// Static file handler: streams files with 64 KB chunks, supports
// byte-range requests (Range/Content-Range), ETags for conditional GET,
// and directory index files.  Safe path joining prevents traversal.

use crate::error::{
    HttpResponse, bytes_body, response_400, response_403, response_404,
    response_416, response_500,
};
use crate::error::ReqBody;
use crate::handler::Handler;
use crate::headers::RequestContext;
use crate::metrics::Metrics;
use async_trait::async_trait;
use std::sync::Arc;
use std::sync::atomic::Ordering;

#[async_trait]
impl Handler for StaticHandler {
    async fn handle(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
        _ctx: &RequestContext<'_>,
    ) -> HttpResponse {
        self.serve(req, matched_prefix).await
    }
}
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::body::{Body, Frame};
use hyper::{Request, Response, StatusCode};
use std::fs::Metadata;
use std::io::{self, SeekFrom};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::UNIX_EPOCH;
use tokio::fs::{self, File};
use tokio::io::{AsyncRead, AsyncSeekExt, ReadBuf};

pub struct StaticHandler {
    // None when the handler runs in `userdir` mode; the root is
    // derived per-request from the requested user's HOME.
    root: Option<PathBuf>,
    index_files: Vec<String>,
    strip_prefix: bool,
    // Ordered candidate templates.  When non-empty, the handler
    // resolves the served file by trying each template in turn
    // and serving the first that exists as a regular file.  No
    // hit yields 404; the default index-file flow is bypassed.
    try_files: Vec<String>,
    /// Render an HTML directory listing when no index matches.
    directory_listing: bool,
    /// Optional URL the handler 302-redirects to when the resolved
    /// path is a directory with no matching index and no listing.
    /// Lets `hypershunt.kdl`'s default `/` location point at `/docs/`
    /// until the operator drops an `index.html` into the webroot.
    fallback_redirect: Option<String>,
    /// Per-user mode: the subdirectory under HOME (e.g.
    /// "public_html").  `None` disables ~user resolution.
    userdir: Option<String>,
    userdir_allowlist: Vec<String>,
    userdir_min_uid: u32,
    metrics: Arc<Metrics>,
}

/// Constructor parameter bag for `StaticHandler::new`.  Keeps the
/// signature stable as new knobs land without forcing every test
/// site to update arg order.
pub struct StaticConfig {
    pub root: Option<String>,
    pub index_files: Vec<String>,
    pub strip_prefix: bool,
    pub try_files: Vec<String>,
    pub directory_listing: bool,
    pub fallback_redirect: Option<String>,
    pub userdir: Option<String>,
    pub userdir_allowlist: Vec<String>,
    pub userdir_min_uid: u32,
}

impl StaticHandler {
    pub fn new(cfg: StaticConfig, metrics: Arc<Metrics>) -> Self {
        Self {
            root: cfg.root.map(PathBuf::from),
            index_files: cfg.index_files,
            strip_prefix: cfg.strip_prefix,
            try_files: cfg.try_files,
            directory_listing: cfg.directory_listing,
            fallback_redirect: cfg.fallback_redirect,
            userdir: cfg.userdir,
            userdir_allowlist: cfg.userdir_allowlist,
            userdir_min_uid: cfg.userdir_min_uid,
            metrics,
        }
    }

    pub async fn serve(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
    ) -> HttpResponse {
        let uri_path = req.uri().path();

        let relative_owned: String;
        let mut relative: &str = if self.strip_prefix {
            uri_path.strip_prefix(matched_prefix).unwrap_or(uri_path)
        } else {
            uri_path
        };

        // Per-user mode: resolve the root from the request's first
        // path segment (`/~<user>/...`) and rewrite `relative` to
        // drop the `~user/` prefix so the rest of the pipeline can
        // proceed unchanged.  Errors here short-circuit; we never
        // fall through to a filesystem root.
        let per_request_root: Option<PathBuf>;
        let effective_root: &Path = if let Some(subdir) = &self.userdir {
            match self.resolve_userdir(relative, subdir) {
                Ok((home_subdir, rest)) => {
                    per_request_root = Some(home_subdir);
                    relative_owned = rest;
                    relative = &relative_owned;
                    per_request_root
                        .as_deref()
                        .expect("just set on the previous line")
                }
                Err(resp) => return resp,
            }
        } else {
            // Filesystem mode: `root` is always set (validated at
            // parse time).
            self.root.as_deref().expect("root or userdir required")
        };

        // try-files overrides the default path resolution.  The
        // resolver returns the first candidate template (after
        // `{path}` expansion) that exists under root as a regular
        // file -- or None when every candidate misses, in which
        // case we 404 immediately rather than falling back to the
        // request URI itself.
        let resolved: String;
        let relative: &str = if self.try_files.is_empty() {
            relative
        } else {
            match self.try_files_resolve(effective_root, relative).await {
                Some(r) => {
                    resolved = r;
                    resolved.as_str()
                }
                None => return response_404(),
            }
        };

        let file_path = match safe_join(effective_root, relative) {
            Some(p) => p,
            None => return response_400(),
        };

        // Canonicalise both root and the requested path.
        // The starts_with check guards against symlinks that escape
        // the configured root directory.
        let canonical_root = match effective_root.canonicalize() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(
                    root = %effective_root.display(),
                    error = %e,
                    "static root is not accessible"
                );
                return response_500();
            }
        };
        let canonical_path = match file_path.canonicalize() {
            Ok(p) => p,
            Err(_) => return response_404(),
        };
        if !canonical_path.starts_with(&canonical_root) {
            return response_403();
        }

        // Refuse any path whose components (relative to root) include a
        // name starting with '.'.  This blocks dotfiles (.env, .htaccess)
        // and directories (.git, .ssh) at any level of the tree.
        let relative = canonical_path
            .strip_prefix(&canonical_root)
            .unwrap_or(canonical_path.as_path());
        if relative.components().any(|c| {
            c.as_os_str()
                .to_str()
                .map(|s| s.starts_with('.'))
                .unwrap_or(false)
        }) {
            return response_404();
        }

        let metadata = match fs::metadata(&canonical_path).await {
            Ok(m) => m,
            Err(_) => return response_404(),
        };

        // Resolve index file for directory requests.
        let target = if metadata.is_dir() {
            match self.resolve_index(&canonical_path).await {
                Some(p) => p,
                None if self.directory_listing => {
                    // Directory listing mode: render an HTML page
                    // of the directory's contents and return it as
                    // a normal 200 response.  No index? No problem.
                    return self
                        .render_directory_listing(
                            &canonical_path,
                            req.uri().path(),
                        )
                        .await;
                }
                None if self.fallback_redirect.is_some() => {
                    // Empty directory, no index, no listing: bounce
                    // to the configured URL.  Used by the default
                    // config to point an empty webroot at /docs/.
                    return self.emit_fallback_redirect();
                }
                // 403 not 404: avoids leaking whether the directory
                // exists when listings aren't enabled.
                None => return response_403(),
            }
        } else {
            canonical_path
        };

        let metadata = match fs::metadata(&target).await {
            Ok(m) => m,
            Err(_) => return response_404(),
        };

        let etag = compute_etag(&metadata);
        if is_not_modified(&req, &etag) {
            self.metrics
                .static_not_modified_total
                .fetch_add(1, Ordering::Relaxed);
            return Response::builder()
                .status(StatusCode::NOT_MODIFIED)
                .header("ETag", &etag)
                .body(bytes_body(Bytes::new()))
                .unwrap();
        }

        let file_len = metadata.len();
        let content_type = mime_guess::from_path(&target)
            .first_raw()
            .unwrap_or("application/octet-stream");

        // Parse an optional Range header and build the response.
        match parse_range_header(&req, file_len) {
            // Syntactically valid range that fits within the file.
            Some(Ok((start, end))) => {
                let mut file = match File::open(&target).await {
                    Ok(f) => f,
                    Err(_) => return response_500(),
                };
                if file.seek(SeekFrom::Start(start)).await.is_err() {
                    return response_500();
                }
                let length = end - start + 1;
                self.metrics
                    .static_range_total
                    .fetch_add(1, Ordering::Relaxed);
                self.metrics
                    .static_bytes_served_total
                    .fetch_add(length, Ordering::Relaxed);
                Response::builder()
                    .status(StatusCode::PARTIAL_CONTENT)
                    .header("Content-Type", content_type)
                    .header("Content-Length", length)
                    .header(
                        "Content-Range",
                        format!("bytes {start}-{end}/{file_len}"),
                    )
                    .header("ETag", &etag)
                    .header("Accept-Ranges", "bytes")
                    .body(
                        FileBody::new(file, Some(length))
                            .map_err(|e| {
                                tracing::warn!("file read error: {e}");
                                e
                            })
                            .boxed(),
                    )
                    .unwrap()
            }
            // Range header present but out of bounds -> 416.
            Some(Err(())) => response_416(file_len),
            // No Range header -> full 200 response.
            None => {
                let file = match File::open(&target).await {
                    Ok(f) => f,
                    Err(_) => return response_500(),
                };
                self.metrics
                    .static_bytes_served_total
                    .fetch_add(file_len, Ordering::Relaxed);
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", content_type)
                    .header("Content-Length", file_len)
                    .header("ETag", &etag)
                    .header("Accept-Ranges", "bytes")
                    .body(
                        FileBody::new(file, None)
                            .map_err(|e| {
                                tracing::warn!("file read error: {e}");
                                e
                            })
                            .boxed(),
                    )
                    .unwrap()
            }
        }
    }

    async fn resolve_index(&self, dir: &Path) -> Option<PathBuf> {
        for name in &self.index_files {
            let candidate = dir.join(name);
            if fs::metadata(&candidate).await.is_ok() {
                return Some(candidate);
            }
        }
        None
    }

    /// Build the 302 response emitted when a directory has no
    /// matching index, no listing is enabled, and
    /// `fallback_redirect` is set.  The `Location` header carries
    /// the configured URL verbatim -- the operator chose the form.
    fn emit_fallback_redirect(&self) -> HttpResponse {
        let url = self
            .fallback_redirect
            .as_deref()
            .expect("fallback_redirect set when this method runs");
        let mut resp = Response::builder()
            .status(StatusCode::FOUND)
            .header(hyper::header::LOCATION, url)
            .header(hyper::header::CONTENT_LENGTH, "0")
            .body(bytes_body(Bytes::new()))
            .expect("static Location header always builds");
        // Defence-in-depth: any caching of a redirect that's
        // meant to switch the moment the operator adds content
        // would be wrong, so opt out explicitly.
        resp.headers_mut().insert(
            hyper::header::CACHE_CONTROL,
            hyper::header::HeaderValue::from_static("no-store"),
        );
        resp
    }

    /// Walk the configured try-files templates and return the
    /// first candidate (already template-expanded) that exists
    /// under `self.root` as a regular file.  Only regular files
    /// count: directories and special files are skipped so a
    /// `{path}` candidate that happens to resolve to a directory
    /// doesn't short-circuit the SPA fallback at the end of the
    /// list.
    async fn try_files_resolve(
        &self,
        root: &Path,
        relative: &str,
    ) -> Option<String> {
        for template in &self.try_files {
            let candidate = expand_try_files_template(template, relative);
            let joined = match safe_join(root, &candidate) {
                Some(p) => p,
                None => continue,
            };
            match fs::metadata(&joined).await {
                Ok(md) if md.is_file() => return Some(candidate),
                _ => continue,
            }
        }
        None
    }

    /// Parse `/~<user>/<rest>` against the configured userdir and
    /// return `(HOME/<userdir>, <rest>)`.  Returns an `HttpResponse`
    /// error (404 / 403) on every failure mode so the caller can
    /// short-circuit without revealing whether the named user
    /// exists.
    // HttpResponse is intentionally big (full hyper Response); boxing
    // it on the error path costs an allocation per 404 with no real
    // benefit.
    #[allow(clippy::result_large_err)]
    #[cfg(unix)]
    fn resolve_userdir(
        &self,
        relative: &str,
        subdir: &str,
    ) -> Result<(PathBuf, String), HttpResponse> {
        // The relative path always starts with `/`; the userdir
        // syntax adds a leading `~`.  Anything else is a bad
        // request that shouldn't reach us, but we 404 to keep
        // probing cheap.
        let path = relative.strip_prefix('/').unwrap_or(relative);
        let path = match path.strip_prefix('~') {
            Some(p) => p,
            None => return Err(response_404()),
        };
        let (username, rest) = match path.split_once('/') {
            Some((u, r)) => (u, r.to_owned()),
            None => (path, String::new()),
        };
        if username.is_empty() {
            return Err(response_404());
        }
        // Strict username charset: matches what useradd permits
        // by default.  Stops shell metacharacters and slashes
        // before they reach nix.
        if !username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return Err(response_404());
        }
        // Allowlist (when set) overrides the UID check; explicit
        // entries get served regardless of system UID.
        if !self.userdir_allowlist.is_empty()
            && !self
                .userdir_allowlist
                .iter()
                .any(|u| u == username)
        {
            return Err(response_404());
        }
        let user = match nix::unistd::User::from_name(username) {
            Ok(Some(u)) => u,
            // Unknown user OR a getpwnam I/O error: 404 either way
            // so we don't leak the difference to the network.
            _ => return Err(response_404()),
        };
        if user.uid.as_raw() < self.userdir_min_uid {
            return Err(response_404());
        }
        let mut home_subdir = user.dir;
        home_subdir.push(subdir);
        Ok((home_subdir, format!("/{rest}")))
    }

    #[cfg(not(unix))]
    fn resolve_userdir(
        &self,
        _relative: &str,
        _subdir: &str,
    ) -> Result<(PathBuf, String), HttpResponse> {
        // Userdir is unix-only.  Validation rejects the config on
        // other platforms before reaching here; this stub keeps the
        // non-unix build compiling.
        Err(response_404())
    }

    /// Render an HTML page listing the entries under `dir`.  The
    /// `url_path` is used to build relative links and to display
    /// the breadcrumb at the top of the page.  Hidden files
    /// (leading `.`) are excluded; entries are sorted directories
    /// first, then by filename.
    async fn render_directory_listing(
        &self,
        dir: &Path,
        url_path: &str,
    ) -> HttpResponse {
        // If the URL doesn't already end in `/`, redirect to the
        // canonical form so relative links in the listing resolve
        // correctly against the browser's base URL.
        if !url_path.ends_with('/') {
            return Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header("Location", format!("{url_path}/"))
                .body(bytes_body(Bytes::new()))
                .unwrap();
        }
        let mut rd = match fs::read_dir(dir).await {
            Ok(r) => r,
            Err(_) => return response_500(),
        };
        let mut entries: Vec<(String, bool, u64, Option<i64>)> = Vec::new();
        while let Ok(Some(e)) = rd.next_entry().await {
            let name = match e.file_name().into_string() {
                Ok(n) => n,
                Err(_) => continue, // skip non-UTF-8 names
            };
            if name.starts_with('.') {
                continue;
            }
            let md = match e.metadata().await {
                Ok(m) => m,
                Err(_) => continue,
            };
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64);
            entries.push((name, md.is_dir(), md.len(), mtime));
        }
        entries.sort_by(|a, b| match (a.1, b.1) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.0.cmp(&b.0),
        });
        let html = render_listing_html(url_path, &entries);
        Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/html; charset=utf-8")
            .header("Content-Length", html.len())
            .header("Cache-Control", "no-cache")
            .body(bytes_body(Bytes::from(html)))
            .unwrap()
    }
}

/// HTML-escape a string for safe embedding inside element text or
/// attribute values.  Only the five characters that can break out
/// of the surrounding context are escaped; anything else is passed
/// through.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Percent-encode a single path segment for use in `href`.  Only
/// encodes the handful of characters that are unsafe in a URL path
/// component; reserved-but-safe chars (`-`, `_`, `.`, `~`) pass
/// through to keep the output readable.
fn url_encode_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Format an entry's byte size with K/M/G/T suffixes.  Directories
/// pass through as "-" because their `.len()` is filesystem-defined
/// and not useful to a user browsing the listing.
fn format_size(bytes: u64) -> String {
    const UNITS: &[(&str, u64)] = &[
        ("T", 1_099_511_627_776),
        ("G", 1_073_741_824),
        ("M", 1_048_576),
        ("K", 1_024),
    ];
    for (unit, threshold) in UNITS {
        if bytes >= *threshold {
            return format!("{:.1}{unit}", bytes as f64 / *threshold as f64);
        }
    }
    format!("{bytes}")
}

/// Format a unix mtime as an ISO-8601 UTC string ("YYYY-MM-DD
/// HH:MM:SS").  Kept inline so we don't drag in chrono just for a
/// listing page.
fn format_mtime(secs: i64) -> String {
    // Days since epoch, then break into Y-M-D using a fixed-point
    // algorithm (no leap-second handling, which the directory
    // listing doesn't need).
    if secs < 0 {
        return "-".into();
    }
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let h = rem / 3600;
    let m = (rem % 3600) / 60;
    let s = rem % 60;
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

/// Convert "days since 1970-01-01" to a (year, month, day) triple
/// using the Howard Hinnant algorithm.  Faster than calling out to
/// chrono and self-contained.
fn days_to_ymd(days_since_epoch: i64) -> (i64, u32, u32) {
    // Shift so the era's anchor (March 1) aligns with day 0.
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Serialise a listing as HTML.  Kept inline because the markup is
/// short and a template engine would be the wrong amount of
/// dependency for one page.  All names are HTML-escaped and
/// URL-encoded so a file called `<script>` can't bend the output.
fn render_listing_html(
    url_path: &str,
    entries: &[(String, bool, u64, Option<i64>)],
) -> String {
    let mut out = String::with_capacity(512 + entries.len() * 128);
    let title = html_escape(url_path);
    out.push_str("<!doctype html>\n<html><head>");
    out.push_str("<meta charset=\"utf-8\">");
    out.push_str(&format!("<title>Index of {title}</title>"));
    out.push_str("<style>");
    out.push_str(
        "body{font-family:sans-serif;margin:2em}\
         table{border-collapse:collapse;width:100%}\
         th,td{padding:0.25em 0.75em;text-align:left}\
         th{border-bottom:1px solid #ccc}\
         tr:hover td{background:#f4f4f4}\
         td.size,td.mtime{font-variant-numeric:tabular-nums;color:#666}\
         a{text-decoration:none}",
    );
    out.push_str("</style></head><body>");
    out.push_str(&format!("<h1>Index of {title}</h1>"));
    out.push_str(
        "<table><thead><tr><th>Name</th><th>Size</th>\
         <th>Modified</th></tr></thead><tbody>",
    );
    // Parent-directory link at the top, except for the root URL.
    if url_path != "/" {
        out.push_str("<tr><td><a href=\"../\">../</a></td>");
        out.push_str("<td class=\"size\">-</td>");
        out.push_str("<td class=\"mtime\">-</td></tr>");
    }
    for (name, is_dir, size, mtime) in entries {
        let display = html_escape(name);
        let href = url_encode_segment(name);
        let slash = if *is_dir { "/" } else { "" };
        out.push_str(&format!(
            "<tr><td><a href=\"{href}{slash}\">{display}{slash}</a></td>"
        ));
        let size_cell = if *is_dir {
            "-".to_string()
        } else {
            format_size(*size)
        };
        out.push_str(&format!("<td class=\"size\">{size_cell}</td>"));
        let mtime_cell = mtime.map(format_mtime).unwrap_or_else(|| "-".into());
        out.push_str(&format!("<td class=\"mtime\">{mtime_cell}</td></tr>"));
    }
    out.push_str("</tbody></table></body></html>\n");
    out
}

/// Expand a try-files template against the current request
/// path.  The only supported substitution is `{path}`; every
/// other character is copied verbatim.  Operators include
/// literal fallbacks (`/index.html`) by simply omitting the
/// template variable.
fn expand_try_files_template(template: &str, path: &str) -> String {
    // The common case is "literal fallback" (e.g. /index.html);
    // skip the allocation when no substitution is needed.
    if !template.contains("{path}") {
        return template.to_owned();
    }
    template.replace("{path}", path)
}

// -- Range parsing -------------------------------------------------
//
// Parses a single `Range: bytes=start-end` header value.
// Returns:
//   None          - no Range header (serve the full file)
//   Some(Ok(_))   - valid range within [0, file_len)
//   Some(Err(()))  - syntactically invalid or out-of-range (-> 416)
//
// Multi-range requests (e.g. `bytes=0-499,600-999`) are not supported;
// they are treated as absent and a 200 is returned instead.
fn parse_range_header(
    req: &Request<ReqBody>,
    file_len: u64,
) -> Option<Result<(u64, u64), ()>> {
    let value = req.headers().get("range").and_then(|v| v.to_str().ok())?;

    let bytes = value.strip_prefix("bytes=")?;

    // Decline multi-range requests -- return None so the caller sends 200.
    if bytes.contains(',') {
        return None;
    }

    let (start, end) = if let Some(suffix) = bytes.strip_prefix('-') {
        // Suffix range: bytes=-N -> last N bytes.
        let n: u64 = suffix.parse().ok()?;
        if n == 0 || file_len == 0 {
            return Some(Err(()));
        }
        let start = file_len.saturating_sub(n);
        (start, file_len - 1)
    } else {
        let mut parts = bytes.splitn(2, '-');
        let start: u64 = parts.next()?.parse().ok()?;
        let end_str = parts.next()?;
        let end = if end_str.is_empty() {
            // Open-ended: bytes=N- -> from N to EOF.
            if file_len == 0 {
                return Some(Err(()));
            }
            file_len - 1
        } else {
            end_str.parse().ok()?
        };
        (start, end)
    };

    if start > end || end >= file_len {
        return Some(Err(()));
    }
    Some(Ok((start, end)))
}

// -- FileBody ------------------------------------------------------
//
// Streams a tokio File in 64 KB chunks without buffering the whole
// file in memory.  `limit` caps the number of bytes read, enabling
// Range responses without over-reading.

const CHUNK: usize = 65536;

struct FileBody {
    file: File,
    buf: Box<[u8; CHUNK]>,
    // Remaining bytes to deliver; None means "read until EOF".
    remaining: Option<u64>,
    done: bool,
}

impl FileBody {
    fn new(file: File, limit: Option<u64>) -> Self {
        Self {
            file,
            buf: Box::new([0u8; CHUNK]),
            remaining: limit,
            done: false,
        }
    }
}

impl Body for FileBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.done {
            return Poll::Ready(None);
        }

        // How many bytes to request in this read.
        let want = match self.remaining {
            Some(0) => {
                self.done = true;
                return Poll::Ready(None);
            }
            Some(rem) => (rem as usize).min(CHUNK),
            None => CHUNK,
        };

        let this = self.as_mut().get_mut();
        let mut rbuf = ReadBuf::new(&mut this.buf[..want]);
        match Pin::new(&mut this.file).poll_read(cx, &mut rbuf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                this.done = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(Ok(())) => {
                let n = rbuf.filled().len();
                if n == 0 {
                    this.done = true;
                    Poll::Ready(None)
                } else {
                    if let Some(rem) = this.remaining.as_mut() {
                        *rem -= n as u64;
                    }
                    let bytes = Bytes::copy_from_slice(&this.buf[..n]);
                    Poll::Ready(Some(Ok(Frame::data(bytes))))
                }
            }
        }
    }
}

// -- Path helpers --------------------------------------------------

/// Join `root` with the URI-decoded `uri_path`, blocking traversal.
///
/// Returns `None` if the path contains `..` segments or null bytes.
/// The caller must still verify the canonicalised result stays inside
/// `root` to defend against symlink escapes.
pub fn safe_join(root: &Path, uri_path: &str) -> Option<PathBuf> {
    if uri_path.contains('\0') {
        return None;
    }

    let decoded = percent_decode(uri_path);

    // Reject any ".." segment after decoding, before the filesystem
    // sees the path.  This stops both raw and percent-encoded traversal.
    for segment in decoded.split('/') {
        if segment == ".." {
            return None;
        }
    }

    let relative = decoded.trim_start_matches('/');
    Some(root.join(relative))
}

// Percent-decode a URI component.  Invalid sequences are passed through
// as-is rather than returning an error, matching common server behaviour.
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let (Some(h), Some(l)) =
                (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2]))
        {
            out.push((h << 4) | l);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ETag derived from mtime + file size.  Cheap to compute and stable
// across server restarts as long as the file is unchanged.
fn compute_etag(meta: &Metadata) -> String {
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!("\"{}-{}\"", mtime, meta.len())
}

fn is_not_modified(req: &Request<ReqBody>, etag: &str) -> bool {
    req.headers()
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == etag)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// Fresh metrics sink for handler constructors in tests.
    fn test_metrics() -> Arc<Metrics> {
        Arc::new(Metrics::new())
    }

    #[test]
    fn safe_join_normal() {
        let root = Path::new("/var/www");
        assert_eq!(
            safe_join(root, "/index.html"),
            Some(PathBuf::from("/var/www/index.html"))
        );
    }

    #[test]
    fn safe_join_traversal_rejected() {
        let root = Path::new("/var/www");
        assert_eq!(safe_join(root, "/../etc/passwd"), None);
        assert_eq!(safe_join(root, "/foo/../../etc/passwd"), None);
    }

    #[test]
    fn safe_join_null_byte_rejected() {
        let root = Path::new("/var/www");
        assert_eq!(safe_join(root, "/foo\0bar"), None);
    }

    #[test]
    fn safe_join_percent_encoded_traversal_rejected() {
        let root = Path::new("/var/www");
        // %2e%2e decodes to ".." which must be caught after decoding.
        assert_eq!(safe_join(root, "/%2e%2e/etc/passwd"), None);
    }

    #[test]
    fn safe_join_encoded_slash_in_name_is_fine() {
        let root = Path::new("/var/www");
        // %2F -> '/' -> segments ["foo", "bar.txt"], neither is "..".
        let result = safe_join(root, "/foo%2Fbar.txt");
        assert!(result.is_some());
    }

    #[test]
    fn safe_join_root_path_returns_root() {
        let root = Path::new("/var/www");
        // Requesting "/" maps to the root directory itself.
        assert_eq!(safe_join(root, "/"), Some(PathBuf::from("/var/www")));
    }

    #[test]
    fn safe_join_single_dot_segment_allowed() {
        // "." is not ".." so it should not be rejected.
        let root = Path::new("/var/www");
        assert!(safe_join(root, "/./index.html").is_some());
    }

    #[test]
    fn percent_decode_basics() {
        assert_eq!(percent_decode("/hello%20world"), "/hello world");
        assert_eq!(percent_decode("/foo%2Fbar"), "/foo/bar");
    }

    #[test]
    fn percent_decode_invalid_sequence_passed_through() {
        // %GG is not valid hex -- bytes passed through as-is.
        assert_eq!(percent_decode("/%GGfile"), "/%GGfile");
    }

    #[test]
    fn percent_decode_trailing_percent_passed_through() {
        // Trailing % with fewer than 2 hex digits is passed through.
        assert_eq!(percent_decode("/file%"), "/file%");
        assert_eq!(percent_decode("/file%2"), "/file%2");
    }

    fn parse(range_hdr: &str, file_len: u64) -> Option<Result<(u64, u64), ()>> {
        parse_range_header_str(range_hdr, file_len)
    }

    // Mirrors parse_range_header without needing a real Request<ReqBody>.
    fn parse_range_header_str(
        hdr: &str,
        file_len: u64,
    ) -> Option<Result<(u64, u64), ()>> {
        let bytes = hdr.strip_prefix("bytes=")?;
        if bytes.contains(',') {
            return None;
        }
        let (start, end) = if let Some(suffix) = bytes.strip_prefix('-') {
            let n: u64 = suffix.parse().ok()?;
            if n == 0 || file_len == 0 {
                return Some(Err(()));
            }
            (file_len.saturating_sub(n), file_len - 1)
        } else {
            let mut parts = bytes.splitn(2, '-');
            let start: u64 = parts.next()?.parse().ok()?;
            let end_str = parts.next()?;
            let end = if end_str.is_empty() {
                if file_len == 0 {
                    return Some(Err(()));
                }
                file_len - 1
            } else {
                end_str.parse().ok()?
            };
            (start, end)
        };
        if start > end || end >= file_len {
            return Some(Err(()));
        }
        Some(Ok((start, end)))
    }

    #[test]
    fn range_full_explicit() {
        assert_eq!(parse("bytes=0-99", 100), Some(Ok((0, 99))));
    }

    #[test]
    fn range_open_ended() {
        assert_eq!(parse("bytes=50-", 100), Some(Ok((50, 99))));
    }

    #[test]
    fn range_suffix() {
        assert_eq!(parse("bytes=-20", 100), Some(Ok((80, 99))));
    }

    #[test]
    fn range_out_of_bounds() {
        // end >= file_len
        assert_eq!(parse("bytes=0-100", 100), Some(Err(())));
    }

    #[test]
    fn range_inverted() {
        // start > end
        assert_eq!(parse("bytes=50-20", 100), Some(Err(())));
    }

    #[test]
    fn range_absent_returns_none() {
        assert_eq!(parse_range_header_str("bytes=0-49,50-99", 100), None);
    }

    #[test]
    fn range_single_byte() {
        assert_eq!(parse("bytes=0-0", 100), Some(Ok((0, 0))));
    }

    #[test]
    fn range_last_byte() {
        assert_eq!(parse("bytes=99-99", 100), Some(Ok((99, 99))));
    }

    #[test]
    fn range_suffix_larger_than_file_clamps_to_start() {
        // bytes=-200 on a 100-byte file is equivalent to bytes=0-99.
        assert_eq!(parse("bytes=-200", 100), Some(Ok((0, 99))));
    }

    #[test]
    fn range_suffix_zero_is_error() {
        // bytes=-0 is semantically invalid (requests zero bytes).
        assert_eq!(parse("bytes=-0", 100), Some(Err(())));
    }

    #[test]
    fn range_start_at_file_length_is_error() {
        // bytes=100- on a 100-byte file: start (100) > end (99) -> error.
        assert_eq!(parse("bytes=100-", 100), Some(Err(())));
    }

    #[test]
    fn range_non_bytes_unit_returns_none() {
        // Only "bytes=" is recognised; other units are ignored.
        assert_eq!(parse_range_header_str("items=0-9", 100), None);
    }

    // Verify the dotfile-blocking logic used in serve().
    // The check iterates path components relative to the root.
    #[test]
    fn dotfile_component_is_detected() {
        use std::path::Path;

        let root = Path::new("/var/www");

        // These should be treated as dotfiles.
        for bad in &[".env", ".hidden", ".git"] {
            let full = root.join(bad);
            let rel = full.strip_prefix(root).unwrap();
            let has_dot = rel.components().any(|c| {
                c.as_os_str()
                    .to_str()
                    .map(|s| s.starts_with('.'))
                    .unwrap_or(false)
            });
            assert!(has_dot, "{bad} should be detected as dotfile");
        }

        // These should NOT be treated as dotfiles.
        for ok in &["index.html", "images/photo.jpg", "api/v1/data"] {
            let full = root.join(ok);
            let rel = full.strip_prefix(root).unwrap();
            let has_dot = rel.components().any(|c| {
                c.as_os_str()
                    .to_str()
                    .map(|s| s.starts_with('.'))
                    .unwrap_or(false)
            });
            assert!(!has_dot, "{ok} must not be detected as dotfile");
        }
    }

    #[test]
    fn try_files_template_expands_path() {
        assert_eq!(
            expand_try_files_template("{path}", "/foo/bar"),
            "/foo/bar"
        );
        assert_eq!(
            expand_try_files_template("{path}.html", "/foo/bar"),
            "/foo/bar.html"
        );
    }

    #[test]
    fn try_files_template_passes_through_literals() {
        assert_eq!(
            expand_try_files_template("/index.html", "/foo"),
            "/index.html"
        );
        assert_eq!(expand_try_files_template("", "/foo"), "");
    }

    #[tokio::test]
    async fn try_files_resolve_returns_first_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::write(root.join("index.html"), "spa").unwrap();
        let handler = StaticHandler {
            root: Some(root.clone()),
            index_files: vec![],
            strip_prefix: false,
            try_files: vec![
                "{path}".into(),
                "{path}.html".into(),
                "/index.html".into(),
            ],
        
            directory_listing: false,
            fallback_redirect: None,
            userdir: None,
            userdir_allowlist: vec![],
            userdir_min_uid: 1000,
            metrics: test_metrics(),
        };
        // Request for /missing -> first two miss, third (literal
        // /index.html) hits the SPA fallback.
        let got = handler.try_files_resolve(handler.root.as_deref().unwrap(), "/missing").await;
        assert_eq!(got.as_deref(), Some("/index.html"));
    }

    #[tokio::test]
    async fn try_files_resolve_picks_path_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::write(root.join("real.txt"), "x").unwrap();
        let handler = StaticHandler {
            root: Some(root.clone()),
            index_files: vec![],
            strip_prefix: false,
            try_files: vec![
                "{path}".into(),
                "/index.html".into(),
            ],
        
            directory_listing: false,
            fallback_redirect: None,
            userdir: None,
            userdir_allowlist: vec![],
            userdir_min_uid: 1000,
            metrics: test_metrics(),
        };
        // The first template matches the existing file, so the
        // fallback is never visited.
        let got = handler.try_files_resolve(handler.root.as_deref().unwrap(), "/real.txt").await;
        assert_eq!(got.as_deref(), Some("/real.txt"));
    }

    #[tokio::test]
    async fn try_files_resolve_skips_directories() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::create_dir(root.join("sub")).unwrap();
        std::fs::write(root.join("index.html"), "spa").unwrap();
        let handler = StaticHandler {
            root: Some(root.clone()),
            index_files: vec![],
            strip_prefix: false,
            try_files: vec![
                "{path}".into(),
                "/index.html".into(),
            ],
        
            directory_listing: false,
            fallback_redirect: None,
            userdir: None,
            userdir_allowlist: vec![],
            userdir_min_uid: 1000,
            metrics: test_metrics(),
        };
        // `/sub` exists as a directory -- try-files must skip
        // it and fall through to /index.html so the SPA route
        // works.
        let got = handler.try_files_resolve(handler.root.as_deref().unwrap(), "/sub").await;
        assert_eq!(got.as_deref(), Some("/index.html"));
    }

    #[tokio::test]
    async fn try_files_substitutes_relative_after_strip_prefix() {
        // serve() passes the post-strip path into
        // try_files_resolve, so a strip-prefix location with
        // try-files like `{path}` should look under root/foo
        // for a request to /app/foo (not under root/app/foo).
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        std::fs::write(root.join("foo"), "ok").unwrap();
        let handler = StaticHandler {
            root: Some(root.clone()),
            index_files: vec![],
            strip_prefix: true,
            try_files: vec!["{path}".into()],
        
            directory_listing: false,
            fallback_redirect: None,
            userdir: None,
            userdir_allowlist: vec![],
            userdir_min_uid: 1000,
            metrics: test_metrics(),
        };
        // The resolver gets the already-stripped relative,
        // which mirrors the runtime contract from serve().
        let got = handler.try_files_resolve(handler.root.as_deref().unwrap(), "/foo").await;
        assert_eq!(got.as_deref(), Some("/foo"));
    }

    // -- Directory listing -----------------------------------------

    /// Build an empty `ReqBody` suitable for `serve()` in tests.
    fn empty_req_body() -> crate::error::ReqBody {
        http_body_util::BodyExt::boxed_unsync(
            http_body_util::Full::new(bytes::Bytes::new())
                .map_err(|never: std::convert::Infallible| match never {}),
        )
    }

    fn listing_handler(root: &Path) -> StaticHandler {
        StaticHandler::new(StaticConfig {
            root: Some(root.to_string_lossy().into_owned()),
            index_files: vec![],
            strip_prefix: false,
            try_files: vec![],
            directory_listing: true,
            fallback_redirect: None,
            userdir: None,
            userdir_allowlist: vec![],
            userdir_min_uid: 1000,
        }, test_metrics())
    }

    fn fallback_handler(root: &Path, target: &str) -> StaticHandler {
        StaticHandler::new(StaticConfig {
            root: Some(root.to_string_lossy().into_owned()),
            index_files: vec!["index.html".into()],
            strip_prefix: false,
            try_files: vec![],
            directory_listing: false,
            fallback_redirect: Some(target.to_owned()),
            userdir: None,
            userdir_allowlist: vec![],
            userdir_min_uid: 1000,
        }, test_metrics())
    }

    #[tokio::test]
    async fn directory_listing_renders_visible_entries() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), "x").unwrap();
        std::fs::write(dir.path().join(".hidden"), "secret").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let handler = listing_handler(dir.path());
        let req = Request::builder()
            .uri("/")
            .body(empty_req_body())
            .unwrap();
        let resp = handler.serve(req, "/").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let s = std::str::from_utf8(&body).unwrap();
        assert!(s.contains("a.txt"), "missing a.txt: {s}");
        assert!(s.contains("sub/"), "missing sub/ link: {s}");
        assert!(!s.contains(".hidden"));
        let sub_at = s.find("sub/").unwrap();
        let a_at = s.find("a.txt").unwrap();
        assert!(sub_at < a_at, "directories should sort first");
    }

    #[tokio::test]
    async fn directory_listing_escapes_html_in_names() {
        let dir = tempfile::tempdir().unwrap();
        // Use a name that's HTML-significant without containing
        // characters that some filesystems disallow.  `<` and `&`
        // are both valid in POSIX paths.
        std::fs::write(dir.path().join("a<b&c"), "x").unwrap();
        let handler = listing_handler(dir.path());
        let req = Request::builder()
            .uri("/")
            .body(empty_req_body())
            .unwrap();
        let resp = handler.serve(req, "/").await;
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let s = std::str::from_utf8(&body).unwrap();
        // The raw filename "a<b&c" should be encoded as "a&lt;b&amp;c"
        // somewhere in the rendered body.
        assert!(
            s.contains("a&lt;b&amp;c"),
            "expected encoded name, body was: {s}"
        );
        // And the unencoded form must not appear inside the body
        // proper (it's fine inside <title> too as long as it's
        // already escaped, which it is).
        assert!(!s.contains("a<b&c"));
    }

    #[tokio::test]
    async fn directory_listing_redirects_when_path_missing_slash() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        let handler = listing_handler(dir.path());
        let req = Request::builder()
            .uri("/sub")
            .body(empty_req_body())
            .unwrap();
        let resp = handler.serve(req, "/").await;
        assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
        assert_eq!(
            resp.headers().get("Location").unwrap(),
            "/sub/"
        );
    }

    #[tokio::test]
    async fn directory_listing_disabled_returns_403_when_no_index() {
        let dir = tempfile::tempdir().unwrap();
        let handler = StaticHandler::new(StaticConfig {
            root: Some(dir.path().to_string_lossy().into_owned()),
            index_files: vec!["index.html".into()],
            strip_prefix: false,
            try_files: vec![],
            directory_listing: false,
            fallback_redirect: None,
            userdir: None,
            userdir_allowlist: vec![],
            userdir_min_uid: 1000,
        }, test_metrics());
        let req = Request::builder()
            .uri("/")
            .body(empty_req_body())
            .unwrap();
        let resp = handler.serve(req, "/").await;
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    // -- fallback-redirect ----------------------------------------

    /// Empty directory + no index + fallback configured => 302
    /// pointing at the configured URL.  Cache-Control: no-store
    /// so a future content-drop isn't shadowed by a cached redirect.
    #[tokio::test]
    async fn fallback_redirect_fires_on_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let h = fallback_handler(dir.path(), "/docs/");
        let req = Request::builder()
            .uri("/")
            .body(empty_req_body())
            .unwrap();
        let resp = h.serve(req, "/").await;
        assert_eq!(resp.status(), StatusCode::FOUND);
        assert_eq!(
            resp.headers().get(hyper::header::LOCATION).unwrap(),
            "/docs/"
        );
        assert_eq!(
            resp.headers().get(hyper::header::CACHE_CONTROL).unwrap(),
            "no-store"
        );
    }

    /// As soon as a matching index file exists, the fallback
    /// redirect stops firing -- the index is served instead.
    #[tokio::test]
    async fn fallback_redirect_does_not_fire_when_index_present() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("index.html"), "hi").unwrap();
        let h = fallback_handler(dir.path(), "/docs/");
        let req = Request::builder()
            .uri("/")
            .body(empty_req_body())
            .unwrap();
        let resp = h.serve(req, "/").await;
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// A request for a path that doesn't exist (neither a
    /// directory nor a file) still 404s; the fallback is
    /// scoped to the "directory with no index" case so a typo'd
    /// URL doesn't silently bounce to docs.
    #[tokio::test]
    async fn fallback_redirect_does_not_catch_random_404() {
        let dir = tempfile::tempdir().unwrap();
        let h = fallback_handler(dir.path(), "/docs/");
        let req = Request::builder()
            .uri("/random/path")
            .body(empty_req_body())
            .unwrap();
        let resp = h.serve(req, "/").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // -- HTML formatting helpers -----------------------------------

    #[test]
    fn html_escape_handles_all_five_special_chars() {
        assert_eq!(html_escape("<&>\"'"), "&lt;&amp;&gt;&quot;&#39;");
        assert_eq!(html_escape("plain"), "plain");
    }

    #[test]
    fn url_encode_segment_keeps_safe_chars_and_encodes_others() {
        assert_eq!(url_encode_segment("a-b_c.d~e"), "a-b_c.d~e");
        assert_eq!(url_encode_segment("a b/c"), "a%20b%2Fc");
    }

    #[test]
    fn format_size_uses_unit_suffixes() {
        assert_eq!(format_size(0), "0");
        assert_eq!(format_size(500), "500");
        assert_eq!(format_size(2048), "2.0K");
        assert_eq!(format_size(2 * 1024 * 1024), "2.0M");
        assert_eq!(format_size(3 * 1024 * 1024 * 1024), "3.0G");
    }

    #[test]
    fn format_mtime_renders_epoch_to_iso() {
        assert_eq!(format_mtime(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(format_mtime(946_684_800), "2000-01-01 00:00:00 UTC");
    }

    // -- ~user resolution ------------------------------------------

    #[cfg(unix)]
    fn userdir_handler(
        min_uid: u32,
        allowlist: Vec<String>,
    ) -> StaticHandler {
        StaticHandler::new(StaticConfig {
            root: None,
            index_files: vec![],
            strip_prefix: false,
            try_files: vec![],
            directory_listing: false,
            fallback_redirect: None,
            userdir: Some("public_html".into()),
            userdir_allowlist: allowlist,
            userdir_min_uid: min_uid,
        }, test_metrics())
    }

    #[cfg(unix)]
    #[test]
    fn userdir_rejects_uid_below_threshold() {
        let h = userdir_handler(1000, vec![]);
        let r = h.resolve_userdir("/~root/file.txt", "public_html");
        let resp = r.expect_err("root must be rejected");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[cfg(unix)]
    #[test]
    fn userdir_rejects_unknown_user() {
        let h = userdir_handler(0, vec![]);
        let r = h.resolve_userdir(
            "/~hypershunt_no_such_user_xyz/foo",
            "public_html",
        );
        assert!(r.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn userdir_rejects_invalid_username_chars() {
        let h = userdir_handler(0, vec![]);
        assert!(
            h.resolve_userdir("/~..%2fetc%2fpasswd/x", "public_html")
                .is_err()
        );
        assert!(
            h.resolve_userdir("/~alice@example/x", "public_html")
                .is_err()
        );
    }

    #[cfg(unix)]
    #[test]
    fn userdir_allowlist_blocks_other_users() {
        let h = userdir_handler(0, vec!["ghost".into()]);
        let r = h.resolve_userdir("/~root/x", "public_html");
        assert!(r.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn userdir_no_username_is_rejected() {
        let h = userdir_handler(0, vec![]);
        assert!(h.resolve_userdir("/~/x", "public_html").is_err());
        assert!(h.resolve_userdir("/alice/x", "public_html").is_err());
    }

    #[tokio::test]
    async fn try_files_resolve_returns_none_when_all_miss() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let handler = StaticHandler {
            root: Some(root.clone()),
            index_files: vec![],
            strip_prefix: false,
            try_files: vec!["{path}".into(), "/missing.html".into()],
        
            directory_listing: false,
            fallback_redirect: None,
            userdir: None,
            userdir_allowlist: vec![],
            userdir_min_uid: 1000,
            metrics: test_metrics(),
        };
        let got = handler.try_files_resolve(handler.root.as_deref().unwrap(), "/nope").await;
        assert!(got.is_none());
    }
}
