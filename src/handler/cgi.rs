// CGI (Common Gateway Interface) handler: fork-per-request execution of
// scripts under the configured document root.  Unix only; uses execve(2)
// via std::process::Command with a CGI-standard environment.

use super::cgi_util::{build_cgi_env, parse_cgi_response};
use crate::error::{HttpResponse, response_404, response_502};
use crate::error::ReqBody;
use crate::handler::Handler;
use crate::headers::RequestContext;
use async_trait::async_trait;
use http_body_util::BodyExt;
use hyper::Request;
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[async_trait]
impl Handler for CgiHandler {
    async fn handle(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
        _ctx: &RequestContext<'_>,
    ) -> HttpResponse {
        self.serve(req, matched_prefix).await
    }
}

pub struct CgiHandler {
    root: PathBuf,
}

impl CgiHandler {
    pub fn new(root: &str) -> Self {
        Self {
            root: PathBuf::from(root),
        }
    }

    pub async fn serve(
        &self,
        req: Request<ReqBody>,
        matched_prefix: &str,
    ) -> HttpResponse {
        let (parts, body) = req.into_parts();
        let uri_path = parts.uri.path().to_owned();

        // Directory requests have no obvious script to execute.
        if uri_path.ends_with('/') {
            return response_404();
        }

        let script_path = match resolve_script(&self.root, &uri_path) {
            Some(p) => p,
            None => {
                tracing::warn!(
                    path = %uri_path,
                    "cgi: path traversal attempt or script not found"
                );
                return response_404();
            }
        };

        let body_bytes = match BodyExt::collect(body).await {
            Ok(c) => c.to_bytes(),
            Err(e) => {
                tracing::error!("cgi: failed to read request body: {e}");
                return response_502();
            }
        };

        // No index for CGI -- build_cgi_env called with None.
        let env = build_cgi_env(
            &parts,
            &self.root.to_string_lossy(),
            matched_prefix,
            &None,
            &body_bytes,
        );

        let mut child = match Command::new(&script_path)
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k.as_str(), v.as_str())))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    script = %script_path.display(),
                    "cgi: failed to spawn script: {e}"
                );
                return response_502();
            }
        };

        // Write request body to the script's stdin, then close it so
        // the script sees EOF.
        if let Some(mut stdin) = child.stdin.take()
            && let Err(e) = stdin.write_all(&body_bytes).await
        {
            tracing::error!("cgi: failed to write stdin: {e}");
            let _ = child.kill().await;
            return response_502();
        }

        let output = match child.wait_with_output().await {
            Ok(o) => o,
            Err(e) => {
                tracing::error!(
                    script = %script_path.display(),
                    "cgi: script execution failed: {e}"
                );
                return response_502();
            }
        };

        if !output.status.success() {
            tracing::warn!(
                script = %script_path.display(),
                status = %output.status,
                "cgi: script exited with non-zero status"
            );
        }

        match parse_cgi_response(&output.stdout) {
            Ok(resp) => resp,
            Err(e) => {
                tracing::error!(
                    script = %script_path.display(),
                    "cgi: malformed response: {e}"
                );
                response_502()
            }
        }
    }
}

// Resolve a URI path to an absolute script path under root, blocking
// directory traversal.  Returns None if the path is unsafe or the
// file does not exist.
fn resolve_script(root: &std::path::Path, uri_path: &str) -> Option<PathBuf> {
    use super::static_files::safe_join;
    let candidate = safe_join(root, uri_path)?;
    if candidate.exists() {
        Some(candidate)
    } else {
        None
    }
}

// -- Tests ---------------------------------------------------------

// No unit tests for process execution -- requires a real filesystem
// script and is better covered by integration tests.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_script_rejects_traversal() {
        let root = std::path::Path::new("/var/www/cgi-bin");
        assert!(resolve_script(root, "/../etc/passwd").is_none());
    }

    /// A path that is safe but refers to a file that does not exist
    /// returns None (the `candidate.exists()` branch).
    #[test]
    fn resolve_script_returns_none_for_nonexistent_file() {
        let dir = tempfile::tempdir().unwrap();
        assert!(resolve_script(dir.path(), "/does-not-exist.cgi").is_none());
    }

    /// A path to an existing file returns Some with the resolved path.
    #[test]
    fn resolve_script_returns_some_for_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.cgi"), b"").unwrap();
        assert!(resolve_script(dir.path(), "/hello.cgi").is_some());
    }

    /// A subdirectory path is resolved against root + the URI
    /// segments; verifies that safe_join doesn't reject ordinary
    /// nested CGI scripts.
    #[test]
    fn resolve_script_resolves_subdir() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("api")).unwrap();
        std::fs::write(dir.path().join("api/v1.cgi"), b"").unwrap();
        let r = resolve_script(dir.path(), "/api/v1.cgi");
        assert!(r.is_some(), "expected /api/v1.cgi to resolve");
        assert!(r.unwrap().ends_with("api/v1.cgi"));
    }

    /// A URI with an absolute-style component (`//etc/passwd`) is
    /// still rejected -- safe_join treats it as a traversal because
    /// the joined path would escape `root`.
    #[test]
    fn resolve_script_rejects_absolute_escape() {
        let dir = tempfile::tempdir().unwrap();
        assert!(resolve_script(dir.path(), "//etc/passwd").is_none());
    }
}
