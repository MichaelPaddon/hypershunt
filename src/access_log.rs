// Access logging: per-request line emission in tracing / JSON / Common /
// Combined log formats.  Configured server-wide via `server { access-log
// { format "..."; path "..." } }`.  Without an `access-log` block the
// default `tracing` format runs and lines flow through the global
// tracing subscriber (preserving prior behaviour).
//
// The file sink, when configured, is opened append-only at startup and
// flushed after every record so an external `logrotate` move-and-truncate
// loses at most one in-flight write.  hypershunt does NOT rotate; that's left
// to the operator's existing log pipeline.

use serde::Serialize;
use std::fs::OpenOptions;
use std::io::{self, BufWriter, Write};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Output format for access-log lines.  `Tracing` keeps the historic
/// structured-event behaviour; the others emit one line per request to
/// the configured sink (file or stdout).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AccessLogFormat {
    /// One structured `tracing::info!` event per request.  Default.
    #[default]
    Tracing,
    /// One newline-delimited JSON object per request.
    Json,
    /// NCSA Common Log Format: `%h %l %u %t "%r" %s %b`.
    Common,
    /// Combined Log Format: common + `"%{Referer}i" "%{User-agent}i"`.
    Combined,
}

/// Fields captured at the end of a request, formatted by the logger.
/// Borrowed everywhere to avoid allocations on the hot path.
pub struct AccessLogRecord<'a> {
    pub peer: &'a str,
    pub user: &'a str,
    pub host: &'a str,
    pub method: &'a str,
    pub path: &'a str,
    pub protocol: &'a str,
    pub status: u16,
    pub bytes_sent: Option<u64>,
    pub ms: u128,
    pub referer: Option<&'a str>,
    pub user_agent: Option<&'a str>,
}

/// JSON shape; flat object keyed by familiar nginx/apache field names.
/// `Option<u64>` for `bytes_sent` round-trips as `null` when the
/// response had no Content-Length (chunked or empty body).
#[derive(Serialize)]
struct JsonRow<'a> {
    time: String,
    peer: &'a str,
    user: &'a str,
    host: &'a str,
    method: &'a str,
    path: &'a str,
    protocol: &'a str,
    status: u16,
    bytes_sent: Option<u64>,
    ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    referer: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    user_agent: Option<&'a str>,
}

/// Owns the output sink and dispatches each record through the
/// configured formatter.  Cloneable via `Arc` from `AppState`.
pub struct AccessLogger {
    format: AccessLogFormat,
    sink: Sink,
}

enum Sink {
    /// Records go through the global `tracing` subscriber.
    Tracing,
    /// Stdout, line-buffered through a mutex so writes don't
    /// interleave under concurrent requests.
    Stdout(Mutex<()>),
    /// Append-only file opened at startup; flushed every line so an
    /// external rotator's move-and-truncate doesn't lose buffered data.
    File(Mutex<BufWriter<std::fs::File>>),
}

impl AccessLogger {
    /// Build a logger from the parsed config.  `path` is opened append-
    /// only with create-if-missing; failures bubble up so the operator
    /// sees them at startup rather than silently losing logs.
    pub fn new(
        format: AccessLogFormat,
        path: Option<&str>,
    ) -> io::Result<Self> {
        let sink = match (format, path) {
            (AccessLogFormat::Tracing, _) => Sink::Tracing,
            (_, Some(p)) => {
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)?;
                Sink::File(Mutex::new(BufWriter::new(f)))
            }
            (_, None) => Sink::Stdout(Mutex::new(())),
        };
        Ok(Self { format, sink })
    }

    /// Default-constructed logger: tracing format, no file sink.
    /// Matches the behaviour shipped before this module existed and is
    /// the fallback when `access-log` is absent from the config.
    pub fn tracing_default() -> Self {
        Self {
            format: AccessLogFormat::Tracing,
            sink: Sink::Tracing,
        }
    }

    #[allow(dead_code)]
    pub fn format(&self) -> AccessLogFormat {
        self.format
    }

    /// Emit one record.  Never panics; I/O errors are dropped because
    /// access logging is best-effort and we'd rather lose a line than
    /// fail a request.
    pub fn emit(&self, r: &AccessLogRecord<'_>) {
        match self.format {
            AccessLogFormat::Tracing => self.emit_tracing(r),
            AccessLogFormat::Json => self.write_line(&format_json(r)),
            AccessLogFormat::Common => self.write_line(&format_common(r)),
            AccessLogFormat::Combined => {
                self.write_line(&format_combined(r))
            }
        }
    }

    fn emit_tracing(&self, r: &AccessLogRecord<'_>) {
        // Cast to u64 for tracing's field type; u128 millisecond counts
        // would overflow only after ~584 million years.
        tracing::info!(
            peer = r.peer,
            user = r.user,
            host = r.host,
            method = r.method,
            path = r.path,
            status = r.status,
            ms = r.ms as u64,
            "request"
        );
    }

    fn write_line(&self, line: &str) {
        match &self.sink {
            Sink::Tracing => {
                // Unreachable: tracing format goes through emit_tracing.
                // Keep silent rather than tripping a hot-path panic.
            }
            Sink::Stdout(lock) => {
                // Single mutex serialises concurrent writes so lines
                // from different requests don't interleave.
                let _g = lock.lock().unwrap_or_else(|p| p.into_inner());
                let mut out = io::stdout().lock();
                let _ = writeln!(out, "{line}");
            }
            Sink::File(m) => {
                let mut g = m.lock().unwrap_or_else(|p| p.into_inner());
                let _ = g.write_all(line.as_bytes());
                let _ = g.write_all(b"\n");
                // Flush every line so external logrotate's move-and-
                // truncate path doesn't lose buffered data.  Access
                // logs are low-volume relative to TLS, so the syscall
                // cost is in the noise.
                let _ = g.flush();
            }
        }
    }
}

/// Build an AccessLogger from a parsed server config.  Used by both
/// startup (`main.rs`) and SIGHUP reload (`reload.rs`) so the same
/// fallback behaviour applies in both places.
pub fn build_access_log(
    server: &crate::config::ServerConfig,
) -> anyhow::Result<std::sync::Arc<AccessLogger>> {
    use crate::config::AccessLogFormatConfig;
    use anyhow::Context;
    let Some(cfg) = server.access_log.as_ref() else {
        return Ok(std::sync::Arc::new(AccessLogger::tracing_default()));
    };
    let format = match cfg.format {
        AccessLogFormatConfig::Tracing => AccessLogFormat::Tracing,
        AccessLogFormatConfig::Json => AccessLogFormat::Json,
        AccessLogFormatConfig::Common => AccessLogFormat::Common,
        AccessLogFormatConfig::Combined => AccessLogFormat::Combined,
    };
    let logger = AccessLogger::new(format, cfg.path.as_deref())
        .with_context(|| {
            format!(
                "opening access-log path {:?}",
                cfg.path.as_deref().unwrap_or("<stdout>")
            )
        })?;
    Ok(std::sync::Arc::new(logger))
}

fn format_json(r: &AccessLogRecord<'_>) -> String {
    let row = JsonRow {
        time: rfc3339_utc(SystemTime::now()),
        peer: r.peer,
        user: r.user,
        host: r.host,
        method: r.method,
        path: r.path,
        protocol: r.protocol,
        status: r.status,
        bytes_sent: r.bytes_sent,
        ms: r.ms as u64,
        referer: r.referer,
        user_agent: r.user_agent,
    };
    // serde_json::to_string never fails for owned/borrowed primitives.
    serde_json::to_string(&row).unwrap_or_else(|_| String::new())
}

fn format_common(r: &AccessLogRecord<'_>) -> String {
    // NCSA Common Log Format: %h %l %u %t "%r" %s %b
    // %l (ident) is always "-": RFC 1413 is dead.
    let bytes = match r.bytes_sent {
        Some(n) => n.to_string(),
        None => "-".to_string(),
    };
    let user = if r.user.is_empty() { "-" } else { r.user };
    format!(
        "{} - {} {} \"{} {} {}\" {} {}",
        r.peer,
        user,
        ncsa_timestamp(SystemTime::now()),
        r.method,
        escape_quotes(r.path),
        r.protocol,
        r.status,
        bytes,
    )
}

fn format_combined(r: &AccessLogRecord<'_>) -> String {
    // Common + "%{Referer}i" "%{User-agent}i".
    let referer = r.referer.unwrap_or("-");
    let agent = r.user_agent.unwrap_or("-");
    format!(
        "{} \"{}\" \"{}\"",
        format_common(r),
        escape_quotes(referer),
        escape_quotes(agent),
    )
}

/// Backslash-escape any literal `"` or `\` so a malicious or unusual
/// path/header can't break the surrounding double-quoted token.  Tabs
/// and control characters are passed through unchanged; downstream
/// parsers that care should run on the JSON format instead.
fn escape_quotes(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            _ => out.push(c),
        }
    }
    out
}

/// NCSA timestamp: `[22/May/2026:14:23:01 +0000]` in UTC.  We format
/// manually to avoid pulling in chrono's `clock` feature for a single
/// `now()` call; the civil-from-days math is Howard Hinnant's, exact for
/// any date in the proleptic Gregorian calendar.
fn ncsa_timestamp(now: SystemTime) -> String {
    let dur = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO);
    let secs = dur.as_secs();
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let (h, m, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let (year, month, day) = civil_from_days(days);
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep",
        "Oct", "Nov", "Dec",
    ];
    format!(
        "[{:02}/{}/{:04}:{:02}:{:02}:{:02} +0000]",
        day,
        MONTHS[(month - 1) as usize],
        year,
        h,
        m,
        s,
    )
}

/// RFC 3339 / ISO 8601 UTC timestamp: `2026-05-22T14:23:01Z`.  Used by
/// the JSON formatter where consumers expect a machine-parsable shape.
fn rfc3339_utc(now: SystemTime) -> String {
    let dur = now
        .duration_since(UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO);
    let secs = dur.as_secs();
    let days = (secs / 86_400) as i64;
    let sod = secs % 86_400;
    let (h, m, s) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    let (year, month, day) = civil_from_days(days);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, h, m, s
    )
}

/// Days-since-Unix-epoch -> (year, month [1..=12], day [1..=31]).
/// Howard Hinnant's `civil_from_days` algorithm:
///   <https://howardhinnant.github.io/date_algorithms.html>
fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn epoch_record() -> AccessLogRecord<'static> {
        AccessLogRecord {
            peer: "10.0.0.1:54321",
            user: "alice",
            host: "example.com",
            method: "GET",
            path: "/foo",
            protocol: "HTTP/1.1",
            status: 200,
            bytes_sent: Some(123),
            ms: 7,
            referer: Some("https://ref.example/"),
            user_agent: Some("curl/8.0"),
        }
    }

    #[test]
    fn civil_from_days_known_dates() {
        // Unix epoch day = 1970-01-01.
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        // 2026-05-22 = day 20595 since epoch.
        assert_eq!(civil_from_days(20595), (2026, 5, 22));
        // Leap day 2024-02-29.
        let leap = 19782; // 2024-02-29.
        assert_eq!(civil_from_days(leap), (2024, 2, 29));
    }

    #[test]
    fn ncsa_timestamp_at_epoch() {
        let s = ncsa_timestamp(UNIX_EPOCH);
        assert_eq!(s, "[01/Jan/1970:00:00:00 +0000]");
    }

    #[test]
    fn rfc3339_at_epoch() {
        assert_eq!(rfc3339_utc(UNIX_EPOCH), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn common_format_shape() {
        let r = epoch_record();
        let line = format_common(&r);
        // Spot-check the field order; the bracketed timestamp varies
        // by wall clock so we anchor on the surrounding tokens.
        assert!(line.starts_with("10.0.0.1:54321 - alice ["));
        assert!(line.contains("\"GET /foo HTTP/1.1\" 200 123"));
    }

    #[test]
    fn combined_appends_referer_and_agent() {
        let r = epoch_record();
        let line = format_combined(&r);
        assert!(line.ends_with("\"https://ref.example/\" \"curl/8.0\""));
    }

    #[test]
    fn combined_uses_dash_for_missing_fields() {
        let mut r = epoch_record();
        r.referer = None;
        r.user_agent = None;
        let line = format_combined(&r);
        assert!(line.ends_with("\"-\" \"-\""));
    }

    #[test]
    fn json_round_trips() {
        let r = epoch_record();
        let line = format_json(&r);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["peer"], "10.0.0.1:54321");
        assert_eq!(v["user"], "alice");
        assert_eq!(v["method"], "GET");
        assert_eq!(v["path"], "/foo");
        assert_eq!(v["status"], 200);
        assert_eq!(v["bytes_sent"], 123);
        assert_eq!(v["protocol"], "HTTP/1.1");
        assert_eq!(v["referer"], "https://ref.example/");
        assert_eq!(v["user_agent"], "curl/8.0");
        // `time` must be an RFC 3339 / ISO 8601 string.
        let t = v["time"].as_str().unwrap();
        assert!(t.ends_with('Z'));
        assert_eq!(t.len(), 20);
    }

    #[test]
    fn json_omits_missing_optional_headers() {
        let mut r = epoch_record();
        r.referer = None;
        r.user_agent = None;
        let line = format_json(&r);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(v.get("referer").is_none());
        assert!(v.get("user_agent").is_none());
    }

    #[test]
    fn json_null_bytes_sent_when_unknown() {
        let mut r = epoch_record();
        r.bytes_sent = None;
        let line = format_json(&r);
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert!(v["bytes_sent"].is_null());
    }

    #[test]
    fn common_dash_for_empty_user_and_unknown_bytes() {
        let mut r = epoch_record();
        r.user = "";
        r.bytes_sent = None;
        let line = format_common(&r);
        // " - - [" matches the no-user, no-ident token pattern.
        assert!(line.contains(" - - ["));
        assert!(line.ends_with(" 200 -"));
    }

    #[test]
    fn escape_quotes_handles_quotes_and_backslashes() {
        assert_eq!(escape_quotes("/a\"b"), "/a\\\"b");
        assert_eq!(escape_quotes("/a\\b"), "/a\\\\b");
        assert_eq!(escape_quotes("/normal/path"), "/normal/path");
    }

    #[test]
    fn file_sink_writes_one_line_per_record() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("access.log");
        let logger = AccessLogger::new(
            AccessLogFormat::Common,
            Some(path.to_str().unwrap()),
        )
        .unwrap();
        logger.emit(&epoch_record());
        logger.emit(&epoch_record());
        // Drop the logger to release the file handle, then read.
        drop(logger);
        let body = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "expected two lines, got {body:?}");
        for l in lines {
            assert!(l.starts_with("10.0.0.1:54321 - alice ["));
        }
    }

    #[test]
    fn tracing_default_has_no_file_sink() {
        let l = AccessLogger::tracing_default();
        assert_eq!(l.format(), AccessLogFormat::Tracing);
        // Should not panic; the tracing path has no I/O of its own
        // beyond the global subscriber.
        l.emit(&epoch_record());
    }
}
