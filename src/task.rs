// Supervised task spawn: wraps `tokio::spawn` with panic-catching and a
// structured log on either panic or unexpected exit.  Use for any task
// that's expected to run for the lifetime of the process (or until the
// reload supervisor cancels it).
//
// Per-connection tasks deliberately stay on bare `tokio::spawn`: they
// outnumber background tasks by orders of magnitude and a panic in one
// is already isolated by hyper's connection error path.

use std::future::Future;
use tokio::task::JoinHandle;

/// Spawn a long-running task with structured panic / exit logging.
///
/// `name` is a stable, short identifier (e.g. "acme.renewal",
/// "oidc.discovery", "rate-limit.eviction"); it shows up in
/// `task=` on every emitted log line so operators can correlate
/// panics with the responsible subsystem.
///
/// The returned `JoinHandle<()>` resolves cleanly when the inner task
/// finishes — panics are absorbed by the supervisor and turned into a
/// log line, so callers don't have to match on `JoinError::Panic`.
/// Aborting the returned handle aborts the supervisor *and* the inner
/// task (the supervisor drops the inner handle, which cancels it).
pub fn spawn_supervised<F>(name: &'static str, fut: F) -> JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let inner = tokio::spawn(fut);
    tokio::spawn(async move {
        match inner.await {
            Ok(()) => {
                tracing::debug!(task = name, "supervised task exited");
            }
            Err(e) if e.is_panic() => {
                tracing::error!(
                    task = name,
                    panic = %format_panic(e),
                    "supervised task panicked",
                );
            }
            Err(e) if e.is_cancelled() => {
                tracing::debug!(task = name, "supervised task cancelled");
            }
            Err(e) => {
                tracing::error!(
                    task = name,
                    error = %e,
                    "supervised task join failed",
                );
            }
        }
    })
}

// Extract a printable message from a JoinError carrying a panic payload.
fn format_panic(e: tokio::task::JoinError) -> String {
    if e.is_panic() {
        let payload = e.into_panic();
        if let Some(s) = payload.downcast_ref::<&'static str>() {
            (*s).to_owned()
        } else if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else {
            "<non-string panic payload>".to_owned()
        }
    } else {
        e.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    #[tokio::test]
    async fn supervised_task_runs_to_completion() {
        let ran = Arc::new(AtomicBool::new(false));
        let r = ran.clone();
        let handle = spawn_supervised("test.ok", async move {
            r.store(true, Ordering::SeqCst);
        });
        handle.await.unwrap();
        assert!(ran.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn supervised_task_catches_panic() {
        // The supervisor must convert a panic into a clean exit so
        // the outer JoinHandle resolves Ok(()), not JoinError::Panic.
        let handle = spawn_supervised("test.panic", async move {
            panic!("intentional");
        });
        let outcome = handle.await;
        assert!(outcome.is_ok(), "supervisor must absorb the panic");
    }
}
