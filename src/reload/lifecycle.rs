// SIGHUP + SIGUSR2 signal handlers and the SIGUSR2 fork+execve binary
// upgrade machinery.
//
// - `spawn_sighup_listener` registers a tokio signal handler that
//   re-parses the config and applies it via `reload::reload()`.
// - `spawn_sigusr2_listener` registers the binary-upgrade handler:
//   forks, hands the child the listening fds (via FD_CLOEXEC=0 +
//   inheritance), reads a one-byte readiness signal from the child,
//   then drains the parent's listeners.
// - `signal_upgrade_ready` is called by the upgrade child once its
//   listeners are accepting; it writes the byte the parent is
//   blocking on.

use super::ReloadState;
use std::sync::Arc;
// ── SIGUSR2 binary upgrade (#14) ────────────────────────────────

/// Env-var name used to hand the child a writable fd it must write
/// one byte to after it has finished startup (sockets bound,
/// listeners accepting).  The parent reads that byte to confirm the
/// child is healthy before initiating its own drain.
#[cfg(unix)]
pub const UPGRADE_READY_FD_ENV: &str = "HYPERSHUNT_UPGRADE_READY_FD";

/// State the SIGUSR2 handler needs to perform a re-exec and then
/// drain the parent.  Held in a single struct alongside ReloadState.
#[cfg(unix)]
pub struct UpgradeState {
    /// Senders held in main.rs's stop_accept_txs map.  Cloned here
    /// so the SIGUSR2 path can flip every listener into drain mode
    /// without needing a lock on the map.
    pub stop_accept_txs: Arc<
        std::sync::Mutex<
            std::collections::HashMap<String, tokio::sync::watch::Sender<bool>>,
        >,
    >,
    /// Seconds the parent waits for the child's ready byte.
    pub startup_timeout_secs: u32,
    /// Signal main.rs's run-loop to stop accepting and drain.  Fired
    /// once after the child has reported ready; main observes this
    /// in its existing shutdown-wait select! and performs the drain
    /// under `graceful_drain_timeout` rather than the standard
    /// shutdown timeout.
    pub drain_signal: tokio::sync::watch::Sender<bool>,
}

/// Spawn a task that listens for SIGUSR2 and re-execs hypershunt into
/// the same binary with all listening fds inherited.  On the child's
/// ready signal the parent stops accepting and waits for in-flight
/// connections to drain (subject to `drain_timeout_secs`) before
/// exiting.
#[cfg(unix)]
pub fn spawn_sigusr2_listener(
    upgrade_state: Arc<UpgradeState>,
) -> tokio::task::JoinHandle<()> {
    crate::task::spawn_supervised("signal.sigusr2", async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sig = match signal(SignalKind::user_defined2()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(target: crate::reload::TARGET, "installing SIGUSR2 handler failed: {e}");
                return;
            }
        };
        tracing::info!(target: crate::reload::TARGET, "SIGUSR2 listener installed");
        while sig.recv().await.is_some() {
            tracing::info!(target: crate::reload::TARGET, "SIGUSR2 received; starting binary upgrade");
            if let Err(e) = perform_upgrade(&upgrade_state).await {
                tracing::warn!(target: crate::reload::TARGET, "SIGUSR2: upgrade failed: {e:#}");
                // Parent keeps serving normally.
            }
            // On success, perform_upgrade() has already fired
            // drain_signal; main.rs's shutdown-wait will pick it up
            // and run the bounded drain.  Loop continues so future
            // SIGUSR2s (rare; the process is about to exit) still
            // log a warning.
        }
    })
}

#[cfg(unix)]
async fn perform_upgrade(state: &UpgradeState) -> anyhow::Result<()> {
    use anyhow::{Context, anyhow};
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::{ForkResult, close, execv, fork, pipe};
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, IntoRawFd};

    // Capture argv[0] and the rest of the args BEFORE forking; doing
    // this in the child would still work but allocating after fork is
    // playing with fire.
    let argv_path = std::env::current_exe()
        .context("resolving current_exe for upgrade")?;
    let argv_path_c = CString::new(argv_path.as_os_str().as_encoded_bytes())
        .context("argv[0] contains a null byte")?;
    let args: Vec<CString> = std::env::args()
        .skip(1)
        .map(|a| CString::new(a).expect("argv contains null byte"))
        .collect();
    let mut argv: Vec<CString> = Vec::with_capacity(args.len() + 1);
    argv.push(argv_path_c.clone());
    argv.extend(args);

    // Pipe for the child's "ready" signal.  Default flags so both
    // ends survive fork() without CLOEXEC closing them mid-flight;
    // we'll set CLOEXEC on the parent's read end after fork so a
    // future re-exec of the parent doesn't leak it.
    let (read_end, write_end) = pipe().context("pipe() for upgrade ready")?;

    // SAFETY: fork() is async-signal-safe but the child must not
    // touch tokio reactor state.  We execv() immediately.
    match unsafe { fork() }.context("fork() for upgrade")? {
        ForkResult::Child => {
            // Child side: close the parent's read end and execve.
            drop(read_end);
            // Set the env var pointing at the write end so the child
            // process knows where to write its ready byte.
            // SAFETY: we are the only thread (post-fork, pre-exec).
            unsafe {
                std::env::set_var(
                    UPGRADE_READY_FD_ENV,
                    write_end.as_raw_fd().to_string(),
                );
            }
            // Don't drop write_end -- we want the fd to survive into
            // the new image.  Leak it explicitly.
            let _leaked = write_end.into_raw_fd();
            // execv replaces the process image; if it returns, it
            // failed.  Print to stderr (no tracing here -- we're
            // post-fork and the subscriber is in unknown state) so
            // the operator at least sees the error.
            let err = execv(&argv_path_c, &argv);
            eprintln!("hypershunt upgrade: execv failed: {err:?}");
            // _exit() avoids running atexit handlers which would
            // touch state we share with the parent.
            unsafe { libc::_exit(127) };
        }
        ForkResult::Parent { child } => {
            // Parent side: close the write end so EOF on the read end
            // reliably means "the child closed it" (or crashed).
            drop(write_end);
            // Read the one-byte ready signal with a timeout.
            // Wrap the read end in a tokio AsyncFd so we get an
            // awaitable readiness without blocking the runtime.
            let read_fd = read_end.into_raw_fd();
            let ready = tokio::time::timeout(
                std::time::Duration::from_secs(
                    state.startup_timeout_secs as u64,
                ),
                read_one_byte(read_fd),
            )
            .await;

            match ready {
                Ok(Ok(())) => {
                    tracing::info!(target: crate::reload::TARGET,
                        pid = child.as_raw(),
                        "SIGUSR2: child reported ready; \
                         beginning parent drain"
                    );
                    // Begin draining: stop accepting on every listener,
                    // then signal main.rs to run its bounded drain.
                    let txs = state.stop_accept_txs.lock().expect("reload stop-accept mutex");
                    for (bind, tx) in txs.iter() {
                        tracing::debug!(target: crate::reload::TARGET, %bind, "stop-accept fired");
                        let _ = tx.send(true);
                    }
                    drop(txs);
                    let _ = state.drain_signal.send(true);
                    Ok(())
                }
                Ok(Err(e)) => {
                    // EOF or read error before timeout.
                    let _ = kill(child, Signal::SIGTERM);
                    Err(anyhow!(
                        "child closed ready pipe before signalling: {e}"
                    ))
                }
                Err(_) => {
                    // Timeout: kill the child and abandon the upgrade.
                    let _ = kill(child, Signal::SIGTERM);
                    let _ = close(read_fd);
                    Err(anyhow!(
                        "child did not signal ready within {}s",
                        state.startup_timeout_secs
                    ))
                }
            }
        }
    }
}

/// Read exactly one byte from `fd`.  Used by the parent to wait for
/// the child's ready signal.  Uses tokio's AsyncFd so the read is
/// non-blocking and integrates with the timeout wrapper.
#[cfg(unix)]
pub(crate) async fn read_one_byte(
    fd: std::os::fd::RawFd,
) -> std::io::Result<()> {
    use tokio::io::unix::AsyncFd;
    // Make the fd non-blocking so AsyncFd's readable() works.
    let flags = nix::fcntl::fcntl(
        unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) },
        nix::fcntl::FcntlArg::F_GETFL,
    )
    .map_err(std::io::Error::from)?;
    nix::fcntl::fcntl(
        unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) },
        nix::fcntl::FcntlArg::F_SETFL(
            nix::fcntl::OFlag::from_bits_truncate(flags)
                | nix::fcntl::OFlag::O_NONBLOCK,
        ),
    )
    .map_err(std::io::Error::from)?;

    // SAFETY: we hold ownership of `fd` from the caller.  AsyncFd
    // does not close on drop unless told to; we close it explicitly
    // after the await.
    use std::os::fd::FromRawFd;
    let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) };
    let async_fd = AsyncFd::new(owned)?;
    loop {
        let mut guard = async_fd.readable().await?;
        let mut buf = [0u8; 1];
        match guard.try_io(|inner| {
            use std::os::fd::AsRawFd;
            let n = unsafe {
                libc::read(
                    inner.get_ref().as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    1,
                )
            };
            if n < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(n as usize)
            }
        }) {
            Ok(Ok(0)) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "child closed pipe without writing ready byte",
                ));
            }
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(e)) => return Err(e),
            Err(_) => continue, // spurious readiness; loop
        }
    }
}

/// On child startup: if `UPGRADE_READY_FD_ENV` is set, write one
/// byte to the indicated fd and close it.  Called from main.rs once
/// all listeners are accepting -- that's the moment the parent is
/// allowed to start draining.
#[cfg(unix)]
pub fn signal_upgrade_ready() {
    use std::os::fd::FromRawFd;
    let Some(fd) = std::env::var(UPGRADE_READY_FD_ENV)
        .ok()
        .and_then(|s| s.parse::<std::os::fd::RawFd>().ok())
    else {
        return;
    };
    // SAFETY: parent passed us a writable fd via env.  Even if
    // someone tampers with the env var, write() will fail benignly.
    let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
    use std::io::Write;
    if let Err(e) = f.write_all(b".") {
        tracing::warn!(target: crate::reload::TARGET, "upgrade ready signal write failed: {e}");
    }
    drop(f); // close fd
    // SAFETY: we are the only writer; clear the env var so a future
    // re-exec of this child doesn't see a stale value.
    unsafe { std::env::remove_var(UPGRADE_READY_FD_ENV) };
    tracing::info!(target: crate::reload::TARGET, "upgrade: signalled parent that child is ready");
}

/// Spawn a task that listens for SIGHUP and calls `reload()` for
/// each one.  Returns the JoinHandle so the caller can keep it
/// alongside the shutdown plumbing.
///
/// On non-Unix platforms this returns a never-completing task.
#[cfg(unix)]
pub fn spawn_sighup_listener(
    reload_state: Arc<ReloadState>,
) -> tokio::task::JoinHandle<()> {
    crate::task::spawn_supervised("signal.sighup", async move {
        use tokio::signal::unix::{SignalKind, signal};
        let mut sig = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(target: crate::reload::TARGET, "installing SIGHUP handler failed: {e}");
                return;
            }
        };
        tracing::info!(target: crate::reload::TARGET, "SIGHUP listener installed");
        while sig.recv().await.is_some() {
            tracing::info!(target: crate::reload::TARGET, "SIGHUP received; reloading config");
            // reload() is async to accommodate ACME cert build
            // (network I/O); future signals queue up at tokio's
            // SignalKind dedup window and only fire after this
            // await returns, so we don't race ourselves here.
            let _ = super::reload(&reload_state).await;
        }
    })
}

#[cfg(test)]
#[cfg(unix)]
mod tests {
    use super::{read_one_byte, signal_upgrade_ready, UPGRADE_READY_FD_ENV};
    use std::sync::Mutex;

    // signal_upgrade_ready reads/writes the process env, which is
    // global state; serialise every test that touches it.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[tokio::test]
    async fn read_one_byte_success() {
        use std::os::fd::IntoRawFd;
        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();
        let read_raw = read_fd.into_raw_fd();
        let write_raw = write_fd.into_raw_fd();

        // Write from a blocking thread so the async await makes
        // progress without racing the setup.
        tokio::task::spawn_blocking(move || {
            use std::io::Write;
            use std::os::fd::FromRawFd;
            let mut f = unsafe { std::fs::File::from_raw_fd(write_raw) };
            f.write_all(b".").unwrap();
        });

        read_one_byte(read_raw).await.unwrap();
    }

    #[tokio::test]
    async fn read_one_byte_eof() {
        use std::os::fd::IntoRawFd;
        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();
        let read_raw = read_fd.into_raw_fd();
        // Close write end without writing; reader gets EOF.
        drop(write_fd);

        let err = read_one_byte(read_raw).await.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn signal_upgrade_ready_writes_and_clears_env() {
        use std::io::Read;
        use std::os::fd::{FromRawFd, IntoRawFd};
        let _guard = ENV_LOCK.lock().unwrap();
        let (read_fd, write_fd) = nix::unistd::pipe().unwrap();
        let read_raw = read_fd.into_raw_fd();
        let write_raw = write_fd.into_raw_fd();

        // SAFETY: single-threaded context; env lock held above.
        unsafe {
            std::env::set_var(
                UPGRADE_READY_FD_ENV,
                write_raw.to_string(),
            );
        }
        signal_upgrade_ready();

        assert!(std::env::var(UPGRADE_READY_FD_ENV).is_err(),
            "env var must be removed after signalling");

        // Exactly one byte must have been written.
        let mut buf = [0u8; 1];
        let mut r = unsafe { std::fs::File::from_raw_fd(read_raw) };
        assert_eq!(r.read(&mut buf).unwrap(), 1);
    }

    #[test]
    fn signal_upgrade_ready_no_env_is_noop() {
        let _guard = ENV_LOCK.lock().unwrap();
        // SAFETY: env lock held; no other thread modifies this var.
        unsafe { std::env::remove_var(UPGRADE_READY_FD_ENV) };
        // Must return immediately without panicking or writing.
        signal_upgrade_ready();
        assert!(std::env::var(UPGRADE_READY_FD_ENV).is_err());
    }
}
