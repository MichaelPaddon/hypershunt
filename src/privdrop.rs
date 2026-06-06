// Unix privilege drop: switch from root to an unprivileged user after
// all privileged sockets have been bound.  Also handles pre-drop
// ownership of the ACME state directory.
// Privilege dropping for Unix servers that start as root.
//
// Call drop_privileges() after all sockets have been bound.
// The function is a no-op when the process is not running as root,
// so it is safe to call unconditionally on any Unix deployment.
//
// Dropping order: setgroups -> setgid -> setuid.
// The UID change must come last; once it is applied the process can
// no longer call setgid.

use anyhow::{Context, bail};
use nix::unistd::{Gid, Group, Uid, User, chown, setgid, setgroups, setuid};
use std::path::Path;

/// Create `path` (if absent) and set its ownership to `user`/`group`
/// while the process still has root privileges.
///
/// Call this for the ACME state directory before `drop_privileges` so
/// that the unprivileged process can write certificates there.
/// No-op when not running as root.
pub fn prepare_state_dir(
    path: &Path,
    user: &str,
    group: Option<&str>,
) -> anyhow::Result<()> {
    if !nix::unistd::getuid().is_root() {
        return Ok(());
    }

    std::fs::create_dir_all(path)
        .with_context(|| format!("creating {}", path.display()))?;

    let pw = User::from_name(user)
        .context("looking up user")?
        .ok_or_else(|| anyhow::anyhow!("user '{user}' not found"))?;
    let gid: Gid = if let Some(name) = group {
        Group::from_name(name)
            .context("looking up group")?
            .ok_or_else(|| anyhow::anyhow!("group '{name}' not found"))?
            .gid
    } else {
        pw.gid
    };

    chown(path, Some(pw.uid), Some(gid))
        .with_context(|| format!("chown {}", path.display()))?;

    tracing::info!(
        path = %path.display(),
        user,
        "prepared state directory"
    );
    Ok(())
}

/// Drop from root to the named user (and optionally group).
///
/// If `group` is `None`, the user's primary GID from `/etc/passwd`
/// is used.  Returns an error if the user or group does not exist,
/// or if any of the syscalls fail.
///
/// Does nothing and returns `Ok` when not running as root.
pub fn drop_privileges(
    user: &str,
    group: Option<&str>,
    inherit_supplementary_groups: bool,
) -> anyhow::Result<()> {
    // Not root -- nothing to do.
    if !nix::unistd::getuid().is_root() {
        return Ok(());
    }

    // Look up the target user in the system user database.
    let pw = User::from_name(user)
        .context("looking up user")?
        .ok_or_else(|| anyhow::anyhow!("user '{user}' not found"))?;

    // Resolve target GID: explicit group name or user's primary GID.
    let gid: Gid = if let Some(name) = group {
        Group::from_name(name)
            .context("looking up group")?
            .ok_or_else(|| anyhow::anyhow!("group '{name}' not found"))?
            .gid
    } else {
        pw.gid
    };
    let uid: Uid = pw.uid;

    // Skipping setgroups preserves supplementary groups inherited at
    // startup (e.g. via podman --group-add keep-groups).  Only safe in
    // container environments where the inherited groups are explicitly
    // controlled.
    if inherit_supplementary_groups {
        tracing::warn!(
            "inherit-supplementary-groups enabled: \
             supplementary groups are NOT cleared"
        );
    } else {
        setgroups(&[gid]).context("setgroups")?;
    }
    setgid(gid).context("setgid")?;
    setuid(uid).context("setuid")?;

    // Verify: attempt to regain root -- it must fail.
    if setuid(Uid::from_raw(0)).is_ok() {
        bail!("setuid(0) succeeded after privilege drop -- aborting");
    }

    tracing::info!(
        user,
        uid = uid.as_raw(),
        gid = gid.as_raw(),
        inherit_supplementary_groups,
        "dropped privileges"
    );
    Ok(())
}
