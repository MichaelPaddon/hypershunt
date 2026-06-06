// Build-time upkeep of the man page and its Markdown mirror.
//
// `docs/hypershunt.1` (troff) is the authored source for the manual.
// At build time we do two things, keyed on changes to the man page:
//
//   1. Sync its `.TH` version footer to the crate version, so
//      Cargo.toml stays the single source of truth for the version
//      (the .TH *date* is left alone -- it's a hand-maintained release
//      date that should not churn on every build).
//   2. Regenerate `docs/manual.md`, a Markdown mirror so the same
//      content is readable on GitHub and on an installed server (it
//      ships in the `docs/**/*` package asset).
//
// pandoc is only needed for step 2 (the mirror) -- by people who edit
// the man page and by CI, which drift-checks both files.  When pandoc
// is absent we warn and leave the committed mirror in place rather than
// failing the build.  Step 1 needs no external tool.

use std::env;
use std::fs;
use std::process::Command;

const MAN_PATH: &str = "docs/hypershunt.1";

fn main() {
    // Only re-run when the man page (or this script) changes.  Writing
    // docs/manual.md is deliberately not a tracked input; writing the
    // man page only happens on a version change and converges (the next
    // build finds it already in sync), so there is no rebuild loop.
    println!("cargo:rerun-if-changed={MAN_PATH}");
    println!("cargo:rerun-if-changed=build.rs");

    sync_man_version();
    regenerate_markdown_mirror();
}

/// Keep the man page's `.TH` `"hypershunt <version>"` footer in sync
/// with `CARGO_PKG_VERSION`.
fn sync_man_version() {
    let Ok(version) = env::var("CARGO_PKG_VERSION") else {
        return;
    };
    let Ok(man) = fs::read_to_string(MAN_PATH) else {
        return;
    };
    if let Some(updated) = replace_th_version(&man, &version) {
        fs::write(MAN_PATH, updated)
            .expect("write docs/hypershunt.1 (version sync)");
    }
}

/// Replace the version in the `.TH` line's `"hypershunt <version>"`
/// field.  Returns the updated text if it changed, else `None`.  Scoped
/// to the `.TH` line so it can't touch `hypershunt` elsewhere in prose.
fn replace_th_version(man: &str, version: &str) -> Option<String> {
    // Anchor on the *line* that starts with ".TH " so prose mentioning
    // ".TH" in a comment can't be mistaken for the header line.
    let th_start = if man.starts_with(".TH ") {
        0
    } else {
        man.find("\n.TH ")? + 1
    };
    let th_end = man[th_start..]
        .find('\n')
        .map_or(man.len(), |n| th_start + n);
    let needle = "\"hypershunt ";
    let rel = man[th_start..th_end].find(needle)?;
    let start = th_start + rel + needle.len();
    let end = start + man[start..].find('"')?;
    if &man[start..end] == version {
        return None;
    }
    let mut out = man.to_string();
    out.replace_range(start..end, version);
    Some(out)
}

/// Regenerate `docs/manual.md` from the man page via pandoc.
fn regenerate_markdown_mirror() {
    let header = "<!-- GENERATED from docs/hypershunt.1 at build time \
                  (build.rs). DO NOT EDIT BY HAND. -->\n\n";

    match Command::new("pandoc")
        .args(["--from=man", "--to=gfm", "--wrap=none", MAN_PATH])
        .output()
    {
        Ok(out) if out.status.success() => {
            let mut md = String::from(header);
            md.push_str(&String::from_utf8_lossy(&out.stdout));
            fs::write("docs/manual.md", md).expect("write docs/manual.md");
        }
        // Soft-fail: a plain build without pandoc still succeeds and
        // uses the committed mirror.  CI installs pandoc and enforces
        // that the committed docs/manual.md is current.
        Ok(out) => println!(
            "cargo:warning=pandoc failed; docs/manual.md not \
             regenerated: {}",
            String::from_utf8_lossy(&out.stderr)
        ),
        Err(_) => println!(
            "cargo:warning=pandoc not found; docs/manual.md not \
             regenerated (install pandoc to refresh the man-page mirror)"
        ),
    }
}
