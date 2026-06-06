// Build-time generation of the Markdown mirror of the man page.
//
// `docs/hypershunt.1` (troff) is the single source of truth for the
// manual.  `docs/manual.md` is a generated mirror so the same content
// is readable on GitHub and on an installed server (it ships in the
// `docs/**/*` package asset).  Regenerating here, keyed on changes to
// the man page, means the mirror can't silently drift.
//
// pandoc is only needed by people who edit the man page (and by CI,
// which also drift-checks the committed `docs/manual.md`).  When pandoc
// is absent we warn and leave the committed mirror in place rather than
// failing the build.

use std::process::Command;

fn main() {
    // Only regenerate when the man page (or this script) changes.
    // Writing `docs/manual.md` is deliberately not a tracked input, so
    // there is no rebuild loop.
    println!("cargo:rerun-if-changed=docs/hypershunt.1");
    println!("cargo:rerun-if-changed=build.rs");

    let header = "<!-- GENERATED from docs/hypershunt.1 at build time \
                  (build.rs). DO NOT EDIT BY HAND. -->\n\n";

    match Command::new("pandoc")
        .args([
            "--from=man",
            "--to=gfm",
            "--wrap=none",
            "docs/hypershunt.1",
        ])
        .output()
    {
        Ok(out) if out.status.success() => {
            let mut md = String::from(header);
            md.push_str(&String::from_utf8_lossy(&out.stdout));
            std::fs::write("docs/manual.md", md)
                .expect("write docs/manual.md");
        }
        // Soft-fail: a plain build without pandoc still succeeds and
        // uses the committed mirror.  CI installs pandoc and enforces
        // that the committed `docs/manual.md` is current.
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
