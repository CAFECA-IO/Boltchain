//! Embeds the source commit in the version (`0.1.0-9ffeafb`, `-dirty` with uncommitted changes),
//! so that `--version`, the explorer status and `web3_clientVersion` tell which build runs.
//! Without git (a source tarball) `BOLT_COMMIT` may be set by hand; otherwise it is `unknown`.

use std::{path::Path, process::Command};

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    println!("cargo:rerun-if-env-changed=BOLT_COMMIT");
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dotgit = root.join(".git");
    // Rebuild when HEAD moves (new commit, checkout) or the index changes (dirty state).
    for f in ["HEAD", "index"] {
        println!("cargo:rerun-if-changed={}", dotgit.join(f).display());
    }
    if let Some(r) = git(&["-C", root.to_str().unwrap_or("."), "symbolic-ref", "-q", "HEAD"]) {
        println!("cargo:rerun-if-changed={}", dotgit.join(r).display());
    }
    let commit = std::env::var("BOLT_COMMIT").ok().filter(|c| !c.is_empty()).unwrap_or_else(|| {
        let dir = root.to_str().unwrap_or(".");
        match git(&["-C", dir, "rev-parse", "--short=7", "HEAD"]) {
            Some(h) => {
                let dirty = git(&["-C", dir, "status", "--porcelain", "--untracked-files=no"])
                    .is_some_and(|s| !s.is_empty());
                if dirty { format!("{h}-dirty") } else { h }
            }
            None => "unknown".into(),
        }
    });
    println!("cargo:rustc-env=BOLT_COMMIT={commit}");
}
