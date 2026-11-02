//! Language dependencies, best effort: a bounded walk of the usual app
//! directories for lockfiles, plus Go build info from executables.

pub mod gobuild;
pub mod lockfiles;

use std::collections::HashSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use crate::model::{Coordinate, Package, PackageKind};
use crate::purl;
use crate::rootfs::{read_file_limited, Rootfs};

use lockfiles::Lockfile;

/// Where application code usually lives in an image.
const ROOTS: &[&str] = &[
    "/app",
    "/usr/src/app",
    "/srv",
    "/opt",
    "/home",
    "/root",
    "/var/www",
    "/workspace",
    "/code",
    "/usr/local/bin",
    "/usr/local/lib",
];
const SKIP_DIRS: &[&str] = &[".git", "__pycache__", ".cache", "proc", "sys", "dev"];

/// Bounds on the lockfile / binary walk.
#[derive(Debug, Clone)]
pub struct LangLimits {
    pub max_depth: usize,
    /// Directory entries visited across all roots.
    pub max_entries: usize,
    pub max_lockfile_size: u64,
    pub max_binary_size: u64,
    /// Executables inspected for Go build info (each is read whole).
    pub max_binaries: usize,
}

impl Default for LangLimits {
    fn default() -> Self {
        Self {
            max_depth: 6,
            max_entries: 50_000,
            max_lockfile_size: 32 * 1024 * 1024,
            max_binary_size: 256 * 1024 * 1024,
            max_binaries: 128,
        }
    }
}

/// Collect language deps from lockfiles under [`ROOTS`] and from Go build
/// info in `executables` (in-container paths, e.g. the running binaries) and
/// in executables met during the walk.
pub fn scan(fs: &Rootfs, executables: &[String], limits: &LangLimits) -> Vec<Package> {
    let mut walk = Walk {
        fs,
        limits,
        visited: 0,
        lockfiles: Vec::new(),
        binaries: executables.to_vec(),
    };
    for root in ROOTS {
        if let Some(canon) = fs.resolve(root) {
            walk.dir(&canon, 0);
        }
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let mut push = |eco: &str, name: &str, version: &str, location: &str| {
        let purl = purl::lang(eco, name, version);
        if seen.insert(purl.clone()) {
            let mut p = Package::new(name, version, PackageKind::Lang, purl);
            p.coordinate = Some(Coordinate::eco(eco, name, version));
            p.location = Some(location.to_string());
            out.push(p);
        }
    };

    for (path, kind) in &walk.lockfiles {
        let Ok(content) = fs.read_string(path, limits.max_lockfile_size) else {
            continue;
        };
        for (name, version) in kind.parse(&content) {
            push(kind.ecosystem(), &name, &version, path);
        }
    }

    // Running binaries come first, so the cap only ever drops walk finds.
    let mut seen_bins = HashSet::new();
    let bins = walk
        .binaries
        .into_iter()
        .filter(|b| seen_bins.insert(b.clone()));
    for path in &bins.take(limits.max_binaries).collect::<Vec<_>>() {
        let Some(host) = fs.host_path(path) else {
            continue;
        };
        let Ok(bytes) = read_file_limited(&host, limits.max_binary_size) else {
            continue;
        };
        if !bytes.starts_with(b"\x7fELF") {
            continue;
        }
        if let Some(info) = gobuild::parse(&bytes) {
            if !info.go_version.is_empty() {
                push("Go", "stdlib", &info.go_version, path);
            }
            for (module, version) in &info.deps {
                push("Go", module, version, path);
            }
        }
    }
    out
}

struct Walk<'a> {
    fs: &'a Rootfs,
    limits: &'a LangLimits,
    visited: usize,
    lockfiles: Vec<(String, Lockfile)>,
    binaries: Vec<String>,
}

impl Walk<'_> {
    /// `path` is canonical; symlinks met inside are not followed (no loops,
    /// no escapes, and the target is usually covered by another root).
    fn dir(&mut self, path: &str, depth: usize) {
        if depth > self.limits.max_depth {
            return;
        }
        let host = self.fs.root().join(path.trim_start_matches('/'));
        let Ok(entries) = fs::read_dir(host) else {
            return;
        };
        for entry in entries.flatten() {
            self.visited += 1;
            if self.visited > self.limits.max_entries {
                return;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            let child = format!("{}/{name}", path.trim_end_matches('/'));
            let Ok(meta) = entry.metadata() else {
                continue; // `DirEntry::metadata` does not follow symlinks
            };
            if meta.is_dir() {
                if name == "node_modules" {
                    // npm ≥ 7's hidden lockfile describes the whole tree.
                    let hidden = format!("{child}/.package-lock.json");
                    if self.fs.exists(&hidden) {
                        self.lockfiles.push((hidden, Lockfile::PackageLock));
                    }
                } else if !SKIP_DIRS.contains(&name.as_str()) {
                    self.dir(&child, depth + 1);
                }
            } else if meta.is_file() {
                if let Some(kind) = Lockfile::from_name(&name) {
                    self.lockfiles.push((child, kind));
                } else if meta.permissions().mode() & 0o111 != 0
                    && meta.len() <= self.limits.max_binary_size
                {
                    self.binaries.push(child);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_finds_lockfiles_and_skips_node_modules_contents() {
        let dir = tempfile::tempdir().unwrap();
        let fx = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/lockfiles");
        let app = dir.path().join("app");
        std::fs::create_dir_all(app.join("node_modules/express")).unwrap();
        std::fs::copy(
            fx.join("v3/package-lock.json"),
            app.join("package-lock.json"),
        )
        .unwrap();
        // A lockfile inside node_modules must not be read (only the hidden one is).
        std::fs::copy(
            fx.join("v1/package-lock.json"),
            app.join("node_modules/express/package-lock.json"),
        )
        .unwrap();
        std::fs::copy(fx.join("Cargo.lock"), app.join("Cargo.lock")).unwrap();

        let pkgs = scan(&Rootfs::new(dir.path()), &[], &LangLimits::default());
        assert!(pkgs.iter().any(
            |p| p.name == "express" && p.location.as_deref() == Some("/app/package-lock.json")
        ));
        assert!(pkgs.iter().any(|p| p.purl == "pkg:cargo/serde@1.0.197"));
        assert!(
            !pkgs.iter().any(|p| p.name == "lodash"),
            "node_modules not descended"
        );
        assert!(pkgs
            .iter()
            .all(|p| p.reachability == crate::model::Reachability::Unknown));
    }

    #[test]
    fn depth_limit_is_respected() {
        let dir = tempfile::tempdir().unwrap();
        let deep = dir.path().join("app/a/b/c");
        std::fs::create_dir_all(&deep).unwrap();
        std::fs::write(deep.join("requirements.txt"), "Django==4.2.10\n").unwrap();
        let limits = LangLimits {
            max_depth: 1,
            ..LangLimits::default()
        };
        assert!(scan(&Rootfs::new(dir.path()), &[], &limits).is_empty());
        assert_eq!(
            scan(&Rootfs::new(dir.path()), &[], &LangLimits::default()).len(),
            1
        );
    }
}
