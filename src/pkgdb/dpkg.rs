//! dpkg: `/var/lib/dpkg/status` + `info/<pkg>[:arch].list`, and the
//! distroless layout (`status.d/<pkg>` + `status.d/<pkg>.md5sums`).

use crate::rootfs::Rootfs;

use super::{OsPackage, MAX_DB_SIZE};

/// Read every installed dpkg package with its file list. `None` = no dpkg db.
pub fn read(fs: &Rootfs) -> Option<Vec<OsPackage>> {
    if let Ok(status) = fs.read_string("/var/lib/dpkg/status", MAX_DB_SIZE) {
        let mut pkgs = parse_status(&status);
        for p in &mut pkgs {
            let list = [format!("{}:{}", p.name, p.arch), p.name.clone()]
                .iter()
                .find_map(|n| {
                    fs.read_string(&format!("/var/lib/dpkg/info/{n}.list"), MAX_DB_SIZE)
                        .ok()
                });
            p.files = list.map(|l| parse_list(&l)).unwrap_or_default();
        }
        return Some(pkgs);
    }
    read_status_d(fs)
}

/// Distroless images ship one status paragraph per file under `status.d/`.
fn read_status_d(fs: &Rootfs) -> Option<Vec<OsPackage>> {
    let dir = fs.host_path("/var/lib/dpkg/status.d")?;
    let mut pkgs = Vec::new();
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.contains('.') {
            continue; // `<pkg>.md5sums` companions
        }
        let path = format!("/var/lib/dpkg/status.d/{name}");
        let Ok(status) = fs.read_string(&path, MAX_DB_SIZE) else {
            continue;
        };
        for mut p in parse_status(&status) {
            if let Ok(sums) = fs.read_string(&format!("{path}.md5sums"), MAX_DB_SIZE) {
                p.files = parse_md5sums(&sums);
            }
            pkgs.push(p);
        }
    }
    Some(pkgs)
}

/// Parse a dpkg status file: installed packages only (`Status: … installed`).
/// Distroless paragraphs have no `Status` field and count as installed.
pub fn parse_status(content: &str) -> Vec<OsPackage> {
    content
        .split("\n\n")
        .filter_map(|para| {
            let field = |key: &str| {
                para.lines()
                    .find_map(|l| l.strip_prefix(key)?.strip_prefix(':'))
                    .map(|v| v.trim().to_string())
            };
            if field("Status").is_some_and(|s| !s.ends_with(" installed")) {
                return None;
            }
            let name = field("Package")?;
            let version = field("Version")?;
            // `Source: glibc` or `Source: bash (5.2.15-2)` (binNMU'd version).
            let (source, source_version) = match field("Source") {
                Some(s) => match s.split_once(' ') {
                    Some((n, v)) => (
                        Some(n.to_string()),
                        Some(v.trim_matches(|c| c == '(' || c == ')').to_string()),
                    ),
                    None => (Some(s), None),
                },
                None => (None, None),
            };
            Some(OsPackage {
                name,
                version,
                arch: field("Architecture").unwrap_or_default(),
                source,
                source_version,
                files: Vec::new(),
            })
        })
        .collect()
}

/// A `.list` file: one path per line, directories included (harmless).
fn parse_list(content: &str) -> Vec<String> {
    content
        .lines()
        .filter(|l| l.starts_with('/') && *l != "/.")
        .map(str::to_string)
        .collect()
}

/// `<md5>  <path without leading slash>`.
fn parse_md5sums(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|l| l.split_once("  ").map(|(_, p)| format!("/{p}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn fixture_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dpkg");
        let db = dir.path().join("var/lib/dpkg");
        std::fs::create_dir_all(db.join("info")).unwrap();
        std::fs::copy(fx.join("status"), db.join("status")).unwrap();
        for e in std::fs::read_dir(fx.join("info")).unwrap().flatten() {
            std::fs::copy(e.path(), db.join("info").join(e.file_name())).unwrap();
        }
        dir
    }

    #[test]
    fn parses_status_and_lists() {
        let dir = fixture_root();
        let pkgs = read(&Rootfs::new(dir.path())).unwrap();
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["base-files", "bash", "dash", "libc6"],
            "oldpkg is config-files only"
        );

        let bash = &pkgs[1];
        assert_eq!(bash.version, "5.2.15-2+b13");
        assert_eq!(bash.source.as_deref(), Some("bash"));
        assert_eq!(bash.source_version.as_deref(), Some("5.2.15-2"));
        assert!(bash.files.iter().any(|f| f == "/bin/bash"));

        let libc = &pkgs[3];
        assert_eq!(libc.arch, "amd64");
        assert_eq!(libc.source.as_deref(), Some("glibc"));
        assert_eq!(libc.source_version, None);
        // `libc6:amd64.list` (multi-arch name) is found.
        assert!(libc
            .files
            .iter()
            .any(|f| f == "/lib/x86_64-linux-gnu/libc.so.6"));
    }

    #[test]
    fn distroless_status_d() {
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().join("var/lib/dpkg/status.d");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(
            d.join("libssl3"),
            "Package: libssl3\nVersion: 3.0.15-1~deb12u1\nArchitecture: amd64\nSource: openssl\n",
        )
        .unwrap();
        std::fs::write(
            d.join("libssl3.md5sums"),
            "0123  usr/lib/x86_64-linux-gnu/libssl.so.3\n",
        )
        .unwrap();
        let pkgs = read(&Rootfs::new(dir.path())).unwrap();
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].files, ["/usr/lib/x86_64-linux-gnu/libssl.so.3"]);
    }
}
