//! Reachability: which packages own a file that is mapped or executed.
//!
//! Package file lists and `/proc/<pid>/maps` don't spell paths the same way:
//! dpkg says `/lib/x86_64-linux-gnu/libc.so.6`, the kernel (usrmerge) says
//! `/usr/lib/x86_64-linux-gnu/libc.so.6`; apk lists `libssl.so.3` while the
//! loader maps the versioned file it points to. The index therefore keys every
//! package file both as listed and with its directory resolved inside the
//! container root; a lookup that misses is retried on the fully resolved path,
//! which lands a symlinked name (`/bin/sh`) on the file that really runs.

use std::collections::HashMap;

use crate::model::{Package, PackageKind, Reachability};
use crate::rootfs::{Resolver, Rootfs};

/// In-container path → index of the owning package.
#[derive(Debug, Default)]
pub struct FileIndex {
    owners: HashMap<String, usize>,
}

impl FileIndex {
    pub fn build(fs: &Rootfs, packages: &[Package]) -> Self {
        let mut resolver = Resolver::new(fs);
        let mut owners = HashMap::new();
        for (i, pkg) in packages.iter().enumerate() {
            if pkg.kind != PackageKind::Os {
                continue;
            }
            for file in &pkg.files {
                // Keep the first owner: dpkg diversions can list a path twice.
                owners.entry(file.clone()).or_insert(i);
                if let Some(canon) = resolver.resolve_parent(file) {
                    owners.entry(canon).or_insert(i);
                }
            }
        }
        Self { owners }
    }

    /// The package owning in-container `path` (as given, or once resolved).
    pub fn owner(&self, fs: &Rootfs, path: &str) -> Option<usize> {
        self.owners
            .get(path)
            .or_else(|| self.owners.get(&fs.resolve(path)?))
            .copied()
    }
}

/// Mark the owners of `files` loaded; returns the indices that just changed.
pub fn mark_loaded<'a>(
    packages: &mut [Package],
    index: &FileIndex,
    fs: &Rootfs,
    files: impl IntoIterator<Item = &'a str>,
) -> Vec<usize> {
    let mut changed = Vec::new();
    for file in files {
        if let Some(i) = index.owner(fs, file) {
            if packages[i].reachability != Reachability::Loaded {
                packages[i].reachability = Reachability::Loaded;
                changed.push(i);
            }
        }
    }
    changed
}

/// The modules of a running Go binary are loaded: it is statically linked,
/// so all of them are in memory with it. `exes`: the running binaries, as
/// language packages name their `location`.
pub fn mark_running_binaries(packages: &mut [Package], exes: &[String]) {
    for p in packages.iter_mut() {
        if p.location.as_ref().is_some_and(|l| exes.contains(l)) {
            p.reachability = Reachability::Loaded;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkgdb::dpkg;
    use crate::procfs::parse_maps;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    /// A Debian-like rootfs: usrmerge symlinks, the dpkg fixture db, and the
    /// libs/binaries a running `bash` would map.
    fn fake_debian() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/dpkg");
        std::fs::create_dir_all(r.join("var/lib/dpkg/info")).unwrap();
        std::fs::copy(fx.join("status"), r.join("var/lib/dpkg/status")).unwrap();
        for e in std::fs::read_dir(fx.join("info")).unwrap().flatten() {
            std::fs::copy(e.path(), r.join("var/lib/dpkg/info").join(e.file_name())).unwrap();
        }
        std::fs::create_dir_all(r.join("usr/lib/x86_64-linux-gnu")).unwrap();
        std::fs::create_dir_all(r.join("usr/bin")).unwrap();
        symlink("usr/lib", r.join("lib")).unwrap();
        symlink("usr/bin", r.join("bin")).unwrap();
        // Absolute symlink, like a real `/lib64` → must resolve in the root.
        symlink("/usr/lib/x86_64-linux-gnu", r.join("lib64")).unwrap();
        for f in [
            "usr/lib/x86_64-linux-gnu/libc.so.6",
            "usr/bin/bash",
            "usr/bin/dash",
        ] {
            std::fs::write(r.join(f), b"\x7fELF").unwrap();
        }
        symlink("dash", r.join("usr/bin/sh")).unwrap();
        dir
    }

    fn packages(fs: &Rootfs) -> Vec<Package> {
        dpkg::read(fs)
            .unwrap()
            .into_iter()
            .map(|p| {
                let mut pkg = Package::new(&p.name, &p.version, PackageKind::Os, p.name.clone());
                pkg.files = p.files;
                pkg
            })
            .collect()
    }

    fn reach(pkgs: &[Package], name: &str) -> Reachability {
        pkgs.iter().find(|p| p.name == name).unwrap().reachability
    }

    #[test]
    fn maps_of_running_bash_mark_bash_and_libc_loaded() {
        let dir = fake_debian();
        let fs = Rootfs::new(dir.path());
        let mut pkgs = packages(&fs);
        let index = FileIndex::build(&fs, &pkgs);

        // What the kernel shows for a bash process: canonical /usr paths.
        let maps = parse_maps(
            "5600-5700 r-xp 0 00:2f 11 /usr/bin/bash\n\
             7f00-7f01 r-xp 0 00:2f 12 /usr/lib/x86_64-linux-gnu/libc.so.6\n\
             7f02-7f03 r-xp 0 00:2f 13 /usr/lib/locale/C.utf8/LC_CTYPE\n",
        );
        let changed = mark_loaded(&mut pkgs, &index, &fs, maps.iter().map(String::as_str));
        assert_eq!(changed.len(), 2);
        assert_eq!(reach(&pkgs, "bash"), Reachability::Loaded);
        assert_eq!(reach(&pkgs, "libc6"), Reachability::Loaded);
        assert_eq!(reach(&pkgs, "dash"), Reachability::Dormant);
        assert_eq!(reach(&pkgs, "base-files"), Reachability::Dormant);
    }

    #[test]
    fn exec_through_symlinks_resolves_to_owner() {
        let dir = fake_debian();
        let fs = Rootfs::new(dir.path());
        let mut pkgs = packages(&fs);
        let index = FileIndex::build(&fs, &pkgs);
        // An exec event says `/bin/sh` (→ /usr/bin/sh → dash).
        mark_loaded(&mut pkgs, &index, &fs, ["/bin/sh"]);
        assert_eq!(reach(&pkgs, "dash"), Reachability::Loaded);
        // Through an absolute in-container symlink.
        mark_loaded(&mut pkgs, &index, &fs, ["/lib64/libc.so.6"]);
        assert_eq!(reach(&pkgs, "libc6"), Reachability::Loaded);
        // Marking again reports no change.
        assert!(mark_loaded(&mut pkgs, &index, &fs, ["/bin/sh"]).is_empty());
    }

    #[test]
    fn running_go_binary_modules_are_loaded() {
        let module = |name: &str, location: &str| {
            let mut p = Package::new(
                name,
                "v1.0.0",
                PackageKind::Lang,
                format!("pkg:golang/{name}@v1.0.0"),
            );
            p.location = Some(location.into());
            p
        };
        let mut pkgs = vec![
            module("github.com/coredns/coredns", "/coredns"),
            module("golang.org/x/net", "/coredns"),
            module("github.com/other/tool", "/usr/local/bin/tool"),
            module("express", "/app/package-lock.json"),
        ];
        mark_running_binaries(&mut pkgs, &["/coredns".to_string()]);
        let r: Vec<_> = pkgs.iter().map(|p| p.reachability).collect();
        assert_eq!(
            r,
            [
                Reachability::Loaded,
                Reachability::Loaded,
                Reachability::Unknown,
                Reachability::Unknown
            ]
        );
    }
}
