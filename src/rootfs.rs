//! Access to a container's live filesystem through `/proc/<pid>/root`.
//!
//! Every in-container path is resolved **in userspace**, component by component,
//! with symlinks re-anchored at the container root. Letting the kernel follow
//! them instead would resolve an absolute symlink (`/lib -> /usr/lib`, or a
//! hostile `/etc/os-release -> /etc/shadow`) against *virtsec's* root, i.e. the
//! host. The container is untrusted input: nothing here escapes its root.

use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

/// Symlink hops allowed while resolving one path (Linux's own limit).
const MAX_HOPS: usize = 40;

/// A container root (normally `/proc/<pid>/root`, a plain dir in tests).
#[derive(Debug, Clone)]
pub struct Rootfs {
    root: PathBuf,
}

impl Rootfs {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn of_pid(pid: u32) -> Self {
        Self::new(format!("/proc/{pid}/root"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Canonical in-container form of `path` (absolute, no symlinks, no `..`),
    /// or `None` if it doesn't exist or loops.
    pub fn resolve(&self, path: &str) -> Option<String> {
        self.walk(Vec::new(), components(path))
    }

    /// Host path to read the canonical target of in-container `path`.
    pub fn host_path(&self, path: &str) -> Option<PathBuf> {
        let canon = self.resolve(path)?;
        Some(self.root.join(canon.trim_start_matches('/')))
    }

    /// Read in-container `path`, refusing files larger than `max` bytes.
    pub fn read_limited(&self, path: &str, max: u64) -> io::Result<Vec<u8>> {
        let host = self
            .host_path(path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path.to_string()))?;
        read_file_limited(&host, max)
    }

    pub fn read_string(&self, path: &str, max: u64) -> io::Result<String> {
        Ok(String::from_utf8_lossy(&self.read_limited(path, max)?).into_owned())
    }

    pub fn exists(&self, path: &str) -> bool {
        self.resolve(path).is_some()
    }

    fn walk(&self, mut out: Vec<String>, mut pending: VecDeque<String>) -> Option<String> {
        let mut hops = 0;
        while let Some(c) = pending.pop_front() {
            if c == ".." {
                out.pop();
                continue;
            }
            out.push(c);
            let host = self.root.join(out.join("/"));
            let meta = fs::symlink_metadata(&host).ok()?;
            if meta.file_type().is_symlink() {
                hops += 1;
                if hops > MAX_HOPS {
                    return None;
                }
                let target = fs::read_link(&host).ok()?;
                let target = target.to_string_lossy();
                out.pop();
                if target.starts_with('/') {
                    out.clear();
                }
                for (i, t) in components(&target).into_iter().enumerate() {
                    pending.insert(i, t);
                }
            }
        }
        Some(format!("/{}", out.join("/")))
    }
}

/// Canonicalizes the *directory* part of many paths, memoized: package file
/// lists share a handful of dirs. The last component is kept as is, so a
/// package's symlink entry stays attributed to the symlink, not its target.
pub struct Resolver<'a> {
    fs: &'a Rootfs,
    dirs: HashMap<String, Option<String>>,
}

impl<'a> Resolver<'a> {
    pub fn new(fs: &'a Rootfs) -> Self {
        Self {
            fs,
            dirs: HashMap::new(),
        }
    }

    pub fn resolve_parent(&mut self, path: &str) -> Option<String> {
        let (dir, name) = path.rsplit_once('/')?;
        let canon_dir = self
            .dirs
            .entry(dir.to_string())
            .or_insert_with(|| self.fs.resolve(if dir.is_empty() { "/" } else { dir }))
            .as_deref()?;
        Some(format!("{}/{name}", canon_dir.trim_end_matches('/')))
    }
}

fn components(path: &str) -> VecDeque<String> {
    path.split('/')
        .filter(|c| !c.is_empty() && *c != ".")
        .map(str::to_string)
        .collect()
}

pub(crate) fn read_file_limited(path: &Path, max: u64) -> io::Result<Vec<u8>> {
    let file = fs::File::open(path)?;
    if file.metadata()?.len() > max {
        return Err(io::Error::other(format!(
            "{} is larger than {max} bytes",
            path.display()
        )));
    }
    let mut buf = Vec::new();
    file.take(max).read_to_end(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn fake_root() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let r = dir.path();
        fs::create_dir_all(r.join("usr/lib/x86_64-linux-gnu")).unwrap();
        fs::write(r.join("usr/lib/x86_64-linux-gnu/libc.so.6"), b"elf").unwrap();
        symlink("usr/lib", r.join("lib")).unwrap();
        fs::create_dir_all(r.join("etc")).unwrap();
        // Absolute symlink: must stay inside the fake root, never hit the host.
        symlink("/usr/lib/os-release", r.join("etc/os-release")).unwrap();
        fs::write(r.join("usr/lib/os-release"), b"ID=debian\n").unwrap();
        symlink("/etc/shadow", r.join("etc/escape")).unwrap();
        symlink("loop", r.join("loop")).unwrap();
        dir
    }

    #[test]
    fn resolves_usrmerge_and_absolute_links_inside_root() {
        let dir = fake_root();
        let fs = Rootfs::new(dir.path());
        assert_eq!(
            fs.resolve("/lib/x86_64-linux-gnu/libc.so.6").as_deref(),
            Some("/usr/lib/x86_64-linux-gnu/libc.so.6")
        );
        assert_eq!(
            fs.read_string("/etc/os-release", 64).unwrap(),
            "ID=debian\n"
        );
    }

    #[test]
    fn never_escapes_root() {
        let dir = fake_root();
        let fs = Rootfs::new(dir.path());
        // `/etc/shadow` doesn't exist in the fake root: no fallback to the host.
        assert_eq!(fs.resolve("/etc/escape"), None);
        assert_eq!(
            fs.resolve("/../../usr/lib/os-release").as_deref(),
            Some("/usr/lib/os-release")
        );
        assert_eq!(fs.resolve("/loop"), None);
    }

    #[test]
    fn resolver_canonicalizes_parent_only() {
        let dir = fake_root();
        let fs = Rootfs::new(dir.path());
        let mut r = Resolver::new(&fs);
        assert_eq!(
            r.resolve_parent("/lib/x86_64-linux-gnu/libc.so.6")
                .as_deref(),
            Some("/usr/lib/x86_64-linux-gnu/libc.so.6")
        );
        // The last component is not followed: the symlink keeps its own path.
        assert_eq!(
            r.resolve_parent("/etc/os-release").as_deref(),
            Some("/etc/os-release")
        );
        assert_eq!(r.resolve_parent("/nodir/x.so"), None);
    }

    #[test]
    fn size_limit_is_enforced() {
        let dir = fake_root();
        let fs = Rootfs::new(dir.path());
        assert!(fs.read_limited("/usr/lib/os-release", 2).is_err());
    }
}
