//! Host `/proc` access: what each process has mapped.

use std::collections::BTreeSet;
use std::fs;

use anyhow::{bail, Result};

/// Fail early, readably, when virtsec can't read other processes' roots.
pub fn check_root_access() -> Result<()> {
    match fs::read_link("/proc/1/root") {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => bail!(
            "inventory needs root to read guests' filesystems (/proc/<pid>/root): \
             run it as root on the Proxmox node"
        ),
        Err(e) => {
            bail!("cannot access /proc/1/root ({e}): is /proc mounted with the host PID namespace?")
        }
    }
}

/// The files mapped by `pid` (binary, shared libraries, ...), as in-container paths.
pub fn mapped_files(pid: u32) -> BTreeSet<String> {
    fs::read_to_string(format!("/proc/{pid}/maps"))
        .map(|s| parse_maps(&s))
        .unwrap_or_default()
}

/// Parse `/proc/<pid>/maps`: the 6th column, file-backed entries only.
///
/// The kernel prints paths relative to the process's own root, so they are
/// already canonical inside the container. A file replaced on disk after it
/// was mapped shows ` (deleted)`; it's still the code running, so keep it.
pub fn parse_maps(content: &str) -> BTreeSet<String> {
    content
        .lines()
        .filter_map(|line| {
            // addr perms offset dev inode path: the path may contain spaces.
            let path = line.splitn(6, ' ').nth(5)?.trim_start();
            path.starts_with('/')
                .then(|| path.trim_end_matches(" (deleted)").to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_keeps_files_only() {
        let maps = "\
55d0c0a00000-55d0c0a28000 r--p 00000000 00:2f 1311 /usr/sbin/nginx
7f1c2a000000-7f1c2a022000 r-xp 00000000 00:2f 2201 /usr/lib/x86_64-linux-gnu/libc.so.6
7f1c2b000000-7f1c2b001000 r-xp 00000000 00:2f 2202 /usr/lib/libssl.so.3 (deleted)
7f1c2c000000-7f1c2c001000 rw-p 00000000 00:00 0
7ffd5a000000-7ffd5a021000 rw-p 00000000 00:00 0                          [stack]
7f1c2d000000-7f1c2d001000 r--p 00000000 00:2f 2203 /opt/my app/lib.so
";
        let files = parse_maps(maps);
        assert_eq!(
            files.into_iter().collect::<Vec<_>>(),
            vec![
                "/opt/my app/lib.so",
                "/usr/lib/libssl.so.3",
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                "/usr/sbin/nginx",
            ]
        );
    }
}
