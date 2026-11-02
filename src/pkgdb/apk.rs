//! apk: `/lib/apk/db/installed` (`P:` name, `V:` version, `A:` arch,
//! `o:` origin, `F:` dir then `R:` files in it).

use crate::rootfs::Rootfs;

use super::{OsPackage, MAX_DB_SIZE};

pub fn read(fs: &Rootfs) -> Option<Vec<OsPackage>> {
    fs.read_string("/lib/apk/db/installed", MAX_DB_SIZE)
        .ok()
        .map(|s| parse_installed(&s))
}

pub fn parse_installed(content: &str) -> Vec<OsPackage> {
    content
        .split("\n\n")
        .filter_map(|block| {
            let (mut name, mut version, mut arch, mut origin) = (None, None, "", None);
            let mut dir = String::new();
            let mut files = Vec::new();
            for line in block.lines() {
                let Some((key, val)) = line.split_once(':') else {
                    continue;
                };
                match key {
                    "P" => name = Some(val.to_string()),
                    "V" => version = Some(val.to_string()),
                    "A" => arch = val,
                    "o" => origin = Some(val.to_string()),
                    "F" => dir = val.to_string(),
                    "R" if dir.is_empty() => files.push(format!("/{val}")),
                    "R" => files.push(format!("/{dir}/{val}")),
                    _ => {}
                }
            }
            Some(OsPackage {
                name: name?,
                version: version?,
                arch: arch.to_string(),
                source: origin,
                source_version: None,
                files,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_fixture() {
        let s = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/apk/installed"
        ))
        .unwrap();
        let pkgs = parse_installed(&s);
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["busybox", "libcrypto3", "musl", "ssl_client"]);

        let crypto = &pkgs[1];
        assert_eq!(crypto.version, "3.1.8-r1");
        assert_eq!(crypto.source.as_deref(), Some("openssl"));
        assert_eq!(crypto.arch, "x86_64");
        assert!(crypto.files.iter().any(|f| f == "/lib/libcrypto.so.3"));

        let busybox = &pkgs[0];
        assert!(busybox.files.iter().any(|f| f == "/bin/busybox"));
    }
}
