//! `/etc/os-release` parsing and the distro → vulnerability-ecosystem mapping.

use serde::{Deserialize, Serialize};

use crate::rootfs::Rootfs;

/// The fields of os-release virtsec needs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsRelease {
    /// `debian`, `ubuntu`, `alpine`, `rocky`, ...
    pub id: String,
    /// `12`, `22.04`, `3.19.1`; empty on rolling releases (Debian sid).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub version_id: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pretty_name: String,
}

impl OsRelease {
    /// Read `/etc/os-release`, falling back to `/usr/lib/os-release`.
    pub fn read(fs: &Rootfs) -> Option<Self> {
        ["/etc/os-release", "/usr/lib/os-release"]
            .iter()
            .find_map(|p| fs.read_string(p, 64 * 1024).ok())
            .map(|s| Self::parse(&s))
            .filter(|o| !o.id.is_empty())
    }

    pub fn parse(content: &str) -> Self {
        let mut os = OsRelease::default();
        for line in content.lines() {
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'').to_string();
            match k.trim() {
                "ID" => os.id = v.to_ascii_lowercase(),
                "VERSION_ID" => os.version_id = v,
                "PRETTY_NAME" => os.pretty_name = v,
                _ => {}
            }
        }
        os
    }

    fn major(&self) -> &str {
        self.version_id.split('.').next().unwrap_or("")
    }

    fn major_minor(&self) -> String {
        self.version_id
            .split('.')
            .take(2)
            .collect::<Vec<_>>()
            .join(".")
    }

    /// The OSV ecosystem advisories for this distro's packages live under,
    /// or `None` when vuln.mlab.sh / OSV doesn't cover it.
    pub fn ecosystem(&self) -> Option<String> {
        if self.version_id.is_empty() {
            return None;
        }
        match self.id.as_str() {
            "debian" => Some(format!("Debian:{}", self.major())),
            "ubuntu" => {
                // OSV keys LTS releases (even year, .04) with a `:LTS` suffix.
                let lts = self.version_id.ends_with(".04")
                    && self.major().parse::<u32>().is_ok_and(|y| y % 2 == 0);
                Some(if lts {
                    format!("Ubuntu:{}:LTS", self.version_id)
                } else {
                    format!("Ubuntu:{}", self.version_id)
                })
            }
            "alpine" => Some(format!("Alpine:v{}", self.major_minor())),
            "rocky" => Some(format!("Rocky Linux:{}", self.major())),
            "almalinux" => Some(format!("AlmaLinux:{}", self.major())),
            _ => None,
        }
    }

    /// The purl `distro` qualifier value (`debian-12`, `alpine-3.19.9`).
    pub fn purl_distro(&self) -> String {
        if self.version_id.is_empty() {
            self.id.clone()
        } else {
            format!("{}-{}", self.id, self.version_id)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(file: &str) -> OsRelease {
        OsRelease::parse(
            &std::fs::read_to_string(format!(
                "{}/tests/fixtures/os-release/{file}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap(),
        )
    }

    #[test]
    fn parses_fixtures_and_maps_ecosystems() {
        let debian = os("debian12");
        assert_eq!(debian.id, "debian");
        assert_eq!(debian.version_id, "12");
        assert_eq!(debian.ecosystem().as_deref(), Some("Debian:12"));
        assert_eq!(debian.purl_distro(), "debian-12");

        let alpine = os("alpine319");
        assert_eq!(alpine.ecosystem().as_deref(), Some("Alpine:v3.19"));
        assert_eq!(alpine.purl_distro(), "alpine-3.19.9");

        let ubuntu = os("ubuntu2204");
        assert_eq!(ubuntu.ecosystem().as_deref(), Some("Ubuntu:22.04:LTS"));
        assert_eq!(ubuntu.pretty_name, "Ubuntu 22.04.5 LTS");

        let rocky = os("rocky9");
        assert_eq!(rocky.ecosystem().as_deref(), Some("Rocky Linux:9"));
    }

    #[test]
    fn non_lts_and_unknown_distros() {
        let u = OsRelease::parse("ID=ubuntu\nVERSION_ID=\"23.10\"\n");
        assert_eq!(u.ecosystem().as_deref(), Some("Ubuntu:23.10"));
        let sid = OsRelease::parse("ID=debian\n");
        assert_eq!(sid.ecosystem(), None);
        let arch = OsRelease::parse("ID=arch\nVERSION_ID=1\n");
        assert_eq!(arch.ecosystem(), None);
    }
}
