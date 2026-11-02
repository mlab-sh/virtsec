//! Inventory data model: packages, their reachability, and per-image results.

use serde::{Deserialize, Serialize};

use crate::guest::Guest;

use crate::os::OsRelease;

/// Whether a package's code is actually in memory on the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Reachability {
    /// At least one of its files is mapped by (or was exec'd in) a container process.
    Loaded,
    /// An OS package none of whose files is mapped or executed.
    Dormant,
    /// Not determinable (language dependencies).
    Unknown,
}

impl Reachability {
    pub fn as_str(self) -> &'static str {
        match self {
            Reachability::Loaded => "loaded",
            Reachability::Dormant => "dormant",
            Reachability::Unknown => "unknown",
        }
    }
}

/// Where a package comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PackageKind {
    /// OS package manager (dpkg / apk / rpm).
    Os,
    /// Language dependency (lockfile or Go binary build info).
    Lang,
    /// The node's own stack (k3s, containerd, kernel).
    Node,
}

/// A coordinate in the shape `POST /api/v2/scan` takes (`ScanCoordinate`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Coordinate {
    Eco {
        ecosystem: String,
        name: String,
        version: String,
    },
    Purl {
        purl: String,
    },
    Cpe {
        cpe: String,
    },
}

impl Coordinate {
    pub fn eco(ecosystem: impl Into<String>, name: &str, version: &str) -> Self {
        Coordinate::Eco {
            ecosystem: ecosystem.into(),
            name: name.to_string(),
            version: version.to_string(),
        }
    }

    /// Whether the coordinate names a version a CVE range can be checked
    /// against. Otherwise the feed answers for every version of the product
    /// (a CPE `*`): possible, not established, so the package is not matched.
    pub fn is_exact(&self) -> bool {
        let version = match self {
            Coordinate::Eco { version, .. } => version.as_str(),
            Coordinate::Purl { purl } => purl
                .split(['?', '#'])
                .next()
                .and_then(|p| p.rsplit_once('@'))
                .map_or("", |(_, v)| v),
            Coordinate::Cpe { cpe } => cpe.split(':').nth(5).unwrap_or(""),
        };
        exact_version(version)
    }
}

/// Not empty, not a wildcard (`*`, `-`, `1.x`), a range (`^1.2`, `>=2`) or a
/// tag (`latest`, `(devel)`).
fn exact_version(v: &str) -> bool {
    let v = v.strip_prefix('v').unwrap_or(v);
    v.starts_with(|c: char| c.is_ascii_digit())
        && !v.contains(['*', '<', '>', '|', ' ', ','])
        && !v.split(['.', '-']).any(|s| s.eq_ignore_ascii_case("x"))
}

/// One installed package or dependency.
#[derive(Debug, Clone, Serialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub kind: PackageKind,
    pub purl: String,
    /// Source package, when it differs from `name` (dpkg `Source`, apk origin).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Lockfile or binary a language dependency was read from.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    pub reachability: Reachability,
    /// Files owned by the package (in-container paths), for the loaded tag.
    #[serde(skip)]
    pub files: Vec<String>,
    /// How to match it against vulns; `None` = ecosystem not covered.
    #[serde(skip)]
    pub coordinate: Option<Coordinate>,
}

impl Package {
    pub fn new(name: &str, version: &str, kind: PackageKind, purl: String) -> Self {
        Self {
            name: name.to_string(),
            version: version.to_string(),
            kind,
            purl,
            source: None,
            location: None,
            reachability: match kind {
                PackageKind::Os => Reachability::Dormant,
                PackageKind::Lang => Reachability::Unknown,
                PackageKind::Node => Reachability::Loaded,
            },
            files: Vec::new(),
            coordinate: None,
        }
    }
}

/// The inventory of one guest, or of the Proxmox host itself (`guest: None`).
#[derive(Debug, Clone, Default, Serialize)]
pub struct Inventory {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OsRelease>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest: Option<Guest>,
    pub packages: Vec<Package>,
    /// Distinct files mapped by the guest's processes.
    pub mapped_files: usize,
    /// Non-fatal problems (unsupported package db, unreadable lockfile, ...).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
    /// Packages upgraded on disk whose old files are still mapped: the fix is
    /// not in effect until these processes restart.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub restart: Vec<Restart>,
    /// Why the guest or the node needs a reboot (`/run/reboot-required`, a newer kernel).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reboot: Option<String>,
}

/// A package whose old version still runs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Restart {
    pub package: String,
    /// `comm[pid]` of the processes holding it; empty in VMs (not reported).
    pub processes: Vec<String>,
}

impl Inventory {
    /// The cache / SBOM key: digest, else name.
    pub fn key(&self) -> &str {
        self.digest.as_deref().unwrap_or(&self.name)
    }

    pub fn count(&self, r: Reachability) -> usize {
        self.packages.iter().filter(|p| p.reachability == r).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_coordinates_only() {
        let eco = |v: &str| Coordinate::eco("npm", "lodash", v).is_exact();
        for v in [
            "4.17.20",
            "v1.9.1",
            "1:9.2p1-2",
            "3.0.11-1~deb12u2",
            "1.36.1-r15",
            "v0.0.0-20231010-abcdef",
        ] {
            assert!(eco(v), "{v}");
        }
        for v in [
            "",
            "*",
            "latest",
            "(devel)",
            "1.x",
            "2.X.3",
            "^1.2.0",
            "~1.2",
            ">=2.0",
            "1.0 || 2.0",
        ] {
            assert!(!eco(v), "{v}");
        }
        let cpe = |c: &str| Coordinate::Cpe { cpe: c.into() }.is_exact();
        assert!(cpe("cpe:2.3:o:linux:linux_kernel:6.8.0:*:*:*:*:*:*:*"));
        assert!(!cpe("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*"));
        assert!(!cpe("cpe:2.3:a:openbsd:openssh:-:*:*:*:*:*:*:*"));
        let purl = |p: &str| Coordinate::Purl { purl: p.into() }.is_exact();
        assert!(purl("pkg:npm/%40babel/core@7.24.0?foo=bar"));
        assert!(!purl("pkg:npm/lodash"));
        assert!(!purl("pkg:golang/example.com/app@(devel)"));
    }
}
