//! OS package databases (dpkg, apk, rpm) → [`Package`]s with purls,
//! vulnerability coordinates and file lists.

pub mod apk;
pub mod dpkg;
#[cfg(feature = "rpm")]
pub mod rpm;

use crate::model::{Coordinate, Package, PackageKind};
use crate::os::OsRelease;
use crate::purl;
use crate::rootfs::Rootfs;

/// Package databases larger than this are refused (corrupt or hostile).
pub(crate) const MAX_DB_SIZE: u64 = 64 * 1024 * 1024;

/// A package as read from a database, before ecosystem mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OsPackage {
    pub name: String,
    pub version: String,
    pub arch: String,
    /// Source package (dpkg `Source`, apk origin, rpm source rpm name).
    pub source: Option<String>,
    /// Source version when it differs (dpkg binNMUs).
    pub source_version: Option<String>,
    pub files: Vec<String>,
}

/// Which package manager an image uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PkgDb {
    Dpkg,
    Apk,
    Rpm,
}

/// Read the image's OS packages. Returns the db kind found (if any) and
/// warnings for what couldn't be read.
pub fn read(fs: &Rootfs, os: Option<&OsRelease>) -> (Vec<Package>, Vec<String>) {
    let mut warnings = Vec::new();
    let found = if let Some(p) = dpkg::read(fs) {
        Some((PkgDb::Dpkg, p))
    } else if let Some(p) = apk::read(fs) {
        Some((PkgDb::Apk, p))
    } else {
        read_rpm(fs, &mut warnings).map(|p| (PkgDb::Rpm, p))
    };
    let Some((db, pkgs)) = found else {
        return (Vec::new(), warnings);
    };
    let os = os.cloned().unwrap_or_default();
    let ecosystem = os.ecosystem();
    if ecosystem.is_none() {
        warnings.push(format!(
            "distro `{}` is not covered by vulnerability matching: OS packages listed, not matched",
            os.purl_distro()
        ));
    }
    let pkgs = pkgs
        .into_iter()
        .map(|p| to_package(db, &os, ecosystem.as_deref(), p))
        .collect();
    (pkgs, warnings)
}

#[cfg(feature = "rpm")]
fn read_rpm(fs: &Rootfs, warnings: &mut Vec<String>) -> Option<Vec<OsPackage>> {
    match rpm::read(fs)? {
        Ok(p) => Some(p),
        Err(e) => {
            warnings.push(format!("rpmdb unreadable: {e:#}"));
            None
        }
    }
}

#[cfg(not(feature = "rpm"))]
fn read_rpm(fs: &Rootfs, warnings: &mut Vec<String>) -> Option<Vec<OsPackage>> {
    if fs.exists("/var/lib/rpm/rpmdb.sqlite") || fs.exists("/var/lib/rpm/Packages") {
        warnings.push(
            "rpm-based guest: OS packages not inventoried (build virtsec with `--features rpm`)"
                .to_string(),
        );
    }
    None
}

fn to_package(db: PkgDb, os: &OsRelease, ecosystem: Option<&str>, p: OsPackage) -> Package {
    let ty = match db {
        PkgDb::Dpkg => "deb",
        PkgDb::Apk => "apk",
        PkgDb::Rpm => "rpm",
    };
    let mut quals = vec![("arch", p.arch.clone())];
    // rpm: epoch moves out of the purl version into its own qualifier.
    let (purl_version, epoch) = match (db, p.version.split_once(':')) {
        (PkgDb::Rpm, Some((e, v))) => (v.to_string(), Some(e.to_string())),
        _ => (p.version.clone(), None),
    };
    quals.push(("distro", os.purl_distro()));
    if let Some(e) = epoch {
        quals.push(("epoch", e));
    }
    if let Some(src) = p.source.as_ref().filter(|s| **s != p.name) {
        quals.push(("upstream", src.clone()));
    }
    let namespace = if os.id.is_empty() {
        None
    } else {
        Some(os.id.as_str())
    };
    let purl = purl::build(ty, namespace, &p.name, &purl_version, &quals);

    let mut pkg = Package::new(&p.name, &p.version, PackageKind::Os, purl);
    // Distro advisories are filed against the *source* package and version.
    let match_name = p.source.clone().unwrap_or_else(|| p.name.clone());
    let match_version = p
        .source_version
        .clone()
        .unwrap_or_else(|| p.version.clone());
    pkg.coordinate = ecosystem.map(|e| Coordinate::eco(e, &match_name, &match_version));
    pkg.source = p.source.filter(|s| *s != p.name);
    pkg.files = p.files;
    pkg
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deb_purl_and_source_coordinate() {
        let os = OsRelease::parse("ID=debian\nVERSION_ID=\"12\"\n");
        let p = to_package(
            PkgDb::Dpkg,
            &os,
            os.ecosystem().as_deref(),
            OsPackage {
                name: "openssh-server".into(),
                version: "1:9.2p1-2+deb12u3".into(),
                arch: "amd64".into(),
                source: Some("openssh".into()),
                source_version: None,
                files: vec![],
            },
        );
        assert_eq!(
            p.purl,
            "pkg:deb/debian/openssh-server@1:9.2p1-2%2Bdeb12u3?arch=amd64&distro=debian-12&upstream=openssh"
        );
        assert_eq!(
            p.coordinate,
            Some(Coordinate::eco("Debian:12", "openssh", "1:9.2p1-2+deb12u3"))
        );
        assert_eq!(p.source.as_deref(), Some("openssh"));
    }

    #[test]
    fn rpm_epoch_qualifier() {
        let os = OsRelease::parse("ID=\"rocky\"\nVERSION_ID=\"9.3\"\n");
        let p = to_package(
            PkgDb::Rpm,
            &os,
            os.ecosystem().as_deref(),
            OsPackage {
                name: "openssl-libs".into(),
                version: "1:3.0.7-27.el9".into(),
                arch: "x86_64".into(),
                source: Some("openssl".into()),
                source_version: None,
                files: vec![],
            },
        );
        assert_eq!(
            p.purl,
            "pkg:rpm/rocky/openssl-libs@3.0.7-27.el9?arch=x86_64&distro=rocky-9.3&epoch=1&upstream=openssl"
        );
        assert_eq!(
            p.coordinate,
            Some(Coordinate::eco(
                "Rocky Linux:9",
                "openssl",
                "1:3.0.7-27.el9"
            ))
        );
    }
}
