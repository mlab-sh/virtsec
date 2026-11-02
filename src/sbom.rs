//! CycloneDX 1.5 JSON SBOMs, one per image digest.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::model::{Inventory, PackageKind};

pub fn cyclonedx(inv: &Inventory) -> Value {
    let components: Vec<Value> = inv
        .packages
        .iter()
        .map(|p| {
            let mut props = vec![
                json!({ "name": "virtsec:reachability", "value": p.reachability.as_str() }),
                json!({ "name": "virtsec:kind", "value": match p.kind {
                    PackageKind::Os => "os", PackageKind::Lang => "lang", PackageKind::Node => "node",
                }}),
            ];
            if let Some(loc) = &p.location {
                props.push(json!({ "name": "virtsec:location", "value": loc }));
            }
            json!({
                "type": if p.kind == PackageKind::Node { "platform" } else { "library" },
                "bom-ref": p.purl,
                "name": p.name,
                "version": p.version,
                "purl": p.purl,
                "properties": props,
            })
        })
        .collect();

    let mut component = json!({
        "type": "container",
        "bom-ref": inv.key(),
        "name": inv.name,
    });
    if let Some(d) = &inv.digest {
        component["version"] = json!(d);
    }
    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            "tools": { "components": [{
                "type": "application", "name": "virtsec", "version": env!("CARGO_PKG_VERSION"),
            }]},
            "component": component,
        },
        "components": components,
    })
}

/// Write `inv`'s SBOM to `<dir>/<digest>.cdx.json`; returns the path.
pub fn write(dir: &Path, inv: &Inventory) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)
        .with_context(|| format!("cannot create SBOM directory {}", dir.display()))?;
    let name: String = inv
        .key()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let path = dir.join(format!("{name}.cdx.json"));
    let body = serde_json::to_vec_pretty(&cyclonedx(inv))?;
    std::fs::write(&path, body).with_context(|| format!("cannot write {}", path.display()))?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Package;

    #[test]
    fn sbom_shape() {
        let inv = Inventory {
            name: "nginx:1.27".into(),
            digest: Some("sha256:abc".into()),
            os: None,
            guest: None,
            packages: vec![Package::new(
                "libssl3",
                "3.0.15-1",
                PackageKind::Os,
                "pkg:deb/debian/libssl3@3.0.15-1?distro=debian-12".into(),
            )],
            mapped_files: 0,
            warnings: vec![],
        };
        let bom = cyclonedx(&inv);
        assert_eq!(bom["bomFormat"], "CycloneDX");
        assert_eq!(bom["metadata"]["component"]["version"], "sha256:abc");
        assert_eq!(
            bom["components"][0]["purl"],
            "pkg:deb/debian/libssl3@3.0.15-1?distro=debian-12"
        );
        assert_eq!(bom["components"][0]["properties"][0]["value"], "dormant");

        let dir = tempfile::tempdir().unwrap();
        let path = write(dir.path(), &inv).unwrap();
        assert!(path.ends_with("sha256_abc.cdx.json"));
    }
}
