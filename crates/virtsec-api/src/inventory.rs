//! The inventory document (`inventory` blob): what runs on a PVE node, per
//! guest and for the node itself, with each package's reachability and the
//! coordinate to match it with. Vulnerability matching happens on the mlab
//! side, from these coordinates.

use serde::{Deserialize, Serialize};

use crate::{ApiError, GuestKind};

pub const INVENTORY_FORMAT: &str = "virtsec-inventory";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    /// [`INVENTORY_FORMAT`].
    pub format: String,
    pub api_version: u16,
    /// Unix milliseconds.
    pub generated_at: i64,
    pub node: String,
    pub cluster_id: Option<String>,
    pub node_info: Option<NodeInfo>,
    pub guests: Vec<GuestInventory>,
}

impl Inventory {
    pub fn encode(&self) -> Result<Vec<u8>, ApiError> {
        crate::to_cbor(self)
    }

    /// Decode, refusing another format or contract version.
    pub fn decode(bytes: &[u8]) -> Result<Self, ApiError> {
        let inv: Inventory = crate::from_cbor(bytes)?;
        if inv.format != INVENTORY_FORMAT {
            return Err(ApiError::Decode(format!(
                "not a virtsec inventory: {}",
                inv.format
            )));
        }
        crate::check_version(inv.api_version)?;
        Ok(inv)
    }
}

/// The node's own stack.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeInfo {
    /// `pve-manager` version (`9.2.2`).
    pub pve_version: String,
    /// `7.0.2-6-pve`.
    pub kernel: String,
    /// os-release `PRETTY_NAME`.
    pub os: String,
}

/// One guest's inventory, or the node's (`guest: None`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestInventory {
    pub guest: Option<GuestInfo>,
    /// Guest name, or `node <hostname>`.
    pub name: String,
    /// os-release `ID`, `VERSION_ID`, `PRETTY_NAME`.
    pub os: Option<Os>,
    pub packages: Vec<Package>,
    pub mapped_files: u32,
    /// Non-fatal problems (`stopped: not inspected`, agent unreachable, ...).
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestInfo {
    pub kind: GuestKind,
    pub vmid: u32,
    pub name: String,
    /// `running`, `stopped` or `template`.
    pub status: String,
    /// Isolation weakened by the config (`privileged`, `mp0 host bind mount
    /// /var/log (ro)`, `hostpci0 PCI passthrough`, ...).
    pub risks: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Os {
    pub id: String,
    pub version_id: String,
    pub pretty_name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Package {
    pub name: String,
    pub version: String,
    /// `os`, `lang` or `node`.
    pub kind: String,
    pub purl: String,
    /// Source package, when it differs from `name`.
    pub source: Option<String>,
    /// Lockfile or binary a language dependency was read from.
    pub location: Option<String>,
    /// `loaded`, `dormant` or `unknown`.
    pub reachability: String,
    /// What to ask vuln.mlab.sh `/api/v2/scan` for; `None` = not matchable.
    pub coordinate: Option<Coordinate>,
}

/// A vuln.mlab.sh `ScanCoordinate` (distro packages by source package and
/// version, the PVE stack by CPE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Coordinate {
    pub ecosystem: Option<String>,
    pub name: Option<String>,
    pub version: Option<String>,
    pub purl: Option<String>,
    pub cpe: Option<String>,
}

/// Body of an `sbom` answer, next to the CycloneDX blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SbomInfo {
    /// `None` = the node.
    pub vmid: Option<u32>,
    pub components: u32,
}
