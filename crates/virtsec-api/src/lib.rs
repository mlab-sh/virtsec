//! What mlab can ask the `virtsec` tool, through the workspace agent
//! (`mlab-agent`), and what the tool sends on its own: op names, their CBOR
//! arguments and answers, events, and the frozen v1 wire schema of
//! [`SecEvent`]s, guest inventories and SBOM descriptors. Spec: the wiki's
//! `Tool-API` page.
//!
//! The agent routes these as opaque bytes; only mlab and `virtsec serve`
//! decode them. This crate depends on nothing of virtsec so the mlab backend
//! can import it alone.
//!
//! **Compatibility.** Every struct refuses unknown fields. Adding a field is
//! a new [`API_VERSION`]; mlab must accept the versions it knows and refuse
//! the others ([`check_version`]).

#![forbid(unsafe_code)]

pub mod inventory;

use std::collections::BTreeMap;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

pub use inventory::{
    Coordinate, GuestInfo, GuestInventory, Inventory, NodeInfo, Os, Package, SbomInfo,
};

/// The tool name in `Request.tool`.
pub const TOOL: &str = "virtsec";

/// Version of this contract (ops, events, every type below).
pub const API_VERSION: u16 = 1;

/// Largest encoded [`Batch`]: an event must fit the agent's 1 MiB envelope
/// with room for the envelope, HPKE and the `Event {tool, name}` wrapper.
pub const MAX_BATCH_BYTES: usize = 768 * 1024;

/// Most events in one [`Batch`].
pub const MAX_BATCH_EVENTS: usize = 2_000;

/// Batches `events_since` returns at most in one answer.
pub const MAX_BATCHES_PER_ANSWER: u32 = 1;

pub mod op {
    /// No arguments. Answer: [`super::Status`].
    pub const STATUS: &str = "status";
    /// Arguments: [`super::Config`]. Answer: [`super::Configured`]. The
    /// config is clamped to the local policy ([`super::Settings`]).
    pub const CONFIGURE: &str = "configure";
    /// Arguments: [`super::EventsSince`]. Answer: [`super::Backlog`]. To fill
    /// the gaps of best-effort `batch` events.
    pub const EVENTS_SINCE: &str = "events_since";
    /// Arguments: [`super::InventoryRequest`] + upload target. Answer: a blob
    /// (the CBOR [`super::Inventory`]) and an [`super::InventoryInfo`] body.
    pub const INVENTORY: &str = "inventory";
    /// Arguments: [`super::SbomRequest`] + upload target. Answer: a blob (the
    /// CycloneDX 1.5 JSON) and a [`super::SbomInfo`] body.
    pub const SBOM: &str = "sbom";
    /// No arguments. Answer: [`super::Audit`], the node's and its guests'
    /// security posture (config checks, restart / reboot needed). Added in
    /// v1: an older tool answers it `unknown op`.
    pub const AUDIT: &str = "audit";

    pub const ALL: [&str; 6] = [STATUS, CONFIGURE, EVENTS_SINCE, INVENTORY, SBOM, AUDIT];
}

pub mod event {
    /// Body: [`super::Batch`]. Runtime events, in order, best effort.
    pub const BATCH: &str = "batch";
    /// Body: [`super::Status`]. Heartbeat, every minute and on change.
    pub const STATUS: &str = "status";
    /// Body: [`super::InventoryReady`]. A guest or the node was
    /// (re)inventoried: fetch it with `inventory` / `sbom`.
    pub const INVENTORY_READY: &str = "inventory_ready";
}

/// Encode a contract value as CBOR.
pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, ApiError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| ApiError::Encode(e.to_string()))?;
    Ok(out)
}

/// Decode a contract value from CBOR (unknown fields are refused).
pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    ciborium::from_reader(bytes).map_err(|e| ApiError::Decode(e.to_string()))
}

/// Refuse a document from a contract version this build doesn't know.
pub fn check_version(version: u16) -> Result<(), ApiError> {
    if version == API_VERSION {
        Ok(())
    } else {
        Err(ApiError::UnsupportedVersion(version))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiError {
    Encode(String),
    Decode(String),
    UnsupportedVersion(u16),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Encode(e) => write!(f, "virtsec-api encode: {e}"),
            ApiError::Decode(e) => write!(f, "virtsec-api decode: {e}"),
            ApiError::UnsupportedVersion(v) => {
                write!(
                    f,
                    "virtsec-api version {v} unsupported (this build: {API_VERSION})"
                )
            }
        }
    }
}

impl std::error::Error for ApiError {}

// ---------------------------------------------------------------------------
// SecEvent v1

/// Where an event comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Source {
    /// A program started in a guest (proc connector, or eBPF when loaded).
    Exec,
    /// eBPF: outbound TCP connects, sensitive file writes.
    Ebpf,
    /// pvedaemon / pveproxy / sshd journal: logins, auth failures, tasks.
    Pve,
    /// Guest configs and states: created, removed, started, risks.
    Config,
}

/// Normalized severity, ordered `info < warning < critical`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// `lxc` or `qemu`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GuestKind {
    Lxc,
    Qemu,
}

/// The guest an event is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRef {
    pub kind: GuestKind,
    pub vmid: u32,
    /// LXC hostname or VM name (`?` when unknown at the time).
    pub name: String,
}

/// One security event.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecEvent {
    pub source: Source,
    /// Unix milliseconds, UTC.
    pub timestamp: i64,
    /// `exec`, `vm_cgroup_exec`, `connect`, `vm_cgroup_connect`, `file_write`,
    /// `vm_cgroup_write`, `auth_failure`, `login`, `task`, `ssh_login`,
    /// `ssh_failure`, `guest_created`, `guest_removed`, `started`, `stopped`,
    /// `risk_added`, `risk_removed`, `listen` (source `config`), `boot_execs`
    /// (source `exec`).
    pub kind: String,
    pub severity: Severity,
    /// `None` for node-level events (API logins, SSH).
    pub guest: Option<GuestRef>,
    pub message: String,
    /// Flat fields: `pid`, `ppid`, `uid`, `comm`, `user`, `rhost`, `task`,
    /// `vmid`, `dest`, `proto`, `addr` (`listen`), `count` (`boot_execs`).
    pub metadata: BTreeMap<String, String>,
    /// Raw detail; `null` when none. Connects carry `{"dest": "ip:port"}`.
    pub payload: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Events stream

/// A run of events. `seq` increases by one per batch within a `boot_id` (one
/// `virtsec serve` process); a gap means lost batches, recovered with
/// `events_since`. A new `boot_id` starts again at 1: what the previous
/// process didn't deliver is gone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Batch {
    pub api_version: u16,
    pub boot_id: String,
    pub seq: u64,
    /// The PVE node the events were seen on.
    pub node: String,
    pub events: Vec<SecEvent>,
    /// Events dropped (buffer full) since the previous batch. Never silent.
    pub dropped: u64,
    /// Flushed early because it holds a critical event.
    pub urgent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EventsSince {
    pub boot_id: String,
    /// The last `seq` mlab has; answers start at `after_seq + 1`.
    pub after_seq: u64,
}

/// What `events_since` answers. With another `boot_id` than asked (the
/// tool restarted), `batches` start the new run and the old one is lost.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backlog {
    pub boot_id: String,
    /// At most [`MAX_BATCHES_PER_ANSWER`]; ask again from the last `seq`.
    pub batches: Vec<Batch>,
    /// Oldest `seq` still held (older ones were evicted: lost).
    pub oldest_seq: u64,
    /// Last `seq` built.
    pub last_seq: u64,
}

// ---------------------------------------------------------------------------
// Config

/// Which sources run. Each is also capped by the local policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sources {
    /// Kernel events: exec (eBPF, else the proc connector), connects and
    /// sensitive writes (eBPF only).
    pub ebpf: bool,
    /// pvedaemon / pveproxy / sshd journal.
    pub journal: bool,
    /// Guest config and state changes.
    pub config: bool,
    /// Package inventory of the guests and the node (reachability, SBOM).
    pub inventory: bool,
}

/// What mlab chooses (`configure`), within the local policy's [`Settings`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub sources: Sources,
    /// eBPF kinds (`exec`, `connect`, `file_write`); empty = all.
    pub kinds: Vec<String>,
    /// Guests to watch and inventory; empty = every guest the policy allows.
    pub vmids: Vec<u32>,
    /// Events below are not sent.
    pub min_severity: Severity,
    /// Inspect VMs from the inside through qemu-guest-agent (read-only
    /// commands in the guest). Only when the policy sets `allow_guest_exec`.
    pub guest_exec: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            sources: Sources {
                ebpf: true,
                journal: true,
                config: true,
                inventory: true,
            },
            kinds: Vec::new(),
            vmids: Vec::new(),
            min_severity: Severity::Info,
            guest_exec: false,
        }
    }
}

/// `configure`'s answer: what is in force now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Configured {
    pub config: Config,
    /// What the local policy cut, in words (`journal not allowed by policy`).
    pub clamped: Vec<String>,
}

/// The tool's table in the agent's local policy (`[tools.virtsec.settings]`),
/// written by the host admin, never by mlab: the ceiling of every [`Config`].
/// Flat on purpose (booleans, lists): mlab's policy editor writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Settings {
    /// Sources mlab may turn on.
    pub allow_ebpf: bool,
    pub allow_journal: bool,
    pub allow_config: bool,
    pub allow_inventory: bool,
    /// Whether mlab may have read-only commands run inside VMs. Off by default.
    pub allow_guest_exec: bool,
    /// Guests mlab may watch; empty = all.
    pub vmids: Vec<u32>,
    /// Events held for `events_since` (memory bound).
    pub backlog_events: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            allow_ebpf: true,
            allow_journal: true,
            allow_config: true,
            allow_inventory: true,
            allow_guest_exec: false,
            vmids: Vec::new(),
            backlog_events: 50_000,
        }
    }
}

impl Settings {
    /// The sources this policy lets mlab turn on.
    pub fn allow(&self) -> Sources {
        Sources {
            ebpf: self.allow_ebpf,
            journal: self.allow_journal,
            config: self.allow_config,
            inventory: self.allow_inventory,
        }
    }
}

// ---------------------------------------------------------------------------
// Status

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub api_version: u16,
    pub virtsec_version: String,
    pub boot_id: String,
    /// Unix milliseconds.
    pub started_at: i64,
    pub node: String,
    /// The PVE cluster name (`corosync.conf`), else the node name: what
    /// mlab groups nodes by.
    pub cluster_id: Option<String>,
    pub node_info: Option<NodeInfo>,
    pub config: Config,
    /// The policy ceiling, as mlab may show it.
    pub allow: Sources,
    pub allow_guest_exec: bool,
    pub allowed_vmids: Vec<u32>,
    pub sources: Vec<SourceState>,
    pub counters: Counters,
    /// Guests inventoried so far.
    pub guests: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceState {
    /// `ebpf`, `exec`, `journal`, `config`, `inventory`.
    pub name: String,
    /// `running`, `off` (config or policy), `failed`.
    pub state: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counters {
    /// Events put in batches.
    pub events: u64,
    /// Events dropped because the buffer was full.
    pub dropped: u64,
    /// Last batch `seq` built.
    pub last_seq: u64,
}

// ---------------------------------------------------------------------------
// Inventory / SBOM ops

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryRequest {
    /// One guest, or every guest and the node.
    pub vmid: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SbomRequest {
    /// One guest; `None` = the node itself.
    pub vmid: Option<u32>,
}

/// Body of an `inventory` answer, next to the blob.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryInfo {
    /// Inventories in the blob (the node counts as one).
    pub guests: u32,
    pub packages: u32,
}

/// `audit`'s answer: the checks that failed, node first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Audit {
    pub api_version: u16,
    /// Unix milliseconds.
    pub generated_at: i64,
    pub node: String,
    pub checks: Vec<AuditCheck>,
}

/// One failed check (the wiki's `Audit` page lists them).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditCheck {
    /// Stable id: `firewall.datacenter`, `users.no_second_factor`,
    /// `backup.missing`, `restart_needed`, `guest.risk`, ...
    pub id: String,
    pub severity: Severity,
    /// The guest it is about; `None` for the node.
    pub guest: Option<GuestRef>,
    pub message: String,
    /// What to change, in words.
    pub fix: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InventoryReady {
    /// `None` = the node.
    pub vmid: Option<u32>,
    pub name: String,
    pub packages: u32,
    /// Packages tagged loaded.
    pub loaded: u32,
}
