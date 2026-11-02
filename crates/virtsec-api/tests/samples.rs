//! Fixed sample values of the v1 contract, shared by the tests and the
//! golden generator. Changing one changes the frozen bytes: don't, for v1.

#![allow(dead_code)]

use std::collections::BTreeMap;

use virtsec_api::inventory::INVENTORY_FORMAT;
use virtsec_api::*;

pub fn escape_event() -> SecEvent {
    SecEvent {
        source: Source::Ebpf,
        timestamp: 1_793_000_000_000,
        kind: "vm_cgroup_write".into(),
        severity: Severity::Critical,
        guest: Some(GuestRef {
            kind: GuestKind::Qemu,
            vmid: 3024,
            name: "web-vm".into(),
        }),
        message: "process in the VM's QEMU cgroup opened /etc/pve/user.cfg for writing (possible VM escape) (bash)".into(),
        metadata: BTreeMap::from([
            ("comm".to_string(), "bash".to_string()),
            ("pid".to_string(), "4242".to_string()),
            ("uid".to_string(), "0".to_string()),
        ]),
        payload: serde_json::Value::Null,
    }
}

pub fn batch() -> Batch {
    Batch {
        api_version: API_VERSION,
        boot_id: "b-0123456789abcdef".into(),
        seq: 7,
        node: "pve".into(),
        events: vec![escape_event()],
        dropped: 3,
        urgent: true,
    }
}

pub fn status() -> Status {
    Status {
        api_version: API_VERSION,
        virtsec_version: "0.1.0".into(),
        boot_id: "b-0123456789abcdef".into(),
        started_at: 1_793_000_000_000,
        node: "pve".into(),
        cluster_id: Some("lab".into()),
        node_info: Some(NodeInfo {
            pve_version: "9.2.2".into(),
            kernel: "7.0.2-6-pve".into(),
            os: "Debian GNU/Linux 13 (trixie)".into(),
        }),
        config: Config::default(),
        allow: Settings::default().allow(),
        allow_guest_exec: false,
        allowed_vmids: vec![],
        sources: vec![SourceState {
            name: "ebpf".into(),
            state: "running".into(),
            error: None,
        }],
        counters: Counters {
            events: 120,
            dropped: 3,
            last_seq: 7,
        },
        guests: 4,
    }
}

pub fn inventory() -> Inventory {
    Inventory {
        format: INVENTORY_FORMAT.into(),
        api_version: API_VERSION,
        generated_at: 1_793_000_000_000,
        node: "pve".into(),
        cluster_id: Some("lab".into()),
        node_info: None,
        guests: vec![GuestInventory {
            guest: Some(GuestInfo {
                kind: GuestKind::Lxc,
                vmid: 4002,
                name: "vs-alpine-priv".into(),
                status: "running".into(),
                risks: vec!["privileged".into(), "mp0 host bind mount /var/log (ro)".into()],
            }),
            name: "vs-alpine-priv".into(),
            os: Some(Os {
                id: "alpine".into(),
                version_id: "3.22.0".into(),
                pretty_name: "Alpine Linux v3.22".into(),
            }),
            packages: vec![Package {
                name: "libssl3".into(),
                version: "3.5.0-r0".into(),
                kind: "os".into(),
                purl: "pkg:apk/alpine/libssl3@3.5.0-r0?arch=x86_64&distro=alpine-3.22.0&upstream=openssl".into(),
                source: Some("openssl".into()),
                location: None,
                reachability: "loaded".into(),
                coordinate: Some(Coordinate {
                    ecosystem: Some("Alpine:v3.22".into()),
                    name: Some("openssl".into()),
                    version: Some("3.5.0-r0".into()),
                    purl: None,
                    cpe: None,
                }),
            }],
            mapped_files: 9,
            warnings: vec![],
        }],
    }
}

pub fn all() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("batch-v1", to_cbor(&batch()).unwrap()),
        ("status-v1", to_cbor(&status()).unwrap()),
        ("config-v1", to_cbor(&Config::default()).unwrap()),
        ("inventory-v1", inventory().encode().unwrap()),
    ]
}
