mod samples;

use virtsec_api::*;

#[test]
fn v1_bytes_are_frozen() {
    for (name, bytes) in samples::all() {
        let path = format!("{}/tests/golden/{name}.hex", env!("CARGO_MANIFEST_DIR"));
        let golden = std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("missing {path}"));
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, golden.trim(), "{name}: the v1 wire format changed");
    }
}

#[test]
fn round_trips() {
    let b = samples::batch();
    assert_eq!(from_cbor::<Batch>(&to_cbor(&b).unwrap()).unwrap(), b);
    let s = samples::status();
    assert_eq!(from_cbor::<Status>(&to_cbor(&s).unwrap()).unwrap(), s);
    let inv = samples::inventory();
    assert_eq!(Inventory::decode(&inv.encode().unwrap()).unwrap(), inv);
}

#[test]
fn unknown_fields_and_versions_are_refused() {
    let mut v: ciborium::Value =
        ciborium::from_reader(to_cbor(&Config::default()).unwrap().as_slice()).unwrap();
    if let ciborium::Value::Map(m) = &mut v {
        m.push(("surprise".into(), true.into()));
    }
    let mut bytes = Vec::new();
    ciborium::into_writer(&v, &mut bytes).unwrap();
    assert!(matches!(
        from_cbor::<Config>(&bytes),
        Err(ApiError::Decode(_))
    ));

    let mut next = samples::inventory();
    next.api_version = API_VERSION + 1;
    assert_eq!(
        Inventory::decode(&next.encode().unwrap()),
        Err(ApiError::UnsupportedVersion(API_VERSION + 1))
    );
    let mut other = samples::inventory();
    other.format = "k3sec-inventory".into();
    assert!(matches!(
        Inventory::decode(&other.encode().unwrap()),
        Err(ApiError::Decode(_))
    ));
}

#[test]
fn settings_default_and_partial_policy_tables() {
    use ciborium::Value;
    let table = Value::Map(vec![
        ("allow_guest_exec".into(), true.into()),
        ("vmids".into(), Value::Array(vec![4001.into()])),
    ]);
    let mut bytes = Vec::new();
    ciborium::into_writer(&table, &mut bytes).unwrap();
    let s: Settings = from_cbor(&bytes).unwrap();
    assert!(s.allow_guest_exec);
    assert_eq!(s.vmids, [4001]);
    assert_eq!(s.allow(), Settings::default().allow());
    assert_eq!(s.backlog_events, 50_000);
    assert!(
        !Settings::default().allow_guest_exec,
        "guest exec is opt-in"
    );
}

#[test]
fn enums_keep_their_v1_names() {
    let name = |v: serde_json::Value| v.as_str().unwrap().to_string();
    assert_eq!(
        [Severity::Info, Severity::Warning, Severity::Critical]
            .map(|s| name(serde_json::to_value(s).unwrap())),
        ["info", "warning", "critical"]
    );
    assert_eq!(
        [Source::Exec, Source::Ebpf, Source::Pve, Source::Config]
            .map(|s| name(serde_json::to_value(s).unwrap())),
        ["exec", "ebpf", "pve", "config"]
    );
    assert_eq!(serde_json::to_value(GuestKind::Qemu).unwrap(), "qemu");
    assert!(Severity::Warning < Severity::Critical);
}

#[test]
fn a_full_batch_of_typical_events_fits_the_envelope() {
    let exec = SecEvent {
        source: Source::Exec,
        kind: "exec".into(),
        severity: Severity::Info,
        message: "/usr/bin/curl  curl -fsS https://example.com/install.sh".into(),
        ..samples::escape_event()
    };
    let full = Batch {
        events: vec![exec; MAX_BATCH_EVENTS],
        ..samples::batch()
    };
    let len = to_cbor(&full).unwrap().len();
    assert!(len < MAX_BATCH_BYTES, "{len} bytes");
}
