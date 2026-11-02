//! Builds the eBPF kernel crate (`crates/virtsec-probe-ebpf`) into the object
//! `src/probe.rs` embeds. Only with the `ebpf` feature, only on Linux; aya-build
//! drives the BPF-target build (nightly, build-std, target, rustflags) itself.

fn main() {
    if std::env::var_os("CARGO_FEATURE_EBPF").is_some() {
        build_ebpf();
    }
}

#[cfg(target_os = "linux")]
fn build_ebpf() {
    let root_dir =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("crates/virtsec-probe-ebpf");
    aya_build::build_ebpf(
        [aya_build::Package {
            name: "virtsec-probe-ebpf",
            root_dir: root_dir.to_str().expect("non-UTF-8 path"),
            no_default_features: false,
            features: &[],
        }],
        aya_build::Toolchain::default(),
    )
    .expect("eBPF build failed");
}

#[cfg(not(target_os = "linux"))]
fn build_ebpf() {
    panic!("the `ebpf` feature is only supported on Linux");
}
