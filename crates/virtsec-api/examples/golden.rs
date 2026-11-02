//! Regenerates the golden CBOR files of the v1 contract:
//! `cargo run -p virtsec-api --example golden`. Only for a new API_VERSION:
//! for v1 these bytes are frozen and the tests compare against them.

#[path = "../tests/samples.rs"]
mod samples;

fn main() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/golden");
    for (name, bytes) in samples::all() {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        std::fs::write(format!("{dir}/{name}.hex"), hex + "\n").expect("write golden file");
        println!("{name}: {} bytes", bytes.len());
    }
}
