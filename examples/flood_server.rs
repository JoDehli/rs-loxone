//! A fake Miniserver that sends a flood of numbered state updates, for load tests.
//!
//! Run it in its own terminal, then point the load test at the address it prints:
//!
//!   FLOOD_RECORDS=200000 FLOOD_PER_TABLE=1 cargo run --release --features mock --example flood_server
//!   LOAD_ADDR=127.0.0.1:<port> FLOOD_RECORDS=200000 FLOOD_PER_TABLE=1 \
//!     cargo test --release --features mock --test load_receive -- --ignored --nocapture
//!
//! Stop it with Ctrl-C. The settings must match the load test's settings.

use std::time::Duration;

use rs_loxone::mock::{Flood, MockConfig, start};

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let records = env_u64("FLOOD_RECORDS", 1_000_000);
    let per_table = env_u64("FLOOD_PER_TABLE", 1000) as usize;
    let mock = start(MockConfig {
        flood: Some(Flood { records, per_table }),
        ..MockConfig::default()
    });
    println!(
        "flood server on {}: {records} records, {per_table} per table",
        mock.addr()
    );
    println!("waiting for a client (Ctrl-C to stop)");
    loop {
        std::thread::sleep(Duration::from_secs(3600));
    }
}
