//! Load test for receiving state updates. Needs the mock feature and is ignored by default.
//!
//! The mock sends a long run of numbered value states. The test checks that every record
//! arrives once and in order, and reports the time and the largest backlog.
//!
//! Run:  cargo test --release --features mock --test load_receive -- --ignored --nocapture
//!
//! Settings (environment variables):
//!   FLOOD_RECORDS      records to send (default 1000000)
//!   FLOOD_PER_TABLE    records per value-state table, one event each (default 1000)
//!   FLOOD_CALLBACK_US  microseconds the callback sleeps per table, to simulate a slow
//!                      callback (default 0). Use it to find where the receiver falls behind.

#![cfg(feature = "mock")]

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rs_loxone::auth::Secret;
use rs_loxone::mock::{Flood, MockConfig, start};
use rs_loxone::session::{AsyncHandler, Event, Session, SessionConfig};
use rs_loxone::transport::url::Endpoint;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

#[derive(Default)]
struct Stats {
    /// Records received so far.
    received: u64,
    /// Records that were skipped (a gap in the numbering).
    missing: u64,
    /// Records that arrived after a later one.
    out_of_order: u64,
    /// The number the next record must have.
    next: u64,
    /// Tables (events) received so far.
    tables: u64,
}

#[tokio::test]
#[ignore = "load test: run with --release --features mock --ignored"]
async fn receive_flood_without_loss() {
    let records = env_u64("FLOOD_RECORDS", 1_000_000);
    let per_table = env_u64("FLOOD_PER_TABLE", 1000) as usize;
    let callback_us = env_u64("FLOOD_CALLBACK_US", 0);

    let mock = start(MockConfig {
        flood: Some(Flood { records, per_table }),
        ..MockConfig::default()
    });
    let stats = Arc::new(Mutex::new(Stats::default()));
    let for_callback = stats.clone();
    let handler = AsyncHandler(move |event: Event| {
        let stats = for_callback.clone();
        async move {
            if let Event::ValueStates(values) = event {
                {
                    let mut s = stats.lock().unwrap();
                    s.tables += 1;
                    for (_uuid, value) in values {
                        let v = value as u64;
                        s.received += 1;
                        if v == s.next {
                            s.next += 1;
                        } else if v > s.next {
                            s.missing += v - s.next;
                            s.next = v + 1;
                        } else {
                            s.out_of_order += 1;
                        }
                    }
                }
                if callback_us > 0 {
                    tokio::time::sleep(Duration::from_micros(callback_us)).await;
                }
            }
        }
    });

    let cfg = SessionConfig::new(
        Endpoint::parse(&format!("http://{}", mock.addr())).unwrap(),
        "admin",
        Secret::new("s3cret"),
    );
    let session = Session::connect(cfg, handler).await.unwrap();

    let started = Instant::now();
    let mut max_backlog = 0usize;
    let deadline = started + Duration::from_secs(600);
    loop {
        max_backlog = max_backlog.max(session.event_backlog());
        if stats.lock().unwrap().received >= records || Instant::now() > deadline {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    let elapsed = started.elapsed();
    let final_backlog = session.event_backlog();
    session.close().await;

    let s = stats.lock().unwrap();
    let per_second = s.received as f64 / elapsed.as_secs_f64();
    println!(
        "records sent:      {records} (in {} tables of up to {per_table})",
        records.div_ceil(per_table as u64)
    );
    println!("records received:  {}", s.received);
    println!("missing:           {}", s.missing);
    println!("out of order:      {}", s.out_of_order);
    println!("elapsed:           {:.2} s", elapsed.as_secs_f64());
    println!("throughput:        {per_second:.0} records/s");
    println!("max backlog:       {max_backlog} tables waiting for the callback");
    println!("backlog at end:    {final_backlog}");
    println!("callback delay:    {callback_us} us per table");

    assert_eq!(s.received, records, "every record must arrive");
    assert_eq!(s.missing, 0, "no record may be skipped");
    assert_eq!(s.out_of_order, 0, "records must keep their order");
}
