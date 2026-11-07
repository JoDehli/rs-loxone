//! Live check of the preflight values on a real Miniserver. Not run by default.
//!
//! Run with:  cargo test --test live_preflight -- --ignored --nocapture
//! Address and credentials: see `tests/live/token_store.rs` (LOX_HOST, LOX_ENV_FILE).

use std::path::PathBuf;

use rs_loxone::auth::Secret;
use rs_loxone::transport::http::{BootstrapConfig, HttpBootstrap};
use rs_loxone::transport::retry::RetryPolicy;
use rs_loxone::transport::tls::TlsOptions;
use rs_loxone::transport::url::Endpoint;

fn file_setting(key: &str) -> Option<String> {
    let path = std::env::var_os("LOX_ENV_FILE")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(".config/rs-loxone/miniserver.env"))
        })?;
    let text = std::fs::read_to_string(path).ok()?;
    text.lines().find_map(|l| {
        l.strip_prefix(&format!("{key}="))
            .map(|v| v.trim().to_owned())
    })
}

fn setting(key: &str) -> String {
    std::env::var(key)
        .ok()
        .or_else(|| file_setting(key))
        .unwrap_or_else(|| panic!("set {key}, or add it to the credentials file"))
}

#[tokio::test]
#[ignore = "live: needs the Miniserver"]
async fn preflight_values_from_the_real_miniserver() {
    let endpoint = Endpoint::parse(&setting("LOX_HOST")).expect("LOX_HOST");
    let http = HttpBootstrap::new(BootstrapConfig {
        endpoint,
        username: setting("LOX_USER"),
        password: Secret::new(setting("LOX_PASS")),
        tls: TlsOptions::default(),
        retry: RetryPolicy::default(),
        connect_addr: None,
    })
    .expect("bootstrap");

    let key = http.api_key().await.expect("apiKey");
    let api = http.api_config().await.expect("cfg/api");
    println!(
        "apiKey: local={:?}, cfg/api: hasEventSlots={:?}",
        key.local, api.has_event_slots
    );
    assert_eq!(
        api.has_event_slots,
        Some(true),
        "a free event slot is needed for this test"
    );
    assert_eq!(key.local, Some(true), "the test connection is local");
}
