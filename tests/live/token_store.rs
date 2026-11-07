//! Live test: a token saved by one connect is used by the next connect, and no new token is
//! requested. Not run by default.
//!
//! Run with:  cargo test --test live_token_store -- --ignored --nocapture
//! The address comes from LOX_HOST. Credentials come from the file named by LOX_ENV_FILE, or
//! `.config/rs-loxone/miniserver.env` in your home folder. Only lengths and flags are printed,
//! never the password or the token.

use std::path::PathBuf;

use rs_loxone::auth::Secret;
use rs_loxone::auth::store::TokenFile;
use rs_loxone::session::{AsyncHandler, Event, Session, SessionConfig};
use rs_loxone::transport::url::Endpoint;

/// One setting from the credentials file, if the file has it.
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

fn config(endpoint: &Endpoint, user: &str, pass: &str) -> SessionConfig {
    SessionConfig::new(endpoint.clone(), user, Secret::new(pass))
}

#[tokio::test]
#[ignore = "live: needs the Miniserver and credentials"]
async fn token_saved_by_one_connect_is_used_by_the_next() {
    let host = setting("LOX_HOST");
    let user = setting("LOX_USER");
    let pass = setting("LOX_PASS");
    let endpoint = Endpoint::parse(&host).expect("LOX_HOST");

    let dir = std::env::temp_dir().join(format!("rs-loxone-live-token-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = TokenFile::new(dir.join("token.json"));

    // 1. Connect without a token: password login.
    let first = Session::connect(
        config(&endpoint, &user, &pass),
        AsyncHandler(|_: Event| async {}),
    )
    .await
    .expect("first connect");
    assert!(
        !first.used_stored_token(),
        "first connect must use the password"
    );
    let issued = first.token();
    println!(
        "first connect: password login, token length {}",
        issued.token().expose().len()
    );
    file.save(&endpoint, &user, &issued).expect("save token");
    first.close().await;

    // 2. Load the saved token and connect again.
    let stored = file
        .load(&endpoint, &user)
        .expect("the saved token must read back for the same endpoint and user");
    assert_eq!(stored.token().expose(), issued.token().expose());

    let mut cfg = config(&endpoint, &user, &pass);
    cfg.token = Some(stored.clone());
    let second = Session::connect(cfg, AsyncHandler(|_: Event| async {}))
        .await
        .expect("second connect");
    assert!(
        second.used_stored_token(),
        "second connect must use the stored token"
    );
    assert_eq!(
        second.token().token().expose(),
        stored.token().expose(),
        "no new token was issued"
    );
    println!("second connect: stored token used, no new token");
    second.close().await;

    std::fs::remove_dir_all(dir).unwrap();
}
