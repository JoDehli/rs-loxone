//! One logged-in connection to a Gen 1 Miniserver.
//!
//! Login, sending commands, decoding frames into events, token refresh. It does not
//! reconnect: that is the `supervisor` module's job. See `SPEC-session.md`.

pub mod commands;
pub mod dispatch;
pub mod event;
pub mod frames;
pub mod login;
pub mod reader;
pub mod refresh;
pub mod secured;

use std::net::SocketAddr;
use std::time::Duration;

use crate::auth::reply::ReplyClass;
use crate::protocol::ll::LlResponse;
use crate::session::login::ensure_200;
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::auth::KeyAndSalt;
use crate::auth::keyexchange::SessionKey;
use crate::auth::store::TokenStore;
use crate::auth::{AuthError, Secret, token::TokenState};
use crate::protocol::ProtocolError;
use crate::transport::TransportError;
use crate::transport::http::{BootstrapConfig, HttpBootstrap};
use crate::transport::keepalive::{
    KEEPALIVE_PERIOD, READ_TIMEOUT, spawn_keepalive, spawn_writer_until,
};
use crate::transport::retry::RetryPolicy;
use crate::transport::tls::TlsOptions;
use crate::transport::url::Endpoint;
use crate::transport::ws::{OPEN_TIMEOUT, WsOptions, connect as ws_connect};

pub use dispatch::{AsyncHandler, EventHandler, SyncHandler};
pub use event::{DisconnectReason, Event};
pub use refresh::RefreshPolicy;

/// Default maximum age of a queued command (30 s).
pub const DEFAULT_MAX_COMMAND_AGE: Duration = Duration::from_secs(30);

/// Configuration for one session.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Where the Miniserver is.
    pub endpoint: Endpoint,
    /// User name.
    pub username: String,
    /// Password.
    pub password: Secret,
    /// A token stored from an earlier session, if any.
    pub token: Option<TokenState>,
    /// TLS settings (used for `https`/`wss` only).
    pub tls: TlsOptions,
    /// Connect to this address instead of resolving the host (CloudDNS local TLS).
    pub connect_addr: Option<SocketAddr>,
    /// Retry settings for the HTTP bootstrap.
    pub retry: RetryPolicy,
    /// Maximum age of a queued command before it is dropped and reported.
    pub max_command_age: Duration,
    /// How token renewal is retried and when it gives up.
    pub refresh: RefreshPolicy,
    /// Refuse to connect if the Miniserver does not see this connection as local.
    pub local_only: bool,
    /// File that keeps the token between runs, if any (see [`crate::auth::store::TokenFile`]).
    pub token_file: Option<crate::auth::store::TokenFile>,
}

impl SessionConfig {
    /// A configuration with defaults for everything except endpoint and credentials.
    pub fn new(endpoint: Endpoint, username: impl Into<String>, password: Secret) -> Self {
        Self {
            endpoint,
            username: username.into(),
            password,
            token: None,
            tls: TlsOptions::default(),
            connect_addr: None,
            retry: RetryPolicy::default(),
            max_command_age: DEFAULT_MAX_COMMAND_AGE,
            refresh: RefreshPolicy::default(),
            local_only: false,
            token_file: None,
        }
    }
}

/// Errors from the session.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SessionError {
    /// A transport error (connect, HTTP, WebSocket).
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// An auth error (keys, hashes, tokens).
    #[error(transparent)]
    Auth(#[from] AuthError),
    /// A protocol error (frames, envelopes).
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    /// Preflight: the Miniserver has no free event slot for state updates right now.
    #[error("the Miniserver has no free event slot")]
    NoEventSlots,
    /// Preflight: `local_only` is set and the Miniserver sees this connection as remote.
    #[error("the connection is not local, and local_only is set")]
    NotLocal,
    /// The Miniserver answered with a non-success code.
    #[error("rejected with code {code} ({class:?})")]
    Rejected { code: i64, class: ReplyClass },
    /// A command was refused because the session is not logged in.
    #[error("not authenticated")]
    NotAuthenticated,
    /// A reply did not arrive in time.
    #[error("timeout waiting for reply")]
    Timeout,
    /// The session has ended.
    #[error("session closed")]
    Closed,
    /// The Miniserver reported that it is out of service during login.
    #[error("the Miniserver is out of service")]
    OutOfService,
    /// The visualization code was wrong (the Miniserver answered 500).
    #[error("wrong visualization code")]
    WrongVisuCode,
}

/// Warning for a password sent over plain HTTP. The bootstrap GETs use HTTP Basic auth,
/// so over `http://` the password crosses the network unencrypted. Gen 1 Miniservers
/// only offer plain HTTP, so this is a warning, not an error.
pub fn plain_http_warning(endpoint: &Endpoint, password: &Secret) -> Option<String> {
    (endpoint.scheme == crate::transport::url::Scheme::Http && !password.expose().is_empty())
        .then(|| {
            format!(
                "password is sent unencrypted to {} (http://). Use https:// if the Miniserver supports it.",
                endpoint.host
            )
        })
}

/// How long closing waits for each background task.
pub const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// The background tasks of a session.
struct Tasks {
    writer: JoinHandle<Result<(), TransportError>>,
    reader: JoinHandle<()>,
    dispatcher: JoinHandle<()>,
    refresh: JoinHandle<()>,
}

/// A logged-in connection. Created by [`Session::connect`].
pub struct Session {
    /// HTTP client for the structure file.
    http: HttpBootstrap,
    /// User name, needed for `getvisusalt` and the token commands.
    username: String,
    /// Sending side: encryption, queue, requests. Shared with the refresh task and reader.
    shared: Arc<commands::Shared>,
    /// Session key (AES key and IV).
    session_key: SessionKey,
    /// getkey2 key and salt (its hash algorithm is used for refresh).
    key2: KeyAndSalt,
    /// The token in use. Shared with the refresh task.
    token: Arc<std::sync::Mutex<TokenState>>,
    tasks: Tasks,
    /// True if login used the stored token instead of the password.
    used_stored_token: bool,
}

impl Session {
    /// Open the connection, log in, enable state updates, and start delivering events to
    /// `handler`. The first events are `TokenChanged` and `Connected`.
    pub async fn connect<H: EventHandler>(
        cfg: SessionConfig,
        handler: H,
    ) -> Result<Session, SessionError> {
        if let Some(warning) = plain_http_warning(&cfg.endpoint, &cfg.password) {
            eprintln!("rs-loxone: {warning}");
        }
        let http = HttpBootstrap::new(BootstrapConfig {
            endpoint: cfg.endpoint.clone(),
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            tls: cfg.tls.clone(),
            retry: cfg.retry,
            connect_addr: cfg.connect_addr,
        })?;
        let info = http.api_key().await?;
        // Preflight. A probe that fails is no verdict: the WebSocket attempt still runs.
        if cfg.local_only && info.local == Some(false) {
            return Err(SessionError::NotLocal);
        }
        if let Ok(api) = http.api_config().await
            && api.has_event_slots == Some(false)
        {
            return Err(SessionError::NoEventSlots);
        }
        let pem = http.public_key_pem().await?;

        let ws_opts = WsOptions {
            tls: cfg.tls.clone(),
            connect_addr: cfg.connect_addr,
            open_timeout: OPEN_TIMEOUT,
        };
        let (sender, mut receiver) = ws_connect(&cfg.endpoint, &ws_opts).await?;
        let activity = receiver.activity();
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        let (out, writer) = spawn_writer_until(sender, stop_rx);

        let login = login::login(&out, &mut receiver, &cfg, info.version, &pem).await?;
        let keepalive = spawn_keepalive(out.clone(), activity, KEEPALIVE_PERIOD, READ_TIMEOUT);

        let (events, rx) = mpsc::unbounded_channel();

        let waiter: reader::WaiterSlot = Arc::new(std::sync::Mutex::new(reader::Slot::default()));
        let backlog = Arc::new(commands::Backlog::new(commands::BACKLOG_WARN_AT));
        let shared = commands::Shared::new(
            out,
            login.cipher,
            events,
            cfg.max_command_age,
            waiter,
            stop_tx,
            backlog.clone(),
        );
        // The first events go through `emit` so that the backlog count stays correct.
        shared.emit(Event::LoggedIn {
            used_stored_token: login.used_stored_token,
        });
        shared.emit(Event::TokenChanged(login.token.clone()));
        shared.emit(Event::Connected);
        let used_stored_token = login.used_stored_token;
        let store = cfg
            .token_file
            .clone()
            .map(|file| TokenStore::new(file, cfg.endpoint.clone(), cfg.username.clone()));
        if let Some(store) = &store {
            store.save_off_thread(login.token.clone()).await;
        }
        let token = Arc::new(std::sync::Mutex::new(login.token));

        let reader = tokio::spawn(reader::run(receiver, shared.clone(), keepalive));
        let dispatcher = tokio::spawn(dispatch::run(rx, handler, backlog.clone()));
        let refresh = tokio::spawn(refresh::run(
            shared.clone(),
            token.clone(),
            login.key2.clone(),
            cfg.username.clone(),
            info.version,
            cfg.refresh,
            store,
        ));

        shared.set_ready().await?;
        Ok(Session {
            http,
            username: cfg.username.clone(),
            shared,
            session_key: login.session_key,
            key2: login.key2,
            used_stored_token,
            token,
            tasks: Tasks {
                writer,
                reader,
                dispatcher,
                refresh,
            },
        })
    }

    /// Fetch the structure file (`/data/LoxAPP3.json`) as the Miniserver sent it.
    /// The caller parses it and keeps its own cache.
    pub async fn structure(&self) -> Result<crate::transport::http::StructureFile, SessionError> {
        Ok(self.http.structure_file().await?)
    }

    /// The structure file's timestamp (`lastModified`) from the Miniserver, via
    /// `jdev/sps/LoxAPPversion3`. Compare it with your cached copy to decide whether to
    /// download the file again.
    pub async fn structure_version(&self) -> Result<String, SessionError> {
        let reply = self
            .request("jdev/sps/LoxAPPversion3", "LoxAPPversion3")
            .await?;
        ensure_200(&reply)?;
        Ok(reply.value)
    }

    /// Events that have been received but not yet handled by the callbacks.
    pub fn event_backlog(&self) -> usize {
        self.shared.backlog.waiting()
    }

    /// Send a command (encrypted). Returns its id. Does not wait for a reply.
    pub async fn send_command(&self, command: &str) -> Result<u64, SessionError> {
        self.shared.send_command(command).await
    }

    /// Send a command and wait for the first reply whose control contains `needle`.
    pub async fn request(&self, command: &str, needle: &str) -> Result<LlResponse, SessionError> {
        self.shared.request(command, &[needle]).await
    }

    /// Resolve when the session has ended, with the reason. Used by the supervisor.
    pub async fn wait_ended(&self) -> DisconnectReason {
        let mut stop = self.shared.stop_signal();
        while !*stop.borrow() {
            if stop.changed().await.is_err() {
                break;
            }
        }
        self.shared
            .stop_reason()
            .unwrap_or(DisconnectReason::Requested)
    }

    /// True if login used the stored token (`authwithtoken`) instead of the password.
    pub fn used_stored_token(&self) -> bool {
        self.used_stored_token
    }

    /// The token in use (a copy; treat it as a secret).
    pub fn token(&self) -> TokenState {
        self.token.lock().expect("token lock poisoned").clone()
    }

    /// The getkey2 key and salt of this session (treat the key as a secret).
    pub fn key2(&self) -> &KeyAndSalt {
        &self.key2
    }

    /// The session key (treat as a secret).
    pub fn session_key(&self) -> &SessionKey {
        &self.session_key
    }

    /// Close the session. Sends a close frame, delivers `Disconnected { Requested }` to the
    /// callbacks, and waits (at most [`CLOSE_TIMEOUT`] per task) until the background tasks
    /// have ended. Returns after the last event has been handled.
    /// Revoke the token this session uses (`killtoken`), then end the session. Afterwards the
    /// Miniserver refuses that token (401 on `authwithtoken`). The command is encrypted, the
    /// token goes in plain text, as the Miniserver expects. It gets no reply.
    pub async fn kill_token(self) -> Result<(), SessionError> {
        let command =
            crate::auth::commands::kill_token(self.token().token().expose(), &self.username);
        self.send_command(&command).await?;
        // The writer sends the command in its own task. Give it time before the close.
        tokio::time::sleep(Duration::from_secs(1)).await;
        self.close().await;
        Ok(())
    }

    pub async fn close(self) {
        self.shared.stop(DisconnectReason::Requested);
        let Tasks {
            writer,
            reader,
            dispatcher,
            refresh,
        } = self.tasks;
        refresh.abort();
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, reader).await;
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, writer).await;
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, dispatcher).await;
    }
}

#[cfg(test)]
mod warning_tests {
    use super::*;
    use crate::transport::url::Endpoint;

    #[test]
    fn plain_http_with_password_warns() {
        let ep = Endpoint::parse("http://10.0.0.10").unwrap();
        assert!(plain_http_warning(&ep, &Secret::new("pw")).is_some());
    }

    #[test]
    fn https_does_not_warn() {
        let ep = Endpoint::parse("https://10.0.0.10").unwrap();
        assert!(plain_http_warning(&ep, &Secret::new("pw")).is_none());
    }

    #[test]
    fn empty_password_does_not_warn() {
        let ep = Endpoint::parse("http://10.0.0.10").unwrap();
        assert!(plain_http_warning(&ep, &Secret::new("")).is_none());
    }
}
