//! Connect to a Miniserver and print what it sends, in a readable form.
//!
//! This is a test of the library and an example of how to use it:
//! 1. find the Miniserver (type an address, or press Enter to search the network),
//! 2. ask for the user and the password (the password is not shown while typing),
//! 3. read the structure file, so state UUIDs are shown with their names,
//! 4. start the supervisor, which connects, reconnects and keeps the token fresh,
//! 5. print every event until you press Enter.
//!
//! Run:  cargo run --example connect
//!
//! For scripted runs, set LOX_PASS in the environment; the password prompt is then skipped.

use std::io::{self, BufRead, Write};
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use rs_loxone::auth::Secret;
use rs_loxone::protocol::Uuid;
use rs_loxone::session::{AsyncHandler, Event, SessionConfig};
use rs_loxone::structure::Structure;
use rs_loxone::supervisor;
use rs_loxone::transport::http::{BootstrapConfig, HttpBootstrap};
use rs_loxone::transport::retry::RetryPolicy;
use rs_loxone::transport::tls::TlsOptions;
use rs_loxone::transport::url::Endpoint;
use tokio::net::UdpSocket;

/// Width of the name column, so the UUIDs line up.
const LABEL_WIDTH: usize = 50;
const DISCOVER_SECONDS: u64 = 5;

/// Read one line after showing `label`. Returns the trimmed text.
fn ask(label: &str) -> String {
    print!("{label}: ");
    io::stdout().flush().ok();
    let mut line = String::new();
    io::stdin().lock().read_line(&mut line).ok();
    line.trim().to_owned()
}

/// Find Miniservers on the local network, as the Loxone discovery does: a UDP broadcast
/// to port 7070, answered from port 7071 with a line like `LoxLIVE:... <ip>:<port> ...`.
async fn discover() -> Vec<(SocketAddrV4, String)> {
    let mut found: Vec<(SocketAddrV4, String)> = Vec::new();
    let Ok(socket) = UdpSocket::bind("0.0.0.0:7071").await else {
        return found;
    };
    if socket.set_broadcast(true).is_err() {
        return found;
    }
    for _ in 0..3 {
        let _ = socket.send_to(&[0u8], "255.255.255.255:7070").await;
    }
    let deadline = Instant::now() + Duration::from_secs(DISCOVER_SECONDS);
    let mut buf = [0u8; 1024];
    while let Ok(Ok((n, _))) =
        tokio::time::timeout_at(deadline.into(), socket.recv_from(&mut buf)).await
    {
        let text = String::from_utf8_lossy(&buf[..n]).to_string();
        if !text.starts_with("LoxLIVE:") {
            continue;
        }
        let addr = text
            .split_whitespace()
            .find_map(|token| token.parse::<SocketAddrV4>().ok());
        if let Some(addr) = addr
            && !found.iter().any(|(known, _)| *known == addr)
        {
            found.push((addr, text.trim().to_owned()));
        }
    }
    found
}

/// Ask for the Miniserver address: typed, or chosen from a discovery result.
async fn choose_address() -> String {
    let typed = ask("Miniserver address (e.g. 192.168.1.10:8080), Enter = search the network");
    if !typed.is_empty() {
        return typed;
    }
    println!("searching the local network ({DISCOVER_SECONDS} s) ...");
    let found = discover().await;
    match found.len() {
        0 => {
            println!("no Miniserver answered. Type the address instead.");
            ask("Miniserver address")
        }
        1 => {
            println!("found one Miniserver: {}", found[0].0);
            found[0].0.to_string()
        }
        n => {
            for (i, (addr, reply)) in found.iter().enumerate() {
                let shown: String = reply.chars().take(60).collect();
                println!("  {}) {addr}   {shown}", i + 1);
            }
            loop {
                let answer = ask(&format!("choose [1-{n}]"));
                if let Some(addr) = answer
                    .parse::<usize>()
                    .ok()
                    .and_then(|i| found.get(i.wrapping_sub(1)))
                {
                    return addr.0.to_string();
                }
                println!("not a valid choice");
            }
        }
    }
}

/// Numbers without noise: `1013`, `3.5`, `0.3333`.
fn format_value(value: f64) -> String {
    if value.fract() == 0.0 && value.abs() < 1e15 {
        format!("{value:.0}")
    } else {
        format!("{value:.4}").trim_end_matches('0').to_owned()
    }
}

/// Current time as `HH:MM:SS` (UTC), without extra crates.
fn clock() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format!(
        "{:02}:{:02}:{:02}",
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}

/// Terminal colors. Off when the NO_COLOR variable is set (https://no-color.org).
struct Style {
    on: bool,
}

impl Style {
    fn new() -> Self {
        Self {
            on: std::env::var_os("NO_COLOR").is_none(),
        }
    }

    /// Wrap `text` in an ANSI code, or return it unchanged.
    fn paint(&self, code: &str, text: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_owned()
        }
    }

    fn time(&self, text: &str) -> String {
        self.paint("33", text) // yellow
    }

    fn uuid(&self, text: &str) -> String {
        self.paint("2;34", text) // dim blue
    }

    fn kind(&self, text: &str) -> String {
        self.paint("36", text) // cyan
    }

    fn ok(&self, text: &str) -> String {
        self.paint("32", text) // green
    }

    fn bad(&self, text: &str) -> String {
        self.paint("31", text) // red
    }

    fn note(&self, text: &str) -> String {
        self.paint("2", text) // dim
    }
}

/// One line per event. Tokens and keys are never printed.
fn describe(event: &Event, structure: &Structure, style: &Style) -> Vec<String> {
    let now = style.time(&clock());
    let label_of = |uuid: &Uuid| {
        structure
            .label(&uuid.to_string())
            .unwrap_or_default()
            .to_owned()
    };
    // The label is padded before it is colored, so the columns still line up.
    let column = |uuid: &Uuid| {
        format!(
            "{:<LABEL_WIDTH$}  {}",
            label_of(uuid),
            style.uuid(&format!("[{uuid}]"))
        )
    };
    match event {
        Event::Connected => vec![format!(
            "{now}  {}",
            style.ok("✔ connected, state updates on")
        )],
        Event::TokenChanged(t) => vec![format!(
            "{now}  {}",
            style.note(&format!(
                "🔑 token renewed, valid until {:.0}",
                t.valid_until()
            ))
        )],
        Event::ValueStates(values) => values
            .iter()
            .map(|(uuid, value)| {
                format!(
                    "{now}  {}  {}  {}",
                    style.kind("state"),
                    column(uuid),
                    format_value(*value)
                )
            })
            .collect(),
        Event::TextStates(texts) => texts
            .iter()
            .map(|(uuid, text)| {
                format!(
                    "{now}  {}  {}  \"{text}\"",
                    style.kind("text "),
                    column(uuid)
                )
            })
            .collect(),
        Event::Text(ll) => vec![format!(
            "{now}  {}  {}  code={}",
            style.kind("reply"),
            ll.control,
            if ll.code == 200 {
                style.ok(&ll.code.to_string())
            } else {
                style.bad(&ll.code.to_string())
            }
        )],
        Event::Raw { kind, bytes } => vec![format!(
            "{now}  {}",
            style.note(&format!("· {kind:?} message, {} bytes", bytes.len()))
        )],
        Event::CommandDropped { id, age } => vec![format!(
            "{now}  {}",
            style.bad(&format!("✖ command {id} dropped, {age:?} old"))
        )],
        Event::Reconnecting {
            attempt,
            wait,
            reason,
        } => vec![format!(
            "{now}  {}",
            style.bad(&format!(
                "↻ reconnect attempt {attempt} in {wait:?} ({reason})"
            ))
        )],
        Event::GaveUp { reason } => vec![format!(
            "{now}  {}",
            style.bad(&format!("⛔ gave up: {reason}"))
        )],
        Event::AuthFailed { reason } => vec![format!(
            "{now}  {}",
            style.bad(&format!("⚠ auth failed: {reason}"))
        )],
        Event::Disconnected { reason } => vec![format!(
            "{now}  {}",
            style.bad(&format!("✖ disconnected: {reason:?}"))
        )],
    }
}

#[tokio::main]
async fn main() {
    println!("rs-loxone connection test");
    println!("-------------------------");
    let host = choose_address().await;
    let user = ask("User");
    let password = std::env::var("LOX_PASS").unwrap_or_else(|_| {
        rpassword::prompt_password("Password (not shown): ").unwrap_or_default()
    });

    let endpoint = match Endpoint::parse(&host) {
        Ok(endpoint) => endpoint,
        Err(err) => {
            eprintln!("invalid address: {err}");
            return;
        }
    };

    // The structure file gives the names of the controls and their states.
    let structure = match HttpBootstrap::new(BootstrapConfig {
        endpoint: endpoint.clone(),
        username: user.clone(),
        password: Secret::new(password.clone()),
        tls: TlsOptions::default(),
        retry: RetryPolicy::default(),
        connect_addr: None,
    }) {
        Ok(http) => match http.structure_file().await {
            Ok(file) => match Structure::parse(&file.bytes) {
                Ok(structure) => structure,
                Err(err) => {
                    eprintln!("structure file not usable: {err}");
                    return;
                }
            },
            Err(err) => {
                eprintln!("no structure file: {err}");
                return;
            }
        },
        Err(err) => {
            eprintln!("cannot reach the Miniserver: {err}");
            return;
        }
    };
    println!(
        "structure loaded: {} controls",
        structure.controls().count()
    );

    // The lookup helpers, shown on whatever system is connected: count the controls of
    // each type, and name the first secured control (if there is one).
    let mut by_type: std::collections::BTreeMap<&str, usize> = std::collections::BTreeMap::new();
    for control in structure.controls() {
        *by_type.entry(control.kind()).or_insert(0) += 1;
    }
    for (kind, count) in by_type.iter().take(8) {
        println!("  {count:>4} x {kind}");
    }
    if let Some(secured) = structure.controls().find(|c| c.is_secured()) {
        println!(
            "first secured control: \"{}\" ({}), commands go to {}",
            secured.name(),
            secured.kind(),
            secured.action_uuid()
        );
    }

    // The supervisor connects in the background and reports everything as events.
    let mut cfg = SessionConfig::new(endpoint, user, Secret::new(password));
    cfg.max_command_age = Duration::from_secs(30);
    let structure_for_events = structure.clone();
    let style = Style::new();
    let handle = supervisor::start(
        cfg,
        AsyncHandler(move |event: Event| {
            let lines = describe(&event, &structure_for_events, &style);
            async move {
                for line in lines {
                    println!("{line}");
                }
            }
        }),
    );

    println!("-------------------------");
    println!("connecting in the background; press Enter to stop");
    let _ = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line).ok();
    })
    .await;

    handle.close();
    // Give the supervisor a moment to print the final disconnect.
    tokio::time::sleep(Duration::from_millis(500)).await;
    println!("stopped");
}
