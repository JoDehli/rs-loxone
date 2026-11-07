# rs-loxone

A low-level, asynchronous Rust client for the Loxone Miniserver. It logs in, reconnects
when the connection drops, delivers every state change to your callbacks, and keeps the
token fresh. It is a library (crate `rs_loxone`) and comes with a command line program.

## Status

- **Gen 1** (`ws://`, firmware 17.x): tested against a real Miniserver: login, state
  updates, commands, token renewal, structure file, discovery, a secured command.
- **Gen 2** (`https://`, `wss://`): tested only against the mock, not on hardware.
- **MQTT:** planned, not started.

## Quick start

Connect to your Miniserver and watch what it sends:

```
cargo run --features cli --bin rs-loxone
```

It asks for the address (empty = search the network), the user and the password. See
[The command line program](#the-command-line-program) for arguments and options.

## Install as a library

Requires Rust 1.95 or newer.

```toml
[dependencies]
rs-loxone = "0.1"
```

The command line program is an optional feature: `cargo install rs-loxone --features cli`.

## Build and test

```
cargo build
cargo test --features mock       # all tests, no Miniserver needed
cargo clippy --all-targets --features mock,cli -- -D warnings
```

The live tests in `tests/live/` need a real Miniserver and are ignored by default:

```
LOX_HOST=http://<ip>:<port> cargo test --test live_gen1 -- --ignored --nocapture
```

## The command line program

```
cargo run --features cli --bin rs-loxone                     # asks for address, user and password
cargo run --features cli --bin rs-loxone -- 192.168.1.10:8080 admin
```

- Leave the address empty to search the local network (Loxone discovery).
- The password is typed without echo. For scripts, set `LOX_PASS` instead.
- Output: time, state name, UUID, value. `NO_COLOR=1` turns the colors off.
- Press Enter to stop.

The live tests read their settings from a file, `miniserver.env`, with the lines
`LOX_USER`, `LOX_PASS`, `LOX_HOST` and, optionally, `LOX_VISU_CODE` and `LOX_TEST_DEVICE`.

- Linux and macOS: `~/.config/rs-loxone/miniserver.env`
- Windows: `%USERPROFILE%\.config\rs-loxone\miniserver.env`
- Any system: set `LOX_ENV_FILE` to the full path of the file.

Keep the file private. On Linux and macOS use `chmod 600`; on Windows, allow only your
own user in the file's security settings. Never commit it.

## Using the library

Connect through the supervisor, which reconnects on its own and queues commands sent
while the connection is down:

```rust
use rs_loxone::auth::Secret;
use rs_loxone::session::{AsyncHandler, Event, SessionConfig};
use rs_loxone::supervisor;
use rs_loxone::transport::url::Endpoint;

#[tokio::main]
async fn main() {
    let endpoint = Endpoint::parse("192.168.1.10:8080").unwrap();
    let cfg = SessionConfig::new(endpoint, "admin", Secret::new("password"));

    let handle = supervisor::start(
        cfg,
        AsyncHandler(|event: Event| async move {
            println!("{event:?}");
        }),
    );

    // Commands can be sent at any time; they wait while the connection is down.
    let id = handle
        .send(rs_loxone::supervisor::outbox::Item::Command(
            "jdev/sps/io/<control-uuid>/on".into(),
        ))
        .unwrap();
    println!("queued command {id}");

    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    handle.close();
}
```

Events you will see:

| Event | Meaning |
|---|---|
| `Connected` | Logged in and state updates are on |
| `ValueStates` / `TextStates` | State changes, as `(uuid, value)` |
| `Text` | A reply to a command that nobody waited for |
| `TokenChanged` | A new token (store it if you want to log in without the password) |
| `CommandDropped` / `CommandFailed` | A queued command was too old, or the Miniserver refused it |
| `Reconnecting` / `GaveUp` | The supervisor waits, or has stopped (for example a wrong password) |
| `Disconnected` | The connection ended; always the last event of a connection |

Callbacks run in order, one at a time. A slow callback delays the next events but never
the reading from the Miniserver.

### Structure file

```rust
use rs_loxone::structure::Structure;

let structure = Structure::parse(&bytes)?;             // bytes of LoxAPP3.json
for alarm in structure.of_type("Alarm") {
    println!("{} (secured: {})", alarm.name(), alarm.is_secured());
}
let armed = structure.find("My alarm").and_then(|c| c.state("armed"));
let label = structure.label(&some_state_uuid);          // "Room / Control / state"
```

### Secured commands

Controls with a visualization password need the code with each command. The library
computes the hash; the code is never sent in clear text.

With a `Session` (from `Session::connect`):

```rust
// Check a code without running anything:
let ok: bool = session.check_visu_code("1234").await?;
// Run a command with the code (returns WrongVisuCode if the code is refused):
session.send_secured("<control-uuid>", "on", "1234").await?;
```

Secured commands through the supervisor use `Item::Secured { device_uuid, value, code }`.

### Discovery

```rust
let found = rs_loxone::discover::discover(std::time::Duration::from_secs(5)).await?;
```

## Security notes

- Over `http://` the password is sent unencrypted with each structure request (Basic
  auth), as the Python library does. The library prints a warning when you do this. Use
  `https://` where the Miniserver supports it.
- The visualization code and the token are kept in `Secret` values and never printed.
- The live tests and the program read credentials from the environment or a file, not
  from the source code.

## Layout

```
src/protocol/    frames and value formats (no I/O)
src/auth/        hashing, key exchange, command encryption, tokens (no I/O)
src/transport/   HTTP bootstrap, WebSocket, TLS, keepalive
src/session/     one logged-in connection
src/supervisor/  reconnects, command queue, auth escalation
src/structure/   structure file helpers
src/discover.rs  network discovery
src/bin/         the rs-loxone program
src/mock/        a scripted fake Miniserver for tests (feature `mock`)
```
