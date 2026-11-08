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

## Tests

Everything runs without a Miniserver:

```
cargo test --features mock
```

The `mock` feature adds a scripted fake Miniserver (`src/mock`). Tests that use it are
only compiled with that feature. Without it, `cargo test` runs the unit tests and the
tests that need no mock (167 tests); with it, all 207 tests run.

Checks before a commit:

```
cargo fmt --check
cargo clippy --all-targets --features mock,cli -- -D warnings
cargo test --features mock
```

### Load test (optional)

`tests/load_receive.rs` sends a long run of state updates from the mock and checks that
each one arrives once and in order. It is ignored, so a normal test run skips it. Run it
with `--release` to get meaningful numbers:

```
cargo test --release --features mock --test load_receive -- --ignored --nocapture
```

Settings, as environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `FLOOD_RECORDS` | 1000000 | records to send |
| `FLOOD_PER_TABLE` | 1000 | records per table (one event each) |
| `FLOOD_CALLBACK_US` | 0 | sleep per table in the callback, to simulate a slow callback |

Example, one record per event and a slower callback:

```
FLOOD_PER_TABLE=1 FLOOD_RECORDS=200000 FLOOD_CALLBACK_US=10 \
  cargo test --release --features mock --test load_receive -- --ignored --nocapture
```

It prints the received count, missing and out-of-order records, the throughput and the
largest backlog. The mock and the client run on the same machine, so the numbers show
this machine, not a network or a real Miniserver.

#### Mock in its own process

By default the mock runs inside the test and shares the CPU with the receiver. To
measure the receiver alone, run the flood server as a separate program and point the
test at it with `LOAD_ADDR`. Use the same settings for both:

```
# terminal 1: prints "flood server on <address>"
FLOOD_PER_TABLE=1 FLOOD_RECORDS=200000 \
  cargo run --release --features mock --example flood_server

# terminal 2: use the address from terminal 1
LOAD_ADDR=127.0.0.1:<port> FLOOD_PER_TABLE=1 FLOOD_RECORDS=200000 \
  cargo test --release --features mock --test load_receive -- --ignored --nocapture
```

Stop the flood server with Ctrl-C when you are done.

### Live tests

The tests in `tests/live/` talk to a real Miniserver. They are ignored by default, so
a normal test run never touches your device. Each one needs its settings from the
credentials file or the environment (see below):

```
cargo test --test live_gen1 -- --ignored --nocapture
```

They print only status codes and results, never passwords, codes or tokens. Some of
them change the device: `gen1_alarm_arm_then_disarm` arms and disarms the alarm, so
run it only when nobody is in the monitored area.

### Settings for the live tests

The live tests read a file `miniserver.env` with these lines:

```
LOX_USER=<user>
LOX_PASS=<password>
LOX_HOST=http://<ip>:<port>
LOX_VISU_CODE=<visualization code>      # only for the visualization code tests
LOX_TEST_DEVICE=<device uuid>           # only for the secured command tests
```

The file is found in this order:

1. `LOX_ENV_FILE`, if set, as the full path.
2. `.config/rs-loxone/miniserver.env` in your home folder: `HOME` on Linux and macOS,
   `USERPROFILE` on Windows.

Environment variables with the same names take precedence over the file. Keep the file
private: `chmod 600` on Linux and macOS; on Windows, allow only your own user in the
file's security settings. Never commit it.

## The command line program

```
cargo run --features cli --bin rs-loxone                     # asks for address, user and password
cargo run --features cli --bin rs-loxone -- 192.168.1.10:8080 admin
```

- Leave the address empty to search the local network (Loxone discovery).
- The password is typed without echo. For scripts, set `LOX_PASS` instead.
- `LOX_TOKEN_FILE=<path>` keeps the token in that file between runs. The next start logs in
  with it, without the password for the connection (the structure file still needs the
  password). See [Keeping the token](#keeping-the-token).
- `LOX_TLS_PIN=<64 hex digits>` accepts only the certificate with this SHA-256 fingerprint,
  and `LOX_TLS_TOFU=<file>` remembers the first certificate seen for each host name in that
  file. See [TLS](#tls).
- Output: time, state name, UUID, value. `NO_COLOR=1` turns the colors off.
- Press Enter to stop.

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
| `LoggedIn { used_stored_token }` | Logged in; `true` if the stored token was used, `false` if the password was used |
| `TokenChanged` | The token is valid until this time (after a login or a renewal). Store it if you want to log in without the password |
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

## Keeping the token

Set `SessionConfig::token_file` to a `TokenFile` and the session keeps its token there:

- After every login and every renewal the token is written. The write is atomic (a
  temporary file, then a rename). On Unix the file is created with mode 0600 and its
  directory with 0700.
- At start, a stored token is used if it has more than 100 s left, and it is offered to
  the Miniserver with `authwithtoken`. The validity is taken from the Miniserver's reply.
- A missing, corrupt or foreign file means "no token". The same applies if the Miniserver
  refuses the token, whether it answers with an error or closes the connection. Then the
  password is used.
- The file holds bearer material as good as the password. Keep it readable only by the
  account that runs the program.

## TLS

`TlsOptions` selects how the server certificate is checked. Over `https://` and `wss://` only.

| Setting | Accepts | Use for |
|---|---|---|
| default (`verify: true`) | A certificate that a public CA or the extra root signed, with the host name | Miniservers under a real name |
| `extra_root_pem` | Same as default, plus your own root (for example the Loxone root) | Your own certificate authority |
| `pinned_cert_sha256` | Only the certificate with this SHA-256 (DER). Chain and host name are not checked | A fixed, known certificate, for example a Miniserver by IP |
| `trust_on_first_use: true` | The first certificate seen for a host name. Later ones must match. With `first_use_file` the list is kept in that file | When you cannot get the fingerprint in advance |
| `verify: false` | Anything | Only for tests; no protection against an attacker on the network |

Notes:
- The pin has priority over `trust_on_first_use`, which has priority over `verify`.
- Without `first_use_file` the memory lasts only for the life of the process; after a restart
  the first contact counts again. With `first_use_file` the list survives restarts (mode 0600,
  written atomically). In both cases an attacker on the network at the first contact gets
  their certificate remembered. Use a pin if you can get the fingerprint some other way.
- To read the fingerprint of a certificate:
  `openssl s_client -connect HOST:PORT </dev/null 2>/dev/null | openssl x509 -outform DER | sha256sum`

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

## License

Copyright (C) 2026 JoDehli. Licensed under the GNU Affero General Public License, version 3 only
(see `LICENSE`). If you run a modified version as a network service, you must offer its source to
the users of that service.
