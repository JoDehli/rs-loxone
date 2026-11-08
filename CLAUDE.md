# CLAUDE.md: rs-loxone

Project knowledge for future sessions. The user writes in German, so answer in German. Code, commit messages and
identifiers stay in English, as in the repo.

## What this project is

- Rust library `rs-loxone` for the Loxone Miniserver. Gen 1 over `ws://` is what runs on the real device. Gen 2 over
  `https`/`wss` is only tested against mocks. Features: login (password or stored token), encrypted commands, state
  stream, token renewal, supervisor with reconnect and backoff, TLS with pinning and trust-on-first-use.
- Also a console program `rs-loxone` (`src/bin/rs-loxone.rs`, feature `cli`).
- License: **AGPL-3.0-only** since `d0e14de`. Before that, MIT OR Apache-2.0. Older published versions keep their license.
- Test device: Gen 1, firmware 17.2.10.21 (main device), earlier 17.1.7. Credentials are in
  `~/.config/rs-loxone/miniserver.env` (mode 0600). Never print their values or write them to files.
- The sister project `pyloxone-api` (Python) is **not** in this repo. It lives in
  `/home/jdehli/Programmierung/PyCharm/pyloxone-api`. The copy `pyloxone-api-main/` in this folder is outdated and not
  authoritative.

## Commands

```
cargo build --features cli                       # console program
cargo test                                        # without mock: unit tests and tests that need no mock
cargo test --features mock                        # all tests, the standard check
cargo fmt --check
cargo clippy --all-targets --features mock,cli -- -D warnings
```

- Before every commit: fmt, clippy and `cargo test --features mock` must pass. Run the whole suite once, not only the
  changed tests.
- Live tests (`tests/live/`, targets `live_gen1`, `live_preflight`, `live_token_store`) are `#[ignore]`. They talk to the
  real device. They need `--ignored` and the user's approval. Their output is limited to status codes and lengths.
- Console program: `rs-loxone HOST USER` with `LOX_PASS`. Optional: `LOX_TOKEN_FILE` (keeps the token between runs),
  `LOX_TLS_PIN` (64 hex digits), `LOX_TLS_TOFU=<file>`, `LOX_KILL_TOKEN=1` (revokes the current token and removes the
  token file). `--help` lists everything.

## Modules (src/)

- `auth/`: keys, hashes, AES wrapper (`enc.rs`, padding removal in `strip_padding`), tokens (`token.rs`), token file
  (`store.rs`: `TokenFile`, `TokenStore`, `write_private_atomic`), command builders (`commands.rs`).
- `transport/`: HTTP bootstrap (`http.rs`), WebSocket (`ws.rs`), TLS (`tls.rs`: `PinVerify`, `FirstUseVerify`),
  keepalive and watchdog (`keepalive.rs`: `KEEPALIVE_PERIOD` 30 s, `READ_TIMEOUT` 90 s), retry (`retry.rs`).
- `protocol/`: frames, headers, LL replies (`ll.rs`), messages (`message.rs`).
- `session/`: `Session::connect` (preflight, login, ready state), `commands.rs` (requests, queue, `request_inner`,
  `clear_waiter`), `reader.rs` (waiter `Slot`, `claim`, abandoned requests `ABANDONED_FOR`), `secured.rs` (secured
  commands: two requests), `refresh.rs` (token renewal), `event.rs` (events).
- `supervisor/`: reconnect logic. `mod.rs` (`token_may_be_the_cause`, `FATAL_CLOSE_CODES`, `force_password`),
  `backoff.rs` (300 s for 901, 4007, 4008).
- `structure/`: structure file (names, rooms, controls). `mock/`: fake Miniserver for tests (feature `mock`).
- `discover.rs`: network discovery.

## Protocol facts (verified on the device unless marked otherwise)

- Encrypted commands are sent with PKCS#7. Replies may use PKCS#7 **or** zero-byte padding (`strip_padding`).
  Whether the device accepts PKCS#7 for secured commands (`jdev/sps/ios`) is **not** verified (step 0 in the plan).
- Secured commands: fetch `getvisusalt` fresh for each command, then send the command with the hash.
- `checktoken` takes the **plain token** (the hash gets 401). Without login the device answers 400.
- `killtoken/<token>/<user>`: both segments are required (without the user name the answer is 400). The token is
  refused with 401 afterwards (measured on 17.2.10.21). This revokes the user's token, so run it only with approval.
- `authwithtoken`: an invalid token gets 404 (measured on 17.1.7 with a made-up token). Whether 17.2 also answers 404 is
  not verified.
- Close codes: 4003 (blocked) and 4006 (disabled) are final. 4007, 4008 and 901 get a 300 s wait.
- A refused token can close the socket instead of answering.
- The salt chain is per connection. After every reconnect it starts again.
- `getkey2` and `getvisusalt` have the same reply shape. Only the correlated command tells them apart.
- Token validity comes from `validUntil` in the reply (Loxone epoch 2009-01-01). A stored token is used only if more
  than 100 s remain (`TOKEN_MIN_REMAINING_SECONDS`).
- The Gen 1 device does not answer HTTPS (ports 8080 and 443 checked). TLS pinning and TOFU are mock-tested only.

## Working rules

- **Do not commit until the user asks.** Then one commit per logical step. End commit messages with
  `Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>` and the session line, as in the existing commits.
- These stay uncommitted on purpose: `NOTES-pyloxone-api.md`, `HANDOVER-pyloxone-api.md`,
  `CHECKTOKEN-PYTHON-CHANGES.md`, `SPEC-*.md`, `tasks/`, `reference/`, `pyloxone-api-main/`, `pyloxone-api-main.zip`,
  `CAPABILITY-MAP.md`, `CommunicatingWithMiniserver.txt`, `1700_Structure-File.txt`, `CLAUDE.md`.
- Protect each change with a test that fails before the change (red, then green). For behaviour that depends on the
  device, use a mock test.
- Actions on the device that change state (switching, killtoken, live tests with write access, deleting tokens) need
  the user's explicit approval.
- No secrets in output, logs, commits or notes: password, token, visualization code, salt values. The token files in
  `~/.config/rs-loxone/` and in the scratchpad hold valid device tokens.
- Credit the source when code or text is taken from another project. `reference/lox/` (lox-cli, AGPL-3.0) is only a
  reference. Implement ideas from it independently.

## Known pitfalls

- zsh: `grep --include=*.rs` fails with "no matches found" because of glob expansion. Use `bash -c '...'` or quote the
  pattern.
- `cp` is aliased and asks "overwrite?", which hangs commands. Use `\cp -f`.
- `cargo fmt` changes files you are editing. Check `git diff` before committing.
- The TOFU tests use the process-wide memory `FIRST_USE_PINS`, so they need unique host names. New TOFU tests need
  unique names too.
- Supervisor tests with long waits use real time (`Duration`). The waits are long on purpose.
- The full suite failed once in `stored_token_takes_its_validity_from_the_reply` (`tests/session_login.rs`). It passed
  when run alone and in later full runs. The cause is not found. Watch this test if a run fails.
- `clear_waiter` (`src/session/commands.rs`) has no test of its own. The logic behind it (`claim`, `ABANDONED_FOR`) does.

## Status and plans

- Findings from the pre-review: all done (commits `c65846c` to `0733e46`, `9a43090`, `8ef2133`, `35d9afe`). Late
  replies: `7370da4`. `killtoken`: `3507b34`. License: `d0e14de`.
- Task list: `tasks/todo-upstream-ideas.md`. Handover to pyloxone-api: `HANDOVER-pyloxone-api.md`. Detailed notes:
  `NOTES-pyloxone-api.md`. Older plans: `tasks/plan.md`, `tasks/todo.md`.
- Open: the device test for PKCS#7 with secured commands (step 0, needs approval). No live check of 404 on 17.2.
  The decisions for pyloxone-api are in the handover, section 7.
