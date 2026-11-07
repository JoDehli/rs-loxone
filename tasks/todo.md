# Task list: rs-loxone (protocol, auth, transport)

Plan: `tasks/plan.md`. Specs: `SPEC-protocol.md`, `SPEC-auth.md`, `SPEC-transport.md`.
Each task is one focused session, S or M size, and leaves the build green.

Verification commands used below:
- `cargo test -p rs-loxone <filter>`
- `cargo clippy --all-targets -- -D warnings`
- `cargo fmt --check`

---

## Phase 1: Foundation

## Task T0: Crate scaffold, lib target, approved dependencies

**Description:** Turn the crate into a library with a binary placeholder. Add the
approved dependencies for `protocol` and `auth` (`serde`, `serde_json`, `thiserror`,
`aes`, `cbc`, `hmac`, `sha1`, `sha2`, `rsa`, `x509-cert`, `base64`, `rand`,
`percent-encoding`, `hex`, `zeroize`). Add module stubs `protocol`, `auth`, `transport`.
Transport dependencies are added in Tr1.

**Acceptance criteria:**
- [ ] `src/lib.rs` declares `pub mod protocol; pub mod auth; pub mod transport;`
- [x] `src/main.rs` placeholder removed (standalone binary comes with the cli-and-crate module)
- [ ] Dependencies added with the versions pinned in `Cargo.lock`

**Verification:**
- [ ] `cargo build` succeeds
- [ ] `cargo clippy --all-targets -- -D warnings` clean

**Dependencies:** None

**Files likely touched:**
- `Cargo.toml`
- `src/lib.rs`
- `src/protocol/mod.rs`, `src/auth/mod.rs`, `src/transport/mod.rs`

**Estimated scope:** Small

---

## Task P1: Frame header parser

**Description:** Parse the 8-byte Loxone binary header: magic `0x03`, identifier,
info (bit 7 = estimated), reserved, and a little-endian `u32` payload length.
Non-`0x03` or short input returns `Unknown` (not an error). An unknown identifier
returns `UnknownType`.

**Acceptance criteria:**
- [ ] `parse_header(&[u8; 8])` returns `FrameHeader { kind, estimated, payload_len }`
- [ ] Non-`0x03` frames and frames shorter than 8 bytes give `Unknown`
- [ ] Identifiers 0–7 map to the message kinds in SPEC-protocol.md; others error

**Verification:**
- [ ] `cargo test -p rs-loxone protocol::header` passes
- [ ] Fixture bytes from `pyloxone-api-main/tests/test_message_parsing.py` parse to the same values

**Dependencies:** T0

**Files likely touched:**
- `src/protocol/header.rs`
- `src/protocol/mod.rs`
- `tests/protocol/header.rs`

**Estimated scope:** Small

---

## Task P2: Loxone UUID type

**Description:** A 16-byte UUID with Loxone byte order (`bytes_le`-compatible),
`Display` in the `8-4-4-16` form, and `FromStr` for that form.

**Acceptance criteria:**
- [ ] `Uuid::from_loxone_bytes([u8; 16])` and `Display` match Python `_uuid_str` for 10 sample UUIDs
- [ ] `FromStr` round-trips the same 10 strings
- [ ] Wrong-length input is an error, not a panic

**Verification:**
- [ ] `cargo test -p rs-loxone protocol::uuid` passes
- [ ] The 10 sample vectors were produced by running Python `_uuid_str` on fixed bytes

**Dependencies:** T0

**Files likely touched:**
- `src/protocol/uuid.rs`
- `tests/protocol/uuid.rs`

**Estimated scope:** Small

---

## Task P5: LL response parser

**Description:** Parse `{"LL": {"control", "code" | "Code", "value"}}`. Strip a
leading `salt/<hex>` from `control`. If `value` is an object, merge its fields
next to `value`. Invalid JSON or missing fields are errors. Decode bytes as UTF-8
with a Latin-1 fallback.

**Acceptance criteria:**
- [ ] Accepts both `code` and `Code`
- [ ] `control` loses a leading `salt/<hex>/` prefix
- [ ] Object `value` merges into the result; string `value` stays a string
- [ ] Non-UTF-8 bytes decode via Latin-1 without error

**Verification:**
- [ ] `cargo test -p rs-loxone protocol::ll` passes
- [ ] Fixtures from the Python tests (LL samples) parse to the same fields

**Dependencies:** T0

**Files likely touched:**
- `src/protocol/ll.rs`
- `tests/protocol/ll.rs`

**Estimated scope:** Small

---

### Checkpoint: Foundation
- [ ] `cargo test -p rs-loxone` passes for P1, P2, P5
- [ ] Clippy and fmt clean

---

## Phase 2: Protocol and Auth

## Task P3: Value-state parser

**Description:** Parse the value-state table: 24-byte records of a 16-byte UUID
and a little-endian `f64`. A trailing partial record is dropped, and the drop
count is returned.

**Acceptance criteria:**
- [ ] Three records give three `(Uuid, f64)` pairs in order
- [ ] A partial trailing record is dropped and counted
- [ ] An empty payload gives an empty result

**Verification:**
- [ ] `cargo test -p rs-loxone protocol::value_states` passes
- [ ] Values equal the Python `ValueStatesTable.as_dict()` output for the same bytes

**Dependencies:** P2

**Files likely touched:**
- `src/protocol/message.rs`
- `tests/protocol/value_states.rs`

**Estimated scope:** Small

---

## Task P4: Text-state parser

**Description:** Parse the text-state table: UUID, icon UUID (discarded), `u32`
text length, text bytes, and padding to the next record start per the Python
formula. Text decodes as UTF-8 with Latin-1 fallback.

**Acceptance criteria:**
- [ ] Multi-record payloads match Python output, including non-ASCII text
- [ ] Padding follows `(floor((4 + len + 16 + 16 - 1) / 4) + 1) * 4` (Python rule)
- [ ] A truncated record is an error, not a panic

**Verification:**
- [ ] `cargo test -p rs-loxone protocol::text_states` passes
- [ ] Fixtures from `test_message_parsing.py` produce the same map

**Dependencies:** P2

**Files likely touched:**
- `src/protocol/message.rs`
- `tests/protocol/text_states.rs`

**Estimated scope:** Small

---

## Task P6: Frame dispatch

**Description:** Map `(FrameHeader, payload)` to a `Message` enum. Daytimer and
weather payloads are returned as raw bytes. Keepalive and out-of-service are
returned as variants without payload. Binary files are returned as an owned `Vec<u8>`.

**Acceptance criteria:**
- [ ] Each identifier maps to its variant, per SPEC-protocol.md
- [ ] `Message::Daytimer(Vec<u8>)` and `Message::Weather(Vec<u8>)` keep the bytes
- [ ] Length mismatch between header and payload is an error

**Verification:**
- [ ] `cargo test -p rs-loxone protocol::dispatch` passes
- [ ] One test per identifier 0–7

**Dependencies:** P1, P3, P4, P5

**Files likely touched:**
- `src/protocol/mod.rs`
- `tests/protocol/dispatch.rs`

**Estimated scope:** Small

---

## Task A1: Credential, token and visual hashes

**Description:** `credential_hash`, `token_hash` and `visual_hash`, each with
SHA-1 or SHA-256 from `hashAlg`. Uppercase intermediate hex, lowercase final
HMAC hex. Unknown `hashAlg` is an error.

**Acceptance criteria:**
- [ ] `credential_hash(user, pwd, ks)` = HMAC(hex_decode(key), user ":" HEX_UPPER(H(pwd ":" salt)))
- [ ] `token_hash(token, ks)` = HMAC(hex_decode(key), token)
- [ ] `visual_hash(code, uuid, value, vis)` follows SPEC-auth.md (visual key)
- [ ] Both algorithms match the Python outputs

**Verification:**
- [ ] `cargo test -p rs-loxone auth::hash` passes
- [ ] Known-answer vectors generated by running Python `helper.hash_token`, `generate_hmac`
      and `_hash_credentials` logic on fixed inputs (SHA-1 and SHA-256)

**Dependencies:** T0

**Files likely touched:**
- `src/auth/hash.rs`
- `tests/auth/vectors/` (vector files)

**Estimated scope:** Small

---

## Task A2: Session key (RSA + AES)

**Description:** Generate the AES-256 key and 16-byte IV, build the plaintext
`hex(key):hex(iv)`, RSA PKCS#1 v1.5-encrypt it with the public key from the
certificate PEM, base64 it (standard, padded), and format
`jdev/sys/keyexchange/<b64>`. The certificate is parsed to its SubjectPublicKeyInfo.

**Acceptance criteria:**
- [ ] Certificate PEM input is accepted; bare public-key PEM is rejected
- [ ] The base64 payload decrypts with the matching private key to `hex(key):hex(iv)`
- [ ] The command string is `jdev/sys/keyexchange/` + base64

**Verification:**
- [ ] `cargo test -p rs-loxone auth::keyexchange` passes
- [ ] Round-trip test with a fixed test certificate and key

**Dependencies:** T0, A1

**Files likely touched:**
- `src/auth/keyexchange.rs`
- `tests/auth/keyexchange.rs`

**Estimated scope:** Medium

---

## Task A3: Command encryption (`enc`)

**Description:** `EncCipher` builds `jdev/sys/enc/<enc>`. The first command uses
`salt/<salt>/<cmd>\0`. Every later command uses
`nextSalt/<old>/<new>/<cmd>\0`. Plaintext is PKCS#7-padded, AES-256-CBC with the
fixed session IV, base64 standard, then percent-encoded.

**Acceptance criteria:**
- [ ] First command: `salt/<salt>/<cmd>\0`; second and later: `nextSalt/<old>/<new>/<cmd>\0`
- [ ] Decrypting the output gives back the plaintext
- [ ] The IV stays the same for the whole connection

**Verification:**
- [ ] `cargo test -p rs-loxone auth::enc` passes
- [ ] Known-answer vector from Python `Padding.pad` + AES-CBC on fixed inputs

**Dependencies:** T0, A1

**Files likely touched:**
- `src/auth/enc.rs`
- `tests/auth/enc.rs`

**Estimated scope:** Small

---

## Task A4: Token state and refresh timing

**Description:** `TokenState` with `token`, `valid_until` (seconds since
2009-01-01), `key`, `hash_alg`, `unsecure_password`, and `token_rights`.
`seconds_to_expire(now)` and `refresh_delay(now)` = clamp(floor(0.5 × remaining), 1 s, 86400 s).
An empty token is "no token"; `valid_until == 0` is an error.

**Acceptance criteria:**
- [ ] Boundary cases: 0 s, 1 s, 2 days remaining
- [ ] Empty token and `valid_until == 0` handled as specified
- [ ] No clock reads inside the module; `now` is a parameter

**Verification:**
- [ ] `cargo test -p rs-loxone auth::token` passes
- [ ] Refresh delays match the Python clamp for the same inputs

**Dependencies:** T0

**Files likely touched:**
- `src/auth/token.rs`
- `tests/auth/token.rs`

**Estimated scope:** Small

---

## Task A5: Auth command builders (version gate)

**Description:** Build the command strings for `getkey2`, `getjwt`/`gettoken`,
`authwithtoken`, `refreshjwt`/`refreshtoken`, `checktoken`, `killtoken`
(hash form), and `getvisusalt`. The version gate chooses JWT (≥ [10,2]) or legacy.
Permission `2`, UUID `edfc5f9a-df3f-4cad-9dddcdc42c732b82`, info `pyloxone_api`.

**Acceptance criteria:**
- [ ] Each builder output matches the SPEC-auth.md path, in both version branches
- [ ] `killtoken` uses the token hash (PDF decision)
- [ ] Version comparison is element-wise on `[major, minor, patch]`

**Verification:**
- [ ] `cargo test -p rs-loxone auth::commands` passes
- [ ] Strings match the Python `connection.py` command format for the same inputs

**Dependencies:** A1, A3, A4

**Files likely touched:**
- `src/auth/commands.rs`
- `tests/auth/commands.rs`

**Estimated scope:** Small

---

## Task A6: Auth reply parsing and error classes

**Description:** `parse_reply` for `getkey2` (key, salt, hashAlg), token replies
(token, validUntil, key, unsecurePass, tokenRights), refresh and checktoken
replies. Map codes to classes: hard (401, 403, 423, 4003, 4006), auth timing
(420, 400), transient (503, 901, 4007, 4008), success (200), other (warning,
transient).

**Acceptance criteria:**
- [ ] Each reply shape parses; a missing field is an error
- [ ] Every code in SPEC-auth.md "Reply codes" maps to its class
- [ ] Error messages never contain the token, key or password

**Verification:**
- [ ] `cargo test -p rs-loxone auth::reply` passes
- [ ] Reply fixtures copied from the Python test suite where they exist

**Dependencies:** P5, A4

**Files likely touched:**
- `src/auth/reply.rs`
- `tests/auth/reply.rs`

**Estimated scope:** Small

---

### Checkpoint: Protocol and Auth
- [ ] `cargo test -p rs-loxone protocol` and `auth` pass
- [ ] Known-answer vectors match Python
- [ ] `grep -rn "tokio\|async" src/protocol src/auth` returns nothing

---

## Phase 3: Transport

## Task Tr1: URL handling

**Description:** Parse the host input (`host`, `host:port`, `http://`, `https://`),
apply default ports (80/443), and build `ws`/`wss` URLs with `/ws/rfc6455`.
Add the transport dependencies (`tokio`, `tokio-tungstenite`, `futures-util`,
`reqwest` without default features, `url`, `rustls`, `webpki-roots`,
`rustls-pki-types`) and `rcgen` as a dev-dependency. The new crates need your
approval in the spec, which is given.

**Acceptance criteria:**
- [ ] Input forms and default-port omission match Python `parse_loxone_url`
- [ ] `http`→`ws`, `https`→`wss`; the path is `/ws/rfc6455`
- [ ] Missing host is a typed error

**Verification:**
- [ ] `cargo test -p rs-loxone transport::url` passes
- [ ] `cargo build` succeeds with the new dependencies

**Dependencies:** T0

**Files likely touched:**
- `Cargo.toml`
- `src/transport/url.rs`
- `tests/transport/url.rs`

**Estimated scope:** Small

---

## Task Tr2: Transport errors and retry backoff

**Description:** `TransportError` with `is_retryable()` (Unreachable, Timeout,
HTTP 503). `backoff(attempt, base, max, rng)` = min(base × 2^n, max) with ±20%
jitter, using injected `Rng` and `Clock` traits.

**Acceptance criteria:**
- [ ] Exact delays with a fixed RNG: attempts 0–4 with base 5 s, cap 60 s
- [ ] Only the three retryable variants return true
- [ ] Error messages carry no credentials or tokens

**Verification:**
- [ ] `cargo test -p rs-loxone transport::retry` passes

**Dependencies:** T0, Tr1

**Files likely touched:**
- `src/transport/mod.rs`
- `src/transport/retry.rs`
- `tests/transport/retry.rs`

**Estimated scope:** Small

---

## Task Tr3: HTTP bootstrap

**Description:** `HttpBootstrap` with Basic auth. Three GETs: `/jdev/cfg/apiKey`
(normalise single quotes, parse `version`, `MAC`, `httpsStatus`, `local`),
`/data/LoxAPP3.json` (bytes, with final URL), and `/jdev/sys/getPublicKey` (PEM
from the LL value). Retry 5 times with backoff on 503, connection and timeout
errors; no retry on 401 or parse errors. Redirects followed, cap 10.

**Acceptance criteria:**
- [ ] Single-quoted apiKey JSON parses
- [ ] Structure file bytes are returned unchanged
- [ ] 503 then 200 succeeds; 401 fails once with no retry
- [ ] Final URL after a redirect is reported

**Verification:**
- [ ] `cargo test -p rs-loxone transport::http` passes against a local mock server
      (a tokio `TcpListener` serving canned responses)

**Dependencies:** Tr1, Tr2, P5

**Files likely touched:**
- `src/transport/http.rs`
- `tests/transport/http.rs`

**Estimated scope:** Medium

---

## Task Tr4: TLS configuration and CloudDNS hostname

**Description:** Trust store: `webpki-roots`, plus an optional `ca_file` (PEM).
`verify_tls = false` turns verification off (explicit). Build the CloudDNS
hostname from `IPHTTPS` (clean IPv4 dots and IPv6 colons to minuses, strip
brackets, append `.{snr}.dyndns.loxonecloud.com:{port}`). `httpsStatus` 1 selects
TLS; 2 is reported.

**Acceptance criteria:**
- [ ] Unknown certificate rejected by default
- [ ] Accepted with `ca_file` or with `verify_tls = false`
- [ ] Hostname built as the PDF describes, for IPv4 and IPv6 examples
- [ ] `httpsStatus` 2 surfaces as a typed result, not a silent fallback

**Verification:**
- [ ] `cargo test -p rs-loxone transport::tls` passes
- [ ] Local TLS test server with an `rcgen` certificate covers the above

**Dependencies:** Tr1, Tr2

**Files likely touched:**
- `src/transport/tls.rs`
- `tests/transport/tls.rs`

**Estimated scope:** Medium

---

## Task Tr5: WebSocket connect, send, receive, close

**Description:** `WsConnection::connect` to `ws(s)://…/ws/rfc6455` with subprotocol
`remotecontrol`, compression off, ping off, max message 5 MiB, open timeout 30 s
(connect bounded at 60 s), close timeout 10 s. `send_text`, `next_frame` (raw
`Binary`/`Text`), `close`. Close codes are kept, including 4003.

**Acceptance criteria:**
- [ ] Subprotocol `remotecontrol` is requested
- [ ] Frames arrive in order, binary and text, unpaired
- [ ] Close with code 4003 gives `Closed { code: Some(4003) }`
- [ ] Clean close gives `None`

**Verification:**
- [ ] `cargo test -p rs-loxone transport::ws` passes against the mock server (plain and TLS)

**Dependencies:** Tr1, Tr2, Tr4

**Files likely touched:**
- `src/transport/ws.rs`
- `tests/transport/ws.rs`

**Estimated scope:** Medium

---

## Task Tr6: Keepalive and watchdog

**Description:** A keepalive task sends `keepalive` every 30 s through a channel
(single writer). Any inbound frame resets the silence timer. Silence over 90 s
reports `ConnectionLost` and stops; it does not close the socket itself.

**Acceptance criteria:**
- [ ] `keepalive` text sent every 30 s
- [ ] No inbound frame for more than 90 s → `ConnectionLost`
- [ ] Any inbound frame (including identifier 0x06 reply) resets the timer
- [ ] Only one writer exists

**Verification:**
- [ ] `cargo test -p rs-loxone transport::keepalive` passes with a fake clock (`tokio::time::pause`)

**Dependencies:** Tr5

**Files likely touched:**
- `src/transport/keepalive.rs`
- `tests/transport/keepalive.rs`

**Estimated scope:** Small

---

### Checkpoint: Transport
- [ ] `cargo test -p rs-loxone transport` passes (TLS on)
- [ ] `cargo test -p rs-loxone --no-default-features` passes
- [ ] Clippy and fmt clean

---

## Final checkpoint (plan scope)

## Task L1: Live check on the Gen 1 Miniserver (needs your go-ahead; Gen 1 only, no Gen 2 device)

**Description:** With your device and credentials, run a live smoke test: bootstrap,
connect, key exchange, `getkey2`, token request, an encrypted command, `keepalive`,
and kill. Record the replies. This is the first run against real hardware. It can
change the Miniserver's session state, so it runs only after you confirm.

**Acceptance criteria:**
- [ ] Token-based login succeeds with the `getkey2` key
- [ ] `getkey2` accepted when encrypted
- [ ] `killtoken` with the hash: reply recorded (Python says 401; PDF says hash is correct)
- [ ] Salt rotation accepted on every command

**Verification:**
- [ ] Captured replies saved under `tests/live/` (no secrets committed)

**Dependencies:** All Phase 3 tasks

**Files likely touched:**
- `tests/live/` (marked `#[ignore]`, run manually)

**Estimated scope:** Small

---

### Checkpoint: Complete (plan scope)
- [ ] All acceptance criteria in SPEC-protocol.md, SPEC-auth.md, SPEC-transport.md met
      at mock and fixture level
- [ ] L1 run with your go-ahead
- [ ] Ready for review before `session` is specified
