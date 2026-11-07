# loxone-mock

A scripted mock of the Loxone Miniserver for tests: the HTTP bootstrap (`apiKey`,
public key, structure file), the WebSocket protocol (key exchange, login with password
or token, encrypted commands with the salt chain, secured commands, state updates),
and HTTPS/WSS with a test certificate.

It is meant for testing software that talks to a Miniserver, such as the
[rs-loxone](https://github.com/JoDehli/rs-loxone) client, without a real device.

```toml
[dev-dependencies]
loxone-mock = "0.1"
```

```rust
use loxone_mock::{MockConfig, start};

let mock = start(MockConfig::default());
// Point a client at mock.addr(), e.g. http://127.0.0.1:<port>
```

The test certificate in `fixtures/` is for tests only. It is not a secret.

Licensed under MIT OR Apache-2.0.
