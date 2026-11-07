# Übergabe: rs-loxone (Stand nach S8 + HTTPS/WSS-Test)

Zum Weiterarbeiten nach einer Kontextbereinigung. Alles Wichtige steht hier und in den Spezifikationen.

## Projekt

- Rust-Bibliothek für Loxone Miniserver. Workspace: `rs-loxone` (Haupt-Crate) und `loxone-mock`
  (Test-Mock, eigenes Crate, unabhängig von rs-loxone).
- Module: `protocol` (fertig), `auth` (fertig), `transport` (fertig), `session` (S0–S8 fertig, S9–S10 offen).
- Specs: `SPEC-protocol.md`, `SPEC-auth.md`, `SPEC-transport.md`, `SPEC-session.md`.
- Pläne: `tasks/plan.md` (Protokoll/Auth/Transport), `tasks/plan-session.md` und `tasks/todo-session.md` (Session).
- Gerät: Gen 1, Firmware 17.1.7, IP <MINISERVER_IP> (HTTP auf Port 443, Klartext). Zugangsdaten in
  `~/.config/rs-loxone/miniserver.env` (nie ausgeben).
- Git: nichts committet.

## Prüfbefehle

- `cargo fmt --all --check`
- `cargo test --workspace --lib --tests` (Live-Tests sind `#[ignore]`, nur mit Freigabe)
- `cargo clippy --workspace --all-targets -- -D warnings`

## Stand Session

- S0 Gerüst, S1 Mock, S2 Login (Passwort und gespeichertes Token mit Rückfall), S3 Leser +
  Übergabe + Dispatcher (Callbacks sync/async), S4 Befehle + Warteschlange (30 s Altersgrenze),
  S5 Antwort-Slot mit 15 s Zeitlimit, S6 Token-Erneuerung (getkey → refreshjwt), S7 gesicherte
  Befehle (getvisusalt → jdev/sps/ios), S8 Strukturdatei + Zeitstempel (LoxAPPversion3).
- HTTPS/WSS (Gen 2): Transport kann TLS. Session-Tests über TLS laufen (`tests/session_tls.rs`).
  Das Mock-Zertifikat ist jetzt eine CA plus Serverzertifikat für localhost/127.0.0.1.
- S9 Abschluss erledigt: `Session::close()` sendet Close-Frame, liefert `Disconnected { Requested }` als letztes Ereignis und wartet auf die Aufgaben. Nach AuthFailed wird die Verbindung ebenfalls geschlossen (Test `tests/session_close.rs`).
- S10 erledigt: `Session::event_backlog()` zeigt die wartenden Ereignisse. Ab 1000 wird einmal gewarnt, erneut erst nach Erholung auf die Hälfte.
- Die Schnittstelle `Session::close(self)` ist die einzige Stelle zum Beenden. Nach `AuthFailed` schließt die Session selbst.

## Entscheidungen (Kurzfassung)

- Reconnect gehört zu `supervisor` (nicht gebaut). Befehle während Trennung: Warteschlange, Altersgrenze 30 s,
  Konfigurationsoption `max_command_age`. Verworfene Befehle werden als Ereignis gemeldet.
- Ereignisse: nichts verwerfen, nichts zusammenfassen. Leser wartet nie. Unbegrenzte Übergabe.
- Callbacks sowohl sync als auch async.
- Strukturdatei: Caching liegt beim Aufrufer.
- killtoken ist aus dem Projekt gestrichen (wirkt auf dem Gerät nicht).
- checktoken mit Klartext-Token (Hash liefert 401).
- Refresh: Schlüssel aus Klartext-`getkey`, nicht aus `getkey2`.
- Logging: vorläufig `eprintln!`. Das Crate `log` ist noch nicht freigegeben.

## Offen für dich

1. Gesicherte Befehle am echten Gerät testen: Entität im Testraum nennen (mit/ohne Visu-Passwort).
2. `log`-Crate freigeben oder nicht.
3. Live-Test (L1) gegen <MINISERVER_IP> nach Freigabe.
4. Python-Bibliothek (pyloxone-api) verbessern oder PyO3-Bindung: später, nach fertiger Rust-Implementierung.
5. Gen 2 hat kein Testgerät. HTTPS/WSS nur mit Mock geprüft.

## Nächste Schritte

- Danach Plan/Aufgaben für `supervisor` (Reconnect + Warteschlange) schreiben und freigeben lassen.

## Hinweise aus den Tests

- Der Mock speichert Tokens über Verbindungen hinweg. Ein neuer Schlüsselaustausch setzt Salt-Kette und
  Verbindungsschlüssel zurück.
- Ein Befehl, den der Mock nicht annimmt, wird mit 401 (Kette/Hash) oder 404 (unbekannt) beantwortet.
- Vor dem Test der Session-Befehle auf Antworten wartet der Test mit `wait_count` (Mock kann verzögert sein).
