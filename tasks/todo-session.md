# Aufgaben: Modul `session`

Plan: `tasks/plan-session.md`. Spec: `SPEC-session.md`.
Jede Aufgabe: Mock-Test zuerst, dann Umsetzung. Prüfbefehle: `cargo test -p rs-loxone session`,
`cargo clippy --all-targets -- -D warnings`, `cargo fmt --check`.

## S0: Modulgerüst, Konfiguration, Fehler- und Ereignistyp
- Akzeptanz: `SessionConfig` mit `max_command_age` (Standard 30 s), `Event`, `SessionError`.
- Dateien: `src/session/mod.rs`, `src/session/event.rs`.

## S1: Mock-Miniserver (erledigt: eigenes Crate `loxone-mock/`)
- Akzeptanz: Mock entschlüsselt `enc` mit dem Testschlüssel, beantwortet `getkey2`, `getjwt`,
  `authwithtoken`, `enablebinstatusupdate`, `getkey`, `refreshjwt`; sendet Frames; kann ablehnen (401, 404).
- Dateien: `tests/session/mock.rs`.

## S2: Login
- Akzeptanz: Passwort-Login, Token-Login (> 100 s gültig), Rückfall auf Passwort bei 401/404,
  `enablebinstatusupdate` verschlüsselt gesendet, `Connected` als Ereignis.
- Abhängig von: S0, S1.

## S3: Leser, Übergabe, Dispatcher (erledigt)
- Akzeptanz: Header + Payload werden gepaart; geschätzter Header wird vom exakten gefolgt;
  Zustandsmeldungen (`ValueStates`, `TextStates`) kommen in Reihenfolge an; Ausfall (Out-of-Service)
  beendet mit `Disconnected`; Leser blockiert nie (Test: langsamer Callback hält Leser nicht an).
- Abhängig von: S2.

## S4: Befehle und Warteschlange (erledigt)
- Akzeptanz: `send_command` kehrt nach dem Senden zurück; vor dem Login oder während der Trennung
  in der Warteschlange; nach Login und Freigabe in Reihenfolge gesendet; Befehle älter als
  `max_command_age` verworfen und als Ereignis gemeldet.
- Abhängig von: S3. Vor Beginn: Lage der Warteschlange klären (siehe Plan).

## S5: Antwort-Slot (erledigt)
- Akzeptanz: Mehrstufige Abläufe warten auf ihre Antwort mit Zeitlimit; normale Befehle nicht.
- Abhängig von: S3.

## S6: Token-Erneuerung (erledigt)
- Akzeptanz: Zeitplan `refresh_delay`; Ablauf: `getkey` (plain), Hash mit diesem Schlüssel,
  `refreshjwt` verschlüsselt; 200 aktualisiert Token und meldet `TokenChanged`; 5 Versuche pro Zyklus,
  nach 10 Fehlzyklen `AuthFailed`.
- Abhängig von: S5.

## S7: Gesicherte Befehle (erledigt)
- Akzeptanz: `getvisusalt` dann `jdev/sps/ios/<hash>/<uuid>/<wert>`; Antwort 200 Erfolg, 500 falscher Code.
- Abhängig von: S5.

## S8: Strukturdatei und Versionsprüfung (erledigt)
- Akzeptanz: `structure()` liefert die Bytes unverändert; `lastModified` über `jdev/sps/LoxAPPversion3`.
- Abhängig von: S2.

## S9: Beenden (erledigt)
- Akzeptanz: `close()` sendet Schließen und beendet Aufgaben; `Disconnected` ist das letzte Ereignis,
  mit Grund (Geschlossen, Verloren, Außer Betrieb, Angefordert).
- Abhängig von: S3.

## S10: Längenüberwachung der Übergabe (erledigt)
- Akzeptanz: Warnung, wenn die Übergabe über einen Schwellwert wächst; Reader bleibt unbeeinflusst.
- Abhängig von: S3.

## Nachbesserungen aus dem Code-Review

- [x] NaN/Unendlich als `validUntil` abgelehnt (`auth/token.rs`), mit Test.
- [x] TLS-Erkennung nach Typ statt Text, geschachtelte `io::Error` werden durchsucht; eine gemeinsame Funktion `transport::tls::is_tls_error` für HTTP und WebSocket (`transport/tls.rs`), mit Tests.
- [x] Login-Antwort: kaputte Frames werden übersprungen, `OutOfService` beendet das Warten mit `SessionError::OutOfService` (`session/login.rs`), mit Tests.
- [x] `ensure_200` nutzt `auth::reply::ensure_success` (keine doppelte Logik mehr).
- [x] Frame-Zuordnung: ein neuer Header während eines geschätzten Headers muss dieselbe Art haben und darf nicht geschätzt sein (`session/frames.rs`), mit Test.
- [x] Antwort-Zuordnung: nur noch spezifische Befehlsnamen (`refreshjwt`, `getvisusalt`, `jdev/sps/ios`), `enc/` entfernt (`session/refresh.rs`, `session/secured.rs`), mit Test.
- [x] `src/main.rs` (Cargo-Vorlage) entfernt.
- [x] Basic-Auth mit Klartext-Passwort über `http://`: Warnung beim Verbinden (`session::plain_http_warning`), Hinweis im Modul `transport/http.rs`, mit Tests.
- [ ] Offen: Die Frame-Zuordnung kann bei einer exakt 8 Byte langen Nutzlast, die mit `0x03` beginnt und dieselbe Art wie der geschätzte Header hat, weiterhin falsch sein. Das ist ein bekannter Rest, kein Fehler im Normalfall.
