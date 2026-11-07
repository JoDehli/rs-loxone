# Aufgaben: `supervisor`

Spec: `SPEC-supervisor.md` (freigegeben). Stand nach dieser Runde.

- [x] S1 Warteschlange (`supervisor/outbox.rs`): Reihenfolge, Altersgrenze (genau 30 s wird noch gesendet), Wiedereinreihen vorn, Visu-Code als `Zeroizing` und im Debug-Ausdruck verdeckt. 6 Tests.
- [x] S2 Wiederverbinden und Backoff (`supervisor/backoff.rs`, `supervisor/mod.rs`): 5 s bis 60 s mit ±20 % Jitter, Zählung wird nach 60 s stabiler Verbindung zurückgesetzt. Ereignisse `Reconnecting` und `GaveUp` in `session::Event`. Tests gegen den Mock: Wiederverbinden nach Abbruch, Befehl während der Wartezeit genau einmal, abgelaufener Befehl wird mit ID gemeldet, `close()` als letztes Ereignis ohne Wiederverbinden.
- [x] S3 Auth-Eskalation: abgelehntes Passwort stoppt ohne zweiten Versuch (`GaveUp`); `AuthFailed` führt einmal zu einer Passwort-Anmeldung, beim zweiten Mal `GaveUp`. Test: `token_renewal_refused_after_password_login_gives_up`.
- [x] S4 Ereignisreihenfolge: `Reconnecting` kommt erst, nachdem das `Disconnected` der alten Session durch den Weiterleiter gelaufen ist. Der Fehler war im Test sichtbar (Reconnecting vor Disconnected).
- [x] S5 Doku und Aufgaben (diese Datei).

## Entschieden (Vorschläge aus der Spec übernommen)
- Wiederholung ohne Obergrenze, nur bei Transportfehlern, bis `close()`.
- Stabil = 60 s bestanden.
- Warteschlange ohne Größenlimit in v1; ab 1000 Befehlen gibt es eine Warnung.
- `Reconnecting` pro Versuch einmal.
- Token wird aus der beendeten Session übernommen (`session.token()`).

## Abweichungen und Lücken
- **Zustellung ist höchstens einmal.** Ein Befehl, der beim Abbruch schon an den Schreiber übergeben war, kann verloren gehen, wird aber nie doppelt gesendet. Die Anforderung „Befehle nach dem Wiederverbinden senden“ gilt für Befehle, die während der Trennung ankommen. Der Test deckt genau diesen Fall ab.
- [x] Fehlgeschlagene Befehle (z. B. gesicherter Befehl mit falschem Code) werden als `Event::CommandFailed { id, reason }` gemeldet, ohne Befehlstext. Test: `refused_secured_command_is_reported_without_its_code`.
- [x] Längenwarnung der Warteschlange: ab 1000 wartenden Befehlen einmal eine Warnung, neu scharf nach dem Leeren. Test: `warns_once_when_the_queue_is_long`.
- `Secret` löscht seinen Inhalt nicht beim Freigeben. Deshalb nutzt die Warteschlange `zeroize::Zeroizing` für den Visu-Code. Die Spec nennt das so.
- Mock: neue Option `close_first_enables`, damit nur die ersten N Anmeldungen schließen.
- Login-Ablehnung: jede Antwort mit Klasse `Rejected` beim Verbinden stoppt (401, 403, 423, 4003, 4006). Vorübergehende Fehler werden wiederholt.

## Nicht getan
- Live-Test gegen das Gerät (wartet auf deine Freigabe).
- `cli-and-crate` (öffentliche Schnittstelle, eigenständige Binary).
