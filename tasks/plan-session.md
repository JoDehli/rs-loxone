# Implementierungsplan: Modul `session`

Spec: `SPEC-session.md` (freigegeben, außer dem Test gesicherter Befehle an einer Entität, der später folgt).
Aufgaben: `tasks/todo-session.md`. Eigene Datei, damit `tasks/plan.md` (Protokoll, Auth, Transport) unberührt bleibt.

## Überblick

`session` ist eine angemeldete Verbindung zu einem Gen-1-Miniserver: Login, Befehle senden,
Ereignisse weitergeben, Token erneuern. Es verbindet nicht selbst neu. Das macht `supervisor` (später).

## Architekturentscheidungen

- **Leser wartet nie.** Er liest Frames und gibt jedes Ereignis an eine unbegrenzte Übergabe ab.
- **Dispatcher** ruft Callbacks in Eingangsreihenfolge auf, synchron oder asynchron. Er wartet pro
  Callback, nicht auf den Leser. Fehler im Callback werden abgefangen.
- **Ein Verschlüsselungskreis pro Verbindung.** Alle verschlüsselten Befehle laufen durch denselben
  `EncCipher` (Salt-Kette).
- **Befehlswarteschlange** (Altersgrenze `max_command_age`, Standard 30 s) für Befehle vor dem Login
  und während einer Trennung. Gesendet wird erst, wenn Login und `enablebinstatusupdate` durch sind.
  Verworfene Befehle werden als Ereignis gemeldet.
- **Antwort-Slot nur für mehrstufige Abläufe** (Login, Refresh, gesicherter Befehl). Normale Befehle
  kehren nach dem Senden zurück.
- **Offen zu klären:** Wo liegt die Befehlswarteschlange? Sie braucht die Verbindung. Vorschlag: sie liegt
  in `session` als Puffer, den `supervisor` beim Wiederverbinden übernimmt. Das prüfen wir vor S3.

## Aufgaben

### Phase 1: Grundlagen
- [x] S0: Modulgerüst, Konfiguration (`SessionConfig`), Fehlertyp, Ereignistyp
- [x] S1: Mock-Miniserver als eigenes Crate `loxone-mock/` (entschlüsselt `enc`, prüft Salt-Kette und Hashes, beantwortet Login-Befehle, sendet Frames)

### Phase 2: Login und Empfang
- [x] S2: Login-Ablauf (keyexchange, getkey2, authwithtoken oder getjwt, enablebinstatusupdate)
- [x] S3: Leser mit Frame-Paarung (Header + Payload, geschätzte Header), Übergabe, Dispatcher

### Checkpoint: Login und Empfang
- [ ] Login gegen Mock (Passwort und gespeichertes Token, inkl. Rückfall auf Passwort)
- [ ] Zustands- und Textnachrichten kommen in Reihenfolge am Callback an
- [ ] `cargo test`, `clippy -D warnings`, `fmt --check`

### Phase 3: Befehle und Abläufe
- [x] S4: Befehle senden, Warteschlange mit Altersgrenze, Meldung bei Verwerfen
- [x] S5: Antwort-Slot für mehrstufige Abläufe mit Zeitlimit
- [x] S6: Token-Erneuerung (getkey, refreshjwt, Zeitplan, Fehlerzähler)
- [x] S7: Gesicherte Befehle (getvisusalt, jdev/sps/ios) gegen Mock

### Checkpoint: Befehle und Abläufe
- [ ] Refresh im Mock: Salt-Kette bleibt konsistent
- [ ] Gesicherter Befehl im Mock: richtiger Pfad und Hash
- [ ] Alle Tests grün, Clippy und fmt sauber

### Phase 4: Abschluss
- [x] S8: Strukturdatei holen und `lastModified` lesen (`jdev/sps/LoxAPPversion3`)
- [x] S9: Beenden und Trennung melden (`Disconnected` als letztes Ereignis, Gründe unterscheiden)
- [x] S10: Warnung bei stark wachsender Ereignis-Übergabe

### Checkpoint: Session fertig
- [ ] Alle Spec-Kriterien im Mock erfüllt
- [ ] Live-Test gegen <MINISERVER_IP> (nach deiner Freigabe)
- [ ] Gesicherter Befehl am echten Gerät (wenn Entität gefunden)

## Risiken

| Risiko | Auswirkung | Gegenmaßnahme |
|---|---|---|
| Befehlswarteschlange liegt in der falschen Schicht | Hoch | Vor S4 klären (siehe oben) |
| Gerät verhält sich bei Befehlen anders als im Mock | Mittel | Live-Test nach dem Mock, mit deiner Freigabe |
| Unbegrenzte Übergabe wächst, wenn ein Callback hängt | Mittel | Längenüberwachung (S10), Warnung |
| Salt-Kette bricht bei neuer Verschlüsselung | Hoch | Ein Cipher pro Verbindung, Test im Mock |
| Gesicherter Befehl ohne Testgerät | Niedrig | Test verschoben, bis du eine Entität nennst |
