# Query Logs SQLite App

[English version](README.md)

Eine DNS-App für ZenitiumDNS, die DNS-Anfragen in eine SQLite-Datenbank protokolliert.

## Überblick

- **Asynchrones Protokollieren** – Einträge laufen über eine begrenzte Warteschlange
- **Aufräumen** – alte Einträge werden nach Alter oder Anzahl gelöscht
- **Optionaler Speichermodus** – kann eine Datenbank im Arbeitsspeicher verwenden
- **Vacuum** – kann die Datenbank nach dem Aufräumen verdichten

## Einbindung und Erweiterungspunkte

- Implementiert: `IDnsApplication`, `IDnsQueryLogger`, `IDnsQueryLogs`
- Läuft als Anfrageprotokoll mit asynchronem Speichern.

## Datenbank

Die Datenbanktabelle speichert einige Felder als Zahlen. Die Felder und ihre Werte:

### Feld Protokoll

| Protokoll | Wert | Beschreibung |
| -------- | ----- | ----------- |
| 0 | UDP | Das übliche DNS über UDP |
| 1 | TCP | Das übliche DNS über TCP |
| 2 | TLS | DNS-over-TLS, RFC 7858 |
| 3 | HTTPS | DNS-over-HTTPS, RFC 8484 |
| 5 | QUIC | DNS-over-QUIC, RFC 9250 |
| 253 | UdpProxy | PROXY-Protokoll über UDP |
| 254 | TcpProxy | PROXY-Protokoll über TCP |

### Feld Antworttyp

| Antworttyp | Wert | Beschreibung |
| ------------- | ----- | ----------- |
| 1 | Authoritative | Antwort, die der DNS-Server selbst erzeugt hat |
| 2 | Recursive | Antwort aus einer rekursiven Anfrage an einen Upstream |
| 3 | Cached | Antwort aus dem Cache des DNS-Servers |
| 4 | Blocked | Antwort, mit der der DNS-Server eine Anfrage blockiert |
| 5 | UpstreamBlocked | Antwort eines Upstreams, der eine Anfrage blockiert |
| 6 | UpstreamBlockedCached | Antwort aus dem Cache des DNS-Servers mit einer Blockierantwort eines Upstreams |
| 7 | Dropped | Eine `null`-Antwort des DNS-Servers, die anzeigt, dass die Anfrage verworfen wurde |

## Konfiguration

`dnsApp.config` enthält diese Schlüssel:

| Eigenschaft | Typ | Standard | Beschreibung |
| --- | --- | --- | --- |
| `enableLogging` | boolean | `true` | Schaltet das Protokollieren ein oder aus. |
| `maxQueueSize` | number | `200000` | Größe der begrenzten Warteschlange. |
| `maxLogDays` | number | `0` | Höchstalter der aufbewahrten Einträge in Tagen. `0` schaltet das Aufräumen nach Alter ab. |
| `maxLogRecords` | number | `0` | Höchstzahl der aufbewahrten Einträge. `0` schaltet das Aufräumen nach Anzahl ab. |
| `enableVacuum` | boolean | `false` | Führt nach dem Aufräumen `VACUUM` aus, wenn Einträge gelöscht wurden. |
| `useInMemoryDb` | boolean | `false` | Verwendet eine SQLite-Datenbank im Arbeitsspeicher. |
| `sqliteDbPath` | string | `querylogs.db` | Pfad zur SQLite-Datenbankdatei. |
| `connectionString` | string | `Data Source='{sqliteDbPath}'; Cache=Shared;` | Vorlage für die SQLite-Verbindungszeichenfolge. |

Das Beispiel unten entspricht der mitgelieferten `dnsApp.config`, die im ausgelieferten Paket standardmäßig nach 7 Tagen und ab 10.000 Einträgen aufräumt.

### Beispiel

```json
{
  "enableLogging": true,
  "maxQueueSize": 200000,
  "maxLogDays": 7,
  "maxLogRecords": 10000,
  "enableVacuum": false,
  "useInMemoryDb": false,
  "sqliteDbPath": "querylogs.db",
  "connectionString": "Data Source='{sqliteDbPath}'; Cache=Shared;"
}
```

## Verhalten zur Laufzeit

1. Anfragen werden in einem begrenzten Channel gepuffert.
2. Ein Hintergrund-Thread schreibt die Einträge gebündelt in SQLite.
3. Ein Timer löscht regelmäßig alte Einträge.
4. Ist `enableVacuum` eingeschaltet und wurden beim Aufräumen Einträge gelöscht, wird die Datenbank verdichtet.

## Risiken und Hinweise für den Betrieb

- Läuft die Warteschlange über, gehen Einträge verloren (Verhalten `DropWrite`).
- Konkurrierende Schreibzugriffe auf SQLite können bei hohem Verkehr bremsen.
- Im Speichermodus bleiben die Daten über einen Neustart nicht erhalten.

## Fehlersuche

- Prüfe, ob der Datenbankpfad beschreibbar ist.
- Prüfe, ob `connectionString` noch den Platzhalter `{sqliteDbPath}` enthält.
- Prüfe das Protokoll des Servers auf SQLite-Fehler, wenn das Protokollieren stoppt.
