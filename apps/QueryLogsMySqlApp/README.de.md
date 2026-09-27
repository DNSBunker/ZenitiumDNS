# Query Logs MySQL App

[English version](README.md)

Eine DNS-App für ZenitiumDNS, die DNS-Anfragen in eine MySQL- oder MariaDB-Datenbank protokolliert.

## Überblick

- **Asynchrones Protokollieren** – Einträge laufen über eine begrenzte Warteschlange
- **Aufräumen** – alte Einträge werden nach Alter oder Anzahl gelöscht
- **Festes Schema** – speichert unter einem Datenbanknamen über eine Verbindungszeichenfolge

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
| `enableLogging` | boolean | `false` | Schaltet das Protokollieren der Anfragen ein oder aus. |
| `maxQueueSize` | number | `1000000` | Höchstzahl der Einträge in der Warteschlange im Arbeitsspeicher, bevor neue Einträge verworfen werden. |
| `maxLogDays` | number | `0` | Höchstalter der aufbewahrten Einträge in Tagen. `0` schaltet das Aufräumen nach Alter ab. |
| `maxLogRecords` | number | `0` | Höchstzahl der aufbewahrten Einträge. `0` schaltet das Aufräumen nach Anzahl ab. |
| `databaseName` | string | `"DnsQueryLogs"` | Name der Datenbank, in der die Einträge gespeichert werden. |
| `connectionString` | string | *(Pflicht)* | MySQL-Verbindungszeichenfolge **ohne** Datenbanknamen. Die App hängt intern `Database={databaseName};` an. |

### Beispiel

```json
{
  "enableLogging": false,
  "maxQueueSize": 1000000,
  "maxLogDays": 0,
  "maxLogRecords": 0,
  "databaseName": "DnsQueryLogs",
  "connectionString": "Server=192.168.180.128; Port=3306; Uid=username; Pwd=password;"
}
```

## Verhalten zur Laufzeit

1. Anfragen werden in einem begrenzten Channel gepuffert.
2. Ein Hintergrund-Thread schreibt die Einträge gebündelt in die MySQL- oder MariaDB-Datenbank.
3. Ein Timer löscht regelmäßig alte Einträge.

## Risiken und Hinweise für den Betrieb

- Läuft die Warteschlange über, gehen Einträge verloren (Verhalten `DropWrite`).
- Verbindungsprobleme zur Datenbank können das Protokollieren stoppen.
- Bei hohem Verkehr sollte die Schreiblatenz überwacht werden.

## Fehlersuche

- Prüfe, ob die Datenbank erreichbar ist und die Zugangsdaten stimmen.
- Prüfe die Verbindungszeichenfolge und `databaseName`.
- Prüfe das Protokoll des Servers auf Fehler des SQL-Clients.
