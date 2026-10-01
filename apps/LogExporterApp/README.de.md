# Log Exporter App

[English version](README.md)

Eine DNS-App für ZenitiumDNS, die das Anfrageprotokoll in eine Datei, an einen HTTP-Endpunkt oder an Syslog exportiert. Mehrere Ziele können gleichzeitig aktiv sein.

## Installation

Die App wird mit ZenitiumDNS ausgeliefert und beim ersten Start installiert, bleibt aber ausgeschaltet. Unter **Apps** einschalten und mit **Konfigurieren** die Einstellungen bearbeiten.

## Konfiguration

```json
{
  "maxQueueSize": 1000000,
  "enableEdnsLogging": false,
  "file": {
    "enabled": false,
    "path": "./dns_logs.json"
  },
  "http": {
    "enabled": false,
    "endpoint": "http://localhost:5000/logs",
    "headers": {
      "Authorization": "Bearer abc123"
    }
  },
  "syslog": {
    "enabled": false,
    "address": "127.0.0.1",
    "port": 514,
    "protocol": "UDP"
  }
}
```

| Schlüssel | Standard | Beschreibung |
| --------- | -------- | ------------ |
| `maxQueueSize` | `1000000` | Höchstzahl der Einträge, die auf den Export warten. Weitere Anfragen werden erst wieder exportiert, wenn in der Warteschlange Platz ist. Fehlt der Wert oder ist er `0`, gilt der Standard. |
| `enableEdnsLogging` | `false` | Ergänzt die Extended DNS Errors der Antwort (`edns` mit `errType` und `message`). |
| `file.enabled` | `false` | Schreibt pro Zeile ein JSON-Objekt in eine Datei. |
| `file.path` | | Pfad der Datei. Ein relativer Pfad bezieht sich auf den Ordner der App im Konfigurationsordner (etwa `/etc/zenitiumdns/apps/LogExporterApp`), in den der Dienst schreiben darf; fehlende Ordner werden angelegt. |
| `http.enabled` | `false` | Sendet die Einträge an einen HTTP-Endpunkt. |
| `http.endpoint` | | Absolute `http`- oder `https`-Adresse, die die Einträge per `POST` erhält. Die Anfrage nutzt den im Server eingestellten Proxy. |
| `http.headers` | | Zusätzliche Request-Header, etwa zur Authentifizierung. |
| `syslog.enabled` | `false` | Sendet die Einträge an einen Syslog-Server. |
| `syslog.address` | | Hostname oder IP-Adresse des Syslog-Servers; für `local` nicht nötig. |
| `syslog.port` | `514` | Port des Syslog-Servers. |
| `syslog.protocol` | `UDP` | `UDP`, `TCP`, `TLS` (TCP mit TLS) oder `local` (lokaler Syslog-Socket). |

Die App sammelt die Einträge im Speicher und exportiert sie alle 10 Sekunden in Paketen von bis zu 1.000 Einträgen. Übrige Einträge werden exportiert, wenn die App ausgeschaltet wird oder der Server anhält.

## Ausgabe

**Datei:** ein JSON-Objekt pro Zeile.

```json
{"answers":[{"dnssecStatus":"Disabled","name":"example.com","recordClass":"IN","recordData":"93.184.215.14","recordTtl":300,"recordType":"A"}],"clientIp":"192.168.1.20","edns":[],"protocol":"Udp","question":{"questionClass":"IN","questionName":"example.com","questionType":"A"},"responseCode":"NoError","responseRtt":12.5,"responseType":"Recursive","timestamp":"2026-09-30T17:04:04.483Z"}
```

`responseType` ist `Recursive`, `Cached`, `Blocked`, `UpstreamBlocked`, `UpstreamBlockedCached`, `Authoritative` oder `Dropped`; `responseRtt` (Millisekunden) gibt es nur bei rekursiven Antworten. Der Zeitstempel ist in UTC.

**HTTP:** alle zwei Sekunden ein `POST` mit `Content-Type: application/json` und einem JSON-Array von Log-Ereignissen. Jedes Ereignis enthält `Timestamp`, `Level` und das oben gezeigte JSON-Objekt als Zeichenkette in `RenderedMessage`.

**Syslog:** Nachrichten nach RFC 5424 mit der Facility `local6` und dem App-Namen `ZenitiumDNS`. Die Felder gehen als strukturierte Daten mit (`clientIp`, `protocol`, `responseType`, `responseRtt`, `rCode`, `qName`, `qType`, `qClass`, `aName_0`, `aRData_0` …), der Nachrichtentext ist eine kurze Zusammenfassung wie `QNAME: example.com, QTYPE: A, QCLASS: IN; RCODE: NoError; ANSWER: [93.184.215.14]`.

Client-Adressen werden unverändert exportiert; die Option „Keine Client-Adressen protokollieren“ unter Einstellungen > Protokollierung gilt nur für das Server-Protokoll. Die App rotiert die Datei nicht; dafür eignet sich etwa `logrotate` mit `copytruncate`.
