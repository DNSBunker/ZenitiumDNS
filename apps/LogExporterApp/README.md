# Log Exporter App

[Deutsche Version](README.de.md)

A DNS App for ZenitiumDNS that exports the query log to a file, an HTTP endpoint or syslog. Several targets can be active at the same time.

## Installation

The app ships with ZenitiumDNS and is installed on the first start, but stays disabled. Enable it under **Apps** and edit the configuration with **Configure**.

## Configuration

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

| Key | Default | Description |
| --- | ------- | ----------- |
| `maxQueueSize` | `1000000` | Maximum number of entries waiting for export. Further queries are not exported until the queue has space again. Missing or `0` means the default. |
| `enableEdnsLogging` | `false` | Adds the Extended DNS Errors of the response (`edns`, with `errType` and `message`). |
| `file.enabled` | `false` | Writes one JSON object per line into a file. |
| `file.path` | | Path of the file. A relative path refers to the folder of the app inside the configuration folder (for example `/etc/zenitiumdns/apps/LogExporterApp`), which the service may write to; missing folders are created. |
| `http.enabled` | `false` | Sends the entries to an HTTP endpoint. |
| `http.endpoint` | | Absolute `http` or `https` address that receives the entries with `POST`. The request uses the proxy configured in the server. |
| `http.headers` | | Additional request headers, for example for authentication. |
| `syslog.enabled` | `false` | Sends the entries to a syslog server. |
| `syslog.address` | | Host name or IP address of the syslog server; not needed for `local`. |
| `syslog.port` | `514` | Port of the syslog server. |
| `syslog.protocol` | `UDP` | `UDP`, `TCP`, `TLS` (TCP with TLS) or `local` (local syslog socket). |

The app collects entries in memory and exports them every 10 seconds in batches of up to 1,000 entries. Remaining entries are exported when the app is disabled or the server stops.

## Output

**File:** one JSON object per line.

```json
{"answers":[{"dnssecStatus":"Disabled","name":"example.com","recordClass":"IN","recordData":"93.184.215.14","recordTtl":300,"recordType":"A"}],"clientIp":"192.168.1.20","edns":[],"protocol":"Udp","question":{"questionClass":"IN","questionName":"example.com","questionType":"A"},"responseCode":"NoError","responseRtt":12.5,"responseType":"Recursive","timestamp":"2026-09-30T17:04:04.483Z"}
```

`responseType` is `Recursive`, `Cached`, `Blocked`, `UpstreamBlocked`, `UpstreamBlockedCached`, `Authoritative` or `Dropped`; `responseRtt` (milliseconds) is only present for recursive answers. The timestamp is in UTC.

**HTTP:** every two seconds a `POST` with `Content-Type: application/json` and a JSON array of log events. Each event contains `Timestamp`, `Level` and the JSON object shown above as a string in `RenderedMessage`.

**Syslog:** RFC 5424 messages with facility `local6` and the app name `ZenitiumDNS`. The fields are sent as structured data (`clientIp`, `protocol`, `responseType`, `responseRtt`, `rCode`, `qName`, `qType`, `qClass`, `aName_0`, `aRData_0` …), the message text is a short summary such as `QNAME: example.com, QTYPE: A, QCLASS: IN; RCODE: NoError; ANSWER: [93.184.215.14]`.

Client addresses are exported as they are; the option "Do not log client addresses" under Settings > Logging only applies to the server log. The file is not rotated by the app; use `logrotate` with `copytruncate` for example.
