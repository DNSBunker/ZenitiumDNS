# Benchmark-Kit

[English version](README.md)

Mit diesem Kit werden ZenitiumDNS und Technitium DNS Server unter gleichen Bedingungen gemessen. Die Ergebnisse in [docs/Performance.de.md](../../docs/Performance.de.md) sind damit entstanden.

Alles läuft in einem unprivilegierten Netz-Namespace (`unshare`); das Netz des Rechners bleibt unberührt, echte Nameserver werden nicht befragt:

- `fakeauth.py` simuliert einen Root-Server (10.53.0.1) und die Top-Level-Domain `deadtld` (10.53.0.2). Jeder Name unter `deadtld` löst auf, Namen, die mit `nx` beginnen, liefern NXDOMAIN.
- `named.root` verweist den DNS-Server auf den simulierten Root. Die Datei wird in einem eigenen Mount-Namespace über die `named.root` des Programmordners gelegt; der Ordner selbst wird nicht verändert.
- `dnsload.c` ist der Lastgenerator: feste Anfragerate, 1.000 Client-Adressen (10.60.0.0/16 auf dem Loopback-Gerät), 75 % A- und 25 % AAAA-Anfragen, Latenz-Histogramm mit 10 µs Auflösung.
- `tlsload/` ist ein kleines .NET-Programm für Last über DNS-over-TLS (und DNS-over-HTTPS): feste Anfragerate über 32 Verbindungen mit Pipelining, Latenzhistogramm. `bench.sh` baut es mit `$DOTNET` und erzeugt ein selbstsigniertes Zertifikat für den Server; ohne .NET-SDK entfällt der DoT-Test.
- Ein optionaler Ordner mit Blocklisten wird per HTTP (10.53.0.5:8080) bereitgestellt, damit beide Server sie auf dieselbe Weise laden.

## Voraussetzungen

Linux mit User-Namespaces, `gcc`, `python3`, `curl`, `taskset`, `iproute2`, `openssl`. Für Technitium wird die .NET-10-Laufzeit (`dotnet`) gebraucht, für den DoT-Test das .NET-10-SDK; ZenitiumDNS wird eigenständig veröffentlicht.

## Ausführen

```
dotnet publish src/ZenitiumDns/ZenitiumDns.csproj -c Release -r linux-x64 --self-contained true -o /tmp/zenitiumdns
curl -sSL -o /tmp/tdns.tar.gz https://download.technitium.com/dns/DnsServerPortable.tar.gz
mkdir -p /tmp/technitium && tar xzf /tmp/tdns.tar.gz -C /tmp/technitium

unshare -rnm bash tools/benchmark/bench.sh zenitiumdns zenitiumdns /tmp/zenitiumdns /pfad/zu/listen
unshare -rnm bash tools/benchmark/bench.sh technitium technitium /tmp/technitium /pfad/zu/listen
```

Das letzte Argument ist optional: ein Ordner mit Blocklisten im reinen Domain-Format (eine Domain pro Zeile). Die Ergebnisse landen in `tools/benchmark/results/<label>/results.txt`.

| Variable | Standard | Bedeutung |
| -------- | -------- | --------- |
| `SERVER_CPUS` | `0-3` | CPUs, die der DNS-Server nutzen darf (`taskset`). |
| `LOAD_CPUS` | `8-15` | CPUs des Lastgenerators; getrennt vom Server halten. |
| `DOTNET` | `dotnet` | Pfad des .NET-Hosts für Technitium und des SDK, das `tlsload` baut. |
| `SERVER_ENV` | leer | Zusätzliche Umgebungsvariablen für den Server, etwa `DOTNET_gcServer=0`. |
| `QUICK` | `0` | `1` führt nur den Test mit Cache-Treffern aus, `2` nur den Test mit rekursiver Auflösung. |
| `OUT` | `tools/benchmark/results` | Ausgabeordner. |

Vor den Tests erhalten beide Server dieselben Einstellungen: lauschen auf 10.53.0.10, DNSSEC-Validierung aus (die simulierten Zonen sind unsigniert), höchstens 100.000 Cache-Einträge (Standard bei Technitium 10.000, bei ZenitiumDNS 100.000), DNS-over-TLS auf Port 853 mit dem erzeugten Zertifikat, und die Lastnetze sind von der Ratenbegrenzung ausgenommen (Technitium: `qpmLimitBypassList`, ZenitiumDNS: `rateLimitBypassList`). Alles andere bleibt auf den Standardwerten einer Neuinstallation.

## Tests

| Ergebnis | Test |
| -------- | ---- |
| `idle_rss_mb` | Belegter Speicher nach dem Start. |
| `cache_hits_40k_*` | 40.000 Anfragen/s über 30 s für 5.000 Namen, die schon im Cache liegen (nach 15 s Aufwärmen). CPU-Zeit pro Anfrage (User + System des Serverprozesses), Latenz-Perzentile, belegter Speicher. |
| `cache_hits_max_*` | 1.000.000 Anfragen/s angeboten über 15 s; Median der Antworten pro Sekunde in den 10-Sekunden-Abschnitten. |
| `dot_8k_*` | DNS-over-TLS, 8.000 Anfragen/s über 30 s auf 32 Verbindungen, Namen, die schon im Cache liegen. CPU-Zeit pro beantworteter Anfrage und Latenzperzentile. |
| `resolve_2k_*` | 2.000 Anfragen/s über 30 s, jeder Name neu, also braucht jede Anfrage eine rekursive Auflösung über Root und TLD. |
| `fill_1m_*` | Cache-Grenze aufgehoben, 20.000 neue Namen pro Sekunde über 50 s (1 Million Namen). Antworten, Latenz, Cache-Einträge und belegter Speicher 20 s nach der Last. |
| `blocklist_*` | Blocklisten geladen; Anzahl der Domains und belegter Speicher 30 s nach dem Laden. |
| `blocked_40k_*` | 40.000 Anfragen/s, die Hälfte für blockierte Namen, die andere für Namen im Cache. |

## Grenzen

Die Last kommt vom selben Rechner über das Loopback-Gerät; die Zahlen zeigen also den Verarbeitungsaufwand im Server, keine Netzwerkeffekte. Die simulierten autoritativen Server antworten sofort; reale Auflösungszeiten hängen vom Internet ab. Laptop-CPUs ändern ihren Takt, einzelne Läufe streuen deshalb; jeden Server mehrmals abwechselnd laufen lassen und Mediane vergleichen.
