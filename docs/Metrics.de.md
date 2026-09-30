# Prometheus-Metriken

[English version](Metrics.md)

ZenitiumDNS kann ausführliche Kennzahlen im [Textformat von Prometheus](https://prometheus.io/docs/instrumenting/exposition_formats/) unter `/metrics` am Port der Weboberfläche bereitstellen. Der Endpunkt ist standardmäßig aus und wird unter Einstellungen > Weboberfläche > Prometheus-Metriken eingeschaltet.

Die Kennzahlen enthalten weder Client-Adressen noch Domainnamen. Abfragetypen und Antwortcodes, die ZenitiumDNS nicht kennt, werden als `other` gezählt, sodass zufällige Werte in Anfragen keine neuen Zeitreihen erzeugen können.

## Erfassung

Die ausführlichen Zähler werden nur erfasst, solange der Endpunkt eingeschaltet ist. Sie beginnen beim Einschalten und beim Start des Servers bei null; Prometheus wertet das als Zähler-Reset, `rate()` und `increase()` kommen damit zurecht. `zenitiumdns_metrics_start_time_seconds` zeigt, wann die Erfassung begonnen hat.

Der Server zählt die Anfragen im Statistik-Thread, der ohnehin jede beantwortete Anfrage verarbeitet. Der zusätzliche Aufwand sind einige Array-Inkremente pro Anfrage und bremst das Beantworten nicht. Anfragen an Nameserver und Weiterleitungsserver werden dort, wo sie gesendet werden, mit atomaren Inkrementen gezählt.

## Zugriff

| Einstellung | Standard | Bedeutung |
| ----------- | -------- | --------- |
| Metriken bereitstellen | aus | Schaltet den Endpunkt und die ausführliche Erfassung ein. Ausgeschaltet liefert `/metrics` 404. |
| Erlaubte Netze (ACL) | `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` | Adressen, die die Kennzahlen abrufen dürfen, eine Adresse oder ein Netz pro Zeile. Ein vorangestelltes `!` verweigert den Zugriff. Die Liste wird von oben nach unten ausgewertet; ist sie leer oder trifft kein Eintrag zu, lautet die Antwort 403. |
| Bearer-Token | leer | Ist es gesetzt, muss jeder Abruf `Authorization: Bearer <Token>` senden, sonst lautet die Antwort 401. 16 bis 255 sichtbare ASCII-Zeichen; die Schaltfläche „Erzeugen“ legt ein zufälliges Token mit 192 Bit an. |

Hinter einem Reverse Proxy verwendet die ACL wie der Rest der Weboberfläche die Client-Adresse aus dem Header mit Client-IP (Einstellungen > Weboberfläche > Hinter einem Reverse Proxy). Trägt ein Abruf `X-Forwarded-For` oder `Forwarded`, aber keinen verwertbaren Header mit Client-IP von einem erlaubten Proxy, kennt der Endpunkt die echte Client-Adresse nicht. Ohne Token werden solche Abrufe mit 403 abgelehnt, mit Token bei richtigem Token angenommen. Auf einem Server, der aus dem Internet erreichbar ist, sollte ein Token gesetzt oder die ACL auf die Adresse des Prometheus-Servers beschränkt werden.

Sitzungen der Weboberfläche berechtigen nicht zum Abruf von `/metrics`. Die JSON-Metriken unter `api/dashboard/metrics/json` erfordern weiterhin eine Sitzung mit dem Recht, die Übersicht anzusehen.

## Prometheus-Konfiguration

Die Einstellungsseite zeigt einen fertigen Eintrag mit der Adresse der Weboberfläche und dem Token. Beispiel:

```yaml
scrape_configs:
  - job_name: zenitiumdns
    scheme: https
    metrics_path: /metrics
    authorization:
      credentials: <Token>
    static_configs:
      - targets: ["dns.example.com:53443"]
```

Ein Abrufintervall von 15 bis 60 Sekunden genügt. Ein Abruf dauert wenige Millisekunden und liefert 20 bis 40 KB, Prometheus erhält sie mit gzip komprimiert.

## Kennzahlen

### Server

| Kennzahl | Typ | Labels | Bedeutung |
| -------- | --- | ------ | --------- |
| `zenitiumdns_build_info` | gauge | `version`, `runtime`, `arch` | Immer 1; Version des Pakets, .NET-Laufzeit und CPU-Architektur. |
| `zenitiumdns_start_time_seconds` | gauge | | Start des DNS-Servers als Unix-Zeit. |
| `zenitiumdns_uptime_seconds` | gauge | | Laufzeit des DNS-Servers. |
| `zenitiumdns_metrics_start_time_seconds` | gauge | | Beginn der ausführlichen Erfassung als Unix-Zeit. |
| `zenitiumdns_clients` | gauge | | Geschätzte Zahl verschiedener Client-Adressen seit dem Start (HyperLogLog). |
| `zenitiumdns_dnssec_validation_enabled` | gauge | | 1, wenn die DNSSEC-Validierung eingeschaltet ist. |
| `zenitiumdns_blocking_enabled` | gauge | | 1, wenn die Blockierung eingeschaltet ist. |
| `zenitiumdns_dns_cookies_enabled` | gauge | | 1, wenn DNS-Cookies (RFC 7873, RFC 9018) eingeschaltet sind. |
| `zenitiumdns_query_logging_suspended` | gauge | | 1, wenn der Watchdog das Protokollieren von Anfragen für den Rest des Tages angehalten hat. |

### Anfragen von Clients

| Kennzahl | Typ | Labels | Bedeutung |
| -------- | --- | ------ | --------- |
| `zenitiumdns_requests_total` | counter | `protocol`, `family` | Eingegangene Anfragen einschließlich verworfener. `protocol`: `udp`, `tcp`, `tls`, `https`, `quic`, `udp_proxy`, `tcp_proxy`; `family`: `ipv4`, `ipv6` des Clients. |
| `zenitiumdns_request_types_total` | counter | `type` | Anfragen je Abfragetyp (`A`, `AAAA`, `HTTPS` …, unbekannte Typen als `other`). |
| `zenitiumdns_request_flags_total` | counter | `flag` | Anfragen mit dem Flag oder Merkmal: `rd` (Rekursion gewünscht), `cd` (Prüfung abgeschaltet), `do` (DNSSEC OK), `edns`, `ecs` (EDNS Client Subnet), `cookie` (Option für DNS-Cookies). |
| `zenitiumdns_responses_total` | counter | `rcode` | Gesendete Antworten je Antwortcode (`NoError`, `NxDomain`, `ServerFailure`, `Refused`, `BADCOOKIE` …). |
| `zenitiumdns_response_sources_total` | counter | `source` | Herkunft der Antwort: `authoritative` (lokale Zonen, Anfragefilter, Sondernamen), `recursive`, `cached`, `blocked`, `upstream_blocked`, `upstream_blocked_cached`. |
| `zenitiumdns_response_flags_total` | counter | `flag` | Antworten mit dem Flag: `aa`, `tc` (gekürzt), `ad` (DNSSEC-validiert), `ra`. |
| `zenitiumdns_nodata_responses_total` | counter | | `NOERROR`-Antworten ohne Einträge im Answer-Abschnitt. |
| `zenitiumdns_extended_errors_total` | counter | `code`, `name` | Antworten mit Extended DNS Error (RFC 8914), z. B. `3` Stale Answer, `6` DNSSEC Bogus, `15` Blocked, `18` Prohibited, `22` No Reachable Authority, `29` Synthesized. Jeder Code zählt höchstens einmal pro Antwort. |
| `zenitiumdns_dropped_total` | counter | `reason` | Anfragen ohne Antwort: `rate_limited` (Ratenbegrenzung) und `no_response` (Anfragefilter über UDP, Apps wie Drop Requests, Do53-Modus „nur DDR“, volle Resolver-Warteschlange). |
| `zenitiumdns_request_duration_seconds` | histogram | `source` | Zeit vom Eingang einer Anfrage bis zum Senden der Antwort, getrennt nach `local`, `cache`, `recursive` und `blocked`. Buckets von 0,25 ms bis 5 s. |
| `zenitiumdns_request_size_bytes` | histogram | `protocol` | Größe der Anfragen. |
| `zenitiumdns_response_size_bytes` | histogram | `protocol` | Größe der gesendeten Antworten, bei DoT, DoH und DoQ einschließlich EDNS-Padding. |
| `zenitiumdns_queries_per_second` | gauge | `window` | Beantwortete Anfragen pro Sekunde über die letzten `1m`, `5m` und `60m`. |
| `zenitiumdns_response_time_milliseconds` | gauge | `window`, `stat` | Antwortzeiten über das Zeitfenster wie in der Übersicht: `avg`, `p50`, `p95`, `p99`, `max`, `cached_avg`, `recursive_avg`. |

Seit dem Start des Servers gezählt, auch ohne Endpunkt: `zenitiumdns_clients`, `zenitiumdns_queries_per_second` und `zenitiumdns_response_time_milliseconds`. Alle anderen Zähler dieser Tabelle beginnen mit der ausführlichen Erfassung.

### Anfragen an Nameserver und Weiterleitungsserver

| Kennzahl | Typ | Labels | Bedeutung |
| -------- | --- | ------ | --------- |
| `zenitiumdns_upstream_queries_total` | counter | `protocol`, `family` | An autoritative Nameserver und Weiterleitungsserver gesendete Anfragen. `family` ist `unknown` bei DoH-Weiterleitungsservern, die per Name angegeben sind. Wiederholungen über UDP innerhalb des Timeouts zählen als eine Anfrage. |
| `zenitiumdns_upstream_responses_total` | counter | `rcode` | Empfangene Antworten je Antwortcode. |
| `zenitiumdns_upstream_errors_total` | counter | `reason` | Anfragen ohne verwertbare Antwort: `timeout`, `network` (Socket- oder Verbindungsfehler), `invalid` (fehlerhafte oder verworfene Antworten), `canceled` (abgebrochen, weil ein anderer Server zuerst geantwortet oder der Client aufgegeben hat). |
| `zenitiumdns_upstream_truncated_total` | counter | | Gekürzte Antworten; der Resolver wiederholt die Anfrage dann über TCP. |
| `zenitiumdns_upstream_response_time_seconds` | histogram | `family` | Round-Trip-Zeit der Antworten, Buckets von 1 ms bis 5 s. |
| `zenitiumdns_ipv6_upstream_available` | gauge | | 1, solange Anfragen an Nameserver über IPv6 genutzt werden, 0, solange der IPv6-Fallback sie pausiert. |
| `zenitiumdns_upstream_cookies_sent_total` | counter | | Anfragen an Nameserver und Forwarder, die ein DNS-Cookie enthielten. |
| `zenitiumdns_upstream_cookie_errors_total` | counter | | Verworfene Antworten, weil das Server-Cookie falsch war oder bei einem Server fehlte, der zuvor Cookies gesendet hatte. |
| `zenitiumdns_upstream_cookie_servers` | gauge | | Nameserver, deren Server-Cookie gerade bekannt ist. |
| `zenitiumdns_qname_minimization_fallbacks_total` | counter | | Minimierte Anfragen, die mit einem längeren oder dem vollständigen Namen wiederholt wurden, weil der Nameserver sie falsch oder gar nicht beantwortet hat. |
| `zenitiumdns_qname_minimization_fallback_zones` | gauge | | Zonen, die gerade ohne QNAME-Minimierung aufgelöst werden, weil ihre Nameserver damit nicht zurechtkommen (eine Stunde gemerkt, höchstens 10.000). |
| `zenitiumdns_qname_minimization_skipped_total` | counter | | Auflösungen, die für eine solche gemerkte Zone ohne QNAME-Minimierung liefen. |

### Cache, Filter und Schutz

| Kennzahl | Typ | Labels | Bedeutung |
| -------- | --- | ------ | --------- |
| `zenitiumdns_cache_enabled` | gauge | | 1, wenn der Cache genutzt wird, 0, wenn er abgeschaltet ist und jede Anfrage ohne zwischengespeicherte Antworten aufgelöst wird. |
| `zenitiumdns_cache_entries` | gauge | | Einträge im Cache. |
| `zenitiumdns_cache_max_entries` | gauge | | Eingestelltes Maximum des Caches (0 = unbegrenzt). |
| `zenitiumdns_cache_max_memory_bytes` | gauge | | Eingestellte Speichergrenze, ab der der Cache verkleinert wird (0 = keine Grenze). |
| `zenitiumdns_cache_memory_trimmed_entries_total` | counter | | Cache-Einträge, die wegen Überschreitung der Speichergrenze entfernt wurden. |
| `zenitiumdns_aggressive_nsec_enabled` | gauge | | 1, wenn die aggressive Nutzung des DNSSEC-validierten Caches (RFC 8198) eingeschaltet ist. |
| `zenitiumdns_aggressive_nsec_entries` | gauge | | Dafür vorgehaltene NSEC- und NSEC3-Einträge. |
| `zenitiumdns_aggressive_nsec_synthesized_total` | counter | | Daraus synthetisierte negative Antworten. |
| `zenitiumdns_filter_domains` | gauge | `list` | Domains in `block_lists`, `allow_lists`, `blocked` (eigene blockierte Domains) und `allowed` (eigene erlaubte Domains). |
| `zenitiumdns_forwarder_zones` | gauge | | Weiterleitungszonen. |
| `zenitiumdns_request_filter_matches_total` | counter | `rule` | Vom Anfragefilter verworfene oder abgewiesene Anfragen je Regel. |
| `zenitiumdns_client_blocklist_drops_total` | counter | | Wegen einer Client-Sperrliste verworfene Anfragen und Verbindungen. |
| `zenitiumdns_client_blocklist_ranges` | gauge | | Aus Client-Sperrlisten geladene Adressbereiche. |
| `zenitiumdns_rate_limiter_tracked_clients` | gauge | | Von der Ratenbegrenzung aktuell verfolgte Client-Netze. |

### Interne Warteschlangen

| Kennzahl | Typ | Labels | Bedeutung |
| -------- | --- | ------ | --------- |
| `zenitiumdns_queue_length` | gauge | `queue` | Wartende Arbeitsschritte: `query` (Anfrageverarbeitung), `resolver` (rekursive Auflösung), `stats` (Statistik). |
| `zenitiumdns_pending_resolutions` | gauge | | Laufende rekursive Auflösungen. |
| `zenitiumdns_stats_queue_dropped_total` | counter | | Verworfene Statistik-Aktualisierungen, weil die Statistik-Warteschlange voll war (100.000 Einträge). Steigt der Wert, zählen die Statistik und die Zähler oben zu wenig. |

### Prozess und .NET-Laufzeit

| Kennzahl | Typ | Labels | Bedeutung |
| -------- | --- | ------ | --------- |
| `process_cpu_seconds_total` | counter | | CPU-Zeit des Prozesses. |
| `process_resident_memory_bytes` | gauge | | Belegter Arbeitsspeicher (RSS). |
| `process_virtual_memory_bytes` | gauge | | Virtueller Adressraum; bei .NET deutlich größer als der belegte Speicher. |
| `process_start_time_seconds` | gauge | | Start des Prozesses als Unix-Zeit. |
| `process_threads` | gauge | | Threads des Betriebssystems. |
| `process_open_fds`, `process_max_fds` | gauge | | Offene Dateideskriptoren und ihr Limit (nur Linux). |
| `dotnet_gc_collections_total` | counter | `generation` | Garbage Collections je Generation. |
| `dotnet_gc_heap_size_bytes` | gauge | `generation` | Größe von `gen0`, `gen1`, `gen2`, `loh` und `poh` nach der letzten Garbage Collection. |
| `dotnet_gc_total_memory_bytes` | gauge | | Aktuell belegter Speicher im verwalteten Heap. |
| `dotnet_gc_committed_bytes` | gauge | | Vom Garbage Collector reservierter Speicher. |
| `dotnet_gc_fragmented_bytes` | gauge | | Freier Platz innerhalb des verwalteten Heaps. |
| `dotnet_gc_allocated_bytes_total` | counter | | Seit dem Start angeforderte Bytes. |
| `dotnet_gc_pause_seconds_total` | counter | | Zeit, in der die Laufzeit für Garbage Collections angehalten war. |
| `dotnet_gc_pause_time_ratio` | gauge | | Anteil dieser Pausen an der Laufzeit. |
| `dotnet_threadpool_threads`, `dotnet_threadpool_queue_length` | gauge | | Threads des Threadpools und wartende Arbeitsschritte. |
| `dotnet_threadpool_completed_items_total` | counter | | Erledigte Arbeitsschritte. |
| `dotnet_monitor_lock_contentions_total` | counter | | Sperren, auf die gewartet werden musste. |
| `dotnet_timers` | gauge | | Aktive Timer. |

## Beispielabfragen

```promql
# Anfragen pro Sekunde je Protokoll
sum by (protocol) (rate(zenitiumdns_requests_total[5m]))

# Cache-Trefferquote
rate(zenitiumdns_response_sources_total{source="cached"}[5m])
  / ignoring(source) sum without(source) (rate(zenitiumdns_response_sources_total[5m]))

# 99. Perzentil der Antwortzeit bei rekursiver Auflösung
histogram_quantile(0.99, sum by (le) (rate(zenitiumdns_request_duration_seconds_bucket{source="recursive"}[5m])))

# Anteil der SERVFAIL-Antworten
rate(zenitiumdns_responses_total{rcode="ServerFailure"}[5m]) / ignoring(rcode) sum without(rcode) (rate(zenitiumdns_responses_total[5m]))

# Timeouts von Nameservern pro Sekunde
rate(zenitiumdns_upstream_errors_total{reason="timeout"}[5m])

# Fehlgeschlagene DNSSEC-Validierungen
rate(zenitiumdns_extended_errors_total{name="DnssecBogus"}[5m])
```

## Einstellungsdatei

Die drei Einstellungen stehen in `webservice.config`, deren Formatversion seit Paket 15.5.1-10 die 7 ist. Ältere Versionen von ZenitiumDNS können diese Datei nicht lesen; Version 6 und älter werden mit ausgeschaltetem Endpunkt eingelesen.
