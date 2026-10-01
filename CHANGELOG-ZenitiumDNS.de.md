# ZenitiumDNS 15.5.1 im Vergleich zu Technitium DNS Server 15.5

[English version](CHANGELOG-ZenitiumDNS.md)

Dieses Dokument listet ausschließlich die Unterschiede zwischen dem Original-Build **Technitium DNS Server 15.5** (veröffentlicht am 19. September 2026) und dem Build **ZenitiumDNS 15.5.1** (Stand 1. Oktober 2026) auf. ZenitiumDNS 15.5.1 enthält außerdem alle Korrekturen aus Technitium DNS Server 15.5.1; welche davon ZenitiumDNS schon vorher hatte, steht am Ende. Die vollständige Versionsgeschichte steht in [CHANGELOG.de.md](CHANGELOG.de.md).

## Überblick

| Bereich | Technitium DNS Server 15.5 | ZenitiumDNS 15.5 |
| ------- | -------------------------- | ---------------- |
| Name, Pfade, Dienst | Technitium, `/etc/dns`, Dienst `dns` | ZenitiumDNS, `/etc/zenitiumdns`, Dienst `zenitiumdns` |
| Einsatzzweck | autoritativer und rekursiver DNS-Server, DHCP-Server, Clustering | öffentlicher rekursiver Resolver mit eigenem DHCP-Server; autoritative Zonen, Zonentransfers, DHCP-Server und Clustering von Technitium und Windows-Komponenten entfernt |
| Update-Prüfung und App-Store | fest auf Technitium-Server | Update-Prüfung gegen die GitHub-Releases von ZenitiumDNS mit Changelog, App-Store entfernt |
| Installation unter Debian 13 | Skript lädt Binärdateien und .NET aus dem Internet | eigenständiges `.deb`-Paket mit eingebauter .NET-Laufzeit und `libmsquic` für DNS-over-QUIC |
| Erstes Admin-Passwort | `admin` | zufällig erzeugt |
| Sprache der Weboberfläche und Doku | Englisch | Deutsch oder Englisch, nach der Installation wählbar und jederzeit umstellbar |
| CNAME-Ketten über viele Zonen (z. B. `www.bbc.com`, `x.com`) | `SERVFAIL` durch zu niedrige Resolver-Limits | werden vollständig aufgelöst |
| Ausfall der Root-Priming-Anfrage | rekursive Auflösung fällt komplett aus | Rückfall auf die Root-Hints |
| „IPv6 bevorzugen“ mit nicht erreichbaren IPv6-Nameservern | jede Anfrage schlägt fehl | nach der ersten Anfrage Antwort über IPv4 in ca. 30 ms |
| Cache-Wartung | blockierende Garbage Collection jede Minute (50–250 ms Hänger) | Garbage Collection im Hintergrund |
| CPU-Zeit pro Anfrage bei 100.000 Anfragen/s | 86–100 µs | 24–30 µs |
| Pipelining über DNS-over-TCP/TLS | unbegrenzt viele gleichzeitige Anfragen pro Verbindung | standardmäßig höchstens 100 pro Verbindung, einstellbar |
| Gestörte IPv6-Anbindung | IPv6-Adressen werden weiter angefragt, Zeitüberschreitungen verzögern Auflösungen | IPv6 wird nur bei bestätigtem Ausfall ausgesetzt (Gegenprobe über die IPv6-Root-Server), einzelne tote IPv6-Nameserver lösen nichts aus, die erste IPv6-Antwort hebt die Sperre auf |
| Antwortzeiten in Übersicht und Metriken | nicht vorhanden | Median, Perzentile, Cache/rekursiv, live und pro Minute |
| Weboberfläche | Bootstrap-Standardoptik, feste Mindestbreite 970 px, Einstellungen in einer langen Seite je Tab | eigenes Design mit Seitenleiste und Messwertleiste, mobil nutzbar, thematische Einstellungsbereiche mit Erklärungen |
| Anfragen vom Typ ANY, AXFR/IXFR, ohne RD-Flag, fremde Opcodes oder Klassen | werden verarbeitet | per Anfragefilter über UDP verworfen, über TCP/DoT/DoH/DoQ mit `REFUSED` abgewiesen |
| DNSSEC mit ML-DSA-44 (Post-Quantum) | unbekannter Algorithmus, Zone gilt als unsigniert | wird validiert, mit Downgrade-Schutz |
| Aggressive Nutzung von NSEC und NSEC3 (RFC 8198) | nicht vorhanden | `NXDOMAIN` und `NODATA` für signierte Zonen aus validierten NSEC/NSEC3-Einträgen im Cache, standardmäßig eingeschaltet; 20.000 zufällige Subdomains lösten 30 bis 48 statt 20.000 Upstream-Anfragen aus |
| Mitgelieferte Apps | müssen einzeln installiert werden, sind danach sofort aktiv | vorinstalliert, standardmäßig deaktiviert, einzeln aktivierbar |
| Container | Docker-Image und Compose-Datei | eigenes OCI-Image für amd64 und arm64 (Alpine Linux, unprivilegierter Benutzer, zufälliges Admin-Passwort), keine Compose-Datei |
| Ratenbegrenzung | Durchschnitt der Anfragen pro Minute über ein Stichprobenfenster | Token-Bucket in Anfragen pro Sekunde mit Burst |
| Client-IP-Sperrlisten | nicht vorhanden | IPsum, Spamhaus DROP u. a., Verwerfen vor dem Auswerten der Anfrage |
| TLS-Zertifikate | nur PKCS#12 (`.pfx`) | zusätzlich PEM (`fullchain.pem`, `privkey.pem`) |
| DDR (RFC 9462) | nur über selbst angelegte Zone | eingebaut, automatisch aus den aktiven Diensten, auch für DoH hinter einem Reverse Proxy |
| Selbsttest | nicht vorhanden | eigener Bereich, schwere Probleme auf der Übersicht |
| Speicher für 2,5 Mio. Blocklisten-Einträge | ca. 395 MB | ca. 80 MB |
| Speicher der Statistik nach 30 Minuten mit 2.000 Anfragen/s von 50.000 Clients | ca. 590 MB, jede Minute der letzten ein bis zwei Stunden vollständig | ca. 50 MB, abgeschlossene Minuten auf die Top 1000 gekürzt |
| Stündliche Statistikdatei einer ausgelasteten Stunde | ca. 100 MB (vollständige Minutendaten) | 0,6–1,4 MB (Stundensummen und Top 1000 je Minute) |
| Lebende Objekte im selben Test mit HaGeZi TIF und PRO | 945 MB, 18,2 Mio. Objekte | 271 MB, 3,8 Mio. Objekte |
| „IPv6 bevorzugen“ mit Nameservern ohne Glue- und AAAA-Einträge | `SERVFAIL` (Upstream-Issue #2175) | wird beantwortet |
| TCP-Anfragen an Cloudflare-Nameserver | wiederverwendete Verbindungen laufen in Timeouts | eigene Verbindung, Wiederverwendung wird erkannt |
| Lokale Root-Zone (RFC 8806) | nur als selbst angelegte Secondary-Zone | eingebaut, Root- und arpa-Zone von IANA mit ZONEMD- und Signaturprüfung, NXDOMAIN für nicht existierende TLDs ohne Root-Server |
| Root-Vertrauensanker | nur mitgelieferte Datei | täglich von IANA, nur mit gültiger ICANN-Signatur, oder eigene Version |
| Do53 | immer aktiv | aktiviert, nur DDR (verwerfen oder REFUSED) oder aus |
| Apps | englisch, Konfiguration als JSON-Textfeld | Namen, Beschreibungen und Fehlermeldungen auf Deutsch oder Englisch, Formular mit übersetzten Bezeichnungen, JSON für Experten |
| Übersicht | ab 1 Stunde | ab 1 Minute, Echtzeitgraphen interner Prozesse |
| Automatisches Eingreifen bei Speicherplatz-, Speicher- oder Dienstproblemen | nicht vorhanden | Wächter |
| EDNS-Padding (RFC 7830, RFC 8467) | nicht vorhanden | Antworten über DoT, DoH und DoQ auf Vielfache von 468 Byte, Anfragen an verschlüsselte Forwarder auf 128 Byte |
| Protokollierung von Client-Adressen | immer | abschaltbar |
| Prefetch | höchstens in den letzten 9 Sekunden der TTL | ab einem einstellbaren Anteil der Rest-TTL, Standard 10 % |
| Prüfung der Systemzeit | nicht vorhanden | Selbsttest gegen den Date-Header von IANA und NTP-Status des Kernels |
| Prometheus-Metriken | einfache Zähler unter `api/dashboard/metrics/text`, Zugriff mit API-Token | optionaler Endpunkt `/metrics` mit ACL und Bearer-Token, Histogramme, je Protokoll, Typ und Antwortcode, Extended DNS Errors, Anfragen an Nameserver, Prozess und Laufzeit ([docs/Metrics.de.md](docs/Metrics.de.md)) |
| API-Tokens | vorhanden | entfernt |
| Formate von Blocklisten | hosts-Dateien, reine Domains, Wildcard-Listen, Adblock-Domainregeln | zusätzlich die Regelsyntax von AdGuard Home und Adblock (Ausnahmen, Platzhalter, reguläre Ausdrücke, `$important`, `$badfilter`, `$dnstype`, `$denyallow`, `$client`), Pi-hole-Regex-Listen und Blockierung über die IP-Adresse in der Antwort ([docs/BlockLists.de.md](docs/BlockLists.de.md)) |
| Unterschiedliche Listen je Gerät | nur über die Advanced Blocking App | Clientprofile über IP-Adresse, Netz oder ClientID (DoH-Pfad, DoT/DoQ-Servername), mit eigenen Listen, ohne Standardlisten oder ohne Blockierung |
| DNS-Cookies (RFC 7873, RFC 9018) | nicht vorhanden | gegenüber Clients und Nameservern, Clients mit gültigem Cookie lässt die Ratenbegrenzung durch |
| Nameserver, die mit QNAME-Minimierung nicht zurechtkommen | Auflösung scheitert oder läuft in Zeitüberschreitungen | automatischer Rückfall auf den vollständigen Namen, Zone eine Stunde gemerkt |
| Betrieb ohne Cache (etwa vor Unbound) | nicht vorhanden | Cache, Prefetch, Serve Stale und lokale Root-Zone lassen sich gemeinsam abschalten |
| Speicher für 1,2 Millionen Namen im Cache | rund 1,5 GB lebende Objekte | rund 0,8 GB, optionale Speichergrenze, die den Cache verkleinert |
| systemd-Sandbox (`systemd-analyze security`) | 3,6 | 1,9 mit Systemaufruf-Filter |
| Speicher fast voll | der Cache wächst weiter, bis dem Prozess der Speicher ausgeht | der Cache wächst ab 85 % des Arbeitsspeichers, des Dienst- oder Container-Limits oder des .NET-Heap-Limits nicht weiter und wird ab 90 % gekürzt |
| Lock-Konflikte bei rekursiver Auflösung und DNS-over-TLS | Hunderte bis Tausende umkämpfte Sperren pro Sekunde (Resolver-Pool, der alle wartenden Schleifen weckt, eigener Scheduler für TCP, DoT und DoQ) | praktisch keine: sperrfreier Resolver-Pool, Verbindungen auf dem .NET-Threadpool |
| CPU-Zeit pro Anfrage über DNS-over-TLS (8.000 Anfragen/s, 4 CPUs) | 122 µs | 56 µs ([docs/Performance.de.md](docs/Performance.de.md)) |
| DHCP | DHCP-Server mit Bereichen | eigener DHCP-Server für IPv4 und IPv6 mit Router Advertisements: einfache Einstellungen oder Konfiguration in der Syntax von dnsmasq (auch per Auswahl), Erkennung anderer DHCP-Server und IPv6-Router mit Priorität, Geräte über MAC-Adresse, Client-ID oder DUID hinweg über IPv4, DHCPv6 und Clientprofile erkannt ([docs/DHCP.de.md](docs/DHCP.de.md)) |

## Messwerte

Der aktuelle Vergleich mit Technitium DNS Server 15.5.1, einschließlich DNS-over-TLS, rekursiver Auflösung, Speicher pro Cache-Eintrag und Lock-Konflikten, steht in [docs/Performance.de.md](docs/Performance.de.md). Die Werte unten stammen aus früheren Entwicklungsständen.

Gemessen auf demselben Rechner (20 Kerne) mit `dnsperf` gegen einen autoritativen Server und einen cachenden Resolver mit 2.000 Namen. Werte für autoritative Antworten / Antworten aus dem Cache. Die Werte für autoritative Antworten stammen aus einem Build vor dem Entfernen der autoritativen Zonen und zeigen die Wirkung der Optimierungen auf den gemeinsamen Anfragepfad.

| Messung | Technitium 15.5 | ZenitiumDNS 15.5 | Änderung |
| ------- | --------------- | ---------------- | -------- |
| CPU-Zeit pro Anfrage bei fester Last (100.000 Anfragen/s) | 85,8 / 99,8 µs | 23,6 / 29,5 µs | −73 % / −70 % |
| Mittlere Latenz bei fester Last | 85 / 71 µs | 19 / 19 µs | −78 % / −73 % |
| Spitzendurchsatz | 686.000 / 628.000 Anfragen/s | 721.000 / 703.000 Anfragen/s | +5 % / +12 % |
| Speicherallokation pro Anfrage aus dem Cache | ca. 2,9 KB | ca. 1,0 KB | −65 % |
| Pausenzeit der Garbage Collection unter Volllast | 22 % | 7 % | −68 % |
| Gen0-Garbage-Collections pro Sekunde unter Volllast | 134 | 55 | −59 % |
| Lock-Konflikte pro Sekunde unter Volllast | 1.798 | 41 | −98 % |

Funktionstests im isolierten Netz-Namespace mit nachgebauter DNS-Hierarchie:

| Test | Technitium 15.5 | ZenitiumDNS 15.5 |
| ---- | --------------- | ---------------- |
| CNAME-Kette über 12 Zonen | 9 von 12 Einträgen, danach Abbruch | alle 12 Einträge |
| Upstream-Anfragen durch Prefetch bei kurzer TTL (24 Client-Anfragen) | 24 | 2 |
| 10 Anfragen, „IPv6 bevorzugen“, IPv6-Nameserver nicht erreichbar | 10 × Fehler nach 2 s | 2 × Fehler, dann 8 × Antwort in 22–42 ms |
| TLS-Zertifikat in `…/cfgcert/` neben dem Konfigurationsordner `…/cfg/` | gespeichert als `cert/test.pfx`, nach Neustart nicht mehr ladbar | absoluter Pfad bleibt erhalten |

## Alle Änderungen im Detail

### Ausrichtung als öffentlicher Resolver
- **Entfernt:**
  - autoritative Zonen vom Typ Primary, Secondary, Stub, Secondary Forwarder und Catalog samt DNSSEC-Signierung und SOA-Bearbeitung,
  - Zonentransfers (AXFR, IXFR, XFR-over-TLS/QUIC), DNS NOTIFY, dynamische Updates und TSIG,
  - DHCP-Server und Clustering von Technitium (15.5.1-12 bringt einen eigenen DHCP-Server, siehe [docs/DHCP.de.md](docs/DHCP.de.md)),
  - die Übernahme von DNS-Client-Antworten in eine lokale Zone,
  - 16 Apps für LAN- und Hosting-Szenarien (Auto PTR, Block Page, Default Records, DNS Block List, Failover, Filter AAAA, Geo Continent, Geo Country, Geo Distance, No Data, NX Domain Override, Split Horizon, Weighted Round Robin, What Is My DNS, Wild IP, Zone Alias),
  - Windows-Dienst, Systemtray, Windows-Firewall-Bibliothek und Windows-Installer.
- **Erhalten:** Conditional-Forwarder-Zonen mit lokalen Einträgen und Zugriffsbeschränkung, Blocklisten, erlaubte und blockierte Domains, die Resolver-Apps (Advanced Blocking, Advanced Forwarding, DNS64, DNS Rebinding Protection, Drop Requests, Log Exporter, NX Domain, Query Logs für SQLite, MySQL, PostgreSQL und SQL Server).
- **Protokollverhalten:** AXFR/IXFR werden mit `REFUSED` und EDE „Not Supported“ beantwortet, NOTIFY und UPDATE mit `NOTIMP`, TSIG-signierte Anfragen mit `BADKEY`.

### Anfragefilter
- Regeln nach dem Vorbild von dnsdist, standardmäßig aktiv: nicht lesbar oder unter 12 Byte, über 1232 Byte, Opcode ungleich QUERY, Klasse ungleich IN, ANY, AXFR/IXFR, ohne RD-Flag, EDNS-Version größer 0.
- UDP-Treffer werden verworfen, über TCP, DoT, DoH und DoQ gibt es `REFUSED` mit EDE „Prohibited“. Loopback ist ausgenommen.
- Trefferzähler je Regel in Einstellungen, JSON-Metriken und Prometheus (`zenitiumdns_request_filter_matches_total`).

### DNSSEC
- Validierung von ML-DSA-44 (Algorithmus 18) und Schutz vor Downgrades auf klassische Algorithmen, wenn der DS-Datensatz einen Post-Quantum-Algorithmus ankündigt.
- Der DNS-Client erklärt, warum die DNSSEC-Prüfung gegen diesen Server scheitert, wenn dessen Validierung ausgeschaltet ist.
- Aggressive Nutzung des DNSSEC-validierten Caches (RFC 8198, RFC 9077): Validierte NSEC- und NSEC3-Einträge beantworten Anfragen nach nicht existierenden Namen und Typen in signierten Zonen mit `NXDOMAIN` bzw. `NODATA` und dem Extended DNS Error 29 (Synthesized). Ausgenommen sind NSEC3-Opt-out, Wildcards, Namen unterhalb von Delegationen und DNAME-Einträgen, Weiterleitungszonen und bedingte Weiterleitung. Schaltbar unter Einstellungen > Resolver > DNSSEC, standardmäßig eingeschaltet.

### Apps
- Mitgelieferte Apps werden beim ersten Start deaktiviert installiert und bei Paket-Updates aktualisiert. Deinstallierte Apps bleiben entfernt.
- Aktivieren und Deaktivieren in der Weboberfläche und über `api/apps/enable` und `api/apps/disable`.

### Schutz, Blockierung und Protokolle
- Ratenbegrenzung in Anfragen pro Sekunde (GCRA-Token-Bucket je Subnetz, Burst einstellbar), Migration bestehender QPM-Werte.
- Client-Sperrlisten mit automatischer Aktualisierung, Verwerfen vor dem Parsen, Trennen von Stream-Verbindungen.
- Eigener Blockierungstext mit Platzhaltern, eigene TTL für negatives Caching; das SOA-MINIMUM bleibt nach einem Neustart erhalten.
- Blocklisten-Schnellauswahl nur mit HaGeZi-Listen (Adblock-Format) vom Build-Mirror, halber Speicherbedarf der Blocklisten, allokationsfreie Suche.
- Regelsyntax von AdGuard Home und Adblock, Pi-hole-Regex-Listen und IP-Regeln für Antworten in Blocklisten; Status je Liste mit Zählern, Fehlern und Aktionen.
- Clientprofile mit ClientID über DoH, DoT und DoQ; ein gemeinsamer Regelsatz, der je Anfrage gefiltert wird.
- DNS-Cookies gegenüber Clients und Nameservern, `BADCOOKIE` und `FORMERR` bei falschen oder fehlerhaften Cookies, Clients mit geprüftem Cookie umgehen die UDP-Ratenbegrenzung innerhalb der TCP-Grenze.
- PEM-Zertifikate mit separatem Schlüssel, eingebautes DDR, Selbsttest.
- Resolver: Umgang mit Nameservern, die nur eine Anfrage pro TCP-Verbindung beantworten; QNAME-Rückfall bei Timeouts; Downloads mit effektivem IPv6-Modus.

### Standardwerte neuer Installationen
- 100.000 Cache-Einträge, Blockier-TTL 300 s, Listen-Backlog 1024, TCP-Empfangs-Timeout 5 s, IPv6 für ausgehende Anfragen aktiviert, Statistik und Logs 30 Tage.

### Statistik und Überwachung
- Antwortzeit-Messung für alle Transportprotokolle mit Durchschnitt, Median, 95./99. Perzentil, Maximum und getrennten Werten für Cache und rekursive Auflösung.
- Neue Übersicht mit Kennzahlen, Statuschips, Antwortzeit-Verlauf, Anteilstabellen und umschaltbaren Verlaufsansichten.
- Zusätzliche Felder in `api/dashboard/stats/get` und in den JSON- und Prometheus-Metriken, neuer Aufruf `api/dashboard/ipv6/probe`.
- Korrektur: Der erste abgeschnittene Eintrag fehlte im Sammelwert „Andere“ gekürzter Top-Listen.

### Weboberfläche und Einstellungen
- Neues Design mit Seitenleiste, Seitentitel und Farbsystem in Petrol, lokal eingebundene Red-Hat-Schriften, einheitliche Formulare, Tabellen und Dialoge in Hell, Dunkel und Bernstein.
- Messwertleiste auf der Übersicht mit Verlauf je Kennzahl und Statusangabe in Worten. Diagrammfarben sind auf Farbfehlsichtigkeit geprüft.
- Mobil nutzbar: Symbolleiste statt Seitenleiste, seitlich scrollbare Tabellen, keine feste Mindestbreite mehr.
- Neu gegliederte Navigation (Übersicht, Resolver, Filter, Apps, DNS-Client, Protokolle, Einstellungen, Verwaltung, Info) und Einstellungen in zehn thematischen Bereichen mit Erklärungstexten.
- Neue Einstellungen: automatischer IPv6-Rückfall, UDP-Empfangs-Threads je Socket, Obergrenze gleichzeitiger Anfragen je TCP-/TLS-Verbindung.
- Entfernte Einstellungen: SOA-Vorgaben, Zonentransfer- und NOTIFY-Netze, TSIG-Schlüssel.

### Resolver
- **CNAME-Ketten und Nameserver ohne Glue:** Die Limits pro Client-Anfrage wurden angehoben, auf 400 ausgehende Anfragen und 128 Hash-Operationen. Domains wie `www.bbc.com` oder `x.com` scheiterten im Original mit „No valid response from name servers“ (Upstream-Issue #2175).
- **QNAME-Minimierung:** Das Original schickte für das letzte Label eine überflüssige Anfrage vom Typ `A`, auch nach NXDOMAIN.
- **Root-Priming:** Scheitert die Priming-Anfrage oder liefert sie keine Adressen, fiel die rekursive Auflösung im Original ganz aus. ZenitiumDNS nutzt dann die Root-Hints. Die Priming-Anfrage wird ohne RD-Flag gesendet.
- **Doppelte Nameserver:** Doppelte Einträge in der Nameserver-Liste werden entfernt.
- **DNS 0x20:** Eine Antwort mit abweichender Groß-/Kleinschreibung des Namens gilt jetzt als Spoofing-Versuch und führt sofort zur Wiederholung über TCP.
- **Nameserver-Auswahl:**
  - Antwortzeit und Fehlerrate werden getrennt pro Adressfamilie (IPv4/IPv6) geführt.
  - Die Antwortquote wird als gleitender Durchschnitt statt über die gesamte Laufzeit gezählt.
  - Ausgefallene Adressen werden hinter funktionierende einsortiert, auch im Modus „IPv6 bevorzugen“.
  - Die Reihenfolge ergibt sich aus einer einzigen kombinierten Sortierung statt aus mehreren instabilen Sortierungen.
- **Cache-Ansicht:** Die Nameserver-Statistik zeigt zusätzlich die aktuelle Antwortquote und die IPv6-Werte.

### Cache
- **Sperre der Root-Server nach DNSSEC-Fehlern:** „Cache leeren“ und das Umschalten der DNSSEC-Validierung setzen die Fehlermarkierung der Root-Hints zurück. Im Original blieb die Auflösung danach bis zu fünf Minuten gestört.
- **Fehler-Cache und Serve Stale:** Abgelaufene Fehlereinträge wurden im Original als veraltete Antwort ausgeliefert und verlängerten Ausfälle.
- **Prefetch:** Das Original löste bei kurzer TTL fast bei jeder Anfrage ein Prefetch aus. Jetzt greift es erst im letzten Zehntel der TTL.
- **Garbage Collection:** Das Original führte in der minütlichen Cache-Wartung eine blockierende vollständige Garbage Collection aus (Upstream-Issue #2174). ZenitiumDNS nutzt dort und beim Neuladen von Statistiken, Blocklisten und der Advanced-Forwarding-App eine Garbage Collection im Hintergrund.
- **Race Condition:** Beim Entfernen leerer Cache-Zonen konnten gleichzeitig hinzugefügte Einträge verloren gehen und der Eintragszähler falsch hochzählen.
- **LRU-Verdrängung:** Bei A-/AAAA-Einträgen mit mehreren Adressen wurde der Zeitpunkt der letzten Nutzung nie aktualisiert. Beliebte Einträge wurden bei vollem Cache dadurch zuerst verdrängt.
- **Speicher je Eintrag:** kompakte Eintragstabelle je Name statt eines nebenläufigen Dictionarys, geteilte Nameserver-Daten in den Metadaten der Antwort, passend große Kind-Arrays im Domainbaum, keine zweite Rohkopie von A-, AAAA- und RRSIG-Daten; rund halber Speicher je Eintrag.
- **Speichergrenze:** optionale Grenze für den belegten Speicher; die Cache-Wartung entfernt die am längsten ungenutzten Einträge und kompaktiert den Heap nach großen Schnitten.

### Performance
- Dedizierte UDP-Empfangs-Threads (automatisch höchstens 8 pro Socket, einstellbar bis 64) beantworten Cache-Treffer ohne Thread-Wechsel.
- UDP-Antworten werden synchron gesendet.
- Die interne Verarbeitungskette nutzt `ValueTask`, die Namenskompression arbeitet ohne Kopien.
- Die Prüfung auf spezielle Zonen erzeugt keine temporären Strings mehr.
- Enumeratoren werden in den heißen Pfaden nicht mehr geboxt.
- Zeitstempel der letzten Nutzung werden höchstens einmal pro Sekunde geschrieben.
- Statistikdaten laufen über eine lockfreie Warteschlange mit eigenem Thread, eindeutige Clients werden per HyperLogLog gezählt.
- UDP-Empfangs-Threads wecken weitere Threads erst bei anhaltendem Rückstau, Sendepuffer werden wiederverwendet.
- Server-GC mit nebenläufiger Garbage Collection.
- Rekursive Auflösungen werden über einen sperrfreien Zähler begrenzt statt über eine wartende Schleife je erlaubter Auflösung, die bei jeder neuen Auflösung alle geweckt wurden; DNS über TCP, DoT und DoQ laufen auf dem .NET-Threadpool statt auf einem eigenen Scheduler. Die Lock-Konflikte bei 700 rekursiven Auflösungen pro Sekunde sanken von etwa 290 auf 0 pro Sekunde ([docs/Performance.de.md](docs/Performance.de.md#lock-konflikte)).
- Eine kurze Gen0-Garbage-Collection läuft, sobald 150 neue Cache-Einträge entstanden sind, damit einzelne Pausen auch bei vielen neuen Namen bei wenigen Millisekunden bleiben.

### Verschlüsselte Protokolle
- **DNS-over-TCP und DNS-over-TLS:** Standardmäßig höchstens 100 laufende Anfragen pro Verbindung, einstellbar. Das Original ließ beliebig viele zu.
- **DNS-over-HTTPS:** Die gespeicherte Serveradresse enthält nicht mehr die komplette Anfrage (`?dns=…`).

### Sicherheit
- API-Tokens aus `DNS_SERVER_AUTH_STATIC_SESSIONS` gelten jetzt auch beim allerersten Start ohne `auth.config`.
- SQL-Injection über den Serverfilter in den Query-Log-Apps für MySQL, PostgreSQL und SQL Server behoben.
- XSS über App-Namen in der Weboberfläche behoben.
- Benutzer ohne Admin-Rechte können keine fremden Sitzungen mehr löschen.
- Beim Wiederherstellen einer Sicherung werden keine Dateien außerhalb des Zielordners mehr geschrieben.
- TLS-Zertifikatspfade neben dem Konfigurationsordner werden korrekt gespeichert (Upstream-Issue #2162).
- DNS-over-HTTPS per POST: Anfragen über 65.535 Byte werden mit 413 abgewiesen und begrenzt gelesen.
- DNS-Nachrichten mit unplausiblen Eintragszahlen werden vor dem Parsen verworfen.
- Werte in Inline-Handlern der Weboberfläche werden für JavaScript maskiert.
- Übersetzungen importierter Oberflächensprachen enthalten keine geraden Anführungszeichen oder Backticks mehr, sie werden durch typografische ersetzt.
- systemd-Dienst mit Systemaufruf-Filter, beschränkten Adressfamilien und `ProtectProc=invisible`; die Datei mit dem Startpasswort wird nach der Passwortänderung oder wenn der Benutzer `admin` gelöscht oder umbenannt wurde automatisch gelöscht.
- Content Security Policy ohne `unsafe-eval`, höchstens 1 MB je Anfrage ohne gültige Sitzung, HSTS bei HTTPS-Umleitung, `nosniff` und `Referrer-Policy`.
- Container-Image mit per Hash festgelegten Actions und Basis-Images, SBOM, Provenienz und cosign-Signatur.

### Web-API und Weboberfläche
- Die Eintrags-APIs beachten `zone=.` für die Root-Zone.
- Die Seitengröße der Log-Abfrage ist begrenzt, und die Größenbegrenzung beim Herunterladen von Logs läuft nicht mehr über.
- Ausstehende Änderungen werden vor Sicherungen und beim Beenden geschrieben.
- Weboberfläche und Dokumentation sind auf Deutsch übersetzt.

### Apps und Stabilität
- Log Exporter App: Syslog-Nachrichten werden nicht mehr doppelt nach RFC 5424 formatiert (Upstream-Issue #2173); fehlende Ziele führen zu einer klaren Fehlermeldung, relative Dateipfade beziehen sich auf den App-Ordner, Extended DNS Errors mit `:` im Text werden vollständig exportiert.
- Advanced Forwarding App: keine Weiterleitung für Clients ohne Rekursionsrecht; Domainregeln ignorieren Groß- und Kleinschreibung und einen abschließenden Punkt.
- DNS64 App: keine AAAA-Synthese für `REFUSED`, blockierte oder verworfene Antworten.
- Drop Requests App: Anfragen an einen erlaubten lokalen Endpunkt überspringen nicht mehr die Regeln für gesperrte Anfragen.
- Clientprofile: Ein ungültiges Profil verwirft nicht mehr alle Profile; IP-Adressen in Profilen und Blocklisten werden streng gelesen (`1.2.3` oder `010.1.1.1` sind keine Adressen).
- Der Timer des Load-Balancing-Proxys löst nach dem Entsorgen nicht mehr aus.
- Ein Fehler beim Laden einer Zonendatei führt nicht mehr zu einer `LockRecursionException`.

### Installation und Betrieb
- Debian-13-Paket (`setup/debian/build-deb.sh`) für amd64 und arm64:
  - gehärteter systemd-Dienst,
  - zufälliges Admin-Passwort,
  - automatische Anpassung von systemd-resolved,
  - mitgelieferte DNS-Apps,
  - mitgeliefertes `libmsquic` für DNS-over-QUIC und HTTP/3.
- Docker-Image, Compose-Datei und die Umgebungsvariablen zur Erstkonfiguration des Originals wurden entfernt; ein eigenes Container-Image (`Containerfile`, `ghcr.io/dnsbunker/zenitiumdns`) ersetzt das Image.
- Update-Prüfung und App-Store sind standardmäßig deaktiviert: `DNS_SERVER_UPDATE_CHECK_URL`, `DNS_SERVER_APP_STORE_URL`.

## Kompatibilität

- **Konfiguration:** Einstellungen, Benutzer, Conditional-Forwarder-Zonen, Blocklisten, erlaubte und blockierte Domains, Statistiken und Sicherungen von Technitium DNS Server 15.5 können übernommen werden. ZenitiumDNS speichert die DNS-Einstellungen im Format Version 14 und die Einstellungen der Weboberfläche im Format Version 6 und Zonendateien mit Zoneninformationen Version 15. Diese Dateien kann das Original nicht mehr lesen.
- **Entfernte Zonentypen:** Zonendateien von Primary-, Secondary-, Stub-, Secondary-Forwarder- und Catalog-Zonen bleiben im Ordner `zones` liegen, werden aber beim Start übersprungen und protokolliert. Sie lassen sich bei Bedarf mit dem Original weiterverwenden.
- **DHCP und Cluster:** DHCP-Bereichsdateien und die Cluster-Konfiguration von Technitium werden ignoriert; Bereiche werden nicht in den DHCP-Server von ZenitiumDNS übernommen, der eigene Einstellungen hat (`dhcp.json`). Berechtigungen für den Bereich DHCP gelten für den neuen DHCP-Server. Versionen vor 15.5.1-12 haben sie beim Laden verworfen; fehlen sie, erhält die Gruppe Administrators volle und die Gruppe DNS Administrators lesende Rechte für DHCP. Eine vorhandene Gruppe „DHCP Administrators“ behält DHCP-Rechte nur, wenn die Konfiguration direkt von Technitium kommt.
- **HTTP-API:** Die API dient nur noch der Weboberfläche. Die Aufrufe für DNSSEC, Catalog-Zonen, Zonenkonvertierung, Resync, TSIG, die DHCP-Bereiche und das Clustering von Technitium, der App-Store, das Installieren und Deinstallieren von Apps, API-Tokens und die Prometheus-Metriken unter `api/dashboard/metrics/text` sowie der Parameter `node` entfallen; Prometheus-Metriken gibt es stattdessen unter `/metrics`. `api/zones/create` akzeptiert nur noch den Typ `Forwarder`.
- **Cache-Datei:** ZenitiumDNS speichert die Nameserver-Statistik in `cache.bin` in einem erweiterten Format (Version 2). Wird eine solche Cache-Datei mit dem Original geladen, verwirft das Original den Cache. Die Konfiguration ist davon nicht betroffen.
- **DNS-Apps:** Die Namensräume wurden umbenannt (`ZenitiumDns.*`, `ZenitiumLibrary.*`). Für Technitium kompilierte Apps müssen gegen `ZenitiumDns.ApplicationCommon` neu kompiliert werden. Alle mitgelieferten Apps sind bereits angepasst.
- **Syslog-Export:** Durch die Korrektur der doppelten Formatierung ändert sich das Format der Syslog-Nachrichten der Log Exporter App. Die Metadaten stehen jetzt als echte strukturierte Daten nach RFC 5424 in der Nachricht.
- **Statistik:** Statistikdateien werden im Format Version 11 (Zähler) und 2 (Stundendateien) gespeichert, das das Original nicht lesen kann. Dateien des Originals werden gelesen.
- **Pipelining:** Clients, die über eine einzelne TCP- oder TLS-Verbindung mehr als 100 Anfragen gleichzeitig offen halten, werden gebremst, bis Antworten gesendet wurden.

## Abgleich mit Technitium DNS Server 15.5.1

Technitium DNS Server 15.5.1 erschien am 26. September 2026. Alle Korrekturen daraus sind in ZenitiumDNS 15.5.1 enthalten, soweit sie noch vorhandene Teile betreffen (DHCP-Korrekturen entfallen). Einige davon hatte ZenitiumDNS bereits vorher:

| Korrektur in 15.5.1 | In ZenitiumDNS |
| ------------------- | -------------- |
| XSS über App-Namen in der Weboberfläche | schon in 15.5 behoben |
| Löschen fremder Sitzungen durch Benutzer ohne Admin-Rechte | schon in 15.5 behoben, zusätzlich Längenprüfung des Teil-Tokens übernommen |
| Blockierende Garbage Collection in der Cache-Wartung (Upstream-Issue #2174) | schon in 15.5 durch Hintergrund-GC behoben, zusätzlich GC nur nach großen Bereinigungen übernommen |
| Resolver-Limits bei langen CNAME-Ketten (Upstream-Issue #2175) | schon in 15.5 durch höhere Limits behoben, jetzt ohne Hash-Limit und mit EDE „ResolverLimitReached“ |
| XSS in der Liste der Logdateien, RA-Flag in Blockierantworten, lokale Blocklisten, RRSIG-Zeitraum, Pfadvergleiche, `install.sh` | neu übernommen |

