# ZenitiumDNS 15.5.1 im Vergleich zu Technitium DNS Server 15.5

Dieses Dokument listet ausschließlich die Unterschiede zwischen dem Original-Build **Technitium DNS Server 15.5** (veröffentlicht am 19. September 2026) und dem Build **ZenitiumDNS 15.5.1** (Stand 27. September 2026) auf. ZenitiumDNS 15.5.1 enthält außerdem alle Korrekturen aus Technitium DNS Server 15.5.1; welche davon ZenitiumDNS schon vorher hatte, steht am Ende. Die vollständige Versionsgeschichte steht in [CHANGELOG.md](CHANGELOG.md).

## Überblick

| Bereich | Technitium DNS Server 15.5 | ZenitiumDNS 15.5 |
| ------- | -------------------------- | ---------------- |
| Name, Pfade, Dienst | Technitium, `/etc/dns`, Dienst `dns` | ZenitiumDNS, `/etc/zenitiumdns`, Dienst `zenitiumdns` |
| Einsatzzweck | autoritativer und rekursiver DNS-Server, DHCP-Server, Clustering | öffentlicher rekursiver Resolver; autoritative Zonen, Zonentransfers, DHCP, Clustering und Windows-Komponenten entfernt |
| Update-Prüfung und App-Store | fest auf Technitium-Server | Update-Prüfung gegen die GitHub-Releases von ZenitiumDNS mit Changelog, App-Store entfernt |
| Installation unter Debian 13 | Skript lädt Binärdateien und .NET aus dem Internet | eigenständiges `.deb`-Paket mit eingebauter .NET-Laufzeit |
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
| Mitgelieferte Apps | müssen einzeln installiert werden, sind danach sofort aktiv | vorinstalliert, standardmäßig deaktiviert, einzeln aktivierbar |
| Docker | Image und Compose-Datei | entfernt |
| Ratenbegrenzung | Durchschnitt der Anfragen pro Minute über ein Stichprobenfenster | Token-Bucket in Anfragen pro Sekunde mit Burst |
| Client-IP-Sperrlisten | nicht vorhanden | IPsum, Spamhaus DROP u. a., Verwerfen vor dem Auswerten der Anfrage |
| TLS-Zertifikate | nur PKCS#12 (`.pfx`) | zusätzlich PEM (`fullchain.pem`, `privkey.pem`) |
| DDR (RFC 9462) | nur über selbst angelegte Zone | eingebaut, automatisch aus den aktiven Diensten, auch für DoH hinter einem Reverse Proxy |
| Selbsttest | nicht vorhanden | eigener Bereich, schwere Probleme auf der Übersicht |
| Speicher für 2,5 Mio. Blocklisten-Einträge | ca. 395 MB | ca. 200 MB |
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
| Prometheus-Metriken, API-Tokens | vorhanden | entfernt |

## Messwerte

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
  - DHCP-Server und Clustering,
  - die Übernahme von DNS-Client-Antworten in eine lokale Zone,
  - 16 Apps für LAN- und Hosting-Szenarien (Auto PTR, Block Page, Default Records, DNS Block List, Failover, Filter AAAA, Geo Continent, Geo Country, Geo Distance, No Data, NX Domain Override, Split Horizon, Weighted Round Robin, What Is My DNS, Wild IP, Zone Alias),
  - Windows-Dienst, Systemtray, Windows-Firewall-Bibliothek und Windows-Installer.
- **Erhalten:** Conditional-Forwarder-Zonen mit lokalen Einträgen und Zugriffsbeschränkung, Blocklisten, erlaubte und blockierte Domains, die Resolver-Apps (Advanced Blocking, Advanced Forwarding, DNS64, DNS Rebinding Protection, Drop Requests, Log Exporter, NX Domain, Query Logs für SQLite, MySQL, PostgreSQL und SQL Server).
- **Protokollverhalten:** AXFR/IXFR werden mit `REFUSED` und EDE „Not Supported“ beantwortet, NOTIFY und UPDATE mit `NOTIMP`, TSIG-signierte Anfragen mit `BADKEY`.

### Anfragefilter
- Regeln nach dem Vorbild von dnsdist, standardmäßig aktiv: nicht lesbar oder unter 12 Byte, über 1232 Byte, Opcode ungleich QUERY, Klasse ungleich IN, ANY, AXFR/IXFR, ohne RD-Flag, EDNS-Version größer 0.
- UDP-Treffer werden verworfen, über TCP, DoT, DoH und DoQ gibt es `REFUSED` mit EDE „Prohibited“. Loopback ist ausgenommen.
- Trefferzähler je Regel in Einstellungen, JSON-Metriken und Prometheus (`request_filter_matches_total`).

### DNSSEC
- Validierung von ML-DSA-44 (Algorithmus 18) und Schutz vor Downgrades auf klassische Algorithmen, wenn der DS-Datensatz einen Post-Quantum-Algorithmus ankündigt.
- Der DNS-Client erklärt, warum die DNSSEC-Prüfung gegen diesen Server scheitert, wenn dessen Validierung ausgeschaltet ist.

### Apps
- Mitgelieferte Apps werden beim ersten Start deaktiviert installiert und bei Paket-Updates aktualisiert. Deinstallierte Apps bleiben entfernt.
- Aktivieren und Deaktivieren in der Weboberfläche und über `api/apps/enable` und `api/apps/disable`.

### Schutz, Blockierung und Protokolle
- Ratenbegrenzung in Anfragen pro Sekunde (GCRA-Token-Bucket je Subnetz, Burst einstellbar), Migration bestehender QPM-Werte.
- Client-Sperrlisten mit automatischer Aktualisierung, Verwerfen vor dem Parsen, Trennen von Stream-Verbindungen.
- Eigener Blockierungstext mit Platzhaltern, eigene TTL für negatives Caching; das SOA-MINIMUM bleibt nach einem Neustart erhalten.
- Blocklisten-Schnellauswahl nur mit HaGeZi-Listen vom Build-Mirror, halber Speicherbedarf der Blocklisten, allokationsfreie Suche.
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

### Web-API und Weboberfläche
- Die Eintrags-APIs beachten `zone=.` für die Root-Zone.
- Die Seitengröße der Log-Abfrage ist begrenzt, und die Größenbegrenzung beim Herunterladen von Logs läuft nicht mehr über.
- Ausstehende Änderungen werden vor Sicherungen und beim Beenden geschrieben.
- Weboberfläche und Dokumentation sind auf Deutsch übersetzt.

### Apps und Stabilität
- Log Exporter App: Syslog-Nachrichten werden nicht mehr doppelt nach RFC 5424 formatiert (Upstream-Issue #2173).
- Der Timer des Load-Balancing-Proxys löst nach dem Entsorgen nicht mehr aus.
- Ein Fehler beim Laden einer Zonendatei führt nicht mehr zu einer `LockRecursionException`.

### Installation und Betrieb
- Debian-13-Paket (`setup/debian/build-deb.sh`) für amd64 und arm64:
  - gehärteter systemd-Dienst,
  - zufälliges Admin-Passwort,
  - automatische Anpassung von systemd-resolved,
  - mitgelieferte DNS-Apps.
- Docker-Image, Compose-Datei und die Umgebungsvariablen zur Erstkonfiguration wurden entfernt.
- Update-Prüfung und App-Store sind standardmäßig deaktiviert: `DNS_SERVER_UPDATE_CHECK_URL`, `DNS_SERVER_APP_STORE_URL`.

## Kompatibilität

- **Konfiguration:** Einstellungen, Benutzer, Conditional-Forwarder-Zonen, Blocklisten, erlaubte und blockierte Domains, Statistiken und Sicherungen von Technitium DNS Server 15.5 können übernommen werden. ZenitiumDNS speichert die DNS-Einstellungen im Format Version 10 und die Einstellungen der Weboberfläche im Format Version 5 und Zonendateien mit Zoneninformationen Version 15. Diese Dateien kann das Original nicht mehr lesen.
- **Entfernte Zonentypen:** Zonendateien von Primary-, Secondary-, Stub-, Secondary-Forwarder- und Catalog-Zonen bleiben im Ordner `zones` liegen, werden aber beim Start übersprungen und protokolliert. Sie lassen sich bei Bedarf mit dem Original weiterverwenden.
- **DHCP und Cluster:** DHCP-Bereichsdateien und die Cluster-Konfiguration werden ignoriert. Berechtigungen für den Bereich DHCP werden beim Laden verworfen. Eine vorhandene Gruppe „DHCP Administrators“ bleibt als gewöhnliche Gruppe ohne Sonderrechte bestehen und kann gelöscht werden.
- **HTTP-API:** Die API dient nur noch der Weboberfläche. Die Aufrufe für DNSSEC, Catalog-Zonen, Zonenkonvertierung, Resync, TSIG, DHCP und Clustering, der App-Store, das Installieren und Deinstallieren von Apps, API-Tokens und die Prometheus-Metriken sowie der Parameter `node` entfallen. `api/zones/create` akzeptiert nur noch den Typ `Forwarder`.
- **Cache-Datei:** ZenitiumDNS speichert die Nameserver-Statistik in `cache.bin` in einem erweiterten Format (Version 2). Wird eine solche Cache-Datei mit dem Original geladen, verwirft das Original den Cache. Die Konfiguration ist davon nicht betroffen.
- **DNS-Apps:** Die Namensräume wurden umbenannt (`ZenitiumDns.*`, `ZenitiumLibrary.*`). Für Technitium kompilierte Apps müssen gegen `ZenitiumDns.ApplicationCommon` neu kompiliert werden. Alle mitgelieferten Apps sind bereits angepasst.
- **Syslog-Export:** Durch die Korrektur der doppelten Formatierung ändert sich das Format der Syslog-Nachrichten der Log Exporter App. Die Metadaten stehen jetzt als echte strukturierte Daten nach RFC 5424 in der Nachricht.
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

