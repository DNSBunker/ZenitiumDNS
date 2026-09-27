# ZenitiumDNS Änderungsprotokoll

## ZenitiumDNS 15.5.1 (Paket 15.5.1-3)
Veröffentlicht: 27. September 2026

### Lokale Root-Zone und Vertrauensanker (RFC 8806)
- Der Resolver lädt die Root-Zone und die arpa-Zone von IANA, prüft sie vollständig und nutzt sie lokal. Die Root-Zone wird über ihre ZONEMD-Prüfsumme (RFC 8976) und die DNSSEC-Signaturen geprüft, die arpa-Zone über die Signaturen aller Einträge und den DS-Eintrag aus der Root-Zone. Delegationen zu Top-Level-Domains und Reverse-Zonen kommen aus dem Speicher, Anfragen nach nicht existierenden Top-Level-Domains beantwortet der Resolver selbst mit NXDOMAIN und signiertem NSEC-Beweis. Im Test gingen bei zufälligen Fantasie-TLDs und neuen Domains keine Anfragen mehr an die Root-Server.
- Die Zonen werden stündlich per If-Modified-Since aktualisiert. Eine Zone, deren Prüfung scheitert, deren Signaturen ablaufen oder die älter als ihr SOA-Expire-Wert ist, wird nicht verwendet; der Resolver fragt dann wie bisher die Root-Server.
- Die Vertrauensanker (Root-KSK) werden täglich aus `root-anchors.xml` von IANA übernommen, aber nur, wenn die Signatur der Datei auf die ICANN Root CA zurückführt. Beide ICANN-Wurzelzertifikate werden mitgeliefert.
- Für alle drei lässt sich unter Einstellungen > Resolver wählen: automatisch von IANA, eine eigene, in der Weboberfläche bearbeitete Version oder aus (Root-Server fragen bzw. mitgelieferte Anker). Der Selbsttest zeigt Seriennummer, Prüfergebnis und Fehler.

### Unverschlüsseltes DNS (Do53)
- Neuer Do53-Modus: aktiviert, nur DDR beantworten und andere Anfragen verwerfen, nur DDR beantworten und andere Anfragen mit `REFUSED` ablehnen, oder deaktiviert (Port 53 wird nicht geöffnet). Anfragen von Loopback-Adressen werden immer beantwortet. Der Selbsttest warnt, wenn Do53 nur DDR beantwortet, es aber keine DDR-Einträge gibt.
- Anfragen von Adressen auf Client-Sperrlisten werden über UDP jetzt vor dem Parsen verworfen.

### Standardwerte für öffentliche Resolver
- Ratenbegrenzung: je IPv4-Adresse 1000 Anfragen/s über UDP und 5000 über TCP, DoT, DoH und DoQ, ohne Sammellimit für `/24`, das CGNAT-Pools ausbremst; IPv6 `/64` 1000 und 5000, `/48` 10.000 und 50.000. Alle gebremsten UDP-Anfragen erhalten eine TC-Antwort, damit echte Clients sofort auf TCP ausweichen. Die bisherigen Standardwerte werden beim Update ersetzt, eigene Werte bleiben erhalten. Die Oberfläche prüft Bereiche und bietet „Empfohlene Werte eintragen“, der Selbsttest warnt vor Limits, die Clients hinter NAT treffen.
- Maximale TTL im Cache 1 Tag statt 7 Tage, neue Obergrenze für negative Antworten von 1 Stunde (RFC 2308), auch für die an Clients ausgelieferte SOA-TTL.
- Auflösungsfehler werden nicht mehr protokolliert und, falls eingeschaltet, einzeilig ohne Stacktrace. Beim Update wird dieses Protokoll abgeschaltet.
- Protokolldateien werden 7 Tage aufbewahrt.

### Blockierung
- Firefox-Canary-Domain `use-application-dns.net` und Chromes Preflight-Prüfung `dns-tunnel-check.googlezip.net` lassen sich mit NXDOMAIN beantworten. Firefox bleibt dann beim Resolver des Netzes, Chrome fragt vor dem Öffnen vorab geladener Seiten nach.
- Der Serverdomainname und alle Namen im TLS-Zertifikat stehen samt Subdomains automatisch auf der Allowlist, damit Listen wie HaGeZis DoH-Bypass den eigenen DoH- oder DoT-Hostnamen nicht sperren.

### Apps
- Der App-Store und das Installieren, Aktualisieren und Deinstallieren von Apps entfallen. Alle Apps kommen mit dem Paket; fehlende mitgelieferte Apps werden beim Start wieder bereitgestellt, vorhandene bei Paket-Updates aktualisiert.
- Neue Konfigurationsoberfläche: ein Formular mit deutschen Bezeichnungen für jede App, abgeleitet aus ihrer `dnsApp.config`, mit Listen, Gruppen und Zuordnungstabellen. Im Expertenmodus lässt sich das JSON direkt bearbeiten; ungültiges JSON wird nicht gespeichert.

### Übersicht und Überwachung
- Zeiträume von 1, 5 und 30 Minuten mit sekundengenauer Auflösung; Standard bleibt die letzte Stunde.
- Echtzeitgraphen interner Prozesse: CPU, Arbeitsspeicher, Garbage Collection, Threadpool, Warteschlangen, laufende Auflösungen, Anfragen pro Sekunde und Lock-Konflikte der letzten 5 Minuten, abschaltbar.
- Neuer Wächter: Er prüft alle 10 Sekunden und greift bei schweren Problemen ein. Bei knappem Speicherplatz oder einer Protokolldatei über 512 MB pausiert er das Datei-Protokoll bis Mitternacht und löscht bei Platzmangel ältere Protokolldateien, bei Speichermangel kürzt er den Cache, eine überlaufende Statistik-Warteschlange leert er, einem ausgehungerten Threadpool gibt er mehr Threads, und fehlen DNS-Dienste, startet er sie bis zu dreimal neu. Eingriffe stehen im Protokoll und im Selbsttest.

### Updates und Version
- Die Update-Prüfung fragt höchstens einmal pro Stunde das neueste Release dieses Projekts auf GitHub ab und zeigt Änderungen, Download-Link für die passende Architektur, SHA256SUMS und den Installationsbefehl. Protokolliert wird nur ein tatsächlich gefundenes Update. Installiert wird nichts automatisch, weil der Dienst ohne Root-Rechte läuft.
- Die Info zeigt die Paketversion, die Technitium-Basisversion, .NET-Laufzeit, Betriebssystem und Architektur.

### Entfernt
- Prometheus-Metriken, API-Tokens (auch `DNS_SERVER_AUTH_STATIC_SESSIONS`) und die API-Dokumentation. Die Weboberfläche nutzt ihre interne API weiter.

### Verschlüsselung und Datenschutz
- EDNS-Padding (RFC 7830, RFC 8467), standardmäßig aktiv: Antworten über DoT, DoH und DoQ werden auf ein Vielfaches von 468 Byte aufgefüllt, wenn die Anfrage selbst Padding enthält, wie bei Browsern und Android. Wahlweise immer oder aus, unter Einstellungen > Protokolle. Anfragen an verschlüsselte Forwarder werden auf 128 Byte aufgefüllt. Antworten über Port 53 werden nie aufgefüllt. Der Selbsttest warnt, wenn Padding ausgeschaltet ist.
- Neue Protokolloption „Keine Client-Adressen protokollieren“: Einträge enthalten dann weder IP-Adressen noch Ports der Clients, auch nicht in den Meldungen der Ratenbegrenzung.
- DDR antwortet zusätzlich auf `_dns.<Servername>` und den Namen im Zertifikat, damit Clients, die den Resolver-Namen schon kennen, die verschlüsselten Dienste direkt abfragen können.

### Sicherheit
- Behoben: Ein Nameserver konnte Einträge mit leeren Daten liefern, etwa einen A-Eintrag ohne Adresse. Jede Anfrage nach solchen Namen schrieb eine Ausnahme samt Stacktrace ins Protokoll, rund 1 KB pro Anfrage, womit sich die Platte füllen ließ; außerdem brach die Cache-Ansicht ab. Solche Einträge werden beim Einlesen abgelehnt.
- Behoben: Eine abgelehnte Einstellungsänderung konnte einzelne Werte trotzdem übernehmen, etwa DDR ausschalten, während Do53 nur DDR beantwortet.

### Behoben
- Die automatische IPv6-Erkennung setzte funktionierende IPv6-Verbindungen aus. Schon 8 aufeinanderfolgende Fehler irgendeines IPv6-Nameservers reichten, und als Fehler zählten auch Anfragen, die nur abgebrochen wurden, weil ein IPv4-Server schneller geantwortet hatte, sowie Antworten wie REFUSED oder SERVFAIL. Auf einem öffentlichen Resolver passierte das ständig; danach waren Zonen, die nur IPv6-Nameserver haben, nicht mehr auflösbar. Jetzt zählen nur echte Transportfehler (Zeitüberschreitung, Netz oder Host nicht erreichbar) und Anfragen, die mindestens eine Sekunde unbeantwortet blieben. Ausgesetzt wird erst, wenn innerhalb von 30 Sekunden keine einzige IPv6-Antwort kam, mindestens 16 Fehler von mindestens 2 Adressen auftraten und eine Prüfung der IPv6-Root-Server ebenfalls scheitert. Jede Antwort über IPv6 hebt die Sperre sofort auf, beide Wechsel stehen im Log. Die Prüfung der IPv6-Root-Server wertet IPv6 erst als gestört, wenn zwei Runden im Abstand von 5 Sekunden mit je 4 zufälligen Root-Servern und 3 Sekunden Timeout scheitern; die Log-Meldung nennt die betroffenen Server und den Fehler. Beim Start läuft die erste Prüfung nach 15 Sekunden, wenn Cache und Blocklisten geladen sind, weil eine einzelne Prüfung unter Startlast IPv6 fälschlich für bis zu 10 Minuten aussetzen konnte. Bis zum Ergebnis (höchstens 120 Sekunden) nutzt der Server IPv6-Adressen nur nachrangig, auch bei Root-Hints und bei Nameservern ohne Glue, deren IPv4-Adresse dann zuerst aufgelöst wird. Auf einem Testserver ohne globales IPv6 scheiterten vorher die ersten Anfragen nach jedem Start mit SERVFAIL, jetzt werden sie in 110 bis 250 ms beantwortet, genauso schnell wie mit abgeschaltetem IPv6; danach läuft die Prüfung nur noch minütlich, solange IPv6 ausgesetzt ist. Im Test mit toten IPv6-Nameservern bei funktionierendem IPv6: vorher gesperrt und 0 von 20 Anfragen an eine reine IPv6-Zone beantwortet, jetzt nicht gesperrt und 20 von 20.
- Beim Nachladen der lokalen Root- und arpa-Zone in den Cache (alle 15 Minuten und nach dem Leeren des Caches) brach der Vorgang mit „Operation is not valid due to the current state of the object“ ab, weil Nameserver-Einträge wiederverwendet wurden. Jetzt werden sie neu angelegt; schlägt eine einzelne Delegation fehl, wird der Rest trotzdem geladen und eine einzeilige Meldung protokolliert.
- Clients, die eine DoH-, DoT- oder DoQ-Verbindung während der Antwort schließen oder zu langsam lesen, erzeugten Fehlermeldungen mit Stacktrace im Log. Diese Fälle werden jetzt still behandelt, die Anfrage wird trotzdem in Statistik und Anfrageprotokoll gezählt. Dasselbe gilt für DoH-Anfragen, deren Body nicht innerhalb des Empfangs-Timeouts ankommt, und für QUIC-Verbindungen, die mit „No route to host“ enden.
- Clients, die für DNS-over-TLS nur TLS 1.0 oder 1.1 anbieten, erzeugten bei jedem Versuch die irreführende Meldung „The server mode SSL must use a certificate with the associated private key“ samt Stacktrace. Der Handshake wird jetzt still abgewiesen; TLS 1.2 und 1.3 sind unverändert.
- Ein ungültiger Servername (SNI) im TLS- oder QUIC-Handshake, etwa mit Steuer- oder Leerzeichen, ließ die Verbindung mit einer Exception scheitern. Der Name wird jetzt ignoriert und die Verbindung normal bedient.
- Das Anfrageprotokoll zeigt Antwortcodes wie `NOERROR` und `NXDOMAIN` statt deutscher Umschreibungen.

### Weitere Änderungen
- Konfigurationsformat Version 11 für die DNS-Einstellungen. Ältere Versionen von ZenitiumDNS können es nicht lesen.
- Die Einträge im Technitium-Repository seit 15.5.1 wurden geprüft: Die gemeldeten Resolver-Probleme sind in der Basis bereits behoben oder betreffen Funktionen, die ZenitiumDNS nicht enthält (Block-Page-App, Syslog-Doppelformatierung).

## ZenitiumDNS 15.5.1 (Paket 15.5.1-2)
Veröffentlicht: 26. September 2026

### Schutz für den öffentlichen Betrieb
- Die Ratenbegrenzung arbeitet in Anfragen pro Sekunde mit einem Token-Bucket je Client-Subnetz (GCRA, wie bei dnsdist). Ein einstellbarer Burst (Standard 5 Sekunden) lässt kurze Spitzen etwa beim Laden einer Webseite zu. Neue Standardwerte: IPv4 `/32` 100 und 400, `/24` 1000 und 4000, IPv6 `/64` 100 und 400, `/56` 1000 und 4000 Anfragen pro Sekunde für UDP und TCP. Bestehende Limits werden umgerechnet, die bisherigen Standardwerte durch die neuen ersetzt. Beginn und Ende einer Drosselung stehen im Log.
- Neue Client-Sperrlisten im Anfragefilter: Listen wie IPsum oder Spamhaus DROP werden automatisch geladen und aktualisiert. Anfragen gesperrter Adressen werden über UDP verworfen, bevor sie ausgewertet werden, TCP-, DoT-, DoQ- und DoH-Verbindungen werden sofort getrennt. Die Suche läuft über sortierte Adressbereiche. Neue Metriken `client_blocklist_drops_total` und `client_blocklist_ranges`.

### Blockierung
- Eigener Blockierungstext für den Extended DNS Error und den TXT-Bericht mit den Platzhaltern `{domain}`, `{list}` und `{source}`.
- Eigene TTL für negatives Caching: NXDOMAIN- und NODATA-Blockierantworten tragen einen SOA-Eintrag mit dieser TTL und diesem MINIMUM (Standard 300 Sekunden).
- Behoben: Das SOA-MINIMUM der Blockierantworten fiel nach jedem Neustart auf 30 Sekunden zurück, bis die Einstellung einmal geändert wurde.
- Die Schnellauswahl der Blocklisten enthält nur noch die Listen von HaGeZi im Format für diesen Server, geladen vom Build-Mirror `hagezi-mirror.dnsbunker.org`. Das Standardintervall für die Aktualisierung beträgt 8 Stunden.
- Blocklisten brauchen rund die Hälfte des Arbeitsspeichers: 2,5 Millionen Domains (HaGeZi PRO und TIF) belegen etwa 200 statt 395 MB. Die Suche läuft ohne Speicherallokation. Gemessen auf 20 Kernen: rund 913.000 Anfragen/s für erlaubte und 852.000 Anfragen/s für blockierte Namen, ohne Listen 919.000 Anfragen/s. Das Neuladen dauert 1,1 Sekunden.

### Verschlüsselte Protokolle
- TLS-Zertifikate im PEM-Format, etwa `fullchain.pem` und `privkey.pem` von Let's Encrypt, auch für die Weboberfläche. Zwischenzertifikate werden mitgesendet, verschlüsselte Schlüssel im PKCS#8-Format unterstützt. Zertifikat und Schlüssel werden auch nach einer Erneuerung über Symlinks automatisch neu geladen.
- DDR (RFC 9462) ist eingebaut: Der Server beantwortet `_dns.resolver.arpa` SVCB mit den aktivierten verschlüsselten Diensten, ihren Ports und dem Namen im Zertifikat. Wahlweise nur über unverschlüsseltes DNS (Standard). Die erzeugten Einträge stehen in den Einstellungen.
- 0-RTT (TLS Early Data) bietet der TLS- und QUIC-Stack von .NET serverseitig nicht an. Die Einstellungen erklären, wie sich 0-RTT für DoH über einen vorgeschalteten Reverse Proxy nutzen lässt.

### Selbsttest
- Neuer Bereich „Selbsttest“: Er prüft lauschende Dienste, die Auflösung der Root-Zone samt DNSSEC-Validierung, IPv6, Zertifikate, Admin-Passwort, Erreichbarkeit der Weboberfläche, Rekursion, Ratenbegrenzung, Anfragefilter, Block- und Client-Sperrlisten, Apps, Systemzeit, Arbeitsspeicher, UDP-Puffer, Dateilimit und freien Speicherplatz. Schwere Probleme erscheinen zusätzlich auf der Übersicht. Neuer API-Aufruf `api/selftest/run`.

### Resolver
- Behoben: Autoritative Server wie die von Cloudflare beantworten nur eine Anfrage pro TCP-Verbindung. Wiederverwendete Verbindungen liefen deshalb in Timeouts, und große Antworten wie DNSKEY-Sätze mit ML-DSA-Signaturen scheiterten. Der TCP-Rückfall nach abgeschnittenen UDP-Antworten nutzt jetzt eigene Verbindungen, und Server ohne Verbindungswiederverwendung werden erkannt.
- Die QNAME-Minimierung fragt eine Zone erneut mit dem vollen Namen, wenn keiner ihrer Nameserver auf die minimierte Anfrage antwortet.
- Behoben: Mit „IPv6 bevorzugen“ ohne funktionierende IPv6-Anbindung scheiterten Downloads von Blocklisten und Apps nach 100 Sekunden. Downloads nutzen jetzt den tatsächlich verfügbaren IPv6-Modus und wechseln nach 5 Sekunden zur nächsten Adresse.

### Weitere Änderungen
- Konfigurationsformat Version 9 für die DNS-Einstellungen und Version 5 für die Weboberfläche.
- Die API-Dokumentation beschreibt die neuen Einstellungen und Aufrufe.

## ZenitiumDNS 15.5.1
Veröffentlicht: 26. September 2026

### Abgleich mit Technitium DNS Server 15.5.1
- Alle Korrekturen aus Technitium DNS Server 15.5.1 vom 26. September 2026 sind übernommen, soweit sie Teile betreffen, die es in ZenitiumDNS noch gibt:
  - Der Resolver hat kein festes Limit für Hash-Operationen pro Anfrage mehr. Erreicht eine Auflösung ein anderes Resolver-Limit, nennen Fehlermeldung und Extended DNS Error (privater Code „ResolverLimitReached“) den Grund.
  - RRSIG-Signaturen, deren Beginn nach ihrem Ablauf liegt, gelten als ungültig.
  - Blockierte Antworten setzen das RA-Flag abhängig von „Blockierungsbericht ausgeben“, auch in der Advanced Blocking App (Version 11.2.1).
  - Lokale Blocklisten (`file://`) werden direkt aus der Quelldatei gelesen statt kopiert. Fehlt die Datei, wird das protokolliert.
  - Die Cache-Wartung stößt die Garbage Collection nur noch nach größeren Bereinigungen an. Server-GC ist fest eingestellt.
  - Pfadvergleiche beim Log-Ordner und in der App-Verwaltung sind korrigiert.
  - `api/user/session/delete` prüft die Länge des Teil-Tokens.
  - XSS in der Liste der Logdateien ist behoben.
  - `install.sh` ändert `/etc/resolv.conf` nur noch bei der Erstinstallation und setzt `umask 0022`.

### Anfragefilter für den öffentlichen Betrieb
- Neuer Einstellungsbereich „Anfragefilter“ mit Regeln nach dem Vorbild von dnsdist. Alle Regeln sind standardmäßig aktiv und greifen vor jeder weiteren Verarbeitung:
  - nicht lesbare Anfragen und Anfragen unter 12 Byte,
  - Anfragen über 1232 Byte (einstellbar),
  - Opcode ungleich QUERY,
  - Klasse ungleich IN,
  - Typ ANY,
  - AXFR und IXFR,
  - Anfragen ohne RD-Flag,
  - EDNS-Version größer 0.
- Über UDP werden Treffer stillschweigend verworfen, damit der Server nicht als Reflektor dient. Über TCP, DNS-over-TLS, DNS-over-HTTPS und DNS-over-QUIC antwortet er mit `REFUSED` und dem Extended DNS Error „Prohibited“. Wahlweise wird auch über UDP nur abgewiesen. Anfragen von Loopback-Adressen sind ausgenommen.
- Trefferzähler je Regel stehen in den Einstellungen, in `api/dashboard/metrics/json` und als Prometheus-Metrik `request_filter_matches_total{rule}`.

### DNSSEC
- Validierung des Post-Quantum-Algorithmus ML-DSA-44 (Algorithmus 18, draft-westerbaan-dnssec-mldsa) über BouncyCastle.
- Schutz vor Downgrades: Kündigt der DS-Datensatz einer Zone einen Post-Quantum-Algorithmus an, akzeptiert der Resolver für diese Zone nur noch Post-Quantum-Schlüssel. Die Einstellung „Post-Quantum-Downgrade-Schutz“ ist standardmäßig aktiv.
- Der DNS-Client der Weboberfläche erklärt, warum eine DNSSEC-Prüfung gegen diesen Server scheitert, wenn dessen DNSSEC-Validierung ausgeschaltet ist. Bisher erschien nur „Attack detected! RRSIGs missing“.
- Das Umschalten der DNSSEC-Validierung leert immer den Cache.

### Apps
- Die mitgelieferten Apps werden beim ersten Start installiert, bleiben aber deaktiviert, bis sie in der Weboberfläche aktiviert werden. Bei Paket-Updates werden sie aktualisiert, ihre Konfiguration bleibt erhalten. Vom Benutzer deinstallierte Apps werden nicht erneut installiert.
- Jede App lässt sich aktivieren und deaktivieren, auch über `api/apps/enable` und `api/apps/disable`. Deaktivierte Apps greifen nicht in die Verarbeitung ein, ihre Konfiguration bleibt bearbeitbar.
- Neue Umgebungsvariable `DNS_SERVER_BUNDLED_APPS_PATH` für den Ordner mit den mitgelieferten Apps.

### Standardwerte für neue Installationen
- Cache: höchstens 100.000 Einträge statt 10.000.
- Blockierantworten: TTL 300 statt 30 Sekunden.
- Netzwerk: Listen-Backlog 1024 statt 100, TCP-Empfangs-Timeout 5 statt 10 Sekunden, IPv6 für ausgehende Anfragen aktiviert.
- Statistik- und Logdateien werden 30 statt 365 Tage aufbewahrt.
- Die Rekursion bleibt auf private Netze beschränkt, bis sie bewusst für alle freigegeben wird.
- Bestehende Konfigurationen bleiben unverändert.

### Performance
- Statistikdaten laufen über eine lockfreie Warteschlange mit eigenem Verarbeitungs-Thread.
- Eindeutige Clients werden per HyperLogLog mit festem Speicherbedarf gezählt. `clients_total` ist in den Prometheus-Metriken jetzt ein Gauge.
- UDP-Empfangs-Threads wecken weitere Threads erst bei anhaltendem Rückstau, Sendepuffer werden wiederverwendet.
- Antworttypen werden ohne Boxing markiert, die Ratenbegrenzung überspringt die Prüfung, solange kein Client ein Limit überschreitet.
- Server-GC mit nebenläufiger Garbage Collection.

### Sicherheit
- DNS-over-HTTPS per POST: Anfragen über 65.535 Byte werden mit Status 413 abgewiesen, der Inhalt wird begrenzt gelesen. Abgebrochene Verbindungen erzeugen keine Fehlerprotokolle mehr.
- DNS-Nachrichten mit unplausiblen Eintragszahlen werden vor dem Parsen verworfen.
- Die Weboberfläche maskiert Werte in Inline-Handlern für JavaScript, etwa im Cache-Browser, bei Weiterleitungszonen und in den Protokollen.

### Betrieb und Quellcode
- Docker-Unterstützung entfernt: Dockerfile, Compose-Datei und die Umgebungsvariablen zur Erstkonfiguration, einschließlich SSO, LDAP und `DNS_SERVER_ADMIN_PASSWORD`. `DNS_SERVER_ADMIN_PASSWORD_FILE` bleibt erhalten.
- Der Quellcode enthält keine Kommentare mehr, nur die Lizenzköpfe bleiben erhalten.
- Die DNS-Einstellungen werden im Format Version 8 gespeichert, das ältere Builds nicht lesen können.
- Quellcode und Releases: https://github.com/DNSBunker/ZenitiumDNS-DE

## ZenitiumDNS 15.5
Veröffentlicht: 26. September 2026

### Fork und Projektstruktur
- Fork von Technitium DNS Server 15.5 unter dem Namen ZenitiumDNS. Die vollständige Liste der Änderungen gegenüber dem Original steht in [NOTICE.md](NOTICE.md).
- DNS-Server und Bibliothek in einem gemeinsamen Quellbaum mit einer Solution (`ZenitiumDNS.slnx`) und Projektreferenzen zusammengeführt.
- Update-Prüfung und DNS-App-Store sind standardmäßig deaktiviert und lassen sich über die neuen Umgebungsvariablen `DNS_SERVER_UPDATE_CHECK_URL` und `DNS_SERVER_APP_STORE_URL` auf eigene Endpunkte umstellen.
- Linux-Installationen verwenden `/opt/zenitiumdns`, `/etc/zenitiumdns` und `/var/log/zenitiumdns` mit dem Dienst und Benutzer `zenitiumdns`.
- Das Docker-Image wird mit einem mehrstufigen `Dockerfile` direkt aus dem Quellcode gebaut.
- Die Weboberfläche und die Dokumentation sind auf Deutsch übersetzt.

### Debian-Paket
- Neues eigenständiges Debian-Paket für Debian 13 (`setup/debian/build-deb.sh`, amd64 und arm64). Es bringt die .NET-Laufzeit mit, sodass keine separate .NET-Installation nötig ist.
- Gehärteter systemd-Dienst mit eigenem Systembenutzer und Start erst nach `network-online.target`.
- Bei der Erstinstallation wird ein zufälliges Admin-Passwort erzeugt und ausgegeben, statt `admin`/`admin` zu verwenden.
- Ist systemd-resolved aktiv, wird dessen Stub-Listener automatisch deaktiviert, damit Port 53 frei ist. Beim Entfernen des Pakets wird das rückgängig gemacht.
- Alle mitgelieferten DNS-Apps liegen als ZIP-Dateien in `/usr/share/zenitiumdns/apps` und können über die Weboberfläche installiert werden.

### Ausrichtung als öffentlicher Resolver
- ZenitiumDNS ist auf den Betrieb als öffentlicher rekursiver Resolver zugeschnitten. Folgende Funktionen des Originals wurden entfernt:
  - autoritative Zonen vom Typ Primary, Secondary, Stub, Secondary Forwarder und Catalog samt DNSSEC-Signierung, Schlüsselverwaltung und SOA-Bearbeitung,
  - Zonentransfers (AXFR, IXFR, XFR-over-TLS, XFR-over-QUIC), DNS NOTIFY, dynamische Updates (RFC 2136) und TSIG-Schlüssel,
  - der DHCP-Server mit Bereichen, Leases und der Berechtigungsgruppe „DHCP Administrators“,
  - das Clustering samt HTTP-API-Client und Cluster-Optionen in Sicherung und Wiederherstellung,
  - die Übernahme von DNS-Client-Antworten in eine lokale Zone,
  - die Apps für LAN- und Hosting-Szenarien: Auto PTR, Block Page, Default Records, DNS Block List, Failover, Filter AAAA, Geo Continent, Geo Country, Geo Distance, No Data, NX Domain Override, Split Horizon, Weighted Round Robin, What Is My DNS, Wild IP und Zone Alias,
  - Windows-Dienst, Systemtray-App, Windows-Firewall-Bibliothek und Windows-Installer.
- Erhalten bleiben Conditional-Forwarder-Zonen (in der Weboberfläche „Weiterleitungszonen“) mit lokal überschreibbaren Einträgen und Zugriffsbeschränkung pro Zone, Blocklisten, erlaubte und blockierte Domains sowie die Resolver-Apps.
- Anfragen vom Typ AXFR und IXFR werden mit `REFUSED` und dem Extended DNS Error „Not Supported“ beantwortet, NOTIFY und UPDATE mit `NOTIMP`. Signierte Anfragen (TSIG) erhalten `BADKEY`.
- Bestehende Installationen lassen sich weiterverwenden: Conditional-Forwarder-Zonen, Einstellungen, Benutzer und Statistiken werden übernommen. Zonendateien anderer Zonentypen bleiben unverändert im Konfigurationsordner liegen und werden beim Start mit einem Protokolleintrag übersprungen. Entfernte Einstellungen werden beim nächsten Speichern verworfen.

### Statistik und Überwachung
- Neue Antwortzeit-Messung vom Eingang einer Anfrage bis zum Versand der Antwort für UDP, TCP, DNS-over-TLS, DNS-over-HTTPS und DNS-over-QUIC. Ausgewertet werden Durchschnitt, Median, 95. und 99. Perzentil und Maximum sowie getrennte Durchschnitte für Antworten aus dem Cache und für rekursiv aufgelöste Antworten.
- Die Übersicht zeigt Kennzahlen für Anfragen pro Sekunde, Antwortzeit, Cache-Trefferquote, Fehlerquote, Blockierquote und Clients, Statuschips für Blockierung, DNSSEC-Validierung, IPv6, Auflösungsart und Laufzeit, einen Antwortzeit-Verlauf pro Minute, Tabellen mit Anteilen sowie umschaltbare Verlaufsansichten (Übersicht, Antworten, Beantwortet durch, Clients).
- Die Kreisdiagramme zeigen Anteile im Tooltip und einen Hinweis, wenn im Zeitraum keine Daten vorliegen. Diagramme passen sich dem hellen und dunklen Design an.
- `api/dashboard/stats/get` liefert zusätzlich `live`, `lastHourResponseTime`, `responseTimeChartData` und `serverStatus`. Die Diagrammdaten enthalten keine Farbangaben mehr.
- Die JSON-Metriken enthalten Antwortzeiten über 5 und 60 Minuten, die Zahl der Cache-Einträge und den Serverstatus. Die Prometheus-Metriken enthalten zusätzlich `cache_entries`, `ipv6_upstream_available`, `queries_per_second` und `response_time_milliseconds` für 1, 5 und 60 Minuten.
- Neuer API-Aufruf `api/dashboard/ipv6/probe`, der die IPv6-Erreichbarkeit der Nameserver sofort prüft.
- Behoben: In gekürzten Top-Listen und Diagrammen fehlte in der Summe „Andere“ der erste abgeschnittene Eintrag.

### Weboberfläche
- Neues Erscheinungsbild: App-Rahmen mit Seitenleiste und Seitentitel, Farbsystem in Petrol passend zum Logo, lokal eingebundene Schriften Red Hat Text, Display und Mono (keine externen Abrufe), einheitlich gestaltete Formulare, Tabellen, Dialoge und Hinweise. Hell, Dunkel und Bernstein nutzen dasselbe Token-System, das Farbschema „wie Betriebssystem“ greift schon vor dem ersten Laden der Skripte.
- Die Übersicht beginnt mit einer Messwertleiste: Anfragen pro Sekunde, Antwortzeit, Cache-Trefferquote, Fehler- und Blockierquote sowie Clients, jeweils mit Verlauf im gewählten Zeitraum und Statusangabe in Worten.
- Diagrammfarben sind auf Unterscheidbarkeit bei Farbfehlsichtigkeit geprüft und folgen dem Farbschema. Jede Kategorie behält ihre Farbe über alle Ansichten.
- Die Oberfläche ist auf Tablets und Smartphones bedienbar: Die Seitenleiste wird zur Symbolleiste, Tabellen lassen sich seitlich scrollen. Die feste Mindestbreite von 970 Pixeln entfällt.
- Hinweise erscheinen als Einblendung oben rechts, Ladeanzeigen sind animierte Symbole statt GIF-Grafiken. Das DNS-Client-Formular ist neu angeordnet, Listen in Cache, Filter und Protokollen zeigen Aktionen mit Symbolen statt Klammer-Links.
- Die Hauptnavigation ist nach Aufgaben gegliedert: Übersicht, Resolver (Weiterleitungszonen und Cache), Filter (blockierte und erlaubte Domains, Blocklisten), Apps, DNS-Client, Protokolle, Einstellungen, Verwaltung und Info.
- Die Einstellungen sind in zehn Bereiche mit seitlicher Navigation, Erklärungstexten und einer stets sichtbaren Speicherleiste aufgeteilt: Server, Netzwerk, Resolver, Weiterleitung & Proxy, Cache, Blockierung, Ratenbegrenzung, Verschlüsselte Protokolle, Weboberfläche und Protokollierung.
- Neue Einstellungen: automatischer IPv6-Rückfall mit Statusanzeige und Prüfknopf, Zahl der UDP-Empfangs-Threads je Socket und Obergrenze gleichzeitiger Anfragen je TCP-/TLS-Verbindung.
- Nicht mehr benötigte Einstellungen für SOA, Zonentransfer, NOTIFY und TSIG wurden entfernt.
- Datumsangaben erscheinen einheitlich im deutschen Format, Forwarder-Einträge zeigen Proxy-Art und DNSSEC-Validierung lesbar an.
- Die Übersicht wird beim Zurückwechseln auf den Tab sofort aktualisiert.

### Rekursiver Resolver
- Behoben: `SERVFAIL` mit „No valid response from name servers“ bei Domains, die über CNAME-Ketten oder Nameserver ohne Glue-Records aufgelöst werden (z. B. `www.bbc.com`, `x.com`). Die Resolver-Limits pro Anfrage wurden angehoben (Upstream-Issue #2175).
- Behoben: Die QNAME-Minimierung schickte vor der eigentlichen Anfrage für das letzte Label eine zusätzliche Anfrage vom Typ `A`, sogar nach einer NXDOMAIN-Antwort.
- Behoben: Die rekursive Auflösung fiel komplett aus, wenn die Root-Priming-Anfrage fehlschlug oder keine Glue-Records lieferte. Der Resolver greift jetzt auf die Root-Hints zurück. Die Priming-Anfrage wird ohne RD-Flag gesendet.
- Behoben: Doppelte Nameserver-Einträge in der Nameserver-Liste des Resolvers.
- Behoben: Antworten mit abweichender Groß-/Kleinschreibung des QNAME (DNS 0x20) wurden als allgemeiner Fehler statt als Spoofing-Versuch behandelt. Der Resolver wiederholt die Anfrage jetzt sofort über TCP.
- Behoben: Mit der Einstellung „IPv6 bevorzugen“ schlug die Auflösung für Zonen, deren Nameserver per IPv6 nicht erreichbar sind, bei jeder Anfrage fehl, weil IPv6-Adressen immer zuerst abgefragt wurden. Nicht erreichbare Adressen werden jetzt erkannt und hinter funktionierende IPv4-Adressen einsortiert.
- Neuer automatischer IPv6-Rückfall (Einstellung „IPv6 bei Störungen automatisch aussetzen“, standardmäßig an): Nach 8 aufeinanderfolgenden IPv6-Zeitüberschreitungen werden ausgehende IPv6-Anfragen für eine Minute ausgesetzt, bei wiederholten Störungen bis zu 30 Minuten. Eine Prüfung gegen die IPv6-Root-Server alle zwei Minuten nimmt IPv6 wieder auf, sobald es funktioniert.
- Die Statistik zur Nameserver-Auswahl (RTT, Fehlerrate) wird jetzt getrennt für IPv4 und IPv6 geführt. Eine defekte IPv6-Adresse wertet dadurch nicht mehr die funktionierende IPv4-Adresse desselben Nameservers ab.
- Die Antwortquote der Nameserver wird als gleitender Durchschnitt statt über die gesamte Laufzeit berechnet. Ausgefallene Nameserver werden dadurch innerhalb weniger Anfragen nach hinten sortiert und nach ihrer Erholung wieder bevorzugt.
- Behoben: Die mehrfachen instabilen Sortierungen der Nameserver-Liste konnten die Reihenfolge nach Antwortzeit wieder zerstören. Die Auswahl verwendet jetzt eine einzige kombinierte Sortierung.
- Die Cache-Ansicht zeigt die Nameserver-Statistik zusätzlich getrennt für IPv6 und die aktuelle Antwortquote an.

### Cache
- Behoben: Schlug die DNSSEC-Validierung an den Root-Servern fehl, etwa hinter einer Firewall, die DNS abfängt, blieben die Root-Server fünf Minuten lang gesperrt. Das galt auch nach dem Abschalten der Validierung und nach „Cache leeren“. Beide Aktionen setzen die Sperre jetzt zurück, das Umschalten der DNSSEC-Validierung leert den Cache in beide Richtungen.
- Behoben: Abgelaufene Fehler-Cache-Einträge wurden als veraltete Antworten (Serve Stale) ausgeliefert und verlängerten so Auflösungsfehler nach Ausfällen.
- Behoben: Das Cache-Prefetching löste bei Einträgen mit kurzer TTL bei fast jeder Anfrage eine Upstream-Anfrage aus.
- Behoben: Die Cache-Wartung führte jede Minute eine blockierende vollständige Garbage Collection aus, die die Anfragebearbeitung für bis zu 250 ms anhielt (Upstream-Issue #2174). Auch das Neuladen von Statistiken, Blocklisten und der Advanced-Forwarding-App nutzt jetzt eine Garbage Collection im Hintergrund.
- Behoben: Eine Race Condition in der Cache-Wartung konnte frisch zwischengespeicherte Einträge verwerfen und den Eintragszähler aufblähen, wenn eine leere Cache-Zone genau dann entfernt wurde, als neue Einträge hinzukamen.
- Behoben: Bei A- und AAAA-RRsets mit mehreren Einträgen wurde der Zeitpunkt der letzten Nutzung nie aktualisiert. Bei vollem Cache wurden so gerade häufig genutzte Einträge zuerst verdrängt.

### Performance
- UDP-Anfragen werden von dedizierten Empfangs-Threads gelesen und bei Cache-Treffern direkt auf demselben Thread beantwortet, ohne Wechsel über den Thread-Pool. Bei 100.000 Anfragen pro Sekunde sinkt die CPU-Zeit pro Anfrage um rund 70 % und die mittlere Latenz von 70–85 µs auf 19 µs.
- Antworten per UDP werden synchron gesendet. Das spart pro Anfrage eine asynchrone Socket-Operation samt Allokationen.
- Die interne Verarbeitungskette nutzt `ValueTask` statt `Task`, sodass bei synchron abgeschlossenen Anfragen keine Task-Objekte mehr entstehen.
- Die Namenskompression beim Serialisieren von DNS-Nachrichten kopiert keine Domainnamen mehr und verwendet eine wiederverwendbare Offset-Liste.
- Die Prüfung auf spezielle Zonen (z. B. `.local`, `.test`) erzeugt keine temporären Strings mehr.
- Der Zeitpunkt der letzten Nutzung von Cache- und Zoneneinträgen wird höchstens einmal pro Sekunde geschrieben. Das vermeidet Konflikte zwischen den CPU-Kernen.
- Insgesamt sinken die Allokationen pro Anfrage um etwa 65 % und die Pausenzeit der Garbage Collection unter Volllast von 22 % auf 7 %. Der Spitzendurchsatz steigt um 5 bis 12 %.

### Verschlüsselte Protokolle
- Behoben: Über eine einzelne DNS-over-TCP- oder DNS-over-TLS-Verbindung konnte ein Client unbegrenzt viele Anfragen gleichzeitig offen halten. Pro Verbindung sind jetzt standardmäßig höchstens 100 laufende Anfragen erlaubt (einstellbar von 1 bis 10.000), weitere werden erst nach Abschluss gelesen.
- Bei DNS-over-HTTPS wird als Serveradresse jetzt die Endpunkt-URL ohne den Anfrageinhalt (`?dns=…`) gespeichert und protokolliert.

### Sicherheit
- Behoben: Die in `DNS_SERVER_AUTH_STATIC_SESSIONS` festgelegten API-Tokens wurden beim allerersten Start ohne vorhandene `auth.config` nicht geladen und funktionierten erst nach einem Neustart.
- Behoben: Der Filter nach Server in den Query-Log-Apps für MySQL, PostgreSQL und SQL Server wurde nicht als Parameter übergeben (SQL-Injection).
- Behoben: Mehrere Stellen in der Weboberfläche gaben App-Namen ohne HTML-Kodierung aus (XSS).
- Behoben: Benutzer ohne Admin-Rechte konnten fremde Sitzungen löschen.
- Behoben: Beim Wiederherstellen einer Sicherung konnten ZIP-Einträge außerhalb des Zielordners geschrieben werden.
- Behoben: TLS-Zertifikatspfade in Ordnern, deren Name mit dem Namen des Konfigurationsordners beginnt (z. B. `/etc/dnscert` neben `/etc/dns`), wurden als falscher relativer Pfad gespeichert. Das Zertifikat ließ sich nach einem Neustart nicht mehr laden (Upstream-Issue #2162).

### Web-API und Weboberfläche
- Behoben: Die API-Aufrufe zum Hinzufügen, Abrufen, Ändern und Löschen von Einträgen ignorierten `zone=.`. Einträge für die Root-Zone landeten dadurch in einer untergeordneten Zone.
- Behoben: Die Seitengröße der Log-Abfrage wurde nicht begrenzt, und die Größenbegrenzung beim Herunterladen von Logs konnte überlaufen.
- Behoben: Ausstehende Änderungen an Zonen- und Konfigurationsdateien wurden vor dem Erstellen einer Sicherung und beim Beenden nicht immer geschrieben.

### Apps und Stabilität
- Behoben: Das Syslog-Ziel der Log-Exporter-App formatierte jede Nachricht zweimal nach RFC 5424 (Upstream-Issue #2173).
- Behoben: Der Timer des Load-Balancing-Proxys konnte nach dem Entsorgen noch auslösen und Ausnahmen werfen.
- Behoben: Schlug das Laden einer Zonendatei beim Start fehl, führte das Aufräumen zu einer `LockRecursionException`.

# Technitium DNS Server Änderungsprotokoll

Die folgenden Einträge stammen aus dem ursprünglichen Projekt Technitium DNS Server, auf dem ZenitiumDNS basiert. Namen von Einstellungen und Menüs beziehen sich auf die jeweilige Version des Originals.

## Version 15.5
Veröffentlicht: 19. September 2026

- Unterstützung für LDAP-Authentifizierung hinzugefügt. Danke an Roy Hagland (@Hemsby) für den PR #1869.
- Unterstützung für [draft-farrokhi-dnsop-ede-nta](https://datatracker.ietf.org/doc/html/draft-farrokhi-dnsop-ede-nta) umgesetzt. Ein NTA wird angelegt, indem eine Conditional-Forwarder-Zone für den Domainnamen mit deaktivierter DNSSEC-Validierung erstellt wird. Die Kommentare des FWD-Eintrags werden als Extended DNS Error (EDE) in die Antwort übernommen.
- Zonendatei-Editor für Primary- und Conditional-Forwarder-Zonen hinzugefügt.
- Unterstützung für vordefinierte statische API-Sitzungen hinzugefügt, die über die neue Umgebungsvariable `DNS_SERVER_AUTH_STATIC_SESSIONS` konfiguriert werden.
- Neue Umgebungsvariable `DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH` hinzugefügt, mit der der www-Stammordner des Webdienstes geändert werden kann, um eine eigene Weboberfläche zu verwenden. Danke an Adrián García (@byGarcia) für den PR #2138.
- Docker Compose um eine Health-Check-Option ergänzt, die den Health-Check-API-Aufruf verwendet.
- Die Health-Check-API darf jetzt von Loopback-Adressen ohne Authentifizierung aufgerufen werden, um den Docker-Health-Check zu unterstützen.
- Von Qifan Zhang (Palo Alto Networks) gemeldete Multi-Hop-Amplification-Schwachstelle behoben, die über mehrere CNAME- und Delegations-Hops einen Paketverstärkungsfaktor von 4.096:1 erreichte.
- Von Qifan Zhang (Palo Alto Networks) gemeldete Cache-Poisoning-Schwachstelle behoben, die das Zwischenspeichern von DNAME-Einträgen außerhalb des Zuständigkeitsbereichs (out-of-bailiwick) aus einer vom Angreifer kontrollierten Zone für beliebige Domainnamen erlaubte.
- Von Qifan Zhang (Palo Alto Networks) gemeldete Umgehung der DNSSEC-Validierung behoben, bei der eine vom Angreifer kontrollierte Zone DS-Einträge außerhalb ihres Zuständigkeitsbereichs in Referral-Antworten einschleusen konnte, um den Resolver-Cache zu vergiften und die DNSSEC-Validierung für beliebige signierte Zonen auszuhebeln.
- Von Xuanchao Xie gemeldete Denial-of-Service-Schwachstelle (DoS) behoben, bei der ein Angreifer die DNS-over-HTTPS/3-Implementierung (DoH/3) ausnutzen konnte, damit der DNS-Server große Datenmengen im Speicher puffert und mit einem Out-Of-Memory-Fehler (OOM) abstürzt.
- Von Tao Pan (@pant0m) gemeldete Umgehung der Berechtigungsprüfung behoben, bei der über die Option `ptr` in den API-Aufrufen zum Hinzufügen, Ändern und Löschen von Einträgen PTR-Einträge in beliebigen Reverse-Zonen angelegt, überschrieben oder gelöscht werden konnten, für die der Benutzer keine Schreibrechte hatte.
- Dauerhafte Denial-of-Service-Schwachstelle (DoS) für einen vom Angreifer gewählten Domainnamen behoben, gemeldet von Abdullah Al Ishtiaq, Kai Tu, Matthew Carter, Xiaotian Zhou, Ananna Rahman, Yilu Dong, Tianwei Yu, Ali Ranjbar und Syed Rafiul Hussain vom SyNSec Lab der Pennsylvania State University. Der Angreifer konnte den Domainnamen des Opfers in einen fehlschlagenden Hintergrund-Resolver-Task einreihen, sodass der DNS-Server neu gestartet werden musste.
- Off-Path-Cache-Poisoning-Schwachstelle behoben, gemeldet von Lior Shafir, Ameer Saleh, Prof. Raja Giryes und Prof. Avishai Wool von der Universität Tel Aviv. Ein Angreifer konnte einen CNAME-Eintrag in den Cache einschleusen, der alle Anfragen für den Domainnamen des Opfers auf die im CNAME angegebene Domain des Angreifers umleitete.
- Mehrere gespeicherte XSS-Schwachstellen behoben, gemeldet von Yuqi Qiu und Xiang Li vom AOSP Lab der Nankai University.
- Umgehung der Zonennamen-Validierung in den API-Aufrufen „Zone klonen“ und „DNS-Client-Import“ behoben, gemeldet von Yuqi Qiu und Xiang Li vom AOSP Lab der Nankai University.
- Schwerer Fehler in der Bereinigung von Antworten im DNS-Client behoben, der bei bestimmten Antworten eine Out-Of-Memory-Ausnahme auslöste und den DNS-Server abstürzen ließ.
- Die Funktion Auto-Prefetch wurde entfernt, da sie kaum wirksam war und zu viele Systemressourcen benötigte. Das einfache Prefetching bleibt verfügbar.
- Wild IP App: Unterstützung für Hex-Strings bei IPv4 hinzugefügt. Danke an Marty Cannon (@swimlane-marty) für den PR #2056.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 15.4
Veröffentlicht: 11. Juli 2026

- Fehler beim Binden von UDP-Sockets behoben, der in einigen Einsatzszenarien zu falsch gerouteten Antworten führte.
- Probleme mit RFC-Konformitätsprüfungen behoben, die in einigen Fällen die Auflösung und Zonentransfers störten.
- Unterstützung für Unix Domain Sockets (UDS) für den Webdienst über HTTPS und für das optionale Protokoll DNS-over-HTTPS hinzugefügt.
- Weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 15.3
Veröffentlicht: 5. Juli 2026

- Mehrere RFC-Konformitätsprobleme behoben, gemeldet von Yuxiao Wu, Yunyi Zhang, Baojun Liu und Haixin Duan von der Tsinghua University.
- Von Lawrence LUO Junhua gemeldetes Problem in den Standardberechtigungen des Bereichs Apps behoben: Die Berechtigung `Delete` für die Gruppe `DNS Administrators` wurde entfernt. Sie konnte zur Rechteausweitung auf den Administrationsbereich des DNS-Servers missbraucht werden. Bei bestehenden Installationen wird empfohlen, diese Berechtigung für den Bereich Apps manuell zu entfernen.
- Problem in den Standardberechtigungen des Bereichs Einstellungen behoben: Die Berechtigung `Delete` für die Gruppe `DNS Administrators` wurde entfernt. Über Sicherung und Wiederherstellung von Konfigurationsdateien konnten sonst Optionen im Administrationsbereich geändert werden. Bei bestehenden Installationen wird empfohlen, diese Berechtigung für den Bereich Einstellungen manuell zu entfernen.
- Mehrere gespeicherte XSS-Schwachstellen in der Weboberfläche behoben, gemeldet von Daniel Goldberg und Anner Klein von Tenzai.
- Das automatische Linux-Installationsskript unterstützt jetzt Alpine Linux mit OpenRC-Dienst. Danke an @Wrong-Code für den PR #1889.
- Unterstützung für Unix Sockets für den Webdienst und das optionale Protokoll DNS-over-HTTP hinzugefügt. Danke an Ingmar Stein (@IngmarStein) für den PR #1753.
- Der Bereich Zonen unterstützt jetzt Suche und Filter sowie das gleichzeitige Löschen mehrerer Zonen.
- Im Benutzermenü gibt es eine Option zum Deaktivieren der Update-Benachrichtigung. Sie verhindert die Update-Prüfung der Weboberfläche nur für den aktuellen Benutzer und wird im lokalen Speicher des Browsers abgelegt.
- Option „Update-Prüfung aktivieren“ unter Einstellungen > Allgemein hinzugefügt. Damit prüft der DNS-Server beim Aufruf der Update-API, die meist nach der Anmeldung an der Weboberfläche erfolgt, ob ein Update verfügbar ist. Ist die Option deaktiviert, meldet die API für alle Benutzer ohne Prüfung, dass kein Update verfügbar ist.
- Option „CSP-Frame-Ancestors-Header“ unter Einstellungen > Webdienst hinzugefügt, um den Wert des Content-Security-Policy-Headers Frame Ancestors festzulegen.
- Option „Weiterleitung zur Hilfeseite aktivieren“ unter Einstellungen > Optionale Protokolle hinzugefügt. Sie steuert, ob beim Aufruf des DoH-Endpunkts `/dns-query` im Browser die DoH-Hilfeseite angezeigt wird.
- Option „Kein Stack-Trace“ unter Einstellungen > Protokollierung hinzugefügt, um nur kurze Fehlermeldungen statt des vollständigen Stack-Traces zu protokollieren.
- SSO-Implementierung aktualisiert, um für unterstützte Claim-Typen eine JSON-Schlüsselzuordnung für den User-Info-Endpunkt einzurichten.
- Unterstützung für lokal bereitgestellte DNS-Zonen (RFC 6303) und Domainnamen für besondere Zwecke (RFC 6761) umgesetzt. Die bisherigen `internal`-Zonen wurden entfernt und werden jetzt über diese neue Implementierung verwaltet. Unter Einstellungen > Rekursion gibt es die neue Option „Lokal bereitgestellte DNS-Zonen“, um diese Zonen vollständig zu deaktivieren. Eine einzelne Zone lässt sich deaktivieren oder überschreiben, indem eine Stub- oder Conditional-Forwarder-Zone dafür angelegt wird.
- TXT-Einträge unterstützen jetzt generische Zeichenketten und damit auch Unicode.
- Fehler in der DNSSEC-Validierung behoben, der in bestimmten Fällen bei Verwendung von Forwardern zum Validierungsfehler „missing RRSIG“ führte.
- Neue Health-Check-API `/api/dnsClient/healthCheck` hinzugefügt, mit der der DNS-Server automatisiert geprüft werden kann, ohne Einträge im Query-Log zu erzeugen.
- Neue Status-API `/api/status` hinzugefügt. Sie ersetzt die SSO-Status-API `/api/sso/status`.
- Die API `/api/zones/list` kann Zonen jetzt nach Name und Typ filtern.
- Block Page App: Die App unterstützt jetzt Online-Signierung mit einem in der App-Konfiguration hinterlegten eigenen CA-Zertifikat, sowohl mit RSA als auch mit ECDSA. Danke an Roy Hagland (@Hemsby) für den PR #1897.
- Geo Continent App und Geo Country App: Beide Apps unterstützen eigene Gruppen in der App-Konfiguration, die in der JSON-Konfiguration von APP-Einträgen verwendet werden können.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 15.2
Veröffentlicht: 9. Mai 2026

- SSO-Implementierung aktualisiert: Claims werden, falls verfügbar, vom User-Info-Endpunkt gelesen, und `HttpClientNetworkHandler` wird als Backchannel verwendet.
- Neue Option „Reverse-Proxy-Adressen des Webdienstes“ hinzugefügt, mit der erlaubte Reverse-Proxys festgelegt werden. Der Real-IP-Header wird nur noch für diese Proxys ausgewertet.
- In der Einstellungs-API wurde die Option `reverseProxyNetworkACL` in `dnsReverseProxyNetworkACL` umbenannt, da sie nur für die optionalen DNS-Protokolle gilt.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 15.1
Veröffentlicht: 3. Mai 2026

- Option hinzugefügt, um SSO-Scopes nach den Anforderungen des SSO-Anbieters zu konfigurieren.
- Die Textausgabe der Prometheus-Metrik-API verwendet jetzt die korrekte Namenskonvention.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 15.0.1
Veröffentlicht: 26. April 2026

- Fehler behoben, durch den das Cluster-API-Token beim Beitritt eines sekundären Knotens nicht synchronisiert wurde.
- Falscher Synchronisationsstatus der SSO-Gruppenzuordnung auf sekundären Knoten behoben.
- Von einigen SSO-Anbietern benötigte SSO-Scopes hinzugefügt.
- Tippfehler in der Textausgabe der Prometheus-Metrik-API behoben.

## Version 15.0
Veröffentlicht: 25. April 2026

- Codebasis auf die .NET-10-Laufzeit umgestellt. Wer den DNS-Server oder die .NET-Laufzeit bisher manuell installiert hat, muss vor dem Upgrade die .NET-10-Laufzeit manuell installieren.
- Das Linux-Installationsskript installiert den DNS-Server jetzt als systemd-Dienst ohne Root-Rechte. Bestehende Installationen funktionieren nach dem Upgrade unverändert. Um die neue Installationsart zu nutzen, wird empfohlen, vor dem Installationsskript das Deinstallationsskript auszuführen. Hinweis: Vor dem Upgrade sollte im Bereich Einstellungen eine Sicherung der Konfiguration als ZIP-Datei exportiert werden.
- Der Windows-Installer installiert den DNS-Server jetzt als Dienst ohne Systemrechte. Bestehende Installationen funktionieren nach dem Upgrade unverändert. Um die neue Installationsart zu nutzen, wird empfohlen, den DNS-Server zu deinstallieren und den Ordner „config“ im Installationsordner zu löschen, bevor der neue Installer ausgeführt wird. Achtung: Vorher muss im Bereich Einstellungen eine Sicherung der Konfiguration als ZIP-Datei exportiert und nach der Neuinstallation wiederhergestellt werden.
- Die HTTP-API akzeptiert das Sitzungstoken jetzt im HTTP-Header `Authorization: Bearer <token>`. Der ältere Parameter `token` in Query-String und Formulardaten wird aus Kompatibilitätsgründen weiter unterstützt.
- Wer einen DNS-Server-Cluster betreibt, muss wegen einiger inkompatibler Änderungen alle Knoten aktualisieren.
- Unterstützung für Single Sign-On (SSO) mit OpenID Connect (OIDC) hinzugefügt. Danke an Zach Stinnett (@zstinnett) für den PR #1678.
- Neue Funktion „EDNS-Client-Subnet-Quelladresse“: Die Quell-IP-Adresse des Clients wird aus der EDNS-Client-Subnet-Option (ECS) von DNS-Anfragen über DNS-over-UDP und DNS-over-TCP gelesen. So kann ein DNS-Proxy die Quell-IP-Adresse des Clients per ECS an den DNS-Server weitergeben.
- Neue Option beim Zonenimport, mit der die gesamte Zone überschrieben wird, sodass nach dem Import nur noch die importierten Einträge (und der SOA-Eintrag der Zone) vorhanden sind.
- Option hinzugefügt, um den Status des Key Signing Key (KSK) einer Primary-Zone manuell zu aktivieren, damit der DNS-Server nicht regelmäßig nach DS-Einträgen in der übergeordneten Zone sucht.
- Neue Option unter Einstellungen > Allgemein, um die Sende- und Empfangspuffergröße der UDP-Listener-Sockets festzulegen.
- Unterstützung für Prometheus mit einem neuen Metrik-API-Aufruf hinzugefügt, der Zähler über die gesamte Laufzeit liefert.
- UDP-Listener werden bei der ersten Anfrage an eine ANY-Adresse dynamisch an die lokale IP-Adresse der Schnittstelle gebunden. Dadurch wird die Antwort über die Schnittstelle gesendet, auf der die Anfrage einging.
- Die DNS-Eintragsverwaltung des DHCP-Servers erlaubt jetzt dauerhafte DNS-Einträge für reservierte Leases mit Hostname, auch wenn der reservierte Lease nicht vergeben wurde.
- Neue Option „IPv6-Modus“ für bessere Performance in Dual-Stack-Netzen umgesetzt.
- Unterstützung für die EDNS-Option EXPIRE (RFC 7314) umgesetzt.
- Fehler im optionalen Protokoll DNS-over-QUIC (DoQ) behoben, durch den der DoQ-Dienst keine neuen Verbindungen mehr annahm.
- Von Shuhan Zhang, Dan Li und Baojun Liu (Tsinghua University) gemeldete DNS-Amplification-Schwachstelle durch selbstreferenzierende Glue-Einträge behoben.
- Von Shuhan Zhang, Dan Li und Baojun Liu (Tsinghua University) gemeldete DNS-Amplification-Schwachstelle durch aggressives Abrufen von DNSSEC-Einträgen behoben.
- Von Qifan Zhang (Palo Alto Networks) gemeldete DNS-Amplification-Schwachstelle durch zyklische Nameserver-Delegation behoben.
- Neues Menü zum Wechseln des Designs mit automatischem Dunkel-/Hellmodus nach dem Design des Systems umgesetzt.
- Neues Design „Amber“ für bessere visuelle Ergonomie und Barrierefreiheit hinzugefügt. Danke an DaeDae (@daedaevibin) für den PR #1810.
- Der Bereich Logs > Query-Logs unterstützt jetzt eine Live-Aktualisierung der Ergebnisse.
- Im Dashboard lässt sich das Blockieren jetzt direkt bei den am häufigsten blockierten Domains aktivieren oder deaktivieren.
- Query Logs (PostgreSQL) App: Neue App, die PostgreSQL als Datenbank für Query-Logs unterstützt. Danke an Chloe Surett (@scj643) für den PR #1600.
- Query Logs (Sqlite) App: Die Seitenaufteilung wurde überarbeitet und die Abfragen sind deutlich schneller. Danke an Jim Strang (@jimstrang) für den PR #1702.
- Query Logs (MySQL) App: Die Seitenaufteilung wurde überarbeitet und die Abfragen sind deutlich schneller. Danke an Jim Strang (@jimstrang) für den PR #1702.
- Query Logs (SQL Server) App: Die Seitenaufteilung wurde überarbeitet und die Abfragen sind deutlich schneller. Danke an Jim Strang (@jimstrang) für den PR #1702.
- Block Page App: Online-Signierung von SSL-Zertifikaten umgesetzt, sodass die App SSL-MiTM durchführen kann, wenn ihr selbstsigniertes Stammzertifikat auf den Clients installiert ist.
- Wild IP App: Neue Option `allowedNetworks` in der Datenkonfiguration von APP-Einträgen, um erlaubte Netze festzulegen und Missbrauch zu verhindern.
- Drop Requests App: Neue Option `allowedLocalEndPoints`, die nur Anfragen über die aufgeführten lokalen Endpunkte des DNS-Servers zulässt und Anfragen über alle anderen lokalen Endpunkte verwirft.
- Geo Continent App: Unterstützung für Einträge nach Autonomous System Number (ASN) in den Daten von APP-Einträgen.
- Geo Country App: Unterstützung für Einträge nach Autonomous System Number (ASN) in den Daten von APP-Einträgen.
- MISP Connector App: Die App wurde entfernt, da ihre Pflege nicht tragbar ist.
- Alle DNS-Apps unterstützen jetzt Kommentare in ihrer JSON-Konfiguration. Auch die JSON-Daten von APP-Einträgen dürfen Kommentare enthalten.
- Alle DNS-Apps enthalten jetzt eine Read-Me-Datei im MD-Format. Danke an Zafer Balkan (@zbalkan) für den PR #1704.
- Neuinstallationen verwenden jetzt einen plattformspezifischen Log-Ordner.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 14.3
Veröffentlicht: 20. Dezember 2025

- Unterstützung für den Dunkelmodus hinzugefügt. Danke an @skidoodle für den PR.
- Catalog-Zonen erlauben jetzt Secondary-Zonen als Mitglieder.
- Beim Wiederherstellen von Einstellungen können jetzt auch Sicherungen älterer DNS-Server-Versionen importiert werden.
- Neue Einstellungen für die Standard-TTL von NS- und SOA-Einträgen hinzugefügt.
- Neue Option in DHCP-Bereichen, mit der dynamische Leases einen vorhandenen DNS-A-Eintrag für den Domainnamen des Clients überschreiben dürfen.
- Advanced Blocking App: Neue Option, um das Aktualisierungsintervall der Blocklisten in Minuten festzulegen.
- Split Horizon App: Domainnamen können für die Adressübersetzung jetzt Gruppen zugeordnet werden.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 14.2
Veröffentlicht: 22. November 2025

- Fehler im Clustering behoben, der die gemeinsame Verwendung von IPv4- und IPv6-Adressen verhinderte. Danke an @ruifung für den PR.
- Das Clustering enthält außerdem eine inkompatible Änderung, daher müssen alle Clusterknoten auf diese Version aktualisiert werden.
- Die Option „Allow-/Block-Listen-URLs“ unterstützt jetzt Kommentarzeilen.
- Advanced Blocking App: Neue Option `blockingAnswerTtl`, mit der die TTL in blockierten Antworten festgelegt wird.
- Log Exporter App: Unterstützung für die Protokollierung von EDNS hinzugefügt. Danke an @zbalkan für den PR.
- MISP Connector App: Neue App, die aus MISP-Feeds bezogene schädliche Domainnamen blockiert. Danke an @zbalkan für den PR.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 14.1
Veröffentlicht: 16. November 2025

- Clustering erlaubt jetzt mehrere eigene IP-Adressen. Dadurch ändert sich die API inkompatibel, und alle Clusterknoten müssen auf diese Version aktualisiert werden, damit sie zusammenarbeiten.
- Probleme bei der Prüfung von Benutzer- und Gruppenberechtigungen mit aktiviertem Clustering behoben, die beim Zugriff auf einen anderen Knoten eine Umgehung der Berechtigungen ermöglichten.
- Fehler behoben, durch den die Advanced Blocking App nicht mehr funktionierte.
- Umgebungsvariablen für TLS-Zertifikatspfad, Zertifikatspasswort und die Weiterleitung von HTTP auf HTTPS hinzugefügt. Danke an @simonvandermeer für den PR.
- URLs der Hagezi-Blocklisten aktualisiert. Danke an @hagezi für den PR.
- Weitere kleinere Änderungen und Verbesserungen.

## Version 14.0.1
Veröffentlicht: 9. November 2025

- Fehler in den API-Aufrufen „Blocklisten-Update erzwingen“ und „Blockieren vorübergehend deaktivieren“ behoben.
- Umgehung der Sitzungsprüfung beim Weiterleiten von Anfragen an einen anderen Knoten mit aktiviertem Clustering behoben.
- Fehler beim Laden von App-Konfigurationen aufgrund von Zeichenkodierungsproblemen behoben.
- Fehler behoben, durch den ältere Versionen von Konfigurationsdateien in einigen Fällen wegen Validierungsfehlern nicht geladen wurden.
- Dokumentation der Weboberfläche zum Initialisieren eines Clusters und zum Beitritt aktualisiert.
- Weitere kleinere Änderungen und Verbesserungen.

## Version 14.0
Veröffentlicht: 8. November 2025

- Codebasis auf die .NET-9-Laufzeit umgestellt. Wer den DNS-Server oder die .NET-8-Laufzeit bisher manuell installiert hat, muss vor dem Upgrade die .NET-9-Laufzeit manuell installieren.
- Diese Hauptversion enthält inkompatible Änderungen an der HTTP-API zum Ändern des Passworts. Eigene API-Clients sollten vor dem produktiven Einsatz getestet werden.
- Denial-of-Service-Schwachstelle (DoS) in der Ratenbegrenzung behoben, gemeldet von Shiming Liu vom Network and Information Security Lab der Tsinghua University. Die Ratenbegrenzung wurde neu entworfen und bietet in den Einstellungen verschiedene Optionen für Anfragen pro Minute (QPM), die das Problem entschärfen.
- Cache-Poisoning-Schwachstelle über einen IP-Fragmentierungsangriff behoben, gemeldet von Yuxiao Wu vom NISL Lab Security der Tsinghua University. Dazu wurden fehlende Bailiwick-Prüfungen für NS-Einträge in Referral-Antworten ergänzt.
- [DNSSEC-Downgrade](https://dnssec-downgrade.net/)-Schwachstelle behoben, über die die Validierung umgangen werden konnte, wenn einer der DNSSEC-Algorithmen einer Domain vom DNS-Server nicht unterstützt wurde.
- Clustering umgesetzt: Zwei oder mehr DNS-Server-Instanzen lassen sich zu einem Cluster zusammenschließen und über die Weboberfläche eines beliebigen Knotens gemeinsam verwalten. Das Dashboard zeigt dabei zusammengefasste Daten des gesamten Clusters.
- Unterstützung für Zwei-Faktor-Authentifizierung (2FA) per TOTP hinzugefügt.
- Optionen zur Konfiguration des UDP-Socket-Poolings in den Einstellungen hinzugefügt.
- Fehler beim Einlesen von Zonendateien behoben, durch den Einträge nicht gelesen wurden, deren Name kein FQDN war und einem Eintragstyp entsprach.
- Der interne HTTP-Client versucht es jetzt auch über IPv4, wenn „IPv6 bevorzugen“ aktiviert ist und die Verbindung über IPv6 fehlschlägt.
- Fehlende NSEC-/NSEC3-Einträge in Antworten für Wildcard- und Empty-Non-Terminal-Einträge (ENT) in Primary-Zonen ergänzt.
- Mehrere Probleme in Prefetch und Auto-Prefetch behoben, die in bestimmten Fällen zu unerwünscht häufigen Aktualisierungen zwischengespeicherter Daten führten.
- Query Logs (Sqlite) App: Verwendet jetzt Channels für bessere Performance.
- Query Logs (MySQL) App: Verwendet jetzt Channels für bessere Performance. Überlauf durch einen Fehler im Schema für den Protokollparameter behoben.
- Query Logs (SQL Server) App: Verwendet jetzt Channels für bessere Performance.
- NX Domain App: Unterstützung für Extended-DNS-Error-Meldungen hinzugefügt.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 13.6
Veröffentlicht: 26. April 2025

- Beim Anlegen einer Primary- oder Forwarder-Zone kann jetzt eine Zonendatei importiert werden. So lassen sich Vorlagen für neue Zonen verwenden.
- Die Weboberfläche unterstützt eigene Listen für die Serverliste des DNS-Clients, die Schnellauswahl zum Blockieren und die Schnellauswahl für Forwarder. Die Anleitung dazu steht in der Datei `www/json/readme.txt` im Installationsordner.
- Der Eintragsfilter in der Zonenansicht unterstützt jetzt Suchen mit Platzhaltern.
- Fehler im DNS-over-QUIC-Dienst behoben, durch den der Dienst nach fehlgeschlagenen Verbindungsaufbauten nicht mehr funktionierte.
- Query Logs (Sqlite) App: Unterstützt jetzt VACUUM, um die Datenbankdatei auf der Festplatte zu verkleinern.
- Geo Continent App und Geo Country App: Beide Apps unterstützen Makrovariablen, um die JSON-Konfiguration von APP-Einträgen zu vereinfachen.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 13.5
Veröffentlicht: 6. April 2025

- [RFC 8080](https://datatracker.ietf.org/doc/rfc8080/) umgesetzt: Die DNSSEC-Algorithmen Ed25519 (15) und Ed448 (16) werden jetzt zum Signieren und Validieren unterstützt.
- Unterstützung für selbst angegebene private DNSSEC-Schlüssel hinzugefügt. Beim Signieren einer Zone oder bei einem Schlüsselwechsel kann ein privater Schlüssel im PEM-Format angegeben werden.
- Im Zoneneditor lassen sich Einträge jetzt nach Name oder Typ filtern, um in großen Zonen leichter zu suchen.
- DNS-Logs können zusätzlich zur Datei auch auf die Konsole (STDOUT) geschrieben werden.
- Beim Zonenimport kann jetzt direkt eine Datei importiert werden, zusätzlich zur Eingabe im Texteditor.
- Der Parser für Zonendateien unterstützt jetzt das erweiterte Zonendateiformat von BIND.
- Die Query-Log-Ansicht färbt Einträge je nach Art des Logeintrags ein.
- [draft-fujiwara-dnsop-resolver-update](https://datatracker.ietf.org/doc/draft-fujiwara-dnsop-resolver-update/) umgesetzt: NS-Einträge der übergeordneten Zone und autoritative NS-Einträge der untergeordneten Zone werden im Cache getrennt gespeichert.
- Die Funktion [NS Revalidation (draft-ietf-dnsop-ns-revalidation)](https://datatracker.ietf.org/doc/draft-ietf-dnsop-ns-revalidation/) wurde entfernt. Sie erhöhte die Komplexität und die Zahl der Anfragen an Nameserver und damit die Last auf dem Resolver. Außerdem ließen sich damit einige Domains nicht mehr auflösen, wenn sich die NS-Einträge der untergeordneten Zone von denen der übergeordneten unterschieden. Einen Nutzen für Betreiber brachte sie nicht, wohl aber Betriebsprobleme. Die Hintergründe stehen in [dieser Diskussion](https://mailarchive.ietf.org/arch/msg/dnsop/s8KBhilK4bCrmSBRMyKaxll02lk/).
- Schnittstelle `IDnsApplicationPreference` hinzugefügt, damit Apps nach einem vom Benutzer festgelegten Präferenzwert sortiert werden können.
- Advanced Forwarding App, DNS64 App, NXDOMAIN App, Split Horizon App und Zone Alias App: Neue Option `appPreference` in der Konfiguration für die App-Präferenz.
- Log Exporter App: HTTP-Header können ohne Validierung konfiguriert werden, um auch nicht standardkonforme Werte zu setzen.
- Die Weboberfläche verwendet relative Pfade und funktioniert damit hinter einem Reverse Proxy unter beliebigen URL-Pfaden.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 13.4.3
Veröffentlicht: 23. Februar 2025

- Hoher Speicherverbrauch bei der Option „Letztes Jahr“ im Dashboard behoben.
- Mehrere DNSSEC-Validierungsfehler für bestimmte Domains bei Verwendung von Forwardern behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 13.4.2
Veröffentlicht: 15. Februar 2025

- In einem bestimmten Fall wurde das CD-Flag nicht behandelt, wenn in der Anfrage das DO-Flag nicht gesetzt war. Behoben.
- Block Page App: Problem mit lokalen Kestrel-Adressen behoben, das auf Linux-Systemen das Binden verhinderte.
- Query Logs (MySQL) App: Verwendet jetzt den Treiber MySqlConnector und funktioniert damit auch mit MariaDB.
- Query Logs (SQL Server) App: Problem beim Masseneinfügen durch das Parameterlimit pro Abfrage und Problem beim Filtern nach Anfragetyp behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 13.4.1
Veröffentlicht: 2. Februar 2025

- Das CD-Flag wurde nicht behandelt, wenn in der Anfrage das DO-Flag nicht gesetzt war. Behoben.
- Block Page App: Die Blockierseite zeigt jetzt Details zur Blockierung an.
- Query Logs (MySQL) App: Die Server-Domain wird mitprotokolliert, sodass mehrere Instanzen dieselbe Datenbank nutzen können.
- Query Logs (SQL Server) App: Die Server-Domain wird mitprotokolliert, sodass mehrere Instanzen dieselbe Datenbank nutzen können.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 13.4
Veröffentlicht: 26. Januar 2025

- Gefälschte DNS-Antworten über UDP werden erkannt, woraufhin auf TCP gewechselt wird, um Cache-Poisoning-Versuche abzuwehren. Das schützt vor dem RebirthDay-Angriff [CVE-2024-56089], gemeldet von Xiang Li, AOSP Lab der Nankai University.
- Minutenstatistiken können jetzt für einen frei wählbaren Zeitraum (maximal 2 Stunden) abgerufen werden.
- HTTP-API und Option in der Weboberfläche zum Export der Query-Logs als CSV-Datei hinzugefügt.
- Drop Requests App: Fehler behoben, durch den bei einem unbekannten Eintragstyp alle Anfragen erfasst wurden.
- Log Exporter App: Neue App zum Export von Query-Logs in Dateien, per HTTP und an Syslog. Die App wurde von [Zafer Balkan](https://github.com/zbalkan) entworfen und umgesetzt.
- Query Logs (SQL Server) App: Neue App, die Query-Logs in Microsoft SQL Server speichert.
- Query Logs (MySQL) App: Neue App, die Query-Logs in einem MySQL-Datenbankserver speichert.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 13.3
Veröffentlicht: 21. Dezember 2024

- Warteschlange für den Resolver umgesetzt, um Zeitüberschreitungen bei großen Installationen mit sehr vielen gleichzeitigen ausgehenden Auflösungen zu vermeiden. Unter Einstellungen > Allgemein legt die neue Option „Maximale gleichzeitige Auflösungen“ fest, wie viele asynchrone Auflösungen pro CPU-Kern gleichzeitig laufen.
- Neue Optionen „Minimaler SOA-Refresh“ und „Minimaler SOA-Retry“ unter Einstellungen > Allgemein. Sie überschreiben kleinere SOA-Werte von Secondary-, Stub-, Secondary-Forwarder- und Secondary-Catalog-Zonen.
- Das selbstsignierte Zertifikat enthält jetzt Subject-Alternative-Name-Einträge (SAN) für die lokalen Unicast-Adressen des Webdienstes.
- Fehler in der Erzeugung von NSEC3-Nichtexistenzbeweisen behoben, der alle DNS-Protokolldienste lahmlegte (DoS), wenn bestimmte Primary- und Secondary-Zonen mit NSEC3 signiert waren.
- Unbehandelte Ausnahme behoben, die den DNS-over-QUIC-Dienst lahmlegte (DoS) [CVE-2024-56946], gemeldet von Michael Wedl, Fachhochschule St. Pölten.
- Fehler beim Neuladen des SSL/TLS-Zertifikats für den Webdienst und den DNS-over-HTTPS-Dienst behoben.
- Problem mit der SOA-Anfrage für Catalog-Zonen behoben, durch das Zonentransfers mit BIND fehlschlugen.
- Query Logs (Sqlite) App: Die Antwortzeit (RTT) wird jetzt mitprotokolliert.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 13.2.2
Veröffentlicht: 2. Dezember 2024

- Fehler behoben, durch den DNS-Antworten gefälschte Einträge enthielten, obwohl in der Anfrage Checking Disabled (CD) nicht gesetzt war.

## Version 13.2.1
Veröffentlicht: 30. November 2024

- Der DNS-over-HTTPS-Dienst liest jetzt den X-Real-IP-Header von Reverse-Proxys, die in der ACL erlaubt sind.
- Problem mit HTTP/2 auf Windows-Versionen vor Windows 10 behoben, durch das HTTPS für den Webdienst und den DNS-over-HTTPS-Dienst nicht aktiviert werden konnte.
- Problem bei der Behandlung abgebrochener Verbindungen in DNS-over-QUIC behoben.
- Problem mit einer Wildcard-Anfrage für ENT-Subdomains in lokalen Zonen behoben.
- Problem beim Forwarding behoben, durch das ein CNAME nicht separat aufgelöst wurde, wenn der Upstream-Server einen SOA-Eintrag im Authority-Abschnitt lieferte.
- Problem beim Laden von DNS-App-Assemblys behoben, durch das in einigen Fällen Abhängigkeiten nicht geladen wurden.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 13.2
Veröffentlicht: 16. November 2024

- Neue Einstellung für eine Netzwerk-ACL für Reverse Proxys, die mit den optionalen Protokollen DNS-over-UDP-PROXY, DNS-over-TCP-PROXY und DNS-over-HTTP verwendet wird.
- Fehler im DNS-over-QUIC-Client behoben, durch den das Forwarding in einigen Fällen nach einiger Zeit mit einer Zeitüberschreitung ausfiel.

## Version 13.1.1
Veröffentlicht: 9. November 2024

- Fehler behoben, durch den HTTP/3 weder für den Webdienst noch für DNS-over-HTTPS/3 funktionierte. Ursache war eine geänderte Verwendung der Anwendungsprotokoll-Option im Kestrel-Webserver.
- Der DNS-over-HTTPS-Client unterstützt mit dem Schema `https` jetzt HTTP/2 und HTTP/1.1 und mit dem Schema `h3` ausschließlich HTTP/3 ohne Rückfall auf andere Protokolle.
- Problem im DNS-over-TCP- und DNS-over-TLS-Client behoben, das auf Plattformen ohne Unterstützung für TCP-Keepalive-Socket-Optionen auftrat.
- Der rekursive Resolver versucht jetzt immer, AAAA für Nameserver ohne IPv6-Glue-Eintrag aufzulösen, damit die Auflösung auch in reinen IPv6-Netzen funktioniert.
- Filter AAAA App: Neue Option für die Standard-TTL.
- DNS Rebinding Protection App: Neue Option für Netze, die von der Prüfung ausgenommen sind.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 13.1
Veröffentlicht: 19. Oktober 2024

- Eine Secondary-Root-Zone kann jetzt direkt hinzugefügt werden.
- Neue Notify-Option für Catalog-Zonen, um eigene Nameserver nur für Aktualisierungen der Catalog-Zone anzugeben.
- Option für die TTL blockierter Antworten in den Einstellungen hinzugefügt.
- Der Header `X-Real-IP` lässt sich für den Webdienst und das optionale Protokoll DNS-over-HTTP anpassen.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.
- Filter AAAA App: Die zu filternden Domainnamen lassen sich jetzt explizit angeben.

## Version 13.0.2
Veröffentlicht: 28. September 2024

- Problem mit DNS-over-TLS und DNS-over-TCP behoben, durch das die zugrunde liegende Verbindung geschlossen wurde, wenn die ursprüngliche Anfrage abgebrochen wurde.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 13.0.1
Veröffentlicht: 23. September 2024

- Problem bei der Verwendung eines Proxys mit Forwardern behoben, durch das DNS-over-TOR mit dem Hidden Service von Cloudflare nicht funktionierte.

## Version 13.0
Veröffentlicht: 22. September 2024

- Catalog-Zonen nach [RFC 9432](https://datatracker.ietf.org/doc/rfc9432/) umgesetzt, um DNS-Zonen automatisch auf einem oder mehreren Secondary-Nameservern bereitzustellen. Unterstützt werden Primary-, Stub- und Conditional-Forwarder-Zonen mit automatischer Bereitstellung der jeweiligen Secondary-Zonen.
- Neue Zonenart Secondary Forwarder, um Secondaries für Conditional-Forwarder-Zonen einzurichten. Conditional-Forwarder-Zonen unterstützen dafür Zonentransfer und Notify und enthalten jetzt einen Platzhalter-SOA-Eintrag.
- Neue Funktion „Abfragezugriff“, um den Zugriff für jede Zone einzeln festzulegen. So lassen sich Anfragen auf Clients aus bestimmten Netzen beschränken, auch wenn der DNS-Server öffentlich erreichbar ist.
- Für Einträge in Zonen kann eine Ablauf-TTL angegeben werden, nach der der DNS-Server die Einträge automatisch löscht.
- Der rekursive Resolver unterstützt Parallelität und fragt mehrere Nameserver gleichzeitig ab, um die Auflösung zu beschleunigen.
- Latenzbasierte Auswahl der Nameserver hinzugefügt, die zusammen mit der Parallelität für rekursive Auflösung und Forwarder die Auflösung deutlich beschleunigt.
- Prioritäten für FWD-Einträge in Conditional-Forwarder-Zonen umgesetzt. So lassen sich einzelne Forwarder bevorzugen und bei Bedarf ein niedrig priorisierter FWD-Eintrag „This Server“ für die rekursive Auflösung verwenden.
- ZONEMD-Validierung nach [RFC 8976](https://datatracker.ietf.org/doc/rfc8976/) für Secondary-Zonen umgesetzt, gedacht für eine lokale Secondary-Root-Zone. Damit wird die vollständige Zone nach jedem Zonentransfer geprüft.
- Unterstützung für den Eintragstyp Responsible Person (RP) nach [RFC 1183](https://www.rfc-editor.org/rfc/rfc1183) hinzugefügt.
- Option zum Aktivieren oder Deaktivieren des parallelen Forwardings hinzugefügt, um auch sequenzielles Forwarding zu ermöglichen.
- Der DNS-Server unterstützt Netzwerk-Zugriffslisten (ACL) für Rekursion, Zonentransfer und dynamische Updates in der Weboberfläche und der HTTP-API.
- Die Behandlung nicht unterstützter NSEC3-Iterationswerte wurde geändert, weil die bisherige Umsetzung in einigen Fällen die Validierung fehlschlagen ließ.
- Der Schutz des Webdienstes vor Brute-Force-Angriffen wurde für IPv6-Netze verbessert.
- Ereignisse der Ratenbegrenzung pro Client-Subnetz werden jetzt ins Log geschrieben.
- Diese Hauptversion enthält inkompatible Änderungen an den HTTP-API-Aufrufen für SOA-Einträge und Zonenoptionen. Einige Optionen des SOA-Eintrags wurden in API und Weboberfläche zu den Zonenoptionen verschoben. Auch die DNS-Client-Bibliothek enthält einige inkompatible Änderungen, daher sollten eigene DNS-Apps vor dem Upgrade getestet werden.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 12.2.1
Veröffentlicht: 15. Juni 2024

- Problem im DHCP-Server behoben, durch das wegen abweichender Hashcodes keine Leases vergeben wurden.
- Problem behoben, durch das nach dem Löschen einer Zone leere Zonendateien entstehen konnten.

## Version 12.2
Veröffentlicht: 15. Juni 2024

- Unterstützung für den Eintragstyp NAPTR hinzugefügt.
- Neue Einstellung „Standard-Verantwortlicher“ für neu angelegte Primary-Zonen.
- Serve Stale wurde überarbeitet: Antwort-TTL, Reset-TTL und maximale Wartezeit lassen sich in den Einstellungen festlegen.
- SVCB-/HTTPS-Einträge unterstützen jetzt automatische IP-Adresshinweise.
- TXT-Einträge behalten jetzt die einzelnen Zeichenketten bei, wie für [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763) nötig.
- Die Systemtray-App unter Windows hat einen neuen Kontextmenüeintrag, um automatische Firewall-Regeln zu konfigurieren.
- Problem mit NSEC-Beweisen für Wildcard-ENT-Fälle behoben.
- Problem in der QNAME-Minimierung behoben, das bei einer nicht unterstützten NSEC3-Iterationszahl während der Auflösung auftrat.
- Neben der Dateiendung .pfx wird jetzt auch .p12 für Zertifikate unterstützt.
- Filter AAAA App: Neue App, die AAAA-Einträge herausfiltert und NO DATA liefert, wenn für denselben Domainnamen A-Einträge vorhanden sind. So nutzen Clients mit Dual-Stack-Anschluss für Webseiten bevorzugt IPv4 und IPv6 nur dann, wenn eine Seite kein IPv4 anbietet.
- Query Logs (Sqlite) App: Problem behoben, durch das die App unter Alpine Linux nicht geladen wurde.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 12.1
Veröffentlicht: 16. März 2024

- [Key-Trap](https://www.athene-center.de/en/keytrap)-[Schwachstelle](https://www.athene-center.de/fileadmin/content/PDF/Technical_Report_KeyTrap.pdf) [CVE-2023-50387] in der DNSSEC-Validierung behoben, die per DoS die Namensauflösung des DNS-Servers beeinträchtigen konnte. Mit den Gegenmaßnahmen arbeitet der DNS-Server auch bei hoher CPU-Last weiter.
  - Es sind höchstens 4 DNSKEY-Einträge mit kollidierendem Key-Tag erlaubt.
  - Kryptografische Fehlschläge sind auf höchstens 16 begrenzt.
  - Mehr als 8 RRSIG-Validierungen pro Antwort unterbrechen den Task. Nach höchstens 16 Unterbrechungen wird die Validierung der Antwort abgebrochen.
- Schwachstelle im NSEC3-Closest-Encloser-Beweis [CVE-2023-50868] in der DNSSEC-Validierung behoben, die per DoS die Namensauflösung beeinträchtigen konnte. Mit den Gegenmaßnahmen arbeitet der DNS-Server auch bei hoher CPU-Last weiter.
  - Mehr als 8 NSEC3-Hashberechnungen pro Antwort unterbrechen den Task.
  - Nach 16 Unterbrechungen wird die Validierung der Antwort abgebrochen.
- Schwachstelle [Non-Responsive Delegation Attack](https://www.usenix.org/system/files/sec23fall-prepub-309-afek.pdf) (NRDelegation-Angriff) [CVE-2022-3204] behoben.
- Schwachstelle [NXNSAttack](https://arxiv.org/abs/2005.09107) [CVE-2020-12662] behoben.
- NSEC3-Iterationen sind auf 100 begrenzt. NSEC3 mit mehr als 100 Iterationen gilt als fehlender Beweis.
- Neue Funktion zum Überschreiben von EDNS Client Subnet (ECS): Der DNS-Server verwendet das angegebene Subnetz per ECS für alle ausgehenden Anfragen.
- In den Zonenoptionen von Secondary-Zonen lassen sich jetzt Berechtigungen für dynamische Updates festlegen.
- Beim Zonenimport kann die SOA-Seriennummer aus dem importierten SOA-Eintrag übernommen werden.
- Der DNS-Client unterstützt jetzt die Option EDNS Client Subnet (ECS), um ECS-Probleme einfach zu testen.
- Cache-Einträge zeigen jetzt Metadaten der Anfrage, etwa welcher Nameserver die Daten geliefert hat.
- DHCP-Bereiche können die Client-Identifier-Option in Anfragen ignorieren und Leases über die Hardwareadresse des Clients verwalten.
- Advanced Blocking App: Die Zuordnung lokaler Endpunkte zu Gruppen unterstützt jetzt Domainnamen und funktioniert damit auch mit Anfragen über DoT, DoH und DoQ.
- Advanced Forwarding App: Die AdGuard-Upstream-Implementierung unterstützt jetzt mehrere Forwarder.
- Geo Continent App: Unterstützt die MaxMind-ISP/ASN-Datenbank, um in Antworten ein passendes ECS-Scope-Präfix zu liefern.
- Geo Country App: Unterstützt die MaxMind-ISP/ASN-Datenbank, um in Antworten ein passendes ECS-Scope-Präfix zu liefern.
- Geo Distance App: Unterstützt die MaxMind-ISP/ASN-Datenbank, um in Antworten ein passendes ECS-Scope-Präfix zu liefern.
- Fehler beim Wildcard-Abgleich in autoritativen Zonen behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 12.0.1
Veröffentlicht: 8. Februar 2024

- Fehler beim Wildcard-Abgleich für Empty-Non-Terminal-Einträge (ENT) in autoritativen Zonen behoben.
- Weitere kleinere Probleme behoben.

## Version 12.0
Veröffentlicht: 4. Februar 2024

- Codebasis auf die .NET-8-Laufzeit umgestellt. Wer den DNS-Server oder die .NET-7-Laufzeit bisher manuell installiert hat, muss vor dem Upgrade die .NET-8-Laufzeit manuell installieren.
- Pulsing-DoS-Schwachstelle [CVE-2024-33655] behoben, gemeldet von Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/). Die Standardwerte des DNS-Servers wurden angepasst, um die Auswirkungen zu begrenzen.
- Das Dashboard und das Hauptdiagramm zeigen die Statistik „Verworfen“: die Zahl der Anfragen, die wegen Ratenbegrenzung oder durch die Drop Requests App verworfen wurden.
- Diagramm der Transportprotokolle im Dashboard hinzugefügt, das die Protokollstatistik der eingehenden Anfragen zeigt.
- Für ausgehende DNS-Anfragen lassen sich eine oder mehrere Quelladressen angeben, wenn der Server mit mehreren Netzen verbunden ist.
- IP-Adressen oder Netze, von denen Notify-Anfragen angenommen werden, lassen sich jetzt zentral festlegen, statt sie für jede Zone einzeln zu konfigurieren.
- Ausnahmeliste für die QPM-Ratenbegrenzung hinzugefügt, mit der IP-Adressen oder Netze von der Begrenzung ausgenommen werden.
- Statistiken können nur im Arbeitsspeicher gehalten werden. Dann zeigt das Dashboard nur die letzte Stunde, und es werden keine Statistikdaten auf die Festplatte geschrieben.
- DNS-over-HTTPS funktioniert mit HTTP/3 (URL mit dem Schema `h3`) jetzt auch über einen SOCKS5-Proxy.
- Die Liste der Root-Server wird automatisch per Priming-Anfragen nach [RFC 8109](https://datatracker.ietf.org/doc/rfc8109/) initialisiert.
- Conditional-Forwarder-Zonen unterstützen jetzt dynamische Updates nach [RFC 2136](https://datatracker.ietf.org/doc/rfc2136/).
- DNS Rebinding Protection App: Neue App, die anhand konfigurierter privater Domains und Netze vor DNS-Rebinding-Angriffen schützt.
- NX Domain Override App: Neue App, die NX-Domain-Antworten für konfigurierte Domainnamen durch eigene A-/AAAA-Antworten ersetzt.
- Block Page App: Verwendet jetzt den Kestrel-Webserver und erlaubt mehrere Webserver auf verschiedenen IP-Adressen.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 11.5.3
Veröffentlicht: 7. November 2023

- Fehler beim Wildcard-Abgleich in autoritativen Zonen behoben, der bei einigen Subdomain-Anfragen zu NXDOMAIN führte.

## Version 11.5.2
Veröffentlicht: 31. Oktober 2023

- Fehler bei den für dynamische Updates erlaubten IP-Adressen und Netzen einer Zone behoben, durch den die IP-Adresse der Anfrage nicht erkannt wurde.

## Version 11.5.1
Veröffentlicht: 30. Oktober 2023

- Fehler im Validierungscode der DNS-over-TLS-Bibliothek behoben, durch den das Protokoll nicht verwendet werden konnte.
- Advanced Blocking App: Kleineres Problem bei der Initialisierung behoben.

## Version 11.5
Veröffentlicht: 29. Oktober 2023

- Zonen können im Standard-Textformat nach RFC 1035 importiert und exportiert werden.
- Eine bestehende Zone lässt sich mit allen Einträgen und Zonenoptionen klonen.
- Neue DS-Info-Ansicht, die alle für die Aktualisierung der DS-Einträge einer signierten Primary-Zone nötigen Angaben an einer Stelle zeigt.
- Option für IP-Adressen und Netze, die für alle lokalen Zonen ohne TSIG-Authentifizierung Zonentransfers durchführen dürfen.
- Option für IP-Adressen und Netze, die von der Domain-Blockierung ausgenommen sind.
- HTTP/3 lässt sich für den Webdienst unabhängig konfigurieren.
- Resolver-Fehler können vom Log ausgenommen werden, um die Größe der Logdatei zu begrenzen.
- Zeitstempel der letzten Änderung einer Zone hinzugefügt.
- Vor dem Speichern geänderter lokaler Endpunkte des Webdienstes wird geprüft, ob sie gebunden werden können, damit man sich nicht aus der Weboberfläche aussperrt.
- Lässt sich ein neuer lokaler Endpunkt des Webdienstes nicht binden, wird der alte Endpunkt wiederhergestellt.
- Die Zonenoptionen für Nameserver bei Zonentransfers und für IP-Adressen bei dynamischen Updates akzeptieren jetzt auch Netzadressen.
- Conditional-Forwarder-Zonen können den in den Einstellungen konfigurierten Standard-Proxy umgehen.
- Neue Schnittstelle `IDnsRequestBlockingHandler`, mit der DNS-Apps Blockierungen im gleichen Umfang wie die eingebaute Blockierung des DNS-Servers umsetzen können.
- Advanced Blocking App: Setzt die neue Schnittstelle `IDnsRequestBlockingHandler` um. Die Gruppe lässt sich jetzt nach dem lokalen Endpunkt wählen, auf dem die Anfrage einging.
- Split Horizon App: Die Adressübersetzung von extern nach intern unterstützt jetzt auch Netzadressen.
- Default Records App: Neue App, die für konfigurierte lokale Zonen einen oder mehrere Standard-Einträge setzt.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 11.4.1
Veröffentlicht: 13. August 2023

- Problem behoben, durch das Sicherungen fehlschlugen.
- Kleineres Problem beim inkrementellen Zonentransfer behoben, durch das leere Knoten nicht aus Secondary-Zonen entfernt wurden.

## Version 11.4
Veröffentlicht: 12. August 2023

- Unterstützung für DNS über das [PROXY-Protokoll](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) in Version 1 und 2 für UDP und TCP hinzugefügt. So kann ein Load Balancer oder Reverse Proxy vor dem DNS-Server die IP-Adresse des Clients weitergeben. Damit lässt sich auch DNS-over-TLS über einen TLS-terminierenden Reverse Proxy anbieten, der Anfragen an den TCP-PROXY-Port weiterreicht.
- Beim TLS-Handshake wird jetzt immer die vollständige Zertifikatskette gesendet.
- Sicherung und Wiederherstellung schließen jetzt die Zertifikatsdateien für den Webdienst und die optionalen Protokolle ein, sofern sie im Konfigurationsordner liegen.
- Die Laufzeit des DNS-Servers wird im Bereich „Über“ angezeigt.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 11.3
Veröffentlicht: 2. Juli 2023

- Unterstützung für den Eintragstyp URI ([RFC 7553](https://www.rfc-editor.org/rfc/rfc7553.html)) hinzugefügt.
- Unterstützung für den Parameter `dohpath` beim Eintragstyp SVCB ([draft-ietf-add-svcb-dns](https://datatracker.ietf.org/doc/draft-ietf-add-svcb-dns/)) hinzugefügt.
- Generische Parameter für SVCB- und HTTPS-Einträge lassen sich in der Weboberfläche konfigurieren.
- Zonen können in einen anderen Zonentyp umgewandelt werden, etwa um eine Secondary-Zone zur Primary-Zone zu machen, wenn die bisherige Primary-Zone stillgelegt wird.
- Schlägt ein NOTIFY einer Primary-Zone fehl, wird es wiederholt, und die Weboberfläche zeigt den Fehlerstatus für den jeweiligen Nameserver an.
- Zone Alias App: Neue App, mit der sich Aliase für beliebige interne oder externe Zonen anlegen lassen, die alle dieselben Einträge liefern.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 11.2
Veröffentlicht: 27. Mai 2023

- Unterstützung für die Eintragstypen SVCB und HTTPS ([draft-ietf-dnsop-svcb-https](https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/)) hinzugefügt.
- Unbekannte, nicht unterstützte Eintragstypen lassen sich jetzt verwalten.
- Auto PTR App: Neue App, die automatisch Antworten auf PTR-Anfragen erzeugt.
- Weighted Round Robin App: Neue App für gewichtetes Round-Robin-Load-Balancing.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 11.1.1
Veröffentlicht: 1. Mai 2023

- Erschöpfung des UDP-Socket-Pools unter Windows behoben, durch die alle ausgehenden UDP-Anfragen fehlschlugen.

## Version 11.1
Veröffentlicht: 29. April 2023

- Unterstützung für internationalisierte Domainnamen (IDN) hinzugefügt.
- Die Seriennummer im SOA-Eintrag einer Primary-Zone kann nach dem Datumsschema vergeben werden.
- Von Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/) gemeldetes Problem behoben, durch das der DNS-Server unter Windows wegen nicht zufälliger UDP-Quellports für ausgehende Anfragen anfällig für Cache Poisoning war.
- Fehler in der Validierung beim Erneuern von RRSIG-Einträgen in mit NSEC3 signierten Primary-Zonen behoben.
- Fehler im Typenfeld von NSEC3-Einträgen behoben, durch den der Eintrag für RRSIG fehlte.
- Der Kestrel-Webserver liefert jetzt auch unbekannte Dateitypen aus, damit die Webroot-HTTP-Challenge von certbot funktioniert.
- Advanced Forwarding App: Zwischengespeicherte Einträge werden jetzt korrekt pro Client-Subnetz aus der App-Konfiguration gespeichert. Unterstützung für Wildcard-Domains hinzugefügt.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 11.0.3
Veröffentlicht: 11. März 2023

- Von Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/) gemeldete DoS-Schwachstelle behoben: Wegen unzureichender Validierung konnte ein Angreifer mit fehlerhaften UDP-Paketen ausgehende Auflösungen scheitern lassen.
- Von Xiang Li gemeldetes Problem behoben, durch das Conditional Forwarder das RD-Flag in Anfragen nicht beachteten.
- Von Xiang Li gemeldetes Problem behoben, durch das die Antwortgrenze von maximal 4096 Byte Amplification-Angriffe begünstigte.
- Problem beim Laden der Allowed- und Blocked-Zonen behoben, das wegen der im letzten Update eingeführten Indizierung autoritativer Zonen zu sehr langen Ladezeiten führte.
- Bei MX-Antworten über UDP werden Glue-Einträge entfernt und das Senden erneut versucht, statt eine gekürzte Antwort zu schicken. Einige alte Mailserver stellten nach einer gekürzten Antwort keine Folgeanfrage über TCP.
- Block Page App: Der Webserver lässt sich jetzt deaktivieren, ohne die App zu deinstallieren.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 11.0.2
Veröffentlicht: 26. Februar 2023

- Problem mit der Prüfung auf private IP-Adressen bei DNS-over-HTTP behoben, die hinter einem Reverse Proxy zu Antworten mit Status 403 führte.
- Problem mit der Seitenaufteilung der Zoneneinträge bei Zonen ohne Einträge behoben.

## Version 11.0.1
Veröffentlicht: 25. Februar 2023

- Allow-Listen werden jetzt getrennt behandelt, und ihre Anzahl wird im Dashboard angezeigt.
- Fehler in Conditional-Forwarder-Zonen für die Root-Zone behoben, durch den der DNS-Server RCODE=ServerFailure lieferte.
- Probleme in der Reihenfolge der Anfragebearbeitung durch Apps behoben, die die Advanced Forwarding App betrafen.
- Der Parser für Blocklisten erkennt jetzt Kommentare am Zeilenende.
- Problem „URI too long“ beim Speichern eines DHCP-Bereichs behoben.
- Das Linux-Installationsskript verwendet für Neuinstallationen den Installationspfad in `/opt` und den Konfigurationspfad `/etc/dns`.
- Der Docker-Container verwendet den neuen Volume-Pfad `/etc/dns` für die Konfiguration.
- Der Docker-Container behandelt das Stopp-Ereignis jetzt korrekt und fährt den DNS-Server sauber herunter.
- Der Docker-Container enthält `libmsquic` für QUIC-Unterstützung.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 11.0
Veröffentlicht: 18. Februar 2023

- Unterstützung für DNS-over-QUIC (DoQ) nach [RFC 9250](https://www.ietf.org/rfc/rfc9250.html) hinzugefügt, als Dienst und für Forwarder. DoQ funktioniert auch über einen SOCKS5-Proxy mit UDP-Unterstützung.
- Unterstützung für Zonentransfers über QUIC (XFR-over-QUIC) nach [RFC 9250](https://www.ietf.org/rfc/rfc9250.html) hinzugefügt.
- DNS-over-HTTPS unterstützt jetzt HTTP/2 und HTTP/3. DNS-over-HTTP/3 lässt sich mit dem Schema `h3` statt `https` in der URL erzwingen.
- Der Webdienst verwendet jetzt den Kestrel-Webserver, daher wird die ASP.NET-Core-Laufzeit benötigt. Der Webdienst unterstützt damit HTTP/2 und HTTP/3. Wer die HTTP-API nutzt, sollte eigenen Code oder Skripte mit dieser Version testen.
- Der DNS-Cache kann beim Beenden auf die Festplatte geschrieben und beim Start wieder geladen werden.
- Die Blockierung von Domainnamen unterstützt Extended DNS Errors, sodass ein Bericht zum blockierten Domainnamen angezeigt werden kann. Der Reiter DNS-Client in der Weboberfläche zeigt diesen Bericht für jede blockierte Domain an.
- Die Blockierung unterstützt Blocklisten mit Platzhaltern und im Adblock-Plus-Format.
- Der DNS-Server erkennt, wenn ein Upstream-Server eine Domain blockiert, und berücksichtigt das in Dashboard und Query-Logs. Das Blockiersignal von Quad9 wird erkannt und als Extended DNS Error angezeigt.
- Der Bereich Zonen der Weboberfläche unterstützt Seitenaufteilung.
- Advanced Blocking App: Unterstützt Blocklisten mit Platzhaltern. Ist eine Domain in der Konfiguration erlaubt, wird die CNAME-Cloaking-Prüfung dafür deaktiviert. Extended DNS Errors für Berichte zu blockierten Domains umgesetzt.
- Advanced Forwarding App: Neue App für Conditional Forwarding in großer Zahl.
- DNS Block List App: Neue App, um eigene DNSBL- oder RBL-Blocklisten nach [RFC 5782](https://www.rfc-editor.org/rfc/rfc5782) zu betreiben.
- Unterstützung für die DHCP-Option „TFTP-Serveradresse“ (150) hinzugefügt.
- Generische DHCP-Optionen hinzugefügt, um Optionen zu konfigurieren, die der DHCP-Server noch nicht direkt unterstützt.
- Unterstützung für das nicht standardisierte DNS-over-HTTPS-Protokoll mit JSON entfernt.
- Die Abhängigkeit von Newtonsoft.Json wurde aus dem DNS-Server und allen DNS-Apps entfernt.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 10.0.1
Veröffentlicht: 4. Dezember 2022

- Mehrere Probleme in der Umsetzung von EDNS Client Subnet (ECS) behoben.
- Serialisierungsproblem beim Speichern von Berechtigungen bei mehr als 255 Zonen behoben.
- Failover App: Problem mit Leerlaufverbindungen bei HTTP- und HTTPS-Prüfungen behoben.
- QueryLogs (Sqlite) App: Problem mit geöffneter Datenbankdatei unter Windows behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 10.0
Veröffentlicht: 26. November 2022

- Sicherheitsrichtlinien für dynamische Updates nach [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136) hinzugefügt, die Updates nur für festgelegte Domainnamen und Eintragstypen erlauben. Die HTTP-API-Aufrufe für Zonenoptionen ändern sich dadurch inkompatibel. Wer diese API nutzt, sollte vor dem produktiven Einsatz testen.
- Unterstützung für den Eintragstyp DANE TLSA nach [RFC 6698](https://datatracker.ietf.org/doc/html/rfc6698) hinzugefügt, einschließlich automatischer Hashberechnung aus Zertifikaten im PEM-Format.
- Unterstützung für den Eintragstyp SSHFP nach [RFC 4255](https://www.rfc-editor.org/rfc/rfc4255.html) hinzugefügt.
- EDNS Client Subnet (ECS) nach [RFC 7871](https://datatracker.ietf.org/doc/html/rfc7871) für rekursive Auflösung und Forwarding umgesetzt.
- Die HTTP-API akzeptiert Datum und Uhrzeit für Dashboard und Query-Logs im Format ISO 8601. Wer diese API nutzt, sollte vor dem produktiven Einsatz testen.
- Codebasis auf die .NET-7-Laufzeit umgestellt. Wer den DNS-Server oder die .NET-6-Laufzeit bisher manuell installiert hat, muss vor dem Upgrade die .NET-7-Laufzeit manuell installieren.
- Self-CNAME-Schwachstelle [CVE-2022-48256] behoben, gemeldet von Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/). Der DNS-Server folgte einem CNAME in einer Schleife, sodass die Antwort bis zum Erreichen des Limits einige hundert Einträge enthielt.
- Das App-Framework hat die neue Schnittstelle `IDnsPostProcessor`, mit der DNS-Apps ausgehende Antworten verändern können.
- NO DATA App: Neue App, die in Conditional-Forwarder-Zonen NO-DATA-Antworten liefert, um für bestimmte Eintragstypen vorhandene Einträge des Forwarders zu überschreiben.
- DNS64 App: Neue App für DNS64 nach [RFC 6147](https://www.rfc-editor.org/rfc/rfc6147) für reine IPv6-Clients.
- Advanced Blocking App: Verbraucht weniger Speicher, wenn dieselben Blocklisten in mehreren Gruppen verwendet werden.
- Geo Continent App, Geo Country App und Geo Distance App: Unterstützen jetzt EDNS Client Subnet (ECS) nach [RFC 7871](https://datatracker.ietf.org/doc/html/rfc7871).
- Split Horizon App: Unterstützt jetzt 1:1-Übersetzung von IP-Adressen. Damit lassen sich externe, öffentliche IP-Adressen auf interne, private Adressen abbilden, sodass Clients im privaten Netz lokale Dienste über interne Adressen erreichen.
- Unterstützung für die DHCP-Option „Domain Search“ nach [RFC 3397](https://www.rfc-editor.org/rfc/rfc3397) hinzugefügt.
- Unterstützung für die DHCP-Option „CAPWAP Access Controller“ nach [RFC 5417](https://www.rfc-editor.org/rfc/rfc5417.html) hinzugefügt.
- Option in DHCP-Bereichen, um DNS-Updates zu deaktivieren.
- Die NTP-Option in DHCP-Bereichen akzeptiert Domainnamen, die der DHCP-Server automatisch auflöst und als IP-Adressen ausliefert.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 9.1
Veröffentlicht: 9. Oktober 2022

- Unterstützung für dynamische Updates nach [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136) hinzugefügt. Damit lassen sich Werkzeuge wie `nsupdate` nutzen, DHCP-Server von Drittanbietern können DNS-Einträge aktualisieren, und das certbot-Plugin [certbot-dns-rfc2136](https://certbot-dns-rfc2136.readthedocs.io/en/stable/) kann TLS-Zertifikate per DNS-Challenge automatisch erneuern.
- Das Hauptdiagramm im Dashboard verwendet die lokale Zeit des Clients statt der des Servers.
- Fehler beim Anlegen einer neuen Secondary-Zone behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 9.0
Veröffentlicht: 24. September 2022

- Mehrbenutzerbetrieb mit rollenbasiertem Zugriff hinzugefügt: mehrere Benutzer und rollenbasierte Gruppen mit Berechtigungen.
- Nicht ablaufende API-Tokens für Automatisierungsskripte hinzugefügt.
- Berechtigungen auf Zonenebene, um den Zugriff auf ausgewählte Benutzer oder Gruppenmitglieder zu beschränken.
- Im Benutzerprofil lässt sich das Sitzungs-Timeout für jeden Benutzer festlegen.
- HTTP-API: Die API wurde umfassend überarbeitet und bleibt abwärtskompatibel. Wer die API nutzt, sollte vor dem produktiven Einsatz testen. Die Verwendung nicht ablaufender API-Tokens wird empfohlen.
- Conditional-Forwarder-Zonen unterstützen APP-Einträge und damit DNS-Apps.
- Option in den Einstellungen, um die automatische Aktualisierung der Blocklisten-URLs zu stoppen.
- DNS-Apps: Die Methode IDnsAppRecordRequestHandler.ProcessRequestAsync() ändert sich inkompatibel. Eigene DNS-Apps müssen vor dem Update mit der aktuellen DnsServerCore.ApplicationCommon.dll neu kompiliert werden.
- DNS-Apps werden automatisch aktualisiert. Der DNS-Server prüft alle 24 Stunden auf Updates und installiert sie.
- Split Horizon App: Netzsammlungen lassen sich für die Daten von APP-Einträgen konfigurieren.
- Wild IP App: Neue App, die A- und AAAA-Anfragen mit der IP-Adresse beantwortet, die im Subdomain-Namen der Anfrage steckt, ähnlich wie [sslip.io](https://sslip.io/).
- Kleinere Probleme in der DNSSEC-Validierung von DNAME-Antworten und Wildcard-NO-DATA-Antworten behoben.
- DHCP-Bereiche aktualisieren DNS-Einträge jetzt sowohl in Primary- als auch in Forwarder-Zonen.
- DHCP-Bereiche können dynamische Vergabe an Geräte mit lokal verwalteter MAC-Adresse verhindern.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 8.1.4
Veröffentlicht: 3. Juli 2022
- Problem in der rekursiven Auflösung behoben, durch das die DNSSEC-Validierung fehlschlug, wenn der Nameserver mit Einträgen außerhalb seines Zuständigkeitsbereichs antwortete.
- Der rekursive Resolver aktualisiert die Adressen aller NS-Einträge asynchron, um schneller zu sein.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 8.1.3
Veröffentlicht: 11. Juni 2022
- DoH-Endpunkte von OpenDNS zur Schnellauswahl für DNS-Client und Forwarder hinzugefügt.
- Fehlende Prüfung auf unterstützte Digest-Typen ergänzt, deren Fehlen eine Ausnahme auslösen und die Auflösung DNSSEC-signierter Domains verhindern konnte.

## Version 8.1.2
Veröffentlicht: 28. Mai 2022
- Problem im IXFR-Verlauf beim Hinzufügen und Ändern von Einträgen in Primary-Zonen behoben, wenn die TTL eines RRsets geändert wurde.
- Problem in der DNSSEC-Validierung von MX- und SRV-Einträgen durch einen falschen Vergleich der Eintragsdaten behoben.
- Problem beim Einlesen des Parameters „Verantwortlicher“ im SOA-Eintrag behoben.
- Diese Version ändert die API-Aufrufe zum Löschen und Ändern von MX- und SRV-Einträgen. Clients von Drittanbietern können Probleme bekommen, wenn sie nicht vorher angepasst werden. Vor dem Einsatz sollte die API-Dokumentation auf Änderungen geprüft werden.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 8.1.1
Veröffentlicht: 21. Mai 2022
- Zonenstatus „Synchronisierung fehlgeschlagen“ und „Notify fehlgeschlagen“ hinzugefügt, um Probleme bei der Synchronisierung zwischen Primary- und Secondary-Zonen anzuzeigen.
- Weitere Zonenoptionen für Zonentransfer und Notify hinzugefügt.
- Zeitprobleme beim Schlüsselwechsel DNSSEC-signierter Primary-Zonen nach [RFC 7583](https://datatracker.ietf.org/doc/html/rfc7583) behoben.
- Problem im rekursiven Resolver durch eine Zonenschnitt-Prüfung für Glue-Einträge behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 8.1
Veröffentlicht: 8. Mai 2022
- Zwei Ghost-Domain-Probleme behoben, CVE-2022-30257 (V1) und CVE-2022-30258 (V2), gemeldet von Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/). V1 wurde durch Änderungen an der NS-Revalidierung behoben, sodass die aktivierte Option in den Einstellungen das Problem entschärft. V2 wurde durch zusätzliche Prüfungen beim Zwischenspeichern von NS-Einträgen behoben.
- Option für die maximale Zahl an Cache-Einträgen hinzugefügt, um den Speicherverbrauch durch Entfernen der am längsten ungenutzten Daten zu begrenzen.
- NS-Revalidierung umgesetzt, die NS-Einträge der übergeordneten Zone nach Ablauf ihrer TTL erneut prüft.
- Die Weboberfläche speichert das Sitzungstoken im lokalen Speicher, damit man beim Neuladen der Seite nicht abgemeldet wird.
- DropRequests App: Für den konfigurierten QNAME lässt sich die gesamte Zone blockieren.
- Fehler im IXFR-Verlauf von Primary-Zonen durch eine fehlende Prüfung der SOA-Seriennummer behoben.
- Falsche IXFR-Verlaufseinträge für DNSKEY-Einträge in Primary-Zonen behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 8.0.2
Veröffentlicht: 3. April 2022
- Fehler in Conditional-Forwarder-Zonen behoben, der bei einigen Anfragen zu ServerFailure führte.
- Problem behoben, durch das bei einer Änderung des SOA-Werts die Mindest-TTL für NSEC- und NSEC3-Einträge in signierten Primary-Zonen gesetzt wurde.
- Problem beim Einlesen von JSON-Antworten von DNS-over-HTTPS für NSEC- und NSEC3-Einträge behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 8.0.1
Veröffentlicht: 29. März 2022
- Fehler in Conditional-Forwarder-Zonen behoben: Die Zonenschnitt-Prüfung erzeugte negative Cache-Einträge für CNAME-Antworten, was zu unvollständigen Antworten führte.
- Problem bei der Behandlung von FormatError-Antworten ohne Question-Abschnitt auf EDNS-Anfragen behoben.
- Kleineres Problem bei der DNSSEC-Validierung unsignierter Zonen behoben, wenn der Forwarder leere NXDOMAIN-Antworten lieferte.
- Problem bei der Behandlung von NODATA-Antworten für ANAME-Einträge behoben.
- Problem bei der Prüfung von Eintragskommentaren behoben, das beim Speichern von SOA-Einträgen einen Fehler auslöste.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 8.0
Veröffentlicht: 26. März 2022
- Unterstützung für EDNS nach [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891) hinzugefügt.
- Extended DNS Errors nach [RFC 8914](https://datatracker.ietf.org/doc/html/rfc8914) hinzugefügt.
- DNSSEC-Validierung mit RSA und ECDSA für rekursiven Resolver, Forwarder und Conditional Forwarder hinzugefügt.
- DNSSEC für alle unterstützten DNS-Transportprotokolle einschließlich der verschlüsselten Protokolle (DoT, DoH, DoH JSON) hinzugefügt.
- Signieren von Zonen mit DNSSEC per RSA und ECDSA hinzugefügt.
- Der DNS-Client unterstützt jetzt DNSSEC-Validierung.
- Der eigene FWD-Eintragstyp für Conditional-Forwarder-Zonen unterstützt jetzt DNSSEC-Validierung und HTTP-/SOCKS5-Proxys.
- Conditional-Forwarder-Zonen können als statische Stub-Zone arbeiten und eine Domain über NS-Einträge zwingend über bestimmte Nameserver auflösen.
- Codebasis auf die .NET-6-Laufzeit umgestellt.
- Query Logs App: Suche mit Platzhaltern für Domainnamen hinzugefügt.
- Mehrere Probleme im DHCP-Server behoben.
- Diese Version ändert viele API-Aufrufe. Clients von Drittanbietern können Probleme bekommen, wenn sie nicht vorher angepasst werden. Vor dem Einsatz sollte die API-Dokumentation auf Änderungen geprüft werden.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 7.1
Veröffentlicht: 23. Oktober 2021
- Option in den Einstellungen, um automatisch ein selbstsigniertes Zertifikat für den Webdienst einzurichten.
- Cache-Poisoning-Schwachstelle [CVE-2021-43105] behoben, gemeldet von Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/), und Qifan Zhang, [Data-driven Security and Privacy (DSP) Lab, University of California, Irvine](https://faculty.sites.uci.edu/zhouli/research/). Sie trat auf, wenn eine Conditional-Forwarder-Zone einen vom Angreifer kontrollierten Forwarder nutzte oder ein UDP-/TCP-Forwarder-Protokoll, bei dem ein Man-in-the-Middle-Angriff möglich war.
- Block Page App: Unterstützt automatische selbstsignierte Zertifikate, um die Blockierseite auch für HTTPS-Webseiten anzuzeigen.
- Drop Requests App: Option zum Verwerfen fehlerhafter DNS-Anfragen hinzugefügt.
- Query Logs App: Kleineres Problem behoben, durch das Abfragen fehlschlugen, wenn eine Domain mit ungültigem Zeichen in der Datenbank stand.
- Advanced Blocking App: Fehler beim Laden von Regex-Blocklisten behoben, durch den Domains nicht wie erwartet blockiert wurden.
- Der DNS-Server protokolliert jetzt, warum eine Anfrage für einen Zonentransfer abgelehnt wurde.
- Weitere Umgebungsvariablen für Docker, um die Konfiguration des DNS-Servers zu initialisieren. Details stehen in der [Dokumentation der Umgebungsvariablen](https://github.com/TechnitiumSoftware/DnsServer/blob/master/DockerEnvironmentVariables.md).
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 7.0
Veröffentlicht: 2. Oktober 2021
- DNS-Apps können jetzt zusätzlich zu APP-Einträgen in autoritativen Zonen selbst als autoritative Zonen arbeiten, Anfragen verwerfen und Anfragen protokollieren.
- Diese Version ändert das Design der DNS-Apps grundlegend, sodass bisher installierte Apps nach dem Update nicht mehr geladen werden. Sie müssen manuell über den DNS-App-Store aktualisiert werden.
- Advanced Blocking App: Neue App, die Domainnamen abhängig von IP-Adresse oder Subnetz der Clients in Gruppen blockiert. Unterstützt auch Regex und Blocklisten im Adblock-Format.
- Block Page App: Neue App mit eingebautem Webserver, der Clients bei blockierten Domains eine Blockierseite anzeigt.
- Drop Requests App: Neue App, die Anfragen verwirft, die den konfigurierten Fragen entsprechen. So lassen sich DNS-Amplification-Angriffe mit bestimmten Domainnamen und Anfragetypen abwehren.
- NX Domain App: Neue App, die Domainnamen mit einer NXDOMAIN-Antwort blockiert.
- Query Logs (Sqlite): Neue App, die alle Anfragen an den DNS-Server in einer Sqlite-Datenbank protokolliert. Die Weboberfläche bietet dafür die Option Query-Logs zur Abfrage der Daten.
- Failover App: Wartungsmodus umgesetzt, um anzuzeigen, dass eine Adresse wegen Wartung abgeschaltet ist.
- Ping-Prüfung in DHCP-Bereichen, um vor der Vergabe festzustellen, ob eine IP-Adresse bereits verwendet wird.
- Vergebene DHCP-Leases lassen sich entfernen.
- Diese Version ändert viele API-Aufrufe. Clients von Drittanbietern können Probleme bekommen, wenn sie nicht vorher angepasst werden. Vor dem Einsatz sollte die API-Dokumentation auf Änderungen geprüft werden.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 6.4.1
Veröffentlicht: 21. August 2021
- Delegation Revalidation nach [draft-ietf-dnsop-ns-revalidation-01](https://datatracker.ietf.org/doc/draft-ietf-dnsop-ns-revalidation/) im rekursiven Resolver umgesetzt.
- Probleme mit DNS-over-TLS behoben, bei denen das ALPN „dot“ den SSL-Handshake mit NextDNS als Forwarder scheitern ließ.
- Probleme beim Zählen eindeutiger Clients in der Dashboard-Statistik behoben. Künftige Daten werden korrekt angezeigt. Fehlerhafte Daten seit dem letzten Release lassen sich durch manuelles Löschen der Dateien '/etc/dns/config/stats/202108*.dstat' bereinigen.
- Erlaubte Listen-URLs werden jetzt zonenweise geprüft, sodass auch Subdomains aus Blocklisten erlaubt werden.
- DNS Failover App auf v1.4 aktualisiert, um Umsetzungsprobleme zu beheben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 6.4
Veröffentlicht: 14. August 2021
- Unterstützung für DNAME-Einträge nach [RFC 6672](https://datatracker.ietf.org/doc/html/rfc6672) hinzugefügt.
- Inkrementeller Zonentransfer (IXFR) nach [RFC 1995](https://datatracker.ietf.org/doc/html/rfc1995) umgesetzt.
- Transaktionsauthentifizierung mit geheimem Schlüssel (TSIG) nach [RFC 8945](https://datatracker.ietf.org/doc/html/rfc8945) für Zonentransfers umgesetzt.
- Zonentransfer über TLS (XFR-over-TLS) nach [draft-ietf-dprive-xfr-over-tls](https://datatracker.ietf.org/doc/draft-ietf-dprive-xfr-over-tls/) umgesetzt.
- Erweiterte Einstellungen für die TTL-Werte im Cache hinzugefügt.
- Schaltfläche „Resync“ hinzugefügt, um Secondary- und Stub-Zonen erneut zu synchronisieren.
- Die Ratenbegrenzung kann Anfragen jetzt pro Client-Subnetz begrenzen.
- SplitHorizon App: Unterstützt jetzt CIDR-Netze.
- Failover App: Mehrere Probleme behoben. Die Health-Check-URL kann aus dem Domainnamen des APP-Eintrags erzeugt oder in dessen Daten angegeben werden.
- Probleme beim Rotieren der Logdateien bei Verwendung der lokalen Zeit behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.
- Einige API-Aufrufe wurden geändert. Clients von Drittanbietern können Probleme bekommen, wenn sie nicht vorher angepasst werden.

## Version 6.3
Veröffentlicht: 6. Juni 2021

- Failover App im DNS-App-Store hinzugefügt.
- Kommentare für DNS-Einträge in Zonen hinzugefügt.
- Rekursions-ACL hinzugefügt, um Netze festzulegen, die Rekursion nutzen dürfen oder nicht.
- Zonenoptionen hinzugefügt, um Zonentransfer und Notify pro Zone zu konfigurieren.
- Begrenzung der Anfragen pro Minute (QPM) pro IP-Adresse hinzugefügt.
- Für blockierte Domainnamen lassen sich eigene IP-Adressen angeben.
- Das Blockieren von Domainnamen lässt sich vorübergehend oder dauerhaft deaktivieren.
- Startseite für den DNS-over-HTTPS-Dienst hinzugefügt, die beim Aufruf der DoH-URL im Browser grundlegende Konfigurationsinformationen zeigt.
- Mehrere Probleme in der QNAME-Minimierung behoben.
- Mehrere Probleme im DNS-Client behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.
- Einige API-Aufrufe wurden geändert. Clients von Drittanbietern können Probleme bekommen, wenn sie nicht vorher angepasst werden.

## Version 6.2.3
Veröffentlicht: 2. Mai 2021

- Die Liste der installierten DNS-Apps zeigt an, ob Updates verfügbar sind.
- Tägliche Statistikdaten werden gekürzt, um weniger Speicher zu verbrauchen.
- Problem in der QNAME-Minimierung behoben, das durch eine fehlende Prüfung auf Antworten ohne Answer- und Authority-Abschnitt entstand.
- Problem im Logger behoben, der unter bestimmten Bedingungen nicht startete.
- DNS-Apps mischen die Adressen in Antworten, um Lastverteilung zu ermöglichen.

## Version 6.2.2
Veröffentlicht: 24. April 2021

- Probleme in der rekursiven Auflösung behoben.
- Problem beim Einlesen von AXFR-Antworten behoben.
- Fehlende Markierungen in Antworten ergänzt, damit das Dashboard korrekte Statistiken zeigt.
- Problem mit der Weiterleitung der Weboberfläche beim Speichern von Einstellungen hinter einem Reverse Proxy behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 6.2.1
Veröffentlicht: 17. April 2021

- Serve Stale im DNS-Cache für bessere Performance überarbeitet.
- CNAME-Auflösung im DNS-Cache und in autoritativen Zonen optimiert.
- Problem im DNS-Cache behoben, bei dem durch eine fehlende Typprüfung der RDATA von NS-Einträgen spezielle Cache-Einträge zurückgegeben wurden.
- Problem im DNS-Client beim Empfang von Antworten behoben, die größer als der Puffer waren.

## Version 6.2
Veröffentlicht: 11. April 2021

- Kritischen Fehler in der Blocklistenprüfung behoben, durch den der Server mit `RCODE=Refused` antwortete, wenn nur die Blocked-Zone verwendet wurde.
- Option, blockierte Domains mit `RCODE=NxDomain` statt mit der Adresse `0.0.0.0` zu beantworten.
- `NameError` wurde in `NxDomain` umbenannt, um deutlich zu machen, dass die Domain nicht existiert. Die Dashboard-API liefert JSON mit dem neuen Begriff, daher sollte eigener Code vor dem Update getestet werden.

## Version 6.1
Veröffentlicht: 10. April 2021

- DNS-App-Store hinzugefügt, der alle verfügbaren Apps zur einfachen Installation und Aktualisierung auflistet.
- Option „Überschreiben“ beim Hinzufügen von Einträgen in Zonen hinzugefügt.
- Mehrere ANAME-Einträge werden unterstützt.
- Erlaubte URLs für Blocklisten hinzugefügt, um zu verhindern, dass Domains in die Blocklistenzone aufgenommen werden.
- Fehler in ZoneTree behoben.
- Fehler in DNS-Apps behoben.
- Die Standard-DNS-App wurde in 5 eigenständige Apps aufgeteilt, die im DNS-App-Store verfügbar sind.
- Probleme im DNS-Cache behoben und den Code für geringeren Speicherverbrauch optimiert.
- Alle Bibliotheksprojekte auf .NET 5 umgestellt.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 6.0
Veröffentlicht: 13. März 2021

- Die gesamte Codebasis wurde auf .NET 5 mit neuem Windows-Installer umgestellt. Das verbessert die Performance unter Windows.
- Unterstützung für den eigenen Eintragstyp DNS Application (APP) mit DNS-Apps hinzugefügt. Damit können Drittanbieter mit .NET eigene Apps entwickeln, die auf dem DNS-Server laufen, DNS-Anfragen verarbeiten und nach beliebiger Geschäftslogik eigene Antworten liefern.
- Eine separat herunterladbare Standard-App unterstützt APP-Einträge für Split Horizon und geolokalisierte Antworten mit den MaxMind-Datenbanken GeoIP2 City und Country.
- Die Diagramme im Dashboard merken sich die Auswahl in der Legende.
- Im Dashboard lässt sich ein eigener Zeitraum für die Statistik wählen.
- Option für die maximale Zahl an Statistiktagen in den Einstellungen hinzugefügt.
- Option zum Aktivieren oder Deaktivieren der QNAME-Minimierung hinzugefügt.
- Option zum Löschen vorhandener Dateien beim Wiederherstellen von Einstellungen hinzugefügt.
- Anfragestatistiken werden gespeichert, damit das automatische Prefetching den Cache nach einem Neustart auffrischen kann.
- Selbstsignierte Zertifikate lassen sich für Weboberfläche, DoH und DoT verwenden.
- Optionen zum Reservieren und Freigeben von DHCP-Leases hinzugefügt, um Leases für Clients schnell zu reservieren.
- Reservierte DHCP-Leases können den Hostnamen des Clients überschreiben.
- Probleme mit dem automatischen Prefetching im DNS-Cache behoben.
- Mehrere Probleme im DNS-Cache behoben.
- Mehrere Schwachstellen behoben, die Cache Poisoning ermöglichten.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 5.6
Veröffentlicht: 2. Januar 2021

- Die eigenständige Konsolenanwendung läuft jetzt auf .NET 5, die eigenständige .NET-Framework-Anwendung wird nicht mehr unterstützt. .NET 5 verbessert die Performance auf allen Plattformen.
- DNS- und DHCP-Listener verwenden asynchrone Ein-/Ausgabe für bessere Performance.
- HTTPS für den Webdienst der Weboberfläche hinzugefügt.
- Die lokalen Adressen des Webdienstes lassen sich ändern.
- Endpunkte des DNS-Servers und des Webdienstes sowie DoH und DoT lassen sich sofort ändern, ohne den Dienst manuell neu zu starten. Alle Einstellungen werden dynamisch übernommen.
- HTTP-Komprimierung für den Webdienst hinzugefügt.
- HTTP-Komprimierung beim Herunterladen von Blocklisten hinzugefügt.
- Option zum Löschen aller Dashboard-Statistiken und automatisches Aufräumen alter Statistikdateien hinzugefügt.
- Option zum Löschen aller Logdateien und automatisches Aufräumen alter Logdateien hinzugefügt.
- Optionen zum Deaktivieren der Protokollierung, zur Protokollierung in lokaler Zeit und zum Ändern des Log-Ordners hinzugefügt.
- Option für das Aktualisierungsintervall der Blocklisten mit manueller Möglichkeit, alle Blocklisten sofort zu aktualisieren.
- Export einer Sicherung als ZIP-Datei mit ausgewählten Inhalten wie Konfigurationsdateien, Logs und Statistiken sowie Wiederherstellung ohne Neustart des Dienstes.
- Mehrere Probleme in der DNS-Eintragsverwaltung des DHCP-Servers behoben.
- Fehler beim Cache-Prefetching für Stub- und Conditional-Forwarder-Zonen behoben, durch den zwischengespeicherte Daten mit dem Ergebnis rekursiver Auflösung überschrieben wurden.
- Problem mit der HTML-Kodierung in der Web-App behoben.
- Die Web-App kann die Top 1000 der Clients, Domains und blockierten Domains auflisten.
- Serve Stale im DNS-Cache ist konfigurierbar, die Standard-TTL für veraltete Antworten beträgt 3 statt 7 Tage.
- Problem im rekursiven Resolver behoben, damit keine Root-Server abgefragt werden, wenn einer der Nameserver der übergeordneten Zone bereits im Cache liegt.
- Inkompatible Änderungen an den API-Aufrufen `getDnsSettings` und `setDnsSettings` erfordern eine Anpassung von API-Clients vor dem Update.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 5.5
Veröffentlicht: 14. November 2020

- Option für den Namen der Bootdatei beim PXE-Boot hinzugefügt.
- DHCP-Option für herstellerspezifische Informationen umgesetzt.
- Die Ausschlussliste wird jetzt strikt durchgesetzt.
- Fehler beim anfänglichen Servernamen behoben, der durch ungültige Zeichen im Computernamen entstand.
- Unterstützung für die Verarbeitung zusätzlicher Einträge bei SRV-Einträgen hinzugefügt und Probleme bei NS- und MX-Einträgen behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 5.4
Veröffentlicht: 18. Oktober 2020

- QNAME-Randomisierung nach [draft-vixie-dnsext-dns0x20](https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00) umgesetzt.
- Fehler behoben, der unter bestimmten Bedingungen bei UDP eine Endlosschleife verursachte.
- Fehler bei Cache-Abfragen behoben, durch den der Server bei der rekursiven Auflösung unnötige Anfragen stellte.
- Option „PTR-Zone anlegen“ beim Hinzufügen von A- oder AAAA-Einträgen hinzugefügt.
- Probleme bei der Auswahl des DHCP-Bereichs mit Relay-Agent behoben.
- Die IP-Vergabe eines DHCP-Bereichs lässt sich von dynamisch auf reserviert und umgekehrt umstellen.
- DHCP-Bereiche erlauben die Angabe einer Next-Server-Adresse für den Boot über TFTP.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 5.3
Veröffentlicht: 26. September 2020

- Probleme im DHCP-Server behoben, durch die er mit Relay-Agents nicht korrekt funktionierte.
- Der DHCP-Server unterstützt mehrere Bereiche auf einer Netzwerkschnittstelle und kann so Gerätegruppen unterschiedliche Optionen zuweisen.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 5.2
Veröffentlicht: 6. September 2020

- TLS-Zertifikate für DNS-over-HTTPS und DNS-over-TLS lassen sich mit `certbot` automatisch erneuern.
- Problem im DHCP-Server behoben, der durch fehlende asynchrone Methoden Threads blockierte.
- Fehler im DNS-Client behoben, der durch die QNAME-Minimierung zu abweichenden QTYPEs führte.
- Probleme im DNS-over-HTTPS-Client bei Wiederholungen und der Behandlung von HTTP-Fehlern behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 5.1
Veröffentlicht: 29. August 2020

- Asynchrone Ein-/Ausgabe umgesetzt, damit der DNS-Server deutlich mehr gleichzeitige Last verarbeiten kann.
- Eigene Thread-Pools für den Webdienst und den rekursiven Resolver umgesetzt.
- Fehler im Blocklisten-Downloader behoben, der Dateien mit 0 Byte herunterlud.
- Fehler im DHCP-Server beim Anlegen von Reverse-Zonen behoben.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 5.0.2
Veröffentlicht: 18. Juli 2020

- Fehlenden Port für „This Server“ im DNS-Client ergänzt.
- Der blockierte Domainname wird im TXT-Eintrag angegeben.
- Fehler in der CNAME-Cloaking-Erkennung behoben.
- .NET Framework auf v4.8 aktualisiert.
- Mehrere weitere kleinere Fehlerbehebungen und Verbesserungen.

## Version 5.0.1
Veröffentlicht: 6. Juli 2020

- Serialisierungsfehler bei TXT-Einträgen behoben.
- Problem beim Lesen von DnsDatagram bei DoH-POST-Anfragen behoben.
- Fehler bei der JSON-Serialisierung von DnsDatagram im DoH-JSON-Format behoben.
- Fehler bei der RTT-Berechnung für DoH-JSON-Verbindungen behoben.

## Version 5.0
Veröffentlicht: 4. Juli 2020

- Lokale Endpunkte des DNS-Servers mit abweichenden Ports für UDP und TCP werden unterstützt.
- Performance-Probleme durch Thread-Konflikte behoben.
- CNAME-Cloaking-Erkennung umgesetzt, um Domains zu blockieren, die per CNAME auf blockierte Domains verweisen.
- Neue Blocklistenzone, die sehr wenig Speicher benötigt und Blocklisten mit Millionen Domains selbst auf einem Raspberry Pi mit 1 GB RAM lädt.
- QNAME-Minimierung im rekursiven Resolver nach [draft-ietf-dnsop-rfc7816bis-04](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-rfc7816bis-04).
- Eigener ANAME-Eintragstyp, der eine CNAME-ähnliche Funktion an der Zonenwurzel ermöglicht.
- Primary-Zonen mit NOTIFY nach [RFC 1996](https://datatracker.ietf.org/doc/html/rfc1996) hinzugefügt.
- Secondary-Zonen mit NOTIFY nach [RFC 1996](https://datatracker.ietf.org/doc/html/rfc1996) hinzugefügt.
- Stub-Zonen mit der Möglichkeit, Einträge zu überschreiben, hinzugefügt.
- Conditional-Forwarder-Zonen mit allen Protokollen einschließlich DNS-over-HTTPS und DNS-over-TLS hinzugefügt.
- Conditional-Forwarder-Zonen können Einträge überschreiben.
- Conditional-Forwarder-Zonen unterstützen mehrere Forwarder für verschiedene Subdomains.
- Zonenbaum auf Basis von ByteTree, einem vollständig sperrfreien und threadsicheren Baum für gleichzeitige Lese- und Schreibzugriffe.
- Fehler beim Einlesen großer TXT-Einträge behoben.
- Der DNS-Client kann intern parallel abfragen, um mehrere Forwarder gleichzeitig zu fragen und die schnellste Antwort zu verwenden.
- Der DNS-Client kann Einträge per Zonentransfer importieren.
- Mehrere weitere Fehlerbehebungen in den DNS- und DHCP-Modulen.
