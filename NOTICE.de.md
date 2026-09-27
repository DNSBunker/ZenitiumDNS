# Hinweis

[English version](NOTICE.md)

ZenitiumDNS ist eine veränderte Fassung der folgenden Werke:

- **Technitium DNS Server** Version 15.5.1, Copyright (C) 2026 Shreyas Zare (shreyas@technitium.com), https://github.com/TechnitiumSoftware/DnsServer
- **TechnitiumLibrary**, Copyright (C) 2026 Shreyas Zare (shreyas@technitium.com), https://github.com/TechnitiumSoftware/TechnitiumLibrary

Beide Werke stehen unter der GNU General Public License Version 3 oder (nach deiner Wahl) jeder späteren Version. ZenitiumDNS wird unter derselben Lizenz verbreitet. Der vollständige Lizenztext steht in der Datei [LICENSE](LICENSE). Die ursprünglichen Urheberrechts- und Lizenzhinweise in den Quelldateien wurden beibehalten.

Die Änderungen und Ergänzungen von ZenitiumDNS: Copyright (C) 2026 xRuffKez. Veränderte Quelldateien tragen diesen Hinweis zusätzlich zum ursprünglichen, neu hinzugekommene Dateien einen eigenen Lizenzkopf.

Der Name „Technitium“ wird hier nur verwendet, um die Herkunft dieses Werks anzugeben. ZenitiumDNS steht in keiner Verbindung zu Technitium oder dem ursprünglichen Autor und wird von ihnen nicht unterstützt.

## Mitgelieferte Schriften

Die Weboberfläche enthält die Schriften **Red Hat Text**, **Red Hat Display** und **Red Hat Mono**, Copyright 2024 The Red Hat Project Authors (https://github.com/RedHatOfficial/RedHatFont). Sie stehen unter der SIL Open Font License 1.1, deren Text in `src/ZenitiumDns.Core/www/fonts/RedHatFont-OFL.txt` liegt.

## Änderungen

Die folgenden Änderungen wurden im September 2026 vorgenommen:

- Das Produkt wurde in ZenitiumDNS umbenannt. Logos, Symbole, Produktnamen, User-Agents, Dienstnamen, Registrierungsschlüssel, Installationspfade und Log-Pfade wurden ersetzt.
- Die Repositorys von DNS-Server und Bibliothek wurden zu einem Quellbaum mit einer Solution (`ZenitiumDNS.slnx`) zusammengeführt. Statt vorkompilierter Assemblys werden Projektreferenzen verwendet, gemeinsame Build-Eigenschaften stehen in `Directory.Build.props`.
- Namensräume und Assemblys wurden von `TechnitiumLibrary.*` in `ZenitiumLibrary.*` und von `DnsServerCore.*` in `ZenitiumDns.*` umbenannt. Die Assembly des Server-Hosts wurde ebenfalls umbenannt.
- Nicht vom DNS-Server verwendete Bibliotheksprojekte wurden entfernt (BitTorrent, Tor, UPnP, Security.Cryptography).
- Alle Verbindungen zur Infrastruktur des Originalprojekts wurden entfernt. Die Update-Prüfung fragt die Releases von ZenitiumDNS auf GitHub ab und lässt sich über `DNS_SERVER_UPDATE_CHECK_URL` umstellen oder abschalten. Den DNS-App-Store gibt es nicht mehr, alle Apps werden mit dem Paket ausgeliefert.
- Der Linux-Installer installiert aus einem lokalen Build, statt Binärdateien des Originals herunterzuladen. Neu hinzugekommen ist ein eigenständiges Debian-Paket.
- Der Funktionsumfang wurde auf den Betrieb als öffentlicher rekursiver Resolver reduziert. Entfernt wurden autoritative Zonen (Primary, Secondary, Stub, Secondary Forwarder, Catalog), DNSSEC-Signierung, Zonentransfers (AXFR/IXFR, XFR-over-TLS/QUIC), DNS NOTIFY, dynamische Updates, TSIG, der DHCP-Server, das Clustering samt HTTP-API-Client, die für LAN- und Hosting-Szenarien gedachten DNS-Apps sowie Windows-Dienst, Systemtray-App, Windows-Firewall-Bibliothek und Windows-Installer. Conditional-Forwarder-Zonen, Blocklisten sowie erlaubte und blockierte Domains bleiben erhalten.
- Statistik und Überwachung wurden um Antwortzeiten (Median, Perzentile, Cache/rekursiv), Live-Kennzahlen und zusätzliche Metriken erweitert. Die Weboberfläche wurde neu gegliedert und um Einstellungen für IPv6-Rückfall, UDP-Empfangs-Threads und Pipelining-Limit ergänzt.
- Weboberfläche und Dokumentation wurden ins Deutsche übersetzt. Zusätzlich gibt es eine vollständige englische Fassung, die Sprache ist nach der Installation wählbar.
- Die Weboberfläche erhielt ein neues Design. Die GIF-Ladeanimationen und die Stylesheets für Dunkel- und Bernstein-Modus wurden durch ein gemeinsames Stylesheet ersetzt.
- Neu hinzugekommen sind ein Anfragefilter für den öffentlichen Betrieb, die DNSSEC-Validierung von ML-DSA-44 und das Aktivieren und Deaktivieren einzelner Apps. Das Docker-Image wurde entfernt.
- Kommentare wurden aus dem Quellcode entfernt. Die Urheberrechts- und Lizenzköpfe der Quelldateien blieben dabei erhalten.
- Zahlreiche Fehler, Sicherheitsprobleme und Performance-Engpässe wurden behoben. Die vollständige Liste steht in [CHANGELOG-ZenitiumDNS.de.md](CHANGELOG-ZenitiumDNS.de.md).
