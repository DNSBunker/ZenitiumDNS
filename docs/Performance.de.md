# Performance im Vergleich mit Technitium DNS Server

[English version](Performance.md)

ZenitiumDNS ist ein Fork von Technitium DNS Server 15.5.1. Dieses Dokument zeigt, was der Fork an Geschwindigkeit und Speicherbedarf verändert, mit Messungen, die jeder wiederholen kann, und nennt die Codeänderungen dahinter. Es führt auch auf, wo ZenitiumDNS nicht besser ist.

## Zusammenfassung

Gemessen auf derselben Maschine, mit derselben .NET-Laufzeit, denselben Einstellungen und derselben Last, gegen die aktuelle Version Technitium DNS Server 15.5.1 (Mediane aus je drei Läufen):

- **54 bis 70 % weniger CPU-Zeit pro Anfrage**: 10,2 statt 31,2 µs für Antworten aus dem Cache, 11,2 statt 37,7 µs, wenn die Hälfte der Anfragen Blocklisten trifft, 56 statt 122 µs über DNS-over-TLS und 385 statt 837 µs pro rekursiver Auflösung.
- **Etwa doppelter Durchsatz** auf vier logischen CPUs: 500.000 statt 251.000 Antworten pro Sekunde aus dem Cache.
- **Hält mit vielen neuen Namen mit**: Bei 20.000 neuen Namen pro Sekunde beantwortete ZenitiumDNS alle Anfragen mit einer mittleren Latenz von 0,5 ms; Technitium beantwortete 88 % mit einer mittleren Latenz von 1,1 Sekunden, der Rest ging verloren.
- **81 % weniger Speicher pro Name im Cache** (rund 0,8 statt 4,3 KB) und **60 % weniger Speicher für Blocklisten** (216 statt 537 MB für 2,5 Millionen Domains).
- **Keine Lock-Konflikte** bei rekursiver Auflösung und über DNS über TCP, DoT und DoQ (Einzelheiten unten); die ursprüngliche Auslegung verursachte Hunderte bis Tausende umkämpfte Sperren pro Sekunde. Auf einem Server mit 8 CPUs brauchten 700 Anfragen pro Sekunde vorher 2,42 ms CPU-Zeit pro Anfrage, jetzt 0,46 ms.
- **Niedrigerer Median der Latenz** in jedem Test und weniger Ausreißer bei rekursiver Auflösung (99. Perzentil 2,5 statt 3,6 ms), dafür sind bei **Antworten aus dem Cache das 99. und 99,9. Perzentil höher** (365 statt 265 µs und 1,0 statt 0,7 ms).

## Ergebnisse

Maschine: Intel Core i7-12700H (Laptop, 6 Performance- und 8 Effizienzkerne, 20 logische CPUs), 64 GB RAM, Fedora 44, Linux 7.2.7, .NET 10.0.12 für beide Server. Der DNS-Server lief auf 4 logischen CPUs (zwei Performance-Kerne), die Lastgeneratoren auf 8 anderen logischen CPUs. Technitium DNS Server 15.5.1 ist die portable Version von download.technitium.com (1. Oktober 2026), ZenitiumDNS der Entwicklungsstand nach Version 15.5.1-11 einschließlich der unter [Lock-Konflikte](#lock-konflikte) beschriebenen Änderungen. Jeder Server lief dreimal, abwechselnd. Die Rohdaten stehen in [performance-data/2026-10-01](performance-data/2026-10-01).

| Messung (Median aus je 3 Läufen) | Technitium 15.5.1 | ZenitiumDNS | Änderung |
| --- | ---: | ---: | ---: |
| Belegter Speicher nach dem Start (MB) | 113 | 115 | +2 % |
| Cache-Treffer, 40.000 Anfragen/s: CPU-Zeit pro Anfrage (µs) | 31,2 | 10,2 | −67 % |
| Cache-Treffer, 40.000 Anfragen/s: Median der Latenz (µs) | 135 | 125 | −7 % |
| Cache-Treffer, 40.000 Anfragen/s: 99. Perzentil (µs) | 265 | 365 | +38 % |
| Cache-Treffer, 40.000 Anfragen/s: 99,9. Perzentil (µs) | 675 | 1.015 | siehe unten |
| Cache-Treffer: höchste Zahl Antworten pro Sekunde | 251.105 | 499.532 | +99 % |
| DNS-over-TLS, Cache-Treffer, 8.000 Anfragen/s: CPU-Zeit pro Anfrage (µs) | 121,7 | 56,2 | −54 % |
| DNS-over-TLS, Cache-Treffer, 8.000 Anfragen/s: Median der Latenz (µs) | 135 | 75 | −44 % |
| DNS-over-TLS, Cache-Treffer, 8.000 Anfragen/s: 99. Perzentil (µs) | 935 | 935 | ±0 % |
| Rekursive Auflösung, 2.000 neue Namen/s: CPU-Zeit pro Anfrage (µs) | 837 | 385 | −54 % |
| Rekursive Auflösung, 2.000 neue Namen/s: Median der Latenz (µs) | 225 | 215 | −4 % |
| Rekursive Auflösung, 2.000 neue Namen/s: 99. Perzentil (µs) | 3.635 | 2.495 | −31 % |
| Rekursive Auflösung, 2.000 neue Namen/s: 99,9. Perzentil (µs) | 7.985 | 5.225 | −35 % |
| 20.000 neue Namen/s über 50 s: beantwortete Anfragen (von 1 Million) | 883.110 | 999.991 | +13 % |
| 20.000 neue Namen/s über 50 s: mittlere Latenz (ms) | 1.137,8 | 0,5 | −100 % |
| 20.000 neue Namen/s über 50 s: belegter Speicher (MB) | 3.947 | 894 | −77 % |
| 20.000 neue Namen/s über 50 s: Speicher pro Name im Cache (Byte) | 4.262 | 817 | −81 % |
| Blocklisten HaGeZi Pro + TIF, 2.493.399 Domains: belegter Speicher (MB) | 537 | 216 | −60 % |
| 50 % blockierte Namen, 40.000 Anfragen/s: CPU-Zeit pro Anfrage (µs) | 37,7 | 11,2 | −70 % |
| 50 % blockierte Namen, 40.000 Anfragen/s: Median der Latenz (µs) | 145 | 115 | −21 % |
| 50 % blockierte Namen, 40.000 Anfragen/s: 99. Perzentil (µs) | 335 | 325 | −3 % |

Für den Höchstdurchsatz boten die Lastgeneratoren in jedem Lauf 622.000 bis 750.000 Anfragen pro Sekunde an, mehr als einer der beiden Server beantwortete.

„20.000 neue Namen/s“ ist der härteste Test für einen Resolver: Jede Anfrage braucht eine rekursive Auflösung und einen neuen Cache-Eintrag. Technitium kam auf vier CPUs nicht mit; seine Warteschlange lief voll, die Latenz stieg auf rund eine Sekunde, und 3,5 bis 12 % der Anfragen blieben unbeantwortet. Dabei nutzte es nur etwa die Hälfte der vier CPUs. ZenitiumDNS beantwortete jede Anfrage. Die CPU-Zeit pro Anfrage ist in diesem Test deshalb nicht vergleichbar und fehlt.

Der Test mit DNS-over-TLS schickt 8.000 Anfragen pro Sekunde über 32 Verbindungen mit Pipelining an Namen, die schon im Cache liegen; der Lastgenerator ist `tools/benchmark/tlsload`.

## Lock-Konflikte

Auf einem Produktivserver zeigte der Live-Graph von ZenitiumDNS 15.5.1-11 bei einem Median von 700 Anfragen pro Sekunde rund 400 umkämpfte Sperren pro Sekunde. Mitschnitte der Konflikte (`dotnet-trace`, Contention-Ereignisse mit Stacks) führten zu zwei Teilen, die ZenitiumDNS aus dem Original übernommen hatte:

1. **Pool für rekursive Auflösungen.** Das Original betreibt für jede erlaubte gleichzeitige Auflösung (standardmäßig 100 pro CPU, auf vier CPUs also 400) eine wartende Schleife an einem .NET-Channel. Jede neue Auflösung weckt *alle* wartenden Schleifen; eine bekommt die Arbeit, alle anderen nehmen die Sperre des Channels, finden nichts und melden sich mit einer neuen Allokation wieder an. ZenitiumDNS ersetzt das durch eine sperrfreie Begrenzung (eine Warteschlange und ein Zähler), die Auflösungen direkt auf dem .NET-Threadpool startet.
2. **Eigener Scheduler für DNS über TCP, DoT und DoQ.** Fertige Lesevorgänge auf diesen Verbindungen kommen ohnehin auf einem Threadpool-Thread an und wurden dann über einen Semaphor unter einer Sperre an einen eigenen Thread übergeben. Diese Verbindungen laufen jetzt auf dem Threadpool, wie es DNS-over-HTTPS (Kestrel) schon tat; der Scheduler wurde entfernt.

Umkämpfte Sperren pro Sekunde auf vier CPUs (Live-Graph und `dotnet_monitor_lock_contentions_total`):

| Last | 15.5.1-11 | jetzt |
| --- | ---: | ---: |
| UDP, 700 Anfragen/s, alle aus dem Cache | 1,4 | 0,0 |
| UDP, 700 neue Namen/s (rekursive Auflösung) | 287 | 0,0 |
| UDP, 5.000 neue Namen/s | 2.537 | 0,6 |
| DNS-over-HTTPS, 700 Anfragen/s, 30 % neue Namen | 145 | 0,2 |
| DNS-over-TLS, 700 Anfragen/s, alle aus dem Cache | 152 | 0,0–0,1 |
| DNS-over-TLS, 700 Anfragen/s, 30 % neue Namen | 232 | 0,0–0,1 |
| DNS-over-TLS, 8.000 Anfragen/s, alle aus dem Cache | 1.357–1.592 | 0,6–0,7 |

Die Konflikte waren nicht nur eine Zahl im Graphen: Im direkten Vergleich auf derselben Maschine sank die CPU-Zeit pro rekursiver Auflösung von 637–644 auf 372–379 µs und pro Anfrage über DNS-over-TLS bei 8.000 Anfragen pro Sekunde von 102–115 auf 60–63 µs.

Auf einem Server mit mehr CPUs ist der Effekt größer, weil das Original 100 wartende Schleifen pro CPU startet. Der Testserver (Debian-13-Container mit 8 logischen CPUs auf Proxmox, dasselbe Paket einmal als 15.5.1-11 und einmal mit diesen Änderungen) erhielt eine Minute lang 700 Anfragen pro Sekunde für nicht existierende Top-Level-Domains, die die lokale Root-Zone ohne Anfrage ins Internet beantwortet; jede Anfrage läuft also durch den Resolver:

| 8 CPUs, 700 Anfragen/s | 15.5.1-11 | jetzt |
| --- | ---: | ---: |
| Umkämpfte Sperren pro Sekunde | 1.700–2.170 | 0–0,2 |
| CPU-Zeit pro Anfrage | 2,42 ms | 0,46 ms |
| Arbeitsschritte des .NET-Threadpools pro Sekunde | rund 553.000 | rund 1.400 |
| Latenz: Median / 99. / 99,9. Perzentil | 426 µs / 2,5 ms / 8,9 ms | 166 µs / 463 µs / 5,4 ms |
| Zeitanteil der Pausen durch Garbage Collection | rund 2 % | rund 0,1 % |

553.000 Arbeitsschritte pro Sekunde sind 700 Auflösungen mal die 800 wartenden Schleifen, die jede davon geweckt hat.

## Ausreißer bei der Latenz

### Antworten aus dem Cache

Das 99. und 99,9. Perzentil bei Antworten aus dem Cache sind der einzige Bereich, in dem ZenitiumDNS schlechter abschnitt. Die einzelnen Läufe streuen stark:

| Cache-Treffer, 40.000 Anfragen/s | Median | 99. Perzentil | 99,9. Perzentil |
| --- | ---: | ---: | ---: |
| Technitium, Lauf 1 / 2 / 3 | 135 / 135 / 145 µs | 245 / 265 / 285 µs | 635 / 675 / 875 µs |
| ZenitiumDNS, Lauf 1 / 2 / 3 | 125 / 105 / 125 µs | 445 / 255 / 365 µs | 1.225 / 635 / 1.015 µs |

Von 1.000 Antworten braucht etwa eine länger als 1 ms. Eine Zeitleiste pro Sekunde zeigt, dass sie über den ganzen Lauf verteilt sind und nicht an einem einzelnen Ereignis hängen. Drei Erklärungen wurden geprüft und verworfen:

- **Art der Garbage Collection**: Mit Workstation-GC statt Server-GC blieben die Perzentile gleich (99,9. Perzentil 935–1.145 µs gegenüber 995–1.125 µs).
- **UDP-Empfangsthreads**: ZenitiumDNS antwortet mit einem Empfangsthread pro Socket und weckt weitere Threads erst bei anhaltendem Rückstau. Sie schon nach 4 oder sogar 1 wartenden Paket statt nach 16 zu wecken, verdoppelte die CPU-Zeit pro Anfrage (17–22 µs) und verschlechterte das 99. Perzentil, statt es zu verbessern.
- **Zeitscheibe des Linux-Schedulers**: Seit Linux 6.12 kann ein Thread eine kürzere Zeitscheibe anfordern (`sched_setattr` mit `sched_runtime`). Empfangsthreads mit 0,1 ms, allein oder zusammen mit einer niedrigeren Priorität (nice 5) für den Statistik-Thread, ergaben in je drei abwechselnden Läufen ein 99. Perzentil von 385–575 µs und ein 99,9. Perzentil von 955–4.885 µs, denselben Bereich wie ohne. Die Änderung wurde nicht übernommen.

Für einen DNS-Resolver liegt die zusätzliche Zeit deutlich unter der Laufzeit, die ein Client im Netz ohnehin hat (meist mehrere Millisekunden). Sie steht trotzdem hier, weil sie ein messbarer Unterschied ist.

### Rekursive Auflösung

Mit den wartenden Schleifen (siehe [Lock-Konflikte](#lock-konflikte)) verschwand auch der größte Teil des Speichermülls, den sie erzeugten. Die .NET-Laufzeit, die bei dieser Last mit einem einzigen Collector-Heap arbeitet (DATAS), sammelte die jüngste Generation danach nur noch alle 1,8 Sekunden und musste dabei jedes Mal rund 3 MB neuer Cache-Einträge kopieren, was den Prozess 15 bis 35 ms anhielt. Bei 2.000 neuen Namen pro Sekunde stieg das 99,9. Perzentil auf 30–40 ms. Die Laufzeit-Einstellungen für das Budget der jüngsten Generation (`GCgen0size`, `GCgen0MaxBudget`, `GCDTargetTCP`) wirken in diesem Modus nicht; ohne DATAS gab es eine Sammlung alle 10 Sekunden mit 12 MB und 20 ms.

ZenitiumDNS startet deshalb eine kurze Sammlung der jüngsten Generation, sobald seit der letzten Sammlung 150 neue Cache-Einträge entstanden sind (Prüfung alle 50 ms). Jede Pause kopiert dann nur wenige hundert Kilobyte. Je drei abwechselnde Läufe pro Variante bei 2.000 neuen Namen pro Sekunde:

| Rekursive Auflösung, 2.000 neue Namen/s | 15.5.1-11 | ohne Steuerung | alle 300 Einträge, Prüfung alle 100 ms | alle 150 Einträge, Prüfung alle 50 ms (übernommen) |
| --- | ---: | ---: | ---: | ---: |
| 99. Perzentil | 2,9–3,2 ms | 4,1–6,1 ms | 3,4–4,2 ms | 2,3–2,4 ms |
| 99,9. Perzentil | 5,0–11,0 ms | 31–39 ms | 6,7–9,2 ms | 4,2–5,7 ms |
| CPU-Zeit pro Auflösung | 637–644 µs | 358–373 µs | 345–361 µs | 372–379 µs |

Die Zahl dieser Sammlungen steht in der Metrik `zenitiumdns_gc_paced_collections_total`. Ohne neue Cache-Einträge (Antworten aus dem Cache, voller Cache, abgeschalteter Cache) laufen keine zusätzlichen Sammlungen.

## Was sich im Code geändert hat

Die Unterschiede oben stammen aus Änderungen am Anfragepfad, am Cache, an den Blocklisten und an der Statistik. Die wichtigsten mit den betroffenen Dateien:

| Bereich | Änderung | Dateien |
| ------- | -------- | ------- |
| UDP-Empfangspfad | Eigene Empfangsthreads (höchstens 8 pro Socket, einstellbar bis 64) beantworten Cache-Treffer auf dem empfangenden Thread, ohne Übergabe an den Threadpool; weitere Threads werden nur bei anhaltendem Rückstau geweckt. Antworten werden synchron mit wiederverwendeten Sendepuffern verschickt. | `src/ZenitiumDns.Core/Dns/DnsServer.cs` (`StartUdpListenerThreads`, `ReadUdpRequests`), `Dns/UdpListenerGate.cs`, `Dns/UdpSendBuffers.cs` |
| Rekursive Auflösungen | Sperrfreie Begrenzung gleichzeitiger Auflösungen statt Hunderter wartender Schleifen, die bei jeder Auflösung alle geweckt wurden; Auflösungen starten direkt auf dem .NET-Threadpool. | `src/ZenitiumLibrary/TaskPool.cs`, `Dns/DnsServer.cs` |
| DNS über TCP, DoT, DoQ | Verbindungen laufen auf dem .NET-Threadpool statt auf einem eigenen Scheduler mit einer Sperre bei jeder Übergabe. | `Dns/DnsServer.cs` |
| Allokationen im Anfragepfad | `ValueTask` in der Verarbeitungskette, Namenskompression ohne Kopien, keine temporären Zeichenketten bei der Prüfung besonderer Zonen, keine geboxten Enumeratoren in heißen Schleifen, Zeitpunkt der letzten Nutzung höchstens einmal pro Sekunde geschrieben. Rund 1 KB statt 2,9 KB Allokation pro Cache-Treffer. | `Dns/DnsServer.cs`, `src/ZenitiumLibrary.Net/Dns/`, `Dns/ResourceRecords/CacheRecordInfo.cs` |
| Statistik | Anfragen laufen über eine sperrfreie Warteschlange zu einem eigenen Thread, statt im Anfragepfad unter Sperren gezählt zu werden; eindeutige Clients werden mit HyperLogLog gezählt; abgeschlossene Minuten behalten nur die Top 1.000. | `Dns/StatsManager.cs`, `Dns/UniqueAddressCounter.cs` |
| Aufbau des Caches | Einträge eines Namens in einem kleinen Copy-on-Write-Array statt eines Concurrent Dictionary pro Name, gemeinsam genutzte Nameserver-Metadaten, Knoten des Domainbaums mit passend großen Kind-Arrays (bis 8 Kinder) statt 41 Plätzen, keine zweite Rohkopie der Daten von A, AAAA und RRSIG. | `Dns/Zones/CacheZone.cs`, `Dns/Zones/CacheEntrySet.cs`, `src/ZenitiumLibrary.ByteTree/ByteTree.cs`, `src/ZenitiumLibrary.Net/Dns/ResourceRecords/` |
| Blocklisten | Domains als ASCII in 1-MB-Blöcken mit einer Hashtabelle aus 8-Byte-Plätzen statt Millionen Zeichenketten in Dictionaries; ein gemeinsamer Regelsatz für alle Clientprofile. | `Dns/ZoneManagers/DomainTable.cs`, `Dns/ZoneManagers/ListRuleSet.cs` |
| Garbage Collection | Das Original lief in der Cache-Wartung jede Minute eine blockierende vollständige Garbage Collection (Upstream-Issue #2174); ZenitiumDNS nutzt dort Hintergrund-Sammlungen. Kurze Sammlungen der jüngsten Generation nach 150 neuen Cache-Einträgen halten einzelne Pausen kurz. Server-GC mit nebenläufiger Sammlung. | `Dns/ZoneManagers/CacheZoneManager.cs`, `src/ZenitiumDns/ZenitiumDns.csproj` |
| Weniger Anfragen an Nameserver | Prefetch erst im letzten Zehntel der TTL (24 Client-Anfragen lösten im Original 24 Anfragen an Nameserver aus, in ZenitiumDNS 2), aggressive Nutzung DNSSEC-geprüfter NSEC/NSEC3-Einträge (20.000 zufällige Subdomains einer signierten Zone lösten 30 bis 48 statt 20.000 Anfragen aus), IPv6-Rückfall ohne Timeouts, lokale Kopie der Root-Zone (RFC 8806). | `Dns/ZoneManagers/CacheZoneManager.cs`, `Dns/AggressiveNsecCache.cs`, `Dns/IanaDataManager.cs` |
| Speicherschutz | Der Cache wächst ab 85 % des Arbeitsspeichers, der Speichergrenze des Dienstes oder Containers oder der Heap-Grenze von .NET nicht weiter und wird ab 90 % gekürzt, statt in einen Absturz durch Speichermangel zu laufen. | `Dns/MemoryPressure.cs`, `Dns/ZoneManagers/CacheZoneManager.cs` |

## Frühere Messungen

Während der Entwicklung wurde ZenitiumDNS außerdem mit `dnsperf` auf 20 CPUs gegen Technitium DNS Server 15.5 gemessen ([CHANGELOG-ZenitiumDNS.de.md](../CHANGELOG-ZenitiumDNS.de.md)). Diese Zahlen zeigen in dieselbe Richtung: CPU-Zeit pro Anfrage bei 100.000 Anfragen/s 23,6 statt 85,8 µs, Allokation pro Cache-Treffer rund 1,0 statt 2,9 KB, Zeitanteil der Garbage Collection unter Volllast 7 statt 22 %, Sperrkonflikte pro Sekunde 41 statt 1.798. Mit 20 CPUs lag der Höchstdurchsatz nur 5 bis 12 % höher, weil dort Lastgenerator und Netzwerkstack einer einzelnen Maschine zur Grenze werden.

## Messungen wiederholen

Lastgeneratoren, simulierte Root- und Top-Level-Domain-Server und das Skript liegen in [tools/benchmark](../tools/benchmark/README.de.md). Ein Lauf dauert pro Server etwa fünf bis acht Minuten:

```
unshare -rnm bash tools/benchmark/bench.sh zenitiumdns zenitiumdns /pfad/zu/zenitiumdns /pfad/zu/listen
unshare -rnm bash tools/benchmark/bench.sh technitium technitium /pfad/zu/technitium /pfad/zu/listen
python3 tools/benchmark/summarize.py Technitium tools/benchmark/results/technitium/results.txt -- ZenitiumDNS tools/benchmark/results/zenitiumdns/results.txt
```

Beide Server erhalten dieselben Einstellungen: DNSSEC-Validierung aus (die simulierten Zonen sind unsigniert), 100.000 Cache-Einträge (Standard bei Technitium 10.000), DNS-over-TLS mit einem selbstsignierten Zertifikat und die Lastnetze von der Ratenbegrenzung ausgenommen. Alles andere bleibt auf den Standardwerten einer Neuinstallation.

## Grenzen dieser Messungen

- Die Last kommt vom selben Rechner über das Loopback-Gerät; die Zahlen zeigen den Verarbeitungsaufwand im Server, keine Netzwerkeffekte.
- Die simulierten autoritativen Server antworten sofort. Im Internet bestimmen die Laufzeiten zu den echten Nameservern die Dauer einer rekursiven Auflösung.
- Eine Laptop-CPU ändert ihren Takt; einzelne Läufe streuen, besonders bei den Ausreißer-Perzentilen. Mediane mehrerer abwechselnder Läufe vergleichen.
- DNS-over-TLS wird mit Antworten aus dem Cache bei fester Rate gemessen. DNS-over-HTTPS und DNS-over-QUIC sind nicht Teil des Vergleichs; die Zahlen zu Lock-Konflikten bei DNS-over-HTTPS stammen aus der eigenen Messung oben.
