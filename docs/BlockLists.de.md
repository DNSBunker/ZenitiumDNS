# Blocklisten und Clientprofile

[English version](BlockLists.md)

ZenitiumDNS liest Block- und Erlaubnislisten in mehreren Formaten und kann verschiedenen Geräten verschiedene Listen zuweisen. Listen werden unter Einstellungen > Blockierung eingetragen (eine URL pro Zeile) und automatisch heruntergeladen und aktualisiert. Lokale Dateien funktionieren mit `file:///pfad/zur/liste.txt`; beim Debian-Paket muss der Dienst sie lesen dürfen (siehe README.Debian).

## Listenformate

Alle Formate lassen sich in einer Liste mischen. Zeilen, die mit `!`, `#` oder `[` beginnen, sind Kommentare.

| Format | Beispiel | Wirkung |
| ------ | -------- | ------- |
| Reine Domain | `example.com` | Blockiert die Domain und alle Subdomains. |
| Wildcard-Domain | `*.example.com` | Wie eine reine Domain (kompatibel zu Wildcard-Listen). |
| hosts-Datei | `0.0.0.0 ads.example.com tracker.example.com` | Blockiert jeden Hostnamen der Zeile samt Subdomains; `localhost` und ähnliche Einträge werden ignoriert. |
| Adblock-Domainregel | `\|\|example.com^` | Blockiert die Domain und alle Subdomains. |
| Exakte Regel | `\|example.com^` | Blockiert nur genau diesen Namen, nicht seine Subdomains. |
| Nur Subdomains | `\|\|*.example.com^` | Blockiert alle Subdomains, nicht die Domain selbst. |
| Platzhaltermuster | `\|\|ads*.example.com^`, `tracker-*.net` | `*` steht für beliebige Zeichen einschließlich Punkten. |
| Regulärer Ausdruck | `/^ad[0-9]+\.example\.com$/` | Passt auf den kleingeschriebenen Namen ohne abschließenden Punkt. |
| Ausnahme | `@@\|\|good.example.com^` | Erlaubt den Namen wieder (funktioniert auch für Muster und reguläre Ausdrücke). |
| IP-Adresse oder Netz | `192.0.2.1`, `198.51.100.0/24`, `2001:db8::/32` | Blockiert Antworten, deren A- oder AAAA-Einträge auf die Adresse zeigen (siehe unten). |

### Modifikatoren

Adblock-Regeln können nach `$` Modifikatoren tragen:

| Modifikator | Beispiel | Wirkung |
| ----------- | -------- | ------- |
| `important` | `\|\|example.com^$important` | Hat Vorrang vor Ausnahmen und Erlaubnislisten. Eine Ausnahme mit `$important` hat wiederum Vorrang davor. |
| `badfilter` | `\|\|example.com^$badfilter` | Schaltet die gleiche Regel ohne `badfilter` ab, auch in anderen Listen. |
| `dnstype` | `\|\|example.com^$dnstype=AAAA\|HTTPS`, `$dnstype=~TXT` | Nur für diese Abfragetypen oder für alle außer diesen (`~`). |
| `denyallow` | `\|\|example.com^$denyallow=cdn.example.com` | Blockiert die Domain, aber nicht die genannten Domains und ihre Subdomains. |
| `client` | `\|\|games.example^$client='Kinder'\|192.168.1.0/24`, `$client=~buero` | Nur für diese Clients oder für alle außer diesen (`~`). Ein Client passt über IP-Adresse oder Netz, über den Namen seines Clientprofils oder über seine ClientID. Namen mit Leerzeichen oder Kommas stehen in Anführungszeichen. |

Regeln für Elemente von Webseiten (`##`, `#@#`, `#?#`, `#$#`, `$$`) und Modifikatoren ohne Bedeutung für DNS (zum Beispiel `$third-party` oder `$script`) werden übersprungen; der Listenstatus zeigt, wie viele Zeilen das waren. `$ctag` wird nicht unterstützt.

### Pi-hole-Regex-Listen

Listen im Format der Regex-Filter von Pi-hole funktionieren ohne Anpassung: ein regulärer Ausdruck pro Zeile, optional gefolgt von `;querytype=AAAA` oder `;querytype=!A,AAAA`. POSIX-Zeichenklassen wie `[[:alnum:]]` oder `[[:space:]]` werden übersetzt. Ausdrücke, die Backtracking brauchen (Rückverweise, Lookaround), werden übersprungen, weil alle Ausdrücke mit der Engine ohne Backtracking von .NET und einem Zeitlimit von 50 ms laufen; eine Liste kann den Server so nicht ausbremsen. Pro Liste werden bis zu 10.000 Ausdrücke geladen.

### Blockierung über die Antwortadresse

IP-Adressen und Netze in einer Blockliste blockieren keine Namen, sondern Antworten: Enthält eine Antwort einen A- oder AAAA-Eintrag mit einer gelisteten Adresse, bekommt der Client stattdessen die Blockierantwort (mit dem Extended DNS Error „Blocked“ und der Quelle `block-list-ip <Adresse>`). Das gilt auch für Antworten aus dem Cache. Adressen in einer Erlaubnisliste nehmen sie aus. Netze müssen bei IPv4 mindestens /8 und bei IPv6 mindestens /16 groß sein; `0.0.0.0` und `::` werden ignoriert, weil viele hosts-Dateien sie als Ziel verwenden.

### Reihenfolge der Auswertung

1. Ausnahmen mit `$important`
2. Blockregeln mit `$important`
3. Erlaubnislisten und Ausnahmen (`@@`)
4. Blockregeln

Manuell erlaubte Domains (Filter > Erlaubte Domains) werden vor allen Listen geprüft, manuell blockierte Domains vor den Blocklisten.

## Clientprofile

Clientprofile (Filter > Clients) legen fest, welche Listen für welche Geräte gelten, ähnlich den dauerhaften Clients von AdGuard Home. Anfragen von Geräten ohne Profil nutzen die Standard-Blocklisten.

Ein Profil enthält:

- **Kennungen**, eine pro Zeile: eine IP-Adresse (`192.168.1.20`), ein Netz (`192.168.2.0/24`) oder eine ClientID (`kinder`, Kleinbuchstaben, Ziffern und Bindestriche, höchstens 63 Zeichen). Eine Kennung kann nur zu einem Profil gehören.
- **Blockierung aktiv**: ausgeschaltet werden alle Anfragen dieser Geräte ungefiltert beantwortet, auch manuell blockierte Domains.
- **Standard-Blocklisten verwenden**: ausgeschaltet gelten nur die eigenen Listen des Profils; manuell blockierte und erlaubte Domains bleiben wirksam.
- **Eigene Listen**: zusätzliche Block- oder Erlaubnislisten (`!` vor der URL) in denselben Formaten wie oben.

Jede Liste wird nur einmal heruntergeladen und geladen, auch wenn mehrere Profile sie nutzen; jede Anfrage wird gegen die Listen ihres Profils geprüft. Der Listenstatus unter Einstellungen > Blockierung zeigt, welche Profile eine Liste nutzen, und kennzeichnet Listen, die nur von Profilen genutzt werden.

### Geräte erkennen

Das Profil wird in dieser Reihenfolge gewählt: ClientID, genaue IP-Adresse, kleinstes Netz.

Die ClientID kommt aus verschlüsseltem DNS:

| Protokoll | Adresse für die ClientID `kinder` |
| --------- | --------------------------------- |
| DNS-over-HTTPS | `https://dns.example.com/dns-query/kinder` |
| DNS-over-TLS | Servername `kinder.dns.example.com` |
| DNS-over-QUIC | Servername `kinder.dns.example.com` |

Für DoT und DoQ muss das TLS-Zertifikat auch für `*.dns.example.com` gelten. Der erste Teil des Servernamens zählt nur als ClientID, wenn ein Profil sie verwendet; der normale Servername funktioniert also weiter. Hinter einem Reverse Proxy für DoH muss der Pfad unverändert weitergegeben werden. Normales DNS über Port 53 kennt nur die IP-Adresse.

### API

| Aufruf | Parameter |
| ------ | --------- |
| `api/settings/clients/list` | keine; liefert die Profile, die Standardlisten sowie Servername und Ports, die für ClientIDs gebraucht werden |
| `api/settings/clients/set` | `name`, `identifiers` (zeilen- oder kommagetrennt), `blockingEnabled`, `useDefaultLists`, `blockListUrls` (zeilen- oder kommagetrennt), `originalName` zum Ändern eines vorhandenen Profils |
| `api/settings/clients/delete` | `name` |

Lesen erfordert die Berechtigung, Einstellungen anzusehen, Ändern die Berechtigung, sie zu ändern. Profile stehen in `clients.json` im Konfigurationsverzeichnis und sind zusammen mit den Blocklisten Teil der Sicherung.
