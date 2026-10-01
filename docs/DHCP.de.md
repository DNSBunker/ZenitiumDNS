# DHCP-Server

[English version](DHCP.md)

ZenitiumDNS enthält einen DHCP-Server für IPv4 und IPv6. Er vergibt Adressen, kündigt per Router Advertisement Präfix und DNS-Server an, trägt die Namen der Geräte in das lokale DNS ein und erkennt andere DHCP-Server und IPv6-Router im Netz. Eingerichtet wird er in der Weboberfläche unter **DHCP**; nach der Installation ist er ausgeschaltet.

## Einfache Einstellungen

Für ein einzelnes Netz genügt der Reiter **Einstellungen**:

| Einstellung | Bedeutung |
| ----------- | --------- |
| Schnittstelle | Automatisch antwortet auf jeder Schnittstelle, deren Netz zum Adressbereich passt. Für IPv6 muss eine Schnittstelle gewählt sein, weil die Präfixe von ihr stammen. |
| Adressbereich | Erste und letzte Adresse, die vergeben wird. |
| Netzmaske | Leer übernimmt das Präfix der Schnittstelle. |
| Gateway | Leer sendet das Standard-Gateway der Schnittstelle, sofern es im selben Netz liegt. |
| DNS-Server | Leer sendet die Adresse dieses Servers; die Geräte nutzen dann ZenitiumDNS mit allen Filtern. |
| Domain | Geräte sind unter `name.domain` erreichbar; unbekannte Namen in dieser Domain beantwortet der Server selbst mit NXDOMAIN. Für ein privates Netz eignen sich `home.arpa` oder `lan`. |
| Lease-Dauer | Etwa `30m`, `12h`, `7d` oder `infinite`; mindestens 2 Minuten. |
| Autoritativ | Nur, wenn dieser Server der einzige DHCP-Server im Netz ist: Falsche Anfragen werden sofort mit DHCPNAK abgewiesen, und Leases, die er nicht kennt (etwa nach Verlust der Lease-Datei), werden übernommen. |
| Reservierungen | Feste Adressen nach MAC-Adresse oder per `id:` nach Client-Kennung bzw. DUID, auf Wunsch mit Hostname und Clientprofil. Die IPv4-Adresse darf außerhalb des Bereichs liegen, muss aber im selben Netz sein. Für IPv6 genügt der hintere Teil wie `::20`; er wird mit jedem Präfix der Schnittstelle kombiniert. |

Die einfachen Einstellungen werden in die Syntax der Expertenkonfiguration übersetzt; der Reiter **Experte** zeigt die erzeugten Zeilen.

### IPv6

| Einstellung | Bedeutung |
| ----------- | --------- |
| IPv6 im Netz | **SLAAC** (empfohlen): Geräte bilden ihre Adressen selbst und erfahren den DNS-Server per Router Advertisement (RDNSS, RFC 8106) und per DHCPv6 ohne Adressvergabe. Funktioniert mit allen Systemen, auch mit Android. **SLAAC und zusätzlich DHCPv6-Adressen**: vergibt zusätzlich Adressen aus dem DHCPv6-Bereich, die unter dem Gerätenamen im DNS stehen. **Nur DHCPv6-Adressen**: kein SLAAC; Android bekommt dann von hier keine IPv6-Adresse (es unterstützt DHCPv6 für Adressen nicht), nur den DNS-Server. |
| DHCPv6-Bereich | Hinterer Teil der ersten und letzten Adresse, etwa `::1000` bis `::1fff`. Hat die Schnittstelle mehrere Präfixe (etwa vom Anbieter und eine ULA), bekommt jedes Gerät aus jedem Präfix eine Adresse. |
| Standard-Router | **Automatisch** kündigt diesen Rechner nur dann als Standard-Router an, wenn er IPv6 weiterleitet (`/proc/sys/net/ipv6/conf/<schnittstelle>/forwarding`). **Nein** kündigt nur Präfix und DNS-Server an (Router-Lebensdauer 0); die Geräte behalten ihren Router. **Ja** kündigt ihn immer an. |

Die Präfixe stammen aus den globalen und eindeutigen lokalen Adressen (ULA) der gewählten Schnittstelle und folgen automatisch, wenn der Anbieter sie wechselt; weggefallene Präfixe werden zwei Stunden lang als nicht mehr gültig angekündigt. Als DNS-Server kündigt der Server seine eigene Adresse auf der Schnittstelle an und bevorzugt dabei eine ULA und fest eingetragene (nicht per SLAAC gebildete) Adressen, damit die angekündigte Adresse stabil bleibt. Stehen IPv6-Adressen im Feld DNS-Server, werden stattdessen diese angekündigt.

## Expertenkonfiguration

Der Reiter **Experte** versteht die DHCP-Syntax von [dnsmasq](https://dnsmasq.org/docs/dnsmasq-man.html). Er zeigt die eigene Konfiguration in zwei Ansichten desselben Textes:

- **Liste**: jede Zeile als lesbarer Eintrag (etwa „NTP-Server (ntp-server, 42) = dieser Server“) mit Bearbeiten, Verschieben und Entfernen. **Neuer Eintrag** öffnet ein Formular für IPv4- und IPv6-Bereiche, Reservierungen, DHCP- und DHCPv6-Optionen, Gerätegruppen (Tags), Regeln, Netzwerkstart, Domains, Parameter der Router Advertisements und allgemeine Schalter. Optionen werden aus einer Liste mit Beschreibung gewählt, die Wertfelder passen zum Typ der Option (Adressen mit „Adresse dieses Servers“, Ja/Nein, Zahlen, Routen zeilenweise, Text). Das Formular zeigt die entstehende Zeile, bevor sie übernommen wird. Zeilen, die die Formulare nicht abdecken (etwa gekapselte Herstelleroptionen), werden als freie Zeile bearbeitet.
- **Text**: die Zeilen selbst.

Änderungen werden im Hintergrund geprüft; fehlerhafte Zeilen sind in der Liste mit der Meldung des Servers markiert. Übernommen wird erst mit **Speichern**; **Prüfen** prüft auf Wunsch.

```
dhcp-range=set:buero,192.168.10.100,192.168.10.200,12h
dhcp-range=::1000,::1fff,constructor:eth0,slaac,64,12h
enable-ra
ra-param=eth0,600,0
dhcp-option=option6:dns-server,[::]
dhcp-host=aa:bb:cc:dd:ee:ff,192.168.10.20,[::20],drucker
dhcp-range=set:gaeste,10.10.0.50,10.10.0.250,255.255.255.0,2h
dhcp-option=tag:gaeste,option:router,10.10.0.1
dhcp-option=tag:gaeste,option:dns-server,0.0.0.0
dhcp-host=aa:bb:cc:dd:ee:ff,192.168.10.20,drucker
dhcp-host=11:22:33:*:*:*,set:iot
dhcp-vendorclass=set:telefone,Yealink
dhcp-option=tag:telefone,66,"http://provisioning.example/"
dhcp-match=set:efi64,option:client-arch,7
dhcp-boot=tag:efi64,ipxe.efi,,192.168.10.5
domain=home.arpa,192.168.10.0/24,local
dhcp-authoritative
```

Unterstützte Anweisungen:

| Anweisung | Zweck |
| --------- | ----- |
| `dhcp-range=[tag:<tag>,][set:<tag>,]<start>,<ende>\|static[,<netzmaske>[,<broadcast>]][,<lease-dauer>]` | Adressbereich. Für Netze hinter einem DHCP-Relay ist die Netzmaske Pflicht. `static` vergibt nur reservierte Adressen. Höchstens 65.536 Adressen pro Bereich, Bereiche dürfen sich nicht überlappen. |
| `dhcp-host=[<mac>][,id:<client-id>\|*][,set:<tag>][,tag:<tag>][,<ip>][,<name>][,<lease-dauer>][,ignore]` | Reservierung, Name, Lease-Dauer oder Ausschluss eines Geräts. MAC-Adressen dürfen `*` enthalten, ein Hardwaretyp wird als `1-aa:bb:…` vorangestellt. Ohne MAC und Client-ID passt der Eintrag auf den Hostnamen, den das Gerät sendet. |
| `dhcp-option=[tag:<tag>,…][encap:<opt>,][vi-encap:<enterprise>,][vendor:<klasse>,]<nummer>\|option:<name>,[<wert>,…]` | Option. `0.0.0.0` steht für die Adresse dieses Servers im jeweiligen Netz, ein leerer Wert unterdrückt die Option. Optionen mit mehr Tags gewinnen gegenüber solchen mit weniger, bei gleicher Anzahl gewinnt die spätere Zeile. Zeilen der Expertenkonfiguration gewinnen immer gegenüber den einfachen Einstellungen. |
| `dhcp-option-force=…` | Wie `dhcp-option`, wird aber auch ungefragt gesendet. |
| `dhcp-match=set:<tag>,<nummer>\|option:<name>\|vi-encap:<enterprise>[,<wert>]` | Setzt ein Tag, wenn die Anfrage die Option (mit dem Wert) enthält. |
| `dhcp-vendorclass=set:<tag>,[enterprise:<nummer>,]<text>`, `dhcp-userclass=set:<tag>,<text>` | Tag nach Herstellerklasse (Option 60 / 124) oder Benutzerklasse (Option 77), Teilzeichenfolge. |
| `dhcp-mac=set:<tag>,<mac mit *>` | Tag nach MAC-Adresse. |
| `dhcp-circuitid=set:<tag>,<wert>`, `dhcp-remoteid=…`, `dhcp-subscrid=…` | Tag nach den Relay-Angaben (Option 82). |
| `tag-if=set:<tag>[,set:<tag>][,tag:<tag>…]` | Setzt Tags, wenn alle angegebenen Tags gesetzt sind (`tag:!x` verneint). |
| `dhcp-ignore=tag:<tag>[,…]` | Beantwortet passende Geräte nicht. |
| `dhcp-ignore-names[=tag:…]`, `dhcp-generate-names[=tag:…]` | Ignoriert die Hostnamen der Geräte oder bildet Namen aus der MAC-Adresse. |
| `dhcp-broadcast[=tag:…]` | Sendet Antworten immer per Broadcast. |
| `dhcp-boot=[tag:<tag>,]<datei>[,<servername>[,<serveradresse>]]` | PXE- und BOOTP-Boot (`file`, `sname`, `siaddr`). |
| `domain=<domain>[,<netz/präfix>\|<start>,<ende>][,local]` | Domain für die Namen der Geräte; mit `local` beantwortet der Server unbekannte Namen selbst. |
| `dhcp-reply-delay=[tag:<tag>,]<sekunden>` | Verzögert Angebote (höchstens 10 Sekunden). |
| `dhcp-range=[tag:<tag>,][set:<tag>,]<start6>[,<ende6>\|static][,constructor:<schnittstelle>][,ra-only\|ra-stateless\|slaac\|ra-names][,off-link][,<präfixlänge>][,<lease-dauer>]` | IPv6-Bereich. Mit `constructor:` enthalten die Adressen nur den hinteren Teil (`::100`) und werden mit jedem globalen oder ULA-Präfix der Schnittstelle kombiniert (`eth*` passt auf mehrere). Ohne werden vollständige Adressen angegeben; solche Bereiche bedienen auch DHCPv6-Relays, deren Link-Adresse im Präfix liegt. `ra-only` kündigt das Präfix für SLAAC ohne DHCPv6 an, `ra-stateless` ergänzt DHCPv6 ohne Adressen, `slaac` verbindet SLAAC und DHCPv6-Adressen, ohne Modus vergibt nur DHCPv6 Adressen. `ra-names` wird akzeptiert und wie `slaac` behandelt. Präfixlänge standardmäßig 64; SLAAC braucht genau 64. |
| `enable-ra` | Sendet Router Advertisements für alle IPv6-Bereiche (die Modi `ra-only`, `ra-stateless` und `slaac` schalten sie für ihren Bereich ohnehin ein). |
| `ra-param=<schnittstelle>,[mtu:<wert>\|<schnittstelle>\|off,][high\|low,]<intervall>[,<router-lebensdauer>]` | Abstand der unaufgeforderten Router Advertisements (4 bis 1800 Sekunden, Standard 600), Router-Priorität, MTU-Option und Router-Lebensdauer (0 = kein Standard-Router). Ohne Router-Lebensdauer kündigt sich der Server nur an, wenn er IPv6 weiterleitet. |
| `dhcp-option=[tag:<tag>,…]option6:<nummer>\|<name>,[<wert>,…]` | DHCPv6-Option, etwa `option6:dns-server,[::]`, `option6:domain-search,home.arpa`, `option6:ntp-server,[::]` oder `option6:sntp-server,[2001:db8::123]`. `[::]` steht für die Adresse dieses Servers im Netz. `dns-server` und `domain-search` gelten auch für RDNSS und DNSSL in den Router Advertisements. |
| `dhcp-host=…,[<ipv6>]` | IPv6-Adresse einer Reservierung. `[::20]` wird mit jedem Präfix des Bereichs kombiniert, eine vollständige Adresse gilt wie angegeben. Für DHCPv6 wird das Gerät an `id:<DUID>` (hexadezimal), an der MAC-Adresse in seiner DUID (Typen LLT und LL) oder an der von einem Relay weitergegebenen MAC-Adresse (RFC 6939) erkannt. |
| `interface=<name>`, `except-interface=<name>` | Schränkt die Schnittstellen ein; `eth*` passt auf einen Anfang. |
| `dhcp-authoritative`, `dhcp-rapid-commit`, `dhcp-sequential-ip`, `dhcp-ignore-clid`, `dhcp-no-override`, `bootp-dynamic`, `no-ping`, `dhcp-lease-max=<n>` | Globale Schalter. |

Automatische Tags: der Name der Schnittstelle, auf der die Anfrage einging, `known`, wenn ein `dhcp-host`-Eintrag passt, `bootp` bei BOOTP-Anfragen und das `set:`-Tag des gewählten Bereichs.

Nicht unterstützt (mit Fehlermeldung): Proxy-DHCP, `pxe-service`, `dhcp-script`, `dhcp-relay`, Host- und Optionsdateien sowie Einstellungen zur Lease-Datei. DHCPv6-Präfix-Delegation (IA_PD) und temporäre Adressen (IA_TA) werden mit „nicht verfügbar“ beantwortet, Reconfigure wird nicht gesendet.

Die Optionsnamen folgen dnsmasq (`dnsmasq --help dhcp` und `dnsmasq --help dhcp6`); die Liste steht im Reiter **Experte**. Werte werden nach dem Typ der Option kodiert: Adressen, Adresslisten, Zahlen, Text, Suchdomänen-Listen (RFC 3397, mit Kompression) und klassenlose statische Routen (RFC 3442, `dhcp-option=121,10.0.0.0/8,192.168.1.1`). Hexadezimale Werte werden als `01:02:03` geschrieben, Text in Anführungszeichen.

## Protokollverhalten

- DISCOVER, REQUEST (Auswahl, Neustart, Verlängerung, Neubindung), DECLINE, RELEASE und INFORM nach RFC 2131, BOOTP für reservierte Geräte (mit `bootp-dynamic` auch dynamisch).
- Eine Adresse bleibt einem Gerät zugeordnet: Ein wiederkehrendes Gerät bekommt seine bisherige Adresse, solange sie frei ist. Neue Geräte erhalten Adressen in einer aus ihrer MAC-Adresse abgeleiteten Reihenfolge, damit nicht alle um die erste Adresse konkurrieren.
- Bevor eine Adresse zum ersten Mal angeboten wird, wird sie angepingt. Antwortet sie, bleibt sie zehn Minuten gesperrt. Ein DHCPDECLINE eines Geräts sperrt die Adresse ebenfalls.
- Relay-Agenten (`giaddr`) mit Subnet Selection (RFC 3011) und Link Selection (RFC 3527); die Relay-Agent-Information (RFC 3046) wird unverändert zurückgegeben.
- Lange Optionen werden nach RFC 3396 aufgeteilt; passt die Antwort nicht in die Maximalgröße des Geräts (Option 57, mindestens 576 Byte), werden zusätzlich die Felder `file` und `sname` genutzt (Option Overload).
- Rapid Commit (RFC 4039), Client-FQDN (RFC 4702), Client-Identifier (RFC 6842).
- Antworten an Geräte ohne Adresse gehen direkt an deren MAC-Adresse. Dafür wird die Berechtigung `CAP_NET_RAW` gebraucht; ohne sie werden sie per Broadcast gesendet, was mit fast allen Geräten funktioniert.
- Pro MAC-Adresse werden höchstens 20 Pakete pro Sekunde verarbeitet, weitere verworfen.

### DHCPv6 und Router Advertisements

- DHCPv6 nach RFC 8415: SOLICIT und ADVERTISE (mit Präferenz 255, wenn der Server autoritativ ist und die Priorität „Primär“ hat), REQUEST, RENEW, REBIND, CONFIRM, RELEASE, DECLINE und INFORMATION-REQUEST, Rapid Commit (`dhcp-rapid-commit`), Relays (RELAY-FORW mit bis zu 32 Stufen, die Interface-ID wird zurückgegeben). Nachrichten, die per Unicast kommen, obwohl der Server kein Unicast angeboten hat, werden mit dem Status UseMulticast beantwortet oder ignoriert.
- Der Server weist sich mit einer DUID-UUID (RFC 6355) aus, die aus `dhcp-node.id` abgeleitet ist.
- Ein Gerät behält seine Adresse je IAID; neue Adressen werden in einer aus DUID und IAID abgeleiteten Reihenfolge gewählt. Ein DECLINE sperrt die Adresse für eine Stunde.
- DNS-Server (Option 23) und Domain (Option 24) gehen mit jeder Antwort; ist nichts eingestellt, gelten die Adresse dieses Servers im Netz und die Domain der einfachen Einstellungen. Weitere Optionen werden gesendet, wenn das Gerät danach fragt, oder mit `dhcp-option-force`. Antworten auf INFORMATION-REQUEST tragen eine Auffrischungszeit aus der Lease-Dauer (mindestens 10 Minuten, höchstens ein Tag).
- Client-FQDN (RFC 4704): Der Hostname kommt aus Option 39, die Antwort teilt mit, dass der Server den Namen einträgt.
- Router Advertisements nach RFC 4861 mit Präfix-Informationen, RDNSS und DNSSL (RFC 8106), der Link-Layer-Adresse des Absenders und auf Wunsch der MTU. Nach dem Start oder einer Änderung gehen sie dreimal innerhalb von 16 Sekunden hinaus, danach zu zufälligen Zeitpunkten zwischen einem Drittel des Intervalls und dem ganzen Intervall; Router Solicitations werden innerhalb einer halben Sekunde beantwortet, höchstens alle 3 Sekunden. Das M-Flag ist gesetzt, wenn DHCPv6 Adressen vergibt, das O-Flag, wenn DHCPv6 verfügbar ist. Hält der Server an oder wird IPv6 ausgeschaltet, sendet er ein letztes Advertisement mit Router- und DNS-Lebensdauer 0.

## Andere DHCP-Server und Priorität

Der Server sendet in regelmäßigen Abständen (standardmäßig alle 5 Minuten) auf jeder Schnittstelle selbst eine DHCP-Anfrage und wertet die Angebote aus. Zusätzlich erkennt er andere Server an der Serverkennung in den Anfragen der Geräte. Gefundene Server erscheinen im Reiter **Status** und im Selbsttest. **Nach anderen DHCP-Servern suchen** im Reiter **Status** funktioniert auch bei ausgeschaltetem DHCP-Server; die Anfrage geht dann über jede Schnittstelle mit IPv4-Adresse, damit sich ein vorhandener Server, etwa auf dem Router, schon vor dem Einschalten finden lässt.

Die Priorität legt fest, wie sich der Server verhält, wenn ein anderer DHCP-Server vorhanden ist, etwa ein Router, dessen DHCP sich nicht abschalten lässt:

| Priorität | Verhalten |
| --------- | --------- |
| Primär | Antwortet sofort. |
| Nachrangig | Sendet Angebote verzögert (standardmäßig 2 Sekunden) und auf Wunsch erst, wenn ein Gerät schon eine Mindestzeit sucht (Feld `secs`); solange der andere Server funktioniert, wird er gewählt. |
| Reserve | Antwortet neuen Geräten nur, solange kein anderer DHCP-Server gesehen wurde; bestehende Leases werden weiter verlängert. |

## IPv6-Router und DNS-Ankündigungen

Solange der DHCP-Server eingeschaltet ist, hört er auf allen Schnittstellen auf die Router Advertisements anderer Router. Der Reiter **Status** listet sie mit Flags, Präfixen und den angekündigten DNS-Servern. Kündigt ein Router andere DNS-Server als diesen Server an, können Geräte diese statt ZenitiumDNS fragen, und dann greifen Filter und Gerätenamen nicht; Status und Selbsttest warnen davor. Abhilfe schafft, im Router die DNS-Ankündigung (RDNSS) abzuschalten oder auf diesen Server zu setzen, oder hier IPv6 einzuschalten, damit auch ZenitiumDNS angekündigt wird. DHCPv6-Server, die Geräte ansprechen, erkennt der Server an der Serverkennung in ihren Anfragen; mit der Priorität „Reserve“ vergibt er dann keine neuen IPv6-Adressen.

## Geräte, Client-IDs und Profile

Der Server fasst die Adressen eines Geräts zu einem Gerät zusammen:

- Ein IPv4-Lease gehört zur MAC-Adresse des Geräts; die Client-Kennung (Option 61) zeigt die Lease-Liste, wenn sie nicht einfach die MAC-Adresse ist. Geräte, die eine Client-Kennung nach RFC 4361 senden (Typ 255 mit IAID und DUID, etwa systemd-networkd), nutzen dieselbe DUID wie bei DHCPv6; die Liste zeigt sie als DUID.
- Ein DHCPv6-Lease bekommt die MAC-Adresse des Geräts aus seiner DUID (Typen LLT und LL), von einem Relay (RFC 6939), aus dem IPv4-Lease mit derselben DUID, aus einer aus der MAC-Adresse gebildeten Link-Local-Adresse (EUI-64) oder aus der Nachbartabelle. So gelten Reservierungen nach MAC-Adresse, Namen und Clientprofile auch für DHCPv6-Geräte, deren DUID keine MAC-Adresse enthält.
- Reservierungen können ein Gerät an der MAC-Adresse oder per `id:` an Client-Kennung oder DUID erkennen.

In den einfachen Einstellungen hat jede Reservierung eine Spalte **Profil**, und die Lease-Liste hat je Lease eine Profilauswahl: Die Auswahl ordnet die MAC-Adresse des Geräts (ohne MAC-Adresse die reservierte IPv4-Adresse) diesem Clientprofil zu, sodass dessen Filter für das Gerät über IPv4 und IPv6 gelten. Die MAC-Adresse ermittelt der Server aus den Leases und der Nachbartabelle des Systems, siehe [BlockLists.de.md](BlockLists.de.md#geräte-erkennen). Das Abfrageprotokoll zeigt unter der Adresse den Namen eines bekannten Geräts, und der Dialog der Clientprofile bietet die bekannten Geräte zur Auswahl an.

## Namen im DNS

Mit **Gerätenamen im DNS eintragen** beantwortet der Server A- und AAAA-Anfragen für `name.domain` und PTR-Anfragen (`in-addr.arpa` und `ip6.arpa`) für die Adressen aktiver Leases und Reservierungen. Der Name stammt aus der Reservierung, sonst vom Gerät (Option 12 oder 81, bei DHCPv6 Option 39), und bei DHCPv6-Leases ohne Namen aus dem IPv4-Lease derselben MAC-Adresse. Ein Gerät mit Adressen aus mehreren Präfixen bekommt für jede einen AAAA-Eintrag. Diese Antworten erhalten nur Clients, die den Resolver nutzen dürfen. Melden zwei Geräte denselben Namen, gewinnt das mit dem jüngsten Lease; Reservierungen gewinnen immer.

## Überwachung

Der Selbsttest (Reiter Selbsttest) prüft den DHCP-Server, sobald er eingeschaltet ist: Fehler in der Konfiguration, Schnittstellen ohne Empfang, andere DHCP-Server im Netz (Warnung bei Priorität „Primär“, Hinweis bei „Nachrangig“ und „Reserve“), eine fehlgeschlagene Suche danach, die Auslastung der dynamischen Bereiche (Warnung ab 90 %, Fehler, wenn voll) Broadcast-Antworten ohne `CAP_NET_RAW`, Router Advertisements und DHCPv6 je Schnittstelle (etwa eine Schnittstelle ohne Präfix), Router, die andere DNS-Server ankündigen, Router, die das M-Flag setzen, während hier DHCPv6 Adressen vergibt, und andere DHCPv6-Server. Der Prometheus-Endpunkt liefert die Zähler und die Auslastung als `zenitiumdns_dhcp_*`, `zenitiumdns_dhcp6_*` und `zenitiumdns_ra_*` ([Metrics.de.md](Metrics.de.md#dhcp)).

## Dateien

| Datei im Konfigurationsordner | Inhalt |
| ----------------------------- | ------ |
| `dhcp.json` | DHCP-Einstellungen einschließlich der Expertenkonfiguration. |
| `dhcp-leases.json` | Leases, nach Änderungen höchstens einmal pro Sekunde geschrieben. |
| `dhcp6-leases.json` | DHCPv6-Leases. |
| `dhcp-node.id` | Zufällige ID dieses Servers; daraus werden die Hardware-Adresse für die Suche nach anderen DHCP-Servern und die DUID des DHCPv6-Servers abgeleitet. |

`dhcp.json`, `dhcp-leases.json` und `dhcp6-leases.json` sind zusammen mit den DNS-Einstellungen Teil der Sicherung. Die Wiederherstellung ersetzt DHCP-Einstellungen und Leases. `dhcp-node.id` gehört nicht zur Sicherung.

## API

| Aufruf | Berechtigung | Zweck |
| ------ | ------------ | ----- |
| `api/dhcp/status` | DHCP: lesen | Zustand, Schnittstellen, Pool-Auslastung, Zähler, andere DHCP-Server; unter `ipv6` die Router Advertisements je Schnittstelle, DHCPv6-Empfang und -Zähler, andere Router und DHCPv6-Server. |
| `api/dhcp/settings/get` | DHCP: lesen | Einstellungen, erzeugte Zeilen, Schnittstellen (mit IPv6-Präfixen unter `interfaces6`), Optionsnamen. |
| `api/dhcp/settings/validate` | DHCP: lesen | Prüft `settings` (JSON), ohne zu speichern. |
| `api/dhcp/settings/set` | DHCP: ändern | Speichert `settings` (JSON); Fehler kommen mit Zeilennummern zurück. |
| `api/dhcp/leases/list` | DHCP: lesen | Leases, DHCPv6-Leases unter `leases6`. |
| `api/dhcp/leases/reserve` | DHCP: ändern | Wandelt das Lease von `address` in eine Reservierung um; bei IPv6 wird der hintere Teil reserviert, wofür die DUID des Geräts eine MAC-Adresse enthalten muss. |
| `api/dhcp/leases/delete` | DHCP: löschen | Löscht das Lease von `address` (IPv4 oder IPv6). |
| `api/dhcp/probe` | DHCP: ändern | Sucht sofort nach anderen DHCP-Servern. |
| `api/dhcp/foreign/clear` | DHCP: ändern | Leert die Liste der anderen DHCP-Server. |
| `api/dhcp/devices` | DHCP oder Einstellungen: lesen | Bekannte Geräte aus Leases, Reservierungen und der Nachbartabelle mit Adressen, Client-ID, DUIDs und Profil. |

Der Berechtigungsbereich **DHCP** ist neu; bestehende Installationen geben ihn der Gruppe Administrators vollständig und der Gruppe DNS Administrators zum Lesen.

## Voraussetzungen

Der Server braucht UDP-Port 67 (und 68 für die Suche nach anderen Servern), für DHCPv6 UDP-Port 547 und die Berechtigung `CAP_NET_RAW` für Antworten an die MAC-Adresse, für Router Advertisements und für das Beobachten anderer Router; der systemd-Dienst des Debian-Pakets erteilt sie. Ohne sie gehen IPv4-Antworten an Geräte ohne Adresse per Broadcast hinaus, und Router Advertisements sind nicht verfügbar (der Status nennt den Grund). Das Container-Image startet den Server als Benutzer ohne `CAP_NET_RAW`; DHCPv4 und DHCPv6 funktionieren dort, Router Advertisements nicht. Ein Container muss das Netz des Hosts nutzen (`--network host`), sonst sieht er die Broadcasts und Multicasts der Geräte nicht.
