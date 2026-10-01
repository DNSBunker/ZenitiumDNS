# DHCP-Server

[English version](DHCP.md)

ZenitiumDNS enthält einen DHCPv4-Server. Er vergibt Adressen, trägt die Namen der Geräte in das lokale DNS ein und erkennt andere DHCP-Server im Netz. Eingerichtet wird er in der Weboberfläche unter **DHCP**; nach der Installation ist er ausgeschaltet.

## Einfache Einstellungen

Für ein einzelnes Netz genügt der Reiter **Einstellungen**:

| Einstellung | Bedeutung |
| ----------- | --------- |
| Schnittstelle | Automatisch antwortet auf jeder Schnittstelle, deren Netz zum Adressbereich passt. |
| Adressbereich | Erste und letzte Adresse, die vergeben wird. |
| Netzmaske | Leer übernimmt das Präfix der Schnittstelle. |
| Gateway | Leer sendet das Standard-Gateway der Schnittstelle, sofern es im selben Netz liegt. |
| DNS-Server | Leer sendet die Adresse dieses Servers; die Geräte nutzen dann ZenitiumDNS mit allen Filtern. |
| Domain | Geräte sind unter `name.domain` erreichbar; unbekannte Namen in dieser Domain beantwortet der Server selbst mit NXDOMAIN. Für ein privates Netz eignen sich `home.arpa` oder `lan`. |
| Lease-Dauer | Etwa `30m`, `12h`, `7d` oder `infinite`; mindestens 2 Minuten. |
| Autoritativ | Nur, wenn dieser Server der einzige DHCP-Server im Netz ist: Falsche Anfragen werden sofort mit DHCPNAK abgewiesen, und Leases, die er nicht kennt (etwa nach Verlust der Lease-Datei), werden übernommen. |
| Reservierungen | Feste Adressen nach MAC-Adresse, auf Wunsch mit Hostname. Die Adresse darf außerhalb des Bereichs liegen, muss aber im selben Netz sein. |

Die einfachen Einstellungen werden in die Syntax der Expertenkonfiguration übersetzt; der Reiter **Experte** zeigt die erzeugten Zeilen.

## Expertenkonfiguration

Der Reiter **Experte** versteht die DHCP-Syntax von [dnsmasq](https://dnsmasq.org/docs/dnsmasq-man.html). Fehler werden mit Zeilennummer gemeldet, **Prüfen** kontrolliert ohne zu speichern.

```
dhcp-range=set:buero,192.168.10.100,192.168.10.200,12h
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
| `interface=<name>`, `except-interface=<name>` | Schränkt die Schnittstellen ein; `eth*` passt auf einen Anfang. |
| `dhcp-authoritative`, `dhcp-rapid-commit`, `dhcp-sequential-ip`, `dhcp-ignore-clid`, `dhcp-no-override`, `bootp-dynamic`, `no-ping`, `dhcp-lease-max=<n>` | Globale Schalter. |

Automatische Tags: der Name der Schnittstelle, auf der die Anfrage einging, `known`, wenn ein `dhcp-host`-Eintrag passt, `bootp` bei BOOTP-Anfragen und das `set:`-Tag des gewählten Bereichs.

Nicht unterstützt (mit Fehlermeldung): DHCPv6 und Router Advertisements, Proxy-DHCP, `pxe-service`, `dhcp-script`, `dhcp-relay`, Host- und Optionsdateien sowie Einstellungen zur Lease-Datei.

Die Optionsnamen folgen dnsmasq (`dnsmasq --help dhcp`); die Liste steht im Reiter **Experte**. Werte werden nach dem Typ der Option kodiert: Adressen, Adresslisten, Zahlen, Text, Suchdomänen-Listen (RFC 3397, mit Kompression) und klassenlose statische Routen (RFC 3442, `dhcp-option=121,10.0.0.0/8,192.168.1.1`). Hexadezimale Werte werden als `01:02:03` geschrieben, Text in Anführungszeichen.

## Protokollverhalten

- DISCOVER, REQUEST (Auswahl, Neustart, Verlängerung, Neubindung), DECLINE, RELEASE und INFORM nach RFC 2131, BOOTP für reservierte Geräte (mit `bootp-dynamic` auch dynamisch).
- Eine Adresse bleibt einem Gerät zugeordnet: Ein wiederkehrendes Gerät bekommt seine bisherige Adresse, solange sie frei ist. Neue Geräte erhalten Adressen in einer aus ihrer MAC-Adresse abgeleiteten Reihenfolge, damit nicht alle um die erste Adresse konkurrieren.
- Bevor eine Adresse zum ersten Mal angeboten wird, wird sie angepingt. Antwortet sie, bleibt sie zehn Minuten gesperrt. Ein DHCPDECLINE eines Geräts sperrt die Adresse ebenfalls.
- Relay-Agenten (`giaddr`) mit Subnet Selection (RFC 3011) und Link Selection (RFC 3527); die Relay-Agent-Information (RFC 3046) wird unverändert zurückgegeben.
- Lange Optionen werden nach RFC 3396 aufgeteilt; passt die Antwort nicht in die Maximalgröße des Geräts (Option 57, mindestens 576 Byte), werden zusätzlich die Felder `file` und `sname` genutzt (Option Overload).
- Rapid Commit (RFC 4039), Client-FQDN (RFC 4702), Client-Identifier (RFC 6842).
- Antworten an Geräte ohne Adresse gehen direkt an deren MAC-Adresse. Dafür wird die Berechtigung `CAP_NET_RAW` gebraucht; ohne sie werden sie per Broadcast gesendet, was mit fast allen Geräten funktioniert.
- Pro MAC-Adresse werden höchstens 20 Pakete pro Sekunde verarbeitet, weitere verworfen.

## Andere DHCP-Server und Priorität

Der Server sendet in regelmäßigen Abständen (standardmäßig alle 5 Minuten) auf jeder Schnittstelle selbst eine DHCP-Anfrage und wertet die Angebote aus. Zusätzlich erkennt er andere Server an der Serverkennung in den Anfragen der Geräte. Gefundene Server erscheinen im Reiter **Status** und im Selbsttest. **Nach anderen DHCP-Servern suchen** im Reiter **Status** funktioniert auch bei ausgeschaltetem DHCP-Server; die Anfrage geht dann über jede Schnittstelle mit IPv4-Adresse, damit sich ein vorhandener Server, etwa auf dem Router, schon vor dem Einschalten finden lässt.

Die Priorität legt fest, wie sich der Server verhält, wenn ein anderer DHCP-Server vorhanden ist, etwa ein Router, dessen DHCP sich nicht abschalten lässt:

| Priorität | Verhalten |
| --------- | --------- |
| Primär | Antwortet sofort. |
| Nachrangig | Sendet Angebote verzögert (standardmäßig 2 Sekunden) und auf Wunsch erst, wenn ein Gerät schon eine Mindestzeit sucht (Feld `secs`); solange der andere Server funktioniert, wird er gewählt. |
| Reserve | Antwortet neuen Geräten nur, solange kein anderer DHCP-Server gesehen wurde; bestehende Leases werden weiter verlängert. |

## Namen im DNS

Mit **Gerätenamen im DNS eintragen** beantwortet der Server A-Anfragen für `name.domain` und PTR-Anfragen für die Adressen aktiver Leases und Reservierungen. Der Name stammt aus der Reservierung, sonst vom Gerät (Option 12 oder 81). Diese Antworten erhalten nur Clients, die den Resolver nutzen dürfen. Melden zwei Geräte denselben Namen, gewinnt das mit dem jüngsten Lease; Reservierungen gewinnen immer.

## Überwachung

Der Selbsttest (Reiter Selbsttest) prüft den DHCP-Server, sobald er eingeschaltet ist: Fehler in der Konfiguration, Schnittstellen ohne Empfang, andere DHCP-Server im Netz (Warnung bei Priorität „Primär“, Hinweis bei „Nachrangig“ und „Reserve“), eine fehlgeschlagene Suche danach, die Auslastung der dynamischen Bereiche (Warnung ab 90 %, Fehler, wenn voll) und Broadcast-Antworten ohne `CAP_NET_RAW`. Der Prometheus-Endpunkt liefert die Zähler und die Auslastung als `zenitiumdns_dhcp_*` ([Metrics.de.md](Metrics.de.md#dhcp)).

## Dateien

| Datei im Konfigurationsordner | Inhalt |
| ----------------------------- | ------ |
| `dhcp.json` | DHCP-Einstellungen einschließlich der Expertenkonfiguration. |
| `dhcp-leases.json` | Leases, nach Änderungen höchstens einmal pro Sekunde geschrieben. |
| `dhcp-node.id` | Zufällige ID dieses Servers; daraus wird die Hardware-Adresse für die Suche nach anderen DHCP-Servern abgeleitet. |

`dhcp.json` und `dhcp-leases.json` sind zusammen mit den DNS-Einstellungen Teil der Sicherung. Die Wiederherstellung ersetzt DHCP-Einstellungen und Leases. `dhcp-node.id` gehört nicht zur Sicherung.

## API

| Aufruf | Berechtigung | Zweck |
| ------ | ------------ | ----- |
| `api/dhcp/status` | DHCP: lesen | Zustand, Schnittstellen, Pool-Auslastung, Zähler, andere DHCP-Server. |
| `api/dhcp/settings/get` | DHCP: lesen | Einstellungen, erzeugte Zeilen, Schnittstellen, Optionsnamen. |
| `api/dhcp/settings/validate` | DHCP: lesen | Prüft `settings` (JSON), ohne zu speichern. |
| `api/dhcp/settings/set` | DHCP: ändern | Speichert `settings` (JSON); Fehler kommen mit Zeilennummern zurück. |
| `api/dhcp/leases/list` | DHCP: lesen | Leases. |
| `api/dhcp/leases/reserve` | DHCP: ändern | Wandelt das Lease von `address` in eine Reservierung um. |
| `api/dhcp/leases/delete` | DHCP: löschen | Löscht das Lease von `address`. |
| `api/dhcp/probe` | DHCP: ändern | Sucht sofort nach anderen DHCP-Servern. |
| `api/dhcp/foreign/clear` | DHCP: ändern | Leert die Liste der anderen DHCP-Server. |

Der Berechtigungsbereich **DHCP** ist neu; bestehende Installationen geben ihn der Gruppe Administrators vollständig und der Gruppe DNS Administrators zum Lesen.

## Voraussetzungen

Der Server braucht UDP-Port 67 (und 68 für die Suche nach anderen Servern) sowie für Antworten an die MAC-Adresse die Berechtigung `CAP_NET_RAW`, die der systemd-Dienst des Debian-Pakets erteilt. Im Container-Image werden Antworten an Geräte ohne Adresse per Broadcast gesendet. Ein Container muss das Netz des Hosts nutzen (`--network host`), sonst sieht er die Broadcasts der Geräte nicht.
