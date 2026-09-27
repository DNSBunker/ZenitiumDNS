# DNS64 App

[English version](README.md)

Eine DNS-App für ZenitiumDNS, die DNS64 nach RFC 6147 umsetzt, damit Clients, die nur IPv6 haben, per Übersetzung im DNS auf Ziele zugreifen können, die nur über IPv4 erreichbar sind.

Die App erweitert ZenitiumDNS so, dass aus A-Einträgen AAAA-Einträge erzeugt werden. Zusammen mit einem NAT64-Gateway finden und erreichen Clients, die nur IPv6 haben, damit IPv4-Ziele. Die App arbeitet sowohl als Nachbearbeitung (Post-Processor) rekursiver Anfragen als auch als autoritativer Handler für Reverse-Lookups im DNS64-Adressraum.

## Überblick

Die DNS64 App setzt die **DNS Extensions for Network Address Translation from IPv6 Clients to IPv4 Servers** nach RFC 6147 um. Sie ermöglicht Netzen, die nur IPv6 haben, eine durchgängige Verbindung, indem sie IPv4-Adressen über einstellbare Präfixzuordnungen in erzeugte IPv6-Adressen übersetzt.

Die wichtigsten Funktionen:

- **Automatisches Erzeugen von AAAA-Einträgen** aus A-Einträgen bei AAAA-Anfragen
- **Gruppenrichtlinien nach Netz** für eine fein abgestufte Steuerung von DNS64
- **Einstellbare Zuordnung von IPv6-Präfixen** mit den üblichen Präfixlängen (32, 40, 48, 56, 64, 96)
- **Ausschluss von IPv6-Adressen**, für die keine Einträge erzeugt werden sollen
- **Reverse-DNS (PTR)** für erzeugte IPv6-Adressen
- **Berücksichtigung von DNSSEC**: Fordert ein Client DNSSEC-Validierung an, wird DNS64 übergangen

Die App ist ein wichtiger Baustein für die Umstellung auf Dual-Stack und für Netze, die nur IPv6 verwenden.

## ⚠️ Wichtiger Hinweis: NAT64 ist Voraussetzung

DNS64 **muss** zusammen mit einem funktionierenden NAT64-Gateway eingesetzt werden. Die App übersetzt nur im DNS, sie übernimmt keine Adressübersetzung im Netz.

**Risiko im Betrieb:**

Wird die DNS64 App ohne passendes NAT64-Gateway aktiviert, schlagen **Verbindungen fehl**, wenn Clients, die nur IPv6 haben, Ziele erreichen wollen, die nur IPv4 haben. Die erzeugten AAAA-Einträge zeigen dann auf IPv6-Adressen, die ohne NAT64 nicht geroutet werden können.

**Möglichkeiten für die Einführung:**

- **Variante A:** Erst das NAT64-Gateway in Betrieb nehmen, dann die DNS64 App aktivieren
- **Variante B:** Die DNS64 App zunächst mit `enableDns64: false` einrichten, NAT64 in Betrieb nehmen und dann DNS64 einschalten

**Verarbeitungsreihenfolge:**

DNS64 arbeitet als Nachbearbeitung in der Auflösungskette. Die App verarbeitet Antworten **nach** der rekursiven Auflösung und **bevor** sie an die Clients gehen.

## Installation

Die App wird mit ZenitiumDNS ausgeliefert und beim ersten Start installiert, bleibt aber deaktiviert.

1. Öffne die Weboberfläche von ZenitiumDNS

2. Wechsle zu **Apps**

3. Klicke bei *DNS64* (Dns64App) auf **Aktivieren**

4. Klicke auf **Konfigurieren**, um die Konfiguration zu bearbeiten

## Konfiguration

Die DNS64 App wird über die JSON-Datei `dnsApp.config` eingestellt. Die Konfiguration legt globale Einstellungen, die Zuordnung von Netzen zu Gruppen und die DNS64-Regeln je Gruppe fest.

Alle Optionen sind unten beschrieben. Der Aufbau erlaubt Regeln in Stufen, abhängig vom Netz, aus dem ein Client kommt.

### Optionen auf oberster Ebene

| Eigenschaft | Typ | Standard | Beschreibung |
| --- | --- | --- | --- |
| `appPreference` | integer | 30 | Priorität bei der Verarbeitung, wenn mehrere Apps `IDnsApplicationPreference` implementieren. Kleinere Werte laufen zuerst. |
| `enableDns64` | boolean | (Pflicht) | Globaler Schalter für DNS64. Bei `false` ist die App unabhängig von den Gruppeneinstellungen inaktiv. |
| `networkGroupMap` | object | (Pflicht) | Ordnet Client-Netzadressen (CIDR-Schreibweise) benannten Gruppen zu. Der längste passende Präfix bestimmt die Gruppe. |
| `groups` | array | (Pflicht) | Liste der Gruppenobjekte mit den DNS64-Regeln. Die Gruppen werden in `networkGroupMap` über ihren Namen angesprochen. |

### Zuordnung von Netzen zu Gruppen

Das Objekt `networkGroupMap` ordnet Quellnetze der Clients benannten Regelgruppen zu. Schlüssel sind Netze in CIDR-Schreibweise, Werte die Gruppennamen.

**Zweck:**

Ermöglicht unterschiedliches DNS64-Verhalten je nach Herkunftsnetz des Clients, etwa für interne und externe Clients, verschiedene VLANs oder Vertrauenszonen.

**Zuordnung:**

Die App wählt den längsten passenden Präfix. Passt eine Client-IP zu mehreren Netzen, gilt die spezifischste Zuordnung (längste Präfixlänge).

**JSON-Beispiel:**

```json
"networkGroupMap": {
  "::/0": "default-group",
  "2001:db8:1000::/48": "internal-group",
  "2001:db8:2000::/48": "guest-group"
}
```

### Konfiguration einer Gruppe

Jedes Gruppenobjekt beschreibt eine vollständige DNS64-Regel.

| Eigenschaft | Typ | Standard | Beschreibung |
| --- | --- | --- | --- |
| `name` | string | (Pflicht) | Eindeutiger Name der Gruppe, auf den `networkGroupMap` verweist. |
| `enableDns64` | boolean | (Pflicht) | Schalter für DNS64 in dieser Gruppe, um es je Gruppe ein- oder auszuschalten. |
| `dns64PrefixMap` | object | (Pflicht) | Ordnet IPv4-Netzbereiche DNS64-IPv6-Präfixen zu. Schlüssel sind IPv4-Netze in CIDR-Schreibweise, Werte IPv6-Präfixe oder `null`. |
| `excludedIpv6` | array | `[]` | Liste von IPv6-Netzen (CIDR), deren AAAA-Einträge ignoriert werden. Liegen alle AAAA-Einträge einer Antwort in diesen Bereichen, werden AAAA-Einträge erzeugt, als gäbe es keine. |

### Zuordnung von DNS64-Präfixen

Das Objekt `dns64PrefixMap` jeder Gruppe legt fest, wie IPv4-Adressen in IPv6-Adressen übersetzt werden.

**Aufbau:**

Schlüssel sind IPv4-Netze in CIDR-Schreibweise. Werte sind entweder:

- ein **IPv6-Präfix** (CIDR-Schreibweise), mit dem die Adressen erzeugt werden
- **`null`**, um den IPv4-Bereich von DNS64 auszunehmen

**Zulässige Präfixlängen:**

DNS64-Präfixe müssen eine der folgenden Präfixlängen nach RFC 6147 haben: **32, 40, 48, 56, 64 oder 96**.

**Zuordnung:**

Der längste passende Präfix gilt. Das spezifischste passende IPv4-Netz bestimmt das DNS64-Präfix, mit dem die Adresse erzeugt wird.

**JSON-Beispiel:**

```json
"dns64PrefixMap": {
  "0.0.0.0/0": "64:ff9b::/96",
  "10.0.0.0/8": null,
  "172.16.0.0/12": null,
  "192.168.0.0/16": null,
  "203.0.113.0/24": "2001:db8:64::/96"
}
```

**Erklärung:**

- Alle IPv4-Adressen verwenden das Präfix `64:ff9b::/96` (das bekannte Präfix aus RFC 6052)
- Private Adressen nach RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) sind ausgenommen
- Der öffentliche Bereich 203.0.113.0/24 verwendet das eigene Präfix `2001:db8:64::/96`

### Ausschlussliste für IPv6

Die Liste `excludedIpv6` enthält IPv6-Bereiche, deren vorhandene AAAA-Einträge ignoriert werden (RFC 6147, Abschnitt 5.1.4). Enthält eine Antwort nur AAAA-Einträge aus diesen Bereichen, erzeugt DNS64 trotzdem AAAA-Einträge.

**Zweck:**

Sorgt dafür, dass Einträge erzeugt werden, wenn zwar AAAA-Einträge vorhanden sind, diese aber nicht verwendet werden dürfen (zum Beispiel IPv4-gemappte IPv6-Adressen).

**Übliche Ausnahmen:**

- `::ffff:0:0/96` — IPv4-gemappte IPv6-Adressen (RFC 4291, Abschnitt 2.5.5.2)

**JSON-Beispiel:**

```json
"excludedIpv6": [
  "::ffff:0:0/96",
  "2001:db8:exclude::/48"
]
```

## Beispielkonfiguration

```json
{
  "appPreference": 30,
  "enableDns64": true,
  "networkGroupMap": {
    "::/0": "everyone",
    "2001:db8:internal::/48": "internal-ipv6"
  },
  "groups": [
    {
      "name": "everyone",
      "enableDns64": true,
      "dns64PrefixMap": {
        "0.0.0.0/0": "64:ff9b::/96",
        "10.0.0.0/8": null,
        "172.16.0.0/12": null,
        "192.168.0.0/16": null
      },
      "excludedIpv6": [
        "::ffff:0:0/96"
      ]
    },
    {
      "name": "internal-ipv6",
      "enableDns64": true,
      "dns64PrefixMap": {
        "0.0.0.0/0": "2001:db8:64::/96",
        "10.0.0.0/8": "2001:db8:64:a::/96",
        "172.16.0.0/12": "2001:db8:64:ac::/96",
        "192.168.0.0/16": "2001:db8:64:c0::/96"
      },
      "excludedIpv6": [
        "::ffff:0:0/96"
      ]
    }
  ]
}
```

## Formate der DNS64-Präfixe

Die App unterstützt die Präfixlängen nach RFC 6147. Die IPv4-Adresse wird je nach Präfixlänge in das IPv6-Präfix eingebettet.

**Unterstützte Präfixlängen:**

| Präfixlänge | Format | Einbettung der IPv4-Adresse |
| --- | --- | --- |
| `/32` | `pppp:pppp::/32` | Bits 32–63 und 64–95 |
| `/40` | `pppp:pppp:pp00::/40` | Bits 40–63 und 64–95 |
| `/48` | `pppp:pppp:pppp::/48` | Bits 48–63 und 64–95 |
| `/56` | `pppp:pppp:pppp:pp00::/56` | Bits 56–63 und 64–95 |
| `/64` | `pppp:pppp:pppp:pppp::/64` | Bits 64–95 |
| `/96` | `pppp:pppp:pppp:pppp:pppp:pppp::/96` | Bits 96–127 |

**Bekanntes Präfix:**

RFC 6052 legt `64:ff9b::/96` als bekanntes Präfix (Well-Known Prefix) für DNS64/NAT64 fest.

**Beispiel:**

Aus der IPv4-Adresse `192.0.2.1` wird mit dem Präfix `64:ff9b::/96` die Adresse `64:ff9b::192.0.2.1` bzw. `64:ff9b::c000:201`.

## So arbeitet DNS64

Die DNS64 App hat zwei getrennte Verarbeitungswege:

### AAAA-Anfragen (Nachbearbeitung)

1. **Prüfung der Anfrage:** Die App prüft, ob DNS64 global eingeschaltet ist und keine DNSSEC-Validierung angefordert wurde
2. **Auswertung der Antwort:** Die App wertet die Antwort des rekursiven Resolvers auf die AAAA-Anfrage aus
3. **Auswahl der Gruppe:** Die Quell-IP des Clients wird über den längsten passenden Präfix mit `networkGroupMap` abgeglichen
4. **Prüfung der Ausnahmen:** AAAA-Einträge in den Bereichen aus `excludedIpv6` werden entfernt; bleiben AAAA-Einträge außerhalb dieser Bereiche übrig, wird nichts erzeugt
5. **Abfrage der A-Einträge:** Gibt es keine gültigen AAAA-Einträge, fragt die App intern die A-Einträge ab
6. **Präfixzuordnung:** Jeder A-Eintrag wird über den längsten passenden Präfix mit `dns64PrefixMap` abgeglichen
7. **Erzeugen der AAAA-Einträge:** Die IPv4-Adressen werden in das IPv6-Präfix eingebettet, daraus entstehen die AAAA-Einträge
8. **Aufbau der Antwort:** Die erzeugten AAAA-Einträge kommen mit einer durch das SOA-Minimum begrenzten TTL in die Antwort

### PTR-Anfragen (autoritativer Handler)

1. **Prüfung der Anfrage:** Die App prüft, ob es sich um eine PTR-Anfrage für eine `.ip6.arpa`-Domain handelt
2. **Auswahl der Gruppe:** Die Quell-IP des Clients wird mit `networkGroupMap` abgeglichen
3. **Präfixabgleich:** Die umgekehrte IPv6-Adresse wird mit den eingestellten Werten in `dns64PrefixMap` abgeglichen
4. **Herauslösen der IPv4-Adresse:** Die IPv4-Adresse wird aus der erzeugten IPv6-Adresse gewonnen
5. **CNAME-Antwort:** Die App antwortet autoritativ mit einem CNAME-Eintrag auf die `.in-addr.arpa`-Domain
6. **Rekursive Auflösung:** Der DNS-Server folgt dem CNAME und löst den PTR-Eintrag aus der IPv4-Reverse-Zone auf

## Einsatzbeispiele

1. **Client-Netze nur mit IPv6:** Mit der DNS64 App erreichen Clients, die nur IPv6 haben, Internetangebote, die nur über IPv4 erreichbar sind, ohne Dual-Stack auf den Clients. Verbreitet in Mobilfunknetzen und bei aktuellen IPv6-Umstellungen in Unternehmen.
2. **Übergang über Dual-Stack:** DNS64 dient während einer schrittweisen IPv6-Einführung als Rückfallweg für IPv6-fähige Clients, die mit alten Diensten sprechen, die nur IPv4 haben.
3. **IPv6-Dienste von Providern:** Internetanbieter setzen DNS64 zusammen mit Carrier-Grade-NAT64 ein, um Privat- oder Geschäftskunden reine IPv6-Anschlüsse anzubieten und trotzdem das IPv4-Internet erreichbar zu halten.
4. **Interne IPv6-Umstellung in Unternehmen:** Organisationen mit internen Netzen, die nur IPv6 verwenden, erreichen per DNS64 während der Umstellung weiter interne Anwendungen und SaaS-Angebote, die nur IPv4 haben.
5. **Test- und Entwicklungsumgebungen:** Netzwerktechniker simulieren mit DNS64 im Labor Clients, die nur IPv6 haben, und prüfen die IPv6-Tauglichkeit von Anwendungen ohne großen Umbau der Infrastruktur.
6. **DNS64-Präfixe nach Region:** Organisationen mit mehreren regionalen NAT64-Gateways leiten Clients über die Zuordnung von Netzen zu Gruppen zum passenden DNS64-Präfix und NAT64-Gateway ihrer Region.

## Fehlersuche

### DNS64 erzeugt keine AAAA-Einträge

**Anzeichen:** Clients, die nur IPv6 haben, erhalten für Domains, bei denen DNS64 greifen sollte, keine AAAA-Einträge.

**Vorgehen:**

1. Prüfe, ob `enableDns64: true` sowohl auf oberster Ebene als auch in der Gruppe gesetzt ist
2. Prüfe, ob die Quell-IP des Clients zu einem Netz in `networkGroupMap` passt
3. Prüfe, ob die Ziel-IPv4-Adresse nicht über eine `null`-Zuordnung in `dns64PrefixMap` ausgenommen ist
4. Prüfe, ob der Client keine DNSSEC-Validierung anfordert (solche Anfragen übergeht die App)
5. Prüfe, ob keine AAAA-Einträge vorhanden sind oder alle in den Bereichen aus `excludedIpv6` liegen

**Konfiguration prüfen:**

Prüfe in `dns64PrefixMap`, ob die CIDR-Schreibweise stimmt und nur die Präfixlängen 32, 40, 48, 56, 64 und 96 verwendet werden.

**Protokolle:**

Schalte die Protokollierung der Anfragen des DNS-Servers ein, um die Nachbearbeitung durch DNS64 und die internen Abfragen der A-Einträge zu verfolgen.

### Erzeugte AAAA-Einträge sind nicht erreichbar

**Anzeichen:** Clients erhalten AAAA-Einträge, aber Verbindungen schlagen fehl oder laufen in Zeitüberschreitungen.

**Vorgehen:**

1. **Prüfe, ob das NAT64-Gateway läuft und aus dem Client-Netz erreichbar ist**
2. Prüfe, ob das in NAT64 eingestellte Präfix zu den Präfixen in `dns64PrefixMap` passt
3. Teste die NAT64-Verbindung mit ping6 an eine bekannte IPv4-Adresse: `ping6 64:ff9b::8.8.8.8`
4. Prüfe das Routing des DNS64-Präfixbereichs zum NAT64-Gateway
5. Prüfe, ob das NAT64-Gateway eine IPv4-Route zum Ziel hat

**Häufige Ursache:**

DNS64 wurde ohne passende NAT64-Infrastruktur in Betrieb genommen.

### Private IPv4-Adressen werden übersetzt

**Anzeichen:** Private Adressen nach RFC 1918 (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) werden in IPv6 umgewandelt.

**Lösung:**

Ausnahmen in `dns64PrefixMap` eintragen:

```json
"dns64PrefixMap": {
  "10.0.0.0/8": null,
  "172.16.0.0/12": null,
  "192.168.0.0/16": null
}
```

Private IPv4-Adressen sollten in der Regel nicht übersetzt werden, es sei denn, NAT64 ist ausdrücklich für Dual-Stack eingerichtet.

### Reverse-DNS-Anfragen (PTR) schlagen fehl

**Anzeichen:** PTR-Anfragen für erzeugte IPv6-Adressen liefern NXDOMAIN.

**Vorgehen:**

1. Prüfe, ob die erzeugte IPv6-Adresse im eingestellten DNS64-Präfix liegt
2. Prüfe, ob die zugehörige IPv4-Reverse-Zone (`.in-addr.arpa`) existiert und auflösbar ist
3. Prüfe im Protokoll des DNS-Servers die CNAME-Verarbeitung von `.ip6.arpa` nach `.in-addr.arpa`

**Erwartetes Verhalten:**

Die App antwortet autoritativ mit einem CNAME von `.ip6.arpa` auf `.in-addr.arpa`, danach löst der Server den PTR-Eintrag rekursiv auf.

### Fehler bei der Präfixlänge

**Anzeichen:** Die Konfiguration wird mit dem Fehler „Das DNS64-Präfix muss eine Länge von 32, 40, 48, 56, 64 oder 96 haben.“ abgelehnt.

**Lösung:**

Prüfe, ob alle DNS64-Präfixe in `dns64PrefixMap` nur die zulässigen Präfixlängen verwenden: `/32`, `/40`, `/48`, `/56`, `/64` oder `/96`.

**Ungültiges Beispiel:**

```json
"dns64PrefixMap": {
  "0.0.0.0/0": "2001:db8::/80"  // Ungültig: /80 gehört nicht zu den unterstützten Präfixlängen
}
```

**Korrigiertes Beispiel:**

```json
"dns64PrefixMap": {
  "0.0.0.0/0": "2001:db8:64::/96"
}
```
