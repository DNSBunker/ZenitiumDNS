# Advanced Blocking App

[English version](README.md)

Eine DNS-App für ZenitiumDNS mit erweiterten Blockierfunktionen: Gruppenrichtlinien je Client, mehrere Blocklistenformate und eine fein einstellbare Blockierung.

## Überblick

Die Advanced Blocking App erweitert die Blockierung des DNS-Servers. Administratoren können damit:

- **Gruppen je Client** mit eigenen Blockierregeln anlegen, abhängig von IP-Adresse, Subnetz oder lokalem Endpunkt
- mehrere Arten von Blocklisten verwenden: Domainlisten, reguläre Ausdrücke und Listen im AdBlock-Format
- eigene Blockierantworten festlegen (NXDOMAIN oder eigene IP-Adressen)
- Allowlists einrichten, um bestimmte Domains freizugeben
- Clients über Netzadressen oder DNS-Endpunkte Gruppen zuordnen

## ⚠️ Wichtiger Hinweis: Überschneidung mit der eingebauten Blockierung

> **Ist diese App aktiviert, arbeitet sie unabhängig von der eingebauten Blockierung des DNS-Servers.**
>
> Die Advanced Blocking App verwendet **nicht** die Blocklisten aus den Einstellungen des DNS-Servers unter Einstellungen > Blockierung. Alle Blocklisten, Allowlists und das Blockierverhalten werden in der eigenen Konfiguration der App festgelegt.
>
> **Entscheide dich für einen Weg:**
>
> - **Variante A:** Die eingebaute Blockierung des DNS-Servers verwenden (Einstellungen > Blockierung) und diese App **nicht** aktivieren
> - **Variante B:** Diese App aktivieren und **alle** Blockierregeln hier festlegen, die eingebauten Blockiereinstellungen bleiben dann ungenutzt
>
> Beides gleichzeitig zu verwenden führt leicht zu Verwirrung, weil beide Anfragen unabhängig voneinander verarbeiten. Die Blockierung der App wird während der Anfrageverarbeitung ausgewertet und kann je nach Reihenfolge Vorrang haben.

## Installation

Die App wird mit ZenitiumDNS ausgeliefert und beim ersten Start installiert, bleibt aber deaktiviert.

1. Öffne die Weboberfläche von ZenitiumDNS
2. Wechsle zu **Apps**
3. Klicke bei *Erweiterte Blockierung* (AdvancedBlockingApp) auf **Aktivieren**
4. Klicke auf **Konfigurieren**, um die Konfiguration zu bearbeiten

## Konfiguration

Die App wird über eine JSON-Konfigurationsdatei (`dnsApp.config`) eingestellt. Hier alle Optionen im Überblick:

### Optionen auf oberster Ebene

| Eigenschaft | Typ | Standard | Beschreibung |
| --- | --- | --- | --- |
| `enableBlocking` | boolean | `true` | Hauptschalter, der die gesamte Blockierung ein- oder ausschaltet |
| `blockingAnswerTtl` | integer | `30` | TTL (in Sekunden) der Blockierantworten |
| `blockListUrlUpdateIntervalHours` | integer | `24` | Stunden zwischen automatischen Aktualisierungen der Blocklisten |
| `blockListUrlUpdateIntervalMinutes` | integer | `0` | zusätzliche Minuten für das Aktualisierungsintervall |
| `localEndPointGroupMap` | object | `{}` | ordnet lokale DNS-Endpunkte Gruppennamen zu |
| `networkGroupMap` | object | `{}` | ordnet Client-Netze oder -IP-Adressen Gruppennamen zu |
| `groups` | array | `[]` | Liste der Gruppendefinitionen |

### Zuordnung lokaler Endpunkte zu Gruppen

Ordnet bestimmte Endpunkte des DNS-Servers Gruppen zu. Nützlich, wenn mehrere DNS-Dienste laufen (etwa DoH, DoT und normales DNS) und jeder eigene Regeln bekommen soll.

```json
"localEndPointGroupMap": {
  "127.0.0.1": "bypass",
  "192.168.10.2:53": "bypass",
  "user1.dot.example.com":  "kids",
  "user2.doh.example.com:443": "bypass"
}
```

### Zuordnung von Netzen zu Gruppen

Ordnet Client-IP-Adressen oder Subnetze Gruppen zu. Spezifischere Treffer haben Vorrang.

```json
"networkGroupMap": {
  "192.168.10.20": "kids",
  "192.168.10.0/24": "standard",
  "0.0.0.0/0": "everyone",
  "::/0": "everyone"
}
```

### Konfiguration einer Gruppe

Jede Gruppe legt ihre eigenen Blockierregeln fest:

| Eigenschaft | Typ | Standard | Beschreibung |
| --- | --- | --- | --- |
| `name` | string | *Pflicht* | eindeutiger Name der Gruppe |
| `enableBlocking` | boolean | `true` | Blockierung für diese Gruppe einschalten |
| `allowTxtBlockingReport` | boolean | `true` | Angaben zur Blockierung in TXT-Antworten und als EDNS Extended DNS Error zurückgeben |
| `blockAsNxDomain` | boolean | `false` | für blockierte Domains NXDOMAIN statt einer eigenen IP-Adresse zurückgeben |
| `blockingAddresses` | array | `[]` | IP-Adressen, die für blockierte A-/AAAA-Anfragen zurückgegeben werden |
| `allowed` | array | `[]` | ausdrücklich erlaubte Domains (Allowlist) |
| `blocked` | array | `[]` | ausdrücklich blockierte Domains |
| `allowListUrls` | array | `[]` | URLs von Allowlists mit Domains |
| `blockListUrls` | array | `[]` | URLs von Blocklisten mit Domains (Text oder Objekt) |
| `allowedRegex` | array | `[]` | reguläre Ausdrücke für erlaubte Domains |
| `blockedRegex` | array | `[]` | reguläre Ausdrücke für blockierte Domains |
| `regexAllowListUrls` | array | `[]` | URLs von Allowlists mit regulären Ausdrücken |
| `regexBlockListUrls` | array | `[]` | URLs von Blocklisten mit regulären Ausdrücken |
| `adblockListUrls` | array | `[]` | URLs von Listen im AdBlock-Format |

### Formate für Blocklisten-URLs

Blocklisten-URLs lassen sich als einfacher Text oder als Objekt mit zusätzlichen Optionen angeben:

**Einfaches Format:**

```json
"blockListUrls": [
  "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
]
```

**Objektformat mit eigenen Optionen:**

```json
"blockListUrls": [
  {
    "url": "https://example.com/blocklist.txt",
    "blockAsNxDomain":  false,
    "blockingAddresses": ["192.168.10.2"]
  }
]
```

## Beispielkonfiguration

```json
{
  "enableBlocking": true,
  "blockingAnswerTtl": 30,
  "blockListUrlUpdateIntervalHours": 24,
  "blockListUrlUpdateIntervalMinutes": 0,
  "localEndPointGroupMap": {
    "127.0.0.1":  "bypass"
  },
  "networkGroupMap":  {
    "192.168.10.0/24": "kids",
    "0.0.0.0/0": "everyone",
    "::/0": "everyone"
  },
  "groups": [
    {
      "name": "everyone",
      "enableBlocking": true,
      "allowTxtBlockingReport":  true,
      "blockAsNxDomain": true,
      "blockingAddresses": ["0.0.0.0", "::"],
      "allowed": [],
      "blocked":  ["example.com"],
      "allowListUrls": [],
      "blockListUrls": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"
      ],
      "allowedRegex": [],
      "blockedRegex": ["^ads\\."],
      "regexAllowListUrls": [],
      "regexBlockListUrls": [],
      "adblockListUrls": []
    },
    {
      "name":  "kids",
      "enableBlocking":  true,
      "allowTxtBlockingReport": true,
      "blockAsNxDomain": false,
      "blockingAddresses": ["0.0.0.0", "::"],
      "allowed":  [],
      "blocked":  [],
      "allowListUrls": [],
      "blockListUrls": [
        {
          "url":  "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts",
          "blockAsNxDomain": false,
          "blockingAddresses": ["192.168.10.2"]
        }
      ],
      "allowedRegex": [],
      "blockedRegex": [],
      "regexAllowListUrls":  [],
      "regexBlockListUrls": [],
      "adblockListUrls": []
    },
    {
      "name": "bypass",
      "enableBlocking": false,
      "allowTxtBlockingReport": true,
      "blockAsNxDomain": true,
      "blockingAddresses": ["0.0.0.0", "::"],
      "allowed":  [],
      "blocked": [],
      "allowListUrls":  [],
      "blockListUrls": [],
      "allowedRegex": [],
      "blockedRegex": [],
      "regexAllowListUrls": [],
      "regexBlockListUrls":  [],
      "adblockListUrls": []
    }
  ]
}
```

## Unterstützte Blocklistenformate

### Domain-Blocklisten

Übliches hosts-Dateiformat oder einfache Domainlisten:

```syslog
# Kommentarzeile
0.0.0.0 ads.example.com
127.0.0.1 tracking.example.com
malware.example.com
```

### Blocklisten mit regulären Ausdrücken

Ein regulärer Ausdruck pro Zeile:

```regex
# Alle Subdomains blockieren, die mit "ads" beginnen
^ads\. 
# Tracking-Domains blockieren
.*tracking.*\.com$
```

### AdBlock-Listen

Unterstützt wird ein Teil der AdBlock-Syntax:

```regex
! Kommentar
||ads.example.com^
||tracking.example.com^$all
@@||safe.example.com^
```

## So funktioniert die Blockierung

1. **Auswahl der Gruppe**: Trifft eine DNS-Anfrage ein, bestimmt die App die zuständige Gruppe:
   - zuerst über die Zuordnung lokaler Endpunkte (`localEndPointGroupMap`)
   - danach über die Zuordnung von Client-IP-Adressen und Netzen (`networkGroupMap`)
   - spezifischere Netze haben Vorrang

2. **Prüfung auf Freigabe**: Passt die Domain zu einer Allowlist (fest eingetragen, per URL, als regulärer Ausdruck oder als AdBlock-Ausnahme), wird die Anfrage **nicht** blockiert.

3. **Prüfung auf Blockierung**: Passt die Domain zu einer Blockliste, antwortet die App mit:
   - `NXDOMAIN`, wenn `blockAsNxDomain` auf `true` steht
   - den eingestellten `blockingAddresses` bei A-/AAAA-Anfragen
   - einer NO-DATA-Antwort bei anderen Anfragetypen

4. **Blockierungsbericht**: Ist `allowTxtBlockingReport` eingeschaltet,
   - liefern TXT-Anfragen für blockierte Domains Angaben dazu, warum die Domain blockiert wurde
   - enthalten Antworten die EDNS-Option Extended DNS Error

## Einsatzbeispiele

1. **Jugendschutz**: eine Gruppe „kids“ mit strengerer Blockierung für die Geräte der Kinder
2. **Gastnetz**: eigene Regeln für das Subnetz des Gast-WLANs
3. **IoT-Abschottung**: Telemetrie von IoT-Geräten in einem bestimmten VLAN blockieren
4. **DNS für mehrere Mandanten**: unterschiedliche Blockierregeln für verschiedene Clients auf demselben DNS-Server
5. **Unterscheidung nach DoH/DoT**: unterschiedliche Regeln je nach DNS-Transportprotokoll

## Fehlersuche

### Blocklisten werden nicht aktualisiert

- Prüfe das Protokoll des DNS-Servers auf Downloadfehler
- Prüfe, ob die URLs vom Server aus erreichbar sind
- Stelle sicher, dass der Server Internetzugang hat (oder ein Proxy eingerichtet ist)

### Domains werden nicht blockiert

1. Prüfe, ob die Client-IP der richtigen Gruppe zugeordnet ist
2. Prüfe, ob die Domain auf einer Allowlist steht
3. Stelle sicher, dass `enableBlocking` sowohl auf oberster Ebene als auch in der Gruppe auf `true` steht
4. Prüfe die Blocklisten der Gruppe

### Blockierung testen

Frage vom Client aus einen TXT-Eintrag für eine blockierte Domain ab, um den Blockierungsbericht zu sehen:

```bash
dig TXT blocked-domain.com @your-dns-server
```
