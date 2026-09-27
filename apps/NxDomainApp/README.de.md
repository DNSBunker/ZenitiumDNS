# NxDomain App

[English version](README.md)

Eine DNS-App für ZenitiumDNS, die eingetragene Domainnamen mit **NXDOMAIN** blockiert.

## Überblick

- **Einfache Blockliste** – bestimmte Domains blockieren
- **Einschluss von Subdomains** – wer `example.com` blockiert, blockiert auch `www.example.com`
- **TXT-Bericht** – auf Wunsch Angaben zur Blockierung in TXT-Antworten
- **Ausführungspriorität** – über `appPreference` einstellbar

## Einbindung und Erweiterungspunkte

- Implementiert: `IDnsApplication`, `IDnsAuthoritativeRequestHandler`, `IDnsApplicationPreference`
- Läuft im autoritativen Anfragepfad.

## Konfiguration

`dnsApp.config` enthält genau diese Schlüssel:

| Eigenschaft | Typ | Standard | Beschreibung |
| --- | --- | --- | --- |
| `appPreference` | number | `20` | Reihenfolge, in der die App ausgeführt wird (kleinere Werte laufen früher). |
| `enableBlocking` | boolean | Pflicht | Schaltet die Blockierung ein oder aus. |
| `allowTxtBlockingReport` | boolean | Pflicht | Schaltet TXT-Blockierungsberichte und den EDNS-Fehlertext ein. |
| `blocked` | string[] | Pflicht | Zu blockierende Domainnamen. Eine blockierte Domain gilt für den genauen Namen und seine Subdomains. |

### Beispiel

```json
{
  "appPreference": 20,
  "enableBlocking": true,
  "allowTxtBlockingReport": true,
  "blocked": [
    "use-application-dns.net",
    "mask.icloud.com",
    "mask-h2.icloud.com"
  ]
}
```

## Verhalten zur Laufzeit

1. Die angefragte Domain wird mit der Liste `blocked` verglichen.
2. Ist die Domain oder eine übergeordnete Domain blockiert, antwortet die App mit NXDOMAIN.
3. Ist der Anfragetyp TXT und `allowTxtBlockingReport` eingeschaltet, antwortet sie mit einer TXT-Antwort mit Angaben zur Blockierung.
4. Enthält die Anfrage EDNS und ist der TXT-Bericht eingeschaltet, fügt sie einen Extended DNS Error hinzu.

## Risiken und Hinweise für den Betrieb

- Die Blockierung gilt global; es gibt keine Regeln je Client oder Netz.
- Wird eine übergeordnete Domain blockiert, sind alle Subdomains mit blockiert.
- TXT-Berichte können verraten, dass eine Domain blockiert wurde.

## Fehlersuche

- Prüfe, ob `enableBlocking` auf `true` steht.
- Prüfe, ob die Domain in `blocked` steht oder eine Subdomain eines blockierten Namens ist.
- Prüfe `allowTxtBlockingReport`, wenn TXT-Antworten erwartet werden.
