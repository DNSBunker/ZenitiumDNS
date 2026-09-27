# Advanced Forwarding App

[English version](README.md)

Eine DNS-App für ZenitiumDNS, die Anfragen bedingt an eingestellte Upstream-Resolver weiterleitet.

## Überblick

- **Bedingte Weiterleitung** – Anfragen nach Domain und Client-Netz weiterleiten
- **Mehrere Forwarder** – wiederverwendbare Upstream-Resolver definieren
- **Proxy-Unterstützung** – Forwarder können einen definierten Proxyserver nutzen
- **Steuerung über Gruppen** – Weiterleitungsregeln werden nach Client-Netz gruppiert

## Einbindung und Erweiterungspunkte

- Implementiert: `IDnsApplication`, `IDnsAuthoritativeRequestHandler`, `IDnsApplicationPreference`
- Läuft im autoritativen Anfragepfad, wenn die Weiterleitung eingeschaltet ist.

## Konfiguration

`dnsApp.config` enthält diese Schlüssel:

| Eigenschaft | Typ | Standard | Beschreibung |
| --- | --- | --- | --- |
| `appPreference` | number | `200` | Reihenfolge, in der die App ausgeführt wird. |
| `enableForwarding` | boolean | `true` | Hauptschalter für die Weiterleitung. |
| `proxyServers` | array | `[]` | Proxyserver, die Forwarder nutzen können. |
| `forwarders` | array | `[]` | Definitionen der Forwarder. |
| `networkGroupMap` | object | Pflicht | ordnet Client-Netze Gruppennamen zu. |
| `groups` | array | Pflicht | Weiterleitungsgruppen mit ihren Zuordnungen von Domains zu Forwardern. |

### Beispiel

```json
{
  "appPreference": 200,
  "enableForwarding": true,
  "proxyServers": [
    {
      "name": "local-proxy",
      "type": "socks5",
      "proxyAddress": "localhost",
      "proxyPort": 1080,
      "proxyUsername": null,
      "proxyPassword": null
    }
  ],
  "forwarders": [
    {
      "name": "quad9-doh",
      "proxy": null,
      "dnssecValidation": true,
      "forwarderProtocol": "Https",
      "forwarderAddresses": ["https://dns.quad9.net/dns-query (9.9.9.9)"]
    }
  ],
  "networkGroupMap": {
    "0.0.0.0/0": "everyone",
    "::/0": "everyone"
  },
  "groups": [
    {
      "name": "everyone",
      "enableForwarding": true,
      "forwardings": [
        {
          "forwarders": ["quad9-doh"],
          "domains": ["*"]
        }
      ]
    }
  ]
}
```

## Verhalten zur Laufzeit

1. Die App wählt anhand von `networkGroupMap` eine Client-Gruppe.
2. Sie prüft, ob die Weiterleitung für diese Gruppe eingeschaltet ist.
3. Sie vergleicht die angefragte Domain mit den Weiterleitungsregeln der Gruppe.
4. Für passende Forwarder gibt sie eigene FWD-Einträge zurück.

## Risiken und Hinweise für den Betrieb

- Sich überschneidende Weiterleitungsregeln sind schwer zu durchschauen.
- Ein fehlerhafter Upstream oder Proxy kann die Auflösung der betroffenen Domains lahmlegen.
- Halte die Zuordnung von Netzen zu Gruppen eindeutig, damit Anfragen nicht ungewollt umgeleitet werden.

## Fehlersuche

- Prüfe, ob die Client-IP zu einer Gruppe in `networkGroupMap` passt.
- Prüfe, ob die Gruppe `enableForwarding: true` hat.
- Prüfe, ob die angefragte Domain zu einem Eintrag in `domains` der Gruppe passt.
