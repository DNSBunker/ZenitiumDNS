# Advanced Forwarding App

[English version](README.md)

Eine DNS-App für ZenitiumDNS, die Anfragen abhängig vom Client-Netz und der angefragten Domain an unterschiedliche Forwarder weiterleitet, auf Wunsch über einen Proxy. Neben eigenen Regeln liest sie Upstream-Dateien im Format von AdGuard Home, sodass sich große Listen bedingter Weiterleitungen nutzen lassen, ohne für jede Domain eine Forwarder-Zone anzulegen.

## Installation

Die App wird mit ZenitiumDNS ausgeliefert und beim ersten Start installiert, bleibt aber ausgeschaltet. Unter **Apps** einschalten und mit **Konfigurieren** die Einstellungen bearbeiten. In der mitgelieferten Konfiguration ist `enableForwarding` ausgeschaltet.

## Ablauf einer Anfrage

1. Anfragen ohne RD-Flag und Anfragen von Clients, die keine Rekursion nutzen dürfen (Einstellungen > Resolver), bleiben unberührt; die App macht den Server also nie zum offenen Resolver.
2. Die Client-Adresse wählt über `networkGroupMap` eine Gruppe; das spezifischste Netz gewinnt.
3. Der angefragte Name wird mit den `forwardings` der Gruppe verglichen, danach mit ihren AdGuard-Upstream-Dateien. Der längste passende Eintrag gewinnt; ein exakter Name schlägt `*.parent`, das wiederum `*` schlägt.
4. Passt eine Regel, löst der Server die Anfrage über deren Forwarder auf. Namen lokal bedienter Zonen (RFC 6303, etwa private Reverse-Zonen) leitet eine `*`-Regel nicht weiter.

Passt nichts, löst der Server die Anfrage wie gewohnt auf.

## Konfiguration

| Schlüssel | Standard | Beschreibung |
| --------- | -------- | ------------ |
| `appPreference` | `200` | Reihenfolge unter den Apps; kleinere Werte laufen zuerst, Apps ohne Angabe zählen als 100. |
| `enableForwarding` | `true` | Hauptschalter. |
| `proxyServers` | | Proxyserver, die Forwarder nutzen können. |
| `forwarders` | | Benannte Forwarder. |
| `networkGroupMap` | | Objekt, das Netze (`"192.168.0.0/16"`, `"::/0"`) Gruppennamen zuordnet. |
| `groups` | | Gruppen mit ihren Weiterleitungsregeln. Mindestens eine Gruppe ist Pflicht. |

### `proxyServers`

| Schlüssel | Beschreibung |
| --------- | ------------ |
| `name` | Name, auf den `proxy` verweist. |
| `type` | `Http` oder `Socks5`. |
| `proxyAddress`, `proxyPort` | Adresse und Port des Proxys. |
| `proxyUsername`, `proxyPassword` | Optionale Zugangsdaten. |

### `forwarders`

| Schlüssel | Standard | Beschreibung |
| --------- | -------- | ------------ |
| `name` | | Name, auf den `forwardings` verweist. |
| `proxy` | `null` | Name eines Proxyservers oder `null` für den im Server eingestellten Proxy. |
| `dnssecValidation` | `true` | Antworten dieses Forwarders mit DNSSEC prüfen. |
| `forwarderProtocol` | `Udp` | `Udp`, `Tcp`, `Tls`, `Https` oder `Quic`. |
| `forwarderAddresses` | | Adressen wie `9.9.9.9`, `dns.quad9.net:853 (9.9.9.9)` oder `https://dns.quad9.net/dns-query (9.9.9.9)`. |

### `groups`

| Schlüssel | Standard | Beschreibung |
| --------- | -------- | ------------ |
| `name` | | Name, auf den `networkGroupMap` verweist. |
| `enableForwarding` | `true` | Schalter für diese Gruppe. |
| `forwardings` | | Liste von Regeln mit `forwarders` (Namen) und `domains`. Ein Domain-Eintrag passt auf den Namen und seine Subdomains (`example.com`), nur auf Subdomains (`*.example.com`) oder auf alles (`*`). Groß- und Kleinschreibung spielt keine Rolle. |
| `adguardUpstreams` | | Liste von Upstream-Dateien mit `configFile`, `proxy` und `dnssecValidation`. |

### AdGuard-Upstream-Dateien

`configFile` ist ein Pfad relativ zum Ordner der App (etwa `/etc/zenitiumdns/apps/AdvancedForwardingApp`) oder ein absoluter Pfad. Die Datei wird beim Start gelesen und jede Minute auf Änderungen geprüft. Format:

```
# Standard-Upstreams für Namen ohne eigene Regel
https://dns.quad9.net/dns-query (9.9.9.9)
tls://1.1.1.1
[/corp.example/lab.example/]10.0.0.53 10.0.0.54
[/ads.corp.example/]#
```

- Eine Zeile ohne Klammern fügt einen Standard-Upstream hinzu.
- `[/domain/…/]upstreams` leitet die genannten Domains und ihre Subdomains an die angegebenen, durch Leerzeichen getrennten Upstreams weiter.
- `[/domain/]#` verwendet für diese Domain die Standard-Upstreams, etwa um eine Subdomain von einer allgemeineren Regel auszunehmen.
- Zeilen, die mit `#` beginnen, sind Kommentare.

Gibt es Standard-Upstreams, geht jede Anfrage der Gruppe, auf die keine Regel der Gruppe passt, an sie.

### Beispiel

```json
{
  "appPreference": 200,
  "enableForwarding": true,
  "proxyServers": [
    {
      "name": "local-proxy",
      "type": "Socks5",
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
    },
    {
      "name": "corp",
      "proxy": null,
      "dnssecValidation": false,
      "forwarderProtocol": "Udp",
      "forwarderAddresses": ["10.0.0.53"]
    }
  ],
  "networkGroupMap": {
    "10.0.0.0/8": "office",
    "0.0.0.0/0": "everyone",
    "::/0": "everyone"
  },
  "groups": [
    {
      "name": "office",
      "enableForwarding": true,
      "forwardings": [
        { "forwarders": ["corp"], "domains": ["corp.example"] },
        { "forwarders": ["quad9-doh"], "domains": ["*"] }
      ]
    },
    {
      "name": "everyone",
      "enableForwarding": true,
      "forwardings": [
        { "forwarders": ["quad9-doh"], "domains": ["*"] }
      ],
      "adguardUpstreams": [
        { "proxy": null, "dnssecValidation": true, "configFile": "adguard-upstreams.txt" }
      ]
    }
  ]
}
```

## Hinweise

- Forwarder mit `dnssecValidation: false` wirken für die passenden Domains wie ein negativer Vertrauensanker.
- Die zwischengespeicherten Antworten verschiedener Gruppen hält der Server nur getrennt, wenn EDNS Client Subnet unter Einstellungen > Resolver eingeschaltet ist; das Client-Netz selbst wird nicht an die Forwarder gesendet. Ohne diese Einstellung können Gruppen, die denselben Namen an unterschiedliche Forwarder weiterleiten, die zwischengespeicherten Antworten der jeweils anderen erhalten.
- Fehler in einer Upstream-Datei landen im Server-Protokoll; der vorherige Stand der Datei bleibt in Gebrauch.
