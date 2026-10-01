# Drop Requests App

[English version](README.md)

Eine DNS-App für ZenitiumDNS, die eingehende DNS-Anfragen anhand der Quelladresse und der angefragten Namen und Typen verwirft.

Die App erweitert den DNS-Server, indem sie Anfragen direkt beim Eingang abfängt und einstellbare Filterregeln anwendet, bevor die Anfragen die Auflösung erreichen. Administratoren steuern damit genau, welche DNS-Anfragen verarbeitet werden, etwa für die Trennung von Netzen, die Abwehr von Missbrauch und die Durchsetzung von Sicherheitsregeln.

## Überblick

Die Drop Requests App **filtert Anfragen vor der Auflösung**. Administratoren können damit:

- **Anfragen aus bestimmten Netzen blockieren** (CIDR-Schreibweise)
- **Anfragen nur aus vertrauenswürdigen Netzen zulassen** (Allowlist-Modus)
- **fehlerhafte oder ungültige DNS-Pakete verwerfen**, um den Parser zu entlasten
- **DNS-Anfragen nach Name und Eintragstyp filtern**, um Missbrauch zu verhindern
- **ganze Zonen blockieren**, also alle Anfragen für eine Domain und ihre Subdomains verwerfen

Die App richtet sich an **Systemadministratoren, Provider und sicherheitsbewusste Organisationen**, die Verkehr steuern, DDoS-Angriffe abmildern oder Netzrichtlinien auf DNS-Ebene durchsetzen wollen.

## Installation

Die App wird mit ZenitiumDNS ausgeliefert und beim ersten Start installiert, bleibt aber deaktiviert.

1. Öffne die **Weboberfläche** von ZenitiumDNS

2. Wechsle zu **Apps**

3. Klicke bei *Anfragen verwerfen* (DropRequestsApp) auf **Aktivieren**

4. Klicke auf **Konfigurieren**, um die Konfiguration zu bearbeiten

## Konfiguration

Die Drop Requests App wird über die Datei `dnsApp.config` im Installationsordner der App eingestellt. Die Datei ist im JSON-Format und unterstützt Filter nach Netz, Filter nach Anfrage und das Erkennen fehlerhafter Pakete.

Alle Optionen sind unten beschrieben.

### Optionen auf oberster Ebene

| Eigenschaft | Typ | Standard | Beschreibung |
| --- | --- | --- | --- |
| `enableBlocking` | boolean | `true` | Hauptschalter für alle Blockierfunktionen. Bei `false` werden alle Anfragen unabhängig von den übrigen Regeln zugelassen. |
| `dropMalformedRequests` | boolean | `false` | Verwirft DNS-Anfragen stillschweigend, die sich nicht korrekt einlesen lassen. Hilft gegen Angriffe auf den Parser und reduziert Protokolleinträge durch fehlerhafte Pakete. |
| `allowedNetworks` | Liste von Texten | `[]` | Netzadressen (IP oder CIDR), deren Anfragen immer zugelassen werden. Ist die Liste gefüllt, werden Anfragen aus anderen Netzen gegen die blockierten Netze und Anfragen geprüft. Eine leere Liste schaltet den Allowlist-Modus ab. |
| `blockedNetworks` | Liste von Texten | `[]` | Netzadressen (IP oder CIDR), deren Anfragen immer verworfen werden. Wird nach `allowedNetworks` ausgewertet. |
| `allowedLocalEndPoints` | Liste von Texten | `[]` | Lokale Endpunkte des Servers, über die Anfragen angenommen werden, als IP-Adresse oder Hostname mit optionalem Port (`192.0.2.10:53`, `[2001:db8::10]:853`, `dns.example.com:443`); ohne Port passt jeder Port. Bei DoH, DoT und DoQ zählt der Hostname, mit dem sich der Client verbunden hat. Ist die Liste gefüllt, werden Anfragen über alle anderen Endpunkte verworfen. Für angenommene Anfragen gelten `blockedQuestions` weiterhin. |
| `blockedQuestions` | Liste von Objekten | `[]` | Muster für DNS-Anfragen, die blockiert werden. Jedes Objekt legt Name, Typ und das Blockieren ganzer Zonen fest. Siehe [Blockierte Anfragen](#blockierte-anfragen). |

### Blockierte Anfragen

Jeder Eintrag in `blockedQuestions` ist ein Objekt mit diesen Eigenschaften:

| Eigenschaft | Typ | Pflicht | Beschreibung |
| --- | --- | --- | --- |
| `name` | string | nein | Der vollständige Domainname (FQDN), der passen muss. Ein Punkt am Ende wird automatisch entfernt. Fehlt er, passt jede Domain. |
| `blockZone` | boolean | nein | Bei `true` werden `name` und alle Subdomains blockiert, bei `false` nur exakte Treffer. Standard: `false`. Setzt voraus, dass `name` angegeben ist. |
| `type` | string | nein | Der DNS-Eintragstyp, der blockiert wird (etwa `A`, `AAAA`, `ANY`, `RRSIG`). Groß- und Kleinschreibung spielt keine Rolle. Fehlt er, passt jeder Eintragstyp. Muss ein gültiger DNS-Eintragstyp sein. |

**Abgleich:**

- Nur `name` angegeben: blockiert Anfragen genau für diese Domain, bei jedem Eintragstyp
- Nur `type` angegeben: blockiert Anfragen für diesen Eintragstyp, bei jeder Domain
- `name` und `type` angegeben: blockiert Anfragen, die beide Bedingungen erfüllen
- `blockZone` auf `true`: blockiert die Domain und alle Subdomains, die zum Typfilter passen

**Beispiel (ganze Zone blockieren):**

```json
{
  "name": "malicious.com",
  "blockZone": true
}
```

Blockiert `malicious.com`, `www.malicious.com`, `api.subdomain.malicious.com` und alle anderen Subdomains, bei allen Eintragstypen.

**Beispiel (nur nach Typ blockieren):**

```json
{
  "type": "ANY"
}
```

Blockiert alle `ANY`-Anfragen unabhängig vom Domainnamen.

**Beispiel (genaue Domain und Typ):**

```json
{
  "name": "pizzaseo.com",
  "type": "RRSIG"
}
```

Blockiert nur `RRSIG`-Anfragen für `pizzaseo.com` (exakter Treffer).

## Schreibweisen für Netzadressen

Netzadressen in `allowedNetworks` und `blockedNetworks` können so angegeben werden:

- **Einzelne IPv4-Adresse:** `192.168.1.100`
- **Einzelne IPv6-Adresse:** `2001:db8::1` oder `::1`
- **IPv4 in CIDR-Schreibweise:** `10.0.0.0/8`, `192.168.0.0/16`
- **IPv6 in CIDR-Schreibweise:** `fe80::/10`, `2001:db8::/32`

**Beispiel für eine Netzliste:**

```json
"allowedNetworks": [
  "127.0.0.1",
  "::1",
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "2001:db8::/32"
]
```

## Beispielkonfiguration

```json
{
  "enableBlocking": true,
  "dropMalformedRequests": false,
  "allowedNetworks": [
    "127.0.0.1",
    "::1",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16"
  ],
  "blockedNetworks": [
    "203.0.113.0/24",
    "198.51.100.0/24"
  ],
  "blockedQuestions": [
    {
      "name": "example.com",
      "blockZone": true
    },
    {
      "type": "ANY"
    },
    {
      "name": "pizzaseo.com",
      "type": "RRSIG"
    },
    {
      "name": "sl",
      "type": "ANY"
    },
    {
      "name": "a.a.a.ooooops.space",
      "type": "A"
    }
  ]
}
```

## So funktioniert die Filterung

Die Drop Requests App prüft jede eingehende DNS-Anfrage in diesen Schritten:

1. **Prüfung des Hauptschalters:** Steht `enableBlocking` auf `false`, wird die Anfrage sofort zugelassen.

2. **Prüfung auf fehlerhafte Pakete:** Steht `dropMalformedRequests` auf `true` und ließ sich die Anfrage nicht einlesen oder enthält sie nicht genau eine Frage, wird sie stillschweigend verworfen.

3. **Auswertung der Allowlist:** Ist `allowedNetworks` gefüllt, wird geprüft, ob die Quell-IP zu einem erlaubten Netz passt. Bei einem Treffer wird die Anfrage zugelassen. Ist `allowedNetworks` leer, entfällt dieser Schritt.

4. **Auswertung der Blockliste:** Passt die Quell-IP zu einem Netz in `blockedNetworks`, wird die Anfrage stillschweigend verworfen.

5. **Prüfung des lokalen Endpunkts:** Ist `allowedLocalEndPoints` gefüllt und kam die Anfrage nicht über einen der genannten Endpunkte, wird sie stillschweigend verworfen.

6. **Abgleich mit Mustern:** Die DNS-Frage wird mit allen Einträgen in `blockedQuestions` verglichen. Passt ein Eintrag, wird die Anfrage stillschweigend verworfen.

7. **Standardmäßig zulassen:** Greift keine Regel, geht die Anfrage weiter in die DNS-Auflösung.

**Wichtig:** Die Allowlist (`allowedNetworks`) hat Vorrang vor der Blockliste (`blockedNetworks`). Steht ein Netz in beiden Listen, werden seine Anfragen zugelassen.

## Einsatzbeispiele

1. **DNS-Server auf private Netze beschränken:** `allowedNetworks` mit den privaten Adressbereichen nach RFC 1918 füllen, damit nur interne Hosts den DNS-Server fragen können und er nicht als offener Resolver missbraucht wird.
2. **DNS-Amplification-Angriffe abmildern:** `ANY`-Anfragen über eine Regel nach Typ blockieren, um die Angriffsfläche für Verstärkungsangriffe zu verkleinern.
3. **Bekannte bösartige Domains bei der Anfrage blockieren:** Ganze Zonen blockieren, damit für bekannte bösartige Domains und ihre Subdomains gar keine Anfragen mehr verarbeitet werden, noch bevor eine Auflösung beginnt.
4. **Regionale oder organisatorische Netzrichtlinien durchsetzen:** Bestimmte externe Netze über `blockedNetworks` von Anfragen ausschließen, etwa für Geofencing oder Compliance-Vorgaben.
5. **Protokolleinträge durch fehlerhafte Pakete reduzieren:** `dropMalformedRequests` einschalten, um ungültige DNS-Pakete stillschweigend zu verwerfen und bei DDoS-Angriffen Parser und Protokoll zu entlasten.
6. **Missbrauch bestimmter DNSSEC-Anfragen verhindern:** `RRSIG`- oder andere DNSSEC-Anfragen für Domains blockieren, die bekanntermaßen übermäßig viel Verkehr erzeugen oder die DNSSEC-Validierung missbrauchen.

## Fehlersuche

### Anfragen werden nicht blockiert

**Anzeichen:** DNS-Anfragen, die zu Blockierregeln passen sollten, werden normal aufgelöst.

**Vorgehen:**

1. Prüfe, ob `enableBlocking` in `dnsApp.config` auf `true` steht

2. Prüfe das Protokoll des DNS-Servers auf Fehler beim Einlesen der Konfiguration

3. Prüfe, ob die Quell-IP der Anfrage nicht in `allowedNetworks` steht (die Allowlist hebt alle Blockierungen auf)

4. Prüfe, ob die CIDR-Schreibweise stimmt (etwa `/24` statt `/255.255.255.0`)

5. Prüfe bei Regeln nach Anfrage, ob der Domainname genau zu `name` passt (Groß- und Kleinschreibung egal) oder ob `blockZone` für Subdomains eingeschaltet ist

6. Lade die App über die Weboberfläche neu, indem du ihre Konfiguration erneut speicherst.

### Gewollte Anfragen werden verworfen

**Anzeichen:** Gültige DNS-Anfragen berechtigter Clients werden stillschweigend verworfen.

**Vorgehen:**

1. Prüfe im Allowlist-Modus, ob die IP-Adresse des Clients in `allowedNetworks` enthalten ist

2. Prüfe bei gefülltem `blockedNetworks`, ob die IP des Clients nicht in einem blockierten Bereich liegt

3. Prüfe `blockedQuestions` auf zu weit gefasste Muster (etwa alle `A`-Einträge blockiert oder `blockZone` auf einer verbreiteten TLD)

4. Prüfe bei eingeschaltetem `dropMalformedRequests`, ob der Client korrekte DNS-Pakete sendet (Verkehr mit `tcpdump` oder Wireshark ansehen)

5. Setze `enableBlocking` vorübergehend auf `false`, um festzustellen, ob das Problem an dieser App liegt

### Fehlerhafte Anfragen werden nicht verworfen

**Anzeichen:** Ungültige DNS-Pakete erreichen weiterhin den Resolver oder erscheinen im Protokoll.

**Vorgehen:**

1. Prüfe, ob `dropMalformedRequests` in `dnsApp.config` auf `true` steht

2. Prüfe anhand von Einlesefehlern im Protokoll des DNS-Servers, ob die Pakete tatsächlich fehlerhaft sind

3. Lade die App über die Weboberfläche neu, indem du ihre Konfiguration erneut speicherst.

4. Manche fehlerhaften Pakete erscheinen noch im Protokoll, bevor sie verworfen werden; prüfe dort die ausgeführte Aktion (`DropSilently`)

### Das Blockieren ganzer Zonen erfasst keine Subdomains

**Anzeichen:** Anfragen nach Subdomains werden trotz `blockZone: true` nicht blockiert.

**Vorgehen:**

1. Prüfe, ob `name` in der Konfiguration keinen Punkt am Ende hat

2. Prüfe, ob `blockZone` für die Regel auf `true` steht

3. Prüfe im Protokoll das Format der angefragten Namen und ob es dem erwarteten FQDN entspricht

4. Teste zuerst einen exakten Domaintreffer (ohne `blockZone`), um zu sehen, ob der einfache Namensabgleich funktioniert

**Testbefehl:**

```bash
dig @<dns-server-ip> subdomain.blocked-domain.com
```

Erwartetes Verhalten: Die Anfrage wird stillschweigend verworfen, es kommt keine Antwort.
