# DNS Rebinding Protection App

[English version](README.md)

## Zusammenfassung

Eine DNS-App für ZenitiumDNS, die vor DNS-Rebinding-Angriffen schützt, indem sie private IP-Adressen aus den DNS-Antworten für nicht lokale Domainnamen entfernt.

## Einbindung und Erweiterungspunkte

- Implementiert: `IDnsApplication`, `IDnsPostProcessor`
- Läuft als: Nachbearbeitung (arbeitet auf den DNS-Antworten nach der eigentlichen Auflösung).

## Überblick

Die App erweitert ZenitiumDNS über **IDnsPostProcessor** und prüft DNS-Antworten, bevor sie an die Clients gehen. Sie verhindert DNS-Rebinding-Angriffe, indem sie:

- **private IP-Adressen** aus A- und AAAA-Einträgen öffentlicher Domainnamen **entfernt**
- **private IP-Adressen** nur für ausdrücklich eingetragene private Domains **zulässt**
- private Netzbereiche für **IPv4 und IPv6** nach RFC 1918 und RFC 4193 **berücksichtigt**
- vertrauenswürdige Client-Netze bei Bedarf **vom Schutz ausnimmt**
- **autoritative Antworten unverändert lässt**, damit lokal verwaltete Zonen nicht beeinträchtigt werden

Dieser Schutz ist wichtig, wenn Clients sowohl interne als auch externe Angebote nutzen: Er verhindert, dass bösartige Webseiten auf Dienste im internen Netz zugreifen.

## ⚠️ Wichtiger Hinweis: Auswirkung auf gewollte private IP-Adressen

Die App **entfernt private IP-Adressen** aus den DNS-Antworten für jeden Domainnamen, der nicht ausdrücklich in `privateDomains` eingetragen ist.

**Verhalten bei der Verarbeitung:**

- Liefert eine öffentliche DNS-Anfrage private IP-Adressen (etwa `example.com` → `192.168.1.1`), **werden diese Einträge aus der Antwort entfernt**
- Nur Domains aus `privateDomains` dürfen auf private IP-Adressen auflösen
- Autoritative Antworten aus lokalen Zonen werden **nie gefiltert**, weil ein Rebinding dort als gewollt gilt

**Möglichkeiten der Konfiguration:**

- **Variante A**: Alle gewollten internen Domainnamen in `privateDomains` eintragen
- **Variante B**: Die App ganz deaktivieren, wenn private IP-Adressen für Domains nötig sind, die sich nicht aufzählen lassen
- **Variante C**: Vertrauenswürdige Client-Netze in `bypassNetworks` eintragen, um sie vom Schutz auszunehmen

**Verarbeitungsreihenfolge:**

Die App bearbeitet Antworten, **nachdem** der DNS-Server die Auflösung abgeschlossen hat, aber **bevor** die Antwort an den Client geht. Gefiltert werden nur nicht autoritative Antworten.

## Installation

Die App wird mit ZenitiumDNS ausgeliefert und beim ersten Start installiert, bleibt aber deaktiviert.

1. Öffne die Weboberfläche von ZenitiumDNS

2. Wechsle zu **Apps**

3. Klicke bei *Schutz vor DNS-Rebinding* (DnsRebindingProtectionApp) auf **Aktivieren**

4. Klicke auf **Konfigurieren**, um die Konfiguration zu bearbeiten

## Konfiguration

Die App wird über die Datei `dnsApp.config` im Installationsordner der App eingestellt.

Die Konfiguration ist ein JSON-Objekt mit vier Eigenschaften auf oberster Ebene, die das Schutzverhalten, die Netzdefinitionen und die Ausnahmen für Domains steuern.

### Optionen auf oberster Ebene

| Eigenschaft | Typ | Standard | Beschreibung |
| --- | --- | --- | --- |
| `enableProtection` | Boolean | `true` | Hauptschalter, der den Schutz vor DNS-Rebinding global ein- oder ausschaltet |
| `bypassNetworks` | Liste von Texten | `[]` | Netzbereiche in CIDR-Schreibweise für Client-IP-Adressen, die vollständig vom Schutz ausgenommen sind |
| `privateNetworks` | Liste von Texten | siehe unten | Netzbereiche in CIDR-Schreibweise, die als privat gelten; Antworten mit diesen IP-Adressen werden gefiltert |
| `privateDomains` | Liste von Texten | `["home.arpa"]` | Domainnamen, die ohne Filterung auf private IP-Adressen auflösen dürfen |

### Private Netze

Die Liste `privateNetworks` legt fest, welche IP-Adressbereiche als privat gelten und dem Schutz vor Rebinding unterliegen.

**Die Standardkonfiguration enthält alle in RFCs festgelegten privaten Bereiche:**

```json
"privateNetworks": [
  "10.0.0.0/8",
  "127.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "169.254.0.0/16",
  "fc00::/7",
  "fe80::/10"
]
```

**Zweck**: Jede DNS-Antwort mit IP-Adressen aus diesen Bereichen wird gefiltert, es sei denn, die Domain steht in `privateDomains` oder der Client in `bypassNetworks`.

**Einsatz**: Organisationen können die Liste um weitere private Adressbereiche ergänzen (etwa Carrier-Grade-NAT `100.64.0.0/10`) oder Bereiche entfernen, die bei ihnen nicht vorkommen.

### Private Domains

Die Liste `privateDomains` enthält Domainnamen, die **von der Filterung ausgenommen** sind und gewollt auf private IP-Adressen auflösen dürfen.

**Schreibweise:**

- Groß- und Kleinschreibung spielt keine Rolle
- Übergeordnete Zonen werden berücksichtigt (`internal.local` erlaubt zum Beispiel auch `server.internal.local`)
- Keine Platzhalter verwenden, Subdomains werden automatisch einbezogen

**Beispiel:**

```json
"privateDomains": [
  "home.arpa",
  "internal.local",
  "corp.example.com"
]
```

### Ausgenommene Netze

Die Liste `bypassNetworks` legt Client-IP-Bereiche fest, die **vollständig vom Schutz vor Rebinding ausgenommen** sind.

**Zweck**: Vertrauenswürdige Netze (etwa Verwaltungsnetze) erhalten ungefilterte DNS-Antworten.

**Einsatz**: Interne Managementnetze oder Arbeitsplätze von Entwicklern, die Zugriff auf Split-Horizon-DNS brauchen.

**Beispiel:**

```json
"bypassNetworks": [
  "10.50.0.0/24",
  "192.168.100.0/24"
]
```

## Beispielkonfiguration

```json
{
  "enableProtection": true,
  "bypassNetworks": [
    "10.50.0.0/24"
  ],
  "privateNetworks": [
    "10.0.0.0/8",
    "127.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "fc00::/7",
    "fe80::/10"
  ],
  "privateDomains": [
    "home.arpa",
    "internal.local",
    "corp.example.com",
    "lab.local"
  ]
}
```

Diese Konfiguration:

- schaltet den Schutz global ein
- nimmt Clients aus `10.50.0.0/24` von jeder Filterung aus
- filtert alle üblichen privaten IP-Adressen nach RFC 1918 und RFC 4193
- erlaubt private IP-Adressen für `*.home.arpa`, `*.internal.local`, `*.corp.example.com` und `*.lab.local`

## Unterstützte Schreibweisen für Netzadressen

Die App unterstützt die übliche CIDR-Schreibweise für IPv4- und IPv6-Netze:

**IPv4 in CIDR-Schreibweise:**

```
192.168.1.0/24
10.0.0.0/8
```

**IPv6 in CIDR-Schreibweise:**

```
fc00::/7
fe80::/10
2001:db8::/32
```

**Einzelne Hostadressen:**

```
192.168.1.1/32
::1/128
```

## So funktioniert der Schutz vor Rebinding

Die App verarbeitet jede DNS-Antwort in diesen Schritten:

1. **Prüfung auf Ausnahme**: Steht `enableProtection` auf `false` oder ist in der Antwort das Flag `AuthoritativeAnswer` gesetzt, geht die Antwort unverändert zurück

2. **Prüfung des Client-Netzes**: Die IP-Adresse des Clients wird mit jedem Eintrag in `bypassNetworks` verglichen; bei einem Treffer geht die Antwort unverändert zurück

3. **Prüfung der Einträge**: Für jeden A- oder AAAA-Eintrag im Antwortteil:
   - Domainnamen und IP-Adresse auslesen
   - prüfen, ob die Domain zu einem Eintrag in `privateDomains` passt (einschließlich übergeordneter Zonen)
   - ist die Domain privat, zum nächsten Eintrag springen
   - ist die Domain öffentlich, prüfen, ob die IP-Adresse in einem Bereich aus `privateNetworks` liegt
   - ist die IP-Adresse privat, den Eintrag zum Entfernen vormerken

4. **Anpassung der Antwort**: Wurden Einträge zum Entfernen vorgemerkt, entsteht eine neue Antwort nur mit den erlaubten Einträgen

5. **Auslieferung an den Client**: Zurück geht entweder die ursprüngliche Antwort (kein Rebinding erkannt) oder die gefilterte Antwort

## Einsatzbeispiele

**Split-Horizon-DNS im Unternehmen**: Interne Domainnamen wie `intranet.corp.local` dürfen auf `10.x.x.x` auflösen, während externe Domains keine privaten IP-Adressen liefern dürfen.

**Schutz für Kunden von Providern**: DNS-Rebinding-Angriffe auf Heimrouter (meist unter `192.168.x.x`) verhindern, indem private IP-Adressen in den Antworten zu allen öffentlichen Domains gefiltert werden.

**Sicherheit im Heimnetz**: IoT-Geräte und Heimserver vor Cross-Site-Request-Forgery schützen, die per DNS-Rebinding auf Adressen wie `192.168.1.x` zielt.

**Abgrenzung von Entwicklungsumgebungen**: Über `bypassNetworks` erhalten Entwicklerrechner uneingeschränkten DNS-Zugriff, während die Client-Netze im Betrieb geschützt bleiben.

**Organisationen mit mehreren Standorten**: Eigene Listen in `privateDomains` für die internen Namen jedes Standorts (etwa `site1.internal`, `site2.internal`).

**Schutz bei IPv6-Dual-Stack**: Rebinding-Angriffe auf Unique Local Addresses (`fc00::/7`) und Link-Local-Adressen (`fe80::/10`) in Netzen mit IPv6 verhindern.

## Fehlersuche

### Interne Domainnamen werden nicht aufgelöst

**Anzeichen**: Anfragen nach internen Domainnamen liefern leere Antworten oder SERVFAIL.

**Vorgehen**:

1. Prüfe das Protokoll des DNS-Servers auf Einträge des Rebinding-Schutzes
2. Prüfe, ob der Domainname in `privateDomains` eingetragen ist
3. Prüfe, ob die übergeordnete Zone richtig passt (`example.local` erlaubt zum Beispiel `host.example.local`)

**Lösung**: Die betroffene Domain in `dnsApp.config` in die Liste `privateDomains` aufnehmen.

### Schutz greift bei öffentlichen Domains nicht

**Anzeichen**: Öffentliche Domainnamen lösen ungefiltert auf private IP-Adressen auf.

**Vorgehen**:

1. Prüfe, ob `enableProtection` auf `true` steht
2. Prüfe, ob die Client-IP in `bypassNetworks` eingetragen ist
3. Prüfe, ob in der DNS-Antwort das Flag `AuthoritativeAnswer` nicht gesetzt ist
4. Prüfe, ob die IP-Adresse in `privateNetworks` enthalten ist

**Lösung**: Die Konfiguration auf ungewollte Ausnahmen oder fehlende private Netze prüfen.

### Gewollte private IP-Adressen werden gefiltert

**Anzeichen**: Split-Horizon-DNS oder interne Dienste sind nicht erreichbar, weil Antworten gefiltert werden.

**Vorgehen**:

1. Die betroffenen Domainnamen ermitteln
2. Prüfen, ob die Domains in `privateDomains` eingetragen sind
3. Prüfen, ob der Abgleich mit übergeordneten Zonen funktioniert

**Lösung**: Die betroffenen Domains in `privateDomains` oder das Client-Netz in `bypassNetworks` aufnehmen.

### Änderungen an der Konfiguration wirken nicht

**Anzeichen**: Änderungen an `dnsApp.config` ändern das Verhalten der App nicht.

**Vorgehen**:

1. Prüfe, ob die Datei `dnsApp.config` im richtigen App-Ordner liegt
2. Prüfe die JSON-Syntax mit einem JSON-Validator
3. Prüfe das Protokoll des DNS-Servers auf Fehler beim Einlesen der Konfiguration

**Lösung**: Die App über die Weboberfläche neu laden, indem du ihre Konfiguration erneut speicherst.
