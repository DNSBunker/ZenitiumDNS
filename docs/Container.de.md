# Container-Image

[English version](Container.md)

ZenitiumDNS gibt es als OCI-Container-Image für amd64 und arm64. Es wird für jedes Release aus diesem Repository gebaut und läuft mit Podman und Docker:

```
ghcr.io/dnsbunker/zenitiumdns:latest
ghcr.io/dnsbunker/zenitiumdns:15.5.1-11
```

Das Image basiert auf Alpine Linux und enthält den eigenständigen Server, die mitgelieferten Apps und `libmsquic` für DNS-over-QUIC und HTTP/3. Der Server läuft als unprivilegierter Benutzer `zenitiumdns` (UID und GID 1053).

## Starten

```
podman run -d --name zenitiumdns \
  -p 53:53/udp -p 53:53/tcp -p 5380:5380/tcp \
  -v zenitiumdns-config:/etc/zenitiumdns \
  -v zenitiumdns-logs:/var/log/zenitiumdns \
  --restart unless-stopped \
  ghcr.io/dnsbunker/zenitiumdns:latest
```

Mit Docker gilt derselbe Befehl mit `docker` statt `podman`.

Rootless Podman darf keine Ports unter 1024 veröffentlichen. Entweder den Container als root starten, niedrige Ports mit `sudo sysctl net.ipv4.ip_unprivileged_port_start=53` freigeben oder das Netz des Hosts verwenden (`--network host`). Manche Netzmodi von Rootless Podman ersetzen die Client-Adresse durch die Adresse des Container-Gateways; für Statistik, Ratenbegrenzung und Zugriffsregeln mit den echten Client-Adressen das Netz des Hosts oder einen Container mit root-Rechten verwenden.

## Erste Anmeldung

Beim ersten Start legt der Container ein zufälliges Passwort für den Benutzer `admin` an und gibt es im Container-Protokoll aus:

```
podman logs zenitiumdns
```

Das Passwort steht außerdem in `/etc/zenitiumdns/admin.password`. `http://<Host>:5380/` öffnen, anmelden, die Sprache wählen und das Passwort im Kontomenü ändern. Der Server löscht die Datei danach selbst, ebenso wenn der Benutzer `admin` gelöscht oder umbenannt wird.

## Ports

| Port | Protokoll | Dienst |
| ---- | --------- | ------ |
| 53 | UDP, TCP | DNS |
| 5380 | TCP | Weboberfläche (HTTP) |
| 53443 | TCP | Weboberfläche (HTTPS, wenn eingeschaltet) |
| 853 | TCP | DNS-over-TLS |
| 853 | UDP | DNS-over-QUIC |
| 443 | TCP, UDP | DNS-over-HTTPS mit HTTP/2 und HTTP/3 |

Nur die Ports der eingeschalteten Dienste veröffentlichen. Zertifikate für die verschlüsselten Protokolle gehören in das Konfigurations-Volume, etwa `/etc/zenitiumdns/fullchain.pem` und `/etc/zenitiumdns/privkey.pem`, lesbar für UID 1053; unter Einstellungen > Dienste relativ zum Konfigurationsordner eintragen.

## Volumes

| Pfad | Inhalt |
| ---- | ------ |
| `/etc/zenitiumdns` | Einstellungen, Benutzer, Statistik, Cache, heruntergeladene Blocklisten und installierte Apps |
| `/var/log/zenitiumdns` | Protokolldateien |

Der Container startet als root, übergibt Konfigurations- und Protokollordner an UID 1053, auch vom Host eingebundene Ordner, und startet den Server dann als dieser Benutzer. Läuft der Container mit festem Benutzer (`--user` oder `user:` in Compose), kann er den Besitzer nicht selbst ändern; eingebundene Ordner müssen dann für diesen Benutzer beschreibbar sein, sonst beendet sich der Container mit einer Meldung, die den Ordner nennt:

```
sudo mkdir -p /srv/zenitiumdns/config /srv/zenitiumdns/logs
sudo chown -R 1053:1053 /srv/zenitiumdns
```

Lokale Blocklisten (`file://`) gehören ebenfalls in das Konfigurations-Volume, etwa `file:///etc/zenitiumdns/lists/meine-liste.txt`.

## Rekursion

Neue Installationen beantworten rekursive Anfragen nur aus privaten Netzen. Das reicht zu Hause und im Firmennetz. Erreichen Clients den Server über öffentliche Adressen, die Rekursion unter Einstellungen > Resolver anpassen und die Ratenbegrenzung prüfen.

## Aktualisieren

```
podman pull ghcr.io/dnsbunker/zenitiumdns:latest
podman rm -f zenitiumdns
```

Danach den Container mit demselben Befehl wieder starten. Einstellungen und Statistik bleiben in den Volumes erhalten.

## Arbeitsspeicher

Umgebungsvariablen werden mit `-e` übergeben. Damit die Garbage Collection bei knappem Speicher den Heap öfter verdichtet (um den Preis längerer Pausen, siehe [README.Debian](../setup/debian/README.Debian.de.md)):

```
-e DOTNET_GCConserveMemory=5
```

Größe und optionale Speichergrenze des Caches stehen unter Einstellungen > Cache. Mit einer Speichergrenze für den Container (`--memory`) hält der Server den Cache selbst darunter: ab 85 % der Grenze wächst der Cache nicht mehr, ab 90 % wird er gekürzt. Leitet der Container an einen cachenden Resolver wie Unbound weiter, lässt sich der Cache dort vollständig abschalten (Cache verwenden).

## Image selbst bauen

```
podman build -t zenitiumdns -f Containerfile .
```

Die Build-Stufe läuft immer auf der Architektur des Build-Rechners und kompiliert für die Zielarchitektur. Für eine andere Architektur, etwa mit `--platform linux/arm64`, braucht die letzte Stufe `qemu-user-static`.
