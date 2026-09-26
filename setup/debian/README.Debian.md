# ZenitiumDNS unter Debian

## Installation

```
sudo apt install ./zenitiumdns_<version>_<arch>.deb
```

Das Paket enthält die .NET-Laufzeit, eine separate .NET-Installation ist nicht nötig.

| Pfad | Inhalt |
| ---- | ------ |
| `/opt/zenitiumdns` | Programmdateien |
| `/etc/zenitiumdns` | Konfigurationsordner (Zonen, Einstellungen, Cache, Statistiken) |
| `/var/log/zenitiumdns` | Logdateien |
| `/usr/share/zenitiumdns/apps` | Mitgelieferte DNS-Apps als ZIP-Dateien, werden beim Start deaktiviert installiert und bei Paket-Updates aktualisiert |
| `/usr/lib/systemd/system/zenitiumdns.service` | systemd-Dienst |

Der Dienst läuft als unprivilegierter Systembenutzer `zenitiumdns` und wird nach der Installation automatisch aktiviert und gestartet.

## Erste Anmeldung

Bei der Erstinstallation wird ein zufälliges Passwort für den Benutzer `admin` erzeugt. Der Installer gibt es aus und speichert es in `/etc/zenitiumdns/admin.password`. Rufe `http://<IP-Adresse-des-Servers>:5380/` auf, melde dich an, ändere das Passwort und lösche anschließend die Datei:

```
sudo rm /etc/zenitiumdns/admin.password
```

## Port 53

Ist bei der Erstinstallation systemd-resolved aktiv, wird dessen Stub-Listener über `/etc/systemd/resolved.conf.d/zenitiumdns.conf` abgeschaltet, damit Port 53 frei wird. Zeigte `/etc/resolv.conf` auf den Stub-Resolver, wird die Datei stattdessen auf `/run/systemd/resolve/resolv.conf` verlinkt. Beim Entfernen des Pakets werden beide Änderungen rückgängig gemacht.

Darüber hinaus verändert der Installer `/etc/resolv.conf` nicht. Soll der Server selbst ZenitiumDNS verwenden, trage `nameserver 127.0.0.1` in `/etc/resolv.conf` oder in der Netzwerkkonfiguration ein.

Andere DNS-Server wie `bind9`, `dnsmasq` oder `unbound` müssen beendet werden, bevor ZenitiumDNS Port 53 belegen kann. Der Installer warnt, wenn der Port bereits belegt ist.

## Umgebungsvariablen

Umgebungsvariablen für den Dienst (siehe `docs/EnvironmentVariables.md` im Quellbaum) lassen sich in `/etc/default/zenitiumdns` setzen, zum Beispiel:

```
DNS_SERVER_UPDATE_CHECK_URL=https://example.org/zenitiumdns/update.json
DNS_SERVER_APP_STORE_URL=https://example.org/zenitiumdns/apps.json
```

Nach einer Änderung `sudo systemctl restart zenitiumdns` ausführen.

## DNS-over-QUIC und HTTP/3

DNS-over-QUIC und DNS-over-HTTPS mit HTTP/3 benötigen `libmsquic` aus dem Paket-Repository von Microsoft:

```
wget https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update
sudo apt install libmsquic
sudo systemctl restart zenitiumdns
```

## TLS-Zertifikate

Der Dienst hat nur Lesezugriff auf `/etc/zenitiumdns` und den Programmordner. Lege Zertifikatsdateien (pfx) in `/etc/zenitiumdns` ab und mache sie für den Benutzer `zenitiumdns` lesbar:

```
sudo chown zenitiumdns:zenitiumdns /etc/zenitiumdns/cert.pfx
```

## Überwachung

Die Übersicht der Weboberfläche zeigt Anfragen pro Sekunde, Antwortzeiten, Cache-Treffer-, Fehler- und Blockierquote sowie den Zustand der IPv6-Anbindung. Für externe Überwachung liefert `http://<IP-Adresse-des-Servers>:5380/api/dashboard/metrics/text` dieselben Werte im Prometheus-Format, `…/metrics/json` als JSON.

Lege dafür unter Verwaltung > Benutzer einen eigenen Benutzer an, gib ihm über eine Gruppe nur das Leserecht für den Bereich Übersicht und erzeuge unter Verwaltung > Sitzungen ein API-Token für ihn. Beispiel für Prometheus:

```
scrape_configs:
  - job_name: zenitiumdns
    metrics_path: /api/dashboard/metrics/text
    authorization:
      credentials: <API-Token>
    static_configs:
      - targets: ['dns.example.org:5380']
```

## Dienst verwalten

```
sudo systemctl status zenitiumdns
sudo systemctl restart zenitiumdns
sudo journalctl -u zenitiumdns
```

## Entfernen

`sudo apt remove zenitiumdns` entfernt das Programm und behält Konfigurations- und Log-Ordner. `sudo apt purge zenitiumdns` löscht zusätzlich `/etc/zenitiumdns`, `/var/log/zenitiumdns` und den Benutzer `zenitiumdns`.

## Paket bauen

Das Paket wird mit dem .NET 10 SDK auf einer beliebigen Linux-Distribution aus dem Quellbaum gebaut:

```
setup/debian/build-deb.sh --arch amd64
setup/debian/build-deb.sh --arch arm64
```

Optionen:

| Option | Beschreibung |
| ------ | ------------ |
| `--arch amd64\|arm64` | Zielarchitektur, standardmäßig die des Build-Rechners. |
| `--output ORDNER` | Ausgabeordner, standardmäßig `setup/debian/dist`. |
| `--revision N` | Debian-Paketrevision, standardmäßig `1`. |
| `--maintainer 'Name <E-Mail>'` | Wert des Feldes `Maintainer`. |
| `--no-apps` | Die DNS-Apps nicht mitliefern. |
| `--no-ready-to-run` | ReadyToRun-Vorkompilierung abschalten (kleineres Paket, langsamerer Start). |

Liegt `dotnet` nicht im `PATH`, den Pfad über die Umgebungsvariable `DOTNET` angeben.
