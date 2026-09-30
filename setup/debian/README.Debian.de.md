# ZenitiumDNS unter Debian

[English version](README.Debian.md)

## Installation

```
sudo apt install ./zenitiumdns_<version>_<arch>.deb
```

Das Paket enthält die .NET-Laufzeit, eine separate .NET-Installation ist nicht nötig.

| Pfad | Inhalt |
| ---- | ------ |
| `/opt/zenitiumdns` | Programmdateien |
| `/etc/zenitiumdns` | Konfigurationsordner (Zonen, Einstellungen, Cache, Statistiken) |
| `/etc/zenitiumdns/iana` | Geprüfte Kopien von Root-Zone, arpa-Zone und Root-Vertrauensankern von IANA sowie eigene Versionen |
| `/var/log/zenitiumdns` | Logdateien |
| `/usr/share/zenitiumdns/apps` | Mitgelieferte DNS-Apps als ZIP-Dateien, werden beim Start deaktiviert installiert und bei Paket-Updates aktualisiert |
| `/usr/lib/systemd/system/zenitiumdns.service` | systemd-Dienst |

Der Dienst läuft als unprivilegierter Systembenutzer `zenitiumdns` und wird nach der Installation automatisch aktiviert und gestartet.

## Erste Anmeldung

Bei der Erstinstallation wird ein zufälliges Passwort für den Benutzer `admin` erzeugt. Der Installer gibt es aus und speichert es in `/etc/zenitiumdns/admin.password`. Rufe `http://<IP-Adresse-des-Servers>:5380/` auf, melde dich an, wähle die Sprache der Oberfläche (Deutsch oder Englisch) und ändere das Passwort im Kontomenü. Sobald das Passwort von `admin` nicht mehr mit dem in der Datei übereinstimmt, löscht der Server `/etc/zenitiumdns/admin.password` selbst, direkt nach der Änderung oder beim nächsten Start.

Die Sprache gilt für alle Benutzer des Servers und lässt sich jederzeit unter Einstellungen > Server > Sprache ändern. Aktualisierte bestehende Installationen bleiben auf Deutsch.

## Port 53

Ist bei der Erstinstallation systemd-resolved aktiv, wird dessen Stub-Listener über `/etc/systemd/resolved.conf.d/zenitiumdns.conf` abgeschaltet, damit Port 53 frei wird. Zeigte `/etc/resolv.conf` auf den Stub-Resolver, wird die Datei stattdessen auf `/run/systemd/resolve/resolv.conf` verlinkt. Beim Entfernen des Pakets werden beide Änderungen rückgängig gemacht.

Darüber hinaus verändert der Installer `/etc/resolv.conf` nicht. Soll der Server selbst ZenitiumDNS verwenden, trage `nameserver 127.0.0.1` in `/etc/resolv.conf` oder in der Netzwerkkonfiguration ein.

Andere DNS-Server wie `bind9`, `dnsmasq` oder `unbound` müssen beendet werden, bevor ZenitiumDNS Port 53 belegen kann. Der Installer warnt, wenn der Port bereits belegt ist.

## Umgebungsvariablen

Umgebungsvariablen für den Dienst (siehe `docs/EnvironmentVariables.md` im Quellbaum) lassen sich in `/etc/default/zenitiumdns` setzen, zum Beispiel:

```
DNS_SERVER_UPDATE_CHECK_URL=https://example.org/zenitiumdns/update.json
```

Nach einer Änderung `sudo systemctl restart zenitiumdns` ausführen.

## DNS-over-QUIC und HTTP/3

Das Paket enthält `libmsquic` 2.6.1 aus dem Debian-13-Repository von Microsoft als `/opt/zenitiumdns/libmsquic.so.2`, DNS-over-QUIC und DNS-over-HTTPS mit HTTP/3 funktionieren also ohne weitere Pakete. Der Server lädt diese Kopie vor einer im System installierten `libmsquic`. Sie benötigt glibc 2.38 oder neuer und `libnuma1`, das vom Paket mitinstalliert wird.

Ein mit `build-deb.sh --no-msquic` gebautes Paket enthält die Bibliothek nicht. Dafür `libmsquic` aus dem Paket-Repository von Microsoft installieren:

```
wget https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update
sudo apt install libmsquic
sudo systemctl restart zenitiumdns
```

## TLS-Zertifikate

ZenitiumDNS liest PEM-Zertifikate direkt, etwa `fullchain.pem` und `privkey.pem` von Let's Encrypt, eine Umwandlung in PKCS#12 ist nicht nötig. PKCS#12-Dateien (`.pfx`, `.p12`) funktionieren weiterhin. Zertifikat und Schlüssel werden nach einer Änderung innerhalb einer Minute automatisch neu geladen.

Der Dienst läuft als Benutzer `zenitiumdns` und darf `/etc/letsencrypt/live` nicht lesen. Am einfachsten kopiert ein Deploy-Hook von certbot die Dateien nach jeder Erneuerung in den Konfigurationsordner:

```
sudo certbot certonly --standalone -d dns.example.org --deploy-hook 'install -o zenitiumdns -g zenitiumdns -m 0644 "$RENEWED_LINEAGE/fullchain.pem" /etc/zenitiumdns/fullchain.pem; install -o zenitiumdns -g zenitiumdns -m 0600 "$RENEWED_LINEAGE/privkey.pem" /etc/zenitiumdns/privkey.pem'
```

Anschließend unter Einstellungen > Verschlüsselte Protokolle als TLS-Zertifikat `fullchain.pem` und als privaten Schlüssel `privkey.pem` eintragen, beides relativ zum Konfigurationsordner. Für die Weboberfläche gilt dasselbe unter Einstellungen > Weboberfläche. Verschlüsselte Schlüssel müssen im PKCS#8-Format vorliegen (`BEGIN ENCRYPTED PRIVATE KEY`).

Damit Windows 11, iOS und macOS per DDR automatisch auf DoH, DoT oder DoQ wechseln, sollte das Zertifikat zusätzlich die IP-Adressen des Servers enthalten. Let's Encrypt stellt solche Zertifikate nicht aus. Der Selbsttest zeigt an, ob das Zertifikat IP-Adressen enthält.

## Lokale Blocklisten

Blocklisten können auch lokale Dateien sein (`file:///pfad/zur/liste.txt`). Der Dienst läuft mit `ProtectHome` und `PrivateTmp` und sieht deshalb keine Dateien unter `/home`, `/root` oder `/tmp`. Lege lokale Listen in den Konfigurationsordner, etwa nach `/etc/zenitiumdns/lists`, lesbar für den Benutzer `zenitiumdns`:

```
sudo install -d -o zenitiumdns -g zenitiumdns -m 0750 /etc/zenitiumdns/lists
sudo install -o zenitiumdns -g zenitiumdns -m 0640 meine-liste.txt /etc/zenitiumdns/lists/
```

Anschließend unter Einstellungen > Blockierung `file:///etc/zenitiumdns/lists/meine-liste.txt` eintragen.

## Root-Zone und Vertrauensanker

Der Dienst lädt Root-Zone und arpa-Zone von `www.internic.net` sowie die Root-Vertrauensanker von `data.iana.org` über HTTPS und nutzt sie erst nach vollständiger Prüfung (ZONEMD-Prüfsumme, DNSSEC-Signaturen, ICANN-Signatur der Anker). Der Server braucht dafür ausgehenden HTTPS-Zugang. Ohne diesen Zugang oder bei gescheiterter Prüfung fragt der Resolver wie gewohnt die Root-Server. Einstellungen und Status stehen unter Einstellungen > Resolver.

## Überwachung

Die Übersicht der Weboberfläche zeigt Anfragen pro Sekunde, Antwortzeiten, Cache-Treffer-, Fehler- und Blockierquote, den Zustand der IPv6-Anbindung und Zeiträume von einer Minute bis zwölf Monaten. Darunter zeigen Echtzeitgraphen CPU, Arbeitsspeicher, Garbage Collection, Threadpool, Warteschlangen und laufende Auflösungen der letzten fünf Minuten; abschaltbar unter Einstellungen > Server. Der Wächter greift bei Engpässen selbst ein und meldet das im Selbsttest und im Protokoll.

## Arbeitsspeicher

Den meisten Arbeitsspeicher belegen die Blocklisten, der Cache und die Statistik der laufenden Stunde. Mit HaGeZi TIF und PRO (2,5 Millionen Domains, rund 80 MB) und dauerhaft 2.000 Anfragen/s ist rund 1 GB belegter Speicher normal; ein Teil davon ist freier Platz im Heap, den die Garbage Collection ohne Pausen für Anfragen wiederverwendet. Die Größe des Caches steht unter Einstellungen > Cache, bei Speichermangel kürzt der Wächter den Cache.

Ein Cache-Eintrag belegt grob 600 bis 700 Byte plus seine Einträge; mit DNSSEC-Signaturen, Delegationen und negativen Antworten sind es oft 2 bis 4 KB. Bei sehr vielen oder unbegrenzt vielen Einträgen empfiehlt sich eine Speichergrenze unter Einstellungen > Cache (etwa ein Drittel des Arbeitsspeichers der Maschine). Wird sie überschritten, entfernt die Cache-Wartung jede Minute die am längsten ungenutzten Einträge und kompaktiert den Heap nach großen Schnitten.

Ist der Speicher knapp, lässt sich die Garbage Collection in `/etc/default/zenitiumdns` anweisen, den Heap öfter zu verdichten:

```
DOTNET_GCConserveMemory=5
```

Erlaubt sind Werte von 0 bis 9. Im Test senkte Stufe 7 den belegten Speicher um rund 30 %, hielt die Anfragebearbeitung dafür aber zeitweise bis zu einer halben Sekunde an; die Einstellung lohnt sich also nur, wenn Speicher wichtiger ist als Antwortzeiten. Danach den Dienst mit `sudo systemctl restart zenitiumdns` neu starten.

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
| `--no-msquic` | `libmsquic` nicht mitliefern. Sonst lädt das Skript `libmsquic` 2.6.1 für die Zielarchitektur einmalig aus dem Debian-13-Repository von Microsoft, prüft die SHA-256-Prüfsumme und legt es in `~/.cache/zenitiumdns-build` ab. |
| `--no-ready-to-run` | ReadyToRun-Vorkompilierung abschalten (kleineres Paket, langsamerer Start). |

Liegt `dotnet` nicht im `PATH`, den Pfad über die Umgebungsvariable `DOTNET` angeben.
