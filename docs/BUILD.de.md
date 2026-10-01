# Build-Anleitung

[English version](BUILD.md)

Alle Projekte gehören zu einer gemeinsamen Solution (`ZenitiumDNS.slnx`) und verwenden Projektreferenzen, daher ist kein separater Build der Bibliothek nötig. Zum Bauen wird das [.NET 10 SDK](https://dotnet.microsoft.com/download) benötigt.

## Linux

Mit den folgenden Schritten wird der DNS-Server aus dem Quellcode gebaut und installiert. Die Anleitung ist für Debian, Ubuntu und Raspberry Pi OS geschrieben, lässt sich aber leicht auf andere Distributionen übertragen.

1. Voraussetzungen wie curl und git installieren.
```
sudo apt update
sudo apt install curl git -y
```

2. Das .NET 10 SDK nach der [Installationsanleitung von Microsoft](https://learn.microsoft.com/de-de/dotnet/core/install/linux) für die jeweilige Distribution installieren.

3. Das .NET 10 SDK und `libmsquic` für DNS-over-QUIC installieren.
```
sudo apt install dotnet-sdk-10.0 libmsquic -y
```

Hinweis: Wer DNS-over-QUIC und HTTP/3 nicht nutzen möchte, kann `libmsquic` weglassen.

4. Den DNS-Server im Wurzelverzeichnis des Quellbaums bauen.
```
dotnet publish src/ZenitiumDns/ZenitiumDns.csproj -c Release -o publish
```

Bei Bedarf die Weboberfläche und die DoH-Infoseite verkleinern. Der Minifier entfernt Kommentare und Leerraum aus HTML-, CSS-, JavaScript- und JSON-Dateien und löscht Source Maps; Debian-Paket und Container-Image erledigen das automatisch.
```
dotnet run --project tools/WebMinifier/WebMinifier.csproj -c Release -- publish/www publish/dohwww
```

5. Bei Bedarf die mitgelieferten DNS-Apps bauen. Jede App landet in ihrem eigenen Ordner `apps/<AppName>/bin/Release`, der als ZIP-Datei gepackt und im Bereich Apps der Weboberfläche installiert werden kann.
```
dotnet build apps/AdvancedBlockingApp/AdvancedBlockingApp.csproj -c Release
```

6. Den DNS-Server als Dienst installieren. Der Installer kopiert die Dateien nach `/opt/zenitiumdns` und legt den Systembenutzer `zenitiumdns` an. Als Konfigurationsordner dient `/etc/zenitiumdns`, als Log-Ordner `/var/log/zenitiumdns`. Eingerichtet wird ein systemd- oder OpenRC-Dienst namens `zenitiumdns`. Fehlt die ASP.NET Core Runtime 10, lädt der Installer sie nach `/opt/dotnet`.

Bei der Erstinstallation stellt der Installer außerdem das System auf ZenitiumDNS um: Mit systemd stoppt und deaktiviert er `systemd-resolved` und setzt `dns=none` in `/etc/NetworkManager/NetworkManager.conf`; in beiden Fällen sichert er `/etc/resolv.conf` als `/opt/zenitiumdns/resolv.conf.bak` und ersetzt sie durch `nameserver 127.0.0.1`. Der Deinstaller stellt die gesicherte Datei wieder her. Das Debian-Paket weiter unten ändert `/etc/resolv.conf` nicht.

```
sudo sh publish/install.sh
```

Zum Deinstallieren `sudo sh /opt/zenitiumdns/uninstall.sh` ausführen.

7. Die Weboberfläche im Browser unter `http://<IP-Adresse-des-Servers>:5380/` öffnen, die Sprache der Oberfläche wählen und ein neues Passwort für den Benutzer `admin` festlegen, um die Installation abzuschließen.

## Debian-Paket

Ein eigenständiges Debian-Paket für Debian 13 (trixie), das keine separat installierte .NET-Laufzeit benötigt, lässt sich auf jeder Linux-Distribution mit dem .NET 10 SDK bauen. Die mitgelieferten DNS-Apps sind als ZIP-Dateien enthalten, ebenso `libmsquic` für DNS-over-QUIC und HTTP/3; das Skript lädt es aus dem Paket-Repository von Microsoft und braucht dafür `curl`.

```
setup/debian/build-deb.sh --arch amd64
setup/debian/build-deb.sh --arch arm64
```

Das Paket wird im Ordner `setup/debian/dist` erzeugt und so installiert:

```
sudo apt install ./zenitiumdns_<version>_<arch>.deb
```

Paketaufbau, erste Anmeldung und Build-Optionen sind in [setup/debian/README.Debian.de.md](../setup/debian/README.Debian.de.md) beschrieben.
