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

5. Bei Bedarf die mitgelieferten DNS-Apps bauen. Jede App landet in ihrem eigenen Ordner `apps/<AppName>/bin/Release`, der als ZIP-Datei gepackt und im Bereich Apps der Weboberfläche installiert werden kann.
```
dotnet build apps/AdvancedBlockingApp/AdvancedBlockingApp.csproj -c Release
```

6. Den DNS-Server als Dienst installieren. Der Installer kopiert die Dateien nach `/opt/zenitiumdns` und legt den Systembenutzer `zenitiumdns` an. Als Konfigurationsordner dient `/etc/zenitiumdns`, als Log-Ordner `/var/log/zenitiumdns`. Eingerichtet wird ein systemd- oder OpenRC-Dienst namens `zenitiumdns`.

```
sudo sh publish/install.sh
```

Zum Deinstallieren `sudo sh /opt/zenitiumdns/uninstall.sh` ausführen.

7. Die Weboberfläche im Browser unter `http://<IP-Adresse-des-Servers>:5380/` öffnen, die Sprache der Oberfläche wählen und ein Passwort festlegen, um die Installation abzuschließen.

## Debian-Paket

Ein eigenständiges Debian-Paket für Debian 13 (trixie), das keine separat installierte .NET-Laufzeit benötigt, lässt sich auf jeder Linux-Distribution mit dem .NET 10 SDK bauen. Die mitgelieferten DNS-Apps sind als ZIP-Dateien enthalten.

```
setup/debian/build-deb.sh --arch amd64
setup/debian/build-deb.sh --arch arm64
```

Das Paket wird im Ordner `setup/debian/dist` erzeugt und so installiert:

```
sudo apt install ./zenitiumdns_<version>_<arch>.deb
```

Paketaufbau, erste Anmeldung und Build-Optionen sind in [setup/debian/README.Debian.de.md](../setup/debian/README.Debian.de.md) beschrieben.
