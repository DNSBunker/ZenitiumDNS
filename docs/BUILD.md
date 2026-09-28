# Build instructions

[Deutsche Version](BUILD.de.md)

All projects belong to one solution (`ZenitiumDNS.slnx`) and use project references, so no separate build of the library is needed. Building requires the [.NET 10 SDK](https://dotnet.microsoft.com/download).

## Linux

The following steps build the DNS server from source and install it. The instructions are written for Debian, Ubuntu and Raspberry Pi OS but can easily be adapted to other distributions.

1. Install prerequisites such as curl and git.
```
sudo apt update
sudo apt install curl git -y
```

2. Install the .NET 10 SDK following [Microsoft's installation guide](https://learn.microsoft.com/dotnet/core/install/linux) for your distribution.

3. Install the .NET 10 SDK and `libmsquic` for DNS-over-QUIC.
```
sudo apt install dotnet-sdk-10.0 libmsquic -y
```

Note: If you do not want to use DNS-over-QUIC and HTTP/3, you can leave out `libmsquic`.

4. Build the DNS server in the root folder of the source tree.
```
dotnet publish src/ZenitiumDns/ZenitiumDns.csproj -c Release -o publish
```

5. Optionally build the bundled DNS apps. Each app ends up in its own folder `apps/<AppName>/bin/Release`, which can be packed as a ZIP file and installed in the Apps section of the web interface.
```
dotnet build apps/AdvancedBlockingApp/AdvancedBlockingApp.csproj -c Release
```

6. Install the DNS server as a service. The installer copies the files to `/opt/zenitiumdns` and creates the system user `zenitiumdns`. `/etc/zenitiumdns` serves as the configuration folder and `/var/log/zenitiumdns` as the log folder. A systemd or OpenRC service named `zenitiumdns` is set up.

```
sudo sh publish/install.sh
```

To uninstall, run `sudo sh /opt/zenitiumdns/uninstall.sh`.

7. Open the web interface in your browser at `http://<server-ip-address>:5380/`, choose the interface language and set a password to complete the installation.

## Debian package

A standalone Debian package for Debian 13 (trixie) that needs no separately installed .NET runtime can be built on any Linux distribution with the .NET 10 SDK. The bundled DNS apps are included as ZIP files, and `libmsquic` for DNS-over-QUIC and HTTP/3 is included as well; the script downloads it from Microsoft's package repository and needs `curl` for that.

```
setup/debian/build-deb.sh --arch amd64
setup/debian/build-deb.sh --arch arm64
```

The package is created in the folder `setup/debian/dist` and installed like this:

```
sudo apt install ./zenitiumdns_<version>_<arch>.deb
```

Package layout, first sign-in and build options are described in [setup/debian/README.Debian.md](../setup/debian/README.Debian.md).
