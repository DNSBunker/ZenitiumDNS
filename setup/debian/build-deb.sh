#!/bin/bash
set -euo pipefail

scriptDir="$(cd "$(dirname "$0")" && pwd)"
rootDir="$(cd "$scriptDir/../.." && pwd)"
dotnet="${DOTNET:-dotnet}"

arch=""
outDir="$scriptDir/dist"
revision="1"
maintainer="ZenitiumDNS contributors <zenitiumdns@localhost>"
withApps="yes"
readyToRun="true"

usage()
{
    echo "Aufruf: $0 [--arch amd64|arm64] [--output ORDNER] [--revision N] [--maintainer 'Name <E-Mail>'] [--no-apps] [--no-ready-to-run]"
}

fail()
{
    echo "Fehler: $*" >&2
    exit 1
}

while [ $# -gt 0 ]
do
    case "$1" in
        --arch) arch="${2:?}"; shift 2 ;;
        --output) outDir="${2:?}"; shift 2 ;;
        --revision) revision="${2:?}"; shift 2 ;;
        --maintainer) maintainer="${2:?}"; shift 2 ;;
        --no-apps) withApps="no"; shift ;;
        --no-ready-to-run) readyToRun="false"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; exit 1 ;;
    esac
done

if [ -z "$arch" ]
then
    case "$(uname -m)" in
        x86_64) arch="amd64" ;;
        aarch64|arm64) arch="arm64" ;;
        *) fail "Architektur '$(uname -m)' des Build-Rechners wird nicht unterstützt, bitte --arch angeben" ;;
    esac
fi

case "$arch" in
    amd64) rid="linux-x64" ;;
    arm64) rid="linux-arm64" ;;
    *) fail "Architektur '$arch' wird nicht unterstützt" ;;
esac

for tool in "$dotnet" ar tar xz gzip md5sum find du
do
    command -v "$tool" >/dev/null 2>&1 || fail "'$tool' wurde nicht gefunden"
done

if [ "$withApps" = "yes" ]
then
    command -v zip >/dev/null 2>&1 || fail "'zip' wurde nicht gefunden, bitte installieren oder --no-apps verwenden"
fi

version="$(sed -n 's:.*<ZenitiumDnsVersion>\(.*\)</ZenitiumDnsVersion>.*:\1:p' "$rootDir/Directory.Build.props")"
[ -n "$version" ] || fail "ZenitiumDnsVersion konnte nicht aus Directory.Build.props gelesen werden"

debVersion="$version-$revision"
packageFile="zenitiumdns_${debVersion}_${arch}.deb"
sourceDateEpoch="${SOURCE_DATE_EPOCH:-$(date +%s)}"

workDir="$(mktemp -d)"
trap 'rm -rf "$workDir"' EXIT

pkgDir="$workDir/pkg"
controlDir="$workDir/control"
installDir="$pkgDir/opt/zenitiumdns"
docDir="$pkgDir/usr/share/doc/zenitiumdns"
appsDir="$pkgDir/usr/share/zenitiumdns/apps"

mkdir -p "$installDir" "$controlDir" "$docDir"

echo "Veröffentliche ZenitiumDNS $version für $rid ..."
"$dotnet" publish "$rootDir/src/ZenitiumDns/ZenitiumDns.csproj" -c Release -r "$rid" --self-contained true -p:PublishReadyToRun="$readyToRun" -p:DebugType=embedded -p:ZenitiumDnsRevision="$revision" -o "$installDir" --nologo -v quiet -clp:ErrorsOnly

[ -x "$installDir/ZenitiumDns" ] || fail "Die Veröffentlichung hat keine ausführbare Datei 'ZenitiumDns' erzeugt"

rm -f "$installDir/install.sh" "$installDir/uninstall.sh" "$installDir/start.sh" "$installDir/openrc.service" "$installDir/systemd.service"

if [ "$withApps" = "yes" ]
then
    mkdir -p "$appsDir"

    for project in "$rootDir"/apps/*/*.csproj
    do
        appName="$(basename "$project" .csproj)"
        appOut="$workDir/apps/$appName"

        echo "Veröffentliche DNS-App $appName ..."
        "$dotnet" publish "$project" -c Release -p:DebugType=embedded -o "$appOut" --nologo -v quiet -clp:ErrorsOnly

        (cd "$appOut" && find . -type f -exec touch -d "@$sourceDateEpoch" {} + && zip -q -r -X -D "$appsDir/$appName.zip" .)
    done
fi

install -m 0644 "$scriptDir/zenitiumdns.service" -D "$pkgDir/usr/lib/systemd/system/zenitiumdns.service"
install -m 0644 "$scriptDir/zenitiumdns.sysusers" -D "$pkgDir/usr/lib/sysusers.d/zenitiumdns.conf"
install -m 0644 "$scriptDir/copyright" "$docDir/copyright"
install -m 0644 "$scriptDir/README.Debian.md" "$docDir/README.Debian.md"
install -m 0644 "$rootDir/README.md" "$docDir/README.md"
install -m 0644 "$rootDir/NOTICE.md" "$docDir/NOTICE.md"
gzip -9 -n -c "$rootDir/CHANGELOG.md" > "$docDir/changelog.gz"

find "$pkgDir" -type d -exec chmod 0755 {} +
find "$pkgDir" -type f -exec chmod 0644 {} +
chmod 0755 "$installDir/ZenitiumDns"
[ -f "$installDir/createdump" ] && chmod 0755 "$installDir/createdump"

installedSize="$(du -sk --apparent-size "$pkgDir" | cut -f1)"

cat > "$controlDir/control" <<CONTROL
Package: zenitiumdns
Version: $debVersion
Section: net
Priority: optional
Architecture: $arch
Maintainer: $maintainer
Installed-Size: $installedSize
Depends: libc6 (>= 2.27), libgcc-s1, libstdc++6, libssl3t64 | libssl3, libicu76 | libicu78 | libicu74 | libicu72, ca-certificates, tzdata, passwd
Recommends: iproute2
Suggests: libmsquic, dnsutils
Provides: dns-server
Homepage: https://github.com/DNSBunker/ZenitiumDNS-DE
Description: Rekursiver DNS-Resolver mit Weboberfläche
 ZenitiumDNS ist ein rekursiver DNS-Resolver für den öffentlichen oder
 internen Betrieb mit deutschsprachiger Weboberfläche. Er bietet unter
 anderem:
  - rekursive Auflösung über die Root-Server oder Forwarding über
    DNS-over-TLS, DNS-over-HTTPS und DNS-over-QUIC,
  - DNSSEC-Validierung mit NSEC und NSEC3,
  - lokale, geprüfte Kopie der Root-Zone nach RFC 8806,
  - eigene DoT-, DoH- und DoQ-Dienste sowie das PROXY-Protokoll,
  - Werbe- und Malware-Blockierung über Blocklisten,
  - Weiterleitungszonen (Conditional Forwarder) mit lokalen Einträgen,
  - Cache mit Serve Stale, Prefetch und Speicherung auf der Festplatte,
  - automatischen IPv6-Rückfall bei gestörter IPv6-Anbindung,
  - Statistik mit Antwortzeiten und Echtzeitgraphen,
  - Ratenbegrenzung, SSO, LDAP und Zwei-Faktor-Anmeldung,
  - DNS-Apps für erweiterte Filter, DNS64 und Protokollexport.
 .
 Das Paket enthält die .NET-Laufzeit und benötigt keine separate
 .NET-Installation. Der Dienst läuft als eigener Systembenutzer und
 erhält bei der Erstinstallation ein zufälliges Admin-Passwort. Die
 mitgelieferten DNS-Apps werden beim ersten Start aus
 /usr/share/zenitiumdns/apps installiert, bleiben aber deaktiviert,
 bis sie in der Weboberfläche aktiviert werden.
CONTROL

install -m 0755 "$scriptDir/postinst" "$controlDir/postinst"
install -m 0755 "$scriptDir/prerm" "$controlDir/prerm"
install -m 0755 "$scriptDir/postrm" "$controlDir/postrm"

(cd "$pkgDir" && find . -type f -printf '%P\0' | LC_ALL=C sort -z | xargs -0 md5sum) > "$controlDir/md5sums"
chmod 0644 "$controlDir/control" "$controlDir/md5sums"

tarOptions=(--format=gnu --owner=0 --group=0 --numeric-owner --sort=name --mtime="@$sourceDateEpoch")

echo "Baue $packageFile ..."
printf '2.0\n' > "$workDir/debian-binary"
tar "${tarOptions[@]}" -C "$controlDir" -cf - . | xz -6 -T0 > "$workDir/control.tar.xz"
tar "${tarOptions[@]}" -C "$pkgDir" -cf - . | xz -6 -T0 > "$workDir/data.tar.xz"

mkdir -p "$outDir"
rm -f "$outDir/$packageFile"
(cd "$workDir" && ar rcD "$outDir/$packageFile" debian-binary control.tar.xz data.tar.xz)

echo "Paket erstellt: $outDir/$packageFile"
