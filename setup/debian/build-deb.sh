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
withMsquic="yes"
readyToRun="true"
msquicVersion="2.6.1"
msquicCacheDir="${XDG_CACHE_HOME:-$HOME/.cache}/zenitiumdns-build"

usage()
{
    echo "Aufruf: $0 [--arch amd64|arm64] [--output ORDNER] [--revision N] [--maintainer 'Name <E-Mail>'] [--no-apps] [--no-msquic] [--no-ready-to-run]"
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
        --no-msquic) withMsquic="no"; shift ;;
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
    amd64)
        rid="linux-x64"
        msquicTriplet="x86_64-linux-gnu"
        msquicSha256="8c6fc9982f796b7e4fe554bef6f0cf0e0a6a237d5f00dafcf804a304530f810b"
        ;;
    arm64)
        rid="linux-arm64"
        msquicTriplet="aarch64-linux-gnu"
        msquicSha256="092a89372863f19c8bbb540cb0db663a67a47219c5c291bd296697c32a09c219"
        ;;
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

if [ "$withMsquic" = "yes" ]
then
    for tool in curl sha256sum
    do
        command -v "$tool" >/dev/null 2>&1 || fail "'$tool' wurde nicht gefunden, bitte installieren oder --no-msquic verwenden"
    done
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

extraDepends=""
suggests="libmsquic, dnsutils"
bundledText="the .NET runtime"

if [ "$withMsquic" = "yes" ]
then
    msquicDeb="$msquicCacheDir/libmsquic_${msquicVersion}_${arch}.deb"

    if [ ! -f "$msquicDeb" ] || ! echo "$msquicSha256  $msquicDeb" | sha256sum -c --status
    then
        echo "Lade libmsquic $msquicVersion für $arch ..."
        mkdir -p "$msquicCacheDir"
        curl -fsSL --retry 3 -o "$msquicDeb.part" "https://packages.microsoft.com/debian/13/prod/pool/main/libm/libmsquic/libmsquic_${msquicVersion}_${arch}.deb"
        mv "$msquicDeb.part" "$msquicDeb"
    fi

    echo "$msquicSha256  $msquicDeb" | sha256sum -c --status || fail "Die Prüfsumme von $msquicDeb stimmt nicht"

    mkdir -p "$workDir/msquic"
    (cd "$workDir/msquic" && ar x "$msquicDeb" && tar -xf data.tar.*)

    msquicLibrary="$workDir/msquic/usr/lib/$msquicTriplet/libmsquic.so.$msquicVersion"
    [ -f "$msquicLibrary" ] || fail "libmsquic.so.$msquicVersion wurde im Paket libmsquic nicht gefunden"

    install -m 0644 "$msquicLibrary" "$installDir/libmsquic.so.2"

    extraDepends=", libnuma1"
    suggests="dnsutils"
    bundledText="the .NET runtime and libmsquic for DNS-over-QUIC
 and HTTP/3"
fi

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
install -m 0644 "$scriptDir/README.Debian.de.md" "$docDir/README.Debian.de.md"
install -m 0644 "$rootDir/README.md" "$docDir/README.md"
install -m 0644 "$rootDir/README.de.md" "$docDir/README.de.md"
install -m 0644 "$rootDir/NOTICE.md" "$docDir/NOTICE.md"
install -m 0644 "$rootDir/NOTICE.de.md" "$docDir/NOTICE.de.md"
gzip -9 -n -c "$rootDir/CHANGELOG.md" > "$docDir/changelog.gz"
gzip -9 -n -c "$rootDir/CHANGELOG.de.md" > "$docDir/changelog.de.gz"

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
Depends: libc6 (>= 2.34), libgcc-s1, libstdc++6, libssl3t64 | libssl3, libicu76 | libicu78 | libicu74 | libicu72, ca-certificates, tzdata, passwd$extraDepends
Recommends: iproute2
Suggests: $suggests
Provides: dns-server
Homepage: https://github.com/DNSBunker/ZenitiumDNS
Description: Recursive DNS resolver with web interface
 ZenitiumDNS is a recursive DNS resolver for public or internal use
 with a web interface in English and German. Features include:
  - recursive resolution via the root servers or forwarding over
    DNS-over-TLS, DNS-over-HTTPS and DNS-over-QUIC,
  - DNSSEC validation with NSEC and NSEC3, including aggressive use
    of cached NSEC and NSEC3 records according to RFC 8198,
  - local, verified copy of the root zone according to RFC 8806,
  - its own DoT, DoH and DoQ services and the PROXY protocol,
  - ad and malware blocking with block lists,
  - forwarder zones (conditional forwarders) with local records,
  - cache with serve stale, prefetch and persistence on disk,
  - automatic IPv6 fallback when IPv6 connectivity is broken,
  - statistics with response times and live graphs,
  - rate limiting, SSO, LDAP and two-factor authentication,
  - DNS apps for advanced filtering, DNS64 and log export.
 .
 The package contains $bundledText and needs no separate .NET
 installation. The service runs as its own system user and gets a
 random admin password on the first installation. The interface
 language is chosen after the first sign-in. The bundled DNS apps are
 installed from /usr/share/zenitiumdns/apps on the first start but stay
 disabled until they are enabled in the web interface.
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
