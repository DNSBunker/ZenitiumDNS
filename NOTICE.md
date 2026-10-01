# Notice

[Deutsche Version](NOTICE.de.md)

ZenitiumDNS is a modified version of the following works:

- **Technitium DNS Server** version 15.5.1, Copyright (C) 2026 Shreyas Zare (shreyas@technitium.com), https://github.com/TechnitiumSoftware/DnsServer
- **TechnitiumLibrary**, Copyright (C) 2026 Shreyas Zare (shreyas@technitium.com), https://github.com/TechnitiumSoftware/TechnitiumLibrary

Both works are licensed under the GNU General Public License version 3 or (at your option) any later version. ZenitiumDNS is distributed under the same license. The full license text is in the file [LICENSE](LICENSE). The original copyright and license notices in the source files have been kept.

The changes and additions of ZenitiumDNS: Copyright (C) 2026 xRuffKez. Modified source files carry this notice in addition to the original one, newly added files carry their own license header.

The name "Technitium" is only used here to state the origin of this work. ZenitiumDNS is not affiliated with Technitium or the original author and is not endorsed by them.

## Bundled fonts

The web interface contains the fonts **Red Hat Text**, **Red Hat Display** and **Red Hat Mono**, Copyright 2024 The Red Hat Project Authors (https://github.com/RedHatOfficial/RedHatFont). They are licensed under the SIL Open Font License 1.1, whose text is in `src/ZenitiumDns.Core/www/fonts/RedHatFont-OFL.txt`.

## Bundled libraries

The Debian package contains **MsQuic** 2.6.1 (`libmsquic.so.2`), Copyright (c) Microsoft Corporation (https://github.com/microsoft/msquic), licensed under the MIT license. The library contains **quictls**, a fork of OpenSSL, Copyright (c) The OpenSSL Project Authors (https://github.com/quictls/openssl), licensed under the Apache License 2.0.

## Changes

The following changes were made in September 2026:

- The product was renamed to ZenitiumDNS. Logos, icons, product names, user agents, service names, registry keys, installation paths and log paths were replaced.
- The repositories of the DNS server and the library were merged into one source tree with a single solution (`ZenitiumDNS.slnx`). Project references are used instead of precompiled assemblies, and common build properties are in `Directory.Build.props`.
- Namespaces and assemblies were renamed from `TechnitiumLibrary.*` to `ZenitiumLibrary.*` and from `DnsServerCore.*` to `ZenitiumDns.*`. The assembly of the server host was renamed as well.
- Library projects not used by the DNS server were removed (BitTorrent, Tor, UPnP, Security.Cryptography).
- All connections to the infrastructure of the original project were removed. The update check queries the releases of ZenitiumDNS on GitHub and can be redirected or turned off via `DNS_SERVER_UPDATE_CHECK_URL`. The DNS app store no longer exists; all apps are shipped with the package.
- The Linux installer installs from a local build instead of downloading binaries of the original. A self-contained Debian package was added.
- The feature set was reduced to running a public recursive resolver. Removed were authoritative zones (primary, secondary, stub, secondary forwarder, catalog), DNSSEC signing, zone transfers (AXFR/IXFR, XFR-over-TLS/QUIC), DNS NOTIFY, dynamic updates, TSIG, the DHCP server, clustering including the HTTP API client, the DNS apps intended for LAN and hosting scenarios, as well as the Windows service, system tray app, Windows firewall library and Windows installer. Conditional forwarder zones, block lists and allowed and blocked domains are kept.
- Statistics and monitoring were extended with response times (median, percentiles, cache/recursive), live key figures and additional metrics. The web interface was reorganized and extended with settings for IPv6 fallback, UDP receive threads and a pipelining limit.
- The web interface and documentation were translated into German. In addition, there is a complete English version; the language can be chosen after installation.
- The web interface got a new design. The GIF loading animations and the stylesheets for the dark and amber modes were replaced by a shared stylesheet. The DoH landing page with setup instructions was replaced by a short info page.
- Added were a request filter for public operation, DNSSEC validation of ML-DSA-44 and enabling and disabling individual apps. The original Docker image was replaced by an own container image based on Alpine Linux.
- Comments were removed from the source code. The copyright and license headers of the source files were kept. In the Debian package and the container image, the files of the web interface are minified; their readable source is in this repository.
- Numerous bugs, security issues and performance bottlenecks were fixed. The complete list is in [CHANGELOG-ZenitiumDNS.md](CHANGELOG-ZenitiumDNS.md).
