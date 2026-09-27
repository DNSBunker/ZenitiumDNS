# ZenitiumDNS on Debian

[Deutsche Version](README.Debian.de.md)

## Installation

```
sudo apt install ./zenitiumdns_<version>_<arch>.deb
```

The package contains the .NET runtime; a separate .NET installation is not needed.

| Path | Content |
| ---- | ------- |
| `/opt/zenitiumdns` | Program files |
| `/etc/zenitiumdns` | Configuration folder (zones, settings, cache, statistics) |
| `/etc/zenitiumdns/iana` | Verified copies of the root zone, arpa zone and root trust anchors from IANA as well as custom versions |
| `/var/log/zenitiumdns` | Log files |
| `/usr/share/zenitiumdns/apps` | Bundled DNS apps as ZIP files, installed disabled on start and updated with package updates |
| `/usr/lib/systemd/system/zenitiumdns.service` | systemd service |

The service runs as the unprivileged system user `zenitiumdns` and is enabled and started automatically after installation.

## First sign-in

On the first installation a random password is generated for the user `admin`. The installer prints it and stores it in `/etc/zenitiumdns/admin.password`. Open `http://<server-ip-address>:5380/`, sign in, choose the interface language (English or German), change the password and then delete the file:

```
sudo rm /etc/zenitiumdns/admin.password
```

The language applies to all users of the server and can be changed at any time under Settings > Server > Language. Existing installations that are upgraded keep German.

## Port 53

If systemd-resolved is active during the first installation, its stub listener is turned off via `/etc/systemd/resolved.conf.d/zenitiumdns.conf` so that port 53 becomes free. If `/etc/resolv.conf` pointed to the stub resolver, the file is linked to `/run/systemd/resolve/resolv.conf` instead. Both changes are reverted when the package is removed.

Apart from that, the installer does not change `/etc/resolv.conf`. If the server itself should use ZenitiumDNS, add `nameserver 127.0.0.1` to `/etc/resolv.conf` or the network configuration.

Other DNS servers such as `bind9`, `dnsmasq` or `unbound` must be stopped before ZenitiumDNS can bind port 53. The installer warns if the port is already in use.

## Environment variables

Environment variables for the service (see `docs/EnvironmentVariables.md` in the source tree) can be set in `/etc/default/zenitiumdns`, for example:

```
DNS_SERVER_UPDATE_CHECK_URL=https://example.org/zenitiumdns/update.json
```

Run `sudo systemctl restart zenitiumdns` after a change.

## DNS-over-QUIC and HTTP/3

DNS-over-QUIC and DNS-over-HTTPS with HTTP/3 require `libmsquic` from Microsoft's package repository:

```
wget https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt update
sudo apt install libmsquic
sudo systemctl restart zenitiumdns
```

## TLS certificates

ZenitiumDNS reads PEM certificates directly, such as `fullchain.pem` and `privkey.pem` from Let's Encrypt; converting them to PKCS#12 is not necessary. PKCS#12 files (`.pfx`, `.p12`) still work. Certificate and key are reloaded automatically within a minute after a change.

The service runs as the user `zenitiumdns` and may not read `/etc/letsencrypt/live`. The easiest way is a certbot deploy hook that copies the files to the configuration folder after every renewal:

```
sudo certbot certonly --standalone -d dns.example.org --deploy-hook 'install -o zenitiumdns -g zenitiumdns -m 0644 "$RENEWED_LINEAGE/fullchain.pem" /etc/zenitiumdns/fullchain.pem; install -o zenitiumdns -g zenitiumdns -m 0600 "$RENEWED_LINEAGE/privkey.pem" /etc/zenitiumdns/privkey.pem'
```

Then enter `fullchain.pem` as TLS certificate and `privkey.pem` as private key under Settings > Encrypted protocols, both relative to the configuration folder. The same applies to the web interface under Settings > Web interface. Encrypted keys must be in PKCS#8 format (`BEGIN ENCRYPTED PRIVATE KEY`).

For Windows 11, iOS and macOS to switch to DoH, DoT or DoQ automatically via DDR, the certificate should also contain the IP addresses of the server. Let's Encrypt does not issue such certificates. The self-test shows whether the certificate contains IP addresses.

## Local block lists

Block lists can also be local files (`file:///path/to/list.txt`). The service runs with `ProtectHome` and `PrivateTmp` and therefore cannot see files under `/home`, `/root` or `/tmp`. Put local lists into the configuration folder, for example into `/etc/zenitiumdns/lists`, readable for the user `zenitiumdns`:

```
sudo install -d -o zenitiumdns -g zenitiumdns -m 0750 /etc/zenitiumdns/lists
sudo install -o zenitiumdns -g zenitiumdns -m 0640 my-list.txt /etc/zenitiumdns/lists/
```

Then add `file:///etc/zenitiumdns/lists/my-list.txt` under Settings > Blocking.

## Root zone and trust anchors

The service downloads the root zone and the arpa zone from `www.internic.net` and the root trust anchors from `data.iana.org` over HTTPS and only uses them after full verification (ZONEMD digest, DNSSEC signatures, ICANN signature of the anchors). The server needs outgoing HTTPS access for this. Without that access or if verification fails, the resolver queries the root servers as usual. Settings and status are under Settings > Resolver.

## Monitoring

The dashboard of the web interface shows queries per second, response times, cache hit, failure and block rates, the state of IPv6 connectivity and periods from one minute to twelve months. Below, live graphs show CPU, memory, garbage collection, thread pool, queues and pending resolutions of the last five minutes; this can be turned off under Settings > Server. The watchdog intervenes on bottlenecks by itself and reports it in the self-test and in the log.

## Memory

Most of the memory is taken by the block lists, the cache and the statistics of the current hour. With HaGeZi TIF and PRO (2.5 million domains, about 80 MB) and a steady 2,000 queries/s, around 1 GB of resident memory is normal; part of it is free space inside the heap that the garbage collection reuses without pausing queries. The size of the cache is set under Settings > Cache, and the watchdog trims the cache when memory runs short.

If memory is tight, the garbage collection can be told to compact the heap more often in `/etc/default/zenitiumdns`:

```
DOTNET_GCConserveMemory=5
```

Values range from 0 to 9. In the test, level 7 reduced resident memory by about 30 % but paused query processing for up to half a second at a time, so only raise it if memory matters more than response times. Restart the service afterwards with `sudo systemctl restart zenitiumdns`.

## Managing the service

```
sudo systemctl status zenitiumdns
sudo systemctl restart zenitiumdns
sudo journalctl -u zenitiumdns
```

## Removal

`sudo apt remove zenitiumdns` removes the program and keeps the configuration and log folders. `sudo apt purge zenitiumdns` also deletes `/etc/zenitiumdns`, `/var/log/zenitiumdns` and the user `zenitiumdns`.

## Building the package

The package is built from the source tree with the .NET 10 SDK on any Linux distribution:

```
setup/debian/build-deb.sh --arch amd64
setup/debian/build-deb.sh --arch arm64
```

Options:

| Option | Description |
| ------ | ----------- |
| `--arch amd64\|arm64` | Target architecture, by default that of the build machine. |
| `--output FOLDER` | Output folder, by default `setup/debian/dist`. |
| `--revision N` | Debian package revision, by default `1`. |
| `--maintainer 'Name <email>'` | Value of the `Maintainer` field. |
| `--no-apps` | Do not bundle the DNS apps. |
| `--no-ready-to-run` | Turn off ReadyToRun precompilation (smaller package, slower start). |

If `dotnet` is not in the `PATH`, set its path with the environment variable `DOTNET`.
