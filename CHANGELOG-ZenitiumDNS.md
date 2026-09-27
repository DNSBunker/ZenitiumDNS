# ZenitiumDNS 15.5.1 compared with Technitium DNS Server 15.5

[Deutsche Version](CHANGELOG-ZenitiumDNS.de.md)

This document only lists the differences between the original build **Technitium DNS Server 15.5** (released on 19 September 2026) and the build **ZenitiumDNS 15.5.1** (as of 28 September 2026). ZenitiumDNS 15.5.1 also contains all fixes from Technitium DNS Server 15.5.1; which of them ZenitiumDNS already had before is listed at the end. The complete version history is in [CHANGELOG.md](CHANGELOG.md).

## Overview

| Area | Technitium DNS Server 15.5 | ZenitiumDNS 15.5 |
| ---- | -------------------------- | ---------------- |
| Name, paths, service | Technitium, `/etc/dns`, service `dns` | ZenitiumDNS, `/etc/zenitiumdns`, service `zenitiumdns` |
| Purpose | authoritative and recursive DNS server, DHCP server, clustering | public recursive resolver; authoritative zones, zone transfers, DHCP, clustering and Windows components removed |
| Update check and app store | hard-wired to Technitium servers | update check against the GitHub releases of ZenitiumDNS with changelog, app store removed |
| Installation on Debian 13 | script downloads binaries and .NET from the internet | self-contained `.deb` package with built-in .NET runtime |
| Initial admin password | `admin` | randomly generated |
| Language of web interface and docs | English | German or English, selectable after installation and switchable at any time |
| CNAME chains across many zones (e.g. `www.bbc.com`, `x.com`) | `SERVFAIL` because of resolver limits that are too low | resolved completely |
| Failure of the root priming query | recursive resolution fails completely | falls back to the root hints |
| "Prefer IPv6" with unreachable IPv6 name servers | every query fails | after the first query, answer over IPv4 in about 30 ms |
| Cache maintenance | blocking garbage collection every minute (50–250 ms stalls) | background garbage collection |
| CPU time per query at 100,000 queries/s | 86–100 µs | 24–30 µs |
| Pipelining over DNS-over-TCP/TLS | unlimited concurrent queries per connection | at most 100 per connection by default, adjustable |
| Broken IPv6 connectivity | IPv6 addresses keep being queried, timeouts delay resolutions | IPv6 is only suspended on a confirmed outage (cross-check via the IPv6 root servers), single dead IPv6 name servers trigger nothing, the first IPv6 response lifts the suspension |
| Response times on the dashboard and in the metrics | not available | median, percentiles, cache/recursive, live and per minute |
| Web interface | Bootstrap default look, fixed minimum width of 970 px, settings in one long page per tab | own design with sidebar and readout band, usable on mobile, settings in topic sections with explanations |
| Queries of type ANY, AXFR/IXFR, without RD flag, foreign opcodes or classes | are processed | dropped over UDP by the request filter, refused with `REFUSED` over TCP/DoT/DoH/DoQ |
| DNSSEC with ML-DSA-44 (post-quantum) | unknown algorithm, zone is treated as unsigned | validated, with downgrade protection |
| Bundled apps | must be installed one by one and are active right away | preinstalled, disabled by default, can be enabled individually |
| Docker | image and compose file | removed |
| Rate limiting | average queries per minute over a sampling window | token bucket in queries per second with burst |
| Client IP block lists | not available | IPsum, Spamhaus DROP and others, dropped before the query is evaluated |
| TLS certificates | PKCS#12 (`.pfx`) only | PEM as well (`fullchain.pem`, `privkey.pem`) |
| DDR (RFC 9462) | only via a zone you create yourself | built in, automatically from the active services, also for DoH behind a reverse proxy |
| Self-test | not available | own section, serious problems on the dashboard |
| Memory for 2.5 million block list entries | about 395 MB | about 80 MB |
| Statistics memory after 30 minutes at 2,000 queries/s from 50,000 clients | about 590 MB, every minute of the last one to two hours kept completely | about 50 MB, completed minutes cut down to the top 1,000 |
| Hourly statistics file of a busy hour | about 100 MB (complete minute data) | 0.6–1.4 MB (hour totals and top 1,000 per minute) |
| Live objects in the same test with HaGeZi TIF and PRO | 945 MB, 18.2 million objects | 271 MB, 3.8 million objects |
| "Prefer IPv6" with name servers without glue and AAAA records | `SERVFAIL` (upstream issue #2175) | answered |
| TCP queries to Cloudflare name servers | reused connections run into timeouts | own connection, reuse is detected |
| Local root zone (RFC 8806) | only as a secondary zone you create yourself | built in, root and arpa zone from IANA with ZONEMD and signature verification, NXDOMAIN for nonexistent TLDs without the root servers |
| Root trust anchors | bundled file only | daily from IANA, only with a valid ICANN signature, or a custom version |
| Do53 | always active | enabled, DDR only (drop or REFUSED) or off |
| Apps | English, configuration as a JSON text field | names, descriptions and error messages in German or English, form with translated labels, JSON for experts |
| Dashboard | from 1 hour | from 1 minute, live graphs of internal processes |
| Automatic intervention on disk space, memory or service problems | not available | watchdog |
| EDNS padding (RFC 7830, RFC 8467) | not available | responses over DoT, DoH and DoQ padded to multiples of 468 bytes, queries to encrypted forwarders to 128 bytes |
| Logging of client addresses | always | can be turned off |
| Prefetch | at most within the last 9 seconds of the TTL | from an adjustable share of the remaining TTL, 10 % by default |
| Check of the system time | not available | self-test against the Date header of IANA and the NTP status of the kernel |
| Prometheus metrics, API tokens | available | removed |

## Measurements

Measured on the same machine (20 cores) with `dnsperf` against an authoritative server and a caching resolver with 2,000 names. Values for authoritative answers / answers from the cache. The values for authoritative answers come from a build before the authoritative zones were removed and show the effect of the optimizations on the shared query path.

| Measurement | Technitium 15.5 | ZenitiumDNS 15.5 | Change |
| ----------- | --------------- | ---------------- | ------ |
| CPU time per query at fixed load (100,000 queries/s) | 85.8 / 99.8 µs | 23.6 / 29.5 µs | −73 % / −70 % |
| Mean latency at fixed load | 85 / 71 µs | 19 / 19 µs | −78 % / −73 % |
| Peak throughput | 686,000 / 628,000 queries/s | 721,000 / 703,000 queries/s | +5 % / +12 % |
| Memory allocation per query from the cache | about 2.9 KB | about 1.0 KB | −65 % |
| Garbage collection pause time under full load | 22 % | 7 % | −68 % |
| Gen0 garbage collections per second under full load | 134 | 55 | −59 % |
| Lock contentions per second under full load | 1,798 | 41 | −98 % |

Functional tests in an isolated network namespace with a simulated DNS hierarchy:

| Test | Technitium 15.5 | ZenitiumDNS 15.5 |
| ---- | --------------- | ---------------- |
| CNAME chain across 12 zones | 9 of 12 records, then aborted | all 12 records |
| Upstream queries caused by prefetch with a short TTL (24 client queries) | 24 | 2 |
| 10 queries, "Prefer IPv6", IPv6 name servers unreachable | 10 × error after 2 s | 2 × error, then 8 × answer in 22–42 ms |
| TLS certificate in `…/cfgcert/` next to the configuration folder `…/cfg/` | saved as `cert/test.pfx`, no longer loadable after a restart | absolute path is kept |

## All changes in detail

### Focus on public resolvers
- **Removed:**
  - authoritative zones of type primary, secondary, stub, secondary forwarder and catalog, including DNSSEC signing and SOA editing,
  - zone transfers (AXFR, IXFR, XFR-over-TLS/QUIC), DNS NOTIFY, dynamic updates and TSIG,
  - DHCP server and clustering,
  - importing DNS client responses into a local zone,
  - 16 apps for LAN and hosting scenarios (Auto PTR, Block Page, Default Records, DNS Block List, Failover, Filter AAAA, Geo Continent, Geo Country, Geo Distance, No Data, NX Domain Override, Split Horizon, Weighted Round Robin, What Is My DNS, Wild IP, Zone Alias),
  - Windows service, system tray, Windows firewall library and Windows installer.
- **Kept:** conditional forwarder zones with local records and access restriction, block lists, allowed and blocked domains, the resolver apps (Advanced Blocking, Advanced Forwarding, DNS64, DNS Rebinding Protection, Drop Requests, Log Exporter, NX Domain, Query Logs for SQLite, MySQL, PostgreSQL and SQL Server).
- **Protocol behavior:** AXFR/IXFR are answered with `REFUSED` and the EDE "Not Supported", NOTIFY and UPDATE with `NOTIMP`, TSIG-signed queries with `BADKEY`.

### Request filter
- Rules modeled after dnsdist, active by default: unreadable or under 12 bytes, over 1232 bytes, opcode other than QUERY, class other than IN, ANY, AXFR/IXFR, without RD flag, EDNS version greater than 0.
- UDP matches are dropped; over TCP, DoT, DoH and DoQ the answer is `REFUSED` with the EDE "Prohibited". Loopback is exempt.
- Match counters per rule in the settings, the JSON metrics and Prometheus (`request_filter_matches_total`).

### DNSSEC
- Validation of ML-DSA-44 (algorithm 18) and protection against downgrades to classic algorithms when the DS record set announces a post-quantum algorithm.
- The DNS client explains why the DNSSEC check against this server fails when its validation is turned off.

### Apps
- Bundled apps are installed disabled on the first start and updated on package updates. Uninstalled apps stay removed.
- Enabling and disabling in the web interface and via `api/apps/enable` and `api/apps/disable`.

### Protection, blocking and protocols
- Rate limiting in queries per second (GCRA token bucket per subnet, adjustable burst), migration of existing QPM values.
- Client block lists with automatic updates, dropping before parsing, closing of stream connections.
- Custom blocking text with placeholders, custom TTL for negative caching; the SOA MINIMUM survives a restart.
- Block list quick selection only with HaGeZi lists from the build mirror, half the memory for block lists, allocation-free lookups.
- PEM certificates with a separate key, built-in DDR, self-test.
- Resolver: handling of name servers that only answer one query per TCP connection; QNAME fallback on timeouts; downloads with the effective IPv6 mode.

### Defaults for new installations
- 100,000 cache entries, blocking TTL 300 s, listen backlog 1024, TCP receive timeout 5 s, IPv6 enabled for outgoing queries, statistics and logs 30 days.

### Statistics and monitoring
- Response time measurement for all transport protocols with average, median, 95th/99th percentile, maximum and separate values for the cache and recursive resolution.
- New dashboard with key figures, status chips, response time history, share tables and switchable history views.
- Additional fields in `api/dashboard/stats/get` and in the JSON and Prometheus metrics, new call `api/dashboard/ipv6/probe`.
- Fix: The first truncated entry was missing from the "Others" total of truncated top lists.

### Web interface and settings
- New design with sidebar, page titles and a petrol color system, locally embedded Red Hat fonts, consistent forms, tables and dialogs in Light, Dark and Amber.
- Readout band on the dashboard with a history per key figure and a status in words. Chart colors are checked for color vision deficiencies.
- Usable on mobile: toolbar instead of sidebar, tables scroll sideways, no fixed minimum width anymore.
- Reorganized navigation (Dashboard, Resolver, Filter, Apps, DNS client, Logs, Settings, Administration, About) and settings in ten topic sections with explanatory texts.
- New settings: automatic IPv6 fallback, UDP receive threads per socket, limit for concurrent queries per TCP/TLS connection.
- Removed settings: SOA defaults, zone transfer and NOTIFY networks, TSIG keys.

### Resolver
- **CNAME chains and name servers without glue:** The limits per client query were raised to 400 outgoing queries and 128 hash operations. Domains such as `www.bbc.com` or `x.com` failed in the original with "No valid response from name servers" (upstream issue #2175).
- **QNAME minimization:** The original sent a superfluous query of type `A` for the last label, even after NXDOMAIN.
- **Root priming:** If the priming query fails or returns no addresses, recursive resolution failed completely in the original. ZenitiumDNS then uses the root hints. The priming query is sent without the RD flag.
- **Duplicate name servers:** Duplicate entries in the name server list are removed.
- **DNS 0x20:** A response with a different letter case of the name is now treated as a spoofing attempt and immediately leads to a retry over TCP.
- **Name server selection:**
  - Response time and error rate are kept separately per address family (IPv4/IPv6).
  - The answer rate is counted as a moving average instead of over the entire uptime.
  - Failed addresses are sorted behind working ones, also in "Prefer IPv6" mode.
  - The order results from a single combined sort instead of several unstable sorts.
- **Cache view:** The name server statistics additionally show the current answer rate and the IPv6 values.

### Cache
- **Root servers blocked after DNSSEC errors:** "Clear cache" and toggling DNSSEC validation reset the error mark of the root hints. In the original, resolution stayed disrupted for up to five minutes afterwards.
- **Failure cache and serve stale:** Expired failure entries were served as stale answers in the original and prolonged outages.
- **Prefetch:** With a short TTL, the original triggered a prefetch on almost every query. It now only kicks in within the last tenth of the TTL.
- **Garbage collection:** The original ran a blocking full garbage collection in the cache maintenance every minute (upstream issue #2174). ZenitiumDNS uses a background garbage collection there and when reloading statistics, block lists and the Advanced Forwarding app.
- **Race condition:** When empty cache zones were removed, entries added at the same time could get lost and the entry counter could count up incorrectly.
- **LRU eviction:** For A/AAAA records with several addresses, the last-used time was never updated. Popular entries were therefore evicted first when the cache was full.

### Performance
- Dedicated UDP receive threads (automatically at most 8 per socket, adjustable up to 64) answer cache hits without switching threads.
- UDP responses are sent synchronously.
- The internal processing chain uses `ValueTask`, and name compression works without copies.
- The check for special zones no longer creates temporary strings.
- Enumerators are no longer boxed in the hot paths.
- Last-used timestamps are written at most once per second.
- Statistics data runs through a lock-free queue with its own thread, and unique clients are counted with HyperLogLog.
- UDP receive threads only wake further threads on a sustained backlog, and send buffers are reused.
- Server GC with concurrent garbage collection.

### Encrypted protocols
- **DNS-over-TCP and DNS-over-TLS:** At most 100 running queries per connection by default, adjustable. The original allowed any number.
- **DNS-over-HTTPS:** The stored server address no longer contains the complete query (`?dns=…`).

### Security
- API tokens from `DNS_SERVER_AUTH_STATIC_SESSIONS` now also work on the very first start without `auth.config`.
- SQL injection via the server filter in the query log apps for MySQL, PostgreSQL and SQL Server fixed.
- XSS via app names in the web interface fixed.
- Users without admin rights can no longer delete other users' sessions.
- Restoring a backup no longer writes files outside the target folder.
- TLS certificate paths next to the configuration folder are saved correctly (upstream issue #2162).
- DNS-over-HTTPS via POST: requests over 65,535 bytes are rejected with 413 and read with a limit.
- DNS messages with implausible record counts are dropped before parsing.
- Values in inline handlers of the web interface are escaped for JavaScript.

### Web API and web interface
- The record APIs honor `zone=.` for the root zone.
- The page size of the log query is limited, and the size limit for downloading logs no longer overflows.
- Pending changes are written before backups and on shutdown.
- Web interface and documentation are translated into German.

### Apps and stability
- Log Exporter app: syslog messages are no longer formatted twice according to RFC 5424 (upstream issue #2173).
- The timer of the load balancing proxy no longer fires after disposal.
- An error while loading a zone file no longer leads to a `LockRecursionException`.

### Installation and operation
- Debian 13 package (`setup/debian/build-deb.sh`) for amd64 and arm64:
  - hardened systemd service,
  - random admin password,
  - automatic adjustment of systemd-resolved,
  - bundled DNS apps.
- Docker image, compose file and the environment variables for initial configuration were removed.
- Update check and app store are disabled by default: `DNS_SERVER_UPDATE_CHECK_URL`, `DNS_SERVER_APP_STORE_URL`.

## Compatibility

- **Configuration:** Settings, users, conditional forwarder zones, block lists, allowed and blocked domains, statistics and backups of Technitium DNS Server 15.5 can be taken over. ZenitiumDNS saves the DNS settings in format version 10, the web interface settings in format version 5 and zone files with zone information version 15. The original can no longer read these files.
- **Removed zone types:** Zone files of primary, secondary, stub, secondary forwarder and catalog zones stay in the `zones` folder but are skipped and logged at startup. They can be used further with the original if needed.
- **DHCP and cluster:** DHCP scope files and the cluster configuration are ignored. Permissions for the DHCP section are discarded on load. An existing "DHCP Administrators" group remains as an ordinary group without special rights and can be deleted.
- **HTTP API:** The API only serves the web interface. The calls for DNSSEC, catalog zones, zone conversion, resync, TSIG, DHCP and clustering, the app store, installing and uninstalling apps, API tokens and the Prometheus metrics as well as the `node` parameter are gone. `api/zones/create` only accepts the type `Forwarder`.
- **Cache file:** ZenitiumDNS saves the name server statistics in `cache.bin` in an extended format (version 2). If such a cache file is loaded by the original, the original discards the cache. The configuration is not affected.
- **DNS apps:** The namespaces were renamed (`ZenitiumDns.*`, `ZenitiumLibrary.*`). Apps compiled for Technitium must be recompiled against `ZenitiumDns.ApplicationCommon`. All bundled apps are already adapted.
- **Syslog export:** Because the double formatting was fixed, the format of the syslog messages of the Log Exporter app changes. The metadata is now contained in the message as real structured data according to RFC 5424.
- **Statistics:** Statistics files are saved in format version 11 (counters) and 2 (hourly files), which the original cannot read. Files of the original are read.
- **Pipelining:** Clients that keep more than 100 queries open at the same time over a single TCP or TLS connection are slowed down until responses have been sent.

## Sync with Technitium DNS Server 15.5.1

Technitium DNS Server 15.5.1 was released on 26 September 2026. All of its fixes are included in ZenitiumDNS 15.5.1 where they concern parts that still exist (DHCP fixes do not apply). ZenitiumDNS already had some of them before:

| Fix in 15.5.1 | In ZenitiumDNS |
| ------------- | -------------- |
| XSS via app names in the web interface | already fixed in 15.5 |
| Deleting other users' sessions by users without admin rights | already fixed in 15.5, length check of the partial token adopted in addition |
| Blocking garbage collection in the cache maintenance (upstream issue #2174) | already fixed in 15.5 by a background GC, GC only after large cleanups adopted in addition |
| Resolver limits with long CNAME chains (upstream issue #2175) | already fixed in 15.5 by higher limits, now without a hash limit and with the EDE "ResolverLimitReached" |
| XSS in the list of log files, RA flag in blocking responses, local block lists, RRSIG validity period, path comparisons, `install.sh` | newly adopted |
