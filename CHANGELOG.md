# ZenitiumDNS changelog

[Deutsche Version](CHANGELOG.de.md)

## ZenitiumDNS 15.5.1 (package 15.5.1-13)
Released: 1 October 2026

### New
- DHCPv6 and router advertisements, details in [docs/DHCP.md](docs/DHCP.md#ipv6):
  - simple settings under DHCP > Settings > **IPv6**: SLAAC (recommended), SLAAC plus DHCPv6 addresses or DHCPv6 addresses only, the DHCPv6 range as host part (`::1000` to `::1fff`), and whether the server announces itself as default router (automatic: only if it forwards IPv6). The prefixes are taken from the global and ULA addresses of the interface and follow provider changes; prefixes that disappear are announced as invalid for two hours,
  - DHCPv6 server according to RFC 8415 (SOLICIT/ADVERTISE, REQUEST, RENEW, REBIND, CONFIRM, RELEASE, DECLINE, INFORMATION-REQUEST, rapid commit, relays), one address per device from every prefix of the interface, reservations by DUID, by the MAC address in the DUID or from the relay (RFC 6939), client FQDN (RFC 4704), DNS, domain, NTP and SNTP options,
  - router advertisements according to RFC 4861 with RDNSS and DNSSL (RFC 8106); the announced DNS server is the address of this server on the link, preferring a ULA and fixed addresses,
  - expert configuration in dnsmasq syntax: IPv6 `dhcp-range` with `constructor:`, `ra-only`, `ra-stateless`, `slaac`, `off-link`, plus `enable-ra`, `ra-param`, `dhcp-option=option6:…` and `dhcp-host=…,[::20]`,
  - reservations in the simple settings have an IPv6 column; "Reserve" also works for DHCPv6 leases,
  - device names are answered with AAAA and `ip6.arpa` PTR records as well,
  - while the DHCP server is on, it observes the router advertisements of other routers; the status, the self-test and the metrics show routers that announce other DNS servers over IPv6 (devices may then bypass ZenitiumDNS and its filters), routers with the M flag and other DHCPv6 servers,
  - DHCPv6 leases (`dhcp6-leases.json`) are part of the backup; new metrics `zenitiumdns_dhcp6_*` and `zenitiumdns_ra_*`.
- Devices are recognized across DHCP, DHCPv6 and the client profiles:
  - client profiles accept MAC addresses as identifiers. A MAC address covers a device in the same network over IPv4 and IPv6, also with changing IPv6 addresses; the server finds it through its DHCP leases and the neighbor table of the system (ARP/NDP), so it also works when the router hands out the addresses. Order: ClientID, MAC address, IP address, network,
  - DHCPv6 leases get the MAC address of the device from the DUID, the relay, the IPv4 lease with the same DUID (client identifier according to RFC 4361), an EUI-64 link-local address or the neighbor table, so reservations, names and profiles by MAC address also apply to DHCPv6,
  - reservations can name a device by MAC address or by `id:` with client identifier or DUID and have a profile column; the lease list shows the client identifier or DUID and has a profile selection per lease,
  - the query log shows the names of known devices under their address, and the client profile dialog offers the known devices (new API `api/dhcp/devices`, `api/settings/clients/assign`).
- DHCP expert configuration with selection instead of text only: the **Expert** tab shows the lines as a list of readable entries with edit, move and remove; **New entry** opens forms for ranges (IPv4 and IPv6), reservations, DHCP and DHCPv6 options (picked from a list with descriptions, value fields matching the option type), device groups, rules, network boot, domains, router advertisement parameters and general switches. The text view remains; both show the same configuration. Faulty lines are marked in the list while editing.

### Web interface
- Block lists and the blocking behavior moved from the settings to the **Filter** tab ("Block lists" and "Blocking behavior"), next to blocked and allowed domains and the client profiles. Both tabs load the current settings when opened and have their own save button; write protection applies there as well.
- Backups have their own section under Settings > **Backup**. The "Clear cache" button left the bar of every settings page; the cache is cleared under Resolver > Cache.
- Settings: the watchdog has its own section under Server; the client timeout and the limit of concurrent resolutions moved from Network to Resolver, the QUIC limits to the DNS-over-QUIC settings; "Encrypted protocols" is called **Services** because it also covers unencrypted DNS (Do53); the two sections "Behind a reverse proxy" are named after what they apply to (DNS or web interface).
- The cache and the lists of blocked and allowed domains show their records as a table (name, type, TTL, readable data, DNSSEC state); a click on a row shows all details, as before as JSON.
- Color schemes: eight new presets (Ocean, Lavender, Sun, Slate, Forest, Nord, Berry, High contrast). Own color schemes are now created from a base (light or dark), an accent color, a background tint and the style of the sidebar; all other colors are derived from these, text on the accent automatically becomes black or white, and a readability check shows the contrast of text, links and sidebar. Single colors can still be fine-tuned. Every preset can be used as a starting point ("Customize"). Color schemes created with earlier versions keep looking the same until they are edited.
- Query log: the frequent filters (domain, client, type, period) come first, the others under "More filters"; the selection of app and class path only appears when several query log sources are active, and without one there is a note with a link to the apps.

### Fixed
- DHCP: messages such as "the range overlaps the range in line 5" counted the lines of the simple settings and the expert configuration together; they now name the line of the own configuration or "the simple settings".
- DHCP: an unexpected error while reading a single configuration line no longer stops the whole DHCP server from starting; the line is reported as an error instead.
- DHCP settings: the help text of the interface still mentioned the removed cluster.

## ZenitiumDNS 15.5.1 (package 15.5.1-12)
Released: 1 October 2026

### New
- DHCP server (DHCPv4) under the new **DHCP** tab, details in [docs/DHCP.md](docs/DHCP.md):
  - simple settings (interface, range, gateway, DNS servers, domain, lease time, reservations) and an expert configuration in the syntax of dnsmasq (`dhcp-range`, `dhcp-host`, `dhcp-option`, tags, `dhcp-match`, `dhcp-boot`, relay support and more), checked line by line before saving,
  - detection of other DHCP servers in the network (own DHCPDISCOVER on a schedule and offers seen from devices) and a priority: "Primary" answers immediately, "Secondary" answers after a delay so that an existing server keeps working, "Standby" only serves while no other server is seen,
  - ping check before an address is offered, DHCPDECLINE handling, rapid commit (RFC 4039), client FQDN (RFC 4702), classless static routes (RFC 3442), long options (RFC 3396), relay agent information (RFC 3046), subnet and link selection (RFC 3011, RFC 3527),
  - host names of the devices are answered in DNS (A and PTR) under the configured domain,
  - permission section **DHCP** (Administrators full, DNS Administrators view), self-test checks and Prometheus metrics `zenitiumdns_dhcp_*`,
  - settings and leases are part of the backup together with the DNS settings.
- Memory protection for the cache: when the used memory reaches 85 % of the system memory, of the service or container limit or of the .NET heap limit, the cache stops growing; from 90 % a quarter and from 95 % half of the entries are removed after a compacting garbage collection has confirmed the pressure. The cap is lifted after five minutes below 75 %. The check runs every 2 seconds, replaces the earlier watchdog memory check and is shown in the self-test and as metrics (`zenitiumdns_memory_pressure_ratio`, `zenitiumdns_cache_pressure_*`).
- [docs/Performance.md](docs/Performance.md): measured comparison with Technitium DNS Server 15.5.1 including the raw data, and a benchmark kit in `tools/benchmark` (UDP load generator, DNS-over-TLS load generator, simulated root and TLD servers, script and summary) so that the numbers can be repeated.
- ClientID over DNS-over-TLS and DNS-over-QUIC: the server reads the wildcard names of the certificate; the client profiles show the actual addresses to use and warn when the certificate has no wildcard entry, so the ClientID only works over DNS-over-HTTPS. The self-test checks the same.
- The web interface reconnects by itself when the server is briefly unreachable, for example during a restart or an update: instead of an error message a notice shows the next attempt, the current view is refreshed afterwards, and after an update to a new version the page reloads itself.
- Self-test reworked: headline with the number of errors and warnings, filter "Needs action", "Open" jumps to the matching setting, duration and number of checks; new checks for the admin password and its file, request filter, rate limiting, client block lists, client profiles, UDP buffers, truncated answers, web interface, memory protection, QNAME minimization, cookies and 0x20, EDNS padding and DHCP.

### Performance
- Recursive resolutions no longer go through a pool of hundreds of waiting loops that were all woken for every new resolution (thundering herd in the inherited `TaskPool`). Lock contention at 700 resolutions per second dropped from about 290 to 0 per second, at 5,000 per second from about 2,500 to under 1; the CPU time per recursive resolution dropped by about 40 %. On a server with 8 CPUs (800 waiting loops), 700 queries per second needed 2.42 ms of CPU time per query before and 0.46 ms now, with about 2,000 instead of 0 lock contentions per second.
- DNS-over-TCP, DNS-over-TLS and DNS-over-QUIC run on the .NET thread pool instead of an own scheduler that handed every completed read over to another thread under a lock. At 8,000 DoT queries per second, lock contention dropped from about 1,500 to under 1 per second and the CPU time per query from about 105 to 60 µs.
- With far less garbage, the runtime collected only every two seconds, but for 15 to 35 ms at once. A short gen0 collection now runs as soon as 150 new cache entries were created since the last one; at 2,000 new names per second the 99.9th percentile is 4 to 6 ms instead of 5 to 11 ms before and 30 to 40 ms without pacing (metric `zenitiumdns_gc_paced_collections_total`).
- Web assets are minified when building the package and the image (`tools/WebMinifier`): 29 files, 1.4 instead of 2.4 MB.

### Security
- The file `/etc/zenitiumdns/admin.password` is also deleted when the user `admin` is deleted, renamed or replaced by a non-local user.
- Imported interface languages cannot break out of HTML attributes or scripts anymore: straight quotes and backticks in translations are replaced with typographic ones.
- IP addresses in client profiles and block lists are parsed strictly. Short forms such as `1.2.3`, `10` or `010.1.1.1`, which .NET accepts as IPv4 addresses, are no longer taken as addresses; a numeric ClientID such as `123` now works.
- systemd service: `CAP_NET_RAW` and the address family `AF_PACKET` for DHCP replies to devices without an address.

### Fixed
- One invalid client profile no longer discards all profiles at start: invalid entries and profiles with a name already used are skipped and logged, an identifier already used by another profile is ignored, and a copy of the file is kept as `clients.json.invalid`.
- Block lists: every line starting with `[` was silently ignored; now only header lines such as `[Adblock Plus 2.0]` are, and other lines show up in the counts of skipped or invalid lines.
- Advanced Forwarding app: queries from clients that may not use recursion are no longer forwarded, so the app cannot turn the server into an open resolver; domain rules are compared case-insensitively and without a trailing dot.
- DNS64 app: answers with `REFUSED` and blocked or dropped answers are no longer synthesized into AAAA records.
- Drop Requests app: queries to an allowed local endpoint skipped the rules for blocked questions.
- Log Exporter app: missing paths, endpoints or addresses give a clear error instead of a `NullReferenceException`, relative file paths are resolved against the app folder, a queue size of 0 means the default of 1,000,000, Extended DNS Errors are taken from the parsed option instead of splitting text (messages with `:` were cut), and exports no longer run on the scheduler of the calling thread.
- The live graphs on the dashboard stopped after a restart of the server until the page was reloaded.
- DNS-over-HTTPS landing page: a short page about the service and its address instead of a client tutorial, without Bootstrap and jQuery.

### Tests
- In the isolated test network: general regression tests 88 of 88, list syntax 44 of 44, client profiles 57 of 57, without cache 23 of 23, admin password file 10 of 10, DoH landing page 11 of 11, DNSSEC and aggressive NSEC with signed Knot zones 35 of 35, web interface in German and English 48 and 49 checks including the DHCP pages.
- DHCP: protocol, options, relays and DNS names 66 checks; detection of other DHCP servers against dnsmasq with all three priorities 8 checks; self-test and metrics with and without another DHCP server; backup and restore of settings and leases.
- Comparison with Technitium DNS Server 15.5.1 on the same machine, three alternating runs each, in [docs/Performance.md](docs/Performance.md). On the test server with 8 CPUs, 700 queries per second for nonexistent top-level domains caused 1,700 to 2,170 contended locks per second with 15.5.1-11 and none with 15.5.1-12.

### Other changes
- New files in the configuration folder: `dhcp.json`, `dhcp-leases.json` and `dhcp-node.id`. The formats of the existing files are unchanged; `auth.config` gets the permission section DHCP when it is saved.
- The dashboard graph of the queues shows the .NET thread pool instead of the removed query scheduler.
- New Prometheus metrics for memory protection, GC pacing and DHCP, see [docs/Metrics.md](docs/Metrics.md).
- Supported RFCs: the DHCP RFCs 951, 2131, 2132, 3011, 3046, 3396, 3397, 3442, 3527, 4039, 4702 and 6842 added.
- All Markdown files were checked against the code and corrected; new are [docs/DHCP.md](docs/DHCP.md) and [docs/Performance.md](docs/Performance.md).

## ZenitiumDNS 15.5.1 (package 15.5.1-11)
Released: 30 September 2026

### New
- Block lists understand the rule syntax of AdGuard Home and Adblock next to hosts files, plain domain lists and wildcard lists: `||domain^`, exceptions with `@@`, `|domain^` for exactly this name, `||*.domain^` for subdomains only, `*` wildcards, regular expressions `/…/` and the modifiers `$important`, `$badfilter`, `$dnstype`, `$denyallow` and `$client`. Lists in the format of Pi-hole's regex filters (with `;querytype=`) work as well; POSIX character classes are translated. Regular expressions run without backtracking and with a time limit, so a list cannot slow down the server. Rules for web page elements and modifiers without meaning for DNS are skipped and counted. Details in [docs/BlockLists.md](docs/BlockLists.md).
- IP addresses and networks in a block list block answers whose A or AAAA records point to them, also from the cache; allow lists exempt addresses again.
- The quick selection of HaGeZi's lists now uses the Adblock format from `hagezi-mirror.dnsbunker.org`.
- Client profiles (Filter > Clients) in the style of AdGuard Home: devices are recognized by IP address, network or ClientID and get additional block or allow lists, use only their own lists or are not filtered at all. The ClientID comes from the DoH path (`/dns-query/<id>`) or the server name of DoT and DoQ (`<id>.<server name>`). All profiles share one loaded rule set that is filtered per query, so a list used by several profiles is loaded only once.
- DNS cookies (RFC 7873, RFC 9018), switched on by default: the server answers client cookies with interoperable server cookies (SipHash-2-4, valid for one hour) and sends its own cookies to name servers and forwarders; answers with a wrong or missing cookie from a server that used cookies before are discarded. Clients over the UDP rate limit that present a valid cookie are still answered as long as they stay within the TCP limit; others get a truncated response or `BADCOOKIE`. Malformed cookies are answered with `FORMERR`. The secret is random at every start or can be set (32 hexadecimal characters) so that several servers behind one address accept each other's cookies.
- Automatic fallback for QNAME minimization: if a name server answers a minimized query incorrectly or not at all, the resolver repeats it with the longer or full name and remembers the zone for one hour (at most 10,000 zones). The option is under Settings > Resolver and switched on by default.
- The cache can be switched off completely (Settings > Cache > Use cache), for running ZenitiumDNS as a filtering front end with DoH, DoT and DoQ in front of a resolver with its own cache such as Unbound, without caching twice. Switched off, no answers are stored and there is no prefetch, no serve stale, no aggressive use of NSEC and no local root and arpa zone; the existing cache is flushed and `cache.bin` deleted. TTLs are passed through unchanged, identical concurrent queries are still merged, and each resolution only keeps what it learns on the way in a short-lived buffer. Without forwarders every query is resolved starting at the root servers; the self-test points this out.
- Memory limit for the cache (Settings > Cache, off by default): when the used memory of the server exceeds the limit, the cache maintenance that runs every minute removes the least recently used entries until usage is back at about 90 % of the limit, keeping at least 10,000 entries. After a large cut the memory is compacted at most every 15 minutes, so the process also returns memory to the system.
- Status of every block list (upstream issue #2198): when it was last checked and changed, the result, errors, the number of domains, exceptions, patterns and IP entries and skipped lines. Lists can be switched on and off, named, updated one by one and removed in the table.
- Color schemes of your own: every user can create, change and apply schemes in the theme menu; they are stored on the server per user.
- Write protection for the settings: a lock per user prevents accidental changes; it can be lifted temporarily and locks again when the settings are left.
- Further interface languages can be imported as JSON dictionaries (German text to translation, up to 4 MB) under Settings > Server > Language; missing texts fall back to English.
- The HTTP user agent for block list downloads and other outgoing HTTP requests can be set (default `ZenitiumDNS/<version>`).
- The console shows the version and the start time when the server has started (upstream issue #2195).
- If `admin` is the only user, the sign-in form fills in the user name.

### Memory
- A cache entry needs about half the memory. With 1.2 million cached names the managed heap shrank from 1,506 to 789 MB and the resident memory from 1.94 to 1.26 GB:
  - the records of a name are kept in a small array instead of a concurrent dictionary per name (about 240 bytes less per name),
  - the name server of the response is shared between entries instead of being copied for every answer (about 210 bytes less),
  - the domain tree uses exactly sized child arrays for nodes with up to 8 children instead of 41 slots (39 instead of 157 MB for the tree arrays),
  - A and AAAA records and signatures (RRSIG) no longer keep a second raw copy of their data, and rarely used fields of cache records are only allocated when needed.
- The CPU time per query is unchanged (20.3 µs at 40,000 queries/s on 4 cores); 400,000 queries/s of cache hits and blocked names did not saturate the server.

### Security
- systemd service: system call filter (`@system-service` without `@privileged`), allowed address families limited to Unix, IPv4, IPv6 and netlink, `ProtectProc=invisible`. `ProtectClock` was removed because it also blocked reading the NTP state for the self-test; the service still cannot set the clock. `systemd-analyze security` rates the unit 1.9 instead of 3.6.
- The file `/etc/zenitiumdns/admin.password` with the initial password is deleted as soon as the password of `admin` differs from it, right after the change or at the next start.
- Web interface: the content security policy no longer allows `unsafe-eval`, requests without a valid session may carry at most 1 MB, `Strict-Transport-Security` is sent when HTTPS with redirection is active, `X-Content-Type-Options: nosniff` and `Referrer-Policy: same-origin` on every response, and the short-lived token cookie of single sign-on is `SameSite=Strict` and `Secure` over HTTPS.
- Random letter case of the QNAME (0x20) is switched on by default; installations updated from older versions switch it on once.
- Container image: GitHub Actions and base images are pinned by commit hash and digest, the image gets an SBOM and build provenance and is signed with cosign (keyless).

### Fixed
- Aggressive use of NSEC: names with characters that are not allowed in host names, such as `securel~.ikea.com`, raised an exception while building synthesized answers.
- Restoring a backup with log files could fail with "ZipArchiveEntry does not support reading", because the log files were extracted in the background while the archive was already closed.
- Updates of block lists could run at the same time (for example after quick changes of the settings) and collide on the temporary download file; they now run one after another.
- The installer of the Debian package prints its messages in English only.

### Tests
- Rule parser: 106 checks including Pi-hole lists, `$client`, filters per profile and IP rules; HaGeZi Pro and TIF in Adblock format (2.6 million domains) load in 1.4 s into about 107 MB.
- In the isolated test network: list syntax 44 of 44, client profiles including DoH ClientID, DoT server name and restart 52 of 52, general regression tests 88 of 88, web interface in German and English 27 and 28 checks, DNSSEC and aggressive NSEC with signed Knot zones 35 of 35.
- Domain tree: 600,096 checks against a reference, including order of enumeration and parallel changes, with identical results for the old and the new implementation.
- Without cache in front of Unbound: 23 of 23 checks (every repeated query reaches Unbound, TTLs unchanged, blocking and profiles work, the setting survives a restart, no `cache.bin`); with signed Knot zones, answers without cache are still validated (AD) and denials of existence are proved.
- Memory limit: at 400 MB and 12,000 new names per second the cache was trimmed from 1.2 million to 577,000 entries in one step, and the resident memory dropped from 1.25 GB to 574 MB after a compaction of 312 ms.

### Other changes
- DNS settings file format version 17. Older versions of ZenitiumDNS cannot read it. Existing settings are taken over with DNS cookies, 0x20 and the QNAME minimization fallback switched on, the cache on and without a memory limit.
- Client profiles are stored in `clients.json`, per-user preferences in `userprefs.json` and imported languages in the folder `lang`; all of them are part of the backup.
- New Prometheus metrics for DNS cookies, the QNAME minimization fallback, the cache switch and the memory limit of the cache, see [docs/Metrics.md](docs/Metrics.md).
- Supported RFCs: RFC 7873 and RFC 9018 added.

## ZenitiumDNS 15.5.1 (package 15.5.1-10)
Released: 28 September 2026

### New
- Prometheus metrics: the optional endpoint `/metrics` on the web interface port serves detailed metrics in the Prometheus text format. It is switched on under Settings > Web interface > Prometheus metrics and is off by default. It contains queries per transport protocol and client address family, query type, flag, response code and origin of the answer, Extended DNS Errors (RFC 8914), unanswered queries, histograms of the response time (local, cache, recursive, blocked) and of the query and response sizes per protocol, queries to name servers and forwarders per protocol and address family with response codes, timeouts, network errors, truncated responses and a histogram of the round trip time, the cache, the aggressive NSEC cache, block lists, request filter, client block lists, rate limiting and internal queues, as well as CPU, memory, garbage collection, thread pool and file descriptors of the process. The metrics contain neither client addresses nor domain names; unknown query types and response codes are counted as `other`. All metrics are described in [docs/Metrics.md](docs/Metrics.md).
- Access to `/metrics` is limited by an ACL (by default loopback and private networks) and optionally by a bearer token. Behind a reverse proxy the client address from the client IP header counts. Scrapes that come through a proxy without a usable client IP header are refused unless a token is set. Sessions of the web interface do not grant access. The settings page generates random tokens and shows a ready-made entry for `prometheus.yml`.
- The detailed counters are only collected while the endpoint is switched on: queries on the statistics thread, queries to name servers with atomic counters where they are sent.

### Measurements
Development machine (20 cores), cache hits over UDP at 20,000 queries/s from 50,000 client addresses, after a warm-up three alternating runs of 30 seconds each:
- CPU time per query without the endpoint 22.2 to 26.4 µs, with the endpoint switched on 20.0 to 26.7 µs. The difference lies within the variation between runs; all 600,000 queries of every run were answered, and no statistics update was discarded.
- A scrape takes a few milliseconds and returns about 26 KB (gzip-compressed on request); a format check of the output (one TYPE per family, grouped samples, no duplicate series, cumulative histogram buckets with matching `_count`) passed.

### Other changes
- Web service settings file format version 7. Older versions of ZenitiumDNS cannot read it. Existing settings are taken over, with the metrics endpoint switched off.
- The Prometheus metrics of Technitium (`api/dashboard/metrics/text`, removed in package 15.5.1-3) do not come back; the JSON metrics under `api/dashboard/metrics/json` stay unchanged.

## ZenitiumDNS 15.5.1 (package 15.5.1-9)
Released: 28 September 2026

### New
- Aggressive use of the DNSSEC-validated cache (RFC 8198): the resolver keeps validated NSEC and NSEC3 records of signed zones and answers queries for names and types that do not exist there itself with `NXDOMAIN` or `NODATA`, without asking the authoritative servers again. This speeds up negative answers and takes the load of attacks with random subdomains (random subdomain or water torture attacks) off the resolver and the attacked zone. Synthesized answers carry Extended DNS Error 29 (Synthesized). With the DO bit they contain the SOA, the NSEC or NSEC3 records that prove the answer and their signatures, so validating clients can check them; without the DO bit only the SOA. The option is under Settings > Resolver > DNSSEC, is switched on by default and only works with DNSSEC validation enabled.
- Nothing is synthesized for NSEC3 ranges with opt-out, names covered by a wildcard, names below delegations and DNAME records, names at or below conditional forwarder zones and queries resolved through conditional forwarders (including the Advanced Forwarding app), so split-horizon setups keep working. NSEC3 records with more than 50 iterations are not used. The TTL of a synthesized answer is the lowest of the TTLs of the records used, the SOA minimum and the maximum negative TTL of the cache (RFC 9077). Up to 50,000 NSEC and NSEC3 records are kept, at most 4,096 per zone; they stay in memory only and are not written to `cache.bin`. Flushing the cache or deleting a cache zone also removes them.
- Debian package: `libmsquic` 2.6.1 from Microsoft's Debian 13 repository is included as `/opt/zenitiumdns/libmsquic.so.2`, so DNS-over-QUIC and DNS-over-HTTPS with HTTP/3 work without adding Microsoft's package repository. The server loads this copy before a `libmsquic` installed on the system. The package now depends on `libnuma1`. `build-deb.sh` downloads the library once, checks its SHA-256 checksum and caches it in `~/.cache/zenitiumdns-build`; `--no-msquic` builds a package without it.

### Measurements
Test network with signed zones (Knot DNS as authoritative server for the root, a TLD with NSEC3 opt-out and zones with NSEC and NSEC3, all on one machine), 20,000 random names below a signed zone at 2,000 queries/s:
- Without aggressive use: every name went to the authoritative server (20,000 queries), about 3.5 ms CPU time per query, 99th percentile of the response time 8 to 11 ms.
- With aggressive use and an empty cache: 30 to 48 queries to the authoritative server in total, about 0.1 ms CPU time per query, 99th percentile 0.6 to 0.7 ms.
- 35 functional tests passed: `NXDOMAIN` and `NODATA` from NSEC and NSEC3, empty non-terminals, wildcards, CNAME, DS at signed and unsigned delegations, names in unsigned subzones, NSEC3 opt-out, a conditional forwarder zone for a name that does not exist in the public zone, switching the option off and on, and validation of synthesized answers with `delv`.
- DNS-over-QUIC with the bundled library: `kdig +quic` gets its answer over QUICv1 with TLS 1.3; without the library DoQ cannot be switched on.

### Other changes
- DNS settings file format version 14. Older versions of ZenitiumDNS cannot read it. Existing settings are taken over, with the new option switched on.
- Supported RFCs: RFC 8198 and RFC 9077 added.

## ZenitiumDNS 15.5.1 (package 15.5.1-8)
Released: 28 September 2026

### Fixed
- Container image: with directories mounted from the host, the container did not start and restarted over and over with `can't create /etc/zenitiumdns/admin.password: Permission denied`. It ran as uid 1053 from the start and could not write to a directory owned by root. The container now starts as root, hands the configuration and log directories to uid 1053 and then starts the server as that user with `su-exec`. If the container runs with a fixed user (`--user` or `user:` in Compose) and a directory is not writable, it stops with a message that names the directory and the `chown` command.
- Watchdog: when today's log file reached 512 MB, all file logging was paused until midnight, including errors, watchdog events and actions of administrators. Now only the logging of queries is paused, and everything else is still logged. Only if the file still grows to 1 GB is file logging paused completely. The rule for low disk space is unchanged.
- Deleting the current log file in the web interface did not resume logging that the watchdog had paused. Logging now resumes immediately.
- Under Settings > Network > Connections & timeouts the listen backlog showed 100 as its default, but new installations have used 1024 since package 15.5.1-3. Installations from before that keep 100; in the stress test below, a backlog of 100 dropped 905 connection attempts with 5,000 simultaneous TCP connections. Raise the value there if it is still 100.

### Stress test
Measured on the test server (Intel Core i7-4790S, 4 cores / 8 threads, LXC container that shares the CPU with other services, 6 GB RAM, logging of all queries switched on):
- Cache hits over UDP: about 93,000 answered queries/s at 5.2 CPU cores; above that the kernel drops packets and a probe query on the server itself still gets its answer within 0 to 9 ms. 40,000 queries/s need 2.7 cores.
- Cache hits over TCP: 142,000 queries/s with 200 connections, 45,000 queries/s with 2,000 connections.
- Nonexistent top-level domains, answered from the local root zone: 36,000 queries/s with 1.1 million unique names, memory stayed at 260 to 320 MB.
- 10 minutes at 15,000 queries/s (70 % cache hits, 30 % nonexistent names): 8.4 million queries, 15 without an answer, memory 260 to 370 MB without growth.
- 600,000 malformed UDP packets and 1,264 TCP connections with malformed messages at the same time as normal traffic: no exception, and normal queries were answered as without them.
- 5,000 TCP connections held open: idle connections are closed after 10 s at the latest, and TCP and UDP queries were still answered.
- Recursive resolution behind NAT: at 500 new names per second the whole test network lost internet access for about eight minutes, most likely because the router or the provider's carrier-grade NAT ran out of connection state (every upstream query uses its own source port). ZenitiumDNS recovered on its own afterwards. A resolver behind a home router or carrier-grade NAT should not be flooded with cache misses; test with names that are answered locally.

## ZenitiumDNS 15.5.1 (package 15.5.1-7)
Released: 28 September 2026

### Memory
- Statistics: every completed minute is cut down to its top 1,000 domains, blocked domains and clients right away. Previously every minute of the last one to two hours kept all entries, up to 200,000 per list, which is where most of the memory of a busy public resolver went. Unique clients of a cut-down list are counted with a 4 KB HyperLogLog sketch, so client numbers stay accurate to about 2 %. Top lists of the last hour are built from the top 1,000 of every minute; with very evenly spread traffic the counts of lower-ranked entries can come out too low.
- Hourly statistics files store the totals of the hour (top 10,000 per list) and the cut-down minutes: 0.6 to 1.4 MB instead of about 100 MB for a busy hour. The views for a day, week, month, year and custom ranges only read the hour totals, and old files are read minute by minute, so complete minute data no longer ends up in memory. Daily totals are built without keeping 24 complete hours in memory, the cache of daily totals keeps 32 days and the year view keeps monthly totals. A day is only saved once it is complete (with a 10 minute grace period).
- Block lists are stored compactly: all domains as bytes in 1 MB blocks with a hash table instead of one .NET string per domain. HaGeZi TIF and PRO (2.49 million domains) take 78 instead of 215 MB, and full garbage collections no longer have to walk 2.5 million objects. Lists are read line by line while loading instead of first being kept in memory completely.
- The statistics queue holds at most 100,000 entries; further entries are dropped until it has caught up, and the watchdog empties a full queue. Previously it could grow until the watchdog stepped in at 500,000 entries.
- Measured on 2 CPU cores with HaGeZi TIF and PRO and 2,000 queries/s from 50,000 clients (40 % unique names) for 30 minutes: 271 instead of 945 MB of live objects (3.8 instead of 18.2 million), resident memory about 970 MB instead of about 2 GB. The rest is free space inside the heap that the background garbage collection reuses; `DOTNET_GCConserveMemory` reduces it at the cost of pauses of up to half a second (see README.Debian).

### Fixed
- With "Prefer IPv6", resolution failed with SERVFAIL for zones whose name servers have neither glue nor AAAA records (such as `x.com` or `abs.twimg.com`) once IPv6 was confirmed as working. The resolver tried the AAAA lookups of all name servers first, and the A lookups ended up behind the limit of 8 name servers per referral. The A lookup now directly follows the AAAA lookup of the same name server (upstream issue #2175). In a test with 8 such name servers: previously SERVFAIL, now answered.
- DNS64 app: with more than one entry in `excludedIpv6`, AAAA records were kept as soon as they were outside any single range, so the exclusion hardly ever took effect and answers could contain records twice.
- Overlapping runs of the statistics maintenance are skipped.

### Other changes
- Statistics files: format version 11 for counters and version 2 for hourly files. Older versions of ZenitiumDNS cannot read them. Existing files are read and converted when they are saved again.
- The Debian package requires glibc 2.34 or later, which the SQLite library of the query log app needs (upstream issue #2178), and also installs the German README, NOTICE and changelog.
- All documents are available in English and German: English under the usual file name, German as `.de.md`. New are the English CHANGELOG, CHANGELOG-ZenitiumDNS and NOTICE and German versions of all app READMEs. The app READMEs describe installation without the app store, and the PostgreSQL example uses the PostgreSQL port.
- README.Debian explains where local block lists (`file://`) must be stored so that the hardened service can read them, and how memory can be reduced further.
- Container image for amd64 and arm64 (`ghcr.io/dnsbunker/zenitiumdns`): based on Alpine Linux, runs as an unprivileged user and creates a random admin password on the first start. GitHub Actions builds it for every release from the `Containerfile` in the repository. Details in [docs/Container.md](docs/Container.md) (GitHub issue #1).
- The upstream issues of Technitium DNS Server up to 27 September 2026 were reviewed: #2175 is fixed as described, #2162, #2173 and #2174 were already fixed, and #2178 is covered by the package dependency; the remaining reports concern features that ZenitiumDNS does not contain or the reporter's network.

## ZenitiumDNS 15.5.1 (package 15.5.1-6)
Released: 27 September 2026

### New
- Complete English version: the web interface, the self-test, server and watchdog messages, the status of the root zone and trust anchors, app descriptions and error messages, the DNS-over-HTTPS landing page and the installer output are available in German and English.
- The language is chosen in a dialog at the first sign-in after installation and applies to all users of the server. It can be changed at any time under Settings > Server > Language; the page then reloads in the new language. Until a language is chosen, the sign-in page follows the browser language and offers a German/English switch.
- Date and number formats follow the language (English: `2026-09-27 18:08`, `1,234`).
- The English texts of the web interface are in `www/lang/en.json`. `tools/i18n.py` reports missing translations and checks that markup and placeholders match.

### Other changes
- New repository https://github.com/DNSBunker/ZenitiumDNS. The update check queries its releases.
- The README, README.Debian and the documentation in `docs` are available in English and German; the package description is in English.
- Configuration format version 6 for the web interface (language). Older versions of ZenitiumDNS cannot read it. Existing installations are set to German on update and are not asked for the language again.

## ZenitiumDNS 15.5.1 (package 15.5.1-5)
Released: 27 September 2026

### New
- Prefetch by share of the TTL: a record is refreshed as soon as only 10 % of its original TTL is left when it is queried, so with a TTL of one hour within the last 6 minutes instead of only within the last 9 seconds. Frequently queried records therefore no longer expire. Adjustable from 0 to 50 % under Settings > Cache; 0 switches back to the previous trigger in seconds.
- The self-test compares the system time with the Date header of data.iana.org and reports a deviation of 5 seconds or more as a warning and of 60 seconds or more as an error. It also checks whether the kernel synchronizes the clock via NTP.

### Security
- Log injection: control characters from domain names, HTTP headers or error messages could write their own lines into the log. They now appear as `\xNN`, and line breaks in stack traces are indented.
- The statistics limit domains, blocked domains and clients to 200,000 entries each per time slice. Random names or spoofed senders could previously fill the memory without limit.
- The DNS parser rejects empty RDATA for types that require data, and mailbox names with more than one `@`. Such packets caused exceptions during further processing. Found with a fuzzer, followed by 12 million runs without errors.
- Web interface: session data, user type, app classes and APL records are encoded before output.

### Other changes
- Configuration format version 13 for the DNS settings. Older versions of ZenitiumDNS cannot read it.

## ZenitiumDNS 15.5.1 (package 15.5.1-4)
Released: 27 September 2026

### New
- DDR can announce the DoH endpoint of an upstream reverse proxy such as Caddy or nginx when this server itself only offers DNS-over-HTTP without TLS. The public port and HTTP/3 can be set under Settings > Encrypted protocols > Automatic discovery (DDR). The SVCB records for `_dns.resolver.arpa` and `_dns.<server name>` then contain `alpn=h2,h3`, the port and `dohpath=/dns-query{?dns}` in addition to DoT and DoQ.
- The apps are in German: display names such as "Erweiterte Blockierung" (Advanced blocking) or "Anfrageprotokoll (SQLite)" (Query logs (SQLite)), descriptions, handler descriptions and the error messages for invalid configurations. The technical name stays visible next to it as an identifier. On package updates the bundled apps are updated and their configuration is kept.
- The dashboard shows "Recursive with local root zone" while the local root zone is active.

### Fixed
- The "Check now" button for IPv6 always reported "IPv6 unreachable" and showed "IPv6 suspended", even when IPv6 worked, because the interface read the response incorrectly. After a restart everything looked normal again. The button now shows the result of the check of the IPv6 root servers including the error text, and when a name server last answered over IPv6.
- A failed check of the IPv6 root servers no longer suspends IPv6 as long as name servers have answered over IPv6 within the last 30 seconds.
- Clicking "Check now" while a check was running immediately returned the old state. The result of the running check is now awaited.
- With the "Prefer IPv6" setting, the first queries after every restart failed with SERVFAIL on servers without working IPv6, because name servers without glue records were queried over IPv6 first. Until IPv6 is confirmed, the IPv4 address is now resolved first in this mode as well. On the test server, all domains were then answered in 50 to 200 ms right after the start.

### Other changes
- Configuration format version 12 for the DNS settings. Older versions of ZenitiumDNS cannot read it.

## ZenitiumDNS 15.5.1 (package 15.5.1-3)
Released: 27 September 2026

### Local root zone and trust anchors (RFC 8806)
- The resolver downloads the root zone and the arpa zone from IANA, verifies them completely and uses them locally. The root zone is verified via its ZONEMD digest (RFC 8976) and the DNSSEC signatures, the arpa zone via the signatures of all records and the DS record from the root zone. Delegations to top-level domains and reverse zones come from memory, and queries for nonexistent top-level domains are answered by the resolver itself with NXDOMAIN and a signed NSEC proof. In testing, random made-up TLDs and new domains no longer caused any queries to the root servers.
- The zones are updated hourly with If-Modified-Since. A zone that fails verification, whose signatures expire or that is older than its SOA expire value is not used; the resolver then queries the root servers as before.
- The trust anchors (root KSK) are taken daily from IANA's `root-anchors.xml`, but only if the signature of the file chains up to the ICANN Root CA. Both ICANN root certificates are bundled.
- For all three, Settings > Resolver offers a choice: automatically from IANA, a custom version edited in the web interface, or off (query the root servers or use the bundled anchors). The self-test shows the serial number, the verification result and errors.

### Unencrypted DNS (Do53)
- New Do53 mode: enabled; answer DDR only and drop other queries; answer DDR only and refuse other queries with `REFUSED`; or disabled (port 53 is not opened). Queries from loopback addresses are always answered. The self-test warns if Do53 only answers DDR but there are no DDR records.
- Queries from addresses on client block lists are now dropped over UDP before they are parsed.

### Defaults for public resolvers
- Rate limiting: 1000 queries/s per IPv4 address over UDP and 5000 over TCP, DoT, DoH and DoQ, without an aggregate limit for `/24`, which slows down CGNAT pools; IPv6 `/64` 1000 and 5000, `/48` 10,000 and 50,000. All rate-limited UDP queries receive a TC response so that real clients switch to TCP immediately. The previous defaults are replaced on update, custom values are kept. The interface validates ranges and offers "Fill in recommended values", and the self-test warns about limits that hit clients behind NAT.
- Maximum TTL in the cache 1 day instead of 7 days, and a new cap of 1 hour for negative answers (RFC 2308), also for the SOA TTL sent to clients.
- Resolution errors are no longer logged, and if logging is turned on, as a single line without stack trace. This log is turned off on update.
- Log files are kept for 7 days.

### Blocking
- The Firefox canary domain `use-application-dns.net` and Chrome's preflight check `dns-tunnel-check.googlezip.net` can be answered with NXDOMAIN. Firefox then stays with the network's resolver, and Chrome asks before opening preloaded pages.
- The server domain name and all names in the TLS certificate, including their subdomains, are automatically on the allow list, so that lists such as HaGeZi's DoH bypass do not block your own DoH or DoT host name.

### Apps
- The app store and installing, updating and uninstalling apps are gone. All apps come with the package; missing bundled apps are restored at startup, existing ones are updated on package updates.
- New configuration interface: a form with German labels for every app, derived from its `dnsApp.config`, with lists, groups and mapping tables. In expert mode the JSON can be edited directly; invalid JSON is not saved.

### Dashboard and monitoring
- Time ranges of 1, 5 and 30 minutes with per-second resolution; the default remains the last hour.
- Live graphs of internal processes: CPU, memory, garbage collection, thread pool, queues, running resolutions, queries per second and lock contention over the last 5 minutes, can be turned off.
- New watchdog: it checks every 10 seconds and steps in on serious problems. When disk space runs low or a log file exceeds 512 MB, it pauses file logging until midnight and deletes older log files if space is short; on memory pressure it trims the cache; it empties an overflowing statistics queue; it gives a starved thread pool more threads; and if DNS services are missing, it restarts them up to three times. Interventions appear in the log and in the self-test.

### Updates and version
- The update check queries the latest release of this project on GitHub at most once per hour and shows the changes, the download link for the matching architecture, SHA256SUMS and the installation command. Only an update that was actually found is logged. Nothing is installed automatically, because the service runs without root privileges.
- The About page shows the package version, the Technitium base version, the .NET runtime, the operating system and the architecture.

### Removed
- Prometheus metrics, API tokens (including `DNS_SERVER_AUTH_STATIC_SESSIONS`) and the API documentation. The web interface keeps using its internal API.

### Encryption and privacy
- EDNS padding (RFC 7830, RFC 8467), active by default: responses over DoT, DoH and DoQ are padded to a multiple of 468 bytes when the query itself contains padding, as sent by browsers and Android. Optionally always or off, under Settings > Encrypted protocols. Queries to encrypted forwarders are padded to 128 bytes. Responses over port 53 are never padded. The self-test warns when padding is turned off.
- New logging option "Do not log client addresses": entries then contain neither IP addresses nor ports of clients, not even in the rate limiting messages.
- DDR additionally answers `_dns.<server name>` and the name in the certificate, so that clients that already know the resolver name can query the encrypted services directly.

### Security
- Fixed: A name server could return records with empty data, such as an A record without an address. Every query for such names wrote an exception including stack trace to the log, about 1 KB per query, which could be used to fill up the disk; the cache view also broke. Such records are now rejected when parsed.
- Fixed: A rejected settings change could still apply individual values, for example turning off DDR while Do53 only answers DDR.

### Fixed
- The automatic IPv6 detection suspended working IPv6 connectivity. Just 8 consecutive errors from any IPv6 name server were enough, and errors also included queries that were only canceled because an IPv4 server had answered faster, as well as responses such as REFUSED or SERVFAIL. On a public resolver this happened all the time; afterwards zones that only have IPv6 name servers could no longer be resolved. Now only real transport errors (timeout, network or host unreachable) and queries that stayed unanswered for at least one second count. IPv6 is only suspended when not a single IPv6 response arrived within 30 seconds, at least 16 errors from at least 2 addresses occurred and a check of the IPv6 root servers fails as well. Every response over IPv6 lifts the suspension immediately; both transitions are logged. The check of the IPv6 root servers only considers IPv6 broken when two rounds 5 seconds apart, each with 4 random root servers and a 3 second timeout, fail; the log message names the affected servers and the error. At startup the first check runs after 15 seconds, when the cache and block lists are loaded, because a single check under startup load could wrongly suspend IPv6 for up to 10 minutes. Until the result is known (at most 120 seconds), the server uses IPv6 addresses only with lower priority, including for root hints and for name servers without glue, whose IPv4 address is then resolved first. On a test server without global IPv6, the first queries after every start previously failed with SERVFAIL; now they are answered in 110 to 250 ms, as fast as with IPv6 turned off, and afterwards the check only runs once a minute while IPv6 is suspended. In a test with dead IPv6 name servers and working IPv6: previously suspended and 0 of 20 queries to an IPv6-only zone answered, now not suspended and 20 of 20.
- Reloading the local root and arpa zones into the cache (every 15 minutes and after clearing the cache) aborted with "Operation is not valid due to the current state of the object" because name server records were reused. They are now created anew; if a single delegation fails, the rest is still loaded and a single-line message is logged.
- Clients that close a DoH, DoT or DoQ connection during the response or read too slowly produced error messages with stack traces in the log. These cases are now handled silently, and the query is still counted in the statistics and the query log. The same applies to DoH requests whose body does not arrive within the receive timeout and to QUIC connections that end with "No route to host".
- Clients that only offer TLS 1.0 or 1.1 for DNS-over-TLS produced the misleading message "The server mode SSL must use a certificate with the associated private key" including stack trace on every attempt. The handshake is now rejected silently; TLS 1.2 and 1.3 are unchanged.
- An invalid server name (SNI) in the TLS or QUIC handshake, for example with control characters or spaces, made the connection fail with an exception. The name is now ignored and the connection is served normally.
- The query log shows response codes such as `NOERROR` and `NXDOMAIN` instead of German descriptions.

### Other changes
- Configuration format version 11 for the DNS settings. Older versions of ZenitiumDNS cannot read it.
- The issues in the Technitium repository since 15.5.1 were reviewed: the reported resolver problems are already fixed in the base or concern features that ZenitiumDNS does not contain (Block Page app, syslog double formatting).

## ZenitiumDNS 15.5.1 (package 15.5.1-2)
Released: 26 September 2026

### Protection for public operation
- Rate limiting works in queries per second with a token bucket per client subnet (GCRA, as in dnsdist). An adjustable burst (default 5 seconds) allows short spikes, for example while a web page loads. New defaults: IPv4 `/32` 100 and 400, `/24` 1000 and 4000, IPv6 `/64` 100 and 400, `/56` 1000 and 4000 queries per second for UDP and TCP. Existing limits are converted, and the previous defaults are replaced with the new ones. The start and end of throttling are logged.
- New client block lists in the request filter: lists such as IPsum or Spamhaus DROP are loaded and updated automatically. Queries from blocked addresses are dropped over UDP before they are evaluated, and TCP, DoT, DoQ and DoH connections are closed immediately. The lookup uses sorted address ranges. New metrics `client_blocklist_drops_total` and `client_blocklist_ranges`.

### Blocking
- Custom blocking text for the Extended DNS Error and the TXT report with the placeholders `{domain}`, `{list}` and `{source}`.
- Custom TTL for negative caching: NXDOMAIN and NODATA blocking responses carry an SOA record with this TTL and this MINIMUM (default 300 seconds).
- Fixed: The SOA MINIMUM of blocking responses fell back to 30 seconds after every restart until the setting was changed once.
- The quick selection of block lists only contains HaGeZi's lists in the format for this server, loaded from the build mirror `hagezi-mirror.dnsbunker.org`. The default update interval is 8 hours.
- Block lists need about half the memory: 2.5 million domains (HaGeZi PRO and TIF) take about 200 instead of 395 MB. Lookups run without allocating memory. Measured on 20 cores: about 913,000 queries/s for allowed and 852,000 queries/s for blocked names, 919,000 queries/s without lists. Reloading takes 1.1 seconds.

### Encrypted protocols
- TLS certificates in PEM format, such as `fullchain.pem` and `privkey.pem` from Let's Encrypt, also for the web interface. Intermediate certificates are sent along, and encrypted keys in PKCS#8 format are supported. Certificate and key are reloaded automatically after a renewal, also via symlinks.
- DDR (RFC 9462) is built in: the server answers `_dns.resolver.arpa` SVCB with the enabled encrypted services, their ports and the name in the certificate. Optionally only over unencrypted DNS (default). The generated records are shown in the settings.
- 0-RTT (TLS early data) is not offered server-side by the TLS and QUIC stack of .NET. The settings explain how 0-RTT can be used for DoH through an upstream reverse proxy.

### Self-test
- New "Self-test" section: it checks listening services, resolution of the root zone including DNSSEC validation, IPv6, certificates, the admin password, reachability of the web interface, recursion, rate limiting, the request filter, block lists and client block lists, apps, system time, memory, UDP buffers, the file limit and free disk space. Serious problems also appear on the dashboard. New API call `api/selftest/run`.

### Resolver
- Fixed: Authoritative servers such as Cloudflare's only answer one query per TCP connection. Reused connections therefore ran into timeouts, and large responses such as DNSKEY sets with ML-DSA signatures failed. The TCP fallback after truncated UDP responses now uses its own connections, and servers without connection reuse are detected.
- QNAME minimization queries a zone again with the full name if none of its name servers answers the minimized query.
- Fixed: With "Prefer IPv6" and without working IPv6 connectivity, downloads of block lists and apps failed after 100 seconds. Downloads now use the IPv6 mode that is actually available and switch to the next address after 5 seconds.

### Other changes
- Configuration format version 9 for the DNS settings and version 5 for the web interface.
- The API documentation describes the new settings and calls.

## ZenitiumDNS 15.5.1
Released: 26 September 2026

### Sync with Technitium DNS Server 15.5.1
- All fixes from Technitium DNS Server 15.5.1 of 26 September 2026 have been adopted where they concern parts that still exist in ZenitiumDNS:
  - The resolver no longer has a fixed limit for hash operations per query. If a resolution reaches another resolver limit, the error message and the Extended DNS Error (private code "ResolverLimitReached") name the reason.
  - RRSIG signatures whose inception lies after their expiration are considered invalid.
  - Blocked responses set the RA flag depending on "Return blocking report", also in the Advanced Blocking app (version 11.2.1).
  - Local block lists (`file://`) are read directly from the source file instead of being copied. If the file is missing, this is logged.
  - Cache maintenance only triggers garbage collection after larger cleanups. Server GC is configured permanently.
  - Path comparisons for the log folder and in the app management have been corrected.
  - `api/user/session/delete` checks the length of the partial token.
  - XSS in the list of log files is fixed.
  - `install.sh` only changes `/etc/resolv.conf` on the initial installation and sets `umask 0022`.

### Request filter for public operation
- New settings section "Request filter" with rules modeled after dnsdist. All rules are active by default and apply before any further processing:
  - unreadable queries and queries under 12 bytes,
  - queries over 1232 bytes (adjustable),
  - opcode other than QUERY,
  - class other than IN,
  - type ANY,
  - AXFR and IXFR,
  - queries without the RD flag,
  - EDNS version greater than 0.
- Over UDP, matches are dropped silently so that the server cannot be used as a reflector. Over TCP, DNS-over-TLS, DNS-over-HTTPS and DNS-over-QUIC it answers with `REFUSED` and the Extended DNS Error "Prohibited". Optionally, UDP queries are only refused as well. Queries from loopback addresses are exempt.
- Match counters per rule are shown in the settings, in `api/dashboard/metrics/json` and as the Prometheus metric `request_filter_matches_total{rule}`.

### DNSSEC
- Validation of the post-quantum algorithm ML-DSA-44 (algorithm 18, draft-westerbaan-dnssec-mldsa) via BouncyCastle.
- Downgrade protection: if the DS record set of a zone announces a post-quantum algorithm, the resolver only accepts post-quantum keys for this zone. The "post-quantum downgrade protection" setting is active by default.
- The DNS client of the web interface explains why a DNSSEC check against this server fails when its DNSSEC validation is turned off. Previously only "Attack detected! RRSIGs missing" appeared.
- Toggling DNSSEC validation always clears the cache.

### Apps
- The bundled apps are installed on the first start but stay disabled until they are enabled in the web interface. On package updates they are updated and their configuration is kept. Apps uninstalled by the user are not installed again.
- Every app can be enabled and disabled, also via `api/apps/enable` and `api/apps/disable`. Disabled apps do not take part in processing, and their configuration stays editable.
- New environment variable `DNS_SERVER_BUNDLED_APPS_PATH` for the folder with the bundled apps.

### Defaults for new installations
- Cache: at most 100,000 entries instead of 10,000.
- Blocking responses: TTL 300 instead of 30 seconds.
- Network: listen backlog 1024 instead of 100, TCP receive timeout 5 instead of 10 seconds, IPv6 enabled for outgoing queries.
- Statistics and log files are kept for 30 instead of 365 days.
- Recursion stays restricted to private networks until it is deliberately opened to everyone.
- Existing configurations stay unchanged.

### Performance
- Statistics data runs through a lock-free queue with its own processing thread.
- Unique clients are counted with HyperLogLog using a fixed amount of memory. `clients_total` is now a gauge in the Prometheus metrics.
- UDP receive threads only wake further threads on a sustained backlog, and send buffers are reused.
- Response types are tagged without boxing, and rate limiting skips the check as long as no client exceeds a limit.
- Server GC with concurrent garbage collection.

### Security
- DNS-over-HTTPS via POST: requests over 65,535 bytes are rejected with status 413, and the body is read with a limit. Aborted connections no longer produce error logs.
- DNS messages with implausible record counts are dropped before parsing.
- The web interface escapes values in inline JavaScript handlers, for example in the cache browser, in forwarder zones and in the logs.

### Operation and source code
- Docker support removed: Dockerfile, compose file and the environment variables for initial configuration, including SSO, LDAP and `DNS_SERVER_ADMIN_PASSWORD`. `DNS_SERVER_ADMIN_PASSWORD_FILE` is kept.
- The source code no longer contains comments; only the license headers are kept.
- The DNS settings are saved in format version 8, which older builds cannot read.
- Source code and releases: https://github.com/DNSBunker/ZenitiumDNS

## ZenitiumDNS 15.5
Released: 26 September 2026

### Fork and project structure
- Fork of Technitium DNS Server 15.5 under the name ZenitiumDNS. The complete list of changes from the original is in [NOTICE.md](NOTICE.md).
- DNS server and library merged into one source tree with a single solution (`ZenitiumDNS.slnx`) and project references.
- The update check and the DNS app store are disabled by default and can be pointed to your own endpoints via the new environment variables `DNS_SERVER_UPDATE_CHECK_URL` and `DNS_SERVER_APP_STORE_URL`.
- Linux installations use `/opt/zenitiumdns`, `/etc/zenitiumdns` and `/var/log/zenitiumdns` with the service and user `zenitiumdns`.
- The Docker image is built directly from source with a multi-stage `Dockerfile`.
- The web interface and the documentation are translated into German.

### Debian package
- New self-contained Debian package for Debian 13 (`setup/debian/build-deb.sh`, amd64 and arm64). It bundles the .NET runtime, so no separate .NET installation is needed.
- Hardened systemd service with its own system user, started only after `network-online.target`.
- On the initial installation a random admin password is generated and printed instead of using `admin`/`admin`.
- If systemd-resolved is active, its stub listener is disabled automatically so that port 53 is free. This is reverted when the package is removed.
- All bundled DNS apps are provided as ZIP files in `/usr/share/zenitiumdns/apps` and can be installed via the web interface.

### Focus on public resolvers
- ZenitiumDNS is tailored to running as a public recursive resolver. The following features of the original were removed:
  - authoritative zones of type primary, secondary, stub, secondary forwarder and catalog, including DNSSEC signing, key management and SOA editing,
  - zone transfers (AXFR, IXFR, XFR-over-TLS, XFR-over-QUIC), DNS NOTIFY, dynamic updates (RFC 2136) and TSIG keys,
  - the DHCP server with scopes, leases and the "DHCP Administrators" permission group,
  - clustering including the HTTP API client and the cluster options in backup and restore,
  - importing DNS client responses into a local zone,
  - the apps for LAN and hosting scenarios: Auto PTR, Block Page, Default Records, DNS Block List, Failover, Filter AAAA, Geo Continent, Geo Country, Geo Distance, No Data, NX Domain Override, Split Horizon, Weighted Round Robin, What Is My DNS, Wild IP and Zone Alias,
  - Windows service, system tray app, Windows firewall library and Windows installer.
- Kept are conditional forwarder zones (called "forwarder zones" in the web interface) with locally overridable records and access restriction per zone, block lists, allowed and blocked domains, and the resolver apps.
- Queries of type AXFR and IXFR are answered with `REFUSED` and the Extended DNS Error "Not Supported", NOTIFY and UPDATE with `NOTIMP`. Signed queries (TSIG) receive `BADKEY`.
- Existing installations can be used further: conditional forwarder zones, settings, users and statistics are kept. Zone files of other zone types stay unchanged in the configuration folder and are skipped at startup with a log entry. Removed settings are discarded on the next save.

### Statistics and monitoring
- New response time measurement from the arrival of a query to sending the response for UDP, TCP, DNS-over-TLS, DNS-over-HTTPS and DNS-over-QUIC. Average, median, 95th and 99th percentile and maximum are evaluated, as well as separate averages for responses from the cache and for recursively resolved responses.
- The dashboard shows key figures for queries per second, response time, cache hit rate, error rate, blocking rate and clients, status chips for blocking, DNSSEC validation, IPv6, resolution mode and uptime, a per-minute response time history, tables with shares, and switchable history views (Overview, Responses, Answered by, Clients).
- The pie charts show shares in the tooltip and a note when there is no data in the time range. Charts adapt to the light and dark theme.
- `api/dashboard/stats/get` additionally returns `live`, `lastHourResponseTime`, `responseTimeChartData` and `serverStatus`. The chart data no longer contains colors.
- The JSON metrics contain response times over 5 and 60 minutes, the number of cache entries and the server status. The Prometheus metrics additionally contain `cache_entries`, `ipv6_upstream_available`, `queries_per_second` and `response_time_milliseconds` for 1, 5 and 60 minutes.
- New API call `api/dashboard/ipv6/probe`, which checks the IPv6 reachability of name servers immediately.
- Fixed: In truncated top lists and charts, the first truncated entry was missing from the "Others" sum.

### Web interface
- New look: app frame with sidebar and page titles, a petrol color system matching the logo, locally embedded Red Hat Text, Display and Mono fonts (no external requests), consistently styled forms, tables, dialogs and notices. Light, Dark and Amber use the same token system, and the "same as operating system" color scheme applies even before the scripts have loaded.
- The dashboard starts with a readout band: queries per second, response time, cache hit rate, error and blocking rate as well as clients, each with its history over the selected time range and a status in words.
- Chart colors are checked for distinguishability with color vision deficiencies and follow the color scheme. Every category keeps its color across all views.
- The interface can be used on tablets and smartphones: the sidebar turns into a toolbar, and tables can be scrolled sideways. The fixed minimum width of 970 pixels is gone.
- Notices appear as a toast at the top right, and loading indicators are animated icons instead of GIF images. The DNS client form is rearranged, and lists in the cache, filters and logs show actions as icons instead of bracketed links.
- The main navigation is organized by task: Dashboard, Resolver (forwarder zones and cache), Filter (blocked and allowed domains, block lists), Apps, DNS client, Logs, Settings, Administration and About.
- The settings are split into ten sections with side navigation, explanatory texts and an always visible save bar: Server, Network, Resolver, Forwarding & proxy, Cache, Blocking, Rate limiting, Encrypted protocols, Web interface and Logging.
- New settings: automatic IPv6 fallback with status display and check button, the number of UDP receive threads per socket and a limit for concurrent queries per TCP/TLS connection.
- Settings that are no longer needed for SOA, zone transfers, NOTIFY and TSIG have been removed.
- Dates consistently appear in German format, and forwarder entries show the proxy type and DNSSEC validation in readable form.
- The dashboard refreshes immediately when you switch back to its tab.

### Recursive resolver
- Fixed: `SERVFAIL` with "No valid response from name servers" for domains that are resolved via CNAME chains or name servers without glue records (for example `www.bbc.com`, `x.com`). The resolver limits per query have been raised (upstream issue #2175).
- Fixed: QNAME minimization sent an additional query of type `A` for the last label before the actual query, even after an NXDOMAIN response.
- Fixed: Recursive resolution failed completely when the root priming query failed or returned no glue records. The resolver now falls back to the root hints. The priming query is sent without the RD flag.
- Fixed: Duplicate name server entries in the name server list of the resolver.
- Fixed: Responses with a different letter case of the QNAME (DNS 0x20) were treated as a general error instead of a spoofing attempt. The resolver now repeats the query over TCP immediately.
- Fixed: With the "Prefer IPv6" setting, resolution failed on every query for zones whose name servers cannot be reached over IPv6, because IPv6 addresses were always queried first. Unreachable addresses are now detected and sorted behind working IPv4 addresses.
- New automatic IPv6 fallback (setting "Suspend IPv6 automatically when it fails", on by default): after 8 consecutive IPv6 timeouts, outgoing IPv6 queries are suspended for one minute, for up to 30 minutes on repeated failures. A check against the IPv6 root servers every two minutes resumes IPv6 as soon as it works.
- The statistics for name server selection (RTT, error rate) are now kept separately for IPv4 and IPv6. A broken IPv6 address therefore no longer penalizes the working IPv4 address of the same name server.
- The answer rate of name servers is calculated as a moving average instead of over the entire uptime. Failed name servers are therefore sorted to the back within a few queries and preferred again after they recover.
- Fixed: The multiple unstable sorts of the name server list could destroy the order by response time again. The selection now uses a single combined sort.
- The cache view additionally shows the name server statistics separately for IPv6 and the current answer rate.

### Cache
- Fixed: If DNSSEC validation failed at the root servers, for example behind a firewall that intercepts DNS, the root servers stayed blocked for five minutes. This also applied after turning off validation and after "Clear cache". Both actions now reset the block, and toggling DNSSEC validation clears the cache in both directions.
- Fixed: Expired failure cache entries were served as stale answers (serve stale), which prolonged resolution failures after outages.
- Fixed: Cache prefetching triggered an upstream query on almost every query for records with a short TTL.
- Fixed: Cache maintenance ran a blocking full garbage collection every minute, which halted query processing for up to 250 ms (upstream issue #2174). Reloading statistics, block lists and the Advanced Forwarding app now also uses a background garbage collection.
- Fixed: A race condition in cache maintenance could discard freshly cached entries and inflate the entry counter when an empty cache zone was removed exactly while new entries were being added.
- Fixed: For A and AAAA record sets with several records, the last-used time was never updated. With a full cache, frequently used entries were therefore evicted first.

### Performance
- UDP queries are read by dedicated receive threads and answered directly on the same thread on cache hits, without a detour through the thread pool. At 100,000 queries per second, the CPU time per query drops by about 70 % and the mean latency from 70–85 µs to 19 µs.
- Responses over UDP are sent synchronously. This saves one asynchronous socket operation including allocations per query.
- The internal processing chain uses `ValueTask` instead of `Task`, so no task objects are created for queries that complete synchronously.
- Name compression when serializing DNS messages no longer copies domain names and uses a reusable offset list.
- The check for special zones (for example `.local`, `.test`) no longer creates temporary strings.
- The last-used time of cache and zone entries is written at most once per second. This avoids contention between CPU cores.
- Overall, allocations per query drop by about 65 % and the garbage collection pause time under full load from 22 % to 7 %. Peak throughput rises by 5 to 12 %.

### Encrypted protocols
- Fixed: Over a single DNS-over-TCP or DNS-over-TLS connection, a client could keep an unlimited number of queries open at the same time. By default, at most 100 running queries per connection are now allowed (adjustable from 1 to 10,000); further queries are only read after earlier ones complete.
- For DNS-over-HTTPS, the endpoint URL without the query content (`?dns=…`) is now stored and logged as the server address.

### Security
- Fixed: The API tokens defined in `DNS_SERVER_AUTH_STATIC_SESSIONS` were not loaded on the very first start without an existing `auth.config` and only worked after a restart.
- Fixed: The server filter in the query log apps for MySQL, PostgreSQL and SQL Server was not passed as a parameter (SQL injection).
- Fixed: Several places in the web interface output app names without HTML encoding (XSS).
- Fixed: Users without admin rights could delete sessions of other users.
- Fixed: When restoring a backup, ZIP entries could be written outside the target folder.
- Fixed: TLS certificate paths in folders whose name starts with the name of the configuration folder (for example `/etc/dnscert` next to `/etc/dns`) were saved as a wrong relative path. The certificate could no longer be loaded after a restart (upstream issue #2162).

### Web API and web interface
- Fixed: The API calls for adding, getting, updating and deleting records ignored `zone=.`. Records for the root zone therefore ended up in a subordinate zone.
- Fixed: The page size of the log query was not limited, and the size limit for downloading logs could overflow.
- Fixed: Pending changes to zone and configuration files were not always written before a backup was created and on shutdown.

### Apps and stability
- Fixed: The syslog target of the Log Exporter app formatted every message twice according to RFC 5424 (upstream issue #2173).
- Fixed: The timer of the load balancing proxy could still fire after it was disposed and throw exceptions.
- Fixed: If loading a zone file failed at startup, the cleanup led to a `LockRecursionException`.

# Technitium DNS Server changelog

The following entries come from the original Technitium DNS Server project that ZenitiumDNS is based on. Names of settings and menus refer to the respective version of the original.

## Version 15.5
Release Date: 19 September 2026

- Added support for LDAP authentication. Thanks to Roy Hagland (@Hemsby) for the PR #1869.
- Implemented support for [draft-farrokhi-dnsop-ede-nta](https://datatracker.ietf.org/doc/html/draft-farrokhi-dnsop-ede-nta). NTA can be added by creating a Conditional Forwarder zone for the domain name with DNSSEC validation disabled. The FWD record's comments are used with the Extended DNS Error (EDE) included in the response.
- Added Zone File Editor option for Primary and Conditional Forwarder zones.
- Added support for predefined static API sessions that are configured using new `DNS_SERVER_AUTH_STATIC_SESSIONS` environment variable.
- Added new `DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH` environment variable that allows changing the web service www root folder to allow using custom web service GUI. Thanks to Adrián García (@byGarcia) for PR #2138.
- Updated docker compose to add health check option that uses the Health Check API call.
- Updated Health Check API to be allowed to be called from loopback addresses without requiring authentication to support Docker health check.
- Fixed multi-hop amplification vulnerability reported by Qifan Zhang from Palo Alto Networks, that used multiple CNAME and delegation hops achieving a 4,096:1 packet amplification factor.
- Fixed cache poisoning vulnerability reported by Qifan Zhang from Palo Alto Networks, that allowed caching out-of-bailiwick DNAME record received from an attacker controlled zone targeting any domain name.
- Fixed DNSSEC validation bypass vulnerability reported by Qifan Zhang from Palo Alto Networks, that allowed an attacker controlled zone to inject out-of-bailiwick DS (Delegation Signer) records in referral responses to poison the resolver cache and disable DNSSEC validation for arbitrary signed zones.
- Fixed Denial of Service (DoS) vulnerability reported by Xuanchao Xie, that allowed an attacker to exploit DNS-over-HTTPS/3 (DoH/3) protocol service implementation to cause the DNS server to buffer large amount of data in memory causing the server to crash with Out Of Memory (OOM) error.
- Fixed authorization bypass vulnerability reported by Tao Pan (@pant0m), that allowed using `ptr` option feature in Add Record and Update Record API calls, and Delete Record API call to add/overwrite/delete PTR record in arbitrary reverse zone that the current user did not have modify permissions to.
- Fixed persistent Denial of Service (DoS) vulnerability affecting attacker selected victim domain name reported by Abdullah Al Ishtiaq, Kai Tu, Matthew Carter, Xiaotian Zhou, Ananna Rahman, Yilu Dong, Tianwei Yu, Ali Ranjbar, and Syed Rafiul Hussain from SyNSec Lab, The Pennsylvania State University. This vulnerability caused the attacker to add victim domain name to the background resolver task which fails to execute and requires the DNS Server to restart to recover.
- Fixed off-path cache poisoning vulnerability reported by Lior Shafir, Ameer Saleh, Prof. Raja Giryes, and Prof. Avishai Wool from Tel-Aviv University, that allowed an attacker to inject CNAME record in cache that caused all queries for the victim domain name to get redirected to the attacker's domain name that the CNAME specified.
- Fixed multiple stored XSS vulnerabilities reported by Yuqi Qiu and Xiang Li from AOSP Lab, Nankai University.
- Fixed zone name validation bypass vulnerability in Clone Zone and DNS Client Import API calls reported by Yuqi Qiu and Xiang Li from AOSP Lab, Nankai University.
- Fixed severe bug in DNS Client response sanitization function that caused Out Of Memory (OOM) exception resulting the DNS server to crash when specific types of response was received.
- Removed Auto Prefetch feature since it was not really effective while requiring too many system resources to function. Note that basic Prefetch feature is still available.
- Wild IP App: Updated app to add hex string support for IPv4. Thanks to Marty Cannon (@swimlane-marty) for the PR #2056.
- Multiple other minor bug fixes and improvements.

## Version 15.4
Release Date: 11 July 2026

- Fixed issue with UDP socket binding that cause response routing issues for a few of deployment scenarios.
- Fixed issues with RFC compliance checks causing issues with resolution and zone transfer in some cases.
- Added support for Unix Domain Sockets (UDS) for Web Service over HTTPS and DNS-over-HTTPS optional protocol.
- Other minor bug fixes and improvements.

## Version 15.3
Release Date: 5 July 2026

- Fixed multiple RFC compliance issues reported by Yuxiao Wu, Yunyi Zhang, Baojun Liu, and Haixin Duan from Tsinghu University.
- Fixed an issue reported by Lawrence LUO Junhua in the Apps section default permissions by removing the `Delete` permission for `DNS Administrators` group. This permissions can be misused by users in the `DNS Administrators` group to perform privilege escalation to get access to the DNS server's Administration section. For existing installations, it is recommended to manually remove the `Delete` permission for `DNS Administrators` group for the Apps section.
- Fixed an issue in the Settings section default permissions by removing the `Delete` permission for `DNS Administrators` group. This permission can be misused by users in the `DNS Administrators` to use backup/restore config files allowing to change options in the DNS Server's Administration section. For existing installations, it is recommended to manually remove the `Delete` permission for `DNS Administrators` group for the Settings section.
- Fixed multiple Stored XSS vulnerabilities in the Web Console reported by Daniel Goldberg and Anner Klein from Tenzai.
- The Linux automated installer script now supports Alpine Linux with OpenRC service. Thanks to @Wrong-Code for the PR #1889.
- Added Unix Socket support for the Web Service and DNS-over-HTTP Optional protocol. Thanks to Ingmar Stein (@IngmarStein) for the PR #1753. 
- The Zones section now support search/filtering options along with option to delete multiple zones at once.
- Added option in user drop down menu to disable Update Notification. This option will prevent the Web Console from checking for updates only for the current user. This option is stored in web browser's local storage.
- Added "Enable Check For Update" option in Settings > General section which enables the DNS Server to check if an update is available when the Check For Update API is called which usually occurs after a user logs into the Web Console. Disabling this option will disable check for software update for all users such that the API will always return no update available response without actually checking for updates.
- Added "CSP Frame Ancestors Header" option in Settings > Web Service section to allow configuring the Content Security Policy (CSP) Frame Ancestors header value.
- Added "Enable Redirect To Help Page" option in Setting > Optional Protocols section to control if the DoH help page should be shown when a user visits the `/dns-query` DoH end point with a web browser.
- Added "No Stack Trace" option in Settings > Logging section to enable logging only short error messages instead of full exception stack trace.
- Updated SSO implementation to setup user info endpoint JSON key map for supported claim types.
- Implemented support for Locally Served DNS Zones (RFC 6303) & Special-Use Domain Names (RFC 6761). The default `internal` zones are removed and they are now managed under this new implementation. A new option "Locally Served DNS Zones" is added in Settings > Recursion section to allow completely disabling these local zones. A single zone can be disabled/overridden by adding a Stub or Conditional Forwarder zone for it.
- Updated TXT record implementation to allow configuring generic character-strings enabling support for Unicode strings.
- Fixed issue in DNSSEC validation that caused the "missing RRSIG" validation failure issue in certain cases when the DNS server is configured to use forwarders.
- Added new Health Check API `/api/dnsClient/healthCheck` to enable automated health check for the DNS server without causing query log entries.
- Added new Status API `/api/status` obsoleting the SSO Status API `/api/sso/status`.
- Updated List Zones API `/api/zones/list` to allow filtering zones by name and type.
- Block Page App: Updated the app to support online signing for custom CA certificate configured in the app's config. Online signing now supports both RSA and ECDSA algorithms. Thanks to Roy Hagland (@Hemsby) for PR #1897.
- Geo Continent & Geo Country Apps: Updated both apps to support creating custom groups in app config which can then be used with APP record's JSON config.
- Multiple other minor bug fixes and improvements.

## Version 15.2
Release Date: 9 May 2026

- Updated SSO implementation to read claims from user info endpoint when available and to use `HttpClientNetworkHandler` as backchannel.
- Added new Web Service Reverse Proxy Addresses option to allow defining reverse proxies that are allowed such that Real IP header only works for these proxies.
- The Settings API has been updated to rename `reverseProxyNetworkACL` option to `dnsReverseProxyNetworkACL` to avoid confusion since this option is used only with DNS Optional Protocols.
- Multiple other minor bug fixes and improvements.

## Version 15.1
Release Date: 3 May 2026

- Added option to allow configuring SSO Scopes as required by the SSO provider.
- Updated Prometheus metrics API text output to use correct naming convention.
- Multiple other minor bug fixes and improvements.

## Version 15.0.1
Release Date: 26 April 2026

- Fixed issue that caused cluster API token to fail to sync when a secondary node joins a cluster.
- Fixed issue of incorrect sync state for SSO group map on secondary nodes.
- Added SSO scopes required by some SSO providers.
- Fixed typo in Prometheus metrics API text output.

## Version 15.0
Release Date: 25 April 2026

- Upgraded codebase to use .NET 10 runtime. If you had manually installed the DNS Server or .NET Runtime earlier then you must install .NET 10 Runtime manually before upgrading the DNS Server.
- Updated the DNS Server's install script for Linux to install the DNS Server to run as a non-root systemd service. However, existing installations would work the same after the upgrade. It is recommended to use the uninstall script before running the install script to take advantage of the new non-root systemd service installation. Note! It is recommended to export a backup zip file of the DNS Server's config from the Settings section on the panel before the upgrade.
- Updated the DNS Server's Installer for Windows to install the DNS Server to run as a non-system service. However, existing installations would work the same after the upgrade. It is recommended to uninstall the DNS Server and delete the "config" folder from the installation folder, before using the new installer to take advantage of the new non-system service installation. Warning! You must export a backup zip file of the DNS Server config from the Settings section on the panel before uninstalling the old version and deleting the existing "config" folder, and use the said backup zip file to restore config after the new installation.
- The HTTP API now supports passing session token via the `Authorization: Bearer <token>` HTTP header. The older `token` parameter in query string and form data is supported for backward compatibility.
- If you have DNS Server Cluster setup, make sure to upgrade all nodes for the Cluster to work due to a few breaking changes.
- Added support for Single Sign-On (SSO) with OpenID Connect (OIDC). Thanks to Zach Stinnett (@zstinnett) for the PR #1678.
- Added new EDNS Client Subnet (ECS) Source Address feature to read client's source IP address from the EDNS Client Subnet (ECS) option in the DNS requests coming via DNS-over-UDP or DNS-over-TCP protocols. This option allows a DNS proxy to pass the client's source IP address via ECS option to the DNS Server.
- Added new option in Import Zone feature to allow overwriting entire zone such that only the records being imported will exist (along with zone's SOA record) after the import process.
- Added option to manually activate primary zone's Key Signing Key (KSK) status to prevent the DNS Server from regularly looking up for DS records in parent zone.
- Added new option in Setting > General section to allow configuring UDP listener socket send and receive buffer size.
- Added support for Prometheus with new metrics API call that returns lifetime counters.
- Updated DNS Server to dynamically bind UDP listeners to local interface IP address on first request to ANY address. This allows sending response to the correct interface the request was received on.
- Updated DHCP Server's DNS entry management implementation to allow having persistent DNS records for reserved leases with hostname configured even when reserved lease was not allocated.
- Implemented new IPv6 Mode option in DNS Server for better performance on dual-stack networks.
- Implemented support for EDNS EXPIRE option (RFC 7314).
- Fixed bug in DNS-over-QUIC (DoQ) optional protocol that caused the DoQ service to fail to accept new connections.
- Fixed DNS amplification vulnerability reported by Shuhan Zhang, Dan Li, and Baojun Liu from Tsinghua University, caused by Self-Pointed Glue Records.
- Fixed DNS amplification vulnerability reported by Shuhan Zhang, Dan Li, and Baojun Liu from Tsinghua University, caused by Aggressive Fetching of DNSSEC Records.
- Fixed a DNS amplification vulnerability reported by Qifan Zhang, Palo Alto Networks, caused by Cyclic Name Server Delegation.
- Implemented new Change Theme menu feature with support for automatic dark/light mode based on host system's theme. 
- Added a new Amber theme for improved visual ergonomics and accessibility. Thanks to DaeDae (@daedaevibin) for the PR #1810.
- The Logs > Query Logs section now support Live Update feature for automatically refreshing query logs in results.
- The Dashboard now includes a convenient option at Top Blocked Domains to enable/disable blocking.
- Query Logs (PostgreSQL) App: Added new app to support PostgreSQL as the backend database for query logs. Thanks to Chloe Surett (@scj643) for the PR #1600.
- Query Logs (Sqlite) App: Updated the app's pagination logic to significantly improve query performance. Thanks to Jim Strang (@jimstrang) for the PR #1702.
- Query Logs (MySQL) App: Updated the app's pagination logic to significantly improve query performance. Thanks to Jim Strang (@jimstrang) for the PR #1702.
- Query Logs (SQL Server) App: Updated the app's pagination logic to significantly improve query performance. Thanks to Jim Strang (@jimstrang) for the PR #1702.
- Block Page App: Updated the app to implement online SSL certificate signing feature to allow it to do SSL MiTM when app's self-signed root certificate is installed on client systems.
- Wild IP App: Added new `allowedNetworks` option in the APP record data config for configuring allowed networks to prevent misuse/abuse.
- Drop Requests App: Added new `allowedLocalEndPoints` option to allow requests coming only from the listed DNS Server Local End Points while dropping requests coming from any other DNS Server Local End Point.
- Geo Continent App: Updated app to support Autonomous System Number (ASN) entries in APP record data.
- Geo Country App: Updated app to support Autonomous System Number (ASN) entries in APP record data.
- MISP Connector App: Removed the app since it is not feasible to be supported.
- All DNS Apps now support comments in its JSON config. The APP record data JSON too now supports comments.
- All DNS Apps now include a Read Me file in MD format. Thanks to Zafer Balkan (@zbalkan) for the PR #1704.
- Fresh installation of DNS Server now uses platform specific log folder path.
- Multiple other minor bug fixes and improvements.

## Version 14.3
Release Date: 20 December 2025

- Added support for Dark Mode. Thanks to @skidoodle for the PR.
- Updated Catalog zones implementation to allow adding Secondary zones as members.
- Updated Restore Settings option to allow importing backup zip files from older DNS Server versions.
- Added new options in Settings to configure default TTL values for NS and SOA records.
- Added DNS record overwrite option in DHCP Scopes to allow dynamic leases to overwrite any existing DNS A record for the client domain name.
- Advanced Blocking App: Added new option to allow configuring block list update interval in minutes.
- Split Horizon App: Updated app to support mapping domain names to group for address translation feature.
- Multiple other minor bug fixes and improvements.

## Version 14.2
Release Date: 22 November 2025

- Fixed bug in Clustering implementation which prevented using IPv4 and IPv6 addresses together. Thanks to @ruifung for the PR. 
- There is also a breaking change in clustering and thus all cluster nodes must be upgraded to this release to avoid issues.
- Updated the "Allow / Block List URLs" option implementation to support comment entries.
- Advanced Blocking App: Updated app to implement `blockingAnswerTtl` option to allow specifying the TTL value used in blocked response.
- Log Exporter App: Updated the app to add EDNS logging support. Thanks to @zbalkan for the PR.
- MISP Connector App: Added new app that can block malicious domain names pulled from MISP feeds. Thanks to @zbalkan for the PR.
- Multiple other minor bug fixes and improvements.

## Version 14.1
Release Date: 16 November 2025

- Updated Clustering implementation to allow configuring multiple custom IP addresses. This introduces a breaking change in the API and thus all cluster nodes must be upgraded to this release for them to work together.
- Fixed issues related to user and group permission validation when Clustering is enabled which caused permission bypass when accessing another node.
- Fixed bug that caused the Advanced Blocking app to stop working.
- Added environment variables for TLS certificate path, certificate password, and HTTP to HTTPS redirect option. Thanks to @simonvandermeer for the PR.
- Updated Hagezi block list URLs. Thanks to @hagezi for the PR.
- Other minor changes and improvements.

## Version 14.0.1
Release Date: 9 November 2025

- Fixed bugs in the Force Update Block List and Temporary Disable Blocking API calls.
- Fixed session validation bypass bug during proxying request to another node when Clustering is enabled.
- Fixed issue of failing to load app config due to text encoding issues.
- Fixed issue of failure to load old config file versions due to validation failures in some cases.
- Updated GUI docs for Cluster initialization and joining.
- Other minor changes and improvements.

## Version 14.0
Release Date: 8 November 2025

- Upgraded codebase to use .NET 9 runtime. If you had manually installed the DNS Server or .NET 8 Runtime earlier then you must install .NET 9 Runtime manually before upgrading the DNS Server.
- This major release has a breaking changes in the Change Password HTTP API so its advised to test your API client once before deploying to production.
- Fixed Denial of Service (DoS) vulnerability in the DNS Server's rate limiting implementation reported by Shiming Liu from the Network and Information Security Lab, Tsinghua University. The DNS Server now has a redesigned rate limiting implementation with different Queries Per Minute (QPM) options in Settings that help mitigate this issue.
- Fixed Cache Poisoning vulnerability achieved using a IP fragmentation attack reported by Yuxiao Wu from the NISL Lab Security, Tsinghua University. The DNS Server fixes this issue by adding missing bailiwick validations for NS record in referral responses.
- Fixed [DNSSEC Downgrade](https://dnssec-downgrade.net/) vulnerability that made it possible to bypass validation when one of domain name's DNSSEC algorithm was not supported by the DNS Server.
- Implemented Clustering feature where you can now create a cluster of two or more DNS Server instances and manage all of them from a single DNS admin web console by logging into anyone of the Cluster nodes. It also features showing aggregate Dashboard data for the entire cluster.
- Added TOTP based Two-factor authentication (2FA) support.
- Added options to configure UDP Socket pooling feature in Settings.
- Fixed bug in zone file parsing that failed to parse records when their names were not FDQN and matched with name of a record type.
- Fixed issue with internal Http Client to retry for IPv4 addresses too when `Prefer IPv6` option is enabled and IPv6 address failed to connect.
- Fixed bug of missing NSEC/NSEC3 record in response for wildcard and Empty Non-terminal (ENT) records in Primary zones.
- Fixed multiple issues in Prefetch and Auto Prefetch implementation that caused undesirable frequent refreshing of cached data in certain cases.
- Query Logs (Sqlite) App: Updated app to use Channels for better performance.
- Query Logs (MySQL) App: Updated app to use Channels for better performance. Fixed bug in schema for protocol parameter causing overflow.
- Query Logs (SQL Server) App: Updated app to use Channels for better performance.
- NX Domain App: Updated app to support Extended DNS Error messages.
- Multiple other minor bug fixes and improvements.
 
## Version 13.6
Release Date: 26 April 2025

- Added option to import a zone file when adding a Primary or Forwarder zone. This allows using a template zone file when creating new zones.
- Updated the web GUI to support custom lists for DNS Client server list, quick block drop down list and quick forwarders drop down list. To create a customized list, read the instructions given in the `www/json/readme.txt` file found in the installation folder.
- Updated the record filtering option in zone edit view to support wildcard based search.
- Fixed issue in DNS-over-QUIC service that caused the service to stop working due to failed connection handshake.
- Query Logs (Sqlite) App: Updated app to support VACCUM option to allow trimming database file on disk to reduce its size.
- Geo Continent App and Geo Country App: Updated both apps to support macro variable to simplify APP record data JSON configuration.
- Multiple other minor bug fixes and improvements.

## Version 13.5
Release Date: 6 April 2025

- Implemented [RFC 8080](https://datatracker.ietf.org/doc/rfc8080/) to add support for Ed25519 (15) and Ed448 (16) DNSSEC algorithms for both signing and validation.
- Added support for user specified DNSSEC private keys. This adds option to specify private key in PEM format when signing zone or when doing a key rollover.
- Added feature to filter records in the zone editor based on its name or type to allow ease of searching records in large zones.
- Added support for writing DNS logs to Console (STDOUT) along with existing option to write to a file.
- Updated Import Zone option to allow importing directly from a given file along with existing option to enter records to import with a text editor.
- Updated zone file parser to support BIND extended zone file format.
- Updated Query Logs view to show records with background color based on the type of log entry.
- Implemented [draft-fujiwara-dnsop-resolver-update](https://datatracker.ietf.org/doc/draft-fujiwara-dnsop-resolver-update/) to cache parent side NS records and child side authoritative NS records separately in DNS cache.
- Removed [NS Revalidation (draft-ietf-dnsop-ns-revalidation)](https://datatracker.ietf.org/doc/draft-ietf-dnsop-ns-revalidation/) feature implementation. This featured caused increase in complexity and number of requests to name servers increasing load on the resolver. It also caused few domain names to fail to resolve when the zone's child NS records were different from parent NS records which would have otherwise resolved correctly. It did not add any benefit for the resolver operator but created operational issues. Read the discussion thread [here](https://mailarchive.ietf.org/arch/msg/dnsop/s8KBhilK4bCrmSBRMyKaxll02lk/) to understand more about this decision.
- Added `IDnsApplicationPreference` interface to allow applications to be ordered based on their user configured app preference value.
- Advanced Forwarding App, DNS64 App, NXDOMAIN App, Split Horizon App and Zone Alias App: Updated these apps to implement app preference feature in config with new `appPreference` option.
- Log Exporter App: Updated app to allow configuring HTTP headers without validation to allow adding non-standard header values.
- Updated the DNS admin panel web app to use relative paths to allow using the DNS admin panel with any URL path on a reverse proxy.
- Multiple other minor bug fixes and improvements.

## Version 13.4.3
Release Date: 23 February 2025

- Fixed issue of high memory usage when "Last Year" option is used on Dashboard.
- Fixed multiple issues of DNSSEC validation failures for certain domain names when using forwarders.
- Multiple other minor bug fixes and improvements.

## Version 13.4.2
Release Date: 15 February 2025

- Fixed issue of unhandled CD flag condition when DO flag is unset in requests for a specific case.
- Block Page App: Fixed issue with Kestrel local addresses that caused failure to bind on Linux systems.
- Query Logs (MySQL) App: Updated app to use MySqlConnector driver which allows the app to work with MariaDB too.
- Query Logs (SQL Server) App: Fixed issue with bulk insert due to limit on parameters per query. Fixed issue with qtype filtering.
- Multiple other minor bug fixes and improvements.

## Version 13.4.1
Release Date: 2 February 2025

- Fixed issue of unhandled CD flag condition when DO flag is unset in requests.
- Block Page App: Updated app to show blocking info details on the block page.
- Query Logs (MySQL) App: Updated app to add server domain to db logs to allow using same db with multiple instances.
- Query Logs (SQL Server) App: Updated app to add server domain to db logs to allow using same db with multiple instances.
- Multiple other minor bug fixes and improvements.

## Version 13.4
Release Date: 26 January 2025

- Added implementation to detect spoofed DNS responses over UDP transport and switch to TCP transport to mitigate cache poisoning attempts. This is a mitigation for RebirthDay Attack [CVE-2024-56089] reported by Xiang Li, AOSP Lab of Nankai University.
- Added support for reading minute stats for given custom date time range (for max 2 hours range difference).
- Added HTTP API and GUI option to export Query Logs as a CSV file.
- Drop Requests App: Fixed bug that caused matching all requests when unknown record type was configured.
- Log Exported App: Added new app that supports exporting query logs to file, HTTP, and Syslog sinks. The app was designed and implemented by [Zafer Balkan](https://github.com/zbalkan).
- Query Logs (SQL Server) App: Added new app that supports logging query logs to Microsoft SQL Server.
- Query Logs (MySQL) App: Added new app that supports logging query logs to MySQL database server.
- Multiple other minor bug fixes and improvements.

## Version 13.3
Release Date: 21 December 2024

- Implemented resolver queue mechanism to avoid request timeout error issues caused when too many outbound resolutions were being processed concurrently for large deployments. A new Max Concurrent Resolutions option is now available in Settings > General section to configure the maximum number of concurrent async resolutions per CPU core.
- Added new Minimum SOA Refresh and Minimum SOA Retry options in Settings > General section to override any Secondary, Stub, Secondary Forwarder, or Secondary Catalog zone SOA values that are smaller than these configured minimum values.
- Added feature to include Subject Alternative Name (SAN) entry for DNS admin web service local unicast addresses in the self-signed certificate.
- Fixed bug in NSEC3 non-existent proof generation implementation that caused Denial of Service (DoS) for all DNS protocol services when certain primary and secondary zones are DNSSEC signed using NSEC3.
- Fixed issue of unhandled exception that caused Denial of Service (DoS) for DNS-over-QUIC service [CVE-2024-56946] reported by Michael Wedl, St. Poelten University of Applied Sciences.
- Fixed bug in reloading SSL/TLS certificate for DNS admin web service and DNS-over-HTTPS service.
- Fixed issue with Catalog zone SOA request that caused zone transfer to fail with BIND.
- Query Logs (Sqlite): Updated the app to support logging response RTT value.
- Multiple other minor bug fixes and improvements.

## Version 13.2.2
Release Date: 2 December 2024

- Fixed bug that caused DNS response to include bogus records even when Checking Disabled (CD) is set to false in request.

## Version 13.2.1
Release Date: 30 November 2024

- Updated server to allow DNS-over-HTTPS service to read X-Real-IP header from reverse proxy that are allowed by the ACL.
- Fixed issue with HTTP/2 on OS versions older than Windows 10 that caused failure to enable HTTPS for admin web service and DNS-over-HTTPS service.
- Fixed issue with handling connection abort condition for DNS-over-QUIC.
- Fixed issue with handling a wildcard query case for ENT subdomain names in local zones.
- Fixed issue with Forwarding where CNAME was not being resolved separately when upstream returned SOA in response authority section.
- Fixed issue in DNS Application assembly loading implementation that caused issue loading dependencies for some scenarios.
- Multiple other minor bug fixes and improvements.

## Version 13.2
Release Date: 16 November 2024

- Added new option in Settings to allow configuring reverse proxy network ACL to use with DNS-over-UDP-PROXY, DNS-over-TCP-PROXY, AND DNS-over-HTTP optional protocols.
- Fixed issue in DNS-over-QUIC protocol client which caused the forwarding to fail to work with timeout error after a while in some cases.

## Version 13.1.1
Release Date: 9 November 2024

- Fixed issue with HTTP/3 protocol not working for both admin web service and DNS-over-HTTPS/3 service caused due to changes in how Kestrel web server uses application protocol option.
- Updated DNS-over-HTTPS client implementation such that it will support HTTP/2 and HTTP/1.1 protocols with `https` scheme and only support HTTP/3 protocol with `h3` scheme with no protocol fallback.
- Fixed issue in DNS-over-TCP and DNS-over-TLS client caused due to some platforms not supporting TCP keep alive socket options.
- Updated recursive resolver implementation to always attempt to resolve AAAA for name server with missing IPv6 glue record to allow resolution over IPv6 only networks.
- Filter AAAA App: added new option to configuring default TTL value.
- DNS Rebinding Protection App: added new option to configure bypass networks.
- Multiple other minor bug fixes and improvements.

## Version 13.1
Release Date: 19 October 2024

- Added new option to add Secondary Root Zone directly.
- Added new notify option for Catalog zones to specify separate name servers only for Catalog zone updates.
- Added option to configure blocking answer's TTL value in Settings.
- Added option to make the `X-Real-IP` header customizable for admin web service and for DNS-over-HTTP optional protocol.
- Multiple other minor bug fixes and improvements.
- Filter AAAA App: updated app to support option to explicitly specify filter domain names.

## Version 13.0.2
Release Date: 28 September 2024

- Fixed issue with DNS-over-TLS and DNS-over-TCP protocols that would cause the underlying connection to close if original request gets canceled.
- Multiple other minor bug fixes and improvements.

## Version 13.0.1
Release Date: 23 September 2024

- Fixed issue in using proxy with forwarders that caused failure to use DNS-over-TOR with Cloudflare's hidden service.

## Version 13.0
Release Date: 22 September 2024

- Implemented Catalog Zones [RFC 9432](https://datatracker.ietf.org/doc/rfc9432/) support to allow automatic DNS zone provisioning to one or more secondary name servers. The implementation supports Primary, Stub, and Conditional Forwarder zones for automatic provisioning of their respective secondary zones.
- Added new Secondary Forwarder zone support to allow configuring secondaries for Conditional Forwarder zones. Conditional Forwarder zones now support zone transfer and notify features to support secondaries and will now contain a dummy SOA record.
- Added Query Access feature to allow configuring access to each individual zone. This allows limiting query access to only clients on configured networks even when the DNS Server is publicly accessible.
- Added support for specifying Expiry TTL for records in zones that will cause the DNS Server to automatically delete the records when Expiry TTL elapses.
- Added support for concurrency in recursive resolver to allow querying more than one name server at a time to improve resolution performance.
- Added support for latency based name server selection algorithm that works with concurrency feature for both recursive resolution and forwarders to significantly improve resolution performance.
- Implemented priority support for Conditional Forwarder FWD records which can be used to prioritize some forwarders and have a low priority "This Server" FWD record to perform recursive resolution if needed.
- Implemented ZONEMD [RFC 8976](https://datatracker.ietf.org/doc/rfc8976/) validation support for Secondary zones which is intended to be used with local secondary ROOT zone. This feature allows validating complete zone after each zone transfer.
- Added support for Responsible Person (RP) record [RFC 1183](https://www.rfc-editor.org/rfc/rfc1183).
- Added option to enable/disable Concurrent Forwarding feature so as to allow having sequential forwarding support.
- The DNS Server now supports Network Access Control Lists for Recursion, Zone Transfer, and Dynamic Updates in both the GUI and HTTP API.
- Changed the Unsupported NSEC3 Iteration Value implementation due to bug in previous implementation that caused failure to validate in some cases.
- Improved brute force protection implementation for admin web service for IPv6 networks.
- Added feature to write client subnet query rate limiting events to log file to allow tracking.
- This major update has some breaking changes with SOA record and Zone Options related HTTP API calls. Some options in SOA record have been moved to Zone Options in both HTTP API and GUI. There are few breaking changes with the DNS Client library code too so any custom DNS App should be tested before upgrading the DNS Server.
- Multiple other minor bug fixes and improvements.

## Version 12.2.1
Release Date: 15 June 2024

- Fixed issue in DHCP server that caused failure to allocate lease due to hash code mismatch.
- Fixed issue that may create empty zone files after the zone was deleted.

## Version 12.2
Release Date: 15 June 2024

- Added support for NAPTR record type.
- Added Default Responsible Person option in Settings to use when adding Primary Zones.
- Updated Serve Stale implementation to allow configuring Answer TTL, Reset TTL, and Max Wait Time options in Settings.
- Updated SVCB/HTTPS record implementation to add support for automatic IP address hints.
- Updated TXT record implementation to allow preserving the character-strings for a given TXT record to allow support for [RFC 6763](https://www.rfc-editor.org/rfc/rfc6763).
- Updated DNS Server's System Tray app on Windows with new context menu option to allow configuring Automatic Firewall entry feature.
- Fixed issue with NSEC proof validation for wildcard empty non-terminal (ENT) cases.
- Fixed issue with QNAME minimization implementation caused when NSEC3 unsupported iteration count event is encountered while resolving.
- Added support for .p12 certificate file extension along with existing .pfx extension.
- Filter AAAA App: Added new app that allows filtering AAAA records by returning NO DATA response when A records for the same domain name are available. This allows clients with dual-stack (IPv4 and IPv6) Internet connection to prefer using IPv4 to connect to websites and use IPv6 only when a website has no IPv4 support.
- Query Logs (Sqlite) App: Fixed issue of failing to load the app on Alpine Linux.
- Multiple other minor bug fixes and improvements.

## Version 12.1
Release Date: 16 March 2024

- Fixed [Key Trap](https://www.athene-center.de/en/keytrap) [vulnerability](https://www.athene-center.de/fileadmin/content/PDF/Technical_Report_KeyTrap.pdf) [CVE-2023-50387] that affected DNSSEC validation which can cause DoS affecting the DNS Server's ability to resolve domain names. The mitigations will allow the DNS Server to work even with high CPU usage.
  - The mitigation now allows max 4 DNSKEY records with key tag collision.
  - Limits cryptographic failures to max 16. 
  - More that 8 RRSIG validation attempts per response will cause suspension of the task with max 16 suspensions allowed before the validation stops for the response.
- Fixed vulnerability in NSEC3 closest encloser proof [CVE-2023-50868] that affected DNSSEC validation which can cause DoS affecting the DNS Server's ability to resolve domain names. The mitigations will allow the DNS Server to work even with high CPU usage.
  - More than 8 NSEC3 hash calculation per response will cause suspension of the task.
  - After 16 suspensions the the validation will stop for the response.
- Fixed [Non-Responsive Delegation Attack](https://www.usenix.org/system/files/sec23fall-prepub-309-afek.pdf) (NRDelegation Attack) vulnerability [CVE-2022-3204].
- Fixed [NXNSAttack](https://arxiv.org/abs/2005.09107) vulnerability [CVE-2020-12662].
- Implemented NSEC3 iteration limit of 100. NSEC3 with iterations of more than 100 will be treated as No Proof.
- Added EDNS Client Subnet (ECS) override feature to allow the DNS Server to use the provided network subnet with ECS for all outbound requests.
- Secondary zones now allow configuring Dynamic Updates permissions in Zone Options.
- Import zone feature now supports option to overwrite SOA serial from SOA record being imported.
- DNS Client now supports EDNS Client Subnet (ECS) option to allow testing ECS related issues with ease.
- DNS cache entries now show request meta data to allow knowing the name server that provided the record data.
- DHCP Scope now supports option to ignore Client Identifier option in requests to allow using the client's hardware address for lease management.
- Advanced Blocking App: Updated implementation to support using domain names for local endpoint group map feature which will work with requests over DoT, DoH and DoQ protocols.
- Advanced Forwarding App: Updated AdGuard upstream implementation to support multiple forwarders.
- Geo Continent App: Updated app to support MaxMind ISP/ASN database to allow returning optimal ECS scope prefix in response.
- Geo Country App: Updated app to support MaxMind ISP/ASN database to allow returning optimal ECS scope prefix in response.
- Geo Distance App: Updated app to support MaxMind ISP/ASN database to allow returning optimal ECS scope prefix in response.
- Fixed bug in authoritative zone wildcard matching.
- Multiple other minor bug fixes and improvements.

## Version 12.0.1
Release Date: 8 February 2024

- Fixed bug in authoritative zone wildcard matching for empty non-terminal (ENT) records.
- Fixed other minor issues.

## Version 12.0
Release Date: 4 February 2024

- Upgraded codebase to use .NET 8 runtime. If you had manually installed the DNS Server or .NET 7 Runtime earlier then you must install .NET 8 Runtime manually before upgrading the DNS Server.
- Fixed pulsing DoS vulnerability [CVE-2024-33655] reported by Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/) by updating the default configured values for the DNS Server which mitigates the impact.
- Added "Dropped" request stats on the Dashboard and main chart which shows the number of request that were dropped by the DNS Server due to rate limiting or by the Drop Requests app.
- Added transport protocol types chart on Dashboard which shows the protocol stats for the requests received by the DNS Server.
- Added feature to specify one or more source addresses for outbound DNS requests when the server is connected to two or more networks.
- Added option to allow IP address or networks to allow accepting Notify requests from to avoid having to configure the same individually for each zone.
- Added option to specify QPM bypass list to allow IP addresses or networks to bypass rate limiting restrictions.
- Added feature to enable In-Memory stats such that only Last Hour data to be available on Dashboard and no stats data will be stored on disk.
- Updated DNS-over-HTTPS implementation to work over SOCKS5 proxy when using HTTP/3 protocol (URL with `h3` scheme).
- Added support for automatic initializing of DNS Server root servers list with priming queries [RFC 8109](https://datatracker.ietf.org/doc/rfc8109/).
- Conditional Forwarder Zones now support Dynamic Updates [RFC 2136](https://datatracker.ietf.org/doc/rfc2136/).
- DNS Rebinding Protection App: A new app available that protects from DNS rebinding attacks using configured private domains and networks.
- NX Domain Override App: New app to allow overriding NX Domain response to with custom A/AAAA record response for configured domain names.
- Block Page App: Updated the app to use Kestrel web server and allow configuring multiple web servers that listen on different IP addresses.
- Multiple other minor bug fixes and improvements.

## Version 11.5.3
Release Date: 7 November 2023

- Fixed bug in authoritative zone wildcard matching which caused NXDOMAIN response for some subdomain name requests.

## Version 11.5.2
Release Date: 31 October 2023

- Fixed bug in zone Dynamic Updates allowed IP/network addresses that caused failure to match with request IP address.

## Version 11.5.1
Release Date: 30 October 2023

- Fixed bug in validation code for DNS-over-TLS library that caused failure when trying to use the protocol.
- Advanced Blocking App: Fixed minor issue in initializing the app.

## Version 11.5
Release Date: 29 October 2023

- Added support to import and export zones in standard RFC 1035 text file format.
- Added feature to clone an existing zone with all its records and zone options.
- Added DS Info viewer that shows all the info needed for updating DS records for the signed primary zone in a single view.
- Added option to configure IP/network addresses that are allowed to perform zone transfer for all local zones without any TSIG authentication.
- Added option to configure IP/network addresses that are allowed to bypass domain name blocking.
- Added option to independently configure HTTP/3 protocol for DNS web service.
- Added option to ignore resolver error logs so as to limit the log file size.
- Added zone last modified date time stamp.
- Added check for DNS web service local end point changes to ensure that the new end points are available to bind before saving settings to avoid locking out of the DNS admin web panel.
- Updated DNS web service to revert to old local end point if new end point fails to bind.
- Zone Options for zone transfer name servers and dynamic updates IP addresses can now accept network addresses too.
- Updated conditional forwarder zones to allow bypassing default proxy configured in the DNS Server Settings.
- Added new `IDnsRequestBlockingHandler` interface for DNS apps to allow the same level of blocking support as that of the DNS Server's built-in blocking feature.
- Advanced Blocking App: Updated app to implement the new `IDnsRequestBlockingHandler` interface. Added support to allow selecting group based on the DNS Server local end point on which the request was received.
- Split Horizon App: Address translation now supports using network addresses too for external to internal translation.
- Default Records App: New app added that allows setting one or more default records for configured local zones.
- Multiple other minor bug fixes and improvements.

## Version 11.4.1
Release Date: 13 August 2023

- Fixed issue that caused backup operations to fail.
- Fixed minor issue with incremental zone transfer which caused empty nodes to not get removed from secondary zones.

## Version 11.4
Release Date: 12 August 2023

- Added support for DNS over [PROXY protocol](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) version 1 and 2 for both UDP and TCP transports. This feature allows using a load balancer or reverse proxy in front of the DNS Server such that the client's IP address information is passed to the DNS Server. This can also be used to provide DNS-over-TLS service with a TLS terminating reverse proxy that forwards request to TCP-PROXY protocol port.
- Updated TLS certificate implementation to allow the TLS handshake to always send the certificate chain.
- Updated Backup and Restore feature to include Web Service and Optional Protocols certificate files when they exist within the DNS Server's config folder.
- Added DNS Server uptime info in the About section.
- Multiple other minor bug fixes and improvements.

## Version 11.3
Release Date: 2 July 2023

- Added support for URI record type ([RFC 7553](https://www.rfc-editor.org/rfc/rfc7553.html)).
- Added support for `dohpath` parameter for SVCB record type ([draft-ietf-add-svcb-dns](https://datatracker.ietf.org/doc/draft-ietf-add-svcb-dns/)).
- Added support for configuring generic parameter for SVCB & HTTPS record types in UI.
- Added feature to allow converting zone from one type to another to help scenarios like upgrade of a secondary zone to primary zone when decommissioning the existing primary zone.
- Updated primary zone NOTIFY implementation to keep rechecking when notify fails and explicitly show notify failed status against the specific name servers in the UI.
- Zone Alias App: Added new DNS app that allows creating aliases for any zone (internal or external) such that they all return the same set of records.
- Multiple other minor bug fixes and improvements.

## Version 11.2
Release Date: 27 May 2023

- Added support for SVCB and HTTPS record types ([draft-ietf-dnsop-svcb-https](https://datatracker.ietf.org/doc/draft-ietf-dnsop-svcb-https/)).
- Added support for managing unknown (unsupported) record types.
- Auto PTR App: Added new DNS app that can generate automatic responses for PTR requests.
- Weighted Round Robin App: Added new app to allow returning responses with weighted round robin load balancing.
- Multiple other minor bug fixes and improvements.

## Version 11.1.1
Release Date: 1 May 2023

- Fixed issue of UDP socket pool exhaustion on Windows platform causing all outbound UDP requests to fail.

## Version 11.1
Release Date: 29 April 2023

- Added support for Internationalized Domain Names (IDN).
- Added support for primary zone's SOA record to have serial number date scheme.
- Fixed issue reported by Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/) that made the DNS Server vulnerable to cache poisoning on Windows platform due to non-random UDP ports for outbound requests.
- Fixed bug in validation check during refreshing RRSIG records when primary zone is signed with NSEC3.
- Fixed bug in NSEC3 record's types field which caused missing of RRSIG type entry.
- Fixed issue to allow Kestrel web server to serve unknown file types to allow certbot webroot HTTP challenge to work as expected.
- Advanced Forwarding App: Fixed the implementation to correctly store cached records per client subnet defined in the app's config. Added wildcard domain support.
- Multiple other minor bug fixes and improvements.

## Version 11.0.3
Release Date: 11 March 2023

- Fixed DoS vulnerability reported by Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/) that an attacker can use to send bad-formatted UDP packet to cause the outbound requests to fail to resolve due to insufficient validation.
- Fixed issue reported by Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/) that caused conditional forwarder to not honoring RD flag in requests.
- Fixed issue reported by Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/) that made amplification attacks more effective due to max 4096 bytes limit for responses.
- Fixed issue in loading of Allowed and Blocked zones that resulted in loading to take too much time caused due to indexing feature added in last update for authoritative zones.
- Updated DNS Server UDP response processing to remove glue records for MX responses and try again to send it instead of sending a truncated response that was causing issue with some old mail servers that did not perform follow up request over TCP.
- Block Page App: Updated the app to support option to disable the web server without requiring to uninstall the app to stop the web server.
- Multiple other minor bug fixes and improvements.

## Version 11.0.2
Release Date: 26 February 2023

- Fixed issue with DNS-over-HTTP private IP check that was causing 403 response when using with reverse proxy.
- Fixed issue with zone record pagination caused when zone has no records.

## Version 11.0.1
Release Date: 25 February 2023

- Changed allow list implementation to handle them separately and show allow list count on Dashboard.
- Fixed bug in conditional forwarder zone for root zone that caused the DNS Server to return RCODE=ServerFailure.
- Fixed issues with DNS Server's App request query handling sequence to fix issues with Advanced Forwarding app.
- Fixed issues with block list parser to detect in-line comments.
- Fixed issue of "URI too long" in save DHCP scope action.
- Updated Linux install script to use new install path in `/opt` and new config path `/etc/dns` for new installations.
- Updated Docker container to use new volume path `/etc/dns` for config.
- Updated Docker container to correctly handle container stop event to gracefully shutdown the DNS Server.
- Updated Docker container to include `libmsquic` to allow QUIC support.
- Multiple other minor bug fixes and improvements.

## Version 11.0
Release Date: 18 February 2023

- Added support for DNS-over-QUIC (DoQ) [RFC 9250](https://www.ietf.org/rfc/rfc9250.html). This allows you to run DoQ service as well as use it with Forwarders. DoQ implementation supports running over SOCKS5 proxy server that provides UDP transport.
- Added support for Zone Transfer over QUIC (XFR-over-QUIC) [RFC 9250](https://www.ietf.org/rfc/rfc9250.html).
- Updated DNS-over-HTTPS protocol implementation to support HTTP/2 and HTTP/3. DNS-over-HTTP/3 can be forced by using `h3` instead of `https` scheme for the URL.
- Updated DNS Server's web service backend to use Kestrel web server and thus the DNS Server now requires ASP.NET Core Runtime to be installed. With this change, the web service now supports both HTTP/2 and HTTP/3 protocols. If you are using HTTP API, it is recommended to test your code/script with the new release.
- Added support to save DNS cache data to disk on server shutdown and to reload it at startup.
- Updated DNS Server domain name blocking feature to support Extended DNS Errors to show report on the blocked domain name. With this support added, the DNS Client tab on the web panel will show blocking report for any blocked domain name.
- Updated DNS Server domain name blocking feature to support wildcard block lists file format and Adblock Plus file format.
- Updated DNS Server to detect when an upstream server blocks a domain name to reflect it in dashboard stats and query logs. It will now detect blocking signal from Quad9 and show Extended DNS Error for it.
- Updated web panel Zones GUI to support pagination.
- Advanced Blocking App: Updated DNS app to support wildcard block lists file format. Updated the app to disable CNAME cloaking when a domain name is allowed in config. Implemented Extended DNS Errors support to show blocked domain report.
- Advanced Forwarding App: Added new DNS app to support bulk conditional forwarder.
- DNS Block List App: Added new DNS app to allow running your own DNSBL or RBL block lists [RFC 5782](https://www.rfc-editor.org/rfc/rfc5782).
- Added support for TFTP Server Address DHCP option (150).
- Added support for Generic DHCP option to allow configuring option currently not supported by the DHCP server.
- Removed support for non-standard DNS-over-HTTPS (JSON) protocol.
- Removed Newtonsoft.Json dependency from the DNS Server and all DNS apps.
- Multiple other minor bug fixes and improvements.

## Version 10.0.1
Release Date: 4 December 2022

- Fixed multiple issues in EDNS Client Subnet (ECS) implementation.
- Fixed issue with serialization when saving permission data when there are more than 255 zones.
- Failover App: Fixed issue with idle connection for HTTP/HTTPS probes.
- QueryLogs (Sqlite) App: Fixes issue of open db file on windows installations.
- Multiple other minor bug fixes and improvements.

## Version 10.0
Release Date: 26 November 2022

- Added Dynamic Updates [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136) security policy support to allow updates only for specified domain names and record types. This adds breaking changes to the zone options HTTP API calls. Any implementation that uses the zone options API must test with new update before deploying to production.
- Added support for DANE TLSA [RFC 6698](https://datatracker.ietf.org/doc/html/rfc6698) record type. This includes support for automatically generating the hash values using certificates in PEM format.
- Added support for SSHFP [RFC 4255](https://www.rfc-editor.org/rfc/rfc4255.html) record type.
- Implemented EDNS Client Subnet (ECS) [RFC 7871](https://datatracker.ietf.org/doc/html/rfc7871) support for recursive resolution and forwarding.
- Updated HTTP API to accept date time in ISO 8601 format for dashboard and query logs API calls. Any implementation that uses these API must test with new update before deploying to production.
- Upgraded codebase to .NET 7 runtime. If you had manually installed the DNS Server or .NET 6 Runtime earlier then you must install .NET 7 Runtime manually before upgrading the DNS Server.
- Fixed self-CNAME vulnerability [CVE-2022-48256] reported by Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/) which caused the DNS Server to follow CNAME in loop causing the answer to contain couple of hundred records before the loop limit was hit.
- Updated DNS Apps framework with `IDnsPostProcessor` interface to allow manipulating outbound responses by DNS apps.
- NO DATA App: Added new app to allow returning NO DATA response in Conditional Forwarder zones to allow overriding existing records from the forwarder for specified record types.
- DNS64 App: Added new app to support DNS64 function [RFC 6147](https://www.rfc-editor.org/rfc/rfc6147) for use by IPv6 only clients.
- Advanced Blocking App: Upgraded the app code to use less memory when same block lists are used across multiple groups.
- Geo Continent App, Geo Country App, and Geo Distance App: Upgraded the apps to support EDNS Client Subnet (ECS) [RFC 7871](https://datatracker.ietf.org/doc/html/rfc7871).
- Split Horizon App: Upgraded the app to add 1:1 IP address translation support. This allows mapping external/public IP address to internal/private IP address such that clients in private network can access local services using internal/private IP addresses.
- Added support for Domain Search DHCP option [RFC 3397](https://www.rfc-editor.org/rfc/rfc3397)
- Added support for CAPWAP Access Controller DHCP option [RFC 5417](https://www.rfc-editor.org/rfc/rfc5417.html).
- Added DHCP Scope option to disable DNS updates.
- Added DHCP Scope option to support domain name for NTP option such that the DHCP server will automatically resolve the domain names and use the resolved IP addresses with the NTP option.
- Multiple other minor bug fixes and improvements.

## Version 9.1
Release Date: 9 October 2022

- Added Dynamic Updates [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136) support. This allows using tools like `nsupdate`, allow 3rd party DHCP servers to update DNS records, and use certbot [certbot-dns-rfc2136](https://certbot-dns-rfc2136.readthedocs.io/en/stable/) plugin for automatic TLS certificate renewal using DNS challenge.
- Updated dashboard to display main chart using client's local time instead of server's local time.
- Fixed bug that caused error while adding new secondary zone.
- Multiple other minor bug fixes and improvements.

## Version 9.0
Release Date: 24 September 2022

- Added multi-user role based access support. This allows creating multiple users and multiple role based groups with permission based access controls.
- Added support for non-expiring API tokens to use with automation scripts.
- Added zone level permissions support to allow access only to selected users or group members.
- User profile options available to update each user's session timeout values.
- HTTP API: The API has been updated extensively keeping backward compatibility. Any implementation that uses the API must test with new update before deploying to production. Using the non-expiring API tokens is recommended.
- Updated Conditional Forwarder zones to support APP records to allow using DNS Apps in these zones.
- Option added in Settings to stop block list URL automatic update.
- DNS Apps: There is a breaking change in the IDnsAppRecordRequestHandler.ProcessRequestAsync() method. If you have any custom DNS app deployed, you need to recompile it with the latest DnsServerCore.ApplicationCommon.dll before updating to this new release.
- DNS Apps now support automatic updates. The DNS Server will check for updates and install them automatically every 24 hours.
- Split Horizon App: Added feature to configure collection of networks to use with APP record data.
- Wild IP App: Added new DNS App that returns a response A or AAAA queries with the IP address that is embedded in the subdomain name of the query. This app works similar to [sslip.io](https://sslip.io/).
- Fixed minor issues in DNSSEC validation for DNAME responses and for wildcard NO DATA responses.
- DHCP scopes now support updating DNS records in both Primary and Forwarder zones.
- DHCP scopes now support blocking dynamic allocations to devices with locally administered MAC address.
- Multiple other minor bug fixes and improvements.

## Version 8.1.4
Release Date: 3 July 2022
- Fixed issue in recursive resolution that caused DNSSEC validation to fail in cases when the name server responds with out-of-bailiwick records.
- Updated recursive resolver to update addresses async for all NS records to improve performance.
- Multiple other minor bug fixes and improvements.

## Version 8.1.3
Release Date: 11 June 2022
- Added OpenDNS DoH end points to DNS Client and Forwarder quick select list.
- Fixed issue of missing digest type support check that could cause exception to be thrown causing failure to resolve the DNSSEC signed domain name.

## Version 8.1.2
Release Date: 28 May 2022
- Fixed issue in Primary zone add and update record IXFR history when RRSet TTL was updated.
- Fixed issue in DNSSEC validation for MX and SRV records caused due to incorrect comparison of record data.
- Fixed issue in SOA record responsible person parameter parsing.
- This release updates delete and update record API calls for MX and SRV records which may cause issues in 3rd party clients if they are not updated before deploying this new version. It is recommended to check the API documentation for changes before deploying this new release.
- Multiple other minor bug fixes and improvements.

## Version 8.1.1
Release Date: 21 May 2022
- Added Sync Failed and Notify Failed zone status to indicate issues between primary and secondary zones synchronization.
- Added more options in zone options to configure zone transfer and notify settings.
- Fixed DNSSEC signed primary zone key rollover timing issues as per [RFC 7583](https://datatracker.ietf.org/doc/html/rfc7583).
- Fixed issue in recursive resolver by adding zone cut validation for glue records.
- Multiple other minor bug fixes and improvements.

## Version 8.1
Release Date: 8 May 2022
- Fixed two ghost domain issues, CVE-2022-30257 (V1) and CVE-2022-30258 (V2), reported by Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/). Issue V1 was fixed with some implementation changes in the NS Revalidation feature and thus having this option enabled in Settings will mitigate the issue. Issue V2 was fixed by implementing additional validation checks when caching NS records.
- Added maximum cache entires option to limit memory usage by removing least recently used data from cache.
- Implemented NS revalidation to revalidate parent side NS records when their TTL expires.
- Updated the web console to store session token in local storage to prevent logging out on page reload.
- DropRequests App: Added support to block entire zone for the configured QNAME.
- Fixed bug in primary zone IXFR history caused due to missing SOA serial check.
- Fixed issues with wrong IXFR history entries for DNSKEY records in primary zone.
- Multiple other minor bug fixes and improvements.

## Version 8.0.2
Release Date: 3 April 2022
- Fixed bug in Conditional Forwarder zones that would cause ServerFailure responses for some queries.
- Fixed issue of setting minimum TTL value to NSEC & NSEC3 records in Primary signed zones when SOA value is changed.
- Fixed issue in parsing DNS-over-HTTPS JSON response for NSEC and NSEC3 records.
- Multiple other minor bug fixes and improvements.

## Version 8.0.1
Release Date: 29 March 2022
- Fixed bug in Conditional Forwarder zones due to zone cut validation causing negative cache entry for CNAME responses which resulted in partial responses.
- Fixed issue with handling FormatError response that were missing question section for EDNS requests.
- Fixed minor issue with DNSSEC validation for unsigned zone when forwarder returns empty NXDOMAIN responses.
- Fixed issue with NODATA response handling for ANAME records.
- Fixed issue with record comment validation causing error when saving SOA records in zones.
- Multiple other minor bug fixes and improvements.

## Version 8.0
Release Date: 26 March 2022
- Added EDNS support [RFC 6891](https://datatracker.ietf.org/doc/html/rfc6891).
- Added Extended DNS Errors [RFC 8914](https://datatracker.ietf.org/doc/html/rfc8914).
- Added DNSSEC validation support with RSA & ECDSA algorithms for recursive resolver, forwarders, and conditional forwarders.
- Added DNSSEC support for all supported DNS transport protocols including encrypted DNS protocols (DoT, DoH, DoH JSON).
- Added DNSSEC zone signing support with RSA & ECDSA algorithms.
- Updated DNS Client to support DNSSEC validation.
- Updated proprietary FWD record which is used with Conditional Forwarder Zones for DNSSEC validation and HTTP/SOCKS5 proxy support.
- Updated Conditional Forwarder Zones to support working as a static stub zone to force a domain name to resolve via given name servers using NS records.
- Upgraded codebase to .NET 6 runtime.
- Query Logs App: Added wildcard search support for domain names.
- Fixed multiple issues with DHCP server.
- This release updates many API calls which may cause issues in 3rd party clients if they are not updated before deploying this new version. It is recommended to check the API documentation for changes before deploying this new release.
- Multiple other minor bug fixes and improvements.

## Version 7.1
Release Date: 23 October 2021
- Added option in settings to automatically configure a self signed certificate for DNS web service.
- Fixed cache poisoning vulnerability [CVE-2021-43105] reported by Xiang Li, [Network and Information Security Lab, Tsinghua University](https://netsec.ccert.edu.cn/) and Qifan Zhang, [Data-driven Security and Privacy (DSP) Lab, University of California, Irvine](https://faculty.sites.uci.edu/zhouli/research/) when a conditional forwarder zone uses a forwarder controlled by an attacker or uses UDP/TCP forwarder protocol that the attacker can perform MiTM.
- Block Page App: Added support for automatic self signed certificate to allow showing block page for HTTPS websites.
- Drop Requests App: Added option to drop malformed DNS requests.
- Query Logs App: Fixed minor issue which caused the query logs request to fail when a domain with invalid character was logged in the database.
- Advanced Blocking App: Fixed bug in loading regex block list which caused the app to not block the domain names as expected.
- Added logging in DNS Server to know why a zone transfer request was refused by the server.
- Added more environment variables for use with Docker to initialize the DNS Server config. Read the [environment variable documentation](https://github.com/TechnitiumSoftware/DnsServer/blob/master/DockerEnvironmentVariables.md) for complete details.
- Multiple other minor bug fixes and improvements.

## Version 7.0
Release Date: 2 October 2021
- DNS Apps design updated to allow apps to act as authoritative zones, drop requests, and log queries in addition to the existing APP records in authoritative zones.
- This release is a major update for DNS Apps design and thus any previously installed apps will fail to load after the update. A manual update is required to install the latest app update from the DNS App Store for these apps to work with this new release.
- Advanced Blocking App: This new app allows blocking domain names based on IP address or subnet of the clients by creating groups. It also supports blocking using regex and also supports loading blocked domains from Adblock format lists.
- Block Page App: This new app runs a built-in web server to allow serving a block page to clients when a domain name is blocked.
- Drop Requests App: This new app allows dropping requests that match the blocked questions in the config allowing to block DNS amplification attacks that use specific domain name and query types.
- NX Domain App: This new app allows blocking domain names with a NXDOMAIN response.
- Query Logs (Sqlite): This new app allows logging all queries that the DNS Server receives into a Sqlite database. The DNS Server web panel adds an Query Logs option to allow querying the app for logged data.
- Failover App: Implemented under maintenance feature to indicate if an address is taken down for maintenance.
- Added Ping check option in DHCP scopes to allow detecting if an IP address is already in use before leasing it.
- Added option to allow removing an allocated DHCP lease.
- This release updates many API calls which may cause issues in 3rd party clients if they are not updated before deploying this new version. It is recommended to check the API documentation for changes before deploying this new release.
- Multiple other minor bug fixes and improvements.

## Version 6.4.1
Release Date: 21 August 2021
- Implemented Delegation Revalidation [draft-ietf-dnsop-ns-revalidation-01](https://datatracker.ietf.org/doc/draft-ietf-dnsop-ns-revalidation/) in recursive resolver.
- Fixed issues with DNS-over-TLS due to "dot" ALPN causing SSL handshake to fail when using NextDNS as forwarder.
- Fixed issues in counting total unique clients in dashboard stats. The future data for total clients will be displayed correctly however the bad data since last release can be fixed by deleting '/etc/dns/config/stats/202108*.dstat' files manually.
- Updated allowed list URL implementation to check for domains zone wise so that subdomain names from blocked list URLs too are allowed.
- Updated DNS Failover App to v1.4 to fix implementation issues.
- Multiple other minor bug fixes and improvements.

## Version 6.4
Release Date: 14 August 2021
- Added DNAME record [RFC 6672](https://datatracker.ietf.org/doc/html/rfc6672) support.
- Implemented incremental zone transfer (IXFR) [RFC 1995](https://datatracker.ietf.org/doc/html/rfc1995) support.
- Implemented secret key transaction authentication (TSIG) [RFC 8945](https://datatracker.ietf.org/doc/html/rfc8945) support for zone transfers.
- Implemented zone transfer over TLS (XFR-over-TLS) [draft-ietf-dprive-xfr-over-tls](https://datatracker.ietf.org/doc/draft-ietf-dprive-xfr-over-tls/) support.
- Added advance options in Settings to control TTL values in Cache.
- Added Resync button to force resync Secondary and Stub zones.
- Updated query rate limiting feature to allow limiting requests from the client's subnet.
- Updated SplitHorizon App to support configuring CIDR networks.
- Updated Failover App to fix multiple issues and added feature to auto generate health check URL from APP record domain name or specify the URL in the APP record data.
- Fixed issues with log file rolling when using local time.
- Multiple other minor bug fixes and improvements.
- Updated few API calls which may cause issues in 3rd party clients if they are not updated before deploying this new version.

## Version 6.3
Release Date: 6 June 2021

- Added Failover App in DNS App Store.
- Added comments option to DNS records in Zones.
- Added Recursion ACL support to specify allowed and denied networks that can perform recursion.
- Added Zone Options feature to allow configuring Zone Transfer and Notify settings per zone.
- Added Queries Per Minute (QPM) Limit feature to limit the number of queries being made by an IP address.
- Added feature to specify custom IP addresses for blocked domain names.
- Added feature to temporarily/permanently disable blocking of domain names.
- Added index page for DNS-over-HTTPS (DoH) web service that displays basic configuration information to user when DoH URL is visited using a web browser.
- Fixed multiple issues in QNAME minimization implementation.
- Fixed multiple DNS Client implementation issues.
- Multiple other minor bug fixes and improvements.
- Updated few API calls which may cause issues in 3rd party clients if they are not updated before deploying this new version.

## Version 6.2.3
Release Date: 2 May 2021

- Improved DNS Apps interface to show if updates are available in the installed apps list.
- Updated stats module to truncate daily stats data to optimize memory usage.
- Fixed issue with QNAME minimization caused due to missing check when response contained no answer and no authority.
- Fixed issue in logger which would fail to start in certain conditions.
- Updated DNS Apps to shuffle addresses in response to allow load balancing.

## Version 6.2.2
Release Date: 24 April 2021

- Fixed issues with recursive resolution.
- Fixed issue in parsing AXFR response.
- Fixed missing tags in responses to reflect correct stats on dashboard.
- Fixed issue with web console redirection on saving settings when using a reverse proxy.
- Multiple other minor bug fixes and improvements.

## Version 6.2.1
Release Date: 17 April 2021

- Updated DNS Cache serve stale implementation for better performance.
- Implemented CNAME resolution optimization in DNS Cache and Auth Zone.
- Fixed issue in DNS Cache caused due to missing check of the type of NS record's RDATA causing cache zone to return special cache RDATA record.
- Fixed issue in DNS client caused when response greater than the buffer size is received.

## Version 6.2
Release Date: 11 April 2021

- Fixed critical bug in block list condition check causing server to respond with `RCODE=Refused` when only using Blocked zone.
- Added option to respond with `RCODE=NxDomain` for blocked domains instead of returning `0.0.0.0` address.
- Renamed `NameError` to `NxDomain` to make the terminology clear that the domain does not exists. Dashboard API returns JSON with new terminology so its advised to test your code before updating the server.

## Version 6.1
Release Date: 10 April 2021

- Added DNS App Store feature that list all available apps for quick and easy installation and update.
- Added 'Overwrite' option in Add Record for zones.
- Multiple ANAME record support added.
- Added block list allowed URL feature to prevent domain names from getting added to the block list zone.
- Fixed bug in ZoneTree.
- Fixed bugs in DNS Apps.
- Split Default DNS App into 5 independent apps that are now available on the DNS App Store.
- Fixed issues in DNS Cache and updated code for memory optimization.
- Upgraded all library projects to .NET 5.
- Multiple other minor bug fixes and improvements.

## Version 6.0
Release Date: 13 March 2021

- Updated entire DNS code base to .NET 5 with new Windows installer. This upgrade will improve overall performance on Windows installations.
- Added support for DNS Application (APP) propriety record with DNS Apps feature support. DNS Apps allows creating custom apps by 3rd party using .NET that run on the DNS Server allowing the apps to process DNS requests and provide custom DNS response based on any bussiness logic.
- A default DNS app (available to download separately) supports APP records capable of Split Horizon and Geolocation based responses using MaxMind's GeoIP2 City & Country databases.
- Updated dashboard charts to save legend selection state.
- Updated dashboard with Custom date selection option to display stats.
- Added option to configure max stats days in settings.
- Added option to enable/disable QNAME minimization.
- Added delete existing files option in Restore settings.
- Added support to store query stats data to allow DNS cache auto prefetch to refresh cache when DNS Server restarts.
- Updated TLS certificate implementation to allow using self signed certificates for web console, DoH, and DoT.
- Added DHCP lease Reserve/Unreserve options to allow quickly reserving lease for clients.
- Updated DHCP reserved lease option to allow overriding client's host name.
- Fixed issues with DNS cache auto prefetch feature.
- Fixed multiple issues in DNS cache.
- Fixed multiple vulnerabilities causing DNS cache poisoning.
- Multiple other minor bug fixes and improvements.

## Version 5.6
Release Date: 2 January 2021

- Updated standalone console app to work on .NET 5 and removing standalone .NET Framework app support. .NET 5 update will boost performance of the DNS Server on all platforms.
- Updated DNS and DHCP listener code to use async IO to improve performance.
- Added HTTPS support for web service that provides the web console access.
- Added support to change the web service local addresses.
- Updated the server to allow changing DNS Server end points, the web service end points, or enabling DoH or DoT services instantly without need to manually restart the main service. Basically, you do not need to restart the DNS Server app at all for applying any kind of settings as all the changes are applied dynamically.
- Added HTTP compression support in the main web service.
- Added HTTP compression for downloading block lists.
- Added option to clear and delete all dashboard stats and auto clean up old stats files from disk
- Added option to delete all log files and auto clean up old log files from disk.
- Added configurable option to disable logging, allow logging in local time, and to change log folder path.
- Added option in settings to define the refresh interval for block lists with a manual option to force refresh all block lists.
- Added support for exporting backup zip file containing selected items like config files, logs, stats, etc. and allow restoring the backup zip file without restarting the main service.
- Fixed multiple issues in DHCP server's DNS record management.
- Fixed bug in DNS Server cache prefetching for stub and conditional forwarder zones causing the cached data to be overwritten by the prefetched output from recursive resolution.
- Fixed html encoding issue in web app.
- Added option in web app to list top 1000 clients, top domains and top blocked domains.
- DNS cache serve stale feature made configurable with default serve stale TTL set to 3 days instead of 7 days.
- Fixed issue in recursive resolver to avoid querying root servers when one of the parent zone's name servers exists in DNS cache.
- Breaking changes in the `getDnsSettings` and `setDnsSettings` API calls will require API clients to update the code before updating the DNS Server.
- Multiple other minor bug fixes and improvements.

## Version 5.5
Release Date: 14 November 2020

- Added option to specify bootfile name for PXE booting.
- Implemented DHCP vendor specific information option.
- Implemented strict enforcing of exclusion list.
- Fixed bug in DNS initial server name that was caused due to invalid characters in the computer name.
- Added support for additional record processing for SRV records and fixed issues for NS and MX records processing.
- Multiple other minor bug fixes and improvements.

## Version 5.4
Release Date: 18 October 2020

- Implemented QNAME randomization feature [draft-vixie-dnsext-dns0x20](https://datatracker.ietf.org/doc/html/draft-vixie-dnsext-dns0x20-00).
- Fixed bug causing infinite loop in certain conditions when using UDP as transport.
- Fixed bug in DNS cache querying which caused the server to make unneeded queries when performing recursive resolution.
- Added Create PTR Zone option when adding A or AAAA records.
- Fixed issues with DHCP scope selection when using relay agent.
- Implemented changes to allow changing DHCP scope IP allocation from dynamic to reserved and vice versa.
- Updated DHCP scope to allow specifying Next Server Address for use with TFTP for booting.
- Multiple other minor bug fixes and improvements.

## Version 5.3
Release Date: 26 September 2020

- Fixed issues with DHCP server that caused it to not work correctly with relay agents.
- Updated DHCP server to support multiple scopes to work on a single network interface allowing it to provide different options for groups of devices.
- Multiple other minor bug fixes and improvements.

## Version 5.2
Release Date: 6 September 2020

- Added feature to allow using `certbot` to renew TLS certificates automatically when using DNS-over-HTTPS and DNS-over-TLS.
- Fixed issue in DHCP server that caused thread to block by implementing async methods.
- Fixed bug in DNS client that caused QTYPE mismatch due to QNAME minimization.
- Fixed issues in DNS-over-HTTPS client related to retries and http error handling.
- Multiple other minor bug fixes and improvements.

## Version 5.1
Release Date: 29 August 2020

- Implemented async IO to allow the DNS Server handle much higher concurrent loads.
- Implemented independent thread pools for DNS web service and recursive resolver.
- Fixed bug in block list downloader that caused 0 byte file downloads.
- Fixed bug in DHCP server in creating reverse zone.
- Multiple other minor bug fixes and improvements.

## Version 5.0.2
Release Date: 18 July 2020

- Fixed issue of missing port for "This Server" in DNS Client.
- Added domain name that was blocked in the TXT record.
- Fixed bugs in CNAME cloaking implementation.
- Upgraded .NET Framework version to v4.8.
- Multiple other minor bug fixes and improvements.

## Version 5.0.1
Release Date: 6 July 2020

- Fixed serialization bug for TXT records.
- Fixed issue with reading DnsDatagram for DoH POST requests.
- Fixed bug in json serialization of DnsDatagram for DoH json format.
- Fixed bug in RTT calculation for DoH json Connection.

## Version 5.0
Release Date: 4 July 2020

- DNS Server local end points support to allow specifying alternate ports for UDP and TCP protocols.
- DNS Server performance issues caused by thread contention fixed.
- CNAME cloaking implemented to block domain names that resolve to CNAME which are blocked.
- New Block List zone implementation that uses very less memory allowing to load block lists with millions of domain names even on a Raspberry Pi with 1GB RAM.
- QNAME minimization support in recursive resolver [draft-ietf-dnsop-rfc7816bis-04](https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-rfc7816bis-04).
- ANAME propriety record support to allow using CNAME like feature at zone root.
- Added primary zones with NOTIFY implementation [RFC 1996](https://datatracker.ietf.org/doc/html/rfc1996).
- Added secondary zones with NOTIFY implementation [RFC 1996](https://datatracker.ietf.org/doc/html/rfc1996).
- Added stub zones with feature to override records.
- Added conditional forwarder zones with all protocols including DNS-over-HTTPS and DNS-over-TLS support.
- Conditional forwarder zones with feature to override records.
- Conditional forwarder zones with support for multiple forwarders with different sub domain names.
- ByteTree based zone tree implementation which is a complete lock-less and thread safe tree allowing concurrent read and write operations.
- Fixed bug in parsing large TXT records.
- DNS Client with internal support for concurrent querying. This allows querying multiple forwarders simultaneously to return fastest response of all.
- DNS Client with support to import records via zone transfer.
- Multiple other bug fixes in DNS and DHCP modules.
