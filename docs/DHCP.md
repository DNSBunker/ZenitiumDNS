# DHCP server

[Deutsche Version](DHCP.de.md)

ZenitiumDNS contains a DHCP server for IPv4 and IPv6. It assigns addresses, announces prefix and DNS server with router advertisements, adds the names of the devices to the local DNS, and detects other DHCP servers and IPv6 routers on the network. It is set up under **DHCP** in the web interface and is off after installation.

## Simple settings

For a single network, the **Settings** tab is enough:

| Setting | Meaning |
| ------- | ------- |
| Interface | Automatic answers on every interface whose network matches the address range. IPv6 needs a selected interface because the prefixes come from it. |
| Address range | First and last address that is handed out. |
| Netmask | Empty takes the prefix of the interface. |
| Gateway | Empty sends the default gateway of the interface if it is in the same network. |
| DNS servers | Empty sends the address of this server, so the devices use ZenitiumDNS with all filters. |
| Domain | Devices are reachable as `name.domain`; unknown names in this domain are answered with NXDOMAIN by the server itself. `home.arpa` or `lan` are good choices for a private network. |
| Lease time | For example `30m`, `12h`, `7d` or `infinite`; at least 2 minutes. |
| Authoritative | Only if this server is the only DHCP server on the network: wrong requests are rejected right away with DHCPNAK, and leases it does not know (for example after the lease file was lost) are taken over. |
| Reservations | Fixed addresses by MAC address or by `id:` with client identifier or DUID, optionally with a host name and a client profile. The IPv4 address may be outside the range but must be in the same network. For IPv6 the host part such as `::20` is enough; it is combined with every prefix of the interface. |

The simple settings are converted into the syntax of the expert configuration; the **Expert** tab shows the generated lines.

### IPv6

| Setting | Meaning |
| ------- | ------- |
| IPv6 on the network | **SLAAC** (recommended): devices form their own addresses and learn the DNS server from the router advertisement (RDNSS, RFC 8106) and from DHCPv6 without address assignment. Works with all systems including Android. **SLAAC plus DHCPv6 addresses**: additionally hands out addresses from the DHCPv6 range, which are listed in DNS under the device name. **DHCPv6 addresses only**: no SLAAC; Android then gets no IPv6 address from here (it does not support DHCPv6 for addresses), only the DNS server. |
| DHCPv6 range | Host part of the first and last address, for example `::1000` to `::1fff`. If the interface has several prefixes (for example from the provider and a ULA), every device gets one address from each prefix. |
| Default router | **Automatic** announces this machine as default router only if it forwards IPv6 (`/proc/sys/net/ipv6/conf/<interface>/forwarding`). **No** only announces prefix and DNS server (router lifetime 0); the devices keep their router. **Yes** always announces it. |

The prefixes are taken from the global and unique local (ULA) addresses of the selected interface and follow automatically when the provider changes them; prefixes that disappear are announced as no longer valid for two hours. As DNS server the server announces its own address on the interface, preferring a ULA and fixed (not SLAAC-generated) addresses so that the announced address stays stable. IPv6 addresses in the DNS server field are announced instead.

## Expert configuration

The **Expert** tab accepts the DHCP configuration syntax of [dnsmasq](https://dnsmasq.org/docs/dnsmasq-man.html). It shows the own configuration in two views of the same text:

- **List**: every line as a readable entry (for example "NTP server (ntp-server, 42) = this server") with edit, move and remove. **New entry** opens a form for IPv4 and IPv6 ranges, reservations, DHCP and DHCPv6 options, device groups (tags), rules, network boot, domains, router advertisement parameters and general switches. Options are chosen from a list with descriptions, and the value fields match the type of the option (addresses with "address of this server", yes/no, numbers, routes as lines, text). The form shows the resulting line before it is applied. Lines the forms do not cover (for example encapsulated vendor options) are edited as a free line.
- **Text**: the lines themselves.

Changes are checked in the background; faulty lines are marked in the list with the message of the server. Nothing is applied before **Save**; **Check** validates on demand.

```
dhcp-range=set:office,192.168.10.100,192.168.10.200,12h
dhcp-range=::1000,::1fff,constructor:eth0,slaac,64,12h
enable-ra
ra-param=eth0,600,0
dhcp-option=option6:dns-server,[::]
dhcp-host=aa:bb:cc:dd:ee:ff,192.168.10.20,[::20],printer
dhcp-range=set:guests,10.10.0.50,10.10.0.250,255.255.255.0,2h
dhcp-option=tag:guests,option:router,10.10.0.1
dhcp-option=tag:guests,option:dns-server,0.0.0.0
dhcp-host=aa:bb:cc:dd:ee:ff,192.168.10.20,printer
dhcp-host=11:22:33:*:*:*,set:iot
dhcp-vendorclass=set:phones,Yealink
dhcp-option=tag:phones,66,"http://provisioning.example/"
dhcp-match=set:efi64,option:client-arch,7
dhcp-boot=tag:efi64,ipxe.efi,,192.168.10.5
domain=home.arpa,192.168.10.0/24,local
dhcp-authoritative
```

Supported directives:

| Directive | Purpose |
| --------- | ------- |
| `dhcp-range=[tag:<tag>,][set:<tag>,]<start>,<end>\|static[,<netmask>[,<broadcast>]][,<lease time>]` | Address range. For networks behind a DHCP relay the netmask is required. `static` hands out reserved addresses only. At most 65,536 addresses per range, ranges must not overlap. |
| `dhcp-host=[<mac>][,id:<client-id>\|*][,set:<tag>][,tag:<tag>][,<ip>][,<name>][,<lease time>][,ignore]` | Reservation, name, lease time or exclusion of a device. MAC addresses may contain `*`, an optional hardware type is written as `1-aa:bb:…`. Without MAC and client ID the entry matches the host name the device sends. |
| `dhcp-option=[tag:<tag>,…][encap:<opt>,][vi-encap:<enterprise>,][vendor:<class>,]<number>\|option:<name>,[<value>,…]` | Option. `0.0.0.0` stands for the address of this server in the respective network, an empty value suppresses the option. Options with more tags win over options with fewer; for the same number of tags the later line wins. Lines of the expert configuration always win over the simple settings. |
| `dhcp-option-force=…` | Like `dhcp-option`, but sent even if the device did not ask for it. |
| `dhcp-match=set:<tag>,<number>\|option:<name>\|vi-encap:<enterprise>[,<value>]` | Sets a tag if the request contains the option (with the value). |
| `dhcp-vendorclass=set:<tag>,[enterprise:<number>,]<text>`, `dhcp-userclass=set:<tag>,<text>` | Tag by vendor class (option 60 / 124) or user class (option 77), substring match. |
| `dhcp-mac=set:<tag>,<mac with *>` | Tag by MAC address. |
| `dhcp-circuitid=set:<tag>,<value>`, `dhcp-remoteid=…`, `dhcp-subscrid=…` | Tag by the relay agent information (option 82). |
| `tag-if=set:<tag>[,set:<tag>][,tag:<tag>…]` | Sets tags if all given tags are set (`tag:!x` negates). |
| `dhcp-ignore=tag:<tag>[,…]` | Does not answer matching devices. |
| `dhcp-ignore-names[=tag:…]`, `dhcp-generate-names[=tag:…]` | Ignores the host names of the devices or builds names from the MAC address. |
| `dhcp-broadcast[=tag:…]` | Always sends answers as broadcast. |
| `dhcp-boot=[tag:<tag>,]<file>[,<server name>[,<server address>]]` | PXE and BOOTP boot (`file`, `sname`, `siaddr`). |
| `domain=<domain>[,<network/prefix>\|<start>,<end>][,local]` | Domain for the names of the devices; `local` makes the server answer unknown names itself. |
| `dhcp-reply-delay=[tag:<tag>,]<seconds>` | Delays offers (at most 10 seconds). |
| `dhcp-range=[tag:<tag>,][set:<tag>,]<start6>[,<end6>\|static][,constructor:<interface>][,ra-only\|ra-stateless\|slaac\|ra-names][,off-link][,<prefix length>][,<lease time>]` | IPv6 range. With `constructor:` the addresses only contain the host part (`::100`) and are combined with every global or ULA prefix of the interface (`eth*` matches several). Without it, full addresses are given; such ranges also serve DHCPv6 relays whose link address lies in the prefix. `ra-only` announces the prefix for SLAAC without DHCPv6, `ra-stateless` adds DHCPv6 without addresses, `slaac` combines SLAAC and DHCPv6 addresses, without a mode only DHCPv6 hands out addresses. `ra-names` is accepted and treated like `slaac`. Prefix length 64 by default; SLAAC needs exactly 64. |
| `enable-ra` | Sends router advertisements for all IPv6 ranges (the modes `ra-only`, `ra-stateless` and `slaac` switch them on for their range anyway). |
| `ra-param=<interface>,[mtu:<value>\|<interface>\|off,][high\|low,]<interval>[,<router lifetime>]` | Interval of the unsolicited router advertisements (4 to 1800 seconds, default 600), router preference, MTU option and router lifetime (0 = not a default router). Without a router lifetime the server announces itself only if it forwards IPv6. |
| `dhcp-option=[tag:<tag>,…]option6:<number>\|<name>,[<value>,…]` | DHCPv6 option, for example `option6:dns-server,[::]`, `option6:domain-search,home.arpa`, `option6:ntp-server,[::]` or `option6:sntp-server,[2001:db8::123]`. `[::]` stands for the address of this server on the link. `dns-server` and `domain-search` are also used for RDNSS and DNSSL in router advertisements. |
| `dhcp-host=…,[<ipv6>]` | IPv6 address of a reservation. `[::20]` is combined with every prefix of the range, a full address is used as given. For DHCPv6 the device is recognized by `id:<DUID>` (hexadecimal), by the MAC address contained in its DUID (types LLT and LL) or by the MAC address passed on by a relay (RFC 6939). |
| `interface=<name>`, `except-interface=<name>` | Restricts the interfaces; `eth*` matches a prefix. |
| `dhcp-authoritative`, `dhcp-rapid-commit`, `dhcp-sequential-ip`, `dhcp-ignore-clid`, `dhcp-no-override`, `bootp-dynamic`, `no-ping`, `dhcp-lease-max=<n>` | Global switches. |

Automatic tags: the name of the interface the request came in on, `known` if a `dhcp-host` entry matches, `bootp` for BOOTP requests, and the `set:` tag of the selected range.

Not supported (with an error message): proxy DHCP, `pxe-service`, `dhcp-script`, `dhcp-relay`, host and option files and settings for the lease file. DHCPv6 prefix delegation (IA_PD) and temporary addresses (IA_TA) are answered with "not available", Reconfigure is not sent.

Option names follow dnsmasq (`dnsmasq --help dhcp` and `dnsmasq --help dhcp6`); the list is shown in the **Expert** tab. Values are encoded by the type of the option: addresses, address lists, numbers, text, domain search lists (RFC 3397, with compression) and classless static routes (RFC 3442, `dhcp-option=121,10.0.0.0/8,192.168.1.1`). Hexadecimal values are written as `01:02:03`, text in quotes.

## Protocol behavior

- DISCOVER, REQUEST (selecting, init-reboot, renewing, rebinding), DECLINE, RELEASE and INFORM according to RFC 2131, BOOTP for reserved devices (with `bootp-dynamic` also dynamically).
- An address stays assigned to a device: a returning device gets its previous address as long as it is free. New devices get addresses in an order derived from their MAC address, so that devices do not all compete for the first address.
- Before an address is offered for the first time, it is pinged. If it answers, it is blocked for ten minutes. A DHCPDECLINE of a device blocks the address as well.
- Relay agents (`giaddr`) with subnet selection (RFC 3011) and link selection (RFC 3527), relay agent information (RFC 3046) is returned unchanged.
- Long options are split according to RFC 3396; if the answer does not fit the maximum size of the device (option 57, at least 576 bytes), the `file` and `sname` fields are used as well (option overload).
- Rapid commit (RFC 4039), client FQDN (RFC 4702), client identifier (RFC 6842).
- Answers to devices without an address go to their MAC address directly. This needs the capability `CAP_NET_RAW`; without it they are sent as broadcast, which works with almost all devices.
- At most 20 packets per second and MAC address are processed; further ones are dropped.

### DHCPv6 and router advertisements

- DHCPv6 according to RFC 8415: SOLICIT and ADVERTISE (with preference 255 when the server is authoritative and has priority "Primary"), REQUEST, RENEW, REBIND, CONFIRM, RELEASE, DECLINE and INFORMATION-REQUEST, rapid commit (`dhcp-rapid-commit`), relays (RELAY-FORW with up to 32 levels, the interface ID is returned). Messages that are sent by unicast although the server did not offer unicast are answered with status UseMulticast or ignored.
- The server identifies itself with a DUID-UUID (RFC 6355) derived from `dhcp-node.id`.
- A device keeps its address per IAID; new addresses are chosen in an order derived from DUID and IAID. A DECLINE blocks the address for one hour.
- DNS servers (option 23) and the domain (option 24) are sent with every answer; when nothing is configured, the address of this server on the link and the domain of the simple settings are used. Other options are sent if the device asks for them or with `dhcp-option-force`. INFORMATION-REQUEST answers carry an information refresh time from the lease time (at least 10 minutes, at most one day).
- Client FQDN (RFC 4704): the host name is taken from option 39, the answer states that the server enters the name.
- Router advertisements according to RFC 4861 with prefix information, RDNSS and DNSSL (RFC 8106), the source link-layer address and optionally the MTU. They are sent three times within 16 seconds after a start or a change, then at random times between a third of the interval and the full interval; router solicitations are answered within half a second, at most every 3 seconds. The M flag is set when DHCPv6 hands out addresses, the O flag when DHCPv6 is available. When the server stops or IPv6 is switched off, it sends a last advertisement with router and DNS lifetime 0.

## Other DHCP servers and priority

The server sends a DHCP request of its own on every interface at regular intervals (every 5 minutes by default) and evaluates the offers. In addition, it recognizes other servers from the server identifier in the requests of the devices. Servers found appear on the **Status** tab and in the self-test. **Search for other DHCP servers** on the **Status** tab also works while the DHCP server is off; it then sends the request on every interface with an IPv4 address, so an existing server, for example on the router, can be found before switching on.

The priority defines how the server behaves when another DHCP server is present, for example a router whose DHCP cannot be switched off:

| Priority | Behavior |
| -------- | -------- |
| Primary | Answers immediately. |
| Secondary | Sends offers after a delay (2 seconds by default) and optionally only when a device has been searching for a minimum time (field `secs`), so that the other server is chosen as long as it works. |
| Standby | Answers new devices only as long as no other DHCP server was seen; existing leases are still renewed. |

## IPv6 routers and DNS announcements

While the DHCP server is on, it listens for router advertisements of other routers on all interfaces. The **Status** tab lists them with flags, prefixes and the DNS servers they announce. If a router announces DNS servers other than this server, devices may ask those instead of ZenitiumDNS, and then filters and device names do not apply; the status and the self-test warn about it. The remedy is to switch off the DNS announcement (RDNSS) in the router or to point it to this server, or to switch on IPv6 here so that ZenitiumDNS is announced as well. DHCPv6 servers that devices address are recognized by the server identifier in their requests; with priority "Standby" the server then hands out no new IPv6 addresses.

## Devices, client IDs and profiles

The server treats the addresses of a device as one device:

- An IPv4 lease belongs to the MAC address of the device; the client identifier (option 61) is shown in the lease list when it is not simply the MAC address. Devices that send a client identifier according to RFC 4361 (type 255 with IAID and DUID, for example systemd-networkd) use the same DUID as for DHCPv6; the list shows it as DUID.
- A DHCPv6 lease gets the MAC address of the device from its DUID (types LLT and LL), from a relay (RFC 6939), from the IPv4 lease with the same DUID, from a link-local address formed from the MAC address (EUI-64) or from the neighbor table. That way reservations by MAC address, names and client profiles also apply to DHCPv6 devices whose DUID contains no MAC address.
- Reservations can name a device by MAC address or by `id:` with client identifier or DUID.

In the simple settings every reservation has a **Profile** column, and the lease list has a profile selection per lease: the choice assigns the MAC address of the device (without one, the reserved IPv4 address) to that client profile, so the filters of the profile apply to the device over IPv4 and IPv6. The MAC address is resolved from the leases and the neighbor table of the system, see [BlockLists.md](BlockLists.md#recognizing-devices). The query log shows the name of a known device under its address, and the client profile dialog offers the known devices for selection.

## Names in DNS

With **Add device names to DNS**, the server answers A and AAAA queries for `name.domain` and PTR queries (`in-addr.arpa` and `ip6.arpa`) for the addresses of active leases and reservations. The name comes from the reservation, otherwise from the device (option 12 or 81, for DHCPv6 option 39), and for DHCPv6 leases without a name from the IPv4 lease of the same MAC address. A device with addresses from several prefixes gets an AAAA record for each. Only clients that may use recursion get these answers. If two devices report the same name, the one with the most recent lease wins; reservations always win.

## Monitoring

The self-test (tab Self-test) checks the DHCP server as soon as it is switched on: errors in the configuration, interfaces that do not receive, other DHCP servers in the network (warning with priority "Primary", note with "Secondary" and "Standby"), a failed search for them, the use of the dynamic ranges (warning from 90 %, error when full) broadcast replies without `CAP_NET_RAW`, router advertisements and DHCPv6 per interface (for example an interface without prefix), routers that announce other DNS servers, routers that set the M flag while DHCPv6 hands out addresses here, and other DHCPv6 servers. The Prometheus endpoint exports the counters and the pool usage as `zenitiumdns_dhcp_*`, `zenitiumdns_dhcp6_*` and `zenitiumdns_ra_*` ([Metrics.md](Metrics.md#dhcp)).

## Files

| File in the configuration folder | Content |
| -------------------------------- | ------- |
| `dhcp.json` | DHCP settings including the expert configuration. |
| `dhcp-leases.json` | Leases, written at most once per second after changes. |
| `dhcp6-leases.json` | DHCPv6 leases. |
| `dhcp-node.id` | Random ID of this server; the hardware address used in the search for other DHCP servers and the DUID of the DHCPv6 server are derived from it. |

`dhcp.json`, `dhcp-leases.json` and `dhcp6-leases.json` are part of the backup together with the DNS settings. Restoring them replaces the DHCP settings and leases. `dhcp-node.id` is not part of the backup.

## API

| Call | Permission | Purpose |
| ---- | ---------- | ------- |
| `api/dhcp/status` | DHCP: view | State, interfaces, pool usage, counters, other DHCP servers; under `ipv6` the router advertisements per interface, DHCPv6 listeners and counters, other routers and DHCPv6 servers. |
| `api/dhcp/settings/get` | DHCP: view | Settings, generated lines, interfaces (with IPv6 prefixes under `interfaces6`), option names. |
| `api/dhcp/settings/validate` | DHCP: view | Checks `settings` (JSON) without saving. |
| `api/dhcp/settings/set` | DHCP: modify | Saves `settings` (JSON); errors are returned with line numbers. |
| `api/dhcp/leases/list` | DHCP: view | Leases, DHCPv6 leases under `leases6`. |
| `api/dhcp/leases/reserve` | DHCP: modify | Turns the lease of `address` into a reservation; for IPv6 the host part is reserved, which needs a MAC address in the DUID of the device. |
| `api/dhcp/leases/delete` | DHCP: delete | Deletes the lease of `address` (IPv4 or IPv6). |
| `api/dhcp/probe` | DHCP: modify | Searches for other DHCP servers now. |
| `api/dhcp/foreign/clear` | DHCP: modify | Clears the list of other DHCP servers. |
| `api/dhcp/devices` | DHCP or settings: view | Known devices from leases, reservations and the neighbor table with addresses, client ID, DUIDs and profile. |

The permission section **DHCP** is new; existing installations give it to the Administrators group completely and to the DNS Administrators group for viewing.

## Requirements

The server needs UDP port 67 (and 68 for the search for other servers), for DHCPv6 UDP port 547, and the capability `CAP_NET_RAW` for answers to the MAC address, for router advertisements and for observing other routers; the systemd service of the Debian package grants it. Without it, IPv4 answers to devices without an address are sent as broadcast, and router advertisements are not available (the status shows the reason). The container image runs the server as an unprivileged user without `CAP_NET_RAW`; DHCPv4 and DHCPv6 work there, router advertisements do not. A container must use the host network (`--network host`), otherwise it does not see the broadcasts and multicasts of the devices.
