# DHCP server

[Deutsche Version](DHCP.de.md)

ZenitiumDNS contains a DHCPv4 server. It assigns addresses, adds the names of the devices to the local DNS, and detects other DHCP servers on the network. It is set up under **DHCP** in the web interface and is off after installation.

## Simple settings

For a single network, the **Settings** tab is enough:

| Setting | Meaning |
| ------- | ------- |
| Interface | Automatic answers on every interface whose network matches the address range. |
| Address range | First and last address that is handed out. |
| Netmask | Empty takes the prefix of the interface. |
| Gateway | Empty sends the default gateway of the interface if it is in the same network. |
| DNS servers | Empty sends the address of this server, so the devices use ZenitiumDNS with all filters. |
| Domain | Devices are reachable as `name.domain`; unknown names in this domain are answered with NXDOMAIN by the server itself. `home.arpa` or `lan` are good choices for a private network. |
| Lease time | For example `30m`, `12h`, `7d` or `infinite`; at least 2 minutes. |
| Authoritative | Only if this server is the only DHCP server on the network: wrong requests are rejected right away with DHCPNAK, and leases it does not know (for example after the lease file was lost) are taken over. |
| Reservations | Fixed addresses by MAC address, optionally with a host name. The address may be outside the range but must be in the same network. |

The simple settings are converted into the syntax of the expert configuration; the **Expert** tab shows the generated lines.

## Expert configuration

The **Expert** tab accepts the DHCP configuration syntax of [dnsmasq](https://dnsmasq.org/docs/dnsmasq-man.html). Errors are reported with their line number, **Check** validates without saving.

```
dhcp-range=set:office,192.168.10.100,192.168.10.200,12h
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
| `interface=<name>`, `except-interface=<name>` | Restricts the interfaces; `eth*` matches a prefix. |
| `dhcp-authoritative`, `dhcp-rapid-commit`, `dhcp-sequential-ip`, `dhcp-ignore-clid`, `dhcp-no-override`, `bootp-dynamic`, `no-ping`, `dhcp-lease-max=<n>` | Global switches. |

Automatic tags: the name of the interface the request came in on, `known` if a `dhcp-host` entry matches, `bootp` for BOOTP requests, and the `set:` tag of the selected range.

Not supported (with an error message): DHCPv6 and router advertisements, proxy DHCP, `pxe-service`, `dhcp-script`, `dhcp-relay`, host and option files and settings for the lease file.

Option names follow dnsmasq (`dnsmasq --help dhcp`); the list is shown in the **Expert** tab. Values are encoded by the type of the option: addresses, address lists, numbers, text, domain search lists (RFC 3397, with compression) and classless static routes (RFC 3442, `dhcp-option=121,10.0.0.0/8,192.168.1.1`). Hexadecimal values are written as `01:02:03`, text in quotes.

## Protocol behavior

- DISCOVER, REQUEST (selecting, init-reboot, renewing, rebinding), DECLINE, RELEASE and INFORM according to RFC 2131, BOOTP for reserved devices (with `bootp-dynamic` also dynamically).
- An address stays assigned to a device: a returning device gets its previous address as long as it is free. New devices get addresses in an order derived from their MAC address, so that devices do not all compete for the first address.
- Before an address is offered for the first time, it is pinged. If it answers, it is blocked for ten minutes. A DHCPDECLINE of a device blocks the address as well.
- Relay agents (`giaddr`) with subnet selection (RFC 3011) and link selection (RFC 3527), relay agent information (RFC 3046) is returned unchanged.
- Long options are split according to RFC 3396; if the answer does not fit the maximum size of the device (option 57, at least 576 bytes), the `file` and `sname` fields are used as well (option overload).
- Rapid commit (RFC 4039), client FQDN (RFC 4702), client identifier (RFC 6842).
- Answers to devices without an address go to their MAC address directly. This needs the capability `CAP_NET_RAW`; without it they are sent as broadcast, which works with almost all devices.
- At most 20 packets per second and MAC address are processed; further ones are dropped.

## Other DHCP servers and priority

The server sends a DHCP request of its own on every interface at regular intervals (every 5 minutes by default) and evaluates the offers. In addition, it recognizes other servers from the server identifier in the requests of the devices. Servers found appear on the **Status** tab and in the self-test. **Search for other DHCP servers** on the **Status** tab also works while the DHCP server is off; it then sends the request on every interface with an IPv4 address, so an existing server, for example on the router, can be found before switching on.

The priority defines how the server behaves when another DHCP server is present, for example a router whose DHCP cannot be switched off:

| Priority | Behavior |
| -------- | -------- |
| Primary | Answers immediately. |
| Secondary | Sends offers after a delay (2 seconds by default) and optionally only when a device has been searching for a minimum time (field `secs`), so that the other server is chosen as long as it works. |
| Standby | Answers new devices only as long as no other DHCP server was seen; existing leases are still renewed. |

## Names in DNS

With **Add device names to DNS**, the server answers A queries for `name.domain` and PTR queries for the addresses of active leases and reservations. The name comes from the reservation, otherwise from the device (option 12 or 81). Only clients that may use recursion get these answers. If two devices report the same name, the one with the most recent lease wins; reservations always win.

## Monitoring

The self-test (tab Self-test) checks the DHCP server as soon as it is switched on: errors in the configuration, interfaces that do not receive, other DHCP servers in the network (warning with priority "Primary", note with "Secondary" and "Standby"), a failed search for them, the use of the dynamic ranges (warning from 90 %, error when full) and broadcast replies without `CAP_NET_RAW`. The Prometheus endpoint exports the counters and the pool usage as `zenitiumdns_dhcp_*` ([Metrics.md](Metrics.md#dhcp)).

## Files

| File in the configuration folder | Content |
| -------------------------------- | ------- |
| `dhcp.json` | DHCP settings including the expert configuration. |
| `dhcp-leases.json` | Leases, written at most once per second after changes. |
| `dhcp-node.id` | Random ID of this server; the hardware address used in the search for other DHCP servers is derived from it. |

`dhcp.json` and `dhcp-leases.json` are part of the backup together with the DNS settings. Restoring them replaces the DHCP settings and leases. `dhcp-node.id` is not part of the backup.

## API

| Call | Permission | Purpose |
| ---- | ---------- | ------- |
| `api/dhcp/status` | DHCP: view | State, interfaces, pool usage, counters, other DHCP servers. |
| `api/dhcp/settings/get` | DHCP: view | Settings, generated lines, interfaces, option names. |
| `api/dhcp/settings/validate` | DHCP: view | Checks `settings` (JSON) without saving. |
| `api/dhcp/settings/set` | DHCP: modify | Saves `settings` (JSON); errors are returned with line numbers. |
| `api/dhcp/leases/list` | DHCP: view | Leases. |
| `api/dhcp/leases/reserve` | DHCP: modify | Turns the lease of `address` into a reservation. |
| `api/dhcp/leases/delete` | DHCP: delete | Deletes the lease of `address`. |
| `api/dhcp/probe` | DHCP: modify | Searches for other DHCP servers now. |
| `api/dhcp/foreign/clear` | DHCP: modify | Clears the list of other DHCP servers. |

The permission section **DHCP** is new; existing installations give it to the Administrators group completely and to the DNS Administrators group for viewing.

## Requirements

The server needs UDP port 67 (and 68 for the search for other servers) and, for answers to the MAC address, the capability `CAP_NET_RAW`, which the systemd service of the Debian package grants. In the container image, answers to devices without an address are sent as broadcast. A container must use the host network (`--network host`), otherwise it does not see the broadcasts of the devices.
