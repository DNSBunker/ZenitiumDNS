# Block lists and client profiles

[Deutsche Version](BlockLists.de.md)

ZenitiumDNS reads block and allow lists in several formats and can apply different lists to different devices. Lists are entered under Filter > Block lists (one URL per line) and are downloaded and updated automatically. Local files work with `file:///path/to/list.txt`; with the Debian package they have to be readable by the service (see README.Debian).

## List formats

All formats can be mixed in one list. Lines starting with `!` or `#`, headers such as `[Adblock Plus 2.0]` and text after ` #` on a hosts or domain line are comments.

| Format | Example | Effect |
| ------ | ------- | ------ |
| Plain domain | `example.com` | Blocks the domain and all subdomains. |
| Wildcard domain | `*.example.com` | Same as a plain domain (compatible with wildcard lists). |
| hosts file | `0.0.0.0 ads.example.com tracker.example.com` | Blocks every host name on the line with its subdomains; `localhost` and similar entries are ignored. |
| Adblock domain rule | `\|\|example.com^` | Blocks the domain and all subdomains. |
| Exact rule | `\|example.com^` | Blocks only this name, not its subdomains. |
| Subdomains only | `\|\|*.example.com^` | Blocks all subdomains, not the domain itself. |
| Wildcard pattern | `\|\|ads*.example.com^`, `tracker-*.net` | `*` stands for any characters including dots. |
| Regular expression | `/^ad[0-9]+\.example\.com$/` | Matches the lower-case name without the trailing dot. |
| Exception | `@@\|\|good.example.com^` | Allows the name again (also works for patterns and regular expressions). |
| IP address or network | `192.0.2.1`, `198.51.100.0/24`, `2001:db8::/32` | Blocks responses whose A or AAAA records point to the address (see below). |

### Modifiers

Adblock rules can carry modifiers after `$`:

| Modifier | Example | Effect |
| -------- | ------- | ------ |
| `important` | `\|\|example.com^$important` | Wins over exceptions and allow lists. An exception with `$important` wins over that again. |
| `badfilter` | `\|\|example.com^$badfilter` | Disables the identical rule without `badfilter`, also in other lists. |
| `dnstype` | `\|\|example.com^$dnstype=AAAA\|HTTPS`, `$dnstype=~TXT` | Only for these query types, or for all except these (`~`). |
| `denyallow` | `\|\|example.com^$denyallow=cdn.example.com` | Blocks the domain but not the listed domains and their subdomains. |
| `client` | `\|\|games.example^$client='Kids'\|192.168.1.0/24`, `$client=~office` | Only for these clients, or for all except these (`~`). A client is matched by IP address or network, by the name of its client profile or by its ClientID. Names with spaces or commas are put in quotes. |

Rules for web page elements (`##`, `#@#`, `#?#`, `#$#`, `$$`) and modifiers that have no meaning for DNS (for example `$third-party` or `$script`) are skipped; the list status shows how many lines were skipped. `$ctag` is not supported.

### Pi-hole regex lists

Lists in the format of Pi-hole's regex filters work without changes: one regular expression per line, optionally followed by `;querytype=AAAA` or `;querytype=!A,AAAA`. POSIX character classes such as `[[:alnum:]]` or `[[:space:]]` are translated. Expressions that need backtracking (back references, lookaround) are skipped, because all expressions run with the non-backtracking engine of .NET and a time limit of 50 ms, so a list cannot slow down the server. Up to 10,000 expressions per list are loaded.

### Blocking by answer address

IP addresses and networks in a block list do not block names but answers: if a response contains an A or AAAA record whose address is listed, the client gets the blocked response instead (with the Extended DNS Error "Blocked" and the source `block-list-ip <address>`). This also covers answers from the cache. Addresses in an allow list exempt them. Networks must be at least /8 for IPv4 and /16 for IPv6, and `0.0.0.0` and `::` are ignored because many hosts files use them as a target.

### Order of evaluation

1. Exceptions with `$important`
2. Block rules with `$important`
3. Allow lists and exceptions (`@@`)
4. Block rules

Manually allowed domains (Filter > Allowed domains) are checked before all lists, manually blocked domains before the block lists.

## Client profiles

Client profiles (Filter > Clients) decide which lists apply to which devices, similar to the persistent clients of AdGuard Home. Queries from devices without a profile use the default block lists.

A profile contains:

- **Identifiers**, one per line: an IP address (`192.168.1.20`), a MAC address (`aa:bb:cc:dd:ee:ff`), a network (`192.168.2.0/24`) or a ClientID (`kids`, lower-case letters, digits and hyphens, at most 63 characters). An identifier can only belong to one profile. **Add known device** offers the devices the server knows (see below).
- **Blocking active**: switched off, all queries of these devices are answered unfiltered, including manually blocked domains.
- **Use default block lists**: switched off, only the profile's own lists apply; manually blocked and allowed domains stay in effect.
- **Own lists**: additional block or allow lists (`!` in front of the URL), in the same formats as above.

Every list is downloaded and loaded only once, even if several profiles use it; each query is evaluated against the lists of its profile. The list status under Filter > Block lists shows which profiles use a list and marks lists that are only used by profiles.

### Recognizing devices

The profile is chosen in this order: ClientID, MAC address, exact IP address, smallest network.

A MAC address covers a device in the same network over IPv4 and IPv6, also with changing or temporary IPv6 addresses. The server learns the MAC address of a client address from its own DHCP leases (IPv4 and DHCPv6) and from the neighbor table of the system (ARP and NDP), so this also works when another DHCP server, for example the router, hands out the addresses. Devices behind a router in another network are only seen with the router's address; for them use IP addresses, networks or ClientIDs. The first query of a device that is not yet in the neighbor table can still be answered with the default lists.

The ClientID is taken from encrypted DNS:

| Protocol | Address for the ClientID `kids` |
| -------- | ------------------------------- |
| DNS-over-HTTPS | `https://dns.example.com/dns-query/kids` |
| DNS-over-TLS | server name `kids.dns.example.com` |
| DNS-over-QUIC | server name `kids.dns.example.com` |

For DoT and DoQ the TLS certificate must also be valid for `*.dns.example.com`; the client profile dialog and the self-test warn if it is not. The first label of the server name counts as a ClientID only if a profile uses it, so the normal server name keeps working. Behind a reverse proxy for DoH the path has to be passed on unchanged. Plain DNS over port 53 only knows the IP address.

### API

| Call | Parameters |
| ---- | ---------- |
| `api/settings/clients/list` | none; returns the profiles, the default lists, the server name and ports needed for ClientIDs and whether the certificate covers ClientID server names (`hasTlsCertificate`, `tlsHostName`, `tlsWildcardDomains`) |
| `api/settings/clients/set` | `name`, `identifiers` (line or comma separated), `blockingEnabled`, `useDefaultLists`, `blockListUrls` (line or comma separated), `originalName` to change an existing profile |
| `api/settings/clients/delete` | `name` |
| `api/settings/clients/assign` | `identifier` (IP address, MAC address, network or ClientID), `profile` (empty removes the identifier from every profile); moves a single identifier, used by the profile selection in the DHCP reservations and leases |
| `api/dhcp/devices` | none; the devices known from DHCP leases, reservations and the neighbor table with MAC address, name, addresses, client ID, DUIDs and the profile that applies (permission to view DHCP or settings) |

Reading requires the permission to view settings, changing requires the permission to modify them. Profiles are stored in `clients.json` in the configuration directory and are part of the backup together with the block lists.
