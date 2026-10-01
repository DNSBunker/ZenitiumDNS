# Advanced Forwarding App

[Deutsche Version](README.de.md)

A DNS App for ZenitiumDNS that forwards queries depending on the client network and the queried domain to different forwarders, optionally through a proxy. Besides its own rules it reads upstream files in the format of AdGuard Home, so large lists of conditional forwarders can be used without creating a forwarder zone for every domain.

## Installation

The app ships with ZenitiumDNS and is installed on the first start, but stays disabled. Enable it under **Apps** and edit the configuration with **Configure**. The shipped configuration has `enableForwarding` switched off.

## How a query is handled

1. Queries without the RD flag and queries from clients that may not use recursion (Settings > Resolver) are left alone, so the app never turns the server into an open resolver.
2. The client address selects a group via `networkGroupMap`; the most specific network wins.
3. The queried name is compared with the `forwardings` of the group, then with its AdGuard upstream files. The longest matching entry wins; an exact name beats `*.parent`, which beats `*`.
4. If a rule matches, the server resolves the query through its forwarders. Names of locally served zones (RFC 6303, e.g. private reverse zones) are not forwarded by a `*` rule.

If nothing matches, the server resolves the query as usual.

## Configuration

| Key | Default | Description |
| --- | ------- | ----------- |
| `appPreference` | `200` | Order among apps; lower values run first, apps without a preference count as 100. |
| `enableForwarding` | `true` | Main switch. |
| `proxyServers` | | Proxy servers that forwarders may use. |
| `forwarders` | | Named forwarders. |
| `networkGroupMap` | | Object that maps networks (`"192.168.0.0/16"`, `"::/0"`) to group names. |
| `groups` | | Groups with their forwarding rules. At least one group is required. |

### `proxyServers`

| Key | Description |
| --- | ----------- |
| `name` | Name used in `proxy`. |
| `type` | `Http` or `Socks5`. |
| `proxyAddress`, `proxyPort` | Address and port of the proxy. |
| `proxyUsername`, `proxyPassword` | Optional credentials. |

### `forwarders`

| Key | Default | Description |
| --- | ------- | ----------- |
| `name` | | Name used in `forwardings`. |
| `proxy` | `null` | Name of a proxy server, or `null` for the proxy configured in the server. |
| `dnssecValidation` | `true` | Validate answers from this forwarder with DNSSEC. |
| `forwarderProtocol` | `Udp` | `Udp`, `Tcp`, `Tls`, `Https` or `Quic`. |
| `forwarderAddresses` | | Addresses such as `9.9.9.9`, `dns.quad9.net:853 (9.9.9.9)` or `https://dns.quad9.net/dns-query (9.9.9.9)`. |

### `groups`

| Key | Default | Description |
| --- | ------- | ----------- |
| `name` | | Name used in `networkGroupMap`. |
| `enableForwarding` | `true` | Switch for this group. |
| `forwardings` | | List of rules with `forwarders` (names) and `domains`. A domain entry matches the name and its subdomains (`example.com`), only subdomains (`*.example.com`) or everything (`*`). Case does not matter. |
| `adguardUpstreams` | | List of upstream files with `configFile`, `proxy` and `dnssecValidation`. |

### AdGuard upstream files

`configFile` is a path relative to the folder of the app (for example `/etc/zenitiumdns/apps/AdvancedForwardingApp`) or an absolute path. The file is read on start and checked for changes every minute. Format:

```
# default upstreams, used for names without a specific rule
https://dns.quad9.net/dns-query (9.9.9.9)
tls://1.1.1.1
[/corp.example/lab.example/]10.0.0.53 10.0.0.54
[/ads.corp.example/]#
```

- A line without brackets adds a default upstream.
- `[/domain/…/]upstreams` forwards the listed domains and their subdomains to the given upstreams, separated by spaces.
- `[/domain/]#` uses the default upstreams for this domain, for example to exclude a subdomain from a more general rule.
- Lines starting with `#` are comments.

If default upstreams are present, every query of the group that no rule of the group matches goes to them.

### Example

```json
{
  "appPreference": 200,
  "enableForwarding": true,
  "proxyServers": [
    {
      "name": "local-proxy",
      "type": "Socks5",
      "proxyAddress": "localhost",
      "proxyPort": 1080,
      "proxyUsername": null,
      "proxyPassword": null
    }
  ],
  "forwarders": [
    {
      "name": "quad9-doh",
      "proxy": null,
      "dnssecValidation": true,
      "forwarderProtocol": "Https",
      "forwarderAddresses": ["https://dns.quad9.net/dns-query (9.9.9.9)"]
    },
    {
      "name": "corp",
      "proxy": null,
      "dnssecValidation": false,
      "forwarderProtocol": "Udp",
      "forwarderAddresses": ["10.0.0.53"]
    }
  ],
  "networkGroupMap": {
    "10.0.0.0/8": "office",
    "0.0.0.0/0": "everyone",
    "::/0": "everyone"
  },
  "groups": [
    {
      "name": "office",
      "enableForwarding": true,
      "forwardings": [
        { "forwarders": ["corp"], "domains": ["corp.example"] },
        { "forwarders": ["quad9-doh"], "domains": ["*"] }
      ]
    },
    {
      "name": "everyone",
      "enableForwarding": true,
      "forwardings": [
        { "forwarders": ["quad9-doh"], "domains": ["*"] }
      ],
      "adguardUpstreams": [
        { "proxy": null, "dnssecValidation": true, "configFile": "adguard-upstreams.txt" }
      ]
    }
  ]
}
```

## Notes

- Forwarders with `dnssecValidation: false` work like a negative trust anchor for the matching domains.
- The server keeps the cached answers of different groups apart only when EDNS Client Subnet is switched on under Settings > Resolver; the client network itself is not sent to the forwarders. Without it, groups that forward the same name to different forwarders can receive each other's cached answers.
- Errors in an upstream file are written to the server log; the previous state of the file stays in use.
