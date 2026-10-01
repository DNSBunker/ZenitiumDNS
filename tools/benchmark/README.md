# Benchmark kit

[Deutsche Version](README.de.md)

This kit measures ZenitiumDNS and Technitium DNS Server under the same conditions. The results in [docs/Performance.md](../../docs/Performance.md) were produced with it.

Everything runs inside an unprivileged network namespace (`unshare`), so nothing on the host network is touched and no real name servers are queried:

- `fakeauth.py` simulates a root server (10.53.0.1) and the top-level domain `deadtld` (10.53.0.2). Every name under `deadtld` resolves; names starting with `nx` return NXDOMAIN.
- `named.root` points the DNS server to the simulated root. It is bind-mounted over the `named.root` of the application folder inside a private mount namespace, the folder itself is not changed.
- `dnsload.c` is the load generator: fixed query rate, 1,000 client addresses (10.60.0.0/16 on the loopback device), 75 % A and 25 % AAAA queries, latency histogram with 10 µs resolution.
- `tlsload/` is a small .NET program for DNS-over-TLS (and DNS-over-HTTPS) load: fixed query rate over 32 pipelined connections, latency histogram. `bench.sh` builds it with `$DOTNET` and creates a self-signed certificate for the server; without a .NET SDK the DoT test is skipped.
- An optional folder with block lists is served over HTTP (10.53.0.5:8080) so that both servers download them the same way.

## Requirements

Linux with user namespaces, `gcc`, `python3`, `curl`, `taskset`, `iproute2`, `openssl`. For Technitium the .NET 10 runtime (`dotnet`) is needed, for the DoT test the .NET 10 SDK; ZenitiumDNS is published self-contained.

## Running

```
dotnet publish src/ZenitiumDns/ZenitiumDns.csproj -c Release -r linux-x64 --self-contained true -o /tmp/zenitiumdns
curl -sSL -o /tmp/tdns.tar.gz https://download.technitium.com/dns/DnsServerPortable.tar.gz
mkdir -p /tmp/technitium && tar xzf /tmp/tdns.tar.gz -C /tmp/technitium

unshare -rnm bash tools/benchmark/bench.sh zenitiumdns zenitiumdns /tmp/zenitiumdns /path/to/lists
unshare -rnm bash tools/benchmark/bench.sh technitium technitium /tmp/technitium /path/to/lists
```

The last argument is optional; it is a folder with block lists in plain domain format (one domain per line). The results are written to `tools/benchmark/results/<label>/results.txt`.

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `SERVER_CPUS` | `0-3` | CPUs the DNS server may use (`taskset`). |
| `LOAD_CPUS` | `8-15` | CPUs of the load generator; keep them separate from the server. |
| `DOTNET` | `dotnet` | Path of the .NET host for Technitium and of the SDK that builds `tlsload`. |
| `SERVER_ENV` | empty | Extra environment variables for the server, e.g. `DOTNET_gcServer=0`. |
| `QUICK` | `0` | `1` runs only the cache hit test, `2` only the recursive resolution test. |
| `OUT` | `tools/benchmark/results` | Output folder. |

Before the tests, both servers get the same settings: listening on 10.53.0.10, DNSSEC validation off (the simulated zones are unsigned), at most 100,000 cache entries (Technitium's default is 10,000, ZenitiumDNS's 100,000), DNS-over-TLS on port 853 with the generated certificate, and the load networks are exempt from rate limiting (Technitium: `qpmLimitBypassList`, ZenitiumDNS: `rateLimitBypassList`). Everything else stays at the defaults of a new installation.

## Tests

| Result key | Test |
| ---------- | ---- |
| `idle_rss_mb` | Resident memory after start. |
| `cache_hits_40k_*` | 40,000 queries/s for 30 s over 5,000 names that are already cached (after 15 s warm-up). CPU time per query (user + system of the server process), latency percentiles, resident memory. |
| `cache_hits_max_*` | Offered 1,000,000 queries/s for 15 s; median of the answers per second in the 10-second intervals. |
| `dot_8k_*` | DNS-over-TLS, 8,000 queries/s for 30 s over 32 connections, names that are already cached. CPU time per answered query and latency percentiles. |
| `resolve_2k_*` | 2,000 queries/s for 30 s, every name new, so every query needs a recursive resolution via root and TLD. |
| `fill_1m_*` | Cache limit lifted, 20,000 new names per second for 50 s (1 million names). Answers, latency, cache entries and resident memory 20 s after the load. |
| `blocklist_*` | Block lists loaded; number of domains and resident memory 30 s after loading. |
| `blocked_40k_*` | 40,000 queries/s, half of them for blocked names, half for cached names. |

## Limits

The load comes from the same machine over the loopback device, so the numbers show the processing cost inside the server, not network effects. The simulated authoritative servers answer instantly; real resolution times depend on the internet. Laptop CPUs change their clock speed, so single runs vary; run each server several times, alternating, and compare medians.
