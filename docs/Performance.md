# Performance compared with Technitium DNS Server

[Deutsche Version](Performance.de.md)

ZenitiumDNS is a fork of Technitium DNS Server 15.5.1. This document shows what the fork changes in terms of speed and memory, with measurements anyone can repeat, and names the code changes behind them. It also lists where ZenitiumDNS is not better.

## Summary

Measured on the same machine, with the same .NET runtime, the same settings and the same load, against the current release Technitium DNS Server 15.5.1 (medians of three runs each):

- **CPU time per query 54 to 70 % lower**: 10.2 instead of 31.2 µs for answers from the cache, 11.2 instead of 37.7 µs when half of the queries hit block lists, 56 instead of 122 µs over DNS-over-TLS and 385 instead of 837 µs per recursive resolution.
- **About twice the throughput** on four logical CPUs: 500,000 instead of 251,000 answers per second from the cache.
- **Keeps up with many new names**: at 20,000 new names per second, ZenitiumDNS answered all queries with a mean latency of 0.5 ms; Technitium answered 88 % with a mean latency of 1.1 seconds, the rest were lost.
- **81 % less memory per cached name** (about 0.8 instead of 4.3 KB) and **60 % less memory for block lists** (216 instead of 537 MB for 2.5 million domains).
- **No lock contention** in recursive resolution and over DNS-over-TCP, DoT and DoQ (details below); the original design caused hundreds to thousands of contended locks per second. On a server with 8 CPUs, 700 queries per second needed 2.42 ms of CPU time per query before and 0.46 ms now.
- **Lower median latency** in every test and lower tail latency for recursive resolution (99th percentile 2.5 instead of 3.6 ms), but **higher 99th and 99.9th percentiles for answers from the cache** (365 instead of 265 µs and 1.0 instead of 0.7 ms).

## Results

Machine: Intel Core i7-12700H (laptop, 6 performance and 8 efficiency cores, 20 logical CPUs), 64 GB RAM, Fedora 44, Linux 7.2.7, .NET 10.0.12 for both servers. The DNS server was pinned to 4 logical CPUs (two performance cores), the load generators to 8 other logical CPUs. Technitium DNS Server 15.5.1 is the portable build from download.technitium.com (1 October 2026), ZenitiumDNS is the development state after release 15.5.1-11 including the changes described under [Lock contention](#lock-contention). Each server ran three times, alternating. The raw results are in [performance-data/2026-10-01](performance-data/2026-10-01).

| Measurement (median of 3 runs each) | Technitium 15.5.1 | ZenitiumDNS | Change |
| --- | ---: | ---: | ---: |
| Resident memory after start (MB) | 113 | 115 | +2 % |
| Cache hits, 40,000 queries/s: CPU time per query (µs) | 31.2 | 10.2 | −67 % |
| Cache hits, 40,000 queries/s: median latency (µs) | 135 | 125 | −7 % |
| Cache hits, 40,000 queries/s: 99th percentile (µs) | 265 | 365 | +38 % |
| Cache hits, 40,000 queries/s: 99.9th percentile (µs) | 675 | 1,015 | see below |
| Cache hits: maximum answers per second | 251,105 | 499,532 | +99 % |
| DNS-over-TLS cache hits, 8,000 queries/s: CPU time per query (µs) | 121.7 | 56.2 | −54 % |
| DNS-over-TLS cache hits, 8,000 queries/s: median latency (µs) | 135 | 75 | −44 % |
| DNS-over-TLS cache hits, 8,000 queries/s: 99th percentile (µs) | 935 | 935 | ±0 % |
| Recursive resolution, 2,000 new names/s: CPU time per query (µs) | 837 | 385 | −54 % |
| Recursive resolution, 2,000 new names/s: median latency (µs) | 225 | 215 | −4 % |
| Recursive resolution, 2,000 new names/s: 99th percentile (µs) | 3,635 | 2,495 | −31 % |
| Recursive resolution, 2,000 new names/s: 99.9th percentile (µs) | 7,985 | 5,225 | −35 % |
| 20,000 new names/s for 50 s: answered queries (of 1 million) | 883,110 | 999,991 | +13 % |
| 20,000 new names/s for 50 s: mean latency (ms) | 1,137.8 | 0.5 | −100 % |
| 20,000 new names/s for 50 s: resident memory (MB) | 3,947 | 894 | −77 % |
| 20,000 new names/s for 50 s: memory per cached name (bytes) | 4,262 | 817 | −81 % |
| Block lists HaGeZi Pro + TIF, 2,493,399 domains: resident memory (MB) | 537 | 216 | −60 % |
| 50 % blocked names, 40,000 queries/s: CPU time per query (µs) | 37.7 | 11.2 | −70 % |
| 50 % blocked names, 40,000 queries/s: median latency (µs) | 145 | 115 | −21 % |
| 50 % blocked names, 40,000 queries/s: 99th percentile (µs) | 335 | 325 | −3 % |

For the maximum throughput the load generators offered 622,000 to 750,000 queries per second in every run, more than either server answered.

"20,000 new names/s" is the hardest test for a resolver: every query needs a recursive resolution and a new cache entry. Technitium could not keep up on four CPUs; its queue filled, latency rose to about one second, and 3.5 to 12 % of the queries went unanswered. At the same time it used only about half of the four CPUs. ZenitiumDNS answered every query. The CPU time per query is therefore not comparable in this test and is left out.

The DNS-over-TLS test sends 8,000 queries per second over 32 connections with pipelining to names that are already cached; the load generator is `tools/benchmark/tlsload`.

## Lock contention

On a production server, the live graph of ZenitiumDNS 15.5.1-11 showed about 400 contended lock acquisitions per second at a median of 700 queries per second. Contention traces (`dotnet-trace`, contention events with stacks) pointed to two parts that ZenitiumDNS had taken over from the original:

1. **Pool for recursive resolutions.** The original runs one waiting loop per allowed concurrent resolution (by default 100 per CPU, 400 on four CPUs) on a .NET channel. Every new resolution wakes *all* waiting loops; one gets the work, all others take the channel's lock, find nothing and register again with a new allocation. ZenitiumDNS replaces this with a lock-free limit (a queue and a counter) that starts resolutions directly on the .NET thread pool.
2. **Own scheduler for DNS-over-TCP, DoT and DoQ.** Completed reads on these connections arrive on a thread pool thread anyway and were then handed to an own thread through a semaphore under a lock. These connections now run on the thread pool, like DNS-over-HTTPS (Kestrel) already did; the scheduler was removed.

Contended lock acquisitions per second on four CPUs (live graph and `dotnet_monitor_lock_contentions_total`):

| Load | 15.5.1-11 | now |
| --- | ---: | ---: |
| UDP, 700 queries/s, all from the cache | 1.4 | 0.0 |
| UDP, 700 new names/s (recursive resolution) | 287 | 0.0 |
| UDP, 5,000 new names/s | 2,537 | 0.6 |
| DNS-over-HTTPS, 700 queries/s, 30 % new names | 145 | 0.2 |
| DNS-over-TLS, 700 queries/s, all from the cache | 152 | 0.0–0.1 |
| DNS-over-TLS, 700 queries/s, 30 % new names | 232 | 0.0–0.1 |
| DNS-over-TLS, 8,000 queries/s, all from the cache | 1,357–1,592 | 0.6–0.7 |

The contention was not only a number on a graph: in direct comparisons on the same machine, the CPU time per recursive resolution dropped from 637–644 to 372–379 µs, and per DNS-over-TLS query at 8,000 queries per second from 102–115 to 60–63 µs.

On a server with more CPUs the effect is larger, because the original starts 100 waiting loops per CPU. The test server (Debian 13 container with 8 logical CPUs on Proxmox, the same package once as 15.5.1-11 and once with these changes) received 700 queries per second for nonexistent top-level domains for one minute, which the local root zone answers without any query to the internet, so each query goes through the resolver:

| 8 CPUs, 700 queries/s | 15.5.1-11 | now |
| --- | ---: | ---: |
| Contended locks per second | 1,700–2,170 | 0–0.2 |
| CPU time per query | 2.42 ms | 0.46 ms |
| Work items of the .NET thread pool per second | about 553,000 | about 1,400 |
| Latency: median / 99th / 99.9th percentile | 426 µs / 2.5 ms / 8.9 ms | 166 µs / 463 µs / 5.4 ms |
| Share of time in garbage collection pauses | about 2 % | about 0.1 % |

553,000 work items per second are 700 resolutions times the 800 waiting loops that each of them woke up.

## Tail latency

### Answers from the cache

The 99th and 99.9th percentiles of answers from the cache are the one area where ZenitiumDNS measured worse. The single runs vary a lot:

| Cache hits, 40,000 queries/s | Median | 99th percentile | 99.9th percentile |
| --- | ---: | ---: | ---: |
| Technitium, run 1 / 2 / 3 | 135 / 135 / 145 µs | 245 / 265 / 285 µs | 635 / 675 / 875 µs |
| ZenitiumDNS, run 1 / 2 / 3 | 125 / 105 / 125 µs | 445 / 255 / 365 µs | 1,225 / 635 / 1,015 µs |

Of 1,000 answers, about one takes longer than 1 ms. A per-second timeline shows that these are spread over the whole run and not tied to a single event. Three explanations were tested and ruled out:

- **Garbage collection mode**: with Workstation GC instead of Server GC the percentiles stayed the same (99.9th percentile 935–1,145 µs against 995–1,125 µs).
- **UDP receive threads**: ZenitiumDNS answers with one receive thread per socket and wakes further threads only on a sustained backlog. Waking them after 4 or even 1 backlogged packet instead of 16 doubled the CPU time per query (17–22 µs) and made the 99th percentile worse, not better.
- **Time slice of the Linux scheduler**: since Linux 6.12 a thread can ask for a shorter time slice (`sched_setattr` with `sched_runtime`). Receive threads with a 0.1 ms slice, alone or together with a lower priority (nice 5) for the statistics thread, gave a 99th percentile of 385–575 µs and a 99.9th percentile of 955–4,885 µs in three alternating runs per variant, the same range as without. The change was not adopted.

For a DNS resolver, the extra time is well below the round trip time of a client on a network (usually several milliseconds). It is nevertheless listed here because it is a measurable difference.

### Recursive resolution

Removing the waiting loops (see [Lock contention](#lock-contention)) also removed most of the garbage they produced. The .NET runtime, which at this load works with a single collector heap (DATAS), then collected the youngest generation only every 1.8 seconds and had to copy about 3 MB of new cache entries each time, which paused the process for 15 to 35 ms. At 2,000 new names per second, the 99.9th percentile rose to 30–40 ms. The runtime settings for the budget of the youngest generation (`GCgen0size`, `GCgen0MaxBudget`, `GCDTargetTCP`) have no effect in this mode; without DATAS there was one collection every 10 seconds with 12 MB and 20 ms.

ZenitiumDNS therefore starts a short collection of the youngest generation as soon as 150 new cache entries were created since the last collection (checked every 50 ms). Each pause then copies only a few hundred kilobytes. Three alternating runs per variant at 2,000 new names per second:

| Recursive resolution, 2,000 new names/s | 15.5.1-11 | without pacing | every 300 entries, checked every 100 ms | every 150 entries, checked every 50 ms (adopted) |
| --- | ---: | ---: | ---: | ---: |
| 99th percentile | 2.9–3.2 ms | 4.1–6.1 ms | 3.4–4.2 ms | 2.3–2.4 ms |
| 99.9th percentile | 5.0–11.0 ms | 31–39 ms | 6.7–9.2 ms | 4.2–5.7 ms |
| CPU time per resolution | 637–644 µs | 358–373 µs | 345–361 µs | 372–379 µs |

The number of these collections is exported as `zenitiumdns_gc_paced_collections_total`. Without new cache entries (answers from the cache, a full cache, cache switched off) no extra collections run.

## What changed in the code

The differences above come from changes in the query path, the cache, the block lists and the statistics. The most important ones with the files involved:

| Area | Change | Files |
| ---- | ------ | ----- |
| UDP receive path | Dedicated receive threads (at most 8 per socket, adjustable up to 64) answer cache hits on the receiving thread, without handing over to the thread pool; further threads are only woken on a sustained backlog. Responses are sent synchronously with reused send buffers. | `src/ZenitiumDns.Core/Dns/DnsServer.cs` (`StartUdpListenerThreads`, `ReadUdpRequests`), `Dns/UdpListenerGate.cs`, `Dns/UdpSendBuffers.cs` |
| Recursive resolutions | Lock-free limit of concurrent resolutions instead of hundreds of waiting loops that were all woken for every resolution; resolutions start directly on the .NET thread pool. | `src/ZenitiumLibrary/TaskPool.cs`, `Dns/DnsServer.cs` |
| DNS-over-TCP, DoT, DoQ | Connections run on the .NET thread pool instead of an own scheduler with a lock in every handover. | `Dns/DnsServer.cs` |
| Allocations in the query path | `ValueTask` along the processing chain, name compression without copies, no temporary strings for the special zone check, no boxed enumerators in hot loops, last-used times written at most once per second. About 1 KB instead of 2.9 KB allocated per cache hit. | `Dns/DnsServer.cs`, `src/ZenitiumLibrary.Net/Dns/`, `Dns/ResourceRecords/CacheRecordInfo.cs` |
| Statistics | Queries go through a lock-free queue to one consumer thread instead of being counted under locks in the query path; unique clients are counted with HyperLogLog; completed minutes keep only the top 1,000 entries. | `Dns/StatsManager.cs`, `Dns/UniqueAddressCounter.cs` |
| Cache layout | Records of a name in a small copy-on-write array instead of a concurrent dictionary per name, shared name server metadata, domain tree nodes with exactly sized child arrays (up to 8 children) instead of 41 slots, no second raw copy of A, AAAA and RRSIG data. | `Dns/Zones/CacheZone.cs`, `Dns/Zones/CacheEntrySet.cs`, `src/ZenitiumLibrary.ByteTree/ByteTree.cs`, `src/ZenitiumLibrary.Net/Dns/ResourceRecords/` |
| Block lists | Domains stored as ASCII in 1 MB blocks with an open-addressing hash table of 8-byte slots instead of millions of strings in dictionaries; one shared rule set for all client profiles. | `Dns/ZoneManagers/DomainTable.cs`, `Dns/ZoneManagers/ListRuleSet.cs` |
| Garbage collection | The original ran a blocking full garbage collection every minute in the cache maintenance (upstream issue #2174); ZenitiumDNS uses background collections there. Short collections of the youngest generation after 150 new cache entries keep single pauses short. Server GC with concurrent collection. | `Dns/ZoneManagers/CacheZoneManager.cs`, `src/ZenitiumDns/ZenitiumDns.csproj` |
| Fewer upstream queries | Prefetch only in the last tenth of the TTL (24 client queries caused 24 upstream queries in the original, 2 in ZenitiumDNS), aggressive use of DNSSEC-validated NSEC/NSEC3 (20,000 random subdomains of a signed zone caused 30 to 48 instead of 20,000 upstream queries), IPv6 fallback without timeouts, local root zone copy (RFC 8806). | `Dns/ZoneManagers/CacheZoneManager.cs`, `Dns/AggressiveNsecCache.cs`, `Dns/IanaDataManager.cs` |
| Memory protection | The cache stops growing at 85 % of the system memory, the service or container limit or the .NET heap limit and is cut from 90 %, instead of running into an out-of-memory crash. | `Dns/MemoryPressure.cs`, `Dns/ZoneManagers/CacheZoneManager.cs` |

## Earlier measurements

During development, ZenitiumDNS was also measured with `dnsperf` on 20 CPUs against Technitium DNS Server 15.5 ([CHANGELOG-ZenitiumDNS.md](../CHANGELOG-ZenitiumDNS.md#measurements)). Those numbers point the same way: CPU time per query at 100,000 queries/s 23.6 instead of 85.8 µs, allocations per cache hit about 1.0 instead of 2.9 KB, time in garbage collection under full load 7 instead of 22 %, lock contentions per second 41 instead of 1,798. With 20 CPUs the peak throughput was only 5 to 12 % higher, because the load generator and the network stack of a single machine become the limit there.

## Repeating the measurements

The load generators, the simulated root and top-level domain servers and the script are in [tools/benchmark](../tools/benchmark/README.md). A run takes about five to eight minutes per server:

```
unshare -rnm bash tools/benchmark/bench.sh zenitiumdns zenitiumdns /path/to/zenitiumdns /path/to/lists
unshare -rnm bash tools/benchmark/bench.sh technitium technitium /path/to/technitium /path/to/lists
python3 tools/benchmark/summarize.py Technitium tools/benchmark/results/technitium/results.txt -- ZenitiumDNS tools/benchmark/results/zenitiumdns/results.txt
```

Both servers get the same settings: DNSSEC validation off (the simulated zones are unsigned), 100,000 cache entries (Technitium's default is 10,000), DNS-over-TLS with a self-signed certificate, and the load networks exempt from rate limiting. Everything else stays at the defaults of a new installation.

## Limits of these measurements

- The load comes from the same machine over the loopback device; the numbers show processing cost inside the server, not network effects.
- The simulated authoritative servers answer immediately. On the internet, recursive resolution is dominated by the round trip times to real name servers.
- A laptop CPU changes its clock speed; single runs vary, especially in the tail percentiles. Compare medians of several alternating runs.
- DNS-over-TLS is measured with answers from the cache at a fixed rate. DNS-over-HTTPS and DNS-over-QUIC are not part of the comparison; the lock contention figures for DNS-over-HTTPS come from the separate measurement above.
