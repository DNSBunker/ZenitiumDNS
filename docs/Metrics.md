# Prometheus metrics

[Deutsche Version](Metrics.de.md)

ZenitiumDNS can serve detailed metrics in the [Prometheus text format](https://prometheus.io/docs/instrumenting/exposition_formats/) at `/metrics` on the web interface port. The endpoint is off by default. It is switched on under Settings > Web interface > Prometheus metrics.

The metrics contain neither client addresses nor domain names. Query types and response codes that ZenitiumDNS does not know are counted as `other`, so random values in queries cannot create new time series.

## Collection

The detailed counters are only collected while the endpoint is switched on. They start at zero when it is switched on and when the server starts; Prometheus treats that as a counter reset, `rate()` and `increase()` handle it. `zenitiumdns_metrics_start_time_seconds` shows when the collection started.

The server counts queries on the statistics thread, which processes every answered query anyway. The additional work is a few array increments per query and does not slow down answering. Queries to name servers and forwarders are counted with atomic increments where the query is sent.

## Access

| Setting | Default | Meaning |
| ------- | ------- | ------- |
| Serve metrics | off | Switches the endpoint and the detailed collection on. Switched off, `/metrics` returns 404. |
| Allowed networks (ACL) | `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` | Addresses that may read the metrics, one address or network per line. A leading `!` denies access. The list is evaluated from top to bottom; if it is empty or no entry matches, the answer is 403. |
| Bearer token | empty | If set, every scrape must send `Authorization: Bearer <token>`, otherwise the answer is 401. 16 to 255 visible ASCII characters; the button "Generate" creates a random token with 192 bits. |

Behind a reverse proxy, the ACL uses the client address from the client IP header (Settings > Web interface > Behind a reverse proxy), as for the rest of the web interface. If a scrape carries `X-Forwarded-For` or `Forwarded` but no usable client IP header from an allowed proxy, the endpoint cannot see the real client address. Without a token such scrapes are refused with 403, with a token they are accepted if the token is correct. On a server that is reachable from the internet, set a token or restrict the ACL to the address of the Prometheus server.

Sessions of the web interface do not grant access to `/metrics`. The JSON metrics under `api/dashboard/metrics/json` still require a session with permission to view the dashboard.

## Prometheus configuration

The settings page shows a ready-made entry with the address of the web interface and the token. Example:

```yaml
scrape_configs:
  - job_name: zenitiumdns
    scheme: https
    metrics_path: /metrics
    authorization:
      credentials: <token>
    static_configs:
      - targets: ["dns.example.com:53443"]
```

A scrape interval of 15 to 60 seconds is enough. A scrape takes a few milliseconds and returns 20 to 40 KB, and Prometheus receives it compressed with gzip.

## Metrics

### Server

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `zenitiumdns_build_info` | gauge | `version`, `runtime`, `arch` | Always 1; version of the package, .NET runtime and CPU architecture. |
| `zenitiumdns_start_time_seconds` | gauge | | Start of the DNS server as Unix time. |
| `zenitiumdns_uptime_seconds` | gauge | | Uptime of the DNS server. |
| `zenitiumdns_metrics_start_time_seconds` | gauge | | Start of the detailed collection as Unix time. |
| `zenitiumdns_clients` | gauge | | Estimated number of different client addresses since the start (HyperLogLog). |
| `zenitiumdns_dnssec_validation_enabled` | gauge | | 1 if DNSSEC validation is switched on. |
| `zenitiumdns_blocking_enabled` | gauge | | 1 if blocking is switched on. |
| `zenitiumdns_query_logging_suspended` | gauge | | 1 if the watchdog has paused the logging of queries for the rest of the day. |

### Queries from clients

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `zenitiumdns_requests_total` | counter | `protocol`, `family` | Received queries including dropped ones. `protocol`: `udp`, `tcp`, `tls`, `https`, `quic`, `udp_proxy`, `tcp_proxy`; `family`: `ipv4`, `ipv6` of the client. |
| `zenitiumdns_request_types_total` | counter | `type` | Queries per query type (`A`, `AAAA`, `HTTPS` …, unknown types as `other`). |
| `zenitiumdns_request_flags_total` | counter | `flag` | Queries with the flag or feature: `rd` (recursion desired), `cd` (checking disabled), `do` (DNSSEC OK), `edns`, `ecs` (EDNS Client Subnet). |
| `zenitiumdns_responses_total` | counter | `rcode` | Sent responses per response code (`NoError`, `NxDomain`, `ServerFailure`, `Refused` …). |
| `zenitiumdns_response_sources_total` | counter | `source` | Origin of the answer: `authoritative` (local zones, request filter, special names), `recursive`, `cached`, `blocked`, `upstream_blocked`, `upstream_blocked_cached`. |
| `zenitiumdns_response_flags_total` | counter | `flag` | Responses with the flag: `aa`, `tc` (truncated), `ad` (DNSSEC validated), `ra`. |
| `zenitiumdns_nodata_responses_total` | counter | | `NOERROR` responses without answer records. |
| `zenitiumdns_extended_errors_total` | counter | `code`, `name` | Responses with an Extended DNS Error (RFC 8914), for example `3` Stale Answer, `6` DNSSEC Bogus, `15` Blocked, `18` Prohibited, `22` No Reachable Authority, `29` Synthesized. Every code is counted at most once per response. |
| `zenitiumdns_dropped_total` | counter | `reason` | Queries without an answer: `rate_limited` (rate limiting) and `no_response` (request filter over UDP, apps such as Drop Requests, Do53 mode "DDR only", full resolver queue). |
| `zenitiumdns_request_duration_seconds` | histogram | `source` | Time from receiving a query until the response was sent, by `local`, `cache`, `recursive` and `blocked`. Buckets from 0.25 ms to 5 s. |
| `zenitiumdns_request_size_bytes` | histogram | `protocol` | Size of the queries. |
| `zenitiumdns_response_size_bytes` | histogram | `protocol` | Size of the sent responses, for DoT, DoH and DoQ including EDNS padding. |
| `zenitiumdns_queries_per_second` | gauge | `window` | Answered queries per second over the last `1m`, `5m` and `60m`. |
| `zenitiumdns_response_time_milliseconds` | gauge | `window`, `stat` | Response times over the window as on the dashboard: `avg`, `p50`, `p95`, `p99`, `max`, `cached_avg`, `recursive_avg`. |

Counted since the start of the server, even without the endpoint: `zenitiumdns_clients`, `zenitiumdns_queries_per_second` and `zenitiumdns_response_time_milliseconds`. All other counters in this table start with the detailed collection.

### Queries to name servers and forwarders

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `zenitiumdns_upstream_queries_total` | counter | `protocol`, `family` | Queries sent to authoritative name servers and forwarders. `family` is `unknown` for DoH forwarders given by name. Retries over UDP within the timeout count as one query. |
| `zenitiumdns_upstream_responses_total` | counter | `rcode` | Received responses per response code. |
| `zenitiumdns_upstream_errors_total` | counter | `reason` | Queries without a usable response: `timeout`, `network` (socket or connection errors), `invalid` (malformed or rejected responses), `canceled` (cancelled because another server answered first or the client gave up). |
| `zenitiumdns_upstream_truncated_total` | counter | | Truncated responses; the resolver then repeats the query over TCP. |
| `zenitiumdns_upstream_response_time_seconds` | histogram | `family` | Round trip time of the responses, buckets from 1 ms to 5 s. |
| `zenitiumdns_ipv6_upstream_available` | gauge | | 1 while queries to name servers over IPv6 are used, 0 while the IPv6 fallback has paused them. |

### Cache, filters and protection

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `zenitiumdns_cache_entries` | gauge | | Records in the cache. |
| `zenitiumdns_cache_max_entries` | gauge | | Configured maximum of the cache (0 = unlimited). |
| `zenitiumdns_aggressive_nsec_enabled` | gauge | | 1 if the aggressive use of the DNSSEC-validated cache (RFC 8198) is switched on. |
| `zenitiumdns_aggressive_nsec_entries` | gauge | | NSEC and NSEC3 records kept for it. |
| `zenitiumdns_aggressive_nsec_synthesized_total` | counter | | Negative answers synthesized from them. |
| `zenitiumdns_filter_domains` | gauge | `list` | Domains in `block_lists`, `allow_lists`, `blocked` (own blocked domains) and `allowed` (own allowed domains). |
| `zenitiumdns_forwarder_zones` | gauge | | Forwarder zones. |
| `zenitiumdns_request_filter_matches_total` | counter | `rule` | Queries dropped or refused by the request filter per rule. |
| `zenitiumdns_client_blocklist_drops_total` | counter | | Queries and connections dropped because of a client block list. |
| `zenitiumdns_client_blocklist_ranges` | gauge | | Address ranges loaded from client block lists. |
| `zenitiumdns_rate_limiter_tracked_clients` | gauge | | Client subnets currently tracked by the rate limiting. |

### Internal queues

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `zenitiumdns_queue_length` | gauge | `queue` | Waiting work items: `query` (query processing), `resolver` (recursive resolution), `stats` (statistics). |
| `zenitiumdns_pending_resolutions` | gauge | | Recursive resolutions in progress. |
| `zenitiumdns_stats_queue_dropped_total` | counter | | Statistics updates discarded because the statistics queue was full (100,000 entries). If this grows, the statistics and the counters above undercount. |

### Process and .NET runtime

| Metric | Type | Labels | Meaning |
| ------ | ---- | ------ | ------- |
| `process_cpu_seconds_total` | counter | | CPU time of the process. |
| `process_resident_memory_bytes` | gauge | | Resident memory (RSS). |
| `process_virtual_memory_bytes` | gauge | | Virtual address space; with .NET much larger than the memory in use. |
| `process_start_time_seconds` | gauge | | Start of the process as Unix time. |
| `process_threads` | gauge | | Operating system threads. |
| `process_open_fds`, `process_max_fds` | gauge | | Open file descriptors and their limit (Linux only). |
| `dotnet_gc_collections_total` | counter | `generation` | Garbage collections per generation. |
| `dotnet_gc_heap_size_bytes` | gauge | `generation` | Size of `gen0`, `gen1`, `gen2`, `loh` and `poh` after the last garbage collection. |
| `dotnet_gc_total_memory_bytes` | gauge | | Memory currently in use on the managed heap. |
| `dotnet_gc_committed_bytes` | gauge | | Memory committed by the garbage collector. |
| `dotnet_gc_fragmented_bytes` | gauge | | Free space inside the managed heap. |
| `dotnet_gc_allocated_bytes_total` | counter | | Allocated bytes since the start. |
| `dotnet_gc_pause_seconds_total` | counter | | Time the runtime was paused by garbage collections. |
| `dotnet_gc_pause_time_ratio` | gauge | | Share of the runtime spent in these pauses. |
| `dotnet_threadpool_threads`, `dotnet_threadpool_queue_length` | gauge | | Thread pool threads and waiting work items. |
| `dotnet_threadpool_completed_items_total` | counter | | Completed work items. |
| `dotnet_monitor_lock_contentions_total` | counter | | Contended lock acquisitions. |
| `dotnet_timers` | gauge | | Active timers. |

## Example queries

```promql
# queries per second by protocol
sum by (protocol) (rate(zenitiumdns_requests_total[5m]))

# cache hit rate
rate(zenitiumdns_response_sources_total{source="cached"}[5m])
  / ignoring(source) sum without(source) (rate(zenitiumdns_response_sources_total[5m]))

# 99th percentile of the response time for recursive resolution
histogram_quantile(0.99, sum by (le) (rate(zenitiumdns_request_duration_seconds_bucket{source="recursive"}[5m])))

# share of SERVFAIL answers
rate(zenitiumdns_responses_total{rcode="ServerFailure"}[5m]) / ignoring(rcode) sum without(rcode) (rate(zenitiumdns_responses_total[5m]))

# timeouts of name servers per second
rate(zenitiumdns_upstream_errors_total{reason="timeout"}[5m])

# DNSSEC validation failures
rate(zenitiumdns_extended_errors_total{name="DnssecBogus"}[5m])
```

## Settings file

The three settings are stored in `webservice.config`, whose format version is 7 since package 15.5.1-10. Older versions of ZenitiumDNS cannot read this file; version 6 and older are read with the endpoint switched off.
