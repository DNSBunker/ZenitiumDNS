/*
ZenitiumDNS
Copyright (C) 2026  xRuffKez

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumDns.ApplicationCommon;
using ZenitiumDns.Core.Dhcp;
using ZenitiumDns.Core.Dns;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.EDnsOptions;

namespace ZenitiumDns.Core
{
    public partial class DnsWebService
    {
        sealed class WebServiceMetricsApi
        {
            #region variables

            const string CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8";

            static readonly int[] _windowMinutes = [1, 5, 60];

            readonly DnsWebService _dnsWebService;

            #endregion

            #region constructor

            public WebServiceMetricsApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

            private static string GetBearerToken(HttpRequest request)
            {
                foreach (string value in request.Headers.Authorization)
                {
                    if ((value is not null) && value.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                        return value.Substring(7).Trim();
                }

                return null;
            }

            private bool IsProxiedWithoutClientAddress(HttpContext context)
            {
                HttpRequest request = context.Request;

                if (!request.Headers.ContainsKey("X-Forwarded-For") && !request.Headers.ContainsKey("Forwarded"))
                    return false;

                IPAddress remoteIP = context.Connection.RemoteIpAddress;
                if ((remoteIP is not null) && remoteIP.IsIPv4MappedToIPv6)
                    remoteIP = remoteIP.MapToIPv4();

                if ((remoteIP is not null) && !NetworkAccessControl.IsAddressAllowed(remoteIP, _dnsWebService._webServiceReverseProxyAddresses))
                    return true;

                return string.IsNullOrEmpty(_dnsWebService._webServiceRealIpHeader) || !IPAddress.TryParse(request.Headers[_dnsWebService._webServiceRealIpHeader], out _);
            }

            private int CheckAccess(HttpContext context)
            {
                IPAddress remoteAddress = _dnsWebService.GetRemoteEndPoint(context).Address;

                if (!NetworkAccessControl.IsAddressAllowed(remoteAddress, _dnsWebService._metricsAllowedNetworks))
                    return StatusCodes.Status403Forbidden;

                string token = _dnsWebService._metricsToken;

                if (token is null)
                    return IsProxiedWithoutClientAddress(context) ? StatusCodes.Status403Forbidden : StatusCodes.Status200OK;

                string presentedToken = GetBearerToken(context.Request);
                if (presentedToken is null)
                    return StatusCodes.Status401Unauthorized;

                if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(presentedToken), Encoding.UTF8.GetBytes(token)))
                    return StatusCodes.Status401Unauthorized;

                return StatusCodes.Status200OK;
            }

            private static double ToUnixSeconds(DateTime dateTime)
            {
                return Math.Round((dateTime.ToUniversalTime() - DateTime.UnixEpoch).TotalSeconds, 3);
            }

            private static void WriteProcessMetrics(MetricsWriter w)
            {
                w.Header("process_cpu_seconds_total", "counter", "Total user and system CPU time spent in seconds");
                w.Sample("process_cpu_seconds_total", Environment.CpuUsage.TotalTime.TotalSeconds);

                w.Header("process_resident_memory_bytes", "gauge", "Resident memory size in bytes");
                w.Sample("process_resident_memory_bytes", Environment.WorkingSet);

                using (Process process = Process.GetCurrentProcess())
                {
                    w.Header("process_virtual_memory_bytes", "gauge", "Virtual memory size in bytes");
                    w.Sample("process_virtual_memory_bytes", process.VirtualMemorySize64);

                    w.Header("process_start_time_seconds", "gauge", "Start time of the process since unix epoch in seconds");
                    w.Sample("process_start_time_seconds", ToUnixSeconds(process.StartTime));

                    w.Header("process_threads", "gauge", "Number of operating system threads");
                    w.Sample("process_threads", process.Threads.Count);
                }

                if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                {
                    try
                    {
                        long openFds = Directory.EnumerateFileSystemEntries("/proc/self/fd").LongCount();

                        w.Header("process_open_fds", "gauge", "Number of open file descriptors");
                        w.Sample("process_open_fds", openFds);
                    }
                    catch
                    { }

                    try
                    {
                        foreach (string line in File.ReadLines("/proc/self/limits"))
                        {
                            if (!line.StartsWith("Max open files", StringComparison.Ordinal))
                                continue;

                            string[] parts = line.Substring(14).Split(' ', StringSplitOptions.RemoveEmptyEntries);
                            if ((parts.Length > 0) && long.TryParse(parts[0], NumberStyles.None, CultureInfo.InvariantCulture, out long maxFds))
                            {
                                w.Header("process_max_fds", "gauge", "Maximum number of open file descriptors");
                                w.Sample("process_max_fds", maxFds);
                            }

                            break;
                        }
                    }
                    catch
                    { }
                }

                w.Header("dotnet_gc_collections_total", "counter", "Number of garbage collections per generation");
                for (int generation = 0; generation <= GC.MaxGeneration; generation++)
                    w.Sample("dotnet_gc_collections_total", GC.CollectionCount(generation), "generation", "gen" + generation.ToString(CultureInfo.InvariantCulture));

                GCMemoryInfo gcInfo = GC.GetGCMemoryInfo();

                w.Header("dotnet_gc_heap_size_bytes", "gauge", "Size of each heap generation after the last garbage collection");
                {
                    string[] generationNames = ["gen0", "gen1", "gen2", "loh", "poh"];
                    ReadOnlySpan<GCGenerationInfo> generationInfo = gcInfo.GenerationInfo;

                    for (int i = 0; (i < generationInfo.Length) && (i < generationNames.Length); i++)
                        w.Sample("dotnet_gc_heap_size_bytes", generationInfo[i].SizeAfterBytes, "generation", generationNames[i]);
                }

                w.Header("dotnet_gc_total_memory_bytes", "gauge", "Bytes currently thought to be allocated on the managed heap");
                w.Sample("dotnet_gc_total_memory_bytes", GC.GetTotalMemory(false));

                w.Header("dotnet_gc_committed_bytes", "gauge", "Memory committed by the garbage collector");
                w.Sample("dotnet_gc_committed_bytes", gcInfo.TotalCommittedBytes);

                w.Header("dotnet_gc_fragmented_bytes", "gauge", "Free space inside the managed heap after the last garbage collection");
                w.Sample("dotnet_gc_fragmented_bytes", gcInfo.FragmentedBytes);

                w.Header("dotnet_gc_allocated_bytes_total", "counter", "Bytes allocated on the managed heap since process start");
                w.Sample("dotnet_gc_allocated_bytes_total", GC.GetTotalAllocatedBytes(false));

                w.Header("dotnet_gc_pause_seconds_total", "counter", "Total time the runtime was paused by garbage collections");
                w.Sample("dotnet_gc_pause_seconds_total", GC.GetTotalPauseDuration().TotalSeconds);

                w.Header("dotnet_gc_pause_time_ratio", "gauge", "Share of time spent paused by garbage collection since process start");
                w.Sample("dotnet_gc_pause_time_ratio", gcInfo.PauseTimePercentage / 100d);

                w.Header("dotnet_threadpool_threads", "gauge", "Number of thread pool threads");
                w.Sample("dotnet_threadpool_threads", ThreadPool.ThreadCount);

                w.Header("dotnet_threadpool_queue_length", "gauge", "Work items queued in the thread pool");
                w.Sample("dotnet_threadpool_queue_length", ThreadPool.PendingWorkItemCount);

                w.Header("dotnet_threadpool_completed_items_total", "counter", "Work items completed by the thread pool");
                w.Sample("dotnet_threadpool_completed_items_total", ThreadPool.CompletedWorkItemCount);

                w.Header("dotnet_monitor_lock_contentions_total", "counter", "Contended lock acquisitions");
                w.Sample("dotnet_monitor_lock_contentions_total", Monitor.LockContentionCount);

                w.Header("dotnet_timers", "gauge", "Number of active timers");
                w.Sample("dotnet_timers", Timer.ActiveCount);
            }

            private static void WriteDetailedMetrics(MetricsWriter w, ServerMetrics metrics)
            {
                w.Header("zenitiumdns_metrics_start_time_seconds", "gauge", "Time the detailed metrics collection started since unix epoch in seconds");
                w.Sample("zenitiumdns_metrics_start_time_seconds", ToUnixSeconds(metrics.Since));

                w.Header("zenitiumdns_requests_total", "counter", "Requests received per transport protocol and client address family, including dropped requests");
                for (int p = 0; p < ServerMetrics.PROTOCOL_COUNT; p++)
                {
                    for (int f = 0; f < ServerMetrics.FAMILY_COUNT; f++)
                    {
                        long value = metrics.GetRequests(p, f);
                        if ((value > 0) || (p == 0))
                            w.Sample("zenitiumdns_requests_total", value, "protocol", ServerMetrics.ProtocolNames[p], "family", ServerMetrics.FamilyNames[f]);
                    }
                }

                w.Header("zenitiumdns_request_types_total", "counter", "Requests per query type");
                {
                    IReadOnlyList<long> types = metrics.Types;
                    IReadOnlyList<string> typeNames = ServerMetrics.TypeNames;

                    for (int i = 0; i < types.Count; i++)
                    {
                        long value = types[i];
                        if (value > 0)
                            w.Sample("zenitiumdns_request_types_total", value, "type", typeNames[i]);
                    }
                }

                w.Header("zenitiumdns_request_flags_total", "counter", "Requests with the given header flag or EDNS feature");
                for (int i = 0; i < ServerMetrics.RequestFlagNames.Length; i++)
                    w.Sample("zenitiumdns_request_flags_total", metrics.RequestFlags[i], "flag", ServerMetrics.RequestFlagNames[i]);

                w.Header("zenitiumdns_responses_total", "counter", "Responses sent per response code");
                {
                    IReadOnlyList<long> rcodes = metrics.Rcodes;
                    IReadOnlyList<string> rcodeNames = ServerMetrics.RcodeNames;

                    for (int i = 0; i < rcodes.Count; i++)
                    {
                        long value = rcodes[i];
                        if ((value > 0) || (i < 6))
                            w.Sample("zenitiumdns_responses_total", value, "rcode", rcodeNames[i]);
                    }
                }

                w.Header("zenitiumdns_response_sources_total", "counter", "Responses per source of the answer");
                w.Sample("zenitiumdns_response_sources_total", metrics.GetSource(DnsServerResponseType.Authoritative), "source", "authoritative");
                w.Sample("zenitiumdns_response_sources_total", metrics.GetSource(DnsServerResponseType.Recursive), "source", "recursive");
                w.Sample("zenitiumdns_response_sources_total", metrics.GetSource(DnsServerResponseType.Cached), "source", "cached");
                w.Sample("zenitiumdns_response_sources_total", metrics.GetSource(DnsServerResponseType.Blocked), "source", "blocked");
                w.Sample("zenitiumdns_response_sources_total", metrics.GetSource(DnsServerResponseType.UpstreamBlocked), "source", "upstream_blocked");
                w.Sample("zenitiumdns_response_sources_total", metrics.GetSource(DnsServerResponseType.UpstreamBlockedCached), "source", "upstream_blocked_cached");

                w.Header("zenitiumdns_response_flags_total", "counter", "Responses with the given header flag");
                for (int i = 0; i < ServerMetrics.ResponseFlagNames.Length; i++)
                    w.Sample("zenitiumdns_response_flags_total", metrics.ResponseFlags[i], "flag", ServerMetrics.ResponseFlagNames[i]);

                w.Header("zenitiumdns_nodata_responses_total", "counter", "NOERROR responses without answer records");
                w.Sample("zenitiumdns_nodata_responses_total", metrics.NoData);

                w.Header("zenitiumdns_extended_errors_total", "counter", "Responses carrying the given Extended DNS Error code (RFC 8914)");
                {
                    IReadOnlyList<long> extendedErrors = metrics.ExtendedErrors;

                    for (int i = 0; i < ServerMetrics.EDE_CODE_LIMIT; i++)
                    {
                        long value = extendedErrors[i];
                        if (value > 0)
                        {
                            EDnsExtendedDnsErrorCode code = (EDnsExtendedDnsErrorCode)i;
                            w.Sample("zenitiumdns_extended_errors_total", value, "code", i.ToString(CultureInfo.InvariantCulture), "name", Enum.IsDefined(code) ? code.ToString() : "Unassigned");
                        }
                    }

                    if (extendedErrors[ServerMetrics.EDE_CODE_LIMIT] > 0)
                        w.Sample("zenitiumdns_extended_errors_total", extendedErrors[ServerMetrics.EDE_CODE_LIMIT], "code", "other", "name", "Other");
                }

                w.Header("zenitiumdns_dropped_total", "counter", "Requests that were not answered");
                for (int i = 0; i < ServerMetrics.DropReasonNames.Length; i++)
                    w.Sample("zenitiumdns_dropped_total", metrics.Drops[i], "reason", ServerMetrics.DropReasonNames[i]);

                w.Header("zenitiumdns_request_duration_seconds", "histogram", "Time from receiving a request until the response was sent");
                for (int i = 0; i < ServerMetrics.LATENCY_GROUP_COUNT; i++)
                    w.Histogram("zenitiumdns_request_duration_seconds", metrics.Duration[i], ServerMetrics.DurationBucketsMs, 1000d, true, "source", ServerMetrics.LatencyGroupNames[i]);

                w.Header("zenitiumdns_request_size_bytes", "histogram", "Size of requests in bytes");
                for (int i = 0; i < ServerMetrics.PROTOCOL_COUNT; i++)
                    w.Histogram("zenitiumdns_request_size_bytes", metrics.RequestSize[i], ServerMetrics.SizeBuckets, i == 0, "protocol", ServerMetrics.ProtocolNames[i]);

                w.Header("zenitiumdns_response_size_bytes", "histogram", "Size of responses in bytes");
                for (int i = 0; i < ServerMetrics.PROTOCOL_COUNT; i++)
                    w.Histogram("zenitiumdns_response_size_bytes", metrics.ResponseSize[i], ServerMetrics.SizeBuckets, i == 0, "protocol", ServerMetrics.ProtocolNames[i]);
            }

            private static void WriteUpstreamMetrics(MetricsWriter w)
            {
                w.Header("zenitiumdns_upstream_queries_total", "counter", "Queries sent to name servers and forwarders per transport protocol and address family");
                for (int p = 0; p < DnsClientMetrics.PROTOCOL_COUNT; p++)
                {
                    for (int f = 0; f < DnsClientMetrics.FAMILY_COUNT; f++)
                    {
                        long value = DnsClientMetrics.GetQueries(p, f);
                        if ((value > 0) || ((p == 0) && (f < 2)))
                            w.Sample("zenitiumdns_upstream_queries_total", value, "protocol", DnsClientMetrics.GetProtocolName(p), "family", DnsClientMetrics.GetFamilyName(f));
                    }
                }

                w.Header("zenitiumdns_upstream_responses_total", "counter", "Responses received from name servers and forwarders per response code");
                {
                    long other = 0;

                    for (int i = 0; i < DnsClientMetrics.RCODE_COUNT; i++)
                    {
                        long value = DnsClientMetrics.GetResponses(i);
                        DnsResponseCode rcode = (DnsResponseCode)i;

                        if ((i < DnsClientMetrics.RCODE_COUNT - 1) && Enum.IsDefined(rcode))
                        {
                            if ((value > 0) || (i < 6))
                                w.Sample("zenitiumdns_upstream_responses_total", value, "rcode", rcode.ToString());
                        }
                        else
                        {
                            other += value;
                        }
                    }

                    if (other > 0)
                        w.Sample("zenitiumdns_upstream_responses_total", other, "rcode", "other");
                }

                w.Header("zenitiumdns_upstream_errors_total", "counter", "Queries to name servers and forwarders that failed without a usable response");
                w.Sample("zenitiumdns_upstream_errors_total", DnsClientMetrics.GetErrors(DnsClientMetricsError.Timeout), "reason", "timeout");
                w.Sample("zenitiumdns_upstream_errors_total", DnsClientMetrics.GetErrors(DnsClientMetricsError.Network), "reason", "network");
                w.Sample("zenitiumdns_upstream_errors_total", DnsClientMetrics.GetErrors(DnsClientMetricsError.Invalid), "reason", "invalid");
                w.Sample("zenitiumdns_upstream_errors_total", DnsClientMetrics.GetErrors(DnsClientMetricsError.Canceled), "reason", "canceled");

                w.Header("zenitiumdns_upstream_truncated_total", "counter", "Truncated responses received from name servers and forwarders");
                w.Sample("zenitiumdns_upstream_truncated_total", DnsClientMetrics.Truncated);

                w.Header("zenitiumdns_qname_minimization_fallbacks_total", "counter", "Minimized queries that were repeated with a longer or the full name because the name server answered incorrectly or not at all");
                w.Sample("zenitiumdns_qname_minimization_fallbacks_total", QnameMinimizationFallback.Fallbacks);

                w.Header("zenitiumdns_qname_minimization_fallback_zones", "gauge", "Zones currently queried without QNAME minimization because their name servers mishandled it");
                w.Sample("zenitiumdns_qname_minimization_fallback_zones", QnameMinimizationFallback.Zones);

                w.Header("zenitiumdns_qname_minimization_skipped_total", "counter", "Resolutions that skipped QNAME minimization for a remembered zone");
                w.Sample("zenitiumdns_qname_minimization_skipped_total", QnameMinimizationFallback.Skipped);

                w.Header("zenitiumdns_upstream_cookies_sent_total", "counter", "Queries to name servers and forwarders that carried a DNS cookie since start");
                w.Sample("zenitiumdns_upstream_cookies_sent_total", DnsCookie.ClientCookiesSent);

                w.Header("zenitiumdns_upstream_cookie_errors_total", "counter", "Responses discarded because the DNS cookie was wrong or missing from a server that supports cookies");
                w.Sample("zenitiumdns_upstream_cookie_errors_total", DnsCookie.ClientCookieMismatches);

                w.Header("zenitiumdns_upstream_cookie_servers", "gauge", "Name servers whose server cookie is currently known");
                w.Sample("zenitiumdns_upstream_cookie_servers", DnsCookie.KnownServers);

                w.Header("zenitiumdns_upstream_response_time_seconds", "histogram", "Round trip time of responses from name servers and forwarders");
                {
                    ReadOnlySpan<double> bounds = DnsClientMetrics.ResponseTimeBucketsMs;
                    double[] boundaries = bounds.ToArray();

                    for (int f = 0; f < DnsClientMetrics.FAMILY_COUNT; f++)
                    {
                        long[] buckets = new long[boundaries.Length + 1];
                        for (int b = 0; b < buckets.Length; b++)
                            buckets[b] = DnsClientMetrics.GetResponseTimeBucket(f, b);

                        w.Histogram("zenitiumdns_upstream_response_time_seconds", buckets, DnsClientMetrics.GetResponseTimeSumSeconds(f), boundaries, 1000d, f < 2, "family", DnsClientMetrics.GetFamilyName(f));
                    }
                }
            }

            private string BuildMetrics()
            {
                DnsServer dnsServer = _dnsWebService._dnsServer;
                StatsManager statsManager = dnsServer.StatsManager;
                DateTime utcNow = DateTime.UtcNow;

                MetricsWriter w = new MetricsWriter();

                w.Header("zenitiumdns_build_info", "gauge", "Version information of the running server");
                w.Sample("zenitiumdns_build_info", 1, "version", _dnsWebService.GetServerVersion(), "runtime", RuntimeInformation.FrameworkDescription, "arch", RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant());

                w.Header("zenitiumdns_start_time_seconds", "gauge", "Start time of the DNS server since unix epoch in seconds");
                w.Sample("zenitiumdns_start_time_seconds", ToUnixSeconds(_dnsWebService._uptimestamp));

                w.Header("zenitiumdns_uptime_seconds", "gauge", "Uptime of the DNS server in seconds");
                w.Sample("zenitiumdns_uptime_seconds", Math.Round((utcNow - _dnsWebService._uptimestamp).TotalSeconds, 3));

                ServerMetrics detailedMetrics = statsManager.DetailedMetrics;
                if (detailedMetrics is not null)
                    WriteDetailedMetrics(w, detailedMetrics);

                w.Header("zenitiumdns_clients", "gauge", "Estimated number of distinct client addresses since start");
                w.Sample("zenitiumdns_clients", statsManager.TotalClients);

                ResponseTimeStats.Summary[] summaries = new ResponseTimeStats.Summary[_windowMinutes.Length];
                for (int i = 0; i < summaries.Length; i++)
                    summaries[i] = statsManager.ResponseTimeStats.GetSummary(utcNow, _windowMinutes[i]);

                w.Header("zenitiumdns_queries_per_second", "gauge", "Answered queries per second over the window");
                for (int i = 0; i < summaries.Length; i++)
                    w.Sample("zenitiumdns_queries_per_second", Math.Round(summaries[i].QueriesPerSecond, 3), "window", _windowMinutes[i].ToString(CultureInfo.InvariantCulture) + "m");

                w.Header("zenitiumdns_response_time_milliseconds", "gauge", "Response time statistics of answered queries over the window");
                for (int i = 0; i < summaries.Length; i++)
                {
                    ResponseTimeStats.Summary summary = summaries[i];
                    string window = _windowMinutes[i].ToString(CultureInfo.InvariantCulture) + "m";

                    w.Sample("zenitiumdns_response_time_milliseconds", Math.Round(summary.Average, 3), "window", window, "stat", "avg");
                    w.Sample("zenitiumdns_response_time_milliseconds", Math.Round(summary.Median, 3), "window", window, "stat", "p50");
                    w.Sample("zenitiumdns_response_time_milliseconds", Math.Round(summary.P95, 3), "window", window, "stat", "p95");
                    w.Sample("zenitiumdns_response_time_milliseconds", Math.Round(summary.P99, 3), "window", window, "stat", "p99");
                    w.Sample("zenitiumdns_response_time_milliseconds", Math.Round(summary.Max, 3), "window", window, "stat", "max");
                    w.Sample("zenitiumdns_response_time_milliseconds", Math.Round(summary.CachedAverage, 3), "window", window, "stat", "cached_avg");
                    w.Sample("zenitiumdns_response_time_milliseconds", Math.Round(summary.RecursiveAverage, 3), "window", window, "stat", "recursive_avg");
                }

                WriteUpstreamMetrics(w);

                w.Header("zenitiumdns_ipv6_upstream_available", "gauge", "Whether queries to name servers over IPv6 are currently used (1) or suspended (0)");
                w.Sample("zenitiumdns_ipv6_upstream_available", (dnsServer.IPv6Mode != IPv6Mode.Disabled) && !IPv6Reachability.IsUnavailable ? 1 : 0);

                w.Header("zenitiumdns_cache_enabled", "gauge", "Whether the DNS cache is enabled (0 = every query is resolved without cached answers)");
                w.Sample("zenitiumdns_cache_enabled", dnsServer.EnableCache ? 1 : 0);

                w.Header("zenitiumdns_cache_entries", "gauge", "Records in the DNS cache");
                w.Sample("zenitiumdns_cache_entries", dnsServer.CacheZoneManager.TotalEntries);

                w.Header("zenitiumdns_cache_max_entries", "gauge", "Configured maximum number of records in the DNS cache (0 = unlimited)");
                w.Sample("zenitiumdns_cache_max_entries", dnsServer.CacheZoneManager.MaximumEntries);

                w.Header("zenitiumdns_cache_max_memory_bytes", "gauge", "Configured managed memory limit that triggers cache trimming (0 = unlimited)");
                w.Sample("zenitiumdns_cache_max_memory_bytes", dnsServer.CacheZoneManager.MaximumMemoryMegabytes * 1024L * 1024L);

                w.Header("zenitiumdns_cache_memory_trimmed_entries_total", "counter", "Cache records removed because the memory limit was exceeded");
                w.Sample("zenitiumdns_cache_memory_trimmed_entries_total", dnsServer.CacheZoneManager.MemoryTrimmedEntries);

                w.Header("zenitiumdns_memory_pressure_ratio", "gauge", "Highest memory usage ratio of the system, the service or container memory limit and the .NET heap limit, measured every 2 seconds");
                w.Sample("zenitiumdns_memory_pressure_ratio", dnsServer.CacheZoneManager.LastMemoryPressure.Ratio);

                w.Header("zenitiumdns_cache_pressure_trims_total", "counter", "Times the cache was cut because memory was almost full");
                w.Sample("zenitiumdns_cache_pressure_trims_total", dnsServer.CacheZoneManager.PressureTrims);

                w.Header("zenitiumdns_gc_paced_collections_total", "counter", "Short gen0 collections started early because many new cache entries were created");
                w.Sample("zenitiumdns_gc_paced_collections_total", dnsServer.CacheZoneManager.PacedCollections);

                w.Header("zenitiumdns_cache_pressure_trimmed_entries_total", "counter", "Cache records removed because memory was almost full");
                w.Sample("zenitiumdns_cache_pressure_trimmed_entries_total", dnsServer.CacheZoneManager.PressureTrimmedEntries);

                w.Header("zenitiumdns_cache_pressure_cap_entries", "gauge", "Temporary cache size cap while memory is almost full (0 = none)");
                w.Sample("zenitiumdns_cache_pressure_cap_entries", dnsServer.CacheZoneManager.PressureCapEntries);

                w.Header("zenitiumdns_aggressive_nsec_enabled", "gauge", "Whether aggressive use of DNSSEC-validated cache (RFC 8198) is enabled");
                w.Sample("zenitiumdns_aggressive_nsec_enabled", dnsServer.CacheZoneManager.AggressiveNsec ? 1 : 0);

                w.Header("zenitiumdns_aggressive_nsec_entries", "gauge", "NSEC and NSEC3 records held for aggressive negative caching");
                w.Sample("zenitiumdns_aggressive_nsec_entries", dnsServer.CacheZoneManager.AggressiveNsecEntries);

                w.Header("zenitiumdns_aggressive_nsec_synthesized_total", "counter", "Negative responses synthesized from cached NSEC or NSEC3 records");
                w.Sample("zenitiumdns_aggressive_nsec_synthesized_total", dnsServer.CacheZoneManager.AggressiveNsecSynthesizedResponses);

                w.Header("zenitiumdns_dns_cookies_enabled", "gauge", "Whether DNS cookies (RFC 7873, RFC 9018) are enabled");
                w.Sample("zenitiumdns_dns_cookies_enabled", dnsServer.EnableDnsCookies ? 1 : 0);

                w.Header("zenitiumdns_dnssec_validation_enabled", "gauge", "Whether DNSSEC validation is enabled");
                w.Sample("zenitiumdns_dnssec_validation_enabled", dnsServer.DnssecValidation ? 1 : 0);

                w.Header("zenitiumdns_blocking_enabled", "gauge", "Whether blocking is enabled");
                w.Sample("zenitiumdns_blocking_enabled", dnsServer.EnableBlocking ? 1 : 0);

                w.Header("zenitiumdns_filter_domains", "gauge", "Domains in the block and allow lists");
                w.Sample("zenitiumdns_filter_domains", dnsServer.BlockListZoneManager.TotalZonesBlocked, "list", "block_lists");
                w.Sample("zenitiumdns_filter_domains", dnsServer.BlockListZoneManager.TotalZonesAllowed, "list", "allow_lists");
                w.Sample("zenitiumdns_filter_domains", dnsServer.BlockedZoneManager.TotalZonesBlocked, "list", "blocked");
                w.Sample("zenitiumdns_filter_domains", dnsServer.AllowedZoneManager.TotalZonesAllowed, "list", "allowed");

                w.Header("zenitiumdns_forwarder_zones", "gauge", "Configured forwarder zones");
                w.Sample("zenitiumdns_forwarder_zones", dnsServer.AuthZoneManager.TotalZones);

                w.Header("zenitiumdns_request_filter_matches_total", "counter", "Requests dropped or refused by the request filter per rule");
                foreach (RequestFilterRule rule in Enum.GetValues<RequestFilterRule>())
                    w.Sample("zenitiumdns_request_filter_matches_total", dnsServer.GetRequestFilterMatches(rule), "rule", rule.GetApiName());

                w.Header("zenitiumdns_client_blocklist_drops_total", "counter", "Requests and connections dropped because the client address is on a client block list");
                w.Sample("zenitiumdns_client_blocklist_drops_total", dnsServer.ClientBlockListManager.Drops);

                w.Header("zenitiumdns_client_blocklist_ranges", "gauge", "Address ranges loaded from client block lists");
                w.Sample("zenitiumdns_client_blocklist_ranges", dnsServer.ClientBlockListManager.AddressRanges);

                w.Header("zenitiumdns_rate_limiter_tracked_clients", "gauge", "Client addresses currently tracked by the rate limiter");
                w.Sample("zenitiumdns_rate_limiter_tracked_clients", dnsServer.RateLimiterTrackedClients);

                w.Header("zenitiumdns_queue_length", "gauge", "Work items waiting in internal queues");
                w.Sample("zenitiumdns_queue_length", dnsServer.QueryTaskQueueLength, "queue", "query");
                w.Sample("zenitiumdns_queue_length", dnsServer.ResolverTaskQueueLength, "queue", "resolver");
                w.Sample("zenitiumdns_queue_length", statsManager.QueueLength, "queue", "stats");

                w.Header("zenitiumdns_pending_resolutions", "gauge", "Recursive resolutions currently in progress");
                w.Sample("zenitiumdns_pending_resolutions", dnsServer.PendingResolutions);

                w.Header("zenitiumdns_stats_queue_dropped_total", "counter", "Statistics updates discarded because the statistics queue was full");
                w.Sample("zenitiumdns_stats_queue_dropped_total", statsManager.QueueDropped);

                w.Header("zenitiumdns_query_logging_suspended", "gauge", "Whether the watchdog has suspended query logging for the rest of the day");
                w.Sample("zenitiumdns_query_logging_suspended", _dnsWebService._log.IsQueryLoggingSuspended ? 1 : 0);

                WriteDhcpMetrics(w);
                WriteProcessMetrics(w);

                return w.ToString();
            }

            private void WriteDhcpMetrics(MetricsWriter w)
            {
                DhcpServer dhcpServer = _dnsWebService._dhcpServer;

                if (dhcpServer is null)
                    return;

                DhcpSettings settings = dhcpServer.Settings;

                if (!settings.Enabled)
                    return;

                IReadOnlyDictionary<string, long> counters = dhcpServer.GetCounters();

                long Counter(string key)
                {
                    return counters.TryGetValue(key, out long value) ? value : 0;
                }

                w.Header("zenitiumdns_dhcp_serving", "gauge", "Whether this node currently hands out DHCP addresses");
                w.Sample("zenitiumdns_dhcp_serving", dhcpServer.IsServing ? 1 : 0);

                w.Header("zenitiumdns_dhcp_offers_paused", "gauge", "Whether offers are paused because another DHCP server answers (standby priority)");
                w.Sample("zenitiumdns_dhcp_offers_paused", dhcpServer.OffersPaused ? 1 : 0);

                w.Header("zenitiumdns_dhcp_config_errors", "gauge", "Errors in the DHCP configuration (no addresses are handed out while above 0)");
                w.Sample("zenitiumdns_dhcp_config_errors", dhcpServer.ConfigErrors.Count);

                w.Header("zenitiumdns_dhcp_messages_total", "counter", "DHCP messages processed by type");
                foreach (string type in new string[] { "discover", "offer", "request", "ack", "nak", "decline", "release", "inform" })
                    w.Sample("zenitiumdns_dhcp_messages_total", Counter(type), "type", type);

                w.Header("zenitiumdns_dhcp_packets_total", "counter", "DHCP packets received, sent and dropped");
                w.Sample("zenitiumdns_dhcp_packets_total", Counter("received"), "result", "received");
                w.Sample("zenitiumdns_dhcp_packets_total", Counter("sent"), "result", "sent");
                w.Sample("zenitiumdns_dhcp_packets_total", Counter("malformed"), "result", "malformed");
                w.Sample("zenitiumdns_dhcp_packets_total", Counter("rateLimited"), "result", "rate_limited");
                w.Sample("zenitiumdns_dhcp_packets_total", Counter("busy"), "result", "busy");
                w.Sample("zenitiumdns_dhcp_packets_total", Counter("ignored"), "result", "ignored");

                w.Header("zenitiumdns_dhcp_pool_exhausted_total", "counter", "Requests that found no free address");
                w.Sample("zenitiumdns_dhcp_pool_exhausted_total", Counter("poolExhausted"));

                w.Header("zenitiumdns_dhcp_conflicts_total", "counter", "Addresses found in use by ping check or DHCPDECLINE");
                w.Sample("zenitiumdns_dhcp_conflicts_total", Counter("conflicts"));

                (int total, int used) = dhcpServer.GetPoolUsage();
                w.Header("zenitiumdns_dhcp_pool_addresses", "gauge", "Dynamic pool addresses in total and in use");
                w.Sample("zenitiumdns_dhcp_pool_addresses", total, "state", "total");
                w.Sample("zenitiumdns_dhcp_pool_addresses", used, "state", "used");

                DateTime recent = DateTime.UtcNow.AddSeconds(-Math.Max(900, settings.RogueProbeIntervalSeconds * 3));
                int foreign = 0;
                foreach (DhcpForeignServer server in dhcpServer.GetForeignServers())
                {
                    if (server.LastSeen >= recent)
                        foreign++;
                }

                w.Header("zenitiumdns_dhcp_foreign_servers", "gauge", "Other DHCP servers seen in the network recently");
                w.Sample("zenitiumdns_dhcp_foreign_servers", foreign);

                IReadOnlyDictionary<string, long> counters6 = dhcpServer.GetCounters6();

                long Counter6(string key)
                {
                    return counters6.TryGetValue(key, out long value) ? value : 0;
                }

                w.Header("zenitiumdns_dhcp6_messages_total", "counter", "DHCPv6 messages processed by type");
                foreach ((string key, string type) in new (string, string)[] { ("solicit", "solicit"), ("advertise", "advertise"), ("request", "request"), ("reply", "reply"), ("renew", "renew"), ("rebind", "rebind"), ("release", "release"), ("decline", "decline"), ("confirm", "confirm"), ("informationRequest", "information_request") })
                    w.Sample("zenitiumdns_dhcp6_messages_total", Counter6(key), "type", type);

                w.Header("zenitiumdns_dhcp6_packets_total", "counter", "DHCPv6 packets received, sent and dropped");
                w.Sample("zenitiumdns_dhcp6_packets_total", Counter6("received"), "result", "received");
                w.Sample("zenitiumdns_dhcp6_packets_total", Counter6("sent"), "result", "sent");
                w.Sample("zenitiumdns_dhcp6_packets_total", Counter6("malformed"), "result", "malformed");
                w.Sample("zenitiumdns_dhcp6_packets_total", Counter6("ignored"), "result", "ignored");
                w.Sample("zenitiumdns_dhcp6_packets_total", Counter6("relayed"), "result", "relayed");

                w.Header("zenitiumdns_dhcp6_no_addresses_total", "counter", "DHCPv6 requests that found no free address");
                w.Sample("zenitiumdns_dhcp6_no_addresses_total", Counter6("noAddresses"));

                w.Header("zenitiumdns_dhcp6_leases_active", "gauge", "Active DHCPv6 leases");
                w.Sample("zenitiumdns_dhcp6_leases_active", dhcpServer.LeaseStore6.CountActive(DateTime.UtcNow));

                w.Header("zenitiumdns_ra_sent_total", "counter", "Router advertisements sent");
                w.Sample("zenitiumdns_ra_sent_total", Counter6("raSent"));

                w.Header("zenitiumdns_ra_solicitations_total", "counter", "Router solicitations received");
                w.Sample("zenitiumdns_ra_solicitations_total", Counter6("routerSolicitations"));

                DateTime recentRouter = DateTime.UtcNow.AddHours(-1);
                int foreignRouters = 0;
                int foreignRdnss = 0;

                foreach (RaForeignRouter router in dhcpServer.GetForeignRouters())
                {
                    if (router.LastSeen < recentRouter)
                        continue;

                    foreignRouters++;

                    if (router.DnsServers.Count > 0)
                        foreignRdnss++;
                }

                w.Header("zenitiumdns_ra_foreign_routers", "gauge", "Other IPv6 routers seen in the last hour, and how many of them announce DNS servers");
                w.Sample("zenitiumdns_ra_foreign_routers", foreignRouters, "kind", "all");
                w.Sample("zenitiumdns_ra_foreign_routers", foreignRdnss, "kind", "rdnss");

                int foreign6 = 0;
                foreach (DhcpForeignServer server in dhcpServer.GetForeignServers6())
                {
                    if (server.LastSeen >= recent)
                        foreign6++;
                }

                w.Header("zenitiumdns_dhcp6_foreign_servers", "gauge", "Other DHCPv6 servers addressed by clients recently");
                w.Sample("zenitiumdns_dhcp6_foreign_servers", foreign6);
            }

            #endregion

            #region public

            public async Task WriteMetricsAsync(HttpContext context)
            {
                HttpResponse response = context.Response;

                response.Headers.CacheControl = "no-cache, no-store, must-revalidate";
                response.Headers.Pragma = "no-cache";
                response.Headers.Expires = "0";

                if (!_dnsWebService._metricsEnabled || (_dnsWebService._dnsServer is null))
                {
                    response.StatusCode = StatusCodes.Status404NotFound;
                    response.ContentLength = 0;
                    return;
                }

                int status = CheckAccess(context);
                if (status != StatusCodes.Status200OK)
                {
                    response.StatusCode = status;

                    if (status == StatusCodes.Status401Unauthorized)
                        response.Headers.WWWAuthenticate = "Bearer";

                    response.ContentLength = 0;
                    return;
                }

                byte[] data = Encoding.UTF8.GetBytes(BuildMetrics());

                response.StatusCode = StatusCodes.Status200OK;
                response.ContentType = CONTENT_TYPE;

                await response.Body.WriteAsync(data);
            }

            #endregion

            sealed class MetricsWriter
            {
                readonly StringBuilder _sb = new StringBuilder(32768);

                private static string FormatValue(double value)
                {
                    if (double.IsPositiveInfinity(value))
                        return "+Inf";

                    if (double.IsNegativeInfinity(value))
                        return "-Inf";

                    if (double.IsNaN(value))
                        return "NaN";

                    return value.ToString(CultureInfo.InvariantCulture);
                }

                private void AppendLabels(string[] labels, string extraName = null, string extraValue = null)
                {
                    if ((labels.Length == 0) && (extraName is null))
                        return;

                    _sb.Append('{');

                    bool first = true;

                    for (int i = 0; i + 1 < labels.Length; i += 2)
                    {
                        if (!first)
                            _sb.Append(',');

                        AppendLabel(labels[i], labels[i + 1]);
                        first = false;
                    }

                    if (extraName is not null)
                    {
                        if (!first)
                            _sb.Append(',');

                        AppendLabel(extraName, extraValue);
                    }

                    _sb.Append('}');
                }

                private void AppendLabel(string name, string value)
                {
                    _sb.Append(name).Append("=\"");

                    foreach (char c in value ?? string.Empty)
                    {
                        switch (c)
                        {
                            case '\\':
                                _sb.Append("\\\\");
                                break;

                            case '"':
                                _sb.Append("\\\"");
                                break;

                            case '\n':
                                _sb.Append("\\n");
                                break;

                            default:
                                _sb.Append(c);
                                break;
                        }
                    }

                    _sb.Append('"');
                }

                public void Header(string name, string type, string help)
                {
                    _sb.Append("# HELP ").Append(name).Append(' ').Append(help).Append('\n');
                    _sb.Append("# TYPE ").Append(name).Append(' ').Append(type).Append('\n');
                }

                public void Sample(string name, long value, params string[] labels)
                {
                    _sb.Append(name);
                    AppendLabels(labels);
                    _sb.Append(' ').Append(value.ToString(CultureInfo.InvariantCulture)).Append('\n');
                }

                public void Sample(string name, double value, params string[] labels)
                {
                    _sb.Append(name);
                    AppendLabels(labels);
                    _sb.Append(' ').Append(FormatValue(value)).Append('\n');
                }

                public void Histogram(string name, long[] buckets, double sum, IReadOnlyList<double> boundaries, double divisor, bool includeEmpty, params string[] labels)
                {
                    long count = 0;
                    foreach (long bucket in buckets)
                        count += bucket;

                    if ((count == 0) && !includeEmpty)
                        return;

                    long cumulative = 0;

                    for (int i = 0; i < boundaries.Count; i++)
                    {
                        cumulative += buckets[i];

                        _sb.Append(name).Append("_bucket");
                        AppendLabels(labels, "le", FormatValue(boundaries[i] / divisor));
                        _sb.Append(' ').Append(cumulative.ToString(CultureInfo.InvariantCulture)).Append('\n');
                    }

                    _sb.Append(name).Append("_bucket");
                    AppendLabels(labels, "le", "+Inf");
                    _sb.Append(' ').Append(count.ToString(CultureInfo.InvariantCulture)).Append('\n');

                    _sb.Append(name).Append("_sum");
                    AppendLabels(labels);
                    _sb.Append(' ').Append(FormatValue(sum)).Append('\n');

                    _sb.Append(name).Append("_count");
                    AppendLabels(labels);
                    _sb.Append(' ').Append(count.ToString(CultureInfo.InvariantCulture)).Append('\n');
                }

                public void Histogram(string name, ServerMetrics.Histogram histogram, IReadOnlyList<double> boundaries, double divisor, bool includeEmpty, params string[] labels)
                {
                    Histogram(name, histogram.GetBuckets(), histogram.Sum, boundaries, divisor, includeEmpty, labels);
                }

                public void Histogram(string name, ServerMetrics.Histogram histogram, IReadOnlyList<int> boundaries, bool includeEmpty, params string[] labels)
                {
                    double[] doubleBoundaries = new double[boundaries.Count];
                    for (int i = 0; i < doubleBoundaries.Length; i++)
                        doubleBoundaries[i] = boundaries[i];

                    Histogram(name, histogram.GetBuckets(), histogram.Sum, doubleBoundaries, 1d, includeEmpty, labels);
                }

                public override string ToString()
                {
                    return _sb.ToString();
                }
            }
        }
    }
}
