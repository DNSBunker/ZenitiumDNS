/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)
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

using ZenitiumDns.Core.Auth;
using ZenitiumDns.Core.Dns;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core
{
    public partial class DnsWebService
    {
        class WebServiceDashboardApi
        {
            #region variables

            readonly DnsWebService _dnsWebService;

            #endregion

            #region constructor

            public WebServiceDashboardApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

            private static void WriteChartDataSet(Utf8JsonWriter jsonWriter, DashboardStats.DataSet dataSet)
            {
                jsonWriter.WriteStartObject();

                if (dataSet.Label is not null)
                    jsonWriter.WriteString("label", dataSet.Label);

                jsonWriter.WritePropertyName("data");
                jsonWriter.WriteStartArray();

                foreach (long value in dataSet.Data)
                    jsonWriter.WriteNumberValue(value);

                jsonWriter.WriteEndArray();

                jsonWriter.WriteEndObject();
            }

            private static void ReadCustomDateRange(HttpRequest request, DashboardStatsType type, out DateTime startDate, out DateTime endDate)
            {
                startDate = default;
                endDate = default;

                if (type != DashboardStatsType.Custom)
                    return;

                if (!DateTime.TryParse(request.GetQueryOrForm("start"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out startDate))
                    throw new DnsWebServiceException("Invalid start date format.");

                if (!DateTime.TryParse(request.GetQueryOrForm("end"), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out endDate))
                    throw new DnsWebServiceException("Invalid end date format.");

                if (startDate > endDate)
                    throw new DnsWebServiceException("Start date must be less than or equal to end date.");
            }

            private static void WriteChartData(Utf8JsonWriter jsonWriter, string propertyName, DashboardStats.ChartData chartData, string labelFormat = null)
            {
                jsonWriter.WriteStartObject(propertyName);

                if (labelFormat is not null)
                    jsonWriter.WriteString("labelFormat", labelFormat);

                jsonWriter.WriteStartArray("labels");

                foreach (string label in chartData.Labels)
                    jsonWriter.WriteStringValue(label);

                jsonWriter.WriteEndArray();

                jsonWriter.WriteStartArray("datasets");

                foreach (DashboardStats.DataSet dataSet in chartData.DataSets)
                    WriteChartDataSet(jsonWriter, dataSet);

                jsonWriter.WriteEndArray();

                jsonWriter.WriteEndObject();
            }

            private static void WriteNumberArray(Utf8JsonWriter jsonWriter, string propertyName, double[] values)
            {
                jsonWriter.WriteStartArray(propertyName);

                foreach (double value in values)
                    jsonWriter.WriteNumberValue(value);

                jsonWriter.WriteEndArray();
            }

            private static void WriteTopDomains(Utf8JsonWriter jsonWriter, string propertyName, DashboardStats.TopStats[] topDomains)
            {
                jsonWriter.WriteStartArray(propertyName);

                foreach (DashboardStats.TopStats item in topDomains)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteString("name", item.Name);

                    if (DnsClient.TryConvertDomainNameToUnicode(item.Name, out string idn))
                        jsonWriter.WriteString("nameIdn", idn);

                    jsonWriter.WriteNumber("hits", item.Hits);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            private void WriteTopClients(Utf8JsonWriter jsonWriter, DashboardStats.TopClientStats[] topClients, bool onlyRateLimitedClients = false)
            {
                jsonWriter.WriteStartArray("topClients");

                foreach (DashboardStats.TopClientStats item in topClients)
                {
                    IPAddress ip = IPAddress.Parse(item.Name);
                    bool rateLimited = item.RateLimited || _dnsWebService._dnsServer.IsClientRateLimited(ip);

                    if (onlyRateLimitedClients && !rateLimited)
                        continue;

                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteString("name", item.Name);

                    if (!string.IsNullOrEmpty(item.Domain))
                        jsonWriter.WriteString("domain", item.Domain);

                    jsonWriter.WriteNumber("hits", item.Hits);
                    jsonWriter.WriteBoolean("rateLimited", rateLimited);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            private static void WriteResponseTimeSummary(Utf8JsonWriter jsonWriter, string propertyName, ResponseTimeStats.Summary summary)
            {
                jsonWriter.WriteStartObject(propertyName);

                jsonWriter.WriteNumber("minutes", summary.Minutes);
                jsonWriter.WriteNumber("count", summary.Count);
                jsonWriter.WriteNumber("queriesPerSecond", Math.Round(summary.QueriesPerSecond, 2));
                jsonWriter.WriteNumber("average", Math.Round(summary.Average, 2));
                jsonWriter.WriteNumber("median", Math.Round(summary.Median, 2));
                jsonWriter.WriteNumber("p95", Math.Round(summary.P95, 2));
                jsonWriter.WriteNumber("p99", Math.Round(summary.P99, 2));
                jsonWriter.WriteNumber("max", Math.Round(summary.Max, 2));
                jsonWriter.WriteNumber("cachedAverage", Math.Round(summary.CachedAverage, 2));
                jsonWriter.WriteNumber("recursiveAverage", Math.Round(summary.RecursiveAverage, 2));

                jsonWriter.WriteEndObject();
            }

            private ulong GetUptimeSeconds()
            {
                return Convert.ToUInt64((DateTime.UtcNow - _dnsWebService._uptimestamp).TotalSeconds);
            }

            private bool IsIPv6UpstreamAvailable()
            {
                return (_dnsWebService._dnsServer.IPv6Mode != IPv6Mode.Disabled) && !IPv6Reachability.IsUnavailable;
            }

            private void WriteServerStatus(Utf8JsonWriter jsonWriter)
            {
                DnsServer dnsServer = _dnsWebService._dnsServer;

                jsonWriter.WriteStartObject("serverStatus");

                jsonWriter.WriteNumber("uptimeSeconds", GetUptimeSeconds());
                jsonWriter.WriteString("ipv6Mode", dnsServer.IPv6Mode.ToString());
                jsonWriter.WriteBoolean("ipv6UpstreamAvailable", IsIPv6UpstreamAvailable());

                if (IPv6Reachability.IsUnavailable)
                    jsonWriter.WriteString("ipv6UpstreamUnavailableUntil", IPv6Reachability.UnavailableUntil);

                jsonWriter.WriteBoolean("enableBlocking", dnsServer.EnableBlocking);

                if (!dnsServer.EnableBlocking && (dnsServer.BlockListZoneManager.TemporaryDisableBlockingTill > DateTime.UtcNow))
                    jsonWriter.WriteString("temporaryDisableBlockingTill", dnsServer.BlockListZoneManager.TemporaryDisableBlockingTill);

                jsonWriter.WriteBoolean("dnssecValidation", dnsServer.DnssecValidation);
                jsonWriter.WriteBoolean("forwarding", (dnsServer.Forwarders is not null) && (dnsServer.Forwarders.Count > 0));
                jsonWriter.WriteBoolean("localRootZone", dnsServer.IanaDataManager.IsRootZoneActive);

                jsonWriter.WriteEndObject();
            }

            private async Task ResolvePtrTopClientsAsync(DashboardStats.TopClientStats[] topClients)
            {
                async Task ResolvePtrAsync(DashboardStats.TopClientStats item)
                {
                    string ip = item.Name;

                    IPAddress address = IPAddress.Parse(ip);

                    if (IPAddress.IsLoopback(address))
                    {
                        item.Domain = "localhost";
                        return;
                    }

                    DnsDatagram ptrResponse = await _dnsWebService._dnsServer.DirectQueryAsync(new DnsQuestionRecord(address, DnsClass.IN), 500);
                    if (ptrResponse.Answer.Count > 0)
                    {
                        IReadOnlyList<string> ptrDomains = DnsClient.ParseResponsePTR(ptrResponse);
                        if (ptrDomains.Count > 0)
                        {
                            item.Domain = ptrDomains[0];
                            return;
                        }
                    }
                }

                List<Task> resolverTasks = new List<Task>(topClients.Length);

                foreach (DashboardStats.TopClientStats item in topClients)
                {
                    if (string.IsNullOrEmpty(item.Domain))
                        resolverTasks.Add(ResolvePtrAsync(item));
                }

                foreach (Task resolverTask in resolverTasks)
                {
                    try
                    {
                        await resolverTask;
                    }
                    catch
                    { }
                }
            }

            #endregion

            #region public

            public void GetLiveSystemStats(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Dashboard, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                SystemMonitor systemMonitor = _dnsWebService._dnsServer.SystemMonitor;
                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WriteBoolean("enabled", systemMonitor.Enabled);
                jsonWriter.WriteNumber("capacity", SystemMonitor.CAPACITY);
                jsonWriter.WriteNumber("processorCount", Environment.ProcessorCount);
                jsonWriter.WriteNumber("latestSeq", systemMonitor.LatestSequence);

                jsonWriter.WriteStartArray("samples");

                if (systemMonitor.Enabled)
                {
                    long since = context.Request.GetQueryOrForm("since", long.Parse, 0);

                    foreach (SystemMonitor.Sample sample in systemMonitor.GetSamples(since))
                    {
                        jsonWriter.WriteStartObject();
                        jsonWriter.WriteNumber("seq", sample.Sequence);
                        jsonWriter.WriteString("time", sample.Time);
                        jsonWriter.WriteNumber("cpu", Math.Round(sample.CpuPercent, 1));
                        jsonWriter.WriteNumber("workingSet", sample.WorkingSet);
                        jsonWriter.WriteNumber("gcHeap", sample.GcHeap);
                        jsonWriter.WriteNumber("gen0", Math.Round(sample.Gen0PerSecond, 2));
                        jsonWriter.WriteNumber("gen1", Math.Round(sample.Gen1PerSecond, 2));
                        jsonWriter.WriteNumber("gen2", Math.Round(sample.Gen2PerSecond, 2));
                        jsonWriter.WriteNumber("gcPause", Math.Round(sample.GcPausePercent, 2));
                        jsonWriter.WriteNumber("threads", sample.ThreadPoolThreads);
                        jsonWriter.WriteNumber("threadPoolQueue", sample.ThreadPoolQueue);
                        jsonWriter.WriteNumber("workItems", Math.Round(sample.WorkItemsPerSecond));
                        jsonWriter.WriteNumber("lockContentions", Math.Round(sample.LockContentionsPerSecond, 1));
                        jsonWriter.WriteNumber("queryQueue", sample.QueryQueue);
                        jsonWriter.WriteNumber("resolverQueue", sample.ResolverQueue);
                        jsonWriter.WriteNumber("statsQueue", sample.StatsQueue);
                        jsonWriter.WriteNumber("pendingResolutions", sample.PendingResolutions);
                        jsonWriter.WriteNumber("cacheEntries", sample.CacheEntries);
                        jsonWriter.WriteNumber("qps", Math.Round(sample.QueriesPerSecond, 1));
                        jsonWriter.WriteNumber("rateLimiterClients", sample.RateLimiterClients);
                        jsonWriter.WriteEndObject();
                    }
                }

                jsonWriter.WriteEndArray();
            }

            public Task GetMetricsJson(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Dashboard, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                StatsManager statsManager = _dnsWebService._dnsServer.StatsManager;
                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WriteString("uptimestamp", _dnsWebService._uptimestamp);
                jsonWriter.WriteNumber("uptimeSeconds", GetUptimeSeconds());

                jsonWriter.WriteStartObject("lifetimeCounters");

                jsonWriter.WriteNumber("totalQueries", statsManager.TotalQueries);
                jsonWriter.WriteNumber("totalNoError", statsManager.TotalNoError);
                jsonWriter.WriteNumber("totalServerFailure", statsManager.TotalServerFailure);
                jsonWriter.WriteNumber("totalNxDomain", statsManager.TotalNxDomain);
                jsonWriter.WriteNumber("totalRefused", statsManager.TotalRefused);

                jsonWriter.WriteNumber("totalAuthoritative", statsManager.TotalAuthoritative);
                jsonWriter.WriteNumber("totalRecursive", statsManager.TotalRecursive);
                jsonWriter.WriteNumber("totalCached", statsManager.TotalCached);
                jsonWriter.WriteNumber("totalBlocked", statsManager.TotalBlocked);
                jsonWriter.WriteNumber("totalDropped", statsManager.TotalDropped);

                jsonWriter.WriteNumber("totalClients", statsManager.TotalClients);

                jsonWriter.WriteEndObject();

                DateTime utcNow = DateTime.UtcNow;

                WriteResponseTimeSummary(jsonWriter, "responseTime5Minutes", statsManager.ResponseTimeStats.GetSummary(utcNow, 5));
                WriteResponseTimeSummary(jsonWriter, "responseTime60Minutes", statsManager.ResponseTimeStats.GetSummary(utcNow, 60));

                jsonWriter.WriteNumber("cachedEntries", _dnsWebService._dnsServer.CacheZoneManager.TotalEntries);

                jsonWriter.WriteStartObject("requestFilterMatches");

                foreach (RequestFilterRule rule in Enum.GetValues<RequestFilterRule>())
                    jsonWriter.WriteNumber(rule.GetApiName(), _dnsWebService._dnsServer.GetRequestFilterMatches(rule));

                jsonWriter.WriteEndObject();

                jsonWriter.WriteNumber("clientBlockListDrops", _dnsWebService._dnsServer.ClientBlockListManager.Drops);
                jsonWriter.WriteNumber("clientBlockListAddressRanges", _dnsWebService._dnsServer.ClientBlockListManager.AddressRanges);

                WriteServerStatus(jsonWriter);

                return Task.CompletedTask;
            }

            public async Task ProbeIPv6UpstreamAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                if (_dnsWebService._dnsServer.IPv6Mode == IPv6Mode.Disabled)
                    throw new DnsWebServiceException("IPv6 is disabled in the DNS server settings.");

                if (context.Request.GetQueryOrForm("reset", bool.Parse, false))
                    IPv6Reachability.Reset();

                bool probeSucceeded = await _dnsWebService._dnsServer.ProbeIPv6UpstreamAsync();

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] IPv6 upstream reachability was checked: " + (IPv6Reachability.IsUnavailable ? "unavailable" : "available") + "; root server probe " + (probeSucceeded ? "succeeded" : "failed: " + IPv6Reachability.LastProbeError));

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WriteBoolean("probeSucceeded", probeSucceeded);

                if (!probeSucceeded && (IPv6Reachability.LastProbeError is not null))
                    jsonWriter.WriteString("probeError", IPv6Reachability.LastProbeError);

                DateTime lastSuccess = IPv6Reachability.LastSuccess;
                if (lastSuccess != DateTime.MinValue)
                    jsonWriter.WriteNumber("lastIPv6ResponseSecondsAgo", Math.Max(0, (long)(DateTime.UtcNow - lastSuccess).TotalSeconds));

                WriteServerStatus(jsonWriter);
            }

            public async Task GetStatsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Dashboard, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                DashboardStatsType type = request.GetQueryOrFormEnum("type", DashboardStatsType.LastHour);
                bool utcFormat = request.GetQueryOrForm("utc", bool.Parse, false);

                bool dontTrimQueryTypeData = request.GetQueryOrForm("dontTrimQueryTypeData", bool.Parse, false);

                ReadCustomDateRange(request, type, out DateTime startDate, out DateTime endDate);

                DashboardStats dashboardStats;
                string labelFormat;

                switch (type)
                {
                    case DashboardStatsType.LastMinute:
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetShortTermStats(60, utcFormat);
                        labelFormat = "HH:mm:ss";
                        break;

                    case DashboardStatsType.Last5Minutes:
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetShortTermStats(300, utcFormat);
                        labelFormat = "HH:mm:ss";
                        break;

                    case DashboardStatsType.Last30Minutes:
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetShortTermStats(1800, utcFormat);
                        labelFormat = "HH:mm:ss";
                        break;

                    case DashboardStatsType.LastHour:
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetLastHourMinuteWiseStats(utcFormat);
                        labelFormat = "HH:mm";
                        break;

                    case DashboardStatsType.LastDay:
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetLastDayHourWiseStats(utcFormat);
                        labelFormat = "DD.MM. HH:00";
                        break;

                    case DashboardStatsType.LastWeek:
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetLastWeekDayWiseStats(utcFormat);
                        labelFormat = "DD.MM.";
                        break;

                    case DashboardStatsType.LastMonth:
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetLastMonthDayWiseStats(utcFormat);
                        labelFormat = "DD.MM.";
                        break;

                    case DashboardStatsType.LastYear:
                        dashboardStats = _dnsWebService._dnsServer.StatsManager.GetLastYearMonthWiseStats(utcFormat);
                        labelFormat = "MM.YYYY";
                        break;

                    case DashboardStatsType.Custom:
                        TimeSpan duration = endDate - startDate;

                        if ((Convert.ToInt32(duration.TotalDays) + 1) > 7)
                        {
                            dashboardStats = _dnsWebService._dnsServer.StatsManager.GetDayWiseStats(startDate, endDate, utcFormat);
                            labelFormat = "DD.MM.";
                        }
                        else if ((Convert.ToInt32(duration.TotalHours) + 1) > 3)
                        {
                            dashboardStats = _dnsWebService._dnsServer.StatsManager.GetHourWiseStats(startDate, endDate, utcFormat);
                            labelFormat = "DD.MM. HH:00";
                        }
                        else
                        {
                            dashboardStats = _dnsWebService._dnsServer.StatsManager.GetMinuteWiseStats(startDate, endDate, utcFormat);
                            labelFormat = "DD.MM. HH:mm";
                        }

                        break;

                    default:
                        throw new DnsWebServiceException("Unknown stats type requested: " + type.ToString());
                }

                {
                    dashboardStats.Stats.Zones = _dnsWebService._dnsServer.AuthZoneManager.TotalZones;
                    dashboardStats.Stats.CachedEntries = _dnsWebService._dnsServer.CacheZoneManager.TotalEntries;
                    dashboardStats.Stats.AllowedZones = _dnsWebService._dnsServer.AllowedZoneManager.TotalZonesAllowed;
                    dashboardStats.Stats.BlockedZones = _dnsWebService._dnsServer.BlockedZoneManager.TotalZonesBlocked;
                    dashboardStats.Stats.AllowListZones = _dnsWebService._dnsServer.BlockListZoneManager.TotalZonesAllowed;
                    dashboardStats.Stats.BlockListZones = _dnsWebService._dnsServer.BlockListZoneManager.TotalZonesBlocked;
                }

                if (!dontTrimQueryTypeData)
                    dashboardStats.QueryTypeChartData.Trim(10);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                {
                    jsonWriter.WritePropertyName("stats");
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteNumber("totalQueries", dashboardStats.Stats.TotalQueries);
                    jsonWriter.WriteNumber("totalNoError", dashboardStats.Stats.TotalNoError);
                    jsonWriter.WriteNumber("totalServerFailure", dashboardStats.Stats.TotalServerFailure);
                    jsonWriter.WriteNumber("totalNxDomain", dashboardStats.Stats.TotalNxDomain);
                    jsonWriter.WriteNumber("totalRefused", dashboardStats.Stats.TotalRefused);

                    jsonWriter.WriteNumber("totalAuthoritative", dashboardStats.Stats.TotalAuthoritative);
                    jsonWriter.WriteNumber("totalRecursive", dashboardStats.Stats.TotalRecursive);
                    jsonWriter.WriteNumber("totalCached", dashboardStats.Stats.TotalCached);
                    jsonWriter.WriteNumber("totalBlocked", dashboardStats.Stats.TotalBlocked);
                    jsonWriter.WriteNumber("totalDropped", dashboardStats.Stats.TotalDropped);

                    jsonWriter.WriteNumber("totalClients", dashboardStats.Stats.TotalClients);

                    jsonWriter.WriteNumber("zones", dashboardStats.Stats.Zones);
                    jsonWriter.WriteNumber("cachedEntries", dashboardStats.Stats.CachedEntries);
                    jsonWriter.WriteNumber("allowedZones", dashboardStats.Stats.AllowedZones);
                    jsonWriter.WriteNumber("blockedZones", dashboardStats.Stats.BlockedZones);
                    jsonWriter.WriteNumber("allowListZones", dashboardStats.Stats.AllowListZones);
                    jsonWriter.WriteNumber("blockListZones", dashboardStats.Stats.BlockListZones);

                    jsonWriter.WriteEndObject();
                }

                {
                    DateTime utcNow = DateTime.UtcNow;
                    ResponseTimeStats responseTimeStats = _dnsWebService._dnsServer.StatsManager.ResponseTimeStats;

                    WriteResponseTimeSummary(jsonWriter, "live", responseTimeStats.GetSummary(utcNow, 5));
                    WriteResponseTimeSummary(jsonWriter, "lastHourResponseTime", responseTimeStats.GetSummary(utcNow, 60));

                    if (type == DashboardStatsType.LastHour)
                    {
                        DateTime startMinute = utcNow.AddMinutes(-60);
                        startMinute = new DateTime(startMinute.Year, startMinute.Month, startMinute.Day, startMinute.Hour, startMinute.Minute, 0, DateTimeKind.Utc);

                        double[] average = new double[60];
                        double[] p95 = new double[60];

                        responseTimeStats.GetPerMinuteSeries(startMinute, average, p95);

                        jsonWriter.WriteStartObject("responseTimeChartData");
                        WriteNumberArray(jsonWriter, "average", average);
                        WriteNumberArray(jsonWriter, "p95", p95);
                        jsonWriter.WriteEndObject();
                    }

                    WriteServerStatus(jsonWriter);
                }

                WriteChartData(jsonWriter, "mainChartData", dashboardStats.MainChartData, labelFormat);
                WriteChartData(jsonWriter, "queryResponseChartData", dashboardStats.QueryResponseChartData);
                WriteChartData(jsonWriter, "queryTypeChartData", dashboardStats.QueryTypeChartData);
                WriteChartData(jsonWriter, "protocolTypeChartData", dashboardStats.ProtocolTypeChartData);

                await ResolvePtrTopClientsAsync(dashboardStats.TopClients);

                WriteTopClients(jsonWriter, dashboardStats.TopClients);
                WriteTopDomains(jsonWriter, "topDomains", dashboardStats.TopDomains);
                WriteTopDomains(jsonWriter, "topBlockedDomains", dashboardStats.TopBlockedDomains);
            }

            public async Task GetTopStatsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Dashboard, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                DashboardStatsType type = request.GetQueryOrFormEnum("type", DashboardStatsType.LastHour);
                DashboardTopStatsType statsType = request.GetQueryOrFormEnum<DashboardTopStatsType>("statsType");

                int limit = request.GetQueryOrForm("limit", int.Parse, StatsManager.STATS_TOP_LIMIT);
                if (limit > StatsManager.STATS_TOP_LIMIT)
                    limit = StatsManager.STATS_TOP_LIMIT;

                ReadCustomDateRange(request, type, out DateTime startDate, out DateTime endDate);

                DashboardStats topStatsData;

                switch (type)
                {
                    case DashboardStatsType.LastMinute:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetShortTermTopStats(60, statsType, limit);
                        break;

                    case DashboardStatsType.Last5Minutes:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetShortTermTopStats(300, statsType, limit);
                        break;

                    case DashboardStatsType.Last30Minutes:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetShortTermTopStats(1800, statsType, limit);
                        break;

                    case DashboardStatsType.LastHour:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetLastHourTopStats(statsType, limit);
                        break;

                    case DashboardStatsType.LastDay:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetLastDayTopStats(statsType, limit);
                        break;

                    case DashboardStatsType.LastWeek:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetLastWeekTopStats(statsType, limit);
                        break;

                    case DashboardStatsType.LastMonth:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetLastMonthTopStats(statsType, limit);
                        break;

                    case DashboardStatsType.LastYear:
                        topStatsData = _dnsWebService._dnsServer.StatsManager.GetLastYearTopStats(statsType, limit);
                        break;

                    case DashboardStatsType.Custom:
                        TimeSpan duration = endDate - startDate;

                        if ((Convert.ToInt32(duration.TotalDays) + 1) > 7)
                            topStatsData = _dnsWebService._dnsServer.StatsManager.GetDayWiseTopStats(startDate, endDate, statsType, limit);
                        else if ((Convert.ToInt32(duration.TotalHours) + 1) > 3)
                            topStatsData = _dnsWebService._dnsServer.StatsManager.GetHourWiseTopStats(startDate, endDate, statsType, limit);
                        else
                            topStatsData = _dnsWebService._dnsServer.StatsManager.GetMinuteWiseTopStats(startDate, endDate, statsType, limit);

                        break;

                    default:
                        throw new DnsWebServiceException("Unknown stats type requested: " + type.ToString());
                }

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                switch (statsType)
                {
                    case DashboardTopStatsType.TopClients:
                        if (!request.GetQueryOrForm("noReverseLookup", bool.Parse, false))
                            await ResolvePtrTopClientsAsync(topStatsData.TopClients);

                        WriteTopClients(jsonWriter, topStatsData.TopClients, request.GetQueryOrForm("onlyRateLimitedClients", bool.Parse, false));
                        break;

                    case DashboardTopStatsType.TopDomains:
                        WriteTopDomains(jsonWriter, "topDomains", topStatsData.TopDomains);
                        break;

                    case DashboardTopStatsType.TopBlockedDomains:
                        WriteTopDomains(jsonWriter, "topBlockedDomains", topStatsData.TopBlockedDomains);
                        break;

                    default:
                        throw new NotSupportedException();
                }
            }

            #endregion
        }
    }
}
