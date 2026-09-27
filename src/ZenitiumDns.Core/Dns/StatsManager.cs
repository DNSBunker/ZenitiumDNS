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

using ZenitiumDns.ApplicationCommon;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using ZenitiumLibrary.IO;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns
{
    public sealed class StatsManager : IDisposable
    {
        #region variables

        public const int STATS_TOP_LIMIT = 1000;
        const int STATS_HOUR_LIMIT = 10000;
        const int STATS_SETTLE_MINUTES = 10;
        const int DAILY_STATS_CACHE_DAYS = 32;

        readonly DnsServer _dnsServer;
        readonly string _statsFolder;

        long _totalQueries;
        long _totalNoError;
        long _totalServerFailure;
        long _totalNxDomain;
        long _totalRefused;

        long _totalAuthoritative;
        long _totalRecursive;
        long _totalCached;
        long _totalBlocked;
        long _totalDropped;

        readonly UniqueAddressCounter _uniqueClients = new UniqueAddressCounter();
        readonly ShortTermStats _shortTermStats = new ShortTermStats();

        readonly StatCounter[] _lastHourStatCounters = new StatCounter[60];
        readonly StatCounter[] _lastHourStatCountersCopy = new StatCounter[60];
        ConcurrentDictionary<DateTime, HourlyStats> _hourlyStatsCache = new ConcurrentDictionary<DateTime, HourlyStats>(1, 24);
        ConcurrentDictionary<DateTime, StatCounter> _dailyStatsCache = new ConcurrentDictionary<DateTime, StatCounter>(1, 7);
        ConcurrentDictionary<DateTime, StatCounter> _monthlyStatsCache = new ConcurrentDictionary<DateTime, StatCounter>(1, 12);

        readonly Timer _maintenanceTimer;
        int _maintenanceRunning;
        const int MAINTENANCE_TIMER_INITIAL_INTERVAL = 10000;
        const int MAINTENANCE_TIMER_PERIODIC_INTERVAL = 10000;

        readonly ResponseTimeStats _responseTimeStats = new ResponseTimeStats();

        internal const int MAX_QUEUE_LENGTH = 100000;

        readonly ConcurrentQueue<StatsQueueItem> _queue = new ConcurrentQueue<StatsQueueItem>();
        int _queueLength;
        readonly Thread _consumerThread;
        volatile bool _consumerStopping;
        const int CONSUMER_INTERVAL = 5;

        readonly Timer _statsCleanupTimer;
        const int STATS_CLEANUP_TIMER_INITIAL_INTERVAL = 60 * 1000;
        const int STATS_CLEANUP_TIMER_PERIODIC_INTERVAL = 60 * 60 * 1000;

        bool _enableInMemoryStats;
        int _maxStatFileDays;

        #endregion

        #region constructor

        public StatsManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;
            _statsFolder = Path.Combine(dnsServer.ConfigFolder, "stats");

            if (!Directory.Exists(_statsFolder))
                Directory.CreateDirectory(_statsFolder);

            LoadLastHourStats();

            try
            {
                DoMaintenance();
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }

            _maintenanceTimer = new Timer(delegate (object state)
            {
                if (Interlocked.Exchange(ref _maintenanceRunning, 1) == 1)
                    return;

                try
                {
                    DoMaintenance();
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
                finally
                {
                    Volatile.Write(ref _maintenanceRunning, 0);
                }
            }, null, MAINTENANCE_TIMER_INITIAL_INTERVAL, MAINTENANCE_TIMER_PERIODIC_INTERVAL);

            _consumerThread = new Thread(ConsumeQueue);
            _consumerThread.Name = "Stats";
            _consumerThread.IsBackground = true;
            _consumerThread.Start();

            _statsCleanupTimer = new Timer(delegate (object state)
            {
                try
                {
                    if (_maxStatFileDays < 1)
                        return;

                    DateTime cutoffDate = DateTime.UtcNow.AddDays(_maxStatFileDays * -1).Date;

                    {
                        string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_dnsServer.ConfigFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly);

                        foreach (string hourlyStatsFile in hourlyStatsFiles)
                        {
                            string hourlyStatsFileName = Path.GetFileNameWithoutExtension(hourlyStatsFile);

                            if (!DateTime.TryParseExact(hourlyStatsFileName, "yyyyMMddHH", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime hourlyStatsFileDate))
                                continue;

                            if (hourlyStatsFileDate < cutoffDate)
                            {
                                try
                                {
                                    File.Delete(hourlyStatsFile);
                                    dnsServer.LogManager.Write("StatsManager cleanup deleted the hourly stats file: " + hourlyStatsFile);
                                }
                                catch (Exception ex)
                                {
                                    dnsServer.LogManager.Write(ex);
                                }
                            }
                        }
                    }

                    {
                        string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_dnsServer.ConfigFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly);

                        foreach (string dailyStatsFile in dailyStatsFiles)
                        {
                            string dailyStatsFileName = Path.GetFileNameWithoutExtension(dailyStatsFile);

                            if (!DateTime.TryParseExact(dailyStatsFileName, "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out DateTime dailyStatsFileDate))
                                continue;

                            if (dailyStatsFileDate < cutoffDate)
                            {
                                try
                                {
                                    File.Delete(dailyStatsFile);
                                    dnsServer.LogManager.Write("StatsManager cleanup deleted the daily stats file: " + dailyStatsFile);
                                }
                                catch (Exception ex)
                                {
                                    dnsServer.LogManager.Write(ex);
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            });

            _statsCleanupTimer.Change(STATS_CLEANUP_TIMER_INITIAL_INTERVAL, STATS_CLEANUP_TIMER_PERIODIC_INTERVAL);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _maintenanceTimer?.Dispose();
            _statsCleanupTimer?.Dispose();

            _consumerStopping = true;
            _consumerThread?.Join();

            SpinWait.SpinUntil(delegate () { return Interlocked.CompareExchange(ref _maintenanceRunning, 1, 0) == 0; }, 30000);

            DoMaintenance();

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        #endregion

        #region private

        private void ConsumeQueue()
        {
            while (true)
            {
                while (_queue.TryDequeue(out StatsQueueItem item))
                {
                    Interlocked.Decrement(ref _queueLength);

                    try
                    {
                        ProcessQueueItem(item);
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                }

                if (_consumerStopping)
                    return;

                Thread.Sleep(CONSUMER_INTERVAL);
            }
        }

        private void ProcessQueueItem(in StatsQueueItem item)
        {
            DnsResponseCode responseCode = item._response is null ? DnsResponseCode.NoError : item._response.RCODE;

            DnsServerResponseType responseType;

            if (item._response is null)
                responseType = DnsServerResponseType.Dropped;
            else if (item._response.Tag is null)
                responseType = DnsServerResponseType.Recursive;
            else
                responseType = (DnsServerResponseType)item._response.Tag;

            UpdateLifetimeCounters(responseCode, responseType, item._remoteEP.Address);
            _shortTermStats.Record(item._timestamp, responseCode, responseType, item._remoteEP.Address);

            if (item._response is not null)
                _responseTimeStats.Record(item._timestamp, item._responseTime, responseType);

            StatCounter statCounter = _lastHourStatCounters[item._timestamp.Minute];
            if (statCounter is not null)
            {
                DnsQuestionRecord query;

                if ((item._request is not null) && (item._request.Question.Count > 0))
                    query = item._request.Question[0];
                else
                    query = null;

                statCounter.Update(query, responseCode, responseType, item._remoteEP.Address, item._protocol, item._rateLimited);
            }

            if ((item._request is null) || (item._response is null))
                return;

            foreach (IDnsQueryLogger logger in _dnsServer.DnsApplicationManager.DnsQueryLoggers)
            {
                try
                {
                    _ = logger.InsertLogAsync(item._timestamp, item._request, item._remoteEP, item._protocol, item._response);
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            }
        }

        public void UpdateLifetimeCounters(DnsResponseCode responseCode, DnsServerResponseType responseType, IPAddress clientIpAddress)
        {
            _totalQueries++;

            if (responseType == DnsServerResponseType.Dropped)
            {
                _totalDropped++;
            }
            else
            {
                switch (responseCode)
                {
                    case DnsResponseCode.NoError:
                        _totalNoError++;
                        break;

                    case DnsResponseCode.ServerFailure:
                        _totalServerFailure++;
                        break;

                    case DnsResponseCode.NxDomain:
                        _totalNxDomain++;
                        break;

                    case DnsResponseCode.Refused:
                        _totalRefused++;
                        break;
                }

                switch (responseType)
                {
                    case DnsServerResponseType.Authoritative:
                        _totalAuthoritative++;
                        break;

                    case DnsServerResponseType.Recursive:
                        _totalRecursive++;
                        break;

                    case DnsServerResponseType.Cached:
                        _totalCached++;
                        break;

                    case DnsServerResponseType.Blocked:
                        _totalBlocked++;
                        break;

                    case DnsServerResponseType.UpstreamBlocked:
                        _totalRecursive++;
                        _totalBlocked++;
                        break;

                    case DnsServerResponseType.UpstreamBlockedCached:
                        _totalCached++;
                        _totalBlocked++;
                        break;
                }

                if (clientIpAddress.IsIPv4MappedToIPv6)
                    clientIpAddress = clientIpAddress.MapToIPv4();

                _uniqueClients.Add(clientIpAddress);
            }
        }

        private void LoadLastHourStats()
        {
            try
            {
                DateTime currentDateTime = DateTime.UtcNow;
                DateTime lastHourDateTime = currentDateTime.AddMinutes(-60);

                HourlyStats lastHourlyStats = null;
                DateTime lastHourlyStatsDateTime = new DateTime();

                for (int i = 0; i < 60; i++)
                {
                    DateTime lastDateTime = lastHourDateTime.AddMinutes(i);

                    if ((lastHourlyStats == null) || (lastDateTime.Hour != lastHourlyStatsDateTime.Hour))
                    {
                        lastHourlyStats = LoadHourlyStats(lastDateTime, truncate: false);
                        lastHourlyStatsDateTime = lastDateTime;
                    }

                    _lastHourStatCounters[lastDateTime.Minute] = lastHourlyStats.MinuteStats[lastDateTime.Minute];
                    _lastHourStatCountersCopy[lastDateTime.Minute] = _lastHourStatCounters[lastDateTime.Minute];
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }
        }

        private void DoMaintenance()
        {
            DateTime currentDateTime = DateTime.UtcNow;

            for (int i = 0; i < 5; i++)
            {
                int minute = currentDateTime.AddMinutes(i).Minute;

                StatCounter statCounter = _lastHourStatCounters[minute];
                if ((statCounter == null) || statCounter.IsLocked)
                    _lastHourStatCounters[minute] = new StatCounter();
            }

            DateTime last5MinDateTime = currentDateTime.AddMinutes(-5);

            for (int i = 0; i < 5; i++)
            {
                DateTime lastDateTime = last5MinDateTime.AddMinutes(i);

                StatCounter lastStatCounter = _lastHourStatCounters[lastDateTime.Minute];
                if ((lastStatCounter != null) && !lastStatCounter.IsLocked)
                {
                    lastStatCounter.Lock();

                    if (_enableInMemoryStats)
                    {
                        lastStatCounter.Truncate(STATS_TOP_LIMIT);
                    }
                    else
                    {
                        HourlyStats hourlyStats = LoadHourlyStats(lastDateTime, truncate: false);

                        hourlyStats.UpdateStat(lastDateTime, lastStatCounter);
                        lastStatCounter.Truncate(STATS_TOP_LIMIT);

                        SaveHourlyStats(lastDateTime, hourlyStats);
                    }

                    _lastHourStatCountersCopy[lastDateTime.Minute] = lastStatCounter;
                }
            }

            if (currentDateTime.TimeOfDay >= TimeSpan.FromMinutes(STATS_SETTLE_MINUTES))
                LoadDailyStats(currentDateTime.AddDays(-1));

            {
                DateTime threshold = currentDateTime.AddHours(-24);
                threshold = new DateTime(threshold.Year, threshold.Month, threshold.Day, threshold.Hour, 0, 0, DateTimeKind.Utc);

                List<DateTime> _keysToRemove = new List<DateTime>();

                foreach (KeyValuePair<DateTime, HourlyStats> item in _hourlyStatsCache)
                {
                    if (item.Key < threshold)
                        _keysToRemove.Add(item.Key);
                }

                foreach (DateTime key in _keysToRemove)
                    _hourlyStatsCache.TryRemove(key, out _);
            }

            {
                DateTime completedHourThreshold = currentDateTime.AddMinutes(-6);
                completedHourThreshold = new DateTime(completedHourThreshold.Year, completedHourThreshold.Month, completedHourThreshold.Day, completedHourThreshold.Hour, 0, 0, DateTimeKind.Utc);

                foreach (KeyValuePair<DateTime, HourlyStats> item in _hourlyStatsCache)
                {
                    if (item.Key < completedHourThreshold)
                    {
                        item.Value.UnloadMinuteStats();
                        item.Value.Truncate(STATS_TOP_LIMIT);
                    }
                }
            }

            {
                DateTime threshold = currentDateTime.Date.AddDays(-DAILY_STATS_CACHE_DAYS);

                List<DateTime> _keysToRemove = new List<DateTime>();

                foreach (KeyValuePair<DateTime, StatCounter> item in _dailyStatsCache)
                {
                    if (item.Key < threshold)
                        _keysToRemove.Add(item.Key);
                }

                foreach (DateTime key in _keysToRemove)
                    _dailyStatsCache.TryRemove(key, out _);
            }

            {
                DateTime threshold = currentDateTime.AddMonths(-13);
                threshold = new DateTime(threshold.Year, threshold.Month, 1, 0, 0, 0, DateTimeKind.Utc);

                List<DateTime> _keysToRemove = new List<DateTime>();

                foreach (KeyValuePair<DateTime, StatCounter> item in _monthlyStatsCache)
                {
                    if (item.Key < threshold)
                        _keysToRemove.Add(item.Key);
                }

                foreach (DateTime key in _keysToRemove)
                    _monthlyStatsCache.TryRemove(key, out _);
            }
        }

        private HourlyStats ReadHourlyStats(DateTime dateTime, bool loadMinuteStats, bool ifNotExistsReturnEmptyHourlyStats)
        {
            string hourlyStatsFile = Path.Combine(_statsFolder, dateTime.ToString("yyyyMMddHH", CultureInfo.InvariantCulture) + ".stat");

            if (File.Exists(hourlyStatsFile))
            {
                try
                {
                    using (FileStream fS = new FileStream(hourlyStatsFile, FileMode.Open, FileAccess.Read))
                    {
                        return new HourlyStats(new BinaryReader(fS), loadMinuteStats);
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            }

            if (ifNotExistsReturnEmptyHourlyStats)
                return HourlyStats.Empty;

            return new HourlyStats();
        }

        private HourlyStats LoadHourlyStats(DateTime dateTime, bool forceReload = false, bool ifNotExistsReturnEmptyHourlyStats = false, bool truncate = true, bool loadMinuteStats = true)
        {
            if (_enableInMemoryStats)
                return HourlyStats.Empty;

            DateTime hourlyDateTime = new DateTime(dateTime.Year, dateTime.Month, dateTime.Day, dateTime.Hour, 0, 0, 0, DateTimeKind.Utc);

            if (forceReload || !_hourlyStatsCache.TryGetValue(hourlyDateTime, out HourlyStats hourlyStats) || (hourlyStats.Truncated && !truncate) || (loadMinuteStats && (hourlyStats.MinuteStats is null)) || ReferenceEquals(hourlyStats, HourlyStats.Empty))
            {
                hourlyStats = ReadHourlyStats(hourlyDateTime, loadMinuteStats, ifNotExistsReturnEmptyHourlyStats);

                if (truncate)
                    hourlyStats.Truncate(STATS_TOP_LIMIT);

                _hourlyStatsCache[hourlyDateTime] = hourlyStats;
            }

            return hourlyStats;
        }

        private StatCounter BuildDailyStats(DateTime dailyDateTime)
        {
            StatCounter dailyStats = new StatCounter();
            dailyStats.Lock();

            for (int hour = 0; hour < 24; hour++)
            {
                DateTime hourlyDateTime = dailyDateTime.AddHours(hour);

                if (!_hourlyStatsCache.TryGetValue(hourlyDateTime, out HourlyStats hourlyStats) || hourlyStats.Truncated || ReferenceEquals(hourlyStats, HourlyStats.Empty))
                    hourlyStats = ReadHourlyStats(hourlyDateTime, false, true);

                dailyStats.Merge(hourlyStats.HourStat);
            }

            return dailyStats;
        }

        private StatCounter LoadDailyStats(DateTime dateTime)
        {
            if (_enableInMemoryStats)
                return StatCounter.Empty;

            DateTime dailyDateTime = new DateTime(dateTime.Year, dateTime.Month, dateTime.Day, 0, 0, 0, 0, DateTimeKind.Utc);

            if (_dailyStatsCache.TryGetValue(dailyDateTime, out StatCounter dailyStats))
                return dailyStats;

            DateTime utcNow = DateTime.UtcNow;

            if (dailyDateTime.AddDays(1) > utcNow.AddMinutes(-STATS_SETTLE_MINUTES))
                return BuildDailyStats(dailyDateTime);

            string dailyStatsFile = Path.Combine(_statsFolder, dateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture) + ".dstat");

            if (File.Exists(dailyStatsFile))
            {
                try
                {
                    using (FileStream fS = new FileStream(dailyStatsFile, FileMode.Open, FileAccess.Read))
                    {
                        dailyStats = new StatCounter(new BinaryReader(fS));
                    }

                    if (dailyStats.Truncate(STATS_TOP_LIMIT))
                    {
                        SaveDailyStats(dailyDateTime, dailyStats);
                        GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, false);
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            }

            if (dailyStats is null)
            {
                dailyStats = BuildDailyStats(dailyDateTime);

                if (dailyStats.TotalQueries > 0)
                {
                    _ = dailyStats.Truncate(STATS_TOP_LIMIT);
                    SaveDailyStats(dailyDateTime, dailyStats);
                }
            }

            if (dailyDateTime < utcNow.Date.AddDays(-DAILY_STATS_CACHE_DAYS))
                return dailyStats;

            return _dailyStatsCache.GetOrAdd(dailyDateTime, dailyStats);
        }

        private StatCounter LoadMonthlyStats(DateTime monthlyDateTime)
        {
            if (_enableInMemoryStats)
                return StatCounter.Empty;

            if (_monthlyStatsCache.TryGetValue(monthlyDateTime, out StatCounter monthlyStats))
                return monthlyStats;

            monthlyStats = new StatCounter();
            monthlyStats.Lock();

            int days = DateTime.DaysInMonth(monthlyDateTime.Year, monthlyDateTime.Month);

            for (int day = 0; day < days; day++)
                monthlyStats.Merge(LoadDailyStats(monthlyDateTime.AddDays(day)), true);

            if (monthlyDateTime.AddMonths(1) > DateTime.UtcNow.AddMinutes(-STATS_SETTLE_MINUTES))
                return monthlyStats;

            monthlyStats.Truncate(STATS_TOP_LIMIT);

            return _monthlyStatsCache.GetOrAdd(monthlyDateTime, monthlyStats);
        }

        private void SaveHourlyStats(DateTime dateTime, HourlyStats hourlyStats)
        {
            if (hourlyStats.Truncated)
                throw new InvalidOperationException();

            string hourlyStatsFile = Path.Combine(_statsFolder, dateTime.ToString("yyyyMMddHH", CultureInfo.InvariantCulture) + ".stat");

            try
            {
                using (FileStream fS = new FileStream(hourlyStatsFile, FileMode.Create, FileAccess.Write))
                {
                    hourlyStats.WriteTo(new BinaryWriter(fS));
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }
        }

        private void SaveDailyStats(DateTime dateTime, StatCounter dailyStats)
        {
            string dailyStatsFile = Path.Combine(_statsFolder, dateTime.ToString("yyyyMMdd", CultureInfo.InvariantCulture) + ".dstat");

            try
            {
                using (FileStream fS = new FileStream(dailyStatsFile, FileMode.Create, FileAccess.Write))
                {
                    dailyStats.WriteTo(new BinaryWriter(fS));
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }
        }

        private void Flush()
        {
            for (int i = 0; i < _lastHourStatCountersCopy.Length; i++)
                _lastHourStatCountersCopy[i] = null;

            _hourlyStatsCache = new ConcurrentDictionary<DateTime, HourlyStats>(1, 24);
            _dailyStatsCache = new ConcurrentDictionary<DateTime, StatCounter>(1, 7);
            _monthlyStatsCache = new ConcurrentDictionary<DateTime, StatCounter>(1, 12);
        }

        #endregion

        #region public

        public void ReloadStats()
        {
            Flush();
            LoadLastHourStats();
        }

        public void DeleteAllStats()
        {
            foreach (string hourlyStatsFile in Directory.GetFiles(Path.Combine(_dnsServer.ConfigFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly))
            {
                File.Delete(hourlyStatsFile);
            }

            foreach (string dailyStatsFile in Directory.GetFiles(Path.Combine(_dnsServer.ConfigFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly))
            {
                File.Delete(dailyStatsFile);
            }

            Flush();
        }

        public void QueueUpdate(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response, bool rateLimited, double responseTime = -1)
        {
            if (Interlocked.Increment(ref _queueLength) > MAX_QUEUE_LENGTH)
            {
                Interlocked.Decrement(ref _queueLength);
                return;
            }

            _queue.Enqueue(new StatsQueueItem(request, remoteEP, protocol, response, rateLimited, responseTime));
        }

        public DashboardStats GetLastHourMinuteWiseStats(bool utcFormat)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            string[] labels = new string[60];

            long[] totalQueriesPerInterval = new long[60];
            long[] totalNoErrorPerInterval = new long[60];
            long[] totalServerFailurePerInterval = new long[60];
            long[] totalNxDomainPerInterval = new long[60];
            long[] totalRefusedPerInterval = new long[60];

            long[] totalAuthHitPerInterval = new long[60];
            long[] totalRecursionsPerInterval = new long[60];
            long[] totalCacheHitPerInterval = new long[60];
            long[] totalBlockedPerInterval = new long[60];
            long[] totalDroppedPerInterval = new long[60];

            long[] totalClientsPerInterval = new long[60];

            DateTime lastHourDateTime = DateTime.UtcNow.AddMinutes(-60);
            lastHourDateTime = new DateTime(lastHourDateTime.Year, lastHourDateTime.Month, lastHourDateTime.Day, lastHourDateTime.Hour, lastHourDateTime.Minute, 0, DateTimeKind.Utc);

            for (int minute = 0; minute < 60; minute++)
            {
                DateTime lastDateTime = lastHourDateTime.AddMinutes(minute);
                string label;

                if (utcFormat)
                    label = lastDateTime.AddMinutes(1).ToString("O", CultureInfo.InvariantCulture);
                else
                    label = lastDateTime.AddMinutes(1).ToLocalTime().ToString("HH:mm", CultureInfo.InvariantCulture);

                labels[minute] = label;

                StatCounter statCounter = _lastHourStatCountersCopy[lastDateTime.Minute];
                if ((statCounter != null) && statCounter.IsLocked)
                {
                    totalStatCounter.Merge(statCounter);

                    totalQueriesPerInterval[minute] = statCounter.TotalQueries;

                    totalNoErrorPerInterval[minute] = statCounter.TotalNoError;
                    totalServerFailurePerInterval[minute] = statCounter.TotalServerFailure;
                    totalNxDomainPerInterval[minute] = statCounter.TotalNxDomain;
                    totalRefusedPerInterval[minute] = statCounter.TotalRefused;

                    totalAuthHitPerInterval[minute] = statCounter.TotalAuthoritative;
                    totalRecursionsPerInterval[minute] = statCounter.TotalRecursive;
                    totalCacheHitPerInterval[minute] = statCounter.TotalCached;
                    totalBlockedPerInterval[minute] = statCounter.TotalBlocked;
                    totalDroppedPerInterval[minute] = statCounter.TotalDropped;

                    totalClientsPerInterval[minute] = statCounter.TotalClients;
                }
            }

            DashboardStats.ChartData mainChartData = new DashboardStats.ChartData()
            {
                Labels = labels,
                DataSets =
                [
                    new DashboardStats.DataSet()
                    {
                        Label = "Total",
                        Data = totalQueriesPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "No Error",
                        Data = totalNoErrorPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Server Failure",
                        Data = totalServerFailurePerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "NX Domain",
                        Data = totalNxDomainPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Refused",
                        Data = totalRefusedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Authoritative",
                        Data = totalAuthHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Recursive",
                        Data = totalRecursionsPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Cached",
                        Data = totalCacheHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Blocked",
                        Data = totalBlockedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Dropped",
                        Data = totalDroppedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Clients",
                        Data = totalClientsPerInterval
                    }
                ]
            };

            return new DashboardStats()
            {
                Stats = totalStatCounter.GetStatsData(),
                MainChartData = mainChartData,
                QueryResponseChartData = totalStatCounter.GetQueryResponseChartData(),
                QueryTypeChartData = totalStatCounter.GetTopQueryTypesChartData(),
                ProtocolTypeChartData = totalStatCounter.GetTopProtocolTypesChartData(),
                TopClients = totalStatCounter.GetTopClientStats(10),
                TopDomains = totalStatCounter.GetTopDomainStats(10),
                TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(10)
            };
        }

        private StatCounter MergeLastCompletedMinutes(int minutes)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            DateTime startDateTime = DateTime.UtcNow.AddMinutes(-minutes);
            startDateTime = new DateTime(startDateTime.Year, startDateTime.Month, startDateTime.Day, startDateTime.Hour, startDateTime.Minute, 0, DateTimeKind.Utc);

            for (int minute = 0; minute < minutes; minute++)
            {
                StatCounter statCounter = _lastHourStatCountersCopy[startDateTime.AddMinutes(minute).Minute];
                if ((statCounter != null) && statCounter.IsLocked)
                    totalStatCounter.Merge(statCounter);
            }

            return totalStatCounter;
        }

        public DashboardStats GetShortTermStats(int rangeSeconds, bool utcFormat)
        {
            DashboardStats dashboardStats = _shortTermStats.GetStats(rangeSeconds, 60, utcFormat);
            StatCounter totalStatCounter = MergeLastCompletedMinutes(Math.Max(1, rangeSeconds / 60));

            dashboardStats.QueryTypeChartData = totalStatCounter.GetTopQueryTypesChartData();
            dashboardStats.ProtocolTypeChartData = totalStatCounter.GetTopProtocolTypesChartData();
            dashboardStats.TopClients = totalStatCounter.GetTopClientStats(10);
            dashboardStats.TopDomains = totalStatCounter.GetTopDomainStats(10);
            dashboardStats.TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(10);

            return dashboardStats;
        }

        public DashboardStats GetShortTermTopStats(int rangeSeconds, DashboardTopStatsType type, int limit)
        {
            StatCounter totalStatCounter = MergeLastCompletedMinutes(Math.Max(1, rangeSeconds / 60));

            switch (type)
            {
                case DashboardTopStatsType.TopClients:
                    return new DashboardStats() { TopClients = totalStatCounter.GetTopClientStats(limit) };

                case DashboardTopStatsType.TopDomains:
                    return new DashboardStats() { TopDomains = totalStatCounter.GetTopDomainStats(limit) };

                case DashboardTopStatsType.TopBlockedDomains:
                    return new DashboardStats() { TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(limit) };

                default:
                    throw new NotSupportedException();
            }
        }

        public DashboardStats GetLastDayHourWiseStats(bool utcFormat)
        {
            return GetHourWiseStats(DateTime.UtcNow.AddHours(-24), 24, utcFormat);
        }

        public DashboardStats GetLastWeekDayWiseStats(bool utcFormat)
        {
            return GetDayWiseStats(DateTime.UtcNow.AddDays(-7).Date, 7, utcFormat);
        }

        public DashboardStats GetLastMonthDayWiseStats(bool utcFormat)
        {
            return GetDayWiseStats(DateTime.UtcNow.AddDays(-31).Date, 31, utcFormat);
        }

        public DashboardStats GetLastYearMonthWiseStats(bool utcFormat)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            string[] labels = new string[12];

            long[] totalQueriesPerInterval = new long[12];
            long[] totalNoErrorPerInterval = new long[12];
            long[] totalServerFailurePerInterval = new long[12];
            long[] totalNxDomainPerInterval = new long[12];
            long[] totalRefusedPerInterval = new long[12];

            long[] totalAuthHitPerInterval = new long[12];
            long[] totalRecursionsPerInterval = new long[12];
            long[] totalCacheHitPerInterval = new long[12];
            long[] totalBlockedPerInterval = new long[12];
            long[] totalDroppedPerInterval = new long[12];

            long[] totalClientsPerInterval = new long[12];

            DateTime lastYearDateTime = DateTime.UtcNow.AddMonths(-12);
            lastYearDateTime = new DateTime(lastYearDateTime.Year, lastYearDateTime.Month, 1, 0, 0, 0, DateTimeKind.Utc);

            for (int month = 0; month < 12; month++)
            {
                DateTime lastMonthDateTime = lastYearDateTime.AddMonths(month);
                string label;

                if (utcFormat)
                    label = lastMonthDateTime.ToString("O", CultureInfo.InvariantCulture);
                else
                    label = lastMonthDateTime.ToLocalTime().ToString("MM/yyyy", CultureInfo.InvariantCulture);

                labels[month] = label;

                StatCounter monthlyStatCounter = LoadMonthlyStats(lastMonthDateTime);

                totalStatCounter.Merge(monthlyStatCounter, true);

                totalQueriesPerInterval[month] = monthlyStatCounter.TotalQueries;

                totalNoErrorPerInterval[month] = monthlyStatCounter.TotalNoError;
                totalServerFailurePerInterval[month] = monthlyStatCounter.TotalServerFailure;
                totalNxDomainPerInterval[month] = monthlyStatCounter.TotalNxDomain;
                totalRefusedPerInterval[month] = monthlyStatCounter.TotalRefused;

                totalAuthHitPerInterval[month] = monthlyStatCounter.TotalAuthoritative;
                totalRecursionsPerInterval[month] = monthlyStatCounter.TotalRecursive;
                totalCacheHitPerInterval[month] = monthlyStatCounter.TotalCached;
                totalBlockedPerInterval[month] = monthlyStatCounter.TotalBlocked;
                totalDroppedPerInterval[month] = monthlyStatCounter.TotalDropped;

                totalClientsPerInterval[month] = monthlyStatCounter.TotalClients;
            }

            DashboardStats.ChartData mainChartData = new DashboardStats.ChartData()
            {
                Labels = labels,
                DataSets =
                [
                    new DashboardStats.DataSet()
                    {
                        Label = "Total",
                        Data = totalQueriesPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "No Error",
                        Data = totalNoErrorPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Server Failure",
                        Data = totalServerFailurePerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "NX Domain",
                        Data = totalNxDomainPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Refused",
                        Data = totalRefusedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Authoritative",
                        Data = totalAuthHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Recursive",
                        Data = totalRecursionsPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Cached",
                        Data = totalCacheHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Blocked",
                        Data = totalBlockedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Dropped",
                        Data = totalDroppedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Clients",
                        Data = totalClientsPerInterval
                    }
                ]
            };

            return new DashboardStats()
            {
                Stats = totalStatCounter.GetStatsData(),
                MainChartData = mainChartData,
                QueryResponseChartData = totalStatCounter.GetQueryResponseChartData(),
                QueryTypeChartData = totalStatCounter.GetTopQueryTypesChartData(),
                ProtocolTypeChartData = totalStatCounter.GetTopProtocolTypesChartData(),
                TopClients = totalStatCounter.GetTopClientStats(10),
                TopDomains = totalStatCounter.GetTopDomainStats(10),
                TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(10)
            };
        }

        public DashboardStats GetMinuteWiseStats(DateTime startDate, DateTime endDate, bool utcFormat)
        {
            return GetMinuteWiseStats(startDate, Convert.ToInt32((endDate - startDate).TotalMinutes) + 1, utcFormat);
        }

        public DashboardStats GetMinuteWiseStats(DateTime startDate, int minutes, bool utcFormat)
        {
            startDate = startDate.AddMinutes(-1);

            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            string[] labels = new string[minutes];

            long[] totalQueriesPerInterval = new long[minutes];
            long[] totalNoErrorPerInterval = new long[minutes];
            long[] totalServerFailurePerInterval = new long[minutes];
            long[] totalNxDomainPerInterval = new long[minutes];
            long[] totalRefusedPerInterval = new long[minutes];

            long[] totalAuthHitPerInterval = new long[minutes];
            long[] totalRecursionsPerInterval = new long[minutes];
            long[] totalCacheHitPerInterval = new long[minutes];
            long[] totalBlockedPerInterval = new long[minutes];
            long[] totalDroppedPerInterval = new long[minutes];

            long[] totalClientsPerInterval = new long[minutes];

            for (int minute = 0; minute < minutes; minute++)
            {
                DateTime lastDateTime = startDate.AddMinutes(minute);

                HourlyStats hourlyStats = LoadHourlyStats(lastDateTime, ifNotExistsReturnEmptyHourlyStats: true);
                if (hourlyStats.MinuteStats is null)
                    hourlyStats = LoadHourlyStats(lastDateTime, forceReload: true);

                StatCounter minuteStatCounter = hourlyStats.MinuteStats[lastDateTime.Minute];

                string label;

                if (utcFormat)
                    label = lastDateTime.AddMinutes(1).ToString("O", CultureInfo.InvariantCulture);
                else
                    label = lastDateTime.AddMinutes(1).ToLocalTime().ToString("MM/dd HH:mm", CultureInfo.InvariantCulture);

                labels[minute] = label;

                totalStatCounter.Merge(minuteStatCounter);

                totalQueriesPerInterval[minute] = minuteStatCounter.TotalQueries;

                totalNoErrorPerInterval[minute] = minuteStatCounter.TotalNoError;
                totalServerFailurePerInterval[minute] = minuteStatCounter.TotalServerFailure;
                totalNxDomainPerInterval[minute] = minuteStatCounter.TotalNxDomain;
                totalRefusedPerInterval[minute] = minuteStatCounter.TotalRefused;

                totalAuthHitPerInterval[minute] = minuteStatCounter.TotalAuthoritative;
                totalRecursionsPerInterval[minute] = minuteStatCounter.TotalRecursive;
                totalCacheHitPerInterval[minute] = minuteStatCounter.TotalCached;
                totalBlockedPerInterval[minute] = minuteStatCounter.TotalBlocked;
                totalDroppedPerInterval[minute] = minuteStatCounter.TotalDropped;

                totalClientsPerInterval[minute] = minuteStatCounter.TotalClients;
            }

            DashboardStats.ChartData mainChartData = new DashboardStats.ChartData()
            {
                Labels = labels,
                DataSets =
                [
                    new DashboardStats.DataSet()
                    {
                        Label = "Total",
                        Data = totalQueriesPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "No Error",
                        Data = totalNoErrorPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Server Failure",
                        Data = totalServerFailurePerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "NX Domain",
                        Data = totalNxDomainPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Refused",
                        Data = totalRefusedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Authoritative",
                        Data = totalAuthHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Recursive",
                        Data = totalRecursionsPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Cached",
                        Data = totalCacheHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Blocked",
                        Data = totalBlockedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Dropped",
                        Data = totalDroppedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Clients",
                        Data = totalClientsPerInterval
                    }
                ]
            };

            return new DashboardStats()
            {
                Stats = totalStatCounter.GetStatsData(),
                MainChartData = mainChartData,
                QueryResponseChartData = totalStatCounter.GetQueryResponseChartData(),
                QueryTypeChartData = totalStatCounter.GetTopQueryTypesChartData(),
                ProtocolTypeChartData = totalStatCounter.GetTopProtocolTypesChartData(),
                TopClients = totalStatCounter.GetTopClientStats(10),
                TopDomains = totalStatCounter.GetTopDomainStats(10),
                TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(10)
            };
        }

        public DashboardStats GetHourWiseStats(DateTime startDate, DateTime endDate, bool utcFormat)
        {
            return GetHourWiseStats(startDate, Convert.ToInt32((endDate - startDate).TotalHours) + 1, utcFormat);
        }

        public DashboardStats GetHourWiseStats(DateTime startDate, int hours, bool utcFormat)
        {
            startDate = new DateTime(startDate.Year, startDate.Month, startDate.Day, startDate.Hour, 0, 0, 0, DateTimeKind.Utc);

            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            string[] labels = new string[hours];

            long[] totalQueriesPerInterval = new long[hours];
            long[] totalNoErrorPerInterval = new long[hours];
            long[] totalServerFailurePerInterval = new long[hours];
            long[] totalNxDomainPerInterval = new long[hours];
            long[] totalRefusedPerInterval = new long[hours];

            long[] totalAuthHitPerInterval = new long[hours];
            long[] totalRecursionsPerInterval = new long[hours];
            long[] totalCacheHitPerInterval = new long[hours];
            long[] totalBlockedPerInterval = new long[hours];
            long[] totalDroppedPerInterval = new long[hours];

            long[] totalClientsPerInterval = new long[hours];

            for (int hour = 0; hour < hours; hour++)
            {
                DateTime lastDateTime = startDate.AddHours(hour);
                string label;

                if (utcFormat)
                    label = lastDateTime.AddHours(1).ToString("O", CultureInfo.InvariantCulture);
                else
                    label = lastDateTime.AddHours(1).ToLocalTime().ToString("MM/dd HH", CultureInfo.InvariantCulture) + ":00";

                labels[hour] = label;

                HourlyStats hourlyStats = LoadHourlyStats(lastDateTime, ifNotExistsReturnEmptyHourlyStats: true, loadMinuteStats: false);
                StatCounter hourlyStatCounter = hourlyStats.HourStat;

                totalStatCounter.Merge(hourlyStatCounter);

                totalQueriesPerInterval[hour] = hourlyStatCounter.TotalQueries;

                totalNoErrorPerInterval[hour] = hourlyStatCounter.TotalNoError;
                totalServerFailurePerInterval[hour] = hourlyStatCounter.TotalServerFailure;
                totalNxDomainPerInterval[hour] = hourlyStatCounter.TotalNxDomain;
                totalRefusedPerInterval[hour] = hourlyStatCounter.TotalRefused;

                totalAuthHitPerInterval[hour] = hourlyStatCounter.TotalAuthoritative;
                totalRecursionsPerInterval[hour] = hourlyStatCounter.TotalRecursive;
                totalCacheHitPerInterval[hour] = hourlyStatCounter.TotalCached;
                totalBlockedPerInterval[hour] = hourlyStatCounter.TotalBlocked;
                totalDroppedPerInterval[hour] = hourlyStatCounter.TotalDropped;

                totalClientsPerInterval[hour] = hourlyStatCounter.TotalClients;
            }

            DashboardStats.ChartData mainChartData = new DashboardStats.ChartData()
            {
                Labels = labels,
                DataSets =
                [
                    new DashboardStats.DataSet()
                    {
                        Label = "Total",
                        Data = totalQueriesPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "No Error",
                        Data = totalNoErrorPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Server Failure",
                        Data = totalServerFailurePerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "NX Domain",
                        Data = totalNxDomainPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Refused",
                        Data = totalRefusedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Authoritative",
                        Data = totalAuthHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Recursive",
                        Data = totalRecursionsPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Cached",
                        Data = totalCacheHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Blocked",
                        Data = totalBlockedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Dropped",
                        Data = totalDroppedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Clients",
                        Data = totalClientsPerInterval
                    }
                ]
            };

            return new DashboardStats()
            {
                Stats = totalStatCounter.GetStatsData(),
                MainChartData = mainChartData,
                QueryResponseChartData = totalStatCounter.GetQueryResponseChartData(),
                QueryTypeChartData = totalStatCounter.GetTopQueryTypesChartData(),
                ProtocolTypeChartData = totalStatCounter.GetTopProtocolTypesChartData(),
                TopClients = totalStatCounter.GetTopClientStats(10),
                TopDomains = totalStatCounter.GetTopDomainStats(10),
                TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(10)
            };
        }

        public DashboardStats GetDayWiseStats(DateTime startDate, DateTime endDate, bool utcFormat)
        {
            return GetDayWiseStats(startDate, Convert.ToInt32((endDate - startDate).TotalDays) + 1, utcFormat);
        }

        public DashboardStats GetDayWiseStats(DateTime startDate, int days, bool utcFormat)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            string[] labels = new string[days];

            long[] totalQueriesPerInterval = new long[days];
            long[] totalNoErrorPerInterval = new long[days];
            long[] totalServerFailurePerInterval = new long[days];
            long[] totalNxDomainPerInterval = new long[days];
            long[] totalRefusedPerInterval = new long[days];

            long[] totalAuthHitPerInterval = new long[days];
            long[] totalRecursionsPerInterval = new long[days];
            long[] totalCacheHitPerInterval = new long[days];
            long[] totalBlockedPerInterval = new long[days];
            long[] totalDroppedPerInterval = new long[days];

            long[] totalClientsPerInterval = new long[days];

            for (int day = 0; day < days; day++)
            {
                DateTime lastDayDateTime = startDate.AddDays(day);
                string label;

                if (utcFormat)
                    label = lastDayDateTime.ToString("O", CultureInfo.InvariantCulture);
                else
                    label = lastDayDateTime.ToLocalTime().ToString("MM/dd", CultureInfo.InvariantCulture);

                labels[day] = label;

                StatCounter dailyStatCounter = LoadDailyStats(lastDayDateTime);
                totalStatCounter.Merge(dailyStatCounter, true);

                totalQueriesPerInterval[day] = dailyStatCounter.TotalQueries;

                totalNoErrorPerInterval[day] = dailyStatCounter.TotalNoError;
                totalServerFailurePerInterval[day] = dailyStatCounter.TotalServerFailure;
                totalNxDomainPerInterval[day] = dailyStatCounter.TotalNxDomain;
                totalRefusedPerInterval[day] = dailyStatCounter.TotalRefused;

                totalAuthHitPerInterval[day] = dailyStatCounter.TotalAuthoritative;
                totalRecursionsPerInterval[day] = dailyStatCounter.TotalRecursive;
                totalCacheHitPerInterval[day] = dailyStatCounter.TotalCached;
                totalBlockedPerInterval[day] = dailyStatCounter.TotalBlocked;
                totalDroppedPerInterval[day] = dailyStatCounter.TotalDropped;

                totalClientsPerInterval[day] = dailyStatCounter.TotalClients;
            }

            DashboardStats.ChartData mainChartData = new DashboardStats.ChartData()
            {
                Labels = labels,
                DataSets =
                [
                    new DashboardStats.DataSet()
                    {
                        Label = "Total",
                        Data = totalQueriesPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "No Error",
                        Data = totalNoErrorPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Server Failure",
                        Data = totalServerFailurePerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "NX Domain",
                        Data = totalNxDomainPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Refused",
                        Data = totalRefusedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Authoritative",
                        Data = totalAuthHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Recursive",
                        Data = totalRecursionsPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Cached",
                        Data = totalCacheHitPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Blocked",
                        Data = totalBlockedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Dropped",
                        Data = totalDroppedPerInterval
                    },
                    new DashboardStats.DataSet()
                    {
                        Label = "Clients",
                        Data = totalClientsPerInterval
                    }
                ]
            };

            return new DashboardStats()
            {
                Stats = totalStatCounter.GetStatsData(),
                MainChartData = mainChartData,
                QueryResponseChartData = totalStatCounter.GetQueryResponseChartData(),
                QueryTypeChartData = totalStatCounter.GetTopQueryTypesChartData(),
                ProtocolTypeChartData = totalStatCounter.GetTopProtocolTypesChartData(),
                TopClients = totalStatCounter.GetTopClientStats(10),
                TopDomains = totalStatCounter.GetTopDomainStats(10),
                TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(10)
            };
        }

        public DashboardStats GetLastHourTopStats(DashboardTopStatsType type, int limit)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            DateTime lastHourDateTime = DateTime.UtcNow.AddMinutes(-60);
            lastHourDateTime = new DateTime(lastHourDateTime.Year, lastHourDateTime.Month, lastHourDateTime.Day, lastHourDateTime.Hour, lastHourDateTime.Minute, 0, DateTimeKind.Utc);

            for (int minute = 0; minute < 60; minute++)
            {
                DateTime lastDateTime = lastHourDateTime.AddMinutes(minute);

                StatCounter statCounter = _lastHourStatCountersCopy[lastDateTime.Minute];
                if ((statCounter != null) && statCounter.IsLocked)
                    totalStatCounter.Merge(statCounter);
            }

            switch (type)
            {
                case DashboardTopStatsType.TopClients:
                    return new DashboardStats()
                    {
                        TopClients = totalStatCounter.GetTopClientStats(limit),
                    };

                case DashboardTopStatsType.TopDomains:
                    return new DashboardStats()
                    {
                        TopDomains = totalStatCounter.GetTopDomainStats(limit),
                    };

                case DashboardTopStatsType.TopBlockedDomains:
                    return new DashboardStats()
                    {
                        TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(limit)
                    };

                default:
                    throw new NotSupportedException();
            }
        }

        public DashboardStats GetLastDayTopStats(DashboardTopStatsType type, int limit)
        {
            return GetHourWiseTopStats(DateTime.UtcNow.AddHours(-24), 24, type, limit);
        }

        public DashboardStats GetLastWeekTopStats(DashboardTopStatsType type, int limit)
        {
            return GetDayWiseTopStats(DateTime.UtcNow.AddDays(-7).Date, 7, type, limit);
        }

        public DashboardStats GetLastMonthTopStats(DashboardTopStatsType type, int limit)
        {
            return GetDayWiseTopStats(DateTime.UtcNow.AddDays(-31).Date, 31, type, limit);
        }

        public DashboardStats GetLastYearTopStats(DashboardTopStatsType type, int limit)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            DateTime lastYearDateTime = DateTime.UtcNow.AddMonths(-12);
            lastYearDateTime = new DateTime(lastYearDateTime.Year, lastYearDateTime.Month, 1, 0, 0, 0, DateTimeKind.Utc);

            for (int month = 0; month < 12; month++)
                totalStatCounter.Merge(LoadMonthlyStats(lastYearDateTime.AddMonths(month)), true);

            switch (type)
            {
                case DashboardTopStatsType.TopClients:
                    return new DashboardStats()
                    {
                        TopClients = totalStatCounter.GetTopClientStats(limit),
                    };

                case DashboardTopStatsType.TopDomains:
                    return new DashboardStats()
                    {
                        TopDomains = totalStatCounter.GetTopDomainStats(limit),
                    };

                case DashboardTopStatsType.TopBlockedDomains:
                    return new DashboardStats()
                    {
                        TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(limit)
                    };

                default:
                    throw new NotSupportedException();
            }
        }

        public DashboardStats GetMinuteWiseTopStats(DateTime startDate, DateTime endDate, DashboardTopStatsType type, int limit)
        {
            return GetMinuteWiseTopStats(startDate, Convert.ToInt32((endDate - startDate).TotalMinutes) + 1, type, limit);
        }

        public DashboardStats GetMinuteWiseTopStats(DateTime startDate, int minutes, DashboardTopStatsType type, int limit)
        {
            startDate = startDate.AddMinutes(-1);

            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            for (int minute = 0; minute < minutes; minute++)
            {
                DateTime lastDateTime = startDate.AddMinutes(minute);

                HourlyStats hourlyStats = LoadHourlyStats(lastDateTime, ifNotExistsReturnEmptyHourlyStats: true);
                if (hourlyStats.MinuteStats is null)
                    hourlyStats = LoadHourlyStats(lastDateTime, forceReload: true);

                StatCounter minuteStatCounter = hourlyStats.MinuteStats[lastDateTime.Minute];

                totalStatCounter.Merge(minuteStatCounter);
            }

            switch (type)
            {
                case DashboardTopStatsType.TopClients:
                    return new DashboardStats()
                    {
                        TopClients = totalStatCounter.GetTopClientStats(limit),
                    };

                case DashboardTopStatsType.TopDomains:
                    return new DashboardStats()
                    {
                        TopDomains = totalStatCounter.GetTopDomainStats(limit),
                    };

                case DashboardTopStatsType.TopBlockedDomains:
                    return new DashboardStats()
                    {
                        TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(limit)
                    };

                default:
                    throw new NotSupportedException();
            }
        }

        public DashboardStats GetHourWiseTopStats(DateTime startDate, DateTime endDate, DashboardTopStatsType type, int limit)
        {
            return GetHourWiseTopStats(startDate, Convert.ToInt32((endDate - startDate).TotalHours) + 1, type, limit);
        }

        public DashboardStats GetHourWiseTopStats(DateTime startDate, int hours, DashboardTopStatsType type, int limit)
        {
            startDate = new DateTime(startDate.Year, startDate.Month, startDate.Day, startDate.Hour, 0, 0, 0, DateTimeKind.Utc);

            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            for (int hour = 0; hour < hours; hour++)
            {
                DateTime lastDateTime = startDate.AddHours(hour);

                HourlyStats hourlyStats = LoadHourlyStats(lastDateTime, ifNotExistsReturnEmptyHourlyStats: true, loadMinuteStats: false);
                StatCounter hourlyStatCounter = hourlyStats.HourStat;

                totalStatCounter.Merge(hourlyStatCounter);
            }

            switch (type)
            {
                case DashboardTopStatsType.TopClients:
                    return new DashboardStats()
                    {
                        TopClients = totalStatCounter.GetTopClientStats(limit),
                    };

                case DashboardTopStatsType.TopDomains:
                    return new DashboardStats()
                    {
                        TopDomains = totalStatCounter.GetTopDomainStats(limit),
                    };

                case DashboardTopStatsType.TopBlockedDomains:
                    return new DashboardStats()
                    {
                        TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(limit)
                    };

                default:
                    throw new NotSupportedException();
            }
        }

        public DashboardStats GetDayWiseTopStats(DateTime startDate, DateTime endDate, DashboardTopStatsType type, int limit)
        {
            return GetDayWiseTopStats(startDate, Convert.ToInt32((endDate - startDate).TotalDays) + 1, type, limit);
        }

        public DashboardStats GetDayWiseTopStats(DateTime startDate, int days, DashboardTopStatsType type, int limit)
        {
            StatCounter totalStatCounter = new StatCounter();
            totalStatCounter.Lock();

            for (int day = 0; day < days; day++)
            {
                DateTime lastDayDateTime = startDate.AddDays(day);

                StatCounter dailyStatCounter = LoadDailyStats(lastDayDateTime);
                totalStatCounter.Merge(dailyStatCounter, true);
            }

            switch (type)
            {
                case DashboardTopStatsType.TopClients:
                    return new DashboardStats()
                    {
                        TopClients = totalStatCounter.GetTopClientStats(limit),
                    };

                case DashboardTopStatsType.TopDomains:
                    return new DashboardStats()
                    {
                        TopDomains = totalStatCounter.GetTopDomainStats(limit),
                    };

                case DashboardTopStatsType.TopBlockedDomains:
                    return new DashboardStats()
                    {
                        TopBlockedDomains = totalStatCounter.GetTopBlockedDomainStats(limit)
                    };

                default:
                    throw new NotSupportedException();
            }
        }

        #endregion

        #region properties

        public ResponseTimeStats ResponseTimeStats
        { get { return _responseTimeStats; } }

        internal int QueueLength
        { get { return Math.Max(0, Volatile.Read(ref _queueLength)); } }

        internal int DropQueuedItems()
        {
            int dropped = 0;

            while (_queue.TryDequeue(out _))
            {
                Interlocked.Decrement(ref _queueLength);
                dropped++;
            }

            return dropped;
        }

        public long TotalQueries
        { get { return _totalQueries; } }

        public long TotalNoError
        { get { return _totalNoError; } }

        public long TotalServerFailure
        { get { return _totalServerFailure; } }

        public long TotalNxDomain
        { get { return _totalNxDomain; } }

        public long TotalRefused
        { get { return _totalRefused; } }

        public long TotalAuthoritative
        { get { return _totalAuthoritative; } }

        public long TotalRecursive
        { get { return _totalRecursive; } }

        public long TotalCached
        { get { return _totalCached; } }

        public long TotalBlocked
        { get { return _totalBlocked; } }

        public long TotalDropped
        { get { return _totalDropped; } }

        public long TotalClients
        { get { return _uniqueClients.Estimate(); } }

        public bool EnableInMemoryStats
        {
            get { return _enableInMemoryStats; }
            set
            {
                if (_enableInMemoryStats != value)
                {
                    _enableInMemoryStats = value;

                    if (_enableInMemoryStats)
                    {
                        _hourlyStatsCache = new ConcurrentDictionary<DateTime, HourlyStats>(1, 1);
                        _dailyStatsCache = new ConcurrentDictionary<DateTime, StatCounter>(1, 1);
                        _monthlyStatsCache = new ConcurrentDictionary<DateTime, StatCounter>(1, 1);
                    }
                }
            }
        }

        public int MaxStatFileDays
        {
            get { return _maxStatFileDays; }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(MaxStatFileDays), "MaxStatFileDays must be greater than or equal to 0.");

                _maxStatFileDays = value;

                if (_maxStatFileDays == 0)
                    _statsCleanupTimer.Change(Timeout.Infinite, Timeout.Infinite);
                else
                    _statsCleanupTimer.Change(STATS_CLEANUP_TIMER_INITIAL_INTERVAL, STATS_CLEANUP_TIMER_PERIODIC_INTERVAL);
            }
        }

        #endregion

        class HourlyStats
        {
            #region variables

            public readonly static HourlyStats Empty = new HourlyStats();

            readonly StatCounter _hourStat;
            StatCounter[] _minuteStats;

            bool _truncated;

            #endregion

            #region constructor

            public HourlyStats()
            {
                _hourStat = new StatCounter();
                _hourStat.Lock();

                _minuteStats = new StatCounter[60];

                for (int i = 0; i < _minuteStats.Length; i++)
                {
                    _minuteStats[i] = new StatCounter();
                    _minuteStats[i].Lock();
                }
            }

            public HourlyStats(BinaryReader bR, bool loadMinuteStats)
            {
                if (Encoding.ASCII.GetString(bR.BaseStream.ReadExactly(2)) != "HS")
                    throw new InvalidDataException("HourlyStats format is invalid.");

                byte version = bR.ReadByte();
                switch (version)
                {
                    case 1:
                        _hourStat = new StatCounter();
                        _hourStat.Lock();

                        if (loadMinuteStats)
                            _minuteStats = new StatCounter[60];

                        for (int i = 0; i < 60; i++)
                        {
                            StatCounter minuteStat = new StatCounter(bR);
                            _hourStat.Merge(minuteStat);

                            if (loadMinuteStats)
                            {
                                minuteStat.Truncate(STATS_TOP_LIMIT);
                                _minuteStats[i] = minuteStat;
                            }
                        }

                        break;

                    case 2:
                        _hourStat = new StatCounter(bR);

                        if (loadMinuteStats)
                        {
                            _minuteStats = new StatCounter[60];

                            for (int i = 0; i < 60; i++)
                                _minuteStats[i] = new StatCounter(bR);
                        }

                        break;

                    default:
                        throw new InvalidDataException("HourlyStats version not supported.");
                }
            }

            #endregion

            #region public

            public void UpdateStat(DateTime dateTime, StatCounter minuteStat)
            {
                if (_truncated)
                    throw new InvalidOperationException();

                if (ReferenceEquals(this, Empty))
                    return;

                if (!minuteStat.IsLocked)
                    throw new DnsServerException("StatCounter must be locked.");

                _hourStat.Merge(minuteStat);
                _minuteStats[dateTime.Minute] = minuteStat;
            }

            public void UnloadMinuteStats()
            {
                if (ReferenceEquals(this, Empty))
                    return;

                _minuteStats = null;
            }

            public bool Truncate(int limit)
            {
                if (ReferenceEquals(this, Empty))
                    return false;

                StatCounter[] minuteStats = _minuteStats;
                if (minuteStats is not null)
                {
                    foreach (StatCounter minuteStat in minuteStats)
                        minuteStat?.Truncate(limit);
                }

                if (_truncated)
                    return false;

                if (_hourStat.Truncate(limit))
                    _truncated = true;

                return _truncated;
            }

            public void WriteTo(BinaryWriter bW)
            {
                bW.Write(Encoding.ASCII.GetBytes("HS"));
                bW.Write((byte)2);

                _hourStat.WriteTo(bW, STATS_HOUR_LIMIT);

                for (int i = 0; i < _minuteStats.Length; i++)
                {
                    if (_minuteStats[i] == null)
                    {
                        _minuteStats[i] = new StatCounter();
                        _minuteStats[i].Lock();
                    }

                    _minuteStats[i].WriteTo(bW);
                }
            }

            #endregion

            #region properties

            public StatCounter HourStat
            { get { return _hourStat; } }

            public StatCounter[] MinuteStats
            { get { return _minuteStats; } }

            public bool Truncated
            { get { return _truncated; } }

            #endregion
        }

        class StatCounter
        {
            #region variables

            const int MAX_COUNTER_ENTRIES = 200000;
            const int CLIENT_SKETCH_PRECISION = 12;

            public readonly static StatCounter Empty = new StatCounter() { _locked = true };

            volatile bool _locked;

            long _totalQueries;
            long _totalNoError;
            long _totalServerFailure;
            long _totalNxDomain;
            long _totalRefused;

            long _totalAuthoritative;
            long _totalRecursive;
            long _totalCached;
            long _totalBlocked;
            long _totalDropped;

            long _totalClients;

            ConcurrentDictionary<string, Counter> _queryDomains;
            ConcurrentDictionary<string, Counter> _queryBlockedDomains;
            ConcurrentDictionary<DnsResourceRecordType, Counter> _queryTypes;
            readonly ConcurrentDictionary<DnsTransportProtocol, Counter> _protocolTypes;
            ConcurrentDictionary<IPAddress, (Counter, Counter)> _clientIpAddressesUdpTcp;
            UniqueAddressCounter _clientSketch;

            bool _truncationFoundDuringMerge;
            long _totalClientsDailyStatsSummation;

            #endregion

            #region constructor

            public StatCounter()
            {
                _queryDomains = new ConcurrentDictionary<string, Counter>(1, 10);
                _queryBlockedDomains = new ConcurrentDictionary<string, Counter>(1, 10);
                _queryTypes = new ConcurrentDictionary<DnsResourceRecordType, Counter>(1, 10);
                _protocolTypes = new ConcurrentDictionary<DnsTransportProtocol, Counter>(1, 2);
                _clientIpAddressesUdpTcp = new ConcurrentDictionary<IPAddress, (Counter, Counter)>(1, 10);
            }

            public StatCounter(BinaryReader bR)
            {
                if (Encoding.ASCII.GetString(bR.BaseStream.ReadExactly(2)) != "SC")
                    throw new InvalidDataException("StatCounter format is invalid.");

                byte version = bR.ReadByte();
                switch (version)
                {
                    case 1:
                    case 2:
                    case 3:
                    case 4:
                    case 5:
                    case 6:
                        _totalQueries = bR.ReadInt32();
                        _totalNoError = bR.ReadInt32();
                        _totalServerFailure = bR.ReadInt32();
                        _totalNxDomain = bR.ReadInt32();
                        _totalRefused = bR.ReadInt32();

                        if (version >= 3)
                        {
                            _totalAuthoritative = bR.ReadInt32();
                            _totalRecursive = bR.ReadInt32();
                            _totalCached = bR.ReadInt32();
                            _totalBlocked = bR.ReadInt32();
                        }
                        else
                        {
                            _totalBlocked = bR.ReadInt32();

                            if (version >= 2)
                                _totalCached = bR.ReadInt32();
                        }

                        if (version >= 6)
                            _totalClients = bR.ReadInt32();

                        {
                            int count = bR.ReadInt32();
                            _queryDomains = new ConcurrentDictionary<string, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queryDomains.TryAdd(bR.BaseStream.ReadShortString(), new Counter(bR.ReadInt32()));
                        }

                        {
                            int count = bR.ReadInt32();
                            _queryBlockedDomains = new ConcurrentDictionary<string, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queryBlockedDomains.TryAdd(bR.BaseStream.ReadShortString(), new Counter(bR.ReadInt32()));
                        }

                        {
                            int count = bR.ReadInt32();
                            _queryTypes = new ConcurrentDictionary<DnsResourceRecordType, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queryTypes.TryAdd((DnsResourceRecordType)bR.ReadUInt16(), new Counter(bR.ReadInt32()));
                        }

                        _protocolTypes = new ConcurrentDictionary<DnsTransportProtocol, Counter>(1, 0);

                        {
                            int count = bR.ReadInt32();
                            _clientIpAddressesUdpTcp = new ConcurrentDictionary<IPAddress, (Counter, Counter)>(1, count);

                            for (int i = 0; i < count; i++)
                                _clientIpAddressesUdpTcp.TryAdd(IPAddressExtensions.ReadFrom(bR), (new Counter(bR.ReadInt32()), new Counter()));

                            if (version < 6)
                                _totalClients = count;
                        }

                        if (version >= 4)
                        {
                            int count = bR.ReadInt32();

                            for (int i = 0; i < count; i++)
                            {
                                _ = new DnsQuestionRecord(bR.BaseStream);
                                _ = bR.ReadInt32();
                            }
                        }

                        if (version >= 5)
                        {
                            int count = bR.ReadInt32();
                            ConcurrentDictionary<IPAddress, Counter> errorIpAddresses = new ConcurrentDictionary<IPAddress, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                errorIpAddresses.TryAdd(IPAddressExtensions.ReadFrom(bR), new Counter(bR.ReadInt32()));
                        }

                        break;

                    case 7:
                    case 8:
                    case 9:
                    case 10:
                    case 11:
                        _totalQueries = bR.ReadInt64();
                        _totalNoError = bR.ReadInt64();
                        _totalServerFailure = bR.ReadInt64();
                        _totalNxDomain = bR.ReadInt64();
                        _totalRefused = bR.ReadInt64();

                        _totalAuthoritative = bR.ReadInt64();
                        _totalRecursive = bR.ReadInt64();
                        _totalCached = bR.ReadInt64();
                        _totalBlocked = bR.ReadInt64();

                        if (version >= 8)
                            _totalDropped = bR.ReadInt64();

                        _totalClients = bR.ReadInt64();

                        {
                            int count = bR.ReadInt32();
                            _queryDomains = new ConcurrentDictionary<string, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queryDomains.TryAdd(bR.BaseStream.ReadShortString(), new Counter(bR.ReadInt64()));
                        }

                        {
                            int count = bR.ReadInt32();
                            _queryBlockedDomains = new ConcurrentDictionary<string, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queryBlockedDomains.TryAdd(bR.BaseStream.ReadShortString(), new Counter(bR.ReadInt64()));
                        }

                        {
                            int count = bR.ReadInt32();
                            _queryTypes = new ConcurrentDictionary<DnsResourceRecordType, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _queryTypes.TryAdd((DnsResourceRecordType)bR.ReadUInt16(), new Counter(bR.ReadInt64()));
                        }

                        if (version >= 8)
                        {
                            int count = bR.ReadInt32();
                            _protocolTypes = new ConcurrentDictionary<DnsTransportProtocol, Counter>(1, count);

                            for (int i = 0; i < count; i++)
                                _protocolTypes.TryAdd((DnsTransportProtocol)bR.ReadByte(), new Counter(bR.ReadInt64()));
                        }
                        else
                        {
                            _protocolTypes = new ConcurrentDictionary<DnsTransportProtocol, Counter>(1, 0);
                        }

                        if (version >= 9)
                        {
                            int count = bR.ReadInt32();
                            _clientIpAddressesUdpTcp = new ConcurrentDictionary<IPAddress, (Counter, Counter)>(1, count);

                            for (int i = 0; i < count; i++)
                                _clientIpAddressesUdpTcp.TryAdd(IPAddressExtensions.ReadFrom(bR), (new Counter(bR.ReadInt64()), new Counter(bR.ReadInt64())));
                        }
                        else
                        {
                            int count = bR.ReadInt32();
                            _clientIpAddressesUdpTcp = new ConcurrentDictionary<IPAddress, (Counter, Counter)>(1, count);

                            for (int i = 0; i < count; i++)
                                _clientIpAddressesUdpTcp.TryAdd(IPAddressExtensions.ReadFrom(bR), (new Counter(bR.ReadInt64()), new Counter()));
                        }

                        if (version < 10)
                        {
                            int count = bR.ReadInt32();

                            for (int i = 0; i < count; i++)
                            {
                                _ = new DnsQuestionRecord(bR.BaseStream);
                                _ = bR.ReadInt64();
                            }
                        }

                        if (version <= 8)
                        {
                            int count = bR.ReadInt32();

                            for (int i = 0; i < count; i++)
                            {
                                _ = IPAddressExtensions.ReadFrom(bR);
                                _ = bR.ReadInt64();
                            }
                        }

                        if ((version >= 11) && bR.ReadBoolean())
                        {
                            UniqueAddressCounter clientSketch = new UniqueAddressCounter(bR);

                            if (clientSketch.Precision == CLIENT_SKETCH_PRECISION)
                                _clientSketch = clientSketch;
                        }

                        break;

                    default:
                        throw new InvalidDataException("StatCounter version not supported.");
                }

                _locked = true;
            }

            #endregion

            #region private

            private static List<KeyValuePair<string, T>> GetTopList<T>(List<KeyValuePair<string, T>> list, int limit) where T : DashboardStats.TopStats
            {
                list.Sort(delegate (KeyValuePair<string, T> item1, KeyValuePair<string, T> item2)
                {
                    return item2.Value.Hits.CompareTo(item1.Value.Hits);
                });

                if (list.Count > limit)
                    list.RemoveRange(limit, list.Count - limit);

                return list;
            }

            private static Counter GetNewCounter<T>(T key)
            {
                return new Counter();
            }

            private static (Counter, Counter) GetNewCounterTuple<T>(T key)
            {
                return (new Counter(), new Counter());
            }

            private static int CompareDomainHits(KeyValuePair<string, Counter> item1, KeyValuePair<string, Counter> item2)
            {
                return item2.Value.Count.CompareTo(item1.Value.Count);
            }

            private static int CompareClientHits(KeyValuePair<IPAddress, (Counter, Counter)> item1, KeyValuePair<IPAddress, (Counter, Counter)> item2)
            {
                long hits1 = item1.Value.Item1.Count + item1.Value.Item2.Count;
                long hits2 = item2.Value.Item1.Count + item2.Value.Item2.Count;

                return hits2.CompareTo(hits1);
            }

            private static ConcurrentDictionary<string, Counter> GetTopDomains(ConcurrentDictionary<string, Counter> domains, int limit)
            {
                List<KeyValuePair<string, Counter>> topDomainsList = new List<KeyValuePair<string, Counter>>(domains);

                topDomainsList.Sort(CompareDomainHits);

                if (topDomainsList.Count > limit)
                    topDomainsList.RemoveRange(limit, topDomainsList.Count - limit);

                ConcurrentDictionary<string, Counter> topDomains = new ConcurrentDictionary<string, Counter>(1, topDomainsList.Count);

                foreach (KeyValuePair<string, Counter> item in topDomainsList)
                    topDomains[item.Key] = item.Value;

                return topDomains;
            }

            private static void WriteDomains(BinaryWriter bW, ConcurrentDictionary<string, Counter> domains, int limit)
            {
                List<KeyValuePair<string, Counter>> domainsList = new List<KeyValuePair<string, Counter>>(domains);

                if ((limit > 0) && (domainsList.Count > limit))
                {
                    domainsList.Sort(CompareDomainHits);
                    domainsList.RemoveRange(limit, domainsList.Count - limit);
                }

                bW.Write(domainsList.Count);

                foreach (KeyValuePair<string, Counter> item in domainsList)
                {
                    bW.BaseStream.WriteShortString(item.Key);
                    bW.Write(item.Value.Count);
                }
            }

            private UniqueAddressCounter GetOrCreateClientSketch()
            {
                UniqueAddressCounter clientSketch = _clientSketch;
                if (clientSketch is not null)
                    return clientSketch;

                clientSketch = new UniqueAddressCounter(CLIENT_SKETCH_PRECISION);

                foreach (KeyValuePair<IPAddress, (Counter, Counter)> clientIpAddress in _clientIpAddressesUdpTcp)
                    clientSketch.Add(clientIpAddress.Key);

                _clientSketch = clientSketch;

                return clientSketch;
            }

            #endregion

            #region public

            public void Lock()
            {
                _locked = true;
            }

            private static Counter GetCappedCounter<T>(ConcurrentDictionary<T, Counter> dictionary, T key)
            {
                if (dictionary.TryGetValue(key, out Counter counter))
                    return counter;

                if (dictionary.Count >= MAX_COUNTER_ENTRIES)
                    return null;

                return dictionary.GetOrAdd(key, GetNewCounter);
            }

            private static void IncrementCapped<T>(ConcurrentDictionary<T, Counter> dictionary, T key)
            {
                GetCappedCounter(dictionary, key)?.Increment();
            }

            private (Counter, Counter) GetOrAddClientCounters(IPAddress clientIpAddress)
            {
                if (_clientIpAddressesUdpTcp.TryGetValue(clientIpAddress, out (Counter, Counter) counters))
                    return counters;

                if (_clientIpAddressesUdpTcp.Count >= MAX_COUNTER_ENTRIES)
                    return (new Counter(), new Counter());

                counters = _clientIpAddressesUdpTcp.GetOrAdd(clientIpAddress, GetNewCounterTuple);
                _totalClients = Math.Max(_totalClients, _clientIpAddressesUdpTcp.Count);

                return counters;
            }

            public void Update(DnsQuestionRecord query, DnsResponseCode responseCode, DnsServerResponseType responseType, IPAddress clientIpAddress, DnsTransportProtocol protocol, bool rateLimited)
            {
                if (_locked)
                    return;

                if (clientIpAddress.IsIPv4MappedToIPv6)
                    clientIpAddress = clientIpAddress.MapToIPv4();

                _totalQueries++;

                if (responseType == DnsServerResponseType.Dropped)
                {
                    _totalDropped++;

                    if (rateLimited)
                    {
                        if (protocol == DnsTransportProtocol.Udp)
                            GetOrAddClientCounters(clientIpAddress).Item1.Increment();
                        else
                            GetOrAddClientCounters(clientIpAddress).Item2.Increment();
                    }
                }
                else
                {
                    switch (responseCode)
                    {
                        case DnsResponseCode.NoError:
                            if (query is not null)
                            {
                                switch (responseType)
                                {
                                    case DnsServerResponseType.Blocked:
                                    case DnsServerResponseType.UpstreamBlocked:
                                    case DnsServerResponseType.UpstreamBlockedCached:
                                        break;

                                    default:
                                        IncrementCapped(_queryDomains, query.Name.ToLowerInvariant());
                                        break;
                                }
                            }

                            _totalNoError++;
                            break;

                        case DnsResponseCode.ServerFailure:
                            _totalServerFailure++;
                            break;

                        case DnsResponseCode.NxDomain:
                            _totalNxDomain++;
                            break;

                        case DnsResponseCode.Refused:
                            _totalRefused++;
                            break;
                    }

                    switch (responseType)
                    {
                        case DnsServerResponseType.Authoritative:
                            _totalAuthoritative++;
                            break;

                        case DnsServerResponseType.Recursive:
                            _totalRecursive++;
                            break;

                        case DnsServerResponseType.Cached:
                            _totalCached++;
                            break;

                        case DnsServerResponseType.Blocked:
                            if (query is not null)
                                IncrementCapped(_queryBlockedDomains, query.Name.ToLowerInvariant());

                            _totalBlocked++;
                            break;

                        case DnsServerResponseType.UpstreamBlocked:
                            _totalRecursive++;

                            if (query is not null)
                                IncrementCapped(_queryBlockedDomains, query.Name.ToLowerInvariant());

                            _totalBlocked++;
                            break;

                        case DnsServerResponseType.UpstreamBlockedCached:
                            _totalCached++;

                            if (query is not null)
                                IncrementCapped(_queryBlockedDomains, query.Name.ToLowerInvariant());

                            _totalBlocked++;
                            break;
                    }

                    if (query is not null)
                        _queryTypes.GetOrAdd(query.Type, GetNewCounter).Increment();

                    if (protocol == DnsTransportProtocol.Udp)
                        GetOrAddClientCounters(clientIpAddress).Item1.Increment();
                    else
                        GetOrAddClientCounters(clientIpAddress).Item2.Increment();
                }

                _protocolTypes.GetOrAdd(protocol, GetNewCounter).Increment();
            }

            public void Merge(StatCounter statCounter, bool isDailyStatCounter = false, bool skipLock = false)
            {
                if (!skipLock && (!_locked || !statCounter._locked))
                    throw new DnsServerException("StatCounter must be locked.");

                _totalQueries += statCounter._totalQueries;
                _totalNoError += statCounter._totalNoError;
                _totalServerFailure += statCounter._totalServerFailure;
                _totalNxDomain += statCounter._totalNxDomain;
                _totalRefused += statCounter._totalRefused;

                _totalAuthoritative += statCounter._totalAuthoritative;
                _totalRecursive += statCounter._totalRecursive;
                _totalCached += statCounter._totalCached;
                _totalBlocked += statCounter._totalBlocked;
                _totalDropped += statCounter._totalDropped;

                foreach (KeyValuePair<string, Counter> queryDomain in statCounter._queryDomains)
                    GetCappedCounter(_queryDomains, queryDomain.Key)?.Merge(queryDomain.Value);

                foreach (KeyValuePair<string, Counter> queryBlockedDomain in statCounter._queryBlockedDomains)
                    GetCappedCounter(_queryBlockedDomains, queryBlockedDomain.Key)?.Merge(queryBlockedDomain.Value);

                foreach (KeyValuePair<DnsResourceRecordType, Counter> queryType in statCounter._queryTypes)
                    _queryTypes.GetOrAdd(queryType.Key, GetNewCounter).Merge(queryType.Value);

                foreach (KeyValuePair<DnsTransportProtocol, Counter> protocolType in statCounter._protocolTypes)
                    _protocolTypes.GetOrAdd(protocolType.Key, GetNewCounter).Merge(protocolType.Value);

                foreach (KeyValuePair<IPAddress, (Counter, Counter)> clientIpAddress in statCounter._clientIpAddressesUdpTcp)
                {
                    if (!_clientIpAddressesUdpTcp.TryGetValue(clientIpAddress.Key, out (Counter, Counter) counterTuple))
                    {
                        if (_clientIpAddressesUdpTcp.Count >= MAX_COUNTER_ENTRIES)
                            continue;

                        counterTuple = _clientIpAddressesUdpTcp.GetOrAdd(clientIpAddress.Key, GetNewCounterTuple);
                    }

                    counterTuple.Item1.Merge(clientIpAddress.Value.Item1);
                    counterTuple.Item2.Merge(clientIpAddress.Value.Item2);
                }

                UniqueAddressCounter sourceClientSketch = statCounter._clientSketch;

                if ((sourceClientSketch is not null) || (_clientSketch is not null))
                {
                    UniqueAddressCounter clientSketch = GetOrCreateClientSketch();

                    if (sourceClientSketch is not null)
                    {
                        clientSketch.Merge(sourceClientSketch);
                    }
                    else
                    {
                        foreach (KeyValuePair<IPAddress, (Counter, Counter)> clientIpAddress in statCounter._clientIpAddressesUdpTcp)
                            clientSketch.Add(clientIpAddress.Key);
                    }

                    _totalClients = Math.Max(_clientIpAddressesUdpTcp.Count, clientSketch.Estimate());
                }
                else
                {
                    _totalClients = _clientIpAddressesUdpTcp.Count;
                }

                _totalClientsDailyStatsSummation += statCounter._totalClients;

                if (isDailyStatCounter && (sourceClientSketch is null) && (statCounter._totalClients > statCounter._clientIpAddressesUdpTcp.Count))
                    _truncationFoundDuringMerge = true;
            }

            public bool Truncate(int limit)
            {
                bool truncated = false;

                if (_queryDomains.Count > limit)
                {
                    _queryDomains = GetTopDomains(_queryDomains, limit);
                    truncated = true;
                }

                if (_queryBlockedDomains.Count > limit)
                {
                    _queryBlockedDomains = GetTopDomains(_queryBlockedDomains, limit);
                    truncated = true;
                }

                if (_queryTypes.Count > limit)
                {
                    List<KeyValuePair<DnsResourceRecordType, Counter>> queryTypesList = new List<KeyValuePair<DnsResourceRecordType, Counter>>(_queryTypes);

                    queryTypesList.Sort(delegate (KeyValuePair<DnsResourceRecordType, Counter> item1, KeyValuePair<DnsResourceRecordType, Counter> item2)
                    {
                        return item2.Value.Count.CompareTo(item1.Value.Count);
                    });

                    if (queryTypesList.Count > limit)
                    {
                        long othersCount = 0;

                        for (int i = limit; i < queryTypesList.Count; i++)
                            othersCount += queryTypesList[i].Value.Count;

                        queryTypesList.RemoveRange(limit - 1, queryTypesList.Count - (limit - 1));
                        queryTypesList.Add(new KeyValuePair<DnsResourceRecordType, Counter>(DnsResourceRecordType.Unknown, new Counter(othersCount)));
                    }

                    ConcurrentDictionary<DnsResourceRecordType, Counter> queryTypes = new ConcurrentDictionary<DnsResourceRecordType, Counter>(1, queryTypesList.Count);

                    foreach (KeyValuePair<DnsResourceRecordType, Counter> item in queryTypesList)
                        queryTypes[item.Key] = item.Value;

                    _queryTypes = queryTypes;
                    truncated = true;
                }

                if (_clientIpAddressesUdpTcp.Count > limit)
                {
                    List<KeyValuePair<IPAddress, (Counter, Counter)>> topClientsList = new List<KeyValuePair<IPAddress, (Counter, Counter)>>(_clientIpAddressesUdpTcp);
                    UniqueAddressCounter clientSketch = _clientSketch ?? new UniqueAddressCounter(CLIENT_SKETCH_PRECISION);

                    foreach (KeyValuePair<IPAddress, (Counter, Counter)> item in topClientsList)
                        clientSketch.Add(item.Key);

                    topClientsList.Sort(CompareClientHits);

                    if (topClientsList.Count > limit)
                        topClientsList.RemoveRange(limit, topClientsList.Count - limit);

                    ConcurrentDictionary<IPAddress, (Counter, Counter)> clientIpAddressesUdpTcp = new ConcurrentDictionary<IPAddress, (Counter, Counter)>(1, topClientsList.Count);

                    foreach (KeyValuePair<IPAddress, (Counter, Counter)> item in topClientsList)
                        clientIpAddressesUdpTcp[item.Key] = item.Value;

                    _clientSketch = clientSketch;
                    _clientIpAddressesUdpTcp = clientIpAddressesUdpTcp;
                    truncated = true;
                }

                return truncated;
            }

            public void WriteTo(BinaryWriter bW, int limit = 0)
            {
                if (!_locked)
                    throw new DnsServerException("StatCounter must be locked.");

                bW.Write(Encoding.ASCII.GetBytes("SC"));
                bW.Write((byte)11);

                bW.Write(_totalQueries);
                bW.Write(_totalNoError);
                bW.Write(_totalServerFailure);
                bW.Write(_totalNxDomain);
                bW.Write(_totalRefused);

                bW.Write(_totalAuthoritative);
                bW.Write(_totalRecursive);
                bW.Write(_totalCached);
                bW.Write(_totalBlocked);
                bW.Write(_totalDropped);

                bW.Write(_totalClients);

                WriteDomains(bW, _queryDomains, limit);
                WriteDomains(bW, _queryBlockedDomains, limit);

                {
                    List<KeyValuePair<DnsResourceRecordType, Counter>> queryTypes = new List<KeyValuePair<DnsResourceRecordType, Counter>>(_queryTypes);

                    bW.Write(queryTypes.Count);
                    foreach (KeyValuePair<DnsResourceRecordType, Counter> queryType in queryTypes)
                    {
                        bW.Write((ushort)queryType.Key);
                        bW.Write(queryType.Value.Count);
                    }
                }

                {
                    List<KeyValuePair<DnsTransportProtocol, Counter>> protocolTypes = new List<KeyValuePair<DnsTransportProtocol, Counter>>(_protocolTypes);

                    bW.Write(protocolTypes.Count);
                    foreach (KeyValuePair<DnsTransportProtocol, Counter> protocolType in protocolTypes)
                    {
                        bW.Write((byte)protocolType.Key);
                        bW.Write(protocolType.Value.Count);
                    }
                }

                List<KeyValuePair<IPAddress, (Counter, Counter)>> clientIpAddresses = new List<KeyValuePair<IPAddress, (Counter, Counter)>>(_clientIpAddressesUdpTcp);
                UniqueAddressCounter clientSketch = _clientSketch;

                if ((limit > 0) && (clientIpAddresses.Count > limit))
                {
                    clientSketch = (clientSketch is null) ? new UniqueAddressCounter(CLIENT_SKETCH_PRECISION) : clientSketch.Clone();

                    foreach (KeyValuePair<IPAddress, (Counter, Counter)> clientIpAddress in clientIpAddresses)
                        clientSketch.Add(clientIpAddress.Key);

                    clientIpAddresses.Sort(CompareClientHits);
                    clientIpAddresses.RemoveRange(limit, clientIpAddresses.Count - limit);
                }

                bW.Write(clientIpAddresses.Count);
                foreach (KeyValuePair<IPAddress, (Counter, Counter)> clientIpAddress in clientIpAddresses)
                {
                    clientIpAddress.Key.WriteTo(bW);
                    bW.Write(clientIpAddress.Value.Item1.Count);
                    bW.Write(clientIpAddress.Value.Item2.Count);
                }

                if (clientSketch is null)
                {
                    bW.Write(false);
                }
                else
                {
                    bW.Write(true);
                    clientSketch.WriteTo(bW);
                }
            }

            public DashboardStats.StatsData GetStatsData()
            {
                return new DashboardStats.StatsData
                {
                    TotalQueries = _totalQueries,
                    TotalNoError = _totalNoError,
                    TotalServerFailure = _totalServerFailure,
                    TotalNxDomain = _totalNxDomain,
                    TotalRefused = _totalRefused,

                    TotalAuthoritative = _totalAuthoritative,
                    TotalRecursive = _totalRecursive,
                    TotalCached = _totalCached,
                    TotalBlocked = _totalBlocked,
                    TotalDropped = _totalDropped,

                    TotalClients = _totalClients
                };
            }

            public DashboardStats.ChartData GetQueryResponseChartData()
            {
                return new DashboardStats.ChartData()
                {
                    Labels =
                    [
                        "Authoritative",
                        "Recursive",
                        "Cached",
                        "Blocked",
                        "Dropped"
                    ],
                    DataSets =
                    [
                        new DashboardStats.DataSet()
                        {
                            Data =
                            [
                                _totalAuthoritative,
                                _totalRecursive,
                                _totalCached,
                                _totalBlocked,
                                _totalDropped
                            ]
                        }
                    ]
                };
            }

            public DashboardStats.TopStats[] GetTopDomainStats(int limit)
            {
                List<KeyValuePair<string, DashboardStats.TopStats>> topDomainsList = new List<KeyValuePair<string, DashboardStats.TopStats>>(_queryDomains.Count);

                foreach (KeyValuePair<string, Counter> item in _queryDomains)
                    topDomainsList.Add(new KeyValuePair<string, DashboardStats.TopStats>(item.Key, new DashboardStats.TopStats { Name = item.Key, Hits = item.Value.Count }));

                List<KeyValuePair<string, DashboardStats.TopStats>> topDomainsData = GetTopList(topDomainsList, limit);
                DashboardStats.TopStats[] topDomains = new DashboardStats.TopStats[topDomainsData.Count];

                for (int i = 0; i < topDomainsData.Count; i++)
                    topDomains[i] = topDomainsData[i].Value;

                return topDomains;
            }

            public DashboardStats.TopStats[] GetTopBlockedDomainStats(int limit)
            {
                List<KeyValuePair<string, DashboardStats.TopStats>> topBlockedDomainsList = new List<KeyValuePair<string, DashboardStats.TopStats>>(_queryBlockedDomains.Count);

                foreach (KeyValuePair<string, Counter> item in _queryBlockedDomains)
                    topBlockedDomainsList.Add(new KeyValuePair<string, DashboardStats.TopStats>(item.Key, new DashboardStats.TopStats { Name = item.Key, Hits = item.Value.Count }));

                List<KeyValuePair<string, DashboardStats.TopStats>> topBlockedDomainsData = GetTopList(topBlockedDomainsList, limit);
                DashboardStats.TopStats[] topBlockedDomains = new DashboardStats.TopStats[topBlockedDomainsData.Count];

                for (int i = 0; i < topBlockedDomainsData.Count; i++)
                    topBlockedDomains[i] = topBlockedDomainsData[i].Value;

                return topBlockedDomains;
            }

            public DashboardStats.TopClientStats[] GetTopClientStats(int limit)
            {
                List<KeyValuePair<string, DashboardStats.TopClientStats>> topClientsList = new List<KeyValuePair<string, DashboardStats.TopClientStats>>(_clientIpAddressesUdpTcp.Count);

                foreach (KeyValuePair<IPAddress, (Counter, Counter)> item in _clientIpAddressesUdpTcp)
                    topClientsList.Add(new KeyValuePair<string, DashboardStats.TopClientStats>(item.Key.ToString(), new DashboardStats.TopClientStats { Name = item.Key.ToString(), Hits = item.Value.Item1.Count + item.Value.Item2.Count }));

                List<KeyValuePair<string, DashboardStats.TopClientStats>> topClientsData = GetTopList(topClientsList, limit);
                DashboardStats.TopClientStats[] topClients = new DashboardStats.TopClientStats[topClientsData.Count];

                for (int i = 0; i < topClientsData.Count; i++)
                    topClients[i] = topClientsData[i].Value;

                return topClients;
            }

            public DashboardStats.ChartData GetTopQueryTypesChartData()
            {
                List<KeyValuePair<string, long>> queryTypes = new List<KeyValuePair<string, long>>(_queryTypes.Count);

                foreach (KeyValuePair<DnsResourceRecordType, Counter> item in _queryTypes)
                    queryTypes.Add(new KeyValuePair<string, long>(item.Key.ToString(), item.Value.Count));

                queryTypes.Sort(delegate (KeyValuePair<string, long> item1, KeyValuePair<string, long> item2)
                {
                    return item2.Value.CompareTo(item1.Value);
                });

                string[] queryTypeLabels = new string[queryTypes.Count];
                long[] queryTypeData = new long[queryTypes.Count];

                for (int i = 0; i < queryTypes.Count; i++)
                {
                    KeyValuePair<string, long> topQueryTypeData = queryTypes[i];

                    queryTypeLabels[i] = topQueryTypeData.Key;
                    queryTypeData[i] = topQueryTypeData.Value;
                }

                return new DashboardStats.ChartData()
                {
                    Labels = queryTypeLabels,
                    DataSets =
                    [
                        new DashboardStats.DataSet()
                        {
                            Data = queryTypeData
                        }
                    ]
                };
            }

            public DashboardStats.ChartData GetTopProtocolTypesChartData()
            {
                List<KeyValuePair<string, long>> protocolTypes = new List<KeyValuePair<string, long>>(_protocolTypes.Count);

                foreach (KeyValuePair<DnsTransportProtocol, Counter> protocolType in _protocolTypes)
                    protocolTypes.Add(new KeyValuePair<string, long>(protocolType.Key.ToString(), protocolType.Value.Count));

                protocolTypes.Sort(delegate (KeyValuePair<string, long> item1, KeyValuePair<string, long> item2)
                {
                    return item2.Value.CompareTo(item1.Value);
                });

                string[] topProtocolLabels = new string[protocolTypes.Count];
                long[] topProtocolData = new long[protocolTypes.Count];

                for (int i = 0; i < protocolTypes.Count; i++)
                {
                    KeyValuePair<string, long> topProtocolTypeData = protocolTypes[i];

                    topProtocolLabels[i] = topProtocolTypeData.Key;
                    topProtocolData[i] = topProtocolTypeData.Value;
                }

                return new DashboardStats.ChartData()
                {
                    Labels = topProtocolLabels,
                    DataSets =
                    [
                        new DashboardStats.DataSet()
                        {
                            Data = topProtocolData
                        }
                    ]
                };
            }

            public Dictionary<NetworkAddress, (long, long)> GetClientSubnetStats(IEnumerable<int> ipv4Prefixes, IEnumerable<int> ipv6Prefixes)
            {
                Dictionary<NetworkAddress, (long, long)> clientSubnetStats = new Dictionary<NetworkAddress, (long, long)>(_clientIpAddressesUdpTcp.Count);

                void UpdateClientSubnetStats(NetworkAddress clientSubnet, (Counter, Counter) value)
                {
                    if (clientSubnetStats.TryGetValue(clientSubnet, out ValueTuple<long, long> existingValue))
                    {
                        existingValue.Item1 += value.Item1.Count;
                        existingValue.Item2 += value.Item2.Count;
                    }
                    else
                    {
                        clientSubnetStats.Add(clientSubnet, (value.Item1.Count, value.Item2.Count));
                    }
                }

                foreach (KeyValuePair<IPAddress, (Counter, Counter)> item in _clientIpAddressesUdpTcp)
                {
                    switch (item.Key.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                            IPAddress clientIPv4 = item.Key;

                            foreach (int ipv4Prefix in ipv4Prefixes)
                                UpdateClientSubnetStats(new NetworkAddress(clientIPv4, (byte)ipv4Prefix), item.Value);

                            break;

                        case AddressFamily.InterNetworkV6:
                            IPAddress clientIPv6 = item.Key;

                            foreach (int ipv6Prefix in ipv6Prefixes)
                                UpdateClientSubnetStats(new NetworkAddress(clientIPv6, (byte)ipv6Prefix), item.Value);

                            break;

                        default:
                            throw new NotSupportedException("AddressFamily not supported.");
                    }
                }

                return clientSubnetStats;
            }

            #endregion

            #region properties

            public bool IsLocked
            { get { return _locked; } }

            public long TotalQueries
            { get { return _totalQueries; } }

            public long TotalNoError
            { get { return _totalNoError; } }

            public long TotalServerFailure
            { get { return _totalServerFailure; } }

            public long TotalNxDomain
            { get { return _totalNxDomain; } }

            public long TotalRefused
            { get { return _totalRefused; } }

            public long TotalAuthoritative
            { get { return _totalAuthoritative; } }

            public long TotalRecursive
            { get { return _totalRecursive; } }

            public long TotalCached
            { get { return _totalCached; } }

            public long TotalBlocked
            { get { return _totalBlocked; } }

            public long TotalDropped
            { get { return _totalDropped; } }

            public long TotalClients
            {
                get
                {
                    if (_truncationFoundDuringMerge)
                        return _totalClientsDailyStatsSummation;

                    return _totalClients;
                }
            }

            #endregion

            class Counter
            {
                #region variables

                long _count;

                #endregion

                #region constructor

                public Counter()
                { }

                public Counter(long count)
                {
                    _count = count;
                }

                #endregion

                #region public

                public void Increment()
                {
                    _count++;
                }

                public void Merge(Counter counter)
                {
                    _count += counter._count;
                }

                #endregion

                #region properties

                public long Count
                { get { return _count; } }

                #endregion
            }
        }

        readonly struct StatsQueueItem
        {
            #region variables

            public readonly DateTime _timestamp;

            public readonly DnsDatagram _request;
            public readonly IPEndPoint _remoteEP;
            public readonly DnsTransportProtocol _protocol;
            public readonly DnsDatagram _response;
            public readonly bool _rateLimited;
            public readonly double _responseTime;

            #endregion

            #region constructor

            public StatsQueueItem(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response, bool rateLimited, double responseTime)
            {
                _timestamp = DateTime.UtcNow;

                _request = request;
                _remoteEP = remoteEP;
                _protocol = protocol;
                _response = response;
                _rateLimited = rateLimited;
                _responseTime = responseTime;
            }

            #endregion
        }
    }
}
