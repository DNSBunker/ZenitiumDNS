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

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

namespace ZenitiumDns.Core.Dns
{
    sealed class SystemMonitor : IDisposable
    {
        #region variables

        public const int CAPACITY = 300;
        const int SAMPLE_INTERVAL = 1000;

        readonly DnsServer _dnsServer;
        readonly Sample[] _samples = new Sample[CAPACITY];
        readonly Lock _lock = new Lock();

        Timer _timer;
        long _sequence;

        long _lastTimestamp;
        TimeSpan _lastCpuTime;
        int _lastGen0;
        int _lastGen1;
        int _lastGen2;
        TimeSpan _lastPause;
        long _lastCompletedWorkItems;
        long _lastLockContentions;
        long _lastQueries;

        #endregion

        #region constructor

        public SystemMonitor(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            lock (_lock)
            {
                _timer?.Dispose();
                _timer = null;
            }

            _disposed = true;
        }

        #endregion

        #region private

        private void ResetBaseline()
        {
            _lastTimestamp = Stopwatch.GetTimestamp();
            _lastCpuTime = Environment.CpuUsage.TotalTime;
            _lastGen0 = GC.CollectionCount(0);
            _lastGen1 = GC.CollectionCount(1);
            _lastGen2 = GC.CollectionCount(2);
            _lastPause = GC.GetTotalPauseDuration();
            _lastCompletedWorkItems = ThreadPool.CompletedWorkItemCount;
            _lastLockContentions = Monitor.LockContentionCount;
            _lastQueries = _dnsServer.StatsManager?.TotalQueries ?? 0;
        }

        private void TimerCallback(object state)
        {
            try
            {
                long timestamp = Stopwatch.GetTimestamp();
                double seconds = Stopwatch.GetElapsedTime(_lastTimestamp, timestamp).TotalSeconds;
                if (seconds <= 0)
                    return;

                TimeSpan cpuTime = Environment.CpuUsage.TotalTime;
                int gen0 = GC.CollectionCount(0);
                int gen1 = GC.CollectionCount(1);
                int gen2 = GC.CollectionCount(2);
                TimeSpan pause = GC.GetTotalPauseDuration();
                long completedWorkItems = ThreadPool.CompletedWorkItemCount;
                long lockContentions = Monitor.LockContentionCount;
                long queries = _dnsServer.StatsManager?.TotalQueries ?? 0;

                Sample sample = new Sample()
                {
                    Time = DateTime.UtcNow,
                    CpuPercent = Math.Max(0, (cpuTime - _lastCpuTime).TotalSeconds / seconds / Environment.ProcessorCount * 100),
                    WorkingSet = Environment.WorkingSet,
                    GcHeap = GC.GetTotalMemory(false),
                    Gen0PerSecond = (gen0 - _lastGen0) / seconds,
                    Gen1PerSecond = (gen1 - _lastGen1) / seconds,
                    Gen2PerSecond = (gen2 - _lastGen2) / seconds,
                    GcPausePercent = Math.Max(0, (pause - _lastPause).TotalSeconds / seconds * 100),
                    ThreadPoolThreads = ThreadPool.ThreadCount,
                    ThreadPoolQueue = ThreadPool.PendingWorkItemCount,
                    WorkItemsPerSecond = (completedWorkItems - _lastCompletedWorkItems) / seconds,
                    LockContentionsPerSecond = (lockContentions - _lastLockContentions) / seconds,
                    QueryQueue = _dnsServer.QueryTaskQueueLength,
                    ResolverQueue = _dnsServer.ResolverTaskQueueLength,
                    StatsQueue = _dnsServer.StatsManager?.QueueLength ?? 0,
                    PendingResolutions = _dnsServer.PendingResolutions,
                    CacheEntries = _dnsServer.CacheZoneManager.TotalEntries,
                    QueriesPerSecond = Math.Max(0, (queries - _lastQueries) / seconds),
                    RateLimiterClients = _dnsServer.RateLimiterTrackedClients
                };

                _lastTimestamp = timestamp;
                _lastCpuTime = cpuTime;
                _lastGen0 = gen0;
                _lastGen1 = gen1;
                _lastGen2 = gen2;
                _lastPause = pause;
                _lastCompletedWorkItems = completedWorkItems;
                _lastLockContentions = lockContentions;
                _lastQueries = queries;

                lock (_lock)
                {
                    sample.Sequence = ++_sequence;
                    _samples[(int)(sample.Sequence % CAPACITY)] = sample;
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager?.Write(ex);
            }
        }

        #endregion

        #region public

        public IReadOnlyList<Sample> GetSamples(long since)
        {
            lock (_lock)
            {
                long first = Math.Max(since + 1, Math.Max(1, _sequence - CAPACITY + 1));
                List<Sample> samples = new List<Sample>((int)Math.Max(0, _sequence - first + 1));

                for (long sequence = first; sequence <= _sequence; sequence++)
                    samples.Add(_samples[(int)(sequence % CAPACITY)]);

                return samples;
            }
        }

        public Sample GetLatest()
        {
            lock (_lock)
            {
                if (_sequence == 0)
                    return null;

                return _samples[(int)(_sequence % CAPACITY)];
            }
        }

        #endregion

        #region properties

        public long LatestSequence
        {
            get
            {
                lock (_lock)
                {
                    return _sequence;
                }
            }
        }

        public bool Enabled
        {
            get
            {
                lock (_lock)
                {
                    return _timer is not null;
                }
            }
            set
            {
                lock (_lock)
                {
                    if (_disposed)
                        return;

                    if (value)
                    {
                        if (_timer is not null)
                            return;

                        ResetBaseline();
                        _timer = new Timer(TimerCallback, null, SAMPLE_INTERVAL, SAMPLE_INTERVAL);
                    }
                    else
                    {
                        _timer?.Dispose();
                        _timer = null;

                        _sequence = 0;
                        Array.Clear(_samples);
                    }
                }
            }
        }

        #endregion

        public sealed class Sample
        {
            public long Sequence;
            public DateTime Time;
            public double CpuPercent;
            public long WorkingSet;
            public long GcHeap;
            public double Gen0PerSecond;
            public double Gen1PerSecond;
            public double Gen2PerSecond;
            public double GcPausePercent;
            public int ThreadPoolThreads;
            public long ThreadPoolQueue;
            public double WorkItemsPerSecond;
            public double LockContentionsPerSecond;
            public int QueryQueue;
            public int ResolverQueue;
            public int StatsQueue;
            public int PendingResolutions;
            public long CacheEntries;
            public double QueriesPerSecond;
            public int RateLimiterClients;
        }
    }
}
