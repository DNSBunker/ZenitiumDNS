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
using System.Threading;
using ZenitiumDns.ApplicationCommon;

namespace ZenitiumDns.Core.Dns
{
    public sealed class ResponseTimeStats
    {
        #region variables

        static readonly double[] _binUpperBounds = [0.25, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000, 10000, double.PositiveInfinity];

        readonly Lock _lock = new Lock();
        readonly MinuteBucket[] _buckets = new MinuteBucket[61];

        #endregion

        #region constructor

        public ResponseTimeStats()
        {
            for (int i = 0; i < _buckets.Length; i++)
                _buckets[i] = new MinuteBucket();
        }

        #endregion

        #region private

        private static long GetMinuteKey(DateTime utcTimestamp)
        {
            return utcTimestamp.Ticks / TimeSpan.TicksPerMinute;
        }

        private static int GetBinIndex(double responseTimeMs)
        {
            for (int i = 0; i < _binUpperBounds.Length; i++)
            {
                if (responseTimeMs <= _binUpperBounds[i])
                    return i;
            }

            return _binUpperBounds.Length - 1;
        }

        #endregion

        #region public

        public void Record(DateTime utcTimestamp, double responseTimeMs, DnsServerResponseType responseType)
        {
            if (responseTimeMs < 0)
                return;

            long minuteKey = GetMinuteKey(utcTimestamp);
            int binIndex = GetBinIndex(responseTimeMs);
            MinuteBucket bucket = _buckets[minuteKey % _buckets.Length];

            lock (_lock)
            {
                if (bucket.MinuteKey != minuteKey)
                    bucket.Reset(minuteKey);

                bucket.Add(responseTimeMs, responseType, binIndex);
            }
        }

        public Summary GetSummary(DateTime utcNow, int minutes)
        {
            minutes = Math.Clamp(minutes, 1, 60);

            long currentMinuteKey = GetMinuteKey(utcNow);
            long firstMinuteKey = currentMinuteKey - minutes + 1;

            MinuteBucket total = new MinuteBucket();

            lock (_lock)
            {
                foreach (MinuteBucket bucket in _buckets)
                {
                    if ((bucket.MinuteKey >= firstMinuteKey) && (bucket.MinuteKey <= currentMinuteKey))
                        total.Merge(bucket);
                }
            }

            double elapsedSeconds = Math.Max(1, ((minutes - 1) * 60) + (utcNow.Ticks % TimeSpan.TicksPerMinute / (double)TimeSpan.TicksPerSecond));

            return new Summary
            {
                Minutes = minutes,
                Count = total.Count,
                QueriesPerSecond = total.Count / elapsedSeconds,
                Average = total.Average,
                Median = total.GetPercentile(0.5),
                P95 = total.GetPercentile(0.95),
                P99 = total.GetPercentile(0.99),
                Max = total.Max,
                CachedAverage = total.CachedCount > 0 ? total.CachedSum / total.CachedCount : 0,
                RecursiveAverage = total.RecursiveCount > 0 ? total.RecursiveSum / total.RecursiveCount : 0
            };
        }

        public void GetPerMinuteSeries(DateTime utcStartMinute, double[] average, double[] p95)
        {
            long startMinuteKey = GetMinuteKey(utcStartMinute);

            lock (_lock)
            {
                for (int i = 0; i < average.Length; i++)
                {
                    long minuteKey = startMinuteKey + i;
                    MinuteBucket bucket = _buckets[minuteKey % _buckets.Length];

                    if (bucket.MinuteKey == minuteKey)
                    {
                        average[i] = Math.Round(bucket.Average, 2);
                        p95[i] = Math.Round(bucket.GetPercentile(0.95), 2);
                    }
                    else
                    {
                        average[i] = 0;
                        p95[i] = 0;
                    }
                }
            }
        }

        #endregion

        public struct Summary
        {
            public int Minutes;
            public long Count;
            public double QueriesPerSecond;
            public double Average;
            public double Median;
            public double P95;
            public double P99;
            public double Max;
            public double CachedAverage;
            public double RecursiveAverage;
        }

        sealed class MinuteBucket
        {
            public long MinuteKey = -1;
            public long Count;
            public double Sum;
            public double Max;
            public long CachedCount;
            public double CachedSum;
            public long RecursiveCount;
            public double RecursiveSum;
            public readonly long[] Bins = new long[_binUpperBounds.Length];

            public void Reset(long minuteKey)
            {
                MinuteKey = minuteKey;
                Count = 0;
                Sum = 0;
                Max = 0;
                CachedCount = 0;
                CachedSum = 0;
                RecursiveCount = 0;
                RecursiveSum = 0;
                Array.Clear(Bins);
            }

            public void Add(double responseTimeMs, DnsServerResponseType responseType, int binIndex)
            {
                Count++;
                Sum += responseTimeMs;

                if (responseTimeMs > Max)
                    Max = responseTimeMs;

                Bins[binIndex]++;

                switch (responseType)
                {
                    case DnsServerResponseType.Cached:
                    case DnsServerResponseType.UpstreamBlockedCached:
                        CachedCount++;
                        CachedSum += responseTimeMs;
                        break;

                    case DnsServerResponseType.Recursive:
                    case DnsServerResponseType.UpstreamBlocked:
                        RecursiveCount++;
                        RecursiveSum += responseTimeMs;
                        break;
                }
            }

            public void Merge(MinuteBucket other)
            {
                Count += other.Count;
                Sum += other.Sum;
                CachedCount += other.CachedCount;
                CachedSum += other.CachedSum;
                RecursiveCount += other.RecursiveCount;
                RecursiveSum += other.RecursiveSum;

                if (other.Max > Max)
                    Max = other.Max;

                for (int i = 0; i < Bins.Length; i++)
                    Bins[i] += other.Bins[i];
            }

            public double GetPercentile(double percentile)
            {
                if (Count < 1)
                    return 0;

                double rank = percentile * Count;
                long cumulative = 0;

                for (int i = 0; i < Bins.Length; i++)
                {
                    long binCount = Bins[i];
                    if (binCount == 0)
                        continue;

                    if (cumulative + binCount >= rank)
                    {
                        double lower = i == 0 ? 0 : _binUpperBounds[i - 1];
                        double upper = double.IsPositiveInfinity(_binUpperBounds[i]) ? lower * 2 : _binUpperBounds[i];

                        return Math.Min(lower + ((upper - lower) * ((rank - cumulative) / binCount)), Max);
                    }

                    cumulative += binCount;
                }

                return Max;
            }

            public double Average
            { get { return Count > 0 ? Sum / Count : 0; } }
        }
    }
}
