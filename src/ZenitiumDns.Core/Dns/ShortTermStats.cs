using System;
using System.Globalization;
using System.Net;
using System.Numerics;
using System.Threading;
using ZenitiumDns.ApplicationCommon;
using ZenitiumLibrary.Net.Dns;

namespace ZenitiumDns.Core.Dns
{
    sealed class ShortTermStats
    {
        #region variables

        public const int MAX_SECONDS = 1860;

        const int COUNTERS = 10;
        const int BITMAP_WORDS = 32;
        const int BITMAP_BITS = BITMAP_WORDS * 64;

        const int TOTAL = 0;
        const int NO_ERROR = 1;
        const int SERVER_FAILURE = 2;
        const int NX_DOMAIN = 3;
        const int REFUSED = 4;
        const int AUTHORITATIVE = 5;
        const int RECURSIVE = 6;
        const int CACHED = 7;
        const int BLOCKED = 8;
        const int DROPPED = 9;

        static readonly string[] DATASET_LABELS = ["Total", "No Error", "Server Failure", "NX Domain", "Refused", "Authoritative", "Recursive", "Cached", "Blocked", "Dropped"];

        readonly long[] _seconds = new long[MAX_SECONDS];
        readonly long[] _counters = new long[MAX_SECONDS * COUNTERS];
        readonly ulong[] _clients = new ulong[MAX_SECONDS * BITMAP_WORDS];

        #endregion

        #region private

        private static int GetClientBit(IPAddress clientIpAddress)
        {
            if (clientIpAddress.IsIPv4MappedToIPv6)
                clientIpAddress = clientIpAddress.MapToIPv4();

            Span<byte> bytes = stackalloc byte[16];

            if (!clientIpAddress.TryWriteBytes(bytes, out int length))
                return 0;

            ulong hash = 14695981039346656037UL;

            for (int i = 0; i < length; i++)
            {
                hash ^= bytes[i];
                hash *= 1099511628211UL;
            }

            hash ^= hash >> 33;
            hash *= 0xff51afd7ed558ccdUL;
            hash ^= hash >> 33;

            return (int)(hash >> (64 - 11));
        }

        private static long EstimateClients(ReadOnlySpan<ulong> bitmap)
        {
            int setBits = 0;

            foreach (ulong word in bitmap)
                setBits += BitOperations.PopCount(word);

            if (setBits == 0)
                return 0;

            int zeroBits = BITMAP_BITS - setBits;
            if (zeroBits == 0)
                zeroBits = 1;

            return (long)Math.Round(-BITMAP_BITS * Math.Log((double)zeroBits / BITMAP_BITS));
        }

        #endregion

        #region public

        public void Record(DateTime timestamp, DnsResponseCode responseCode, DnsServerResponseType responseType, IPAddress clientIpAddress)
        {
            long second = timestamp.Ticks / TimeSpan.TicksPerSecond;
            int slot = (int)(second % MAX_SECONDS);
            int counterOffset = slot * COUNTERS;
            int bitmapOffset = slot * BITMAP_WORDS;

            long slotSecond = Volatile.Read(ref _seconds[slot]);
            if (slotSecond != second)
            {
                if (slotSecond > second)
                    return;

                Array.Clear(_counters, counterOffset, COUNTERS);
                Array.Clear(_clients, bitmapOffset, BITMAP_WORDS);
                Volatile.Write(ref _seconds[slot], second);
            }

            _counters[counterOffset + TOTAL]++;

            if (responseType == DnsServerResponseType.Dropped)
            {
                _counters[counterOffset + DROPPED]++;
                return;
            }

            switch (responseCode)
            {
                case DnsResponseCode.NoError:
                    _counters[counterOffset + NO_ERROR]++;
                    break;

                case DnsResponseCode.ServerFailure:
                    _counters[counterOffset + SERVER_FAILURE]++;
                    break;

                case DnsResponseCode.NxDomain:
                    _counters[counterOffset + NX_DOMAIN]++;
                    break;

                case DnsResponseCode.Refused:
                    _counters[counterOffset + REFUSED]++;
                    break;
            }

            switch (responseType)
            {
                case DnsServerResponseType.Authoritative:
                    _counters[counterOffset + AUTHORITATIVE]++;
                    break;

                case DnsServerResponseType.Recursive:
                    _counters[counterOffset + RECURSIVE]++;
                    break;

                case DnsServerResponseType.Cached:
                    _counters[counterOffset + CACHED]++;
                    break;

                case DnsServerResponseType.Blocked:
                    _counters[counterOffset + BLOCKED]++;
                    break;

                case DnsServerResponseType.UpstreamBlocked:
                    _counters[counterOffset + RECURSIVE]++;
                    _counters[counterOffset + BLOCKED]++;
                    break;

                case DnsServerResponseType.UpstreamBlockedCached:
                    _counters[counterOffset + CACHED]++;
                    _counters[counterOffset + BLOCKED]++;
                    break;
            }

            int bit = GetClientBit(clientIpAddress);
            _clients[bitmapOffset + (bit >> 6)] |= 1UL << (bit & 63);
        }

        public DashboardStats GetStats(int rangeSeconds, int points, bool utcFormat)
        {
            if ((rangeSeconds < 1) || (rangeSeconds > MAX_SECONDS - 60))
                throw new ArgumentOutOfRangeException(nameof(rangeSeconds));

            if ((points < 1) || ((rangeSeconds % points) != 0))
                throw new ArgumentOutOfRangeException(nameof(points));

            int bucketSeconds = rangeSeconds / points;
            long endSecond = (DateTime.UtcNow.Ticks / TimeSpan.TicksPerSecond) - 1;
            long startSecond = endSecond - rangeSeconds + 1;

            long[][] series = new long[COUNTERS + 1][];
            for (int i = 0; i < series.Length; i++)
                series[i] = new long[points];

            long[] totals = new long[COUNTERS];
            string[] labels = new string[points];

            Span<ulong> bucketBitmap = stackalloc ulong[BITMAP_WORDS];
            Span<ulong> totalBitmap = stackalloc ulong[BITMAP_WORDS];
            totalBitmap.Clear();

            for (int point = 0; point < points; point++)
            {
                bucketBitmap.Clear();

                for (int offset = 0; offset < bucketSeconds; offset++)
                {
                    long second = startSecond + (point * bucketSeconds) + offset;
                    int slot = (int)(second % MAX_SECONDS);

                    if (Volatile.Read(ref _seconds[slot]) != second)
                        continue;

                    int counterOffset = slot * COUNTERS;

                    for (int counter = 0; counter < COUNTERS; counter++)
                    {
                        long value = _counters[counterOffset + counter];
                        series[counter][point] += value;
                        totals[counter] += value;
                    }

                    int bitmapOffset = slot * BITMAP_WORDS;

                    for (int word = 0; word < BITMAP_WORDS; word++)
                        bucketBitmap[word] |= _clients[bitmapOffset + word];
                }

                series[COUNTERS][point] = EstimateClients(bucketBitmap);

                for (int word = 0; word < BITMAP_WORDS; word++)
                    totalBitmap[word] |= bucketBitmap[word];

                DateTime labelTime = new DateTime((startSecond + ((point + 1) * bucketSeconds)) * TimeSpan.TicksPerSecond, DateTimeKind.Utc);

                if (utcFormat)
                    labels[point] = labelTime.ToString("O", CultureInfo.InvariantCulture);
                else
                    labels[point] = labelTime.ToLocalTime().ToString("HH:mm:ss", CultureInfo.InvariantCulture);
            }

            DashboardStats.DataSet[] dataSets = new DashboardStats.DataSet[COUNTERS + 1];

            for (int i = 0; i < COUNTERS; i++)
                dataSets[i] = new DashboardStats.DataSet() { Label = DATASET_LABELS[i], Data = series[i] };

            dataSets[COUNTERS] = new DashboardStats.DataSet() { Label = "Clients", Data = series[COUNTERS] };

            return new DashboardStats()
            {
                Stats = new DashboardStats.StatsData()
                {
                    TotalQueries = totals[TOTAL],
                    TotalNoError = totals[NO_ERROR],
                    TotalServerFailure = totals[SERVER_FAILURE],
                    TotalNxDomain = totals[NX_DOMAIN],
                    TotalRefused = totals[REFUSED],
                    TotalAuthoritative = totals[AUTHORITATIVE],
                    TotalRecursive = totals[RECURSIVE],
                    TotalCached = totals[CACHED],
                    TotalBlocked = totals[BLOCKED],
                    TotalDropped = totals[DROPPED],
                    TotalClients = EstimateClients(totalBitmap)
                },
                MainChartData = new DashboardStats.ChartData() { Labels = labels, DataSets = dataSets },
                QueryResponseChartData = new DashboardStats.ChartData()
                {
                    Labels = ["Authoritative", "Recursive", "Cached", "Blocked", "Dropped"],
                    DataSets = [new DashboardStats.DataSet() { Data = [totals[AUTHORITATIVE], totals[RECURSIVE], totals[CACHED], totals[BLOCKED], totals[DROPPED]] }]
                }
            };
        }

        #endregion
    }
}
