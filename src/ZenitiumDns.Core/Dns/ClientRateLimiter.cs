using System;
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using ZenitiumLibrary.Net;

namespace ZenitiumDns.Core.Dns
{
    sealed class ClientRateLimiter
    {
        #region variables

        const int MAX_BUCKETS = 500000;

        readonly ConcurrentDictionary<BucketKey, Bucket> _buckets = new ConcurrentDictionary<BucketKey, Bucket>();
        int _bucketCount;

        Rule[] _ipv4Rules = [];
        Rule[] _ipv6Rules = [];
        HashSet<BucketKey> _limited = new HashSet<BucketKey>();

        #endregion

        #region private

        private static Rule[] CreateRules(IReadOnlyDictionary<int, (int, int)> limits, int burstSeconds)
        {
            List<Rule> rules = new List<Rule>(limits.Count);

            foreach (KeyValuePair<int, (int, int)> limit in limits)
            {
                if ((limit.Value.Item1 < 1) && (limit.Value.Item2 < 1))
                    continue;

                rules.Add(new Rule((byte)limit.Key, limit.Value.Item1, limit.Value.Item2, burstSeconds));
            }

            rules.Sort(delegate (Rule x, Rule y) { return y.PrefixLength.CompareTo(x.PrefixLength); });

            return rules.ToArray();
        }

        private static bool TryGetAddress(IPAddress address, out ulong high, out ulong low, out bool ipv6)
        {
            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            Span<byte> bytes = stackalloc byte[16];

            if (!address.TryWriteBytes(bytes, out int length))
            {
                high = 0;
                low = 0;
                ipv6 = false;
                return false;
            }

            if (length == 4)
            {
                high = (ulong)BinaryPrimitives.ReadUInt32BigEndian(bytes) << 32;
                low = 0;
                ipv6 = false;
            }
            else
            {
                high = BinaryPrimitives.ReadUInt64BigEndian(bytes);
                low = BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(8));
                ipv6 = true;
            }

            return true;
        }

        private static BucketKey CreateKey(ulong high, ulong low, bool ipv6, byte prefixLength, bool tcp)
        {
            if (prefixLength == 0)
            {
                high = 0;
                low = 0;
            }
            else if (prefixLength <= 64)
            {
                high &= ulong.MaxValue << (64 - prefixLength);
                low = 0;
            }
            else
            {
                low &= ulong.MaxValue << (128 - prefixLength);
            }

            return new BucketKey(high, low, prefixLength, (byte)((ipv6 ? 1 : 0) | (tcp ? 2 : 0)));
        }

        private Bucket GetBucket(BucketKey key)
        {
            if (_buckets.TryGetValue(key, out Bucket bucket))
                return bucket;

            if (Volatile.Read(ref _bucketCount) >= MAX_BUCKETS)
                return null;

            bucket = new Bucket();

            if (_buckets.TryAdd(key, bucket))
            {
                Interlocked.Increment(ref _bucketCount);
                return bucket;
            }

            if (_buckets.TryGetValue(key, out bucket))
                return bucket;

            return null;
        }

        private int GetLimit(BucketKey key)
        {
            Rule[] rules = key.IsIPv6 ? _ipv6Rules : _ipv4Rules;

            foreach (Rule rule in rules)
            {
                if (rule.PrefixLength == key.PrefixLength)
                    return key.IsTcp ? rule.TcpLimit : rule.UdpLimit;
            }

            return 0;
        }

        #endregion

        #region public

        public void Configure(IReadOnlyDictionary<int, (int, int)> ipv4Limits, IReadOnlyDictionary<int, (int, int)> ipv6Limits, int burstSeconds)
        {
            _ipv4Rules = CreateRules(ipv4Limits, burstSeconds);
            _ipv6Rules = CreateRules(ipv6Limits, burstSeconds);

            _buckets.Clear();
            Volatile.Write(ref _bucketCount, 0);
            _limited = new HashSet<BucketKey>();
        }

        public bool TryAcquire(IPAddress address, bool tcp)
        {
            Rule[] rules = address.AddressFamily == AddressFamily.InterNetwork ? _ipv4Rules : _ipv6Rules;
            if ((rules.Length == 0) && !address.IsIPv4MappedToIPv6)
                return true;

            if (!TryGetAddress(address, out ulong high, out ulong low, out bool ipv6))
                return true;

            rules = ipv6 ? _ipv6Rules : _ipv4Rules;
            long now = Stopwatch.GetTimestamp();

            foreach (Rule rule in rules)
            {
                long interval = tcp ? rule.TcpInterval : rule.UdpInterval;
                if (interval == 0)
                    continue;

                Bucket bucket = GetBucket(CreateKey(high, low, ipv6, rule.PrefixLength, tcp));
                if (bucket is null)
                    continue;

                if (!bucket.TryConsume(now, interval, tcp ? rule.TcpTolerance : rule.UdpTolerance))
                    return false;
            }

            return true;
        }

        public bool IsLimited(IPAddress address)
        {
            HashSet<BucketKey> limited = _limited;
            if (limited.Count == 0)
                return false;

            if (!TryGetAddress(address, out ulong high, out ulong low, out bool ipv6))
                return false;

            foreach (Rule rule in ipv6 ? _ipv6Rules : _ipv4Rules)
            {
                if (limited.Contains(CreateKey(high, low, ipv6, rule.PrefixLength, false)) || limited.Contains(CreateKey(high, low, ipv6, rule.PrefixLength, true)))
                    return true;
            }

            return false;
        }

        public void Maintain(Action<string> log, bool hideAddresses = false)
        {
            long now = Stopwatch.GetTimestamp();
            HashSet<BucketKey> limited = new HashSet<BucketKey>();

            foreach (KeyValuePair<BucketKey, Bucket> entry in _buckets)
            {
                if (entry.Value.ResetLimited())
                {
                    limited.Add(entry.Key);
                }
                else if (entry.Value.TheoreticalArrivalTime <= now)
                {
                    if (_buckets.TryRemove(entry.Key, out _))
                        Interlocked.Decrement(ref _bucketCount);
                }
            }

            HashSet<BucketKey> previous = _limited;
            _limited = limited;

            foreach (BucketKey key in limited)
            {
                if (!previous.Contains(key))
                    log((hideAddresses ? "A client subnet (/" + key.PrefixLength + ")" : "Client subnet '" + key.ToNetworkAddress() + "'") + " exceeded the " + (key.IsTcp ? "TCP" : "UDP") + " rate limit of " + GetLimit(key) + " queries per second and is being rate limited.");
            }

            foreach (BucketKey key in previous)
            {
                if (!limited.Contains(key))
                    log((hideAddresses ? "A client subnet (/" + key.PrefixLength + ")" : "Client subnet '" + key.ToNetworkAddress() + "'") + " is no longer being rate limited for " + (key.IsTcp ? "TCP" : "UDP") + " services.");
            }
        }

        #endregion

        #region properties

        public bool IsEnabled
        { get { return (_ipv4Rules.Length > 0) || (_ipv6Rules.Length > 0); } }

        public int TrackedClients
        { get { return Volatile.Read(ref _bucketCount); } }

        #endregion

        readonly record struct BucketKey(ulong High, ulong Low, byte PrefixLength, byte Flags)
        {
            public bool IsIPv6
            { get { return (Flags & 1) != 0; } }

            public bool IsTcp
            { get { return (Flags & 2) != 0; } }

            public NetworkAddress ToNetworkAddress()
            {
                Span<byte> bytes = stackalloc byte[16];
                BinaryPrimitives.WriteUInt64BigEndian(bytes, High);
                BinaryPrimitives.WriteUInt64BigEndian(bytes.Slice(8), Low);

                IPAddress address = IsIPv6 ? new IPAddress(bytes) : new IPAddress(bytes.Slice(0, 4));

                return new NetworkAddress(address, PrefixLength);
            }
        }

        sealed class Rule
        {
            public readonly byte PrefixLength;
            public readonly int UdpLimit;
            public readonly int TcpLimit;
            public readonly long UdpInterval;
            public readonly long TcpInterval;
            public readonly long UdpTolerance;
            public readonly long TcpTolerance;

            public Rule(byte prefixLength, int udpLimit, int tcpLimit, int burstSeconds)
            {
                PrefixLength = prefixLength;
                UdpLimit = udpLimit;
                TcpLimit = tcpLimit;

                (UdpInterval, UdpTolerance) = GetParameters(udpLimit, burstSeconds);
                (TcpInterval, TcpTolerance) = GetParameters(tcpLimit, burstSeconds);
            }

            private static (long, long) GetParameters(int limit, int burstSeconds)
            {
                if (limit < 1)
                    return (0, 0);

                long interval = Math.Max(1, Stopwatch.Frequency / limit);
                long burst = Math.Max(1L, (long)limit * Math.Max(1, burstSeconds));

                return (interval, interval * (burst - 1));
            }
        }

        sealed class Bucket
        {
            long _theoreticalArrivalTime;
            volatile bool _limited;

            public bool TryConsume(long now, long interval, long tolerance)
            {
                while (true)
                {
                    long tat = Volatile.Read(ref _theoreticalArrivalTime);
                    long start = tat > now ? tat : now;

                    if (start - now > tolerance)
                    {
                        if (!_limited)
                            _limited = true;

                        return false;
                    }

                    if (Interlocked.CompareExchange(ref _theoreticalArrivalTime, start + interval, tat) == tat)
                        return true;
                }
            }

            public bool ResetLimited()
            {
                if (!_limited)
                    return false;

                _limited = false;
                return true;
            }

            public long TheoreticalArrivalTime
            { get { return Volatile.Read(ref _theoreticalArrivalTime); } }
        }
    }
}
