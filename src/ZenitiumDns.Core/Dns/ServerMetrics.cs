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
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using ZenitiumDns.ApplicationCommon;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.EDnsOptions;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns
{
    sealed class ServerMetrics
    {
        #region variables

        public const int PROTOCOL_COUNT = 8;
        public const int FAMILY_COUNT = 2;
        public const int SOURCE_COUNT = 8;
        public const int LATENCY_GROUP_COUNT = 4;
        public const int EDE_CODE_LIMIT = 64;

        public static readonly string[] ProtocolNames = ["udp", "tcp", "tls", "https", "quic", "udp_proxy", "tcp_proxy", "other"];
        public static readonly string[] FamilyNames = ["ipv4", "ipv6"];
        public static readonly string[] LatencyGroupNames = ["local", "cache", "recursive", "blocked"];
        public static readonly string[] RequestFlagNames = ["rd", "cd", "do", "edns", "ecs", "cookie"];
        public static readonly string[] ResponseFlagNames = ["aa", "tc", "ad", "ra"];
        public static readonly string[] DropReasonNames = ["rate_limited", "no_response"];

        public static readonly double[] DurationBucketsMs = [0.25, 0.5, 1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000];
        public static readonly int[] SizeBuckets = [64, 128, 256, 512, 768, 1024, 1232, 1500, 2048, 4096, 8192, 16384, 65535];

        static readonly FrozenDictionary<ushort, int> _typeIndexes;
        static readonly string[] _typeNames;

        static readonly FrozenDictionary<ushort, int> _rcodeIndexes;
        static readonly string[] _rcodeNames;

        readonly DateTime _since = DateTime.UtcNow;

        readonly long[] _requests = new long[PROTOCOL_COUNT * FAMILY_COUNT];
        readonly long[] _types = new long[_typeNames.Length];
        readonly long[] _rcodes = new long[_rcodeNames.Length];
        readonly long[] _sources = new long[SOURCE_COUNT];
        readonly long[] _drops = new long[DropReasonNames.Length];
        readonly long[] _requestFlags = new long[RequestFlagNames.Length];
        readonly long[] _responseFlags = new long[ResponseFlagNames.Length];
        readonly long[] _extendedErrors = new long[EDE_CODE_LIMIT + 1];
        long _noData;

        readonly Histogram[] _duration = new Histogram[LATENCY_GROUP_COUNT];
        readonly Histogram[] _requestSize = new Histogram[PROTOCOL_COUNT];
        readonly Histogram[] _responseSize = new Histogram[PROTOCOL_COUNT];

        #endregion

        #region constructor

        static ServerMetrics()
        {
            {
                Dictionary<ushort, int> indexes = new Dictionary<ushort, int>();
                List<string> names = new List<string>();

                foreach (DnsResourceRecordType type in Enum.GetValues<DnsResourceRecordType>())
                {
                    if (indexes.TryAdd((ushort)type, names.Count))
                        names.Add(type.ToString());
                }

                names.Add("other");

                _typeIndexes = indexes.ToFrozenDictionary();
                _typeNames = names.ToArray();
            }

            {
                Dictionary<ushort, int> indexes = new Dictionary<ushort, int>();
                List<string> names = new List<string>();

                foreach (DnsResponseCode rcode in Enum.GetValues<DnsResponseCode>())
                {
                    if (indexes.TryAdd((ushort)rcode, names.Count))
                        names.Add(rcode.ToString());
                }

                names.Add("other");

                _rcodeIndexes = indexes.ToFrozenDictionary();
                _rcodeNames = names.ToArray();
            }
        }

        public ServerMetrics()
        {
            for (int i = 0; i < _duration.Length; i++)
                _duration[i] = new Histogram(DurationBucketsMs.Length);

            for (int i = 0; i < PROTOCOL_COUNT; i++)
            {
                _requestSize[i] = new Histogram(SizeBuckets.Length);
                _responseSize[i] = new Histogram(SizeBuckets.Length);
            }
        }

        #endregion

        #region private

        private static int GetProtocolIndex(DnsTransportProtocol protocol)
        {
            switch (protocol)
            {
                case DnsTransportProtocol.Udp:
                    return 0;

                case DnsTransportProtocol.Tcp:
                    return 1;

                case DnsTransportProtocol.Tls:
                    return 2;

                case DnsTransportProtocol.Https:
                case DnsTransportProtocol.HttpsJson:
                    return 3;

                case DnsTransportProtocol.Quic:
                    return 4;

                case DnsTransportProtocol.UdpProxy:
                    return 5;

                case DnsTransportProtocol.TcpProxy:
                    return 6;

                default:
                    return 7;
            }
        }

        private static int GetLatencyGroup(DnsServerResponseType responseType)
        {
            switch (responseType)
            {
                case DnsServerResponseType.Cached:
                case DnsServerResponseType.UpstreamBlockedCached:
                    return 1;

                case DnsServerResponseType.Recursive:
                case DnsServerResponseType.UpstreamBlocked:
                    return 2;

                case DnsServerResponseType.Blocked:
                    return 3;

                default:
                    return 0;
            }
        }

        private static int GetDurationBucket(double valueMs)
        {
            for (int i = 0; i < DurationBucketsMs.Length; i++)
            {
                if (valueMs <= DurationBucketsMs[i])
                    return i;
            }

            return DurationBucketsMs.Length;
        }

        private static int GetSizeBucket(int value)
        {
            for (int i = 0; i < SizeBuckets.Length; i++)
            {
                if (value <= SizeBuckets[i])
                    return i;
            }

            return SizeBuckets.Length;
        }

        private void RecordExtendedErrors(DnsDatagram response)
        {
            ulong seen = 0;
            bool seenOther = false;

            void Add(EDnsExtendedDnsErrorCode code)
            {
                int value = (int)code;

                if (value < EDE_CODE_LIMIT)
                {
                    ulong bit = 1UL << value;
                    if ((seen & bit) != 0)
                        return;

                    seen |= bit;
                    _extendedErrors[value]++;
                }
                else if (!seenOther)
                {
                    seenOther = true;
                    _extendedErrors[EDE_CODE_LIMIT]++;
                }
            }

            if (response.EDNS is not null)
            {
                foreach (EDnsOption option in response.EDNS.Options)
                {
                    if ((option.Code == EDnsOptionCode.EXTENDED_DNS_ERROR) && (option.Data is EDnsExtendedDnsErrorOptionData ede))
                        Add(ede.InfoCode);
                }
            }
            else
            {
                foreach (EDnsExtendedDnsErrorOptionData ede in response.DnsClientExtendedErrors)
                    Add(ede.InfoCode);
            }
        }

        #endregion

        #region public

        public void Record(DnsDatagram request, DnsDatagram response, DnsTransportProtocol protocol, IPAddress clientAddress, DnsServerResponseType responseType, bool rateLimited, double responseTimeMs, int responseSize)
        {
            int protocolIndex = GetProtocolIndex(protocol);
            int familyIndex = (clientAddress.AddressFamily == AddressFamily.InterNetworkV6) && !clientAddress.IsIPv4MappedToIPv6 ? 1 : 0;

            _requests[(protocolIndex * FAMILY_COUNT) + familyIndex]++;

            if (request is not null)
            {
                if (request.Question.Count > 0)
                {
                    if (_typeIndexes.TryGetValue((ushort)request.Question[0].Type, out int typeIndex))
                        _types[typeIndex]++;
                    else
                        _types[_types.Length - 1]++;
                }

                if (request.Size > 0)
                    _requestSize[protocolIndex].Add(GetSizeBucket(request.Size), request.Size);

                if (request.RecursionDesired)
                    _requestFlags[0]++;

                if (request.CheckingDisabled)
                    _requestFlags[1]++;

                if (request.EDNS is not null)
                {
                    if (request.DnssecOk)
                        _requestFlags[2]++;

                    _requestFlags[3]++;

                    if (request.GetEDnsClientSubnetOption(true) is not null)
                        _requestFlags[4]++;

                    DnsCookie.GetCookieOption(request, out int cookieCount);
                    if (cookieCount > 0)
                        _requestFlags[5]++;
                }
            }

            if (response is null)
            {
                _drops[rateLimited ? 0 : 1]++;
                return;
            }

            if (_rcodeIndexes.TryGetValue((ushort)response.RCODE, out int rcodeIndex))
                _rcodes[rcodeIndex]++;
            else
                _rcodes[_rcodes.Length - 1]++;

            int sourceIndex = (int)responseType;
            if ((sourceIndex > 0) && (sourceIndex < SOURCE_COUNT))
                _sources[sourceIndex]++;

            if ((response.RCODE == DnsResponseCode.NoError) && (response.Answer.Count == 0))
                _noData++;

            if (response.AuthoritativeAnswer)
                _responseFlags[0]++;

            if (response.Truncation)
                _responseFlags[1]++;

            if (response.AuthenticData)
                _responseFlags[2]++;

            if (response.RecursionAvailable)
                _responseFlags[3]++;

            RecordExtendedErrors(response);

            if (responseTimeMs >= 0)
                _duration[GetLatencyGroup(responseType)].Add(GetDurationBucket(responseTimeMs), responseTimeMs / 1000d);

            if (responseSize > 0)
                _responseSize[protocolIndex].Add(GetSizeBucket(responseSize), responseSize);
        }

        public long GetRequests(int protocolIndex, int familyIndex)
        {
            return _requests[(protocolIndex * FAMILY_COUNT) + familyIndex];
        }

        public long GetSource(DnsServerResponseType responseType)
        {
            return _sources[(int)responseType];
        }

        #endregion

        #region properties

        public DateTime Since
        { get { return _since; } }

        public static IReadOnlyList<string> TypeNames
        { get { return _typeNames; } }

        public static IReadOnlyList<string> RcodeNames
        { get { return _rcodeNames; } }

        public IReadOnlyList<long> Types
        { get { return _types; } }

        public IReadOnlyList<long> Rcodes
        { get { return _rcodes; } }

        public IReadOnlyList<long> Drops
        { get { return _drops; } }

        public IReadOnlyList<long> RequestFlags
        { get { return _requestFlags; } }

        public IReadOnlyList<long> ResponseFlags
        { get { return _responseFlags; } }

        public IReadOnlyList<long> ExtendedErrors
        { get { return _extendedErrors; } }

        public long NoData
        { get { return _noData; } }

        public IReadOnlyList<Histogram> Duration
        { get { return _duration; } }

        public IReadOnlyList<Histogram> RequestSize
        { get { return _requestSize; } }

        public IReadOnlyList<Histogram> ResponseSize
        { get { return _responseSize; } }

        #endregion

        public sealed class Histogram
        {
            readonly long[] _buckets;
            double _sum;

            public Histogram(int boundaries)
            {
                _buckets = new long[boundaries + 1];
            }

            public void Add(int bucket, double value)
            {
                _buckets[bucket]++;
                _sum += value;
            }

            public long[] GetBuckets()
            {
                long[] buckets = new long[_buckets.Length];

                for (int i = 0; i < buckets.Length; i++)
                    buckets[i] = _buckets[i];

                return buckets;
            }

            public double Sum
            { get { return _sum; } }
        }
    }
}
