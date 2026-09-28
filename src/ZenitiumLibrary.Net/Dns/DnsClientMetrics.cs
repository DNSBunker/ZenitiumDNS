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
using System.IO;
using System.Net.Sockets;
using System.Threading;

namespace ZenitiumLibrary.Net.Dns
{
    public enum DnsClientMetricsError : byte
    {
        Timeout = 0,
        Network = 1,
        Invalid = 2,
        Canceled = 3
    }

    public static class DnsClientMetrics
    {
        #region variables

        public const int PROTOCOL_COUNT = 5;
        public const int FAMILY_COUNT = 3;
        public const int RCODE_COUNT = 17;
        public const int ERROR_COUNT = 4;

        static readonly double[] _responseTimeBucketsMs = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000];

        static volatile bool _enabled;

        static readonly long[] _queries = new long[PROTOCOL_COUNT * FAMILY_COUNT];
        static readonly long[] _responses = new long[RCODE_COUNT];
        static readonly long[] _errors = new long[ERROR_COUNT];
        static long _truncated;

        static readonly long[] _responseTimeBuckets = new long[FAMILY_COUNT * (_responseTimeBucketsMs.Length + 1)];
        static readonly long[] _responseTimeSumMicroseconds = new long[FAMILY_COUNT];

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

                default:
                    return -1;
            }
        }

        private static int GetFamilyIndex(NameServerAddress server)
        {
            switch (server.IPEndPoint?.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    return 0;

                case AddressFamily.InterNetworkV6:
                    return 1;

                default:
                    return 2;
            }
        }

        private static void Reset()
        {
            Array.Clear(_queries);
            Array.Clear(_responses);
            Array.Clear(_errors);
            Array.Clear(_responseTimeBuckets);
            Array.Clear(_responseTimeSumMicroseconds);
            Interlocked.Exchange(ref _truncated, 0);
        }

        #endregion

        #region internal

        internal static void RecordQuery(NameServerAddress server)
        {
            if (!_enabled)
                return;

            int protocolIndex = GetProtocolIndex(server.Protocol);
            if (protocolIndex < 0)
                return;

            Interlocked.Increment(ref _queries[(protocolIndex * FAMILY_COUNT) + GetFamilyIndex(server)]);
        }

        internal static void RecordResponse(NameServerAddress server, DnsDatagram response)
        {
            if (!_enabled)
                return;

            int rcode = (int)response.RCODE;
            Interlocked.Increment(ref _responses[(rcode >= 0) && (rcode < RCODE_COUNT - 1) ? rcode : RCODE_COUNT - 1]);

            if (response.Truncation)
                Interlocked.Increment(ref _truncated);

            if (response.Metadata is null)
                return;

            double rtt = response.Metadata.RoundTripTime;
            if ((rtt < 0) || double.IsNaN(rtt))
                return;

            int familyIndex = GetFamilyIndex(server);
            int bucket = _responseTimeBucketsMs.Length;

            for (int i = 0; i < _responseTimeBucketsMs.Length; i++)
            {
                if (rtt <= _responseTimeBucketsMs[i])
                {
                    bucket = i;
                    break;
                }
            }

            Interlocked.Increment(ref _responseTimeBuckets[(familyIndex * (_responseTimeBucketsMs.Length + 1)) + bucket]);
            Interlocked.Add(ref _responseTimeSumMicroseconds[familyIndex], (long)(rtt * 1000));
        }

        internal static bool RecordFailure(Exception ex)
        {
            if (!_enabled)
                return false;

            DnsClientMetricsError error;

            switch (ex)
            {
                case DnsClientNoResponseException:
                case TimeoutException:
                    error = DnsClientMetricsError.Timeout;
                    break;

                case OperationCanceledException:
                    error = DnsClientMetricsError.Canceled;
                    break;

                case SocketException:
                case IOException:
                    error = DnsClientMetricsError.Network;
                    break;

                default:
                    error = DnsClientMetricsError.Invalid;
                    break;
            }

            Interlocked.Increment(ref _errors[(int)error]);
            return false;
        }

        #endregion

        #region public

        public static string GetProtocolName(int protocolIndex)
        {
            switch (protocolIndex)
            {
                case 0:
                    return "udp";

                case 1:
                    return "tcp";

                case 2:
                    return "tls";

                case 3:
                    return "https";

                case 4:
                    return "quic";

                default:
                    throw new ArgumentOutOfRangeException(nameof(protocolIndex));
            }
        }

        public static string GetFamilyName(int familyIndex)
        {
            switch (familyIndex)
            {
                case 0:
                    return "ipv4";

                case 1:
                    return "ipv6";

                default:
                    return "unknown";
            }
        }

        public static long GetQueries(int protocolIndex, int familyIndex)
        {
            return Interlocked.Read(ref _queries[(protocolIndex * FAMILY_COUNT) + familyIndex]);
        }

        public static long GetResponses(int rcodeIndex)
        {
            return Interlocked.Read(ref _responses[rcodeIndex]);
        }

        public static long GetErrors(DnsClientMetricsError error)
        {
            return Interlocked.Read(ref _errors[(int)error]);
        }

        public static long GetResponseTimeBucket(int familyIndex, int bucketIndex)
        {
            return Interlocked.Read(ref _responseTimeBuckets[(familyIndex * (_responseTimeBucketsMs.Length + 1)) + bucketIndex]);
        }

        public static double GetResponseTimeSumSeconds(int familyIndex)
        {
            return Interlocked.Read(ref _responseTimeSumMicroseconds[familyIndex]) / 1000000d;
        }

        #endregion

        #region properties

        public static bool Enabled
        {
            get { return _enabled; }
            set
            {
                if (_enabled == value)
                    return;

                if (value)
                    Reset();

                _enabled = value;
            }
        }

        public static long Truncated
        { get { return Interlocked.Read(ref _truncated); } }

        public static ReadOnlySpan<double> ResponseTimeBucketsMs
        { get { return _responseTimeBucketsMs; } }

        #endregion
    }
}
