using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumLibrary.Net.Dns
{
    public static class IPv6Reachability
    {
        #region variables

        const int FAILURE_THRESHOLD = 8;
        const int MIN_HOLD_SECONDS = 60;
        const int MAX_HOLD_SECONDS = 1800;
        const int PROBE_FAILURE_HOLD_SECONDS = 600;
        const int PROBE_SERVER_COUNT = 4;

        static int _consecutiveFailures;
        static long _unavailableUntilTicks;
        static int _holdSeconds = MIN_HOLD_SECONDS;
        static volatile bool _enabled = true;

        #endregion

        #region internal

        internal static void RecordSuccess()
        {
            Volatile.Write(ref _consecutiveFailures, 0);
            Volatile.Write(ref _holdSeconds, MIN_HOLD_SECONDS);
        }

        internal static void RecordFailure()
        {
            if (!_enabled)
                return;

            if (Interlocked.Increment(ref _consecutiveFailures) < FAILURE_THRESHOLD)
                return;

            Volatile.Write(ref _consecutiveFailures, 0);

            if (IsUnavailable)
                return;

            int holdSeconds = Volatile.Read(ref _holdSeconds);

            Volatile.Write(ref _unavailableUntilTicks, DateTime.UtcNow.AddSeconds(holdSeconds).Ticks);
            Volatile.Write(ref _holdSeconds, Math.Min(holdSeconds * 2, MAX_HOLD_SECONDS));
        }

        #endregion

        #region public

        public static async Task<bool> ProbeAsync(int timeout = 2000, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<NameServerAddress> rootHints = DnsClient.IPv6RootHints;
            if ((rootHints is null) || (rootHints.Count == 0))
                return true;

            List<NameServerAddress> servers = new List<NameServerAddress>(rootHints);
            servers.Shuffle();

            if (servers.Count > PROBE_SERVER_COUNT)
                servers.RemoveRange(PROBE_SERVER_COUNT, servers.Count - PROBE_SERVER_COUNT);

            DnsClient dnsClient = new DnsClient(servers);
            dnsClient.Timeout = timeout;
            dnsClient.Retries = 1;
            dnsClient.Concurrency = servers.Count;

            try
            {
                await dnsClient.ResolveAsync(new DnsQuestionRecord("", DnsResourceRecordType.NS, DnsClass.IN), cancellationToken);

                Reset();
                return true;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
                if (!_enabled)
                    return false;

                Volatile.Write(ref _consecutiveFailures, 0);
                Volatile.Write(ref _unavailableUntilTicks, DateTime.UtcNow.AddSeconds(PROBE_FAILURE_HOLD_SECONDS).Ticks);
                return false;
            }
        }

        public static IPv6Mode GetEffectiveMode(IPv6Mode ipv6Mode)
        {
            if ((ipv6Mode != IPv6Mode.Disabled) && IsUnavailable)
                return IPv6Mode.Disabled;

            return ipv6Mode;
        }

        public static void Reset()
        {
            Volatile.Write(ref _consecutiveFailures, 0);
            Volatile.Write(ref _unavailableUntilTicks, 0);
            Volatile.Write(ref _holdSeconds, MIN_HOLD_SECONDS);
        }

        #endregion

        #region properties

        public static bool Enabled
        {
            get { return _enabled; }
            set
            {
                _enabled = value;

                if (!value)
                    Reset();
            }
        }

        public static bool IsUnavailable
        { get { return _enabled && (DateTime.UtcNow.Ticks < Volatile.Read(ref _unavailableUntilTicks)); } }

        public static DateTime UnavailableUntil
        { get { return new DateTime(Volatile.Read(ref _unavailableUntilTicks), DateTimeKind.Utc); } }

        #endregion
    }
}
