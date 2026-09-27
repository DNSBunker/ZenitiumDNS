using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumLibrary.Net.Dns
{
    public static class IPv6Reachability
    {
        #region variables

        const int SUCCESS_GRACE_SECONDS = 30;
        const int FAILURE_WINDOW_SECONDS = 30;
        const int FAILURE_THRESHOLD = 16;
        const int DISTINCT_ADDRESS_THRESHOLD = 2;
        const int CONFIRMATION_COOLDOWN_SECONDS = 60;
        const int HOLD_SECONDS = 600;
        const int PROBE_SERVER_COUNT = 4;
        const int PROBE_TIMEOUT = 3000;
        const int PROBE_RETRIES = 1;
        const int PROBE_ROUNDS = 2;
        const int PROBE_ROUND_DELAY = 5000;
        const int UNCONFIRMED_SECONDS = 120;

        static readonly Lock _lock = new Lock();
        static readonly IPAddress[] _failedAddresses = new IPAddress[DISTINCT_ADDRESS_THRESHOLD];
        static int _failedAddressCount;
        static int _windowFailures;
        static long _windowStartTicks;
        static long _lastSuccessTicks;
        static long _lastConfirmationTicks;
        static long _unavailableUntilTicks;
        static int _probing;
        static volatile bool _enabled = true;
        static volatile bool _confirmed;
        static volatile string _lastProbeError;
        static long _unconfirmedUntilTicks = DateTime.UtcNow.AddSeconds(UNCONFIRMED_SECONDS).Ticks;

        public static event EventHandler<bool> AvailabilityChanged;

        #endregion

        #region private

        private static void SetAvailable()
        {
            long previous = Interlocked.Exchange(ref _unavailableUntilTicks, 0);
            if (previous > DateTime.UtcNow.Ticks)
                RaiseAvailabilityChanged(true);
        }

        private static void SetUnavailable()
        {
            if (!_enabled)
                return;

            bool wasAvailable = !IsUnavailable;

            Volatile.Write(ref _unavailableUntilTicks, DateTime.UtcNow.AddSeconds(HOLD_SECONDS).Ticks);

            if (wasAvailable)
                RaiseAvailabilityChanged(false);
        }

        private static void RaiseAvailabilityChanged(bool available)
        {
            try
            {
                AvailabilityChanged?.Invoke(null, available);
            }
            catch
            { }
        }

        private static async Task ConfirmAsync()
        {
            try
            {
                if (!await ProbeServersAsync(PROBE_TIMEOUT, CancellationToken.None))
                    SetUnavailable();
            }
            catch
            { }
        }

        private static async Task<bool> ProbeServersAsync(int timeout, CancellationToken cancellationToken)
        {
            IReadOnlyList<NameServerAddress> rootHints = DnsClient.IPv6RootHints;
            if ((rootHints is null) || (rootHints.Count == 0))
                return true;

            if (Interlocked.Exchange(ref _probing, 1) == 1)
                return !IsUnavailable;

            try
            {
                List<string> errors = new List<string>(PROBE_ROUNDS);

                for (int round = 0; round < PROBE_ROUNDS; round++)
                {
                    if (round > 0)
                        await Task.Delay(PROBE_ROUND_DELAY, cancellationToken);

                    List<NameServerAddress> servers = new List<NameServerAddress>(rootHints);
                    servers.Shuffle();

                    if (servers.Count > PROBE_SERVER_COUNT)
                        servers.RemoveRange(PROBE_SERVER_COUNT, servers.Count - PROBE_SERVER_COUNT);

                    DnsClient dnsClient = new DnsClient(servers);
                    dnsClient.Timeout = timeout;
                    dnsClient.Retries = PROBE_RETRIES;
                    dnsClient.Concurrency = servers.Count;

                    try
                    {
                        await dnsClient.ResolveAsync(new DnsQuestionRecord("", DnsResourceRecordType.NS, DnsClass.IN), cancellationToken);
                        _lastProbeError = null;
                        return true;
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (DnsClientResponseValidationException)
                    {
                        _lastProbeError = null;
                        return true;
                    }
                    catch (Exception ex)
                    {
                        errors.Add("round " + (round + 1) + ": " + ex.GetType().Name + ": " + ex.Message);
                    }
                }

                _lastProbeError = string.Join(" ", errors);
                return false;
            }
            finally
            {
                Volatile.Write(ref _probing, 0);
            }
        }

        #endregion

        #region internal

        internal static bool IsTransportFailure(Exception ex)
        {
            switch (ex)
            {
                case DnsClientNoResponseException:
                    return true;

                case SocketException socketException:
                    switch (socketException.SocketErrorCode)
                    {
                        case SocketError.NetworkUnreachable:
                        case SocketError.HostUnreachable:
                        case SocketError.NetworkDown:
                        case SocketError.AddressNotAvailable:
                        case SocketError.TimedOut:
                            return true;

                        default:
                            return false;
                    }

                default:
                    return false;
            }
        }

        internal static void RecordSuccess()
        {
            Volatile.Write(ref _lastSuccessTicks, DateTime.UtcNow.Ticks);

            if (!_confirmed)
                _confirmed = true;

            if (Volatile.Read(ref _unavailableUntilTicks) != 0)
                SetAvailable();
        }

        internal static void RecordFailure(IPAddress address)
        {
            if (!_enabled || (address is null))
                return;

            long now = DateTime.UtcNow.Ticks;

            if ((now - Volatile.Read(ref _lastSuccessTicks)) < TimeSpan.TicksPerSecond * SUCCESS_GRACE_SECONDS)
                return;

            if (IsUnavailable)
                return;

            bool confirm = false;

            lock (_lock)
            {
                if ((now - _windowStartTicks) > (TimeSpan.TicksPerSecond * FAILURE_WINDOW_SECONDS))
                {
                    _windowStartTicks = now;
                    _windowFailures = 0;
                    _failedAddressCount = 0;
                    Array.Clear(_failedAddresses);
                }

                _windowFailures++;

                if (_failedAddressCount < _failedAddresses.Length)
                {
                    bool known = false;

                    for (int i = 0; i < _failedAddressCount; i++)
                    {
                        if (_failedAddresses[i].Equals(address))
                        {
                            known = true;
                            break;
                        }
                    }

                    if (!known)
                        _failedAddresses[_failedAddressCount++] = address;
                }

                if ((_windowFailures >= FAILURE_THRESHOLD) && (_failedAddressCount >= DISTINCT_ADDRESS_THRESHOLD) && ((now - _lastConfirmationTicks) >= (TimeSpan.TicksPerSecond * CONFIRMATION_COOLDOWN_SECONDS)))
                {
                    _lastConfirmationTicks = now;
                    _windowStartTicks = 0;
                    confirm = true;
                }
            }

            if (confirm)
                _ = Task.Run(ConfirmAsync);
        }

        #endregion

        #region public

        public static async Task<bool> ProbeAsync(int timeout = PROBE_TIMEOUT, CancellationToken cancellationToken = default)
        {
            bool reachable = await ProbeServersAsync(timeout, cancellationToken);

            if (reachable)
            {
                _confirmed = true;
                SetAvailable();
            }
            else
            {
                SetUnavailable();
            }

            return reachable;
        }

        public static IPv6Mode GetEffectiveMode(IPv6Mode ipv6Mode)
        {
            if ((ipv6Mode != IPv6Mode.Disabled) && IsUnavailable)
                return IPv6Mode.Disabled;

            return ipv6Mode;
        }

        public static void Reset()
        {
            lock (_lock)
            {
                _windowStartTicks = 0;
                _windowFailures = 0;
                _failedAddressCount = 0;
                Array.Clear(_failedAddresses);
                _lastConfirmationTicks = 0;
            }

            SetAvailable();
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

        public static bool IsUnconfirmed
        { get { return _enabled && !_confirmed && (DateTime.UtcNow.Ticks < Volatile.Read(ref _unconfirmedUntilTicks)); } }

        public static string LastProbeError
        { get { return _lastProbeError; } }

        public static DateTime UnavailableUntil
        { get { return new DateTime(Volatile.Read(ref _unavailableUntilTicks), DateTimeKind.Utc); } }

        #endregion
    }
}
