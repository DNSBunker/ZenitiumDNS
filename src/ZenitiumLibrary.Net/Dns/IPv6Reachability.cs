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
        const int PROBE_OVERRIDE_SECONDS = 30;
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
        static readonly Lock _probeLock = new Lock();
        static Task<bool> _probeTask;
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

            if (HasRecentSuccess(PROBE_OVERRIDE_SECONDS))
                return;

            bool wasAvailable = !IsUnavailable;

            Volatile.Write(ref _unavailableUntilTicks, DateTime.UtcNow.AddSeconds(HOLD_SECONDS).Ticks);

            if (wasAvailable)
                RaiseAvailabilityChanged(false);
        }

        private static bool HasRecentSuccess(int seconds)
        {
            long lastSuccess = Volatile.Read(ref _lastSuccessTicks);
            if (lastSuccess == 0)
                return false;

            return (DateTime.UtcNow.Ticks - lastSuccess) < (TimeSpan.TicksPerSecond * seconds);
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
                if (!await ProbeServersAsync(PROBE_TIMEOUT))
                    SetUnavailable();
            }
            catch
            { }
        }

        private static Task<bool> ProbeServersAsync(int timeout)
        {
            lock (_probeLock)
            {
                if ((_probeTask is null) || _probeTask.IsCompleted)
                    _probeTask = RunProbeAsync(timeout);

                return _probeTask;
            }
        }

        private static async Task<bool> RunProbeAsync(int timeout)
        {
            IReadOnlyList<NameServerAddress> rootHints = DnsClient.IPv6RootHints;
            if ((rootHints is null) || (rootHints.Count == 0))
                return true;

            await Task.Yield();

            List<string> errors = new List<string>(PROBE_ROUNDS);

            for (int round = 0; round < PROBE_ROUNDS; round++)
            {
                if (round > 0)
                    await Task.Delay(PROBE_ROUND_DELAY);

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
                    await dnsClient.ResolveAsync(new DnsQuestionRecord("", DnsResourceRecordType.NS, DnsClass.IN));
                    _lastProbeError = null;
                    return true;
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
            bool reachable = await ProbeServersAsync(timeout).WaitAsync(cancellationToken);

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

        public static DateTime LastSuccess
        {
            get
            {
                long ticks = Volatile.Read(ref _lastSuccessTicks);
                return ticks == 0 ? DateTime.MinValue : new DateTime(ticks, DateTimeKind.Utc);
            }
        }

        public static DateTime UnavailableUntil
        { get { return new DateTime(Volatile.Read(ref _unavailableUntilTicks), DateTimeKind.Utc); } }

        #endregion
    }
}
