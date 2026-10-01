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
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace ZenitiumDns.Core.Dhcp
{
    public sealed class RaPrefix
    {
        public UInt128 Prefix { get; init; }

        public int PrefixLength { get; init; }

        public bool OnLink { get; set; }

        public bool Autonomous { get; set; }

        public uint ValidLifetime { get; set; }

        public uint PreferredLifetime { get; set; }

        public override string ToString()
        {
            return Dhcp6Utilities.FormatPrefix(Prefix, PrefixLength);
        }
    }

    public sealed class RaPlan
    {
        public string Interface { get; init; }

        public int InterfaceIndex { get; init; }

        public IPAddress LinkLocal { get; init; }

        public byte[] HardwareAddress { get; init; } = [];

        public bool Managed { get; init; }

        public bool Other { get; init; }

        public byte RouterPreference { get; init; }

        public ushort RouterLifetime { get; init; }

        public int Interval { get; init; }

        public int Mtu { get; init; }

        public List<RaPrefix> Prefixes { get; init; } = new List<RaPrefix>();

        public List<IPAddress> DnsServers { get; init; } = new List<IPAddress>();

        public List<string> SearchDomains { get; init; } = new List<string>();

        public uint DnsLifetime { get; init; }

        public bool SameAs(RaPlan other)
        {
            if ((other is null) || (Interface != other.Interface) || (InterfaceIndex != other.InterfaceIndex) || !Equals(LinkLocal, other.LinkLocal))
                return false;

            return BuildPacket(this, false).AsSpan().SequenceEqual(BuildPacket(other, false));
        }

        public static byte[] BuildPacket(RaPlan plan, bool final, IReadOnlyList<RaPrefix> deprecated = null)
        {
            using (MemoryStream mS = new MemoryStream())
            {
                Span<byte> header = stackalloc byte[16];
                header.Clear();
                header[0] = 134;
                header[4] = 0;

                byte flags = 0;
                if (plan.Managed)
                    flags |= 0x80;

                if (plan.Other)
                    flags |= 0x40;

                flags |= (byte)((plan.RouterPreference & 0x03) << 3);
                header[5] = flags;
                BinaryPrimitives.WriteUInt16BigEndian(header.Slice(6, 2), final ? (ushort)0 : plan.RouterLifetime);
                mS.Write(header);

                if (plan.HardwareAddress.Length == 6)
                {
                    mS.WriteByte(1);
                    mS.WriteByte(1);
                    mS.Write(plan.HardwareAddress);
                }

                if (plan.Mtu > 0)
                {
                    Span<byte> mtu = stackalloc byte[8];
                    mtu.Clear();
                    mtu[0] = 5;
                    mtu[1] = 1;
                    BinaryPrimitives.WriteUInt32BigEndian(mtu.Slice(4, 4), (uint)plan.Mtu);
                    mS.Write(mtu);
                }

                foreach (RaPrefix prefix in plan.Prefixes)
                    WritePrefix(mS, prefix, final);

                if (deprecated is not null)
                {
                    foreach (RaPrefix prefix in deprecated)
                        WritePrefix(mS, prefix, true);
                }

                if (plan.DnsServers.Count > 0)
                {
                    int length = 1 + 2 * plan.DnsServers.Count;
                    mS.WriteByte(25);
                    mS.WriteByte((byte)length);
                    mS.WriteByte(0);
                    mS.WriteByte(0);
                    WriteUInt32(mS, final ? 0 : plan.DnsLifetime);

                    foreach (IPAddress server in plan.DnsServers)
                        mS.Write(server.GetAddressBytes());
                }

                if (plan.SearchDomains.Count > 0)
                {
                    using (MemoryStream domains = new MemoryStream())
                    {
                        foreach (string domain in plan.SearchDomains)
                            Dhcp6Message.WriteDomain(domains, domain);

                        while (((domains.Length + 8) % 8) != 0)
                            domains.WriteByte(0);

                        mS.WriteByte(31);
                        mS.WriteByte((byte)((domains.Length + 8) / 8));
                        mS.WriteByte(0);
                        mS.WriteByte(0);
                        WriteUInt32(mS, final ? 0 : plan.DnsLifetime);
                        mS.Write(domains.ToArray());
                    }
                }

                return mS.ToArray();
            }
        }

        private static void WriteUInt32(Stream stream, uint value)
        {
            Span<byte> buffer = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(buffer, value);
            stream.Write(buffer);
        }

        private static void WritePrefix(Stream stream, RaPrefix prefix, bool final)
        {
            Span<byte> option = stackalloc byte[32];
            option.Clear();
            option[0] = 3;
            option[1] = 4;
            option[2] = (byte)prefix.PrefixLength;

            byte flags = 0;
            if (prefix.OnLink)
                flags |= 0x80;

            if (prefix.Autonomous)
                flags |= 0x40;

            option[3] = flags;
            BinaryPrimitives.WriteUInt32BigEndian(option.Slice(4, 4), final ? 0 : prefix.ValidLifetime);
            BinaryPrimitives.WriteUInt32BigEndian(option.Slice(8, 4), final ? 0 : prefix.PreferredLifetime);
            BinaryPrimitives.WriteUInt128BigEndian(option.Slice(16, 16), prefix.Prefix);
            stream.Write(option);
        }
    }

    public sealed class RaForeignRouter
    {
        public IPAddress Address { get; init; }

        public string Interface { get; init; }

        public DateTime FirstSeen { get; init; }

        public DateTime LastSeen { get; set; }

        public bool Managed { get; set; }

        public bool Other { get; set; }

        public ushort RouterLifetime { get; set; }

        public IReadOnlyList<string> Prefixes { get; set; } = [];

        public IReadOnlyList<string> DnsServers { get; set; } = [];

        public IReadOnlyList<string> SearchDomains { get; set; } = [];

        public long Count { get; set; }
    }

    public sealed class RaInterfaceStatus
    {
        public string Interface { get; init; }

        public bool Active { get; init; }

        public string Error { get; init; }

        public RaPlan Plan { get; init; }

        public DateTime LastSent { get; init; }

        public long Sent { get; init; }

        public long Solicitations { get; init; }
    }

    public sealed class RouterAdvertiser : IDisposable
    {
        #region variables

        const int IPPROTO_IPV6 = 41;
        const int IPPROTO_ICMPV6 = 58;
        const int ICMP6_FILTER = 1;
        const int IPV6_UNICAST_HOPS = 16;
        const int IPV6_MULTICAST_IF = 17;
        const int IPV6_MULTICAST_HOPS = 18;
        const int IPV6_MULTICAST_LOOP = 19;
        const int SOL_SOCKET = 1;
        const int SO_BINDTODEVICE = 25;

        const int MAX_INITIAL_ADVERTISEMENTS = 3;
        const int MAX_INITIAL_INTERVAL_MS = 16000;
        const int MIN_DELAY_BETWEEN_RAS_MS = 3000;
        const int MAX_RA_DELAY_MS = 500;
        const int DEPRECATED_PREFIX_HOLD_HOURS = 2;
        const int MAX_FOREIGN_ROUTERS = 64;

        static readonly IPAddress AllNodes = IPAddress.Parse("ff02::1");
        static readonly IPAddress AllRouters = IPAddress.Parse("ff02::2");

        readonly Action<string> _log;
        readonly Action<string, Exception> _logError;
        readonly object _lock = new object();
        readonly Dictionary<string, Advertiser> _advertisers = new Dictionary<string, Advertiser>(StringComparer.Ordinal);
        readonly Dictionary<string, string> _errors = new Dictionary<string, string>(StringComparer.Ordinal);
        readonly ConcurrentDictionary<string, RaForeignRouter> _foreignRouters = new ConcurrentDictionary<string, RaForeignRouter>(StringComparer.Ordinal);
        HashSet<IPAddress> _localAddresses = new HashSet<IPAddress>();
        Dictionary<int, string> _interfaceNames = new Dictionary<int, string>();
        Socket _monitor;
        CancellationTokenSource _monitorCancellation;
        string _monitorError;
        long _sent;
        long _solicitations;
        bool _disposed;

        #endregion

        #region constructor

        public RouterAdvertiser(Action<string> log, Action<string, Exception> logError)
        {
            _log = log ?? delegate (string message) { };
            _logError = logError ?? delegate (string message, Exception ex) { };
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            List<Advertiser> advertisers;

            lock (_lock)
            {
                if (_disposed)
                    return;

                _disposed = true;
                advertisers = new List<Advertiser>(_advertisers.Values);
                _advertisers.Clear();
            }

            foreach (Advertiser advertiser in advertisers)
                advertiser.Stop(true);

            StopMonitor();
        }

        #endregion

        #region private types

        private sealed class Advertiser
        {
            readonly RouterAdvertiser _owner;
            readonly Socket _socket;
            readonly CancellationTokenSource _cancellation = new CancellationTokenSource();
            readonly SemaphoreSlim _wakeup = new SemaphoreSlim(0, int.MaxValue);
            readonly List<(RaPrefix Prefix, DateTime Until)> _deprecated = new List<(RaPrefix, DateTime)>();
            RaPlan _plan;
            int _initialSent;
            long _lastSentTicks;
            long _solicitDue;
            DateTime _lastSent;
            long _sent;
            long _solicitations;

            public Advertiser(RouterAdvertiser owner, RaPlan plan)
            {
                _owner = owner;
                _plan = plan;
                _socket = CreateSocket(plan);
                _ = Task.Run(SendLoopAsync);
                _ = Task.Run(ReceiveLoopAsync);
            }

            public RaPlan Plan
            { get { return _plan; } }

            public DateTime LastSent
            { get { return _lastSent; } }

            public long Sent
            { get { return Interlocked.Read(ref _sent); } }

            public long Solicitations
            { get { return Interlocked.Read(ref _solicitations); } }

            public void Update(RaPlan plan)
            {
                lock (_deprecated)
                {
                    DateTime until = DateTime.UtcNow.AddHours(DEPRECATED_PREFIX_HOLD_HOURS);

                    foreach (RaPrefix old in _plan.Prefixes)
                    {
                        bool stillThere = false;

                        foreach (RaPrefix current in plan.Prefixes)
                        {
                            if ((current.Prefix == old.Prefix) && (current.PrefixLength == old.PrefixLength))
                            {
                                stillThere = true;
                                break;
                            }
                        }

                        if (!stillThere)
                            _deprecated.Add((old, until));
                    }

                    _deprecated.RemoveAll(delegate ((RaPrefix Prefix, DateTime Until) entry)
                    {
                        foreach (RaPrefix current in plan.Prefixes)
                        {
                            if ((current.Prefix == entry.Prefix.Prefix) && (current.PrefixLength == entry.Prefix.PrefixLength))
                                return true;
                        }

                        return false;
                    });
                }

                _plan = plan;
                _initialSent = 0;
                _wakeup.Release();
            }

            public void OnSolicitation()
            {
                Interlocked.Increment(ref _solicitations);
                Interlocked.Increment(ref _owner._solicitations);

                long due = Environment.TickCount64 + Random.Shared.Next(0, MAX_RA_DELAY_MS);
                long earliest = Interlocked.Read(ref _lastSentTicks) + MIN_DELAY_BETWEEN_RAS_MS;

                if (due < earliest)
                    due = earliest;

                long current = Interlocked.Read(ref _solicitDue);

                if ((current == 0) || (due < current))
                    Interlocked.Exchange(ref _solicitDue, due);

                _wakeup.Release();
            }

            public void Stop(bool sendFinal)
            {
                if (sendFinal)
                {
                    try
                    {
                        byte[] packet = RaPlan.BuildPacket(_plan, true);
                        _socket.SendTo(packet, new IPEndPoint(new IPAddress(AllNodes.GetAddressBytes(), _plan.InterfaceIndex), 0));
                    }
                    catch
                    { }
                }

                try
                {
                    _cancellation.Cancel();
                }
                catch
                { }

                try
                {
                    _socket.Dispose();
                }
                catch
                { }
            }

            private List<RaPrefix> GetDeprecated()
            {
                lock (_deprecated)
                {
                    DateTime now = DateTime.UtcNow;
                    _deprecated.RemoveAll(delegate ((RaPrefix Prefix, DateTime Until) entry) { return entry.Until <= now; });

                    List<RaPrefix> result = new List<RaPrefix>(_deprecated.Count);
                    foreach ((RaPrefix prefix, DateTime _) in _deprecated)
                        result.Add(prefix);

                    return result;
                }
            }

            private void SendNow()
            {
                RaPlan plan = _plan;
                byte[] packet = RaPlan.BuildPacket(plan, false, GetDeprecated());

                try
                {
                    _socket.SendTo(packet, new IPEndPoint(new IPAddress(AllNodes.GetAddressBytes(), plan.InterfaceIndex), 0));
                    _lastSent = DateTime.UtcNow;
                    Interlocked.Exchange(ref _lastSentTicks, Environment.TickCount64);
                    Interlocked.Increment(ref _sent);
                    Interlocked.Increment(ref _owner._sent);
                }
                catch (ObjectDisposedException)
                { }
                catch (Exception ex)
                {
                    _owner._logError("Router advertisement on " + plan.Interface + " failed", ex);
                }
            }

            private async Task SendLoopAsync()
            {
                CancellationToken token = _cancellation.Token;
                long nextUnsolicited = Environment.TickCount64 + Random.Shared.Next(100, 1000);

                while (!token.IsCancellationRequested)
                {
                    long now = Environment.TickCount64;
                    long solicitDue = Interlocked.Read(ref _solicitDue);
                    long due = nextUnsolicited;

                    if ((solicitDue != 0) && (solicitDue < due))
                        due = solicitDue;

                    if (due > now)
                    {
                        try
                        {
                            await _wakeup.WaitAsync((int)Math.Min(due - now, int.MaxValue), token);
                        }
                        catch (OperationCanceledException)
                        {
                            return;
                        }

                        if (_initialSent == 0)
                            nextUnsolicited = Math.Min(nextUnsolicited, Environment.TickCount64 + Random.Shared.Next(100, 1000));

                        continue;
                    }

                    if (now < Interlocked.Read(ref _lastSentTicks) + MIN_DELAY_BETWEEN_RAS_MS)
                    {
                        long wait = Interlocked.Read(ref _lastSentTicks) + MIN_DELAY_BETWEEN_RAS_MS;

                        if (nextUnsolicited < wait)
                            nextUnsolicited = wait;

                        if ((solicitDue != 0) && (solicitDue < wait))
                            Interlocked.Exchange(ref _solicitDue, wait);

                        continue;
                    }

                    SendNow();
                    Interlocked.Exchange(ref _solicitDue, 0);

                    int interval = Math.Max(4, _plan.Interval) * 1000;
                    int next = Random.Shared.Next(Math.Max(3000, interval / 3), interval + 1);

                    if (_initialSent < MAX_INITIAL_ADVERTISEMENTS)
                    {
                        _initialSent++;
                        next = Math.Min(next, MAX_INITIAL_INTERVAL_MS);
                    }

                    nextUnsolicited = Environment.TickCount64 + next;
                }
            }

            private async Task ReceiveLoopAsync()
            {
                CancellationToken token = _cancellation.Token;
                byte[] buffer = new byte[2048];
                EndPoint any = new IPEndPoint(IPAddress.IPv6Any, 0);

                while (!token.IsCancellationRequested)
                {
                    SocketReceiveFromResult result;

                    try
                    {
                        result = await _socket.ReceiveFromAsync(buffer, SocketFlags.None, any, token);
                    }
                    catch (OperationCanceledException)
                    {
                        return;
                    }
                    catch (ObjectDisposedException)
                    {
                        return;
                    }
                    catch (SocketException)
                    {
                        if (token.IsCancellationRequested)
                            return;

                        await Task.Delay(1000, CancellationToken.None);
                        continue;
                    }

                    if ((result.ReceivedBytes >= 8) && (buffer[0] == 133) && (buffer[1] == 0))
                        OnSolicitation();
                }
            }
        }

        #endregion

        #region private

        private static Socket CreateSocket(RaPlan plan)
        {
            Socket socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);

            try
            {
                if (OperatingSystem.IsLinux())
                {
                    socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, System.Text.Encoding.ASCII.GetBytes(plan.Interface + "\0"));

                    byte[] filter = new byte[32];
                    Array.Fill(filter, (byte)0xFF);
                    ClearFilterBit(filter, 133);
                    socket.SetRawSocketOption(IPPROTO_ICMPV6, ICMP6_FILTER, filter);

                    socket.SetRawSocketOption(IPPROTO_IPV6, IPV6_UNICAST_HOPS, BitConverter.GetBytes(255));
                    socket.SetRawSocketOption(IPPROTO_IPV6, IPV6_MULTICAST_HOPS, BitConverter.GetBytes(255));
                    socket.SetRawSocketOption(IPPROTO_IPV6, IPV6_MULTICAST_LOOP, BitConverter.GetBytes(0));
                    socket.SetRawSocketOption(IPPROTO_IPV6, IPV6_MULTICAST_IF, BitConverter.GetBytes(plan.InterfaceIndex));
                }
                else
                {
                    socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastTimeToLive, 255);
                    socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastLoopback, false);
                    socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, plan.InterfaceIndex);
                }

                socket.Bind(new IPEndPoint(new IPAddress(plan.LinkLocal.GetAddressBytes(), plan.InterfaceIndex), 0));
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, new IPv6MulticastOption(AllRouters, plan.InterfaceIndex));

                return socket;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        private static void ClearFilterBit(byte[] filter, int type)
        {
            int word = type >> 5;
            int bit = type & 31;
            uint value = BitConverter.ToUInt32(filter, word * 4);
            value &= ~(1u << bit);
            BitConverter.TryWriteBytes(filter.AsSpan(word * 4, 4), value);
        }

        private void StartMonitor()
        {
            Socket socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Raw, ProtocolType.IcmpV6);

            try
            {
                if (OperatingSystem.IsLinux())
                {
                    byte[] filter = new byte[32];
                    Array.Fill(filter, (byte)0xFF);
                    ClearFilterBit(filter, 134);
                    socket.SetRawSocketOption(IPPROTO_ICMPV6, ICMP6_FILTER, filter);
                }

                socket.Bind(new IPEndPoint(IPAddress.IPv6Any, 0));
            }
            catch (Exception ex)
            {
                socket.Dispose();

                string message = ex is SocketException se && (se.SocketErrorCode == SocketError.AccessDenied) ? "no permission for raw ICMPv6 sockets (CAP_NET_RAW is missing)" : ex.Message;

                if (_monitorError != message)
                    _log("Router advertisements of other routers cannot be observed: " + message);

                _monitorError = message;
                return;
            }

            CancellationTokenSource cancellation = new CancellationTokenSource();
            _monitor = socket;
            _monitorCancellation = cancellation;
            _monitorError = null;
            _ = Task.Run(delegate () { return MonitorLoopAsync(socket, cancellation.Token); });
        }

        private void StopMonitor()
        {
            Socket socket = _monitor;
            CancellationTokenSource cancellation = _monitorCancellation;
            _monitor = null;
            _monitorCancellation = null;

            try
            {
                cancellation?.Cancel();
            }
            catch
            { }

            try
            {
                socket?.Dispose();
            }
            catch
            { }
        }

        private async Task MonitorLoopAsync(Socket socket, CancellationToken token)
        {
            byte[] buffer = new byte[2048];
            EndPoint any = new IPEndPoint(IPAddress.IPv6Any, 0);
            int errors = 0;

            while (!token.IsCancellationRequested)
            {
                SocketReceiveFromResult result;

                try
                {
                    result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, token);
                    errors = 0;
                }
                catch (OperationCanceledException)
                {
                    return;
                }
                catch (ObjectDisposedException)
                {
                    return;
                }
                catch (SocketException ex)
                {
                    if (token.IsCancellationRequested)
                        return;

                    if (++errors == 10)
                        _logError("Observing router advertisements of other routers failed", ex);

                    await Task.Delay(1000, CancellationToken.None);
                    continue;
                }
                catch (Exception ex)
                {
                    _logError("Observing router advertisements of other routers failed", ex);
                    return;
                }

                if ((result.ReceivedBytes < 16) || (buffer[0] != 134) || (buffer[1] != 0))
                    continue;

                IPAddress source = ((IPEndPoint)result.RemoteEndPoint).Address;

                if (!source.IsIPv6LinkLocal || IsLocal(source))
                    continue;

                int index = (int)source.ScopeId;

                if (!_interfaceNames.TryGetValue(index, out string iface))
                    iface = "#" + index;

                RecordForeignRouter(iface, source, buffer.AsSpan(0, result.ReceivedBytes));
            }
        }

        private bool IsLocal(IPAddress address)
        {
            HashSet<IPAddress> local = _localAddresses;
            return local.Contains(new IPAddress(address.GetAddressBytes()));
        }

        private void RecordForeignRouter(string iface, IPAddress source, ReadOnlySpan<byte> packet)
        {
            if (packet.Length < 16)
                return;

            byte flags = packet[5];
            ushort lifetime = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(6, 2));
            List<string> prefixes = new List<string>();
            List<string> dnsServers = new List<string>();
            List<string> domains = new List<string>();

            int offset = 16;

            while (offset + 2 <= packet.Length)
            {
                byte type = packet[offset];
                int length = packet[offset + 1] * 8;

                if ((length == 0) || (offset + length > packet.Length))
                    break;

                ReadOnlySpan<byte> option = packet.Slice(offset, length);

                switch (type)
                {
                    case 3:
                        if ((length == 32) && (prefixes.Count < 8))
                        {
                            byte prefixFlags = option[3];
                            string text = Dhcp6Utilities.FormatPrefix(BinaryPrimitives.ReadUInt128BigEndian(option.Slice(16, 16)), option[2]);

                            if ((prefixFlags & 0x40) != 0)
                                text += " SLAAC";

                            prefixes.Add(text);
                        }
                        break;

                    case 25:
                        for (int i = 8; (i + 16 <= length) && (dnsServers.Count < 8); i += 16)
                            dnsServers.Add(new IPAddress(option.Slice(i, 16)).ToString());

                        break;

                    case 31:
                        {
                            int domainOffset = 8;
                            ReadOnlySpan<byte> data = option;

                            while ((domainOffset < length) && (data[domainOffset] != 0) && (domains.Count < 8))
                            {
                                if (!Dhcp6Message.TryReadDomain(data, ref domainOffset, out string domain))
                                    break;

                                domains.Add(domain);
                            }
                        }
                        break;
                }

                offset += length;
            }

            DateTime now = DateTime.UtcNow;
            string key = iface + "|" + source;

            if (!_foreignRouters.ContainsKey(key) && (_foreignRouters.Count >= MAX_FOREIGN_ROUTERS))
                return;

            bool added = false;

            RaForeignRouter router = _foreignRouters.GetOrAdd(key, delegate (string k)
            {
                added = true;
                return new RaForeignRouter() { Address = source, Interface = iface, FirstSeen = now };
            });

            lock (router)
            {
                router.LastSeen = now;
                router.Managed = (flags & 0x80) != 0;
                router.Other = (flags & 0x40) != 0;
                router.RouterLifetime = lifetime;
                router.Prefixes = prefixes;
                router.DnsServers = dnsServers;
                router.SearchDomains = domains;
                router.Count++;
            }

            if (added)
                _log("Router advertisement from another router " + source + " seen on " + iface + (dnsServers.Count > 0 ? " (DNS servers: " + string.Join(", ", dnsServers) + ")" : "") + ".");
        }

        #endregion

        #region public

        public static RaPlan BuildPlan(DhcpConfiguration config, Dhcp6InterfaceInfo iface, uint defaultLeaseTime)
        {
            if (!config.IsInterfaceAllowed(iface.Name))
                return null;

            IPAddress linkLocal = iface.LinkLocal;
            if ((linkLocal is null) || (iface.Index <= 0))
                return null;

            List<Dhcp6RangeCandidate> candidates = Dhcp6RangeCandidate.GetForInterface(config, iface);
            if (candidates.Count == 0)
                return null;

            bool enabled = config.EnableRa;
            bool managed = false;
            bool other = false;
            uint maxLease = 0;

            Dictionary<(UInt128, int), RaPrefix> prefixes = new Dictionary<(UInt128, int), RaPrefix>();
            List<RaPrefix> ordered = new List<RaPrefix>();

            foreach (Dhcp6RangeCandidate candidate in candidates)
            {
                Dhcp6RangeRule rule = candidate.Rule;

                if (rule.EnablesRa)
                    enabled = true;

                if (rule.AssignsAddresses)
                    managed = true;

                if (rule.OffersDhcp)
                    other = true;

                uint lease = rule.LeaseTime != 0 ? rule.LeaseTime : defaultLeaseTime;
                maxLease = Math.Max(maxLease, lease);

                if (!prefixes.TryGetValue((candidate.Prefix, candidate.PrefixLength), out RaPrefix prefix))
                {
                    prefix = new RaPrefix() { Prefix = candidate.Prefix, PrefixLength = candidate.PrefixLength, ValidLifetime = lease, PreferredLifetime = lease };
                    prefixes.Add((candidate.Prefix, candidate.PrefixLength), prefix);
                    ordered.Add(prefix);
                }

                if (!rule.OffLink)
                    prefix.OnLink = true;

                if (rule.AutonomousFlag && (candidate.PrefixLength == 64))
                    prefix.Autonomous = true;

                prefix.ValidLifetime = Math.Max(prefix.ValidLifetime, lease);
                prefix.PreferredLifetime = Math.Max(prefix.PreferredLifetime, lease);
            }

            if (!enabled)
                return null;

            foreach (DhcpHostRule host in config.Hosts)
            {
                if (host.Address6 is null)
                    continue;

                foreach (Dhcp6RangeCandidate candidate in candidates)
                {
                    if (candidate.Rule.StaticOnly)
                        managed = true;
                }
            }

            DhcpRaParam param = config.GetRaParam(iface.Name);
            int interval = (param is not null) && (param.Interval > 0) ? param.Interval : 600;
            int routerLifetime;

            if ((param is not null) && (param.RouterLifetime >= 0))
                routerLifetime = param.RouterLifetime;
            else
                routerLifetime = iface.Forwarding ? Math.Min(9000, interval * 3) : 0;

            int mtu = 0;

            if (param is not null)
            {
                if (param.MtuOff)
                    mtu = 0;
                else if (param.Mtu > 0)
                    mtu = param.Mtu;
                else if (param.MtuInterface is not null)
                    mtu = Dhcp6Utilities.GetInterface(param.MtuInterface)?.Mtu ?? 0;
            }

            IPAddress server = iface.GetBestServerAddress() ?? linkLocal;
            List<IPAddress> dnsServers = new List<IPAddress>();
            List<string> domains = new List<string>();
            bool dnsConfigured = false;
            bool domainsConfigured = false;

            foreach (Dhcp6OptionRule rule in GetUntaggedRules(config, iface.Name))
            {
                if (rule.Code == Dhcp6OptionCode.DnsServers)
                {
                    dnsConfigured = true;
                    dnsServers.Clear();

                    if (rule.Suppress)
                        continue;

                    for (int i = 0; i + 16 <= rule.Value.Length; i += 16)
                    {
                        IPAddress address = new IPAddress(rule.Value.AsSpan(i, 16));
                        dnsServers.Add(address.Equals(IPAddress.IPv6Any) ? server : address);
                    }
                }
                else if (rule.Code == Dhcp6OptionCode.DomainList)
                {
                    domainsConfigured = true;
                    domains.Clear();

                    if (rule.Suppress)
                        continue;

                    int offset = 0;
                    while ((offset < rule.Value.Length) && Dhcp6Message.TryReadDomain(rule.Value, ref offset, out string domain))
                    {
                        if (domain.Length > 0)
                            domains.Add(domain);
                    }
                }
            }

            if (!dnsConfigured)
                dnsServers.Add(server);

            if (!domainsConfigured)
            {
                foreach (DhcpDomainRule rule in config.Domains)
                {
                    if (rule.Start is null)
                    {
                        domains.Add(rule.Domain);
                        break;
                    }
                }
            }

            if (dnsServers.Count > 8)
                dnsServers.RemoveRange(8, dnsServers.Count - 8);

            if (domains.Count > 8)
                domains.RemoveRange(8, domains.Count - 8);

            return new RaPlan()
            {
                Interface = iface.Name,
                InterfaceIndex = iface.Index,
                LinkLocal = linkLocal,
                HardwareAddress = iface.HardwareAddress.Length == 6 ? iface.HardwareAddress : [],
                Managed = managed,
                Other = other,
                RouterPreference = param?.RouterPreference ?? 0,
                RouterLifetime = (ushort)routerLifetime,
                Interval = interval,
                Mtu = mtu,
                Prefixes = ordered,
                DnsServers = dnsServers,
                SearchDomains = domains,
                DnsLifetime = (uint)Math.Max(interval * 3, 1200)
            };
        }

        private static List<Dhcp6OptionRule> GetUntaggedRules(DhcpConfiguration config, string interfaceName)
        {
            List<Dhcp6OptionRule> result = new List<Dhcp6OptionRule>();
            HashSet<string> tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { interfaceName };

            foreach (Dhcp6RangeRule range in config.Ranges6)
            {
                if ((range.SetTag is not null) && range.MatchesConstructor(interfaceName) && (range.Conditions.Count == 0))
                    tags.Add(range.SetTag);
            }

            List<(Dhcp6OptionRule Rule, int Score)> scored = new List<(Dhcp6OptionRule, int)>();

            foreach (Dhcp6OptionRule rule in config.Options6)
            {
                if (DhcpTagCondition.AllMatch(rule.Conditions, tags))
                    scored.Add((rule, rule.Conditions.Count * 2 - (rule.Weak ? 1000 : 0)));
            }

            scored.Sort(delegate ((Dhcp6OptionRule Rule, int Score) x, (Dhcp6OptionRule Rule, int Score) y)
            {
                int c = x.Score.CompareTo(y.Score);
                return c != 0 ? c : x.Rule.Line.CompareTo(y.Rule.Line);
            });

            foreach ((Dhcp6OptionRule rule, int _) in scored)
                result.Add(rule);

            return result;
        }

        public void Update(DhcpConfiguration config, bool enabled, List<Dhcp6InterfaceInfo> interfaces, uint defaultLeaseTime)
        {
            HashSet<IPAddress> local = new HashSet<IPAddress>();
            Dictionary<int, string> names = new Dictionary<int, string>();
            Dictionary<string, RaPlan> wanted = new Dictionary<string, RaPlan>(StringComparer.Ordinal);

            foreach (Dhcp6InterfaceInfo iface in interfaces)
            {
                names[iface.Index] = iface.Name;

                foreach (Dhcp6InterfaceAddress address in iface.Addresses)
                    local.Add(address.Address);

                if (!enabled)
                    continue;

                RaPlan plan = BuildPlan(config, iface, defaultLeaseTime);

                if (plan is not null)
                    wanted[iface.Name] = plan;
            }

            _localAddresses = local;
            _interfaceNames = names;

            lock (_lock)
            {
                if (_disposed)
                    return;

                if (enabled && (_monitor is null))
                    StartMonitor();
                else if (!enabled && (_monitor is not null))
                    StopMonitor();
            }

            List<Advertiser> toStop = new List<Advertiser>();
            List<(string Name, RaPlan Plan)> toStart = new List<(string, RaPlan)>();

            lock (_lock)
            {
                if (_disposed)
                    return;

                foreach (KeyValuePair<string, Advertiser> entry in _advertisers)
                {
                    if (!wanted.TryGetValue(entry.Key, out RaPlan plan) || (plan.InterfaceIndex != entry.Value.Plan.InterfaceIndex) || !plan.LinkLocal.Equals(entry.Value.Plan.LinkLocal))
                        toStop.Add(entry.Value);
                }

                foreach (Advertiser advertiser in toStop)
                    _advertisers.Remove(advertiser.Plan.Interface);

                foreach (KeyValuePair<string, RaPlan> entry in wanted)
                {
                    if (_advertisers.TryGetValue(entry.Key, out Advertiser existing))
                    {
                        if (!existing.Plan.SameAs(entry.Value))
                            existing.Update(entry.Value);
                    }
                    else
                    {
                        toStart.Add((entry.Key, entry.Value));
                    }
                }

                foreach (string name in new List<string>(_errors.Keys))
                {
                    if (!wanted.ContainsKey(name))
                        _errors.Remove(name);
                }
            }

            foreach (Advertiser advertiser in toStop)
            {
                advertiser.Stop(true);
                _log("Router advertisements on " + advertiser.Plan.Interface + " were stopped.");
            }

            foreach ((string name, RaPlan plan) in toStart)
            {
                try
                {
                    Advertiser advertiser = new Advertiser(this, plan);

                    lock (_lock)
                    {
                        if (_disposed)
                        {
                            advertiser.Stop(false);
                            return;
                        }

                        _advertisers[name] = advertiser;
                        _errors.Remove(name);
                    }

                    _log("Router advertisements on " + name + " were started (" + (plan.Managed ? "M" : "") + (plan.Other ? "O" : "") + (plan.Managed || plan.Other ? " flags, " : "no flags, ") + "prefixes: " + (plan.Prefixes.Count == 0 ? "none" : string.Join(", ", plan.Prefixes)) + ", DNS: " + string.Join(", ", plan.DnsServers) + ").");
                }
                catch (Exception ex)
                {
                    string message = ex is SocketException se && (se.SocketErrorCode == SocketError.AccessDenied) ? "no permission for raw ICMPv6 sockets (CAP_NET_RAW is missing)" : ex.Message;

                    lock (_lock)
                    {
                        bool known = _errors.TryGetValue(name, out string previous) && (previous == message);
                        _errors[name] = message;

                        if (!known)
                            _log("Router advertisements on " + name + " could not be started: " + message);
                    }
                }
            }
        }

        public void Maintain()
        {
            DateTime limit = DateTime.UtcNow.AddHours(-24);

            foreach (KeyValuePair<string, RaForeignRouter> entry in _foreignRouters)
            {
                if (entry.Value.LastSeen < limit)
                    _foreignRouters.TryRemove(entry.Key, out _);
            }
        }

        public void ClearForeignRouters()
        {
            _foreignRouters.Clear();
        }

        public List<RaForeignRouter> GetForeignRouters()
        {
            return new List<RaForeignRouter>(_foreignRouters.Values);
        }

        public List<RaInterfaceStatus> GetStatus()
        {
            List<RaInterfaceStatus> result = new List<RaInterfaceStatus>();

            lock (_lock)
            {
                foreach (Advertiser advertiser in _advertisers.Values)
                    result.Add(new RaInterfaceStatus() { Interface = advertiser.Plan.Interface, Active = true, Plan = advertiser.Plan, LastSent = advertiser.LastSent, Sent = advertiser.Sent, Solicitations = advertiser.Solicitations });

                foreach (KeyValuePair<string, string> error in _errors)
                    result.Add(new RaInterfaceStatus() { Interface = error.Key, Active = false, Error = error.Value });
            }

            result.Sort(delegate (RaInterfaceStatus x, RaInterfaceStatus y) { return string.CompareOrdinal(x.Interface, y.Interface); });
            return result;
        }

        public string MonitorError
        { get { return _monitorError; } }

        public long Sent
        { get { return Interlocked.Read(ref _sent); } }

        public long Solicitations
        { get { return Interlocked.Read(ref _solicitations); } }

        #endregion
    }
}
