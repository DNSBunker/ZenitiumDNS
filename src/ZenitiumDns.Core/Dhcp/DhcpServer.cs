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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace ZenitiumDns.Core.Dhcp
{
    public sealed class DhcpForeignServer
    {
        public IPAddress Address { get; init; }

        public string ServerId { get; init; }

        public string Interface { get; init; }

        public DateTime FirstSeen { get; init; }

        public DateTime LastSeen { get; set; }

        public string Source { get; set; }

        public IPAddress OfferedAddress { get; set; }

        public long Count { get; set; }
    }

    public sealed class DhcpDevice
    {
        public string HardwareAddress { get; set; }

        public string HostName { get; set; }

        public SortedSet<string> Addresses4 { get; } = new SortedSet<string>(StringComparer.Ordinal);

        public SortedSet<string> Addresses6 { get; } = new SortedSet<string>(StringComparer.Ordinal);

        public string ClientId { get; set; }

        public SortedSet<string> Duids { get; } = new SortedSet<string>(StringComparer.Ordinal);

        public bool Reserved { get; set; }

        public SortedSet<string> Sources { get; } = new SortedSet<string>(StringComparer.Ordinal);

        public DateTime LastSeen { get; set; }
    }

    public sealed class DhcpListenerStatus
    {
        public string Interface { get; init; }

        public IReadOnlyList<string> Addresses { get; init; }

        public string Error { get; init; }

        public bool Listening { get; init; }
    }

    public sealed class DhcpServer : IDisposable
    {
        #region variables

        public const string SETTINGS_FILE = "dhcp.json";
        public const string LEASES_FILE = "dhcp-leases.json";
        public const string LEASES6_FILE = "dhcp6-leases.json";

        const int SERVER_PORT = 67;
        const int CLIENT_PORT = 68;
        const int MAX_CONCURRENT_REQUESTS = 256;
        const int MAX_PACKETS_PER_CLIENT_PER_SECOND = 20;
        const int SO_BINDTODEVICE = 25;
        const int SOL_SOCKET = 1;
        const int MAINTENANCE_INTERVAL_MS = 15000;
        const int PROBE_WAIT_MS = 6000;
        const uint DEFAULT_LEASE_TIME = 3600;

        readonly string _configFolder;
        readonly Action<string> _logMessage;
        readonly Action<string, Exception> _logError;
        readonly string _nodeId;

        readonly object _lock = new object();
        readonly DhcpLeaseStore _store;
        readonly DhcpEngine _engine;
        readonly Dhcp6LeaseStore _store6;
        readonly Dhcp6Engine _engine6;
        readonly RouterAdvertiser _ra;
        readonly byte[] _serverDuid;

        DhcpSettings _settings = new DhcpSettings();
        DhcpConfiguration _config = DhcpConfiguration.Empty;
        List<DhcpConfigError> _configErrors = new List<DhcpConfigError>();

        readonly Dictionary<string, Listener> _listeners = new Dictionary<string, Listener>(StringComparer.Ordinal);
        readonly List<DhcpListenerStatus> _listenerStatus = new List<DhcpListenerStatus>();
        readonly Dictionary<string, Listener6> _listeners6 = new Dictionary<string, Listener6>(StringComparer.Ordinal);
        readonly List<DhcpListenerStatus> _listener6Status = new List<DhcpListenerStatus>();
        HashSet<UInt128> _localAddresses6 = new HashSet<UInt128>();
        long _received6;
        long _sent6;
        long _malformed6;
        DhcpRawSender _rawSender;
        string _rawSenderError;

        readonly SemaphoreSlim _concurrency = new SemaphoreSlim(MAX_CONCURRENT_REQUESTS, MAX_CONCURRENT_REQUESTS);
        readonly ConcurrentDictionary<string, (long Second, int Count)> _packetCounts = new ConcurrentDictionary<string, (long, int)>(StringComparer.Ordinal);
        HashSet<IPAddress> _localAddresses = new HashSet<IPAddress>();
        long _droppedRateLimited;
        long _droppedBusy;
        long _malformed;
        long _received;
        long _sent;

        readonly ConcurrentDictionary<string, DhcpForeignServer> _foreignServers = new ConcurrentDictionary<string, DhcpForeignServer>(StringComparer.Ordinal);
        readonly ConcurrentDictionary<string, DhcpForeignServer> _foreignServers6 = new ConcurrentDictionary<string, DhcpForeignServer>(StringComparer.Ordinal);
        readonly HashSet<string> _probeHardwareAddresses = new HashSet<string>(StringComparer.Ordinal);
        DateTime _lastProbe = DateTime.MinValue;
        DateTime _lastProbeCompleted = DateTime.MinValue;
        string _lastProbeError;
        int _probing;

        readonly NeighborTable _neighbors = new NeighborTable();
        Dictionary<IPAddress, byte[]> _addressToMac = new Dictionary<IPAddress, byte[]>();
        Dictionary<string, byte[]> _duidToMac = new Dictionary<string, byte[]>(StringComparer.Ordinal);

        readonly object _dnsLock = new object();
        Dictionary<string, DnsEntry> _dnsNames = new Dictionary<string, DnsEntry>(StringComparer.OrdinalIgnoreCase);
        Dictionary<uint, string> _dnsReverse = new Dictionary<uint, string>();
        Dictionary<UInt128, string> _dnsReverse6 = new Dictionary<UInt128, string>();
        int _dnsRebuildPending;

        Timer _maintenanceTimer;
        bool _started;
        bool _disposed;

        #endregion

        #region constructor

        public DhcpServer(string configFolder, string nodeId, Action<string> logMessage, Action<string, Exception> logError)
        {
            _configFolder = configFolder;
            _nodeId = nodeId;
            _logMessage = logMessage ?? delegate (string message) { };
            _logError = logError ?? delegate (string message, Exception ex) { };

            Action<string, Exception> storeLog = delegate (string message, Exception ex) { if (ex is null) _logMessage(message); else _logError(message, ex); };

            _store = new DhcpLeaseStore(configFolder is null ? null : Path.Combine(configFolder, LEASES_FILE), nodeId, storeLog);
            _engine = new DhcpEngine(_store, PingAsync, _logMessage);
            _engine.ForeignServerSeen += delegate (IPAddress address, string iface) { RecordForeignServer(address, iface, "request", null); };
            _store.LeaseChanged += delegate (DhcpLease lease) { ScheduleDnsRebuild(); };

            _serverDuid = CreateServerDuid(nodeId);
            _store6 = new Dhcp6LeaseStore(configFolder is null ? null : Path.Combine(configFolder, LEASES6_FILE), storeLog);
            _engine6 = new Dhcp6Engine(_store6, _logMessage);
            _engine6.ForeignServerSeen += RecordForeignServer6;
            _store6.LeaseChanged += delegate (Dhcp6Lease lease) { ScheduleDnsRebuild(); };
            _ra = new RouterAdvertiser(_logMessage, _logError);
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            lock (_lock)
            {
                if (_disposed)
                    return;

                _disposed = true;
            }

            _maintenanceTimer?.Dispose();
            _ra.Dispose();
            StopListeners();
            StopListeners6();
            _rawSender?.Dispose();
            _store.Dispose();
            _store6.Dispose();
        }

        #endregion

        #region private types

        private sealed class Listener
        {
            public Socket Socket;
            public DhcpInterfaceInfo Info;
            public CancellationTokenSource Cancellation;
            public Task ReceiveTask;
        }

        private sealed class Listener6
        {
            public Socket Socket;
            public volatile Dhcp6InterfaceInfo Info;
            public CancellationTokenSource Cancellation;
        }

        private sealed class DnsEntry
        {
            public List<IPAddress> Addresses4 = new List<IPAddress>();
            public DateTime Updated4 = DateTime.MinValue;
            public List<IPAddress> Addresses6 = new List<IPAddress>();
            public DateTime Updated6 = DateTime.MinValue;
            public string ClientKey6;
        }

        #endregion

        #region interfaces

        public static List<DhcpInterfaceInfo> GetInterfaces()
        {
            List<DhcpInterfaceInfo> result = new List<DhcpInterfaceInfo>();

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                        continue;

                    if ((nic.OperationalStatus != OperationalStatus.Up) && (nic.OperationalStatus != OperationalStatus.Unknown))
                        continue;

                    IPInterfaceProperties properties = nic.GetIPProperties();
                    List<DhcpInterfaceAddress> addresses = new List<DhcpInterfaceAddress>();

                    foreach (UnicastIPAddressInformation unicast in properties.UnicastAddresses)
                    {
                        if (unicast.Address.AddressFamily != AddressFamily.InterNetwork)
                            continue;

                        if (IPAddress.IsLoopback(unicast.Address))
                            continue;

                        int prefix = unicast.PrefixLength;
                        if ((prefix <= 0) || (prefix > 32))
                            continue;

                        addresses.Add(new DhcpInterfaceAddress(unicast.Address, prefix));
                    }

                    if (addresses.Count == 0)
                        continue;

                    IPAddress gateway = null;

                    foreach (GatewayIPAddressInformation gw in properties.GatewayAddresses)
                    {
                        if ((gw.Address.AddressFamily == AddressFamily.InterNetwork) && !gw.Address.Equals(IPAddress.Any))
                        {
                            gateway = gw.Address;
                            break;
                        }
                    }

                    int index = 0;
                    try
                    {
                        index = properties.GetIPv4Properties()?.Index ?? 0;
                    }
                    catch
                    { }

                    result.Add(new DhcpInterfaceInfo()
                    {
                        Name = nic.Name,
                        Index = index,
                        Addresses = addresses,
                        Gateway = gateway,
                        HardwareAddress = nic.GetPhysicalAddress().GetAddressBytes()
                    });
                }
                catch
                { }
            }

            return result;
        }

        private bool IsLocalAddress(IPAddress address)
        {
            HashSet<IPAddress> local = _localAddresses;
            return local.Contains(address);
        }

        private static bool SameInterface(DhcpInterfaceInfo a, DhcpInterfaceInfo b)
        {
            if ((a.Index != b.Index) || (a.Addresses.Count != b.Addresses.Count))
                return false;

            for (int i = 0; i < a.Addresses.Count; i++)
            {
                if (!a.Addresses[i].Address.Equals(b.Addresses[i].Address) || (a.Addresses[i].PrefixLength != b.Addresses[i].PrefixLength))
                    return false;
            }

            return Equals(a.Gateway, b.Gateway);
        }

        #endregion

        #region listeners

        private void StopListeners()
        {
            List<Listener> listeners;

            lock (_lock)
            {
                listeners = new List<Listener>(_listeners.Values);
                _listeners.Clear();
            }

            foreach (Listener listener in listeners)
                StopListener(listener);
        }

        private static void StopListener(Listener listener)
        {
            try
            {
                listener.Cancellation.Cancel();
            }
            catch
            { }

            try
            {
                listener.Socket.Dispose();
            }
            catch
            { }
        }

        private static Socket CreateBoundSocket(string interfaceName, int port)
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);

            try
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, true);

                if (OperatingSystem.IsLinux())
                {
                    byte[] name = Encoding.ASCII.GetBytes(interfaceName + "\0");
                    socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, name);
                }

                socket.Bind(new IPEndPoint(IPAddress.Any, port));
                return socket;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        private void RefreshListeners()
        {
            DhcpConfiguration config;
            bool enabled;

            lock (_lock)
            {
                if (_disposed || !_started)
                    return;

                config = _config;
                enabled = _settings.Enabled && (_configErrors.Count == 0);
            }

            List<DhcpInterfaceInfo> allInterfaces = GetInterfaces();
            List<DhcpInterfaceInfo> interfaces = enabled ? allInterfaces : new List<DhcpInterfaceInfo>();

            HashSet<IPAddress> localAddresses = new HashSet<IPAddress>();
            foreach (DhcpInterfaceInfo info in allInterfaces)
            {
                foreach (DhcpInterfaceAddress address in info.Addresses)
                    localAddresses.Add(address.Address);
            }

            _localAddresses = localAddresses;
            List<DhcpListenerStatus> status = new List<DhcpListenerStatus>();
            Dictionary<string, DhcpInterfaceInfo> wanted = new Dictionary<string, DhcpInterfaceInfo>(StringComparer.Ordinal);

            foreach (DhcpInterfaceInfo info in interfaces)
            {
                if (config.IsInterfaceAllowed(info.Name))
                    wanted[info.Name] = info;
            }

            List<Listener> toStop = new List<Listener>();

            lock (_lock)
            {
                foreach (KeyValuePair<string, Listener> entry in _listeners)
                {
                    if (!wanted.TryGetValue(entry.Key, out DhcpInterfaceInfo info) || !SameInterface(info, entry.Value.Info))
                        toStop.Add(entry.Value);
                }

                foreach (Listener listener in toStop)
                    _listeners.Remove(listener.Info.Name);
            }

            foreach (Listener listener in toStop)
                StopListener(listener);

            foreach (DhcpInterfaceInfo info in wanted.Values)
            {
                List<string> addresses = new List<string>();
                foreach (DhcpInterfaceAddress address in info.Addresses)
                    addresses.Add(address.Address + "/" + address.PrefixLength);

                lock (_lock)
                {
                    if (_listeners.ContainsKey(info.Name))
                    {
                        status.Add(new DhcpListenerStatus() { Interface = info.Name, Addresses = addresses, Listening = true });
                        continue;
                    }
                }

                try
                {
                    Socket socket = CreateBoundSocket(info.Name, SERVER_PORT);
                    Listener listener = new Listener() { Socket = socket, Info = info, Cancellation = new CancellationTokenSource() };

                    lock (_lock)
                    {
                        _listeners[info.Name] = listener;
                    }

                    listener.ReceiveTask = Task.Run(delegate () { return ReceiveLoopAsync(listener); });
                    status.Add(new DhcpListenerStatus() { Interface = info.Name, Addresses = addresses, Listening = true });
                    _logMessage("DHCP Server is listening on " + info.Name + " (" + string.Join(", ", addresses) + ").");
                }
                catch (Exception ex)
                {
                    status.Add(new DhcpListenerStatus() { Interface = info.Name, Addresses = addresses, Listening = false, Error = ex.Message });
                    _logError("DHCP Server failed to listen on " + info.Name + " port 67", ex);
                }
            }

            if (enabled && (config.Interfaces.Count > 0))
            {
                foreach (string name in config.Interfaces)
                {
                    if (name.EndsWith('*'))
                        continue;

                    if (!wanted.ContainsKey(name))
                        status.Add(new DhcpListenerStatus() { Interface = name, Addresses = [], Listening = false, Error = "interface not found, down or without IPv4 address" });
                }
            }

            lock (_lock)
            {
                _listenerStatus.Clear();
                _listenerStatus.AddRange(status);
            }

            List<Dhcp6InterfaceInfo> interfaces6 = Dhcp6Utilities.GetInterfaces();
            HashSet<UInt128> localAddresses6 = new HashSet<UInt128>();

            foreach (Dhcp6InterfaceInfo info in interfaces6)
            {
                foreach (Dhcp6InterfaceAddress address in info.Addresses)
                    localAddresses6.Add(Dhcp6Utilities.ToUInt128(address.Address));
            }

            _localAddresses6 = localAddresses6;

            RefreshListeners6(config, enabled, interfaces6);
            _ra.Update(config, enabled, interfaces6, DEFAULT_LEASE_TIME);
        }

        private void StopListeners6()
        {
            List<Listener6> listeners;

            lock (_lock)
            {
                listeners = new List<Listener6>(_listeners6.Values);
                _listeners6.Clear();
            }

            foreach (Listener6 listener in listeners)
                StopListener6(listener);
        }

        private static void StopListener6(Listener6 listener)
        {
            try
            {
                listener.Cancellation.Cancel();
            }
            catch
            { }

            try
            {
                listener.Socket.Dispose();
            }
            catch
            { }
        }

        private static Socket CreateBoundSocket6(Dhcp6InterfaceInfo info)
        {
            Socket socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Dgram, ProtocolType.Udp);

            try
            {
                socket.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);

                if (OperatingSystem.IsLinux())
                {
                    byte[] name = Encoding.ASCII.GetBytes(info.Name + "\0");
                    socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, name);
                }

                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.PacketInformation, true);
                socket.Bind(new IPEndPoint(IPAddress.IPv6Any, Dhcp6Message.SERVER_PORT));
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.AddMembership, new IPv6MulticastOption(Dhcp6Message.AllServersAndRelays, info.Index));
                socket.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastInterface, info.Index);
                return socket;
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        private void RefreshListeners6(DhcpConfiguration config, bool enabled, List<Dhcp6InterfaceInfo> interfaces)
        {
            Dictionary<string, Dhcp6InterfaceInfo> wanted = new Dictionary<string, Dhcp6InterfaceInfo>(StringComparer.Ordinal);
            List<DhcpListenerStatus> status = new List<DhcpListenerStatus>();
            bool relayRanges = false;

            foreach (Dhcp6RangeRule rule in config.Ranges6)
            {
                if ((rule.Constructor is null) && rule.OffersDhcp)
                    relayRanges = true;
            }

            if (enabled && (config.Ranges6.Count > 0))
            {
                foreach (Dhcp6InterfaceInfo info in interfaces)
                {
                    if (!config.IsInterfaceAllowed(info.Name) || (info.LinkLocal is null) || (info.Index <= 0))
                        continue;

                    bool serves = relayRanges;

                    foreach (Dhcp6RangeCandidate candidate in Dhcp6RangeCandidate.GetForInterface(config, info))
                    {
                        if (candidate.Rule.OffersDhcp)
                        {
                            serves = true;
                            break;
                        }
                    }

                    if (serves)
                        wanted[info.Name] = info;
                }

                foreach (Dhcp6RangeRule rule in config.Ranges6)
                {
                    if ((rule.Constructor is null) || rule.Constructor.EndsWith('*'))
                        continue;

                    Dhcp6InterfaceInfo found = null;

                    foreach (Dhcp6InterfaceInfo info in interfaces)
                    {
                        if (info.Name == rule.Constructor)
                        {
                            found = info;
                            break;
                        }
                    }

                    string error = null;

                    if (found is null)
                        error = "interface not found, down or without IPv6";
                    else if (!config.IsInterfaceAllowed(found.Name))
                        error = "the interface is excluded by interface= or except-interface=";
                    else if (found.GetPrefixAddresses(rule.PrefixLength).Count == 0)
                        error = "no global or unique local IPv6 prefix (/" + rule.PrefixLength + " or shorter) on the interface";
                    else if (found.LinkLocal is null)
                        error = "no usable link-local address on the interface";

                    if (error is not null)
                        status.Add(new DhcpListenerStatus() { Interface = rule.Constructor, Addresses = [], Listening = false, Error = error });
                }
            }

            List<Listener6> toStop = new List<Listener6>();

            lock (_lock)
            {
                foreach (KeyValuePair<string, Listener6> entry in _listeners6)
                {
                    if (!wanted.TryGetValue(entry.Key, out Dhcp6InterfaceInfo info) || (info.Index != entry.Value.Info.Index))
                        toStop.Add(entry.Value);
                    else
                        entry.Value.Info = info;
                }

                foreach (Listener6 listener in toStop)
                    _listeners6.Remove(listener.Info.Name);
            }

            foreach (Listener6 listener in toStop)
                StopListener6(listener);

            foreach (Dhcp6InterfaceInfo info in wanted.Values)
            {
                List<string> addresses = new List<string>();
                foreach (Dhcp6InterfaceAddress address in info.Addresses)
                {
                    if (!address.IsTemporary)
                        addresses.Add(address.Address + "/" + address.PrefixLength);
                }

                lock (_lock)
                {
                    if (_listeners6.ContainsKey(info.Name))
                    {
                        status.Add(new DhcpListenerStatus() { Interface = info.Name, Addresses = addresses, Listening = true });
                        continue;
                    }
                }

                try
                {
                    Socket socket = CreateBoundSocket6(info);
                    Listener6 listener = new Listener6() { Socket = socket, Info = info, Cancellation = new CancellationTokenSource() };

                    lock (_lock)
                    {
                        _listeners6[info.Name] = listener;
                    }

                    _ = Task.Run(delegate () { return ReceiveLoop6Async(listener); });
                    status.Add(new DhcpListenerStatus() { Interface = info.Name, Addresses = addresses, Listening = true });
                    _logMessage("DHCPv6 Server is listening on " + info.Name + ".");
                }
                catch (Exception ex)
                {
                    status.Add(new DhcpListenerStatus() { Interface = info.Name, Addresses = addresses, Listening = false, Error = ex.Message });
                    _logError("DHCPv6 Server failed to listen on " + info.Name + " port 547", ex);
                }
            }

            lock (_lock)
            {
                _listener6Status.Clear();
                _listener6Status.AddRange(status);
            }
        }

        private async Task ReceiveLoop6Async(Listener6 listener)
        {
            byte[] buffer = new byte[4096];
            EndPoint any = new IPEndPoint(IPAddress.IPv6Any, 0);
            CancellationToken token = listener.Cancellation.Token;

            while (!token.IsCancellationRequested)
            {
                SocketReceiveMessageFromResult result;

                try
                {
                    result = await listener.Socket.ReceiveMessageFromAsync(buffer, SocketFlags.None, any, token);
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

                    if ((ex.SocketErrorCode == SocketError.ConnectionReset) || (ex.SocketErrorCode == SocketError.MessageSize))
                        continue;

                    _logError("DHCPv6 Server receive error on " + listener.Info.Name, ex);
                    await Task.Delay(1000, CancellationToken.None);
                    continue;
                }

                Interlocked.Increment(ref _received6);

                IPEndPoint remote = (IPEndPoint)result.RemoteEndPoint;

                if (!Dhcp6Message.TryParse(buffer.AsSpan(0, result.ReceivedBytes), out Dhcp6Message request, out _))
                {
                    Interlocked.Increment(ref _malformed6);
                    continue;
                }

                string key = "6|" + remote.Address;
                long second = Environment.TickCount64 / 1000;
                (long Second, int Count) counter = _packetCounts.AddOrUpdate(key, (second, 1), delegate (string k, (long Second, int Count) value) { return value.Second == second ? (second, value.Count + 1) : (second, 1); });
                if (counter.Count > MAX_PACKETS_PER_CLIENT_PER_SECOND)
                {
                    Interlocked.Increment(ref _droppedRateLimited);
                    continue;
                }

                if (!_concurrency.Wait(0))
                {
                    Interlocked.Increment(ref _droppedBusy);
                    continue;
                }

                IPAddress destination = result.PacketInformation.Address;
                bool multicast = (destination is null) || destination.IsIPv6Multicast;
                Dhcp6InterfaceInfo info = listener.Info;

                _ = Task.Run(async delegate ()
                {
                    try
                    {
                        Dhcp6Reply reply = _engine6.Process(request, info, remote.Address, multicast);

                        if (reply is not null)
                        {
                            if (reply.DelayMs > 0)
                                await Task.Delay(reply.DelayMs);

                            int port = reply.ToRelay ? Dhcp6Message.SERVER_PORT : Dhcp6Message.CLIENT_PORT;
                            listener.Socket.SendTo(reply.Message.Serialize(), new IPEndPoint(remote.Address, port));
                            Interlocked.Increment(ref _sent6);
                        }
                    }
                    catch (ObjectDisposedException)
                    { }
                    catch (Exception ex)
                    {
                        _logError("DHCPv6 Server failed to process a request from " + remote.Address, ex);
                    }
                    finally
                    {
                        _concurrency.Release();
                    }
                });
            }
        }

        private async Task ReceiveLoopAsync(Listener listener)
        {
            byte[] buffer = new byte[4096];
            EndPoint any = new IPEndPoint(IPAddress.Any, 0);
            CancellationToken token = listener.Cancellation.Token;

            while (!token.IsCancellationRequested)
            {
                SocketReceiveFromResult result;

                try
                {
                    result = await listener.Socket.ReceiveFromAsync(buffer, SocketFlags.None, any, token);
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

                    if ((ex.SocketErrorCode == SocketError.ConnectionReset) || (ex.SocketErrorCode == SocketError.MessageSize))
                        continue;

                    _logError("DHCP Server receive error on " + listener.Info.Name, ex);
                    await Task.Delay(1000, CancellationToken.None);
                    continue;
                }

                Interlocked.Increment(ref _received);

                if (!DhcpMessage.TryParse(buffer.AsSpan(0, result.ReceivedBytes), out DhcpMessage request, out _))
                {
                    Interlocked.Increment(ref _malformed);
                    continue;
                }

                if (request.Op != DhcpMessage.OP_BOOTREQUEST)
                    continue;

                string hwaddr = request.GetClientHardwareAddressString();

                lock (_probeHardwareAddresses)
                {
                    if (_probeHardwareAddresses.Contains(hwaddr))
                        continue;
                }

                long second = Environment.TickCount64 / 1000;
                (long Second, int Count) counter = _packetCounts.AddOrUpdate(hwaddr, (second, 1), delegate (string key, (long Second, int Count) value) { return value.Second == second ? (second, value.Count + 1) : (second, 1); });
                if (counter.Count > MAX_PACKETS_PER_CLIENT_PER_SECOND)
                {
                    Interlocked.Increment(ref _droppedRateLimited);
                    continue;
                }

                if (!_concurrency.Wait(0))
                {
                    Interlocked.Increment(ref _droppedBusy);
                    continue;
                }

                DhcpInterfaceInfo info = listener.Info;

                _ = Task.Run(async delegate ()
                {
                    try
                    {
                        DhcpReply reply = await _engine.ProcessAsync(request, info);

                        if (reply is not null)
                        {
                            if (reply.DelayMs > 0)
                                await Task.Delay(reply.DelayMs);

                            Send(listener, reply);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logError("DHCP Server failed to process a request from " + hwaddr, ex);
                    }
                    finally
                    {
                        _concurrency.Release();
                    }
                });
            }
        }

        private void Send(Listener listener, DhcpReply reply)
        {
            DhcpMessage message = reply.Message;
            byte[] data = message.Serialize(reply.MaxMessageSize);

            try
            {
                switch (reply.Mode)
                {
                    case DhcpReplyMode.Unicast:
                        listener.Socket.SendTo(data, reply.Destination);
                        break;

                    case DhcpReplyMode.HardwareUnicast:
                        {
                            DhcpRawSender raw = _rawSender;
                            IPAddress source = reply.SourceAddress ?? IPAddress.Any;

                            if ((raw is not null) && !source.Equals(IPAddress.Any) && (listener.Info.Index > 0) && raw.Send(listener.Info.Index, message.ClientHardwareAddress, source, reply.Destination.Address, SERVER_PORT, CLIENT_PORT, data))
                                break;

                            listener.Socket.SendTo(data, new IPEndPoint(IPAddress.Broadcast, CLIENT_PORT));
                        }
                        break;

                    default:
                        listener.Socket.SendTo(data, new IPEndPoint(IPAddress.Broadcast, CLIENT_PORT));
                        break;
                }

                Interlocked.Increment(ref _sent);
            }
            catch (ObjectDisposedException)
            { }
            catch (Exception ex)
            {
                _logError("DHCP Server failed to send a reply on " + listener.Info.Name, ex);
            }
        }

        #endregion

        #region ping

        private static async Task<bool> PingAsync(IPAddress address, int timeoutMs)
        {
            using (Ping ping = new Ping())
            {
                try
                {
                    PingReply reply = await ping.SendPingAsync(address, timeoutMs);
                    return reply.Status == IPStatus.Success;
                }
                catch (PingException)
                {
                    return false;
                }
            }
        }

        #endregion

        #region foreign servers

        private void RecordForeignServer(IPAddress address, string iface, string source, IPAddress offered)
        {
            if ((address is null) || address.Equals(IPAddress.Any) || IsLocalAddress(address))
                return;

            DateTime now = DateTime.UtcNow;
            string key = iface + "|" + address;
            bool added = false;

            DhcpForeignServer server = _foreignServers.GetOrAdd(key, delegate (string k)
            {
                added = true;
                return new DhcpForeignServer() { Address = address, Interface = iface, FirstSeen = now, LastSeen = now, Source = source, OfferedAddress = offered, Count = 0 };
            });

            lock (server)
            {
                server.LastSeen = now;
                server.Count++;

                if (source == "probe")
                    server.Source = "probe";

                if (offered is not null)
                    server.OfferedAddress = offered;
            }

            if (added)
                _logMessage("DHCP Server detected another DHCP server " + address + " on " + iface + " (" + source + ").");

            if (added)
                ApplyEngineSettings();
        }

        private void RecordForeignServer6(byte[] serverDuid, string iface)
        {
            if ((serverDuid is null) || (serverDuid.Length == 0) || (serverDuid.Length > 130))
                return;

            DateTime now = DateTime.UtcNow;
            string serverId = DhcpUtilities.FormatHex(serverDuid);
            string key = iface + "|" + serverId;
            bool added = false;

            if (!_foreignServers6.ContainsKey(key) && (_foreignServers6.Count >= 64))
                return;

            DhcpForeignServer server = _foreignServers6.GetOrAdd(key, delegate (string k)
            {
                added = true;
                return new DhcpForeignServer() { ServerId = serverId, Interface = iface, FirstSeen = now, LastSeen = now, Source = "request", Count = 0 };
            });

            lock (server)
            {
                server.LastSeen = now;
                server.Count++;
            }

            if (added)
            {
                _logMessage("DHCPv6 Server detected another DHCPv6 server with DUID " + serverId + " on " + iface + " (a client addressed it).");
                ApplyEngineSettings();
            }
        }

        private static byte[] GetDuidFromClientId(byte[] clientId)
        {
            if ((clientId is null) || (clientId.Length < 7) || (clientId[0] != 0xFF))
                return null;

            return clientId.AsSpan(5).ToArray();
        }

        private static byte[] GetMacFromLinkLocal(IPAddress address)
        {
            if ((address is null) || !address.IsIPv6LinkLocal)
                return null;

            byte[] bytes = address.GetAddressBytes();

            if ((bytes[11] != 0xFF) || (bytes[12] != 0xFE))
                return null;

            return [(byte)(bytes[8] ^ 0x02), bytes[9], bytes[10], bytes[13], bytes[14], bytes[15]];
        }

        private byte[] ResolveDhcp6ClientMac(byte[] duid, IPAddress source)
        {
            Dictionary<string, byte[]> duidToMac;

            lock (_dnsLock)
            {
                duidToMac = _duidToMac;
            }

            if ((duid is not null) && duidToMac.TryGetValue(Convert.ToHexString(duid), out byte[] mac))
                return mac;

            if (source is null)
                return null;

            mac = GetMacFromLinkLocal(source);
            if (mac is not null)
                return mac;

            if (_neighbors.TryGetHardwareAddress(source, out mac))
                return mac;

            return null;
        }

        private static byte[] CreateServerDuid(string nodeId)
        {
            byte[] duid = new byte[18];
            duid[1] = 4;

            if (Guid.TryParseExact(nodeId ?? "", "N", out Guid guid))
                guid.TryWriteBytes(duid.AsSpan(2), true, out _);
            else
                Random.Shared.NextBytes(duid.AsSpan(2));

            return duid;
        }

        private string FindHostNameByMac(byte[] hardwareAddress)
        {
            DateTime now = DateTime.UtcNow;
            DhcpLease best = null;

            foreach (DhcpLease lease in _store.GetAll())
            {
                if ((lease.HostName is null) || (lease.State != DhcpLeaseState.Bound) || !lease.IsActive(now))
                    continue;

                if (!lease.HardwareAddress.AsSpan().SequenceEqual(hardwareAddress))
                    continue;

                if ((best is null) || (lease.Updated > best.Updated))
                    best = lease;
            }

            if (best is not null)
                return best.HostName;

            DhcpConfiguration config = _config;

            foreach (DhcpHostRule host in config.Hosts)
            {
                if (host.HostName is null)
                    continue;

                foreach (DhcpHardwarePattern pattern in host.HardwareAddresses)
                {
                    if (!pattern.HasWildcard && pattern.Matches(1, hardwareAddress))
                        return host.HostName;
                }
            }

            return null;
        }

        private byte[] GetProbeHardwareAddress(DhcpInterfaceInfo info)
        {
            uint hash = DhcpUtilities.GetStableHash(_nodeId + "|" + info.Name);
            return [0x02, 0x5A, (byte)(hash >> 24), (byte)(hash >> 16), (byte)(hash >> 8), (byte)hash];
        }

        public async Task ProbeAsync()
        {
            if (Interlocked.Exchange(ref _probing, 1) == 1)
                return;

            try
            {
                List<DhcpInterfaceInfo> interfaces = new List<DhcpInterfaceInfo>();

                lock (_lock)
                {
                    foreach (Listener listener in _listeners.Values)
                        interfaces.Add(listener.Info);
                }

                if (interfaces.Count == 0)
                    interfaces.AddRange(GetInterfaces());

                _lastProbe = DateTime.UtcNow;
                List<string> errors = new List<string>();
                List<Task> tasks = new List<Task>();

                if (interfaces.Count == 0)
                    errors.Add("no network interface with an IPv4 address");

                foreach (DhcpInterfaceInfo info in interfaces)
                    tasks.Add(ProbeInterfaceAsync(info, errors));

                await Task.WhenAll(tasks);

                _lastProbeError = errors.Count > 0 ? string.Join("; ", errors) : null;
                _lastProbeCompleted = DateTime.UtcNow;
                ApplyEngineSettings();
            }
            finally
            {
                Interlocked.Exchange(ref _probing, 0);
            }
        }

        private async Task ProbeInterfaceAsync(DhcpInterfaceInfo info, List<string> errors)
        {
            byte[] hwaddr = GetProbeHardwareAddress(info);
            string hwaddrText = DhcpUtilities.FormatHardwareAddress(hwaddr);

            lock (_probeHardwareAddresses)
            {
                _probeHardwareAddresses.Add(hwaddrText);
            }

            Socket socket;

            try
            {
                socket = CreateBoundSocket(info.Name, CLIENT_PORT);
            }
            catch (Exception ex)
            {
                lock (errors)
                {
                    errors.Add(info.Name + ": " + ex.Message);
                }

                return;
            }

            using (socket)
            {
                uint xid = (uint)Random.Shared.Next();

                DhcpMessage discover = new DhcpMessage()
                {
                    Op = DhcpMessage.OP_BOOTREQUEST,
                    HardwareType = 1,
                    HardwareAddressLength = 6,
                    TransactionId = xid,
                    Flags = DhcpMessage.FLAG_BROADCAST,
                    ClientHardwareAddress = hwaddr
                };

                discover.SetOption(DhcpOptionCode.MessageType, [(byte)DhcpMessageType.Discover]);
                discover.SetOption(DhcpOptionCode.ClientIdentifier, [1, .. hwaddr]);
                discover.SetOption(DhcpOptionCode.VendorClassIdentifier, Encoding.ASCII.GetBytes("ZenitiumDNS-probe"));
                discover.SetOption(DhcpOptionCode.ParameterRequestList, [1, 3, 6, 54]);

                try
                {
                    socket.SendTo(discover.Serialize(), new IPEndPoint(IPAddress.Broadcast, SERVER_PORT));
                }
                catch (Exception ex)
                {
                    lock (errors)
                    {
                        errors.Add(info.Name + ": " + ex.Message);
                    }

                    return;
                }

                byte[] buffer = new byte[4096];
                EndPoint any = new IPEndPoint(IPAddress.Any, 0);

                using (CancellationTokenSource cts = new CancellationTokenSource(PROBE_WAIT_MS))
                {
                    while (!cts.IsCancellationRequested)
                    {
                        SocketReceiveFromResult result;

                        try
                        {
                            result = await socket.ReceiveFromAsync(buffer, SocketFlags.None, any, cts.Token);
                        }
                        catch (OperationCanceledException)
                        {
                            break;
                        }
                        catch (SocketException)
                        {
                            break;
                        }

                        if (!DhcpMessage.TryParse(buffer.AsSpan(0, result.ReceivedBytes), out DhcpMessage offer, out _))
                            continue;

                        if ((offer.Op != DhcpMessage.OP_BOOTREPLY) || (offer.TransactionId != xid) || (offer.MessageType != DhcpMessageType.Offer))
                            continue;

                        IPAddress serverId = offer.GetAddressOption(DhcpOptionCode.ServerIdentifier) ?? ((IPEndPoint)result.RemoteEndPoint).Address;

                        RecordForeignServer(serverId, info.Name, "probe", offer.YourAddress);
                    }
                }
            }
        }

        #endregion

        #region dns

        private void ScheduleDnsRebuild()
        {
            if (Interlocked.Exchange(ref _dnsRebuildPending, 1) == 0)
            {
                _ = Task.Run(async delegate ()
                {
                    await Task.Delay(200);
                    Interlocked.Exchange(ref _dnsRebuildPending, 0);
                    RebuildDnsIndex();
                });
            }
        }

        private string GetDomainFor(DhcpConfiguration config, IPAddress address)
        {
            foreach (DhcpDomainRule rule in config.Domains)
            {
                if ((rule.Start is not null) && (address is not null) && rule.Matches(address))
                    return rule.Domain;
            }

            foreach (DhcpDomainRule rule in config.Domains)
            {
                if (rule.Start is null)
                    return rule.Domain;
            }

            return null;
        }

        private static void AddDnsName(Dictionary<string, DnsEntry> names, string fqdn, IPAddress address, DateTime updated)
        {
            if (!names.TryGetValue(fqdn, out DnsEntry entry))
            {
                entry = new DnsEntry();
                names.Add(fqdn, entry);
            }

            if (updated < entry.Updated4)
                return;

            entry.Addresses4.Clear();
            entry.Addresses4.Add(address);
            entry.Updated4 = updated;
        }

        private static void AddDnsName6(Dictionary<string, DnsEntry> names, string fqdn, IPAddress address, DateTime updated, string clientKey)
        {
            if (!names.TryGetValue(fqdn, out DnsEntry entry))
            {
                entry = new DnsEntry();
                names.Add(fqdn, entry);
            }

            if (entry.ClientKey6 == clientKey)
            {
                if (!entry.Addresses6.Contains(address) && (entry.Addresses6.Count < 8))
                    entry.Addresses6.Add(address);

                if (updated > entry.Updated6)
                    entry.Updated6 = updated;

                return;
            }

            if (updated < entry.Updated6)
                return;

            entry.Addresses6.Clear();
            entry.Addresses6.Add(address);
            entry.Updated6 = updated;
            entry.ClientKey6 = clientKey;
        }

        private void RebuildDnsIndex()
        {
            DhcpConfiguration config;
            bool register;

            lock (_lock)
            {
                config = _config;
                register = _settings.RegisterDns && _settings.Enabled;
            }

            Dictionary<string, DnsEntry> names = new Dictionary<string, DnsEntry>(StringComparer.OrdinalIgnoreCase);
            Dictionary<uint, string> reverse = new Dictionary<uint, string>();
            Dictionary<UInt128, string> reverse6 = new Dictionary<UInt128, string>();
            Dictionary<IPAddress, byte[]> addressToMac = new Dictionary<IPAddress, byte[]>();
            Dictionary<string, byte[]> duidToMac = new Dictionary<string, byte[]>(StringComparer.Ordinal);
            DateTime mapNow = DateTime.UtcNow;

            foreach (DhcpLease lease in _store.GetAll())
            {
                if ((lease.State != DhcpLeaseState.Bound) || !lease.IsActive(mapNow) || (lease.HardwareAddress.Length != 6))
                    continue;

                addressToMac[lease.Address] = lease.HardwareAddress;

                byte[] duid = GetDuidFromClientId(lease.ClientId);
                if (duid is not null)
                    duidToMac[Convert.ToHexString(duid)] = lease.HardwareAddress;
            }

            foreach (DhcpHostRule host in config.Hosts)
            {
                if (host.Address is null)
                    continue;

                foreach (DhcpHardwarePattern pattern in host.HardwareAddresses)
                {
                    byte[] mac = pattern.GetFixedAddress();

                    if ((mac is not null) && !addressToMac.ContainsKey(host.Address))
                        addressToMac[host.Address] = mac;
                }
            }

            foreach (Dhcp6Lease lease in _store6.GetAll())
            {
                if ((lease.State == DhcpLeaseState.Bound) && lease.IsActive(mapNow) && (lease.HardwareAddress.Length == 6))
                    addressToMac[lease.Address] = lease.HardwareAddress;
            }

            if (register)
            {
                DateTime now = DateTime.UtcNow;

                foreach (DhcpLease lease in _store.GetAll())
                {
                    if ((lease.State != DhcpLeaseState.Bound) || !lease.IsActive(now) || string.IsNullOrEmpty(lease.HostName))
                        continue;

                    string domain = GetDomainFor(config, lease.Address);
                    AddDnsName(names, domain is null ? lease.HostName : lease.HostName + "." + domain, lease.Address, lease.Updated);
                }

                foreach (DhcpHostRule host in config.Hosts)
                {
                    if ((host.Address is null) || (host.HostName is null) || host.Ignore)
                        continue;

                    string domain = GetDomainFor(config, host.Address);
                    AddDnsName(names, domain is null ? host.HostName : host.HostName + "." + domain, host.Address, DateTime.MaxValue);
                }

                string domain6 = GetDomainFor(config, null);

                foreach (Dhcp6Lease lease in _store6.GetAll())
                {
                    if ((lease.State != DhcpLeaseState.Bound) || !lease.IsActive(now) || string.IsNullOrEmpty(lease.HostName))
                        continue;

                    AddDnsName6(names, domain6 is null ? lease.HostName : lease.HostName + "." + domain6, lease.Address, lease.Reserved ? DateTime.MaxValue : lease.Updated, lease.ClientKey);
                }

                foreach (DhcpHostRule host in config.Hosts)
                {
                    if ((host.Address6 is null) || host.Address6IsSuffix || (host.HostName is null) || host.Ignore)
                        continue;

                    AddDnsName6(names, domain6 is null ? host.HostName : host.HostName + "." + domain6, host.Address6, DateTime.MaxValue, "host:" + host.Line);
                }

                foreach (KeyValuePair<string, DnsEntry> entry in names)
                {
                    foreach (IPAddress address in entry.Value.Addresses4)
                        reverse[DhcpUtilities.ToUInt32(address)] = entry.Key;

                    foreach (IPAddress address in entry.Value.Addresses6)
                        reverse6[Dhcp6Utilities.ToUInt128(address)] = entry.Key;
                }
            }

            lock (_dnsLock)
            {
                _dnsNames = names;
                _dnsReverse = reverse;
                _dnsReverse6 = reverse6;
                _addressToMac = addressToMac;
                _duidToMac = duidToMac;
            }
        }

        public bool TryResolveName(string name, out IReadOnlyList<IPAddress> addresses4, out IReadOnlyList<IPAddress> addresses6, out uint ttl)
        {
            addresses4 = [];
            addresses6 = [];
            ttl = _settings.DnsTtl;

            Dictionary<string, DnsEntry> names;

            lock (_dnsLock)
            {
                names = _dnsNames;
            }

            if (names.Count == 0)
                return false;

            if (names.TryGetValue(name.TrimEnd('.'), out DnsEntry entry))
            {
                addresses4 = entry.Addresses4;
                addresses6 = entry.Addresses6;
                return true;
            }

            return false;
        }

        public bool IsNameInLocalDomain(string name)
        {
            DhcpConfiguration config = _config;

            if (!_settings.Enabled || !_settings.RegisterDns)
                return false;

            name = name.TrimEnd('.');

            foreach (DhcpDomainRule rule in config.Domains)
            {
                if (!rule.Local)
                    continue;

                if (name.Equals(rule.Domain, StringComparison.OrdinalIgnoreCase) || name.EndsWith("." + rule.Domain, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        public bool TryResolveAddress(IPAddress address, out string name, out uint ttl)
        {
            name = null;
            ttl = _settings.DnsTtl;

            if (address is null)
                return false;

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                Dictionary<UInt128, string> reverse6;

                lock (_dnsLock)
                {
                    reverse6 = _dnsReverse6;
                }

                return reverse6.TryGetValue(Dhcp6Utilities.ToUInt128(address), out name);
            }

            if (address.AddressFamily != AddressFamily.InterNetwork)
                return false;

            Dictionary<uint, string> reverse;

            lock (_dnsLock)
            {
                reverse = _dnsReverse;
            }

            return reverse.TryGetValue(DhcpUtilities.ToUInt32(address), out name);
        }

        #endregion

        #region maintenance

        private void Maintenance(object state)
        {
            try
            {
                if (_disposed)
                    return;

                RefreshListeners();

                _store.Maintain(DateTime.UtcNow);
                _store6.Maintain(DateTime.UtcNow);
                _ra.Maintain();

                long currentSecond = Environment.TickCount64 / 1000;

                foreach (KeyValuePair<string, (long Second, int Count)> entry in _packetCounts)
                {
                    if (entry.Value.Second < currentSecond - 5)
                        _packetCounts.TryRemove(entry.Key, out _);
                }

                DateTime now = DateTime.UtcNow;

                foreach (KeyValuePair<string, DhcpForeignServer> entry in _foreignServers)
                {
                    if (entry.Value.LastSeen < now.AddHours(-24))
                        _foreignServers.TryRemove(entry.Key, out _);
                }

                foreach (KeyValuePair<string, DhcpForeignServer> entry in _foreignServers6)
                {
                    if (entry.Value.LastSeen < now.AddHours(-24))
                        _foreignServers6.TryRemove(entry.Key, out _);
                }

                DhcpSettings settings = _settings;

                if (settings.Enabled && settings.RogueDetection && (_listeners.Count > 0) && (now >= _lastProbe.AddSeconds(settings.RogueProbeIntervalSeconds)))
                    _ = ProbeAsync();

                ApplyEngineSettings();
                RebuildDnsIndex();
            }
            catch (Exception ex)
            {
                _logError("DHCP Server maintenance failed", ex);
            }
        }

        private bool HasRecentForeignServer()
        {
            return HasRecentForeignServer(_foreignServers);
        }

        private bool HasRecentForeignServer(ConcurrentDictionary<string, DhcpForeignServer> servers)
        {
            DateTime limit = DateTime.UtcNow.AddSeconds(-Math.Max(900, _settings.RogueProbeIntervalSeconds * 3));

            foreach (DhcpForeignServer server in servers.Values)
            {
                if (server.LastSeen >= limit)
                    return true;
            }

            return false;
        }

        private bool IsLocalAddress6(UInt128 address)
        {
            HashSet<UInt128> local = _localAddresses6;
            return local.Contains(address);
        }

        private void ApplyEngineSettings()
        {
            DhcpSettings settings;
            DhcpConfiguration config;

            lock (_lock)
            {
                settings = _settings;
                config = _config;
            }

            bool serving = settings.Enabled && (_configErrors.Count == 0);
            bool paused = (settings.Priority == DhcpPriorityMode.Standby) && HasRecentForeignServer();

            _engine.Configure(config, new DhcpEngineSettings()
            {
                Serving = serving,
                PingCheck = settings.PingCheck,
                PingTimeoutMs = settings.PingTimeoutMs,
                ResponseDelayMs = settings.Priority == DhcpPriorityMode.Delayed ? settings.ResponseDelayMs : 0,
                MinSecs = settings.Priority == DhcpPriorityMode.Delayed ? settings.MinSecs : 0,
                OffersPaused = paused,
                DefaultLeaseTime = DEFAULT_LEASE_TIME
            }, IsLocalAddress);

            _engine6.Configure(config, new Dhcp6EngineSettings()
            {
                Serving = serving,
                OffersPaused = (settings.Priority == DhcpPriorityMode.Standby) && HasRecentForeignServer(_foreignServers6),
                ResponseDelayMs = settings.Priority == DhcpPriorityMode.Delayed ? settings.ResponseDelayMs : 0,
                PreferMe = config.Authoritative && (settings.Priority == DhcpPriorityMode.Primary),
                RegisterDns = settings.RegisterDns,
                DefaultLeaseTime = DEFAULT_LEASE_TIME
            }, _serverDuid, FindHostNameByMac, IsLocalAddress6, ResolveDhcp6ClientMac);
        }

        #endregion

        #region public

        public static string LoadOrCreateNodeId(string configFolder)
        {
            string file = Path.Combine(configFolder, "dhcp-node.id");

            try
            {
                if (File.Exists(file))
                {
                    string id = File.ReadAllText(file).Trim();

                    if (Guid.TryParseExact(id, "N", out _))
                        return id;
                }
            }
            catch
            { }

            string newId = Guid.NewGuid().ToString("N");
            File.WriteAllText(file, newId);
            return newId;
        }

        public void LoadSettings()
        {
            string file = Path.Combine(_configFolder, SETTINGS_FILE);
            DhcpSettings settings = new DhcpSettings();

            if (File.Exists(file))
            {
                try
                {
                    using (JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(file)))
                    {
                        settings = DhcpSettings.ReadFrom(document.RootElement);
                    }
                }
                catch (Exception ex)
                {
                    _logError("DHCP Server failed to load " + file, ex);

                    try
                    {
                        File.Copy(file, file + ".invalid", true);
                    }
                    catch
                    { }
                }
            }

            _store.Load();
            _store6.Load();
            Apply(settings, false);
        }

        public List<DhcpConfigError> Apply(DhcpSettings settings, bool save)
        {
            List<DhcpConfigError> errors = settings.Validate(out DhcpConfiguration configuration);

            if (save && (errors.Count > 0))
                return errors;

            lock (_lock)
            {
                _settings = settings;
                _config = errors.Count == 0 ? configuration : DhcpConfiguration.Empty;
                _configErrors = errors;
            }

            if (errors.Count > 0)
            {
                foreach (DhcpConfigError error in errors)
                    _logMessage("DHCP Server configuration error: " + error);
            }

            if (save)
            {
                string file = Path.Combine(_configFolder, SETTINGS_FILE);
                string tmpFile = file + ".tmp";

                File.WriteAllBytes(tmpFile, settings.ToJson());
                File.Move(tmpFile, file, true);
            }

            ApplyEngineSettings();
            RefreshListeners();
            RebuildDnsIndex();

            return errors;
        }

        public void Start()
        {
            lock (_lock)
            {
                if (_started)
                    return;

                _started = true;
            }

            _rawSender = DhcpRawSender.TryCreate(out _rawSenderError);

            RefreshListeners();
            ApplyEngineSettings();
            RebuildDnsIndex();

            _maintenanceTimer = new Timer(Maintenance, null, MAINTENANCE_INTERVAL_MS, MAINTENANCE_INTERVAL_MS);

            if (_settings.Enabled && _settings.RogueDetection)
            {
                _ = Task.Run(async delegate ()
                {
                    await Task.Delay(5000);
                    await ProbeAsync();
                });
            }
        }

        public byte[] ExportSettings()
        {
            return _settings.ToJson();
        }

        public byte[] ExportLeases()
        {
            return _store.ExportSnapshot();
        }

        public byte[] ExportLeases6()
        {
            return _store6.ExportSnapshot();
        }

        public int RestoreLeases6(byte[] data)
        {
            List<Dhcp6Lease> leases = Dhcp6LeaseStore.ParseSnapshot(data);

            _store6.ReplaceAll(leases);
            _store6.SaveNow();
            RebuildDnsIndex();

            return leases.Count;
        }

        public List<DhcpConfigError> RestoreSettings(byte[] data)
        {
            DhcpSettings settings;

            using (JsonDocument document = JsonDocument.Parse(data))
            {
                settings = DhcpSettings.ReadFrom(document.RootElement);
            }

            return Apply(settings, true);
        }

        public int RestoreLeases(byte[] data)
        {
            List<DhcpLease> leases = DhcpLeaseStore.ParseSnapshot(data, out long sequence, out _);

            _store.ReplaceAll(leases, sequence, _store.Term);
            _store.SaveNow();
            RebuildDnsIndex();

            return leases.Count;
        }

        public bool DeleteLease(IPAddress address)
        {
            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                return _store6.Remove(address);

            DhcpLease lease = _store.Get(address);
            if (lease is null)
                return false;

            _store.Put(lease.With(DhcpLeaseState.Free, lease.Expires, DateTime.UtcNow));
            return true;
        }

        public void ClearForeignServers()
        {
            _foreignServers.Clear();
            _foreignServers6.Clear();
            _ra.ClearForeignRouters();
            ApplyEngineSettings();
        }

        public bool TryGetHardwareAddress(IPAddress address, out byte[] hardwareAddress)
        {
            hardwareAddress = null;

            if (address is null)
                return false;

            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            Dictionary<IPAddress, byte[]> map;

            lock (_dnsLock)
            {
                map = _addressToMac;
            }

            IPAddress key = (address.AddressFamily == AddressFamily.InterNetworkV6) && (address.ScopeId != 0) ? new IPAddress(address.GetAddressBytes()) : address;

            if (map.TryGetValue(key, out hardwareAddress))
                return true;

            return _neighbors.TryGetHardwareAddress(address, out hardwareAddress);
        }

        public List<DhcpDevice> GetDevices()
        {
            Dictionary<string, DhcpDevice> devices = new Dictionary<string, DhcpDevice>(StringComparer.Ordinal);
            DateTime now = DateTime.UtcNow;
            DhcpConfiguration config = _config;

            DhcpDevice Get(string key)
            {
                if (!devices.TryGetValue(key, out DhcpDevice device))
                {
                    device = new DhcpDevice();

                    if (!key.StartsWith("duid:", StringComparison.Ordinal))
                        device.HardwareAddress = key;

                    devices.Add(key, device);
                }

                return device;
            }

            foreach (DhcpLease lease in _store.GetAll())
            {
                if ((lease.HardwareAddress.Length != 6) || !(lease.IsActive(now) || lease.Reserved))
                    continue;

                if (lease.State == DhcpLeaseState.Declined)
                    continue;

                DhcpDevice device = Get(DhcpUtilities.FormatHardwareAddress(lease.HardwareAddress));
                device.Addresses4.Add(lease.Address.ToString());
                device.Sources.Add("dhcp");
                device.HostName ??= lease.HostName;

                if ((lease.ClientId is not null) && (lease.ClientId.Length > 0))
                {
                    device.ClientId = DhcpUtilities.FormatHex(lease.ClientId);

                    byte[] duid = GetDuidFromClientId(lease.ClientId);
                    if (duid is not null)
                        device.Duids.Add(DhcpUtilities.FormatHex(duid));
                }

                if (lease.Updated > device.LastSeen)
                    device.LastSeen = lease.Updated;
            }

            foreach (Dhcp6Lease lease in _store6.GetAll())
            {
                if ((lease.State != DhcpLeaseState.Bound) || !lease.IsActive(now))
                    continue;

                string key = lease.HardwareAddress.Length == 6 ? DhcpUtilities.FormatHardwareAddress(lease.HardwareAddress) : "duid:" + DhcpUtilities.FormatHex(lease.Duid);
                DhcpDevice device = Get(key);
                device.Addresses6.Add(lease.Address.ToString());
                device.Duids.Add(DhcpUtilities.FormatHex(lease.Duid));
                device.Sources.Add("dhcpv6");
                device.HostName ??= lease.HostName;

                if (lease.Updated > device.LastSeen)
                    device.LastSeen = lease.Updated;
            }

            foreach (DhcpHostRule host in config.Hosts)
            {
                if (host.Ignore)
                    continue;

                foreach (DhcpHardwarePattern pattern in host.HardwareAddresses)
                {
                    byte[] mac = pattern.GetFixedAddress();

                    if (mac is null)
                        continue;

                    DhcpDevice device = Get(DhcpUtilities.FormatHardwareAddress(mac));
                    device.Reserved = true;
                    device.Sources.Add("reservation");

                    if (host.HostName is not null)
                        device.HostName = host.HostName;

                    if (host.Address is not null)
                        device.Addresses4.Add(host.Address.ToString());
                }
            }

            foreach (NeighborEntry entry in _neighbors.GetEntries())
            {
                if (entry.Address.IsIPv6LinkLocal || entry.Address.IsIPv6Multicast || ((entry.HardwareAddress[0] & 0x01) != 0))
                    continue;

                DhcpDevice device = Get(DhcpUtilities.FormatHardwareAddress(entry.HardwareAddress));
                device.Sources.Add("neighbor");

                if (entry.Address.AddressFamily == AddressFamily.InterNetwork)
                    device.Addresses4.Add(entry.Address.ToString());
                else
                    device.Addresses6.Add(entry.Address.ToString());
            }

            foreach (DhcpDevice device in devices.Values)
            {
                if (device.HostName is not null)
                    continue;

                foreach (string text in device.Addresses4)
                {
                    if (TryResolveAddress(IPAddress.Parse(text), out string name, out _))
                    {
                        device.HostName = name;
                        break;
                    }
                }
            }

            return new List<DhcpDevice>(devices.Values);
        }

        public IReadOnlyDictionary<string, long> GetCounters6()
        {
            Dictionary<string, long> counters = new Dictionary<string, long>(_engine6.GetCounters())
            {
                { "received", Interlocked.Read(ref _received6) },
                { "sent", Interlocked.Read(ref _sent6) },
                { "malformed", Interlocked.Read(ref _malformed6) },
                { "raSent", _ra.Sent },
                { "routerSolicitations", _ra.Solicitations }
            };

            return counters;
        }

        public List<DhcpForeignServer> GetForeignServers6()
        {
            return new List<DhcpForeignServer>(_foreignServers6.Values);
        }

        public List<DhcpListenerStatus> GetListener6Status()
        {
            lock (_lock)
            {
                return new List<DhcpListenerStatus>(_listener6Status);
            }
        }

        public List<RaInterfaceStatus> GetRaStatus()
        {
            return _ra.GetStatus();
        }

        public List<RaForeignRouter> GetForeignRouters()
        {
            return _ra.GetForeignRouters();
        }

        public (UInt128 Total, int Used) GetPoolUsage6()
        {
            DhcpConfiguration config = _config;
            DateTime now = DateTime.UtcNow;
            UInt128 total = UInt128.Zero;
            int used = 0;
            List<Dhcp6RangeCandidate> candidates = new List<Dhcp6RangeCandidate>();

            foreach (Dhcp6InterfaceInfo info in Dhcp6Utilities.GetInterfaces())
            {
                if (config.IsInterfaceAllowed(info.Name))
                    candidates.AddRange(Dhcp6RangeCandidate.GetForInterface(config, info));
            }

            foreach (Dhcp6RangeCandidate candidate in candidates)
            {
                if (candidate.Rule.AssignsAddresses)
                {
                    UInt128 size = candidate.Last - candidate.First + UInt128.One;
                    total = total > UInt128.MaxValue - size ? UInt128.MaxValue : total + size;
                }
            }

            foreach (Dhcp6Lease lease in _store6.GetAll())
            {
                if ((lease.State == DhcpLeaseState.Bound) && lease.IsActive(now))
                    used++;
            }

            return (total, used);
        }

        public IReadOnlyDictionary<string, long> GetCounters()
        {
            Dictionary<string, long> counters = new Dictionary<string, long>(_engine.GetCounters())
            {
                { "received", Interlocked.Read(ref _received) },
                { "sent", Interlocked.Read(ref _sent) },
                { "malformed", Interlocked.Read(ref _malformed) },
                { "rateLimited", Interlocked.Read(ref _droppedRateLimited) },
                { "busy", Interlocked.Read(ref _droppedBusy) }
            };

            return counters;
        }

        public List<DhcpForeignServer> GetForeignServers()
        {
            return new List<DhcpForeignServer>(_foreignServers.Values);
        }

        public List<DhcpListenerStatus> GetListenerStatus()
        {
            lock (_lock)
            {
                return new List<DhcpListenerStatus>(_listenerStatus);
            }
        }

        public (int Total, int Used) GetPoolUsage()
        {
            DhcpConfiguration config = _config;
            DateTime now = DateTime.UtcNow;
            int total = 0;
            int used = 0;

            foreach (DhcpRangeRule range in config.Ranges)
            {
                if (range.StaticOnly)
                    continue;

                total += (int)(range.EndValue - range.StartValue + 1);
            }

            foreach (DhcpLease lease in _store.GetAll())
            {
                if (!lease.IsActive(now) && !((lease.State == DhcpLeaseState.Declined) && (lease.Expires > now)))
                    continue;

                foreach (DhcpRangeRule range in config.Ranges)
                {
                    if (range.ContainsInPool(lease.Address))
                    {
                        used++;
                        break;
                    }
                }
            }

            return (total, used);
        }

        #endregion

        #region properties

        public DhcpSettings Settings
        { get { return _settings; } }

        public DhcpConfiguration Configuration
        { get { return _config; } }

        public IReadOnlyList<DhcpConfigError> ConfigErrors
        { get { return _configErrors; } }

        public DhcpLeaseStore LeaseStore
        { get { return _store; } }

        public Dhcp6LeaseStore LeaseStore6
        { get { return _store6; } }

        public byte[] ServerDuid
        { get { return _serverDuid; } }

        public bool IsServing
        { get { return _engine.Settings.Serving; } }

        public bool OffersPaused
        { get { return _engine.Settings.OffersPaused; } }

        public string RawSenderError
        { get { return _rawSenderError; } }

        public DateTime LastProbe
        { get { return _lastProbeCompleted; } }

        public string LastProbeError
        { get { return _lastProbeError; } }

        #endregion
    }
}
