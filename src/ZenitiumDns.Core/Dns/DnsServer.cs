/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)
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

using ZenitiumDns.ApplicationCommon;
using ZenitiumDns.Core.Dns.Applications;
using ZenitiumDns.Core.Dns.ResourceRecords;
using ZenitiumDns.Core.Dns.Trees;
using ZenitiumDns.Core.Dns.ZoneManagers;
using ZenitiumDns.Core.Dns.Zones;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.NetworkInformation;
using System.Net.Quic;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumLibrary;
using ZenitiumLibrary.IO;
using ZenitiumLibrary.Net.Http.Client;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ClientConnection;
using ZenitiumLibrary.Net.Dns.EDnsOptions;
using ZenitiumLibrary.Net.Dns.ResourceRecords;
using ZenitiumLibrary.Net.Proxy;
using ZenitiumLibrary.Net.ProxyProtocol;

namespace ZenitiumDns.Core.Dns
{
#pragma warning disable CA1416

    public enum DnsServerRecursion : byte
    {
        Deny = 0,
        Allow = 1,
        AllowOnlyForPrivateNetworks = 2,
        UseSpecifiedNetworkACL = 3
    }

    public enum DnsServerBlockingType : byte
    {
        AnyAddress = 0,
        NxDomain = 1,
        CustomAddress = 2
    }

    public enum DnsServerDo53Mode : byte
    {
        Enabled = 0,
        DdrOnlyDrop = 1,
        DdrOnlyRefused = 2,
        Disabled = 3
    }

    public enum DnsServerEDnsPaddingMode : byte
    {
        Disabled = 0,
        WhenRequested = 1,
        Always = 2
    }

    enum UdpLimitedResponse : byte
    {
        None = 0,
        Truncation = 1,
        BadCookie = 2
    }

    public sealed class DnsServer : IAsyncDisposable, IDisposable, IDnsClient
    {
        #region enum

        enum ServiceState
        {
            Stopped = 0,
            Starting = 1,
            Running = 2,
            Stopping = 3
        }

        #endregion

        #region variables

        const int SOL_SOCKET = 1;
        const int SO_BINDTODEVICE = 25;

        const int IPPROTO_IP = 0;
        const int IP_BOUND_IF = 25;
        const int IPPROTO_IPV6 = 41;
        const int IPV6_BOUND_IF = 125;

        readonly static char[] commaSeparator = new char[] { ',' };

        internal const int MAX_CNAME_HOPS = 16;
        internal const int SERVE_STALE_MAX_WAIT_TIME = 1800;
        const int SERVE_STALE_TIME_DIFFERENCE = 200;
        internal const int RECURSIVE_RESOLUTION_TIMEOUT = 60000;

        static readonly IPEndPoint IPENDPOINT_ANY_0 = new IPEndPoint(IPAddress.Any, 0);
        static readonly IReadOnlyCollection<DnsARecordData> _aRecords = [new DnsARecordData(IPAddress.Any)];
        static readonly IReadOnlyCollection<DnsAAAARecordData> _aaaaRecords = [new DnsAAAARecordData(IPAddress.IPv6Any)];
        static readonly List<SslApplicationProtocol> _doqApplicationProtocols = new List<SslApplicationProtocol>() { new SslApplicationProtocol("doq") };

        string _serverDomain;
        readonly string _configFolder;
        readonly string _dohwwwFolder;
        IReadOnlyList<IPEndPoint> _localEndPoints;
        readonly LogManager _log;

        MailAddress _defaultResponsiblePerson;
        MailAddress _fallbackResponsiblePerson;

        NameServerAddress _thisServer;

        readonly List<Socket> _udpListeners = new List<Socket>();
        readonly List<Socket> _udpProxyListeners = new List<Socket>();
        readonly List<Socket> _tcpListeners = new List<Socket>();
        readonly List<Socket> _tcpProxyListeners = new List<Socket>();
        readonly List<Socket> _tlsListeners = new List<Socket>();
        readonly List<QuicListener> _quicListeners = new List<QuicListener>();

        WebApplication _dohWebService;

        readonly AuthZoneManager _authZoneManager;
        readonly SpecialZoneManager _specialZoneManager;
        readonly AllowedZoneManager _allowedZoneManager;
        readonly BlockedZoneManager _blockedZoneManager;
        readonly BlockListZoneManager _blockListZoneManager;
        readonly ClientProfileManager _clientProfileManager;
        Dhcp.DhcpServer _dhcpServer;
        readonly CacheZoneManager _cacheZoneManager;
        readonly DnsApplicationManager _dnsApplicationManager;

        readonly ResolverDnsCache _dnsCache;
        readonly ResolverDnsCache _dnsCacheSkipDnsApps;
        readonly ResolverDnsCache _forwarderDnsCache;
        readonly ResolverDnsCache _forwarderDnsCacheSkipDnsApps;
        readonly StatsManager _statsManager;


        bool _enableCheckForUpdate = true;

        IPv6Mode _ipv6Mode;
        bool _enableUdpSocketPool;
        ushort _udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE;
        bool _dnssecValidation = true;

        bool _eDnsClientSubnet;
        byte _eDnsClientSubnetIPv4PrefixLength = 24;
        byte _eDnsClientSubnetIPv6PrefixLength = 56;
        NetworkAddress _eDnsClientSubnetIpv4Override;
        NetworkAddress _eDnsClientSubnetIpv6Override;

        IReadOnlyDictionary<int, (int, int)> _qpsPrefixLimitsIPv4 = GetDefaultQpsPrefixLimitsIPv4();
        IReadOnlyDictionary<int, (int, int)> _qpsPrefixLimitsIPv6 = GetDefaultQpsPrefixLimitsIPv6();
        int _rateLimitBurstSeconds = DEFAULT_RATE_LIMIT_BURST_SECONDS;
        int _rateLimitUdpTruncationPercentage = DEFAULT_RATE_LIMIT_UDP_TRUNCATION_PERCENTAGE;
        IReadOnlyCollection<NetworkAddress> _rateLimitBypassList;
        readonly ClientRateLimiter _rateLimiter = new ClientRateLimiter();
        readonly ClientBlockListManager _clientBlockListManager;
        readonly SystemMonitor _systemMonitor;
        readonly Watchdog _watchdog;
        readonly IanaDataManager _ianaDataManager;
        const int DEFAULT_RATE_LIMIT_BURST_SECONDS = 5;
        const int DEFAULT_RATE_LIMIT_UDP_TRUNCATION_PERCENTAGE = 100;
        public const int MAX_RATE_LIMIT_QPS = 1000000;
        const string DDR_DOMAIN = "_dns.resolver.arpa";
        const uint DDR_RECORD_TTL = 3600;

        int _clientTimeout = 2000;
        int _tcpSendTimeout = 10000;
        int _tcpReceiveTimeout = 10000;
        int _quicIdleTimeout = 60000;
        int _quicMaxInboundStreams = 100;
        int _listenBacklog = 1024;
        int _udpSendBufferSizeKB = 2048;
        int _udpReceiveBufferSizeKB = 2048;

        bool _enableEDnsClientSubnetSourceAddress;
        bool _enableDnsOverUdpProxy;
        bool _enableDnsOverTcpProxy;
        bool _enableDnsOverHttp;
        bool _enableDnsOverHttpUnixSocket;
        bool _enableDnsOverHttpsUnixSocket;
        bool _enableDnsOverTls;
        bool _enableDnsOverHttps;
        bool _enableDnsOverHttp3;
        bool _enableDnsOverQuic;
        bool _enableDnsOverHttpHelpRedirect = true;
        int _dnsOverUdpProxyPort = 538;
        int _dnsOverTcpProxyPort = 538;
        int _dnsOverHttpPort = 80;
        string _dnsOverHttpUnixSocket;
        string _dnsOverHttpsUnixSocket;
        int _dnsOverTlsPort = 853;
        int _dnsOverHttpsPort = 443;
        int _dnsOverQuicPort = 853;
        IReadOnlyCollection<NetworkAccessControl> _dnsReverseProxyNetworkACL;
        string _dnsTlsCertificatePath;
        string _dnsTlsCertificatePassword;
        string _dnsTlsCertificateKeyPath;
        bool _enableDdr = true;
        bool _ddrOnlyUnencrypted = true;
        bool _ddrProxyDoh;
        ushort _ddrProxyDohPort = 443;
        bool _ddrProxyDohHttp3 = true;
        DnsServerDo53Mode _do53Mode = DnsServerDo53Mode.Enabled;
        bool _blockFirefoxCanaryDomain;
        bool _forceChromePreflight;
        DnsServerEDnsPaddingMode _eDnsPaddingMode = DnsServerEDnsPaddingMode.WhenRequested;
        const int EDNS_RESPONSE_PADDING_BLOCK_SIZE = 468;
        volatile string[] _autoAllowedNames = [];
        const string FIREFOX_CANARY_DOMAIN = "use-application-dns.net";
        const string CHROME_PREFLIGHT_DOMAIN = "dns-tunnel-check.googlezip.net";
        X509Certificate2 _dnsTlsCertificate;
        string _dnsOverHttpRealIpHeader = "X-Real-IP";

        Timer _tlsCertificateUpdateTimer;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL = 60000;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL = 60000;

        DateTime _dnsTlsCertificateLastModifiedOn;
        SslServerAuthenticationOptions _dotSslServerAuthenticationOptions;
        SslServerAuthenticationOptions _doqSslServerAuthenticationOptions;
        SslServerAuthenticationOptions _dohSslServerAuthenticationOptions;


        DnsServerRecursion _recursion;
        IReadOnlyCollection<NetworkAccessControl> _recursionNetworkACL;

        bool _randomizeName;
        bool _enableDnsCookies;
        string _httpUserAgent;

        internal static readonly string DefaultHttpUserAgent = "ZenitiumDNS/" + (typeof(DnsServer).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0");
        byte[] _dnsCookieSecret = RandomNumberGenerator.GetBytes(DnsCookie.SECRET_LENGTH);
        bool _dnsCookieSecretConfigured;
        bool _qnameMinimization = true;
        bool _locallyServedDnsZones = true;

        int _resolverRetries = 2;
        int _resolverTimeout = 1500;
        int _resolverConcurrency = 2;
        int _resolverMaxStackCount = 16;

        bool _saveCacheToDisk = true;
        bool _serveStale = true;
        int _serveStaleMaxWaitTime = SERVE_STALE_MAX_WAIT_TIME;
        int _cachePrefetchEligibility = 2;
        int _cachePrefetchTrigger = 9;
        int _cachePrefetchTriggerPercent = 10;

        bool _enableBlocking = true;
        int _udpListenerThreads;
        int _maxPendingStreamRequests = 100;

        bool _requestFilterMalformed = true;
        int _requestFilterMaxSize = 1232;
        bool _requestFilterOpcode = true;
        bool _requestFilterClass = true;
        bool _requestFilterAny = true;
        bool _requestFilterZoneTransfer = true;
        bool _requestFilterNoRecursion = true;
        bool _requestFilterEdnsVersion = true;
        bool _requestFilterRefuseOnly;
        readonly long[] _requestFilterMatches = new long[8];

        bool _allowTxtBlockingReport = true;
        IReadOnlyCollection<NetworkAddress> _blockingBypassList;
        DnsServerBlockingType _blockingType = DnsServerBlockingType.NxDomain;
        uint _blockingAnswerTtl = 30;
        uint _blockingNegativeTtl = 300;
        string _blockingReportText;
        IReadOnlyCollection<DnsARecordData> _customBlockingARecords = [];
        IReadOnlyCollection<DnsAAAARecordData> _customBlockingAAAARecords = [];

        NetProxy _proxy;
        IReadOnlyList<NameServerAddress> _forwarders;
        bool _concurrentForwarding = true;
        int _forwarderRetries = 3;
        int _forwarderTimeout = 2000;
        int _forwarderConcurrency = 2;

        LogManager _resolverLog;
        LogManager _queryLog;

        Timer _rateLimitMaintenanceTimer;

        Timer _ipv6ProbeTimer;
        readonly Lock _ipv6ProbeTimerLock = new Lock();
        const int IPV6_PROBE_TIMER_INTERVAL = 60000;
        const int IPV6_STARTUP_PROBE_DELAY = 15000;
        readonly Lock _rateLimitMaintenanceTimerLock = new Lock();
        const int RATE_LIMIT_MAINTENANCE_TIMER_INTERVAL = 10000;


        TaskPool _resolverTaskPool;
        readonly ConcurrentDictionary<string, Task<RecursiveResolveResponse>> _resolverTasks = new ConcurrentDictionary<string, Task<RecursiveResolveResponse>>(-1, 1000);

        volatile ServiceState _state = ServiceState.Stopped;

        readonly Lock _saveLock = new Lock();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        #endregion

        #region constructor

        static DnsServer()
        {
            {
                ThreadPool.GetMinThreads(out int minWorker, out int minIOC);

                int minThreads = Environment.ProcessorCount * 16;

                if (minWorker < minThreads)
                    minWorker = minThreads;

                if (minIOC < minThreads)
                    minIOC = minThreads;

                ThreadPool.SetMinThreads(minWorker, minIOC);
            }
        }

        public DnsServer(string configFolder, string dohwwwFolder, LogManager log, string serverDomain = null)
            : this(configFolder, dohwwwFolder, [new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53)], log, serverDomain)
        { }

        public DnsServer(string configFolder, string dohwwwFolder, IReadOnlyList<IPEndPoint> localEndPoints, LogManager log, string serverDomain = null)
        {
            if (string.IsNullOrEmpty(serverDomain))
                serverDomain = Environment.MachineName.ToLowerInvariant();

            if (!DnsClient.IsDomainNameValid(serverDomain) || IPAddress.TryParse(serverDomain, out _))
                serverDomain = "dns-server-1";

            _serverDomain = serverDomain;
            _configFolder = configFolder;
            _dohwwwFolder = dohwwwFolder;
            LocalEndPoints = localEndPoints;
            _log = log;

            ReconfigureResolverTaskPool(100);

            _authZoneManager = new AuthZoneManager(this);
            _specialZoneManager = new SpecialZoneManager(this);
            _allowedZoneManager = new AllowedZoneManager(this);
            _blockedZoneManager = new BlockedZoneManager(this);
            _blockListZoneManager = new BlockListZoneManager(this);
            _clientProfileManager = new ClientProfileManager(this, configFolder);
            _cacheZoneManager = new CacheZoneManager(this);
            _dnsApplicationManager = new DnsApplicationManager(this);

            _dnsCache = new ResolverDnsCache(this, false);
            _dnsCacheSkipDnsApps = new ResolverDnsCache(this, true);
            _forwarderDnsCache = new ResolverDnsCache(this, false, false, false);
            _forwarderDnsCacheSkipDnsApps = new ResolverDnsCache(this, true, false, false);

            _statsManager = new StatsManager(this);
            HttpClientNetworkHandler.DefaultUserAgent = DefaultHttpUserAgent;
            _clientBlockListManager = new ClientBlockListManager(this);
            _systemMonitor = new SystemMonitor(this);
            _watchdog = new Watchdog(this);
            _ianaDataManager = new IanaDataManager(this);

            IPv6Reachability.AvailabilityChanged += IPv6Reachability_AvailabilityChanged;

            ApplyRateLimits();

            if (_saveCacheToDisk)
            {
                ThreadPool.QueueUserWorkItem(delegate (object state)
                {
                    try
                    {
                        _cacheZoneManager.LoadCacheZoneFile();
                    }
                    catch (Exception ex)
                    {
                        _log.Write("Failed to fully load DNS Cache from disk.", ex);
                    }
                });
            }

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave)
                    {
                        try
                        {
                            SaveConfigFileInternal();
                            _pendingSave = false;
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);

                            _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                        }
                    }
                }
            });
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
                return;

            await StopAsync();

            IPv6Reachability.AvailabilityChanged -= IPv6Reachability_AvailabilityChanged;

            StopTlsCertificateUpdateTimer();

            _authZoneManager?.Dispose();
            _cacheZoneManager?.Dispose();

            _allowedZoneManager?.Dispose();
            _blockedZoneManager?.Dispose();
            _blockListZoneManager?.Dispose();

            _dnsApplicationManager?.Dispose();

            _statsManager?.Dispose();
            _clientBlockListManager?.Dispose();
            _systemMonitor?.Dispose();
            _watchdog?.Dispose();
            _ianaDataManager?.Dispose();

            _resolverTaskPool?.Dispose();


            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave)
                {
                    try
                    {
                        SaveConfigFileInternal();
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            if (_saveCacheToDisk)
            {
                try
                {
                    _cacheZoneManager?.SaveCacheZoneFile();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        public void Dispose()
        {
            DisposeAsync().Sync();
        }

        #endregion

        #region config

        public void LoadConfigFile()
        {
            string dnsConfigFile = Path.Combine(_configFolder, "dns.config");

            try
            {
                using (FileStream fS = new FileStream(dnsConfigFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS);
                }

                _log.Write("DNS Server config file was loaded: " + dnsConfigFile);
            }
            catch (FileNotFoundException)
            {
                EnableCheckForUpdate = true;

                IPv6Mode = IPv6Mode.Enabled;
                DnssecValidation = true;
                EnableUdpSocketPool = false;
                ListenBacklog = 1024;
                TcpReceiveTimeout = 5000;

                EnableEDnsClientSubnetSourceAddress = false;
                EnableDnsOverHttpHelpRedirect = true;

                Recursion = DnsServerRecursion.AllowOnlyForPrivateNetworks;
                RandomizeName = true;
                QnameMinimization = true;
                QnameMinimizationFallback = true;
                EnableDnsCookies = true;
                LocallyServedDnsZones = true;

                _cacheZoneManager.MaximumEntries = 100000;

                BlockingAnswerTtl = 300;

                ResolverLogManager = null;
                _statsManager.MaxStatFileDays = 30;
                _systemMonitor.Enabled = true;
                _watchdog.Enabled = true;

                lock (_saveLock)
                {
                    SaveConfigFileInternal();
                }
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading DNS config file: " + dnsConfigFile, ex);
                _log.Write("Note: You may try deleting the DNS config file to fix this issue. However, you will lose DNS settings but, other data wont be affected.");
            }
        }

        public void LoadConfig(Stream s)
        {
            lock (_saveLock)
            {
                ReadConfigFrom(s);

                SaveConfigFileInternal();

                if (_pendingSave)
                {
                    _pendingSave = false;
                    _saveTimer.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }
        }

        private void SaveConfigFileInternal()
        {
            string tmpConfigFile = Path.Combine(_configFolder, "dns.tmp");
            string configFile = Path.Combine(_configFolder, "dns.config");

            using (FileStream fS = new FileStream(tmpConfigFile, FileMode.Create, FileAccess.Write))
            {
                WriteConfigTo(fS);
            }

            File.Move(tmpConfigFile, configFile, true);

            _log.Write("DNS Server config file was saved: " + configFile);
        }

        public void SavePendingConfigFile()
        {
            lock (_saveLock)
            {
                if (!_pendingSave)
                    return;

                SaveConfigFileInternal();
                _pendingSave = false;
            }
        }

        public void SaveConfigFile(bool immediately = false)
        {
            lock (_saveLock)
            {
                if (immediately)
                {
                    SaveConfigFileInternal();
                    _pendingSave = false;
                    return;
                }

                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void ReadConfigFrom(Stream s)
        {
            if (Encoding.ASCII.GetString(s.ReadExactly(2)) != "DC")
                throw new InvalidDataException("DNS Server config file format is invalid.");

            BinaryReader bR = new BinaryReader(s);

            int version = bR.ReadByte();
            if ((version < 1) || (version > 17))
                throw new InvalidDataException("DNS Server config version not supported.");

            string serverDomain = s.ReadShortString();
            try
            {
                ServerDomain = serverDomain;
            }
            catch
            {
                _serverDomain = serverDomain;
            }

            {
                IPEndPoint[] localEndPoints;

                int count = bR.ReadByte();
                if (count > 0)
                {
                    IPEndPoint[] localEPs = new IPEndPoint[count];

                    for (int i = 0; i < count; i++)
                        localEPs[i] = (IPEndPoint)EndPointExtensions.ReadFrom(bR);

                    localEndPoints = localEPs;
                }
                else
                {
                    localEndPoints = [new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53)];
                }

                _localEndPoints = localEndPoints;
            }

            NetworkAddress[] ipv4SourceAddresses = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
            DnsClientConnection.IPv4SourceAddresses = ipv4SourceAddresses;

            NetworkAddress[] ipv6SourceAddresses = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
            DnsClientConnection.IPv6SourceAddresses = ipv6SourceAddresses;

            _authZoneManager.DefaultRecordTtl = bR.ReadUInt32();

            if (version >= 2)
            {
                _authZoneManager.DefaultNsRecordTtl = bR.ReadUInt32();
                _authZoneManager.DefaultSoaRecordTtl = bR.ReadUInt32();
            }
            else
            {
                _authZoneManager.DefaultNsRecordTtl = 14400;
                _authZoneManager.DefaultSoaRecordTtl = 900;
            }

            string rp = bR.ReadString();
            if (rp.Length == 0)
                _defaultResponsiblePerson = null;
            else
                _defaultResponsiblePerson = new MailAddress(rp);

            if (version < 7)
            {
                bR.ReadBoolean();
                bR.ReadUInt32();
                bR.ReadUInt32();

                AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                AuthZoneInfo.ReadNetworkAddressesFrom(bR);
            }

            if (version >= 4)
                _enableCheckForUpdate = bR.ReadBoolean();
            else
                _enableCheckForUpdate = true;

            bR.ReadBoolean();

            if (version >= 3)
            {
                IPv6Mode ipv6Mode = (IPv6Mode)bR.ReadByte();
                _ipv6Mode = ipv6Mode;
            }
            else
            {
                bool preferIPv6 = bR.ReadBoolean();
                _ipv6Mode = preferIPv6 ? IPv6Mode.Preferred : IPv6Mode.Disabled;
            }

            {
                bool enableUdpSocketPool = bR.ReadBoolean();
                _enableUdpSocketPool = enableUdpSocketPool;

                int count = bR.ReadUInt16();
                ushort[] socketPoolExcludedPorts = new ushort[count];

                for (int i = 0; i < count; i++)
                    socketPoolExcludedPorts[i] = bR.ReadUInt16();

                UdpClientConnection.SocketPoolExcludedPorts = socketPoolExcludedPorts;
            }

            _udpPayloadSize = bR.ReadUInt16();
            _dnssecValidation = bR.ReadBoolean();

            _eDnsClientSubnet = bR.ReadBoolean();
            _eDnsClientSubnetIPv4PrefixLength = bR.ReadByte();
            _eDnsClientSubnetIPv6PrefixLength = bR.ReadByte();

            if (bR.ReadBoolean())
                _eDnsClientSubnetIpv4Override = NetworkAddress.ReadFrom(bR);
            else
                _eDnsClientSubnetIpv4Override = null;

            if (bR.ReadBoolean())
                _eDnsClientSubnetIpv6Override = NetworkAddress.ReadFrom(bR);
            else
                _eDnsClientSubnetIpv6Override = null;

            {
                Dictionary<int, (int, int)> prefixLimitsIPv4 = ReadPrefixLimits(bR);
                Dictionary<int, (int, int)> prefixLimitsIPv6 = ReadPrefixLimits(bR);
                int burstSeconds = bR.ReadInt32();

                if (version >= 10)
                {
                    _qpsPrefixLimitsIPv4 = prefixLimitsIPv4;
                    _qpsPrefixLimitsIPv6 = prefixLimitsIPv6;
                    _rateLimitBurstSeconds = burstSeconds;
                }
                else if (version == 9)
                {
                    _qpsPrefixLimitsIPv4 = HasSameEntries(prefixLimitsIPv4, new Dictionary<int, (int, int)>() { { 32, (100, 400) }, { 24, (1000, 4000) } }) ? GetDefaultQpsPrefixLimitsIPv4() : prefixLimitsIPv4;
                    _qpsPrefixLimitsIPv6 = HasSameEntries(prefixLimitsIPv6, new Dictionary<int, (int, int)>() { { 64, (100, 400) }, { 56, (1000, 4000) } }) ? GetDefaultQpsPrefixLimitsIPv6() : prefixLimitsIPv6;
                    _rateLimitBurstSeconds = burstSeconds;
                }
                else
                {
                    _qpsPrefixLimitsIPv4 = ConvertLegacyQpmPrefixLimits(prefixLimitsIPv4, false);
                    _qpsPrefixLimitsIPv6 = ConvertLegacyQpmPrefixLimits(prefixLimitsIPv6, true);
                    _rateLimitBurstSeconds = DEFAULT_RATE_LIMIT_BURST_SECONDS;
                }

                ApplyRateLimits();
            }

            _rateLimitUdpTruncationPercentage = bR.ReadInt32();

            if ((version < 10) && (_rateLimitUdpTruncationPercentage == 50))
                _rateLimitUdpTruncationPercentage = DEFAULT_RATE_LIMIT_UDP_TRUNCATION_PERCENTAGE;

            _rateLimitBypassList = AuthZoneInfo.ReadNetworkAddressesFrom(bR);

            _clientTimeout = bR.ReadInt32();
            _tcpSendTimeout = bR.ReadInt32();
            _tcpReceiveTimeout = bR.ReadInt32();
            _quicIdleTimeout = bR.ReadInt32();
            _quicMaxInboundStreams = bR.ReadInt32();
            _listenBacklog = bR.ReadInt32();

            if (version >= 3)
            {
                _udpSendBufferSizeKB = bR.ReadInt32();
                _udpReceiveBufferSizeKB = bR.ReadInt32();
            }
            else
            {
                _udpSendBufferSizeKB = 2048;
                _udpReceiveBufferSizeKB = 2048;
            }

            MaxConcurrentResolutionsPerCore = bR.ReadUInt16();

            if (version >= 3)
            {
                bool enableEDnsClientSubnetSourceAddress = bR.ReadBoolean();
                _enableEDnsClientSubnetSourceAddress = enableEDnsClientSubnetSourceAddress;
            }
            else
            {
                _enableEDnsClientSubnetSourceAddress = false;
            }

            bool enableDnsOverUdpProxy = bR.ReadBoolean();
            _enableDnsOverUdpProxy = enableDnsOverUdpProxy;

            bool enableDnsOverTcpProxy = bR.ReadBoolean();
            _enableDnsOverTcpProxy = enableDnsOverTcpProxy;

            bool enableDnsOverHttp = bR.ReadBoolean();
            _enableDnsOverHttp = enableDnsOverHttp;

            if (version >= 4)
            {
                bool enableDnsOverHttpUnixSocket = bR.ReadBoolean();
                _enableDnsOverHttpUnixSocket = enableDnsOverHttpUnixSocket;
            }
            else
            {
                _enableDnsOverHttpUnixSocket = false;
            }

            if (version >= 5)
            {
                bool enableDnsOverHttpsUnixSocket = bR.ReadBoolean();
                _enableDnsOverHttpsUnixSocket = enableDnsOverHttpsUnixSocket;
            }
            else
            {
                _enableDnsOverHttpsUnixSocket = false;
            }

            bool enableDnsOverTls = bR.ReadBoolean();
            _enableDnsOverTls = enableDnsOverTls;

            bool enableDnsOverHttps = bR.ReadBoolean();
            _enableDnsOverHttps = enableDnsOverHttps;

            bool enableDnsOverHttp3 = bR.ReadBoolean();
            _enableDnsOverHttp3 = enableDnsOverHttp3;

            bool enableDnsOverQuic = bR.ReadBoolean();
            _enableDnsOverQuic = enableDnsOverQuic;

            if (version >= 4)
            {
                bool enableDnsOverHttpHelpRedirect = bR.ReadBoolean();
                _enableDnsOverHttpHelpRedirect = enableDnsOverHttpHelpRedirect;
            }
            else
            {
                _enableDnsOverHttpHelpRedirect = true;
            }

            int dnsOverUdpProxyPort = bR.ReadInt32();
            _dnsOverUdpProxyPort = dnsOverUdpProxyPort;

            int dnsOverTcpProxyPort = bR.ReadInt32();
            _dnsOverTcpProxyPort = dnsOverTcpProxyPort;

            int dnsOverHttpPort = bR.ReadInt32();
            _dnsOverHttpPort = dnsOverHttpPort;

            if (version >= 4)
            {
                string unixSocket = s.ReadShortString();
                _dnsOverHttpUnixSocket = unixSocket.Length == 0 ? null : unixSocket;
            }
            else
            {
                _dnsOverHttpUnixSocket = null;
            }

            if (version >= 5)
            {
                string unixSocket = s.ReadShortString();
                _dnsOverHttpsUnixSocket = unixSocket.Length == 0 ? null : unixSocket;
            }
            else
            {
                _dnsOverHttpsUnixSocket = null;
            }

            int dnsOverTlsPort = bR.ReadInt32();
            _dnsOverTlsPort = dnsOverTlsPort;

            int dnsOverHttpsPort = bR.ReadInt32();
            _dnsOverHttpsPort = dnsOverHttpsPort;

            int dnsOverQuicPort = bR.ReadInt32();
            _dnsOverQuicPort = dnsOverQuicPort;

            NetworkAccessControl[] dnsReverseProxyNetworkACL = AuthZoneInfo.ReadNetworkACLFrom(bR);
            _dnsReverseProxyNetworkACL = dnsReverseProxyNetworkACL;

            string dnsTlsCertificatePath = s.ReadShortString();
            string dnsTlsCertificatePassword = s.ReadShortString();

            _dnsTlsCertificatePath = dnsTlsCertificatePath;
            _dnsTlsCertificatePassword = dnsTlsCertificatePassword;

            if (_dnsTlsCertificatePath.Length == 0)
                _dnsTlsCertificatePath = null;

            string dnsOverHttpRealIpHeader = s.ReadShortString();
            _dnsOverHttpRealIpHeader = dnsOverHttpRealIpHeader;

            if (version < 7)
            {
                int count = bR.ReadByte();

                for (int i = 0; i < count; i++)
                {
                    s.ReadShortString();
                    s.ReadShortString();
                    bR.ReadByte();
                }
            }

            _recursion = (DnsServerRecursion)bR.ReadByte();
            _recursionNetworkACL = AuthZoneInfo.ReadNetworkACLFrom(bR);

            _randomizeName = bR.ReadBoolean();
            _qnameMinimization = bR.ReadBoolean();

            if (version >= 4)
                _locallyServedDnsZones = bR.ReadBoolean();
            else
                _locallyServedDnsZones = true;

            _resolverRetries = bR.ReadInt32();
            _resolverTimeout = bR.ReadInt32();
            _resolverConcurrency = bR.ReadInt32();
            _resolverMaxStackCount = bR.ReadInt32();

            bool saveCacheToDisk = bR.ReadBoolean();
            _saveCacheToDisk = saveCacheToDisk;

            bool serveStale = bR.ReadBoolean();
            _serveStale = serveStale;

            uint serveStaleTtl = bR.ReadUInt32();
            _cacheZoneManager.ServeStaleTtl = serveStaleTtl;

            uint serveStaleAnswerTtl = bR.ReadUInt32();
            _cacheZoneManager.ServeStaleAnswerTtl = serveStaleAnswerTtl;

            uint serveStaleResetTtl = bR.ReadUInt32();
            _cacheZoneManager.ServeStaleResetTtl = serveStaleResetTtl;

            int serveStaleMaxWaitTime = bR.ReadInt32();
            _serveStaleMaxWaitTime = serveStaleMaxWaitTime;

            long cacheMaximumEntries = bR.ReadInt64();
            _cacheZoneManager.MaximumEntries = cacheMaximumEntries;

            uint minimumRecordTtl = bR.ReadUInt32();
            _cacheZoneManager.MinimumRecordTtl = minimumRecordTtl;

            uint maximumRecordTtl = bR.ReadUInt32();
            _cacheZoneManager.MaximumRecordTtl = maximumRecordTtl;

            uint negativeRecordTtl = bR.ReadUInt32();
            _cacheZoneManager.NegativeRecordTtl = negativeRecordTtl;

            uint failureRecordTtl = bR.ReadUInt32();
            _cacheZoneManager.FailureRecordTtl = failureRecordTtl;

            int cachePrefetchEligibility = bR.ReadInt32();
            _cachePrefetchEligibility = cachePrefetchEligibility;

            int cachePrefetchTrigger = bR.ReadInt32();
            _cachePrefetchTrigger = cachePrefetchTrigger;

            if (version < 6)
            {
                bR.ReadInt32();
                bR.ReadInt32();
            }

            _enableBlocking = bR.ReadBoolean();
            _allowTxtBlockingReport = bR.ReadBoolean();

            _blockingBypassList = AuthZoneInfo.ReadNetworkAddressesFrom(bR);

            _blockingType = (DnsServerBlockingType)bR.ReadByte();

            {
                List<DnsARecordData> dnsARecords = new List<DnsARecordData>();
                List<DnsAAAARecordData> dnsAAAARecords = new List<DnsAAAARecordData>();

                int count = bR.ReadByte();
                if (count > 0)
                {
                    for (int i = 0; i < count; i++)
                    {
                        IPAddress customAddress = IPAddressExtensions.ReadFrom(bR);

                        switch (customAddress.AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                dnsARecords.Add(new DnsARecordData(customAddress));
                                break;

                            case AddressFamily.InterNetworkV6:
                                dnsAAAARecords.Add(new DnsAAAARecordData(customAddress));
                                break;
                        }
                    }
                }

                _customBlockingARecords = dnsARecords;
                _customBlockingAAAARecords = dnsAAAARecords;
            }

            _blockingAnswerTtl = bR.ReadUInt32();

            NetProxyType proxyType = (NetProxyType)bR.ReadByte();
            if (proxyType != NetProxyType.None)
            {
                string address = s.ReadShortString();
                int port = bR.ReadInt32();
                NetworkCredential credential = null;

                if (bR.ReadBoolean())
                    credential = new NetworkCredential(s.ReadShortString(), s.ReadShortString());

                _proxy = NetProxy.CreateProxy(proxyType, address, port, credential);

                int count = bR.ReadByte();
                List<NetProxyBypassItem> bypassList = new List<NetProxyBypassItem>(count);

                for (int i = 0; i < count; i++)
                    bypassList.Add(new NetProxyBypassItem(s.ReadShortString()));

                _proxy.BypassList = bypassList;
            }
            else
            {
                _proxy = null;
            }

            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    NameServerAddress[] forwarders = new NameServerAddress[count];

                    for (int i = 0; i < count; i++)
                    {
                        forwarders[i] = new NameServerAddress(bR);

                        if (forwarders[i].Protocol == DnsTransportProtocol.HttpsJson)
                            forwarders[i] = forwarders[i].Clone(DnsTransportProtocol.Https);
                    }

                    _forwarders = forwarders;
                }
                else
                {
                    _forwarders = null;
                }
            }

            _concurrentForwarding = bR.ReadBoolean();
            _forwarderRetries = bR.ReadInt32();
            _forwarderTimeout = bR.ReadInt32();
            _forwarderConcurrency = bR.ReadInt32();

            bool ignoreResolverLogs = bR.ReadBoolean();
            if (ignoreResolverLogs || (version < 10))
                _resolverLog = null;
            else
                _resolverLog = _log;

            bool logQueries = bR.ReadBoolean();
            if (logQueries)
                _queryLog = _log;
            else
                _queryLog = null;

            bool enableInMemoryStats = bR.ReadBoolean();
            _statsManager.EnableInMemoryStats = enableInMemoryStats;

            int maxStatFileDays = bR.ReadInt32();
            _statsManager.MaxStatFileDays = maxStatFileDays;

            if (version >= 7)
            {
                IPv6Reachability.Enabled = bR.ReadBoolean();
                _udpListenerThreads = bR.ReadInt32();
                _maxPendingStreamRequests = bR.ReadInt32();
            }
            else
            {
                IPv6Reachability.Enabled = true;
                _udpListenerThreads = 0;
                _maxPendingStreamRequests = 100;
            }

            if (version >= 8)
            {
                _requestFilterMalformed = bR.ReadBoolean();
                _requestFilterMaxSize = bR.ReadInt32();
                _requestFilterOpcode = bR.ReadBoolean();
                _requestFilterClass = bR.ReadBoolean();
                _requestFilterAny = bR.ReadBoolean();
                _requestFilterZoneTransfer = bR.ReadBoolean();
                _requestFilterNoRecursion = bR.ReadBoolean();
                _requestFilterEdnsVersion = bR.ReadBoolean();
                _requestFilterRefuseOnly = bR.ReadBoolean();
                DnsClient.PostQuantumDowngradeProtection = bR.ReadBoolean();
            }
            else
            {
                _requestFilterMalformed = true;
                _requestFilterMaxSize = 1232;
                _requestFilterOpcode = true;
                _requestFilterClass = true;
                _requestFilterAny = true;
                _requestFilterZoneTransfer = true;
                _requestFilterNoRecursion = true;
                _requestFilterEdnsVersion = true;
                _requestFilterRefuseOnly = false;
                DnsClient.PostQuantumDowngradeProtection = true;
            }

            if (version >= 9)
            {
                string blockingReportText = s.ReadShortString();
                _blockingReportText = blockingReportText.Length == 0 ? null : blockingReportText;
                _blockingNegativeTtl = bR.ReadUInt32();

                string dnsTlsCertificateKeyPath = s.ReadShortString();
                _dnsTlsCertificateKeyPath = dnsTlsCertificateKeyPath.Length == 0 ? null : dnsTlsCertificateKeyPath;
                _enableDdr = bR.ReadBoolean();
                _ddrOnlyUnencrypted = bR.ReadBoolean();

                int count = bR.ReadByte();
                Uri[] clientBlockListUrls = new Uri[count];

                for (int i = 0; i < count; i++)
                    clientBlockListUrls[i] = new Uri(s.ReadShortString());

                _clientBlockListManager.UpdateIntervalHours = bR.ReadInt32();
                _clientBlockListManager.ListUrls = clientBlockListUrls;
            }
            else
            {
                _blockingReportText = null;
                _blockingNegativeTtl = _blockingAnswerTtl;
                _dnsTlsCertificateKeyPath = null;
                _enableDdr = true;
                _ddrOnlyUnencrypted = true;
            }

            if (version >= 10)
            {
                _do53Mode = (DnsServerDo53Mode)bR.ReadByte();
                _cacheZoneManager.MaximumNegativeRecordTtl = bR.ReadUInt32();
                _blockFirefoxCanaryDomain = bR.ReadBoolean();
                _forceChromePreflight = bR.ReadBoolean();
                _systemMonitor.Enabled = bR.ReadBoolean();
                _watchdog.Enabled = bR.ReadBoolean();
                _ianaDataManager.LoadModes((IanaDataMode)bR.ReadByte(), (IanaDataMode)bR.ReadByte(), (IanaDataMode)bR.ReadByte());
            }
            else
            {
                _systemMonitor.Enabled = true;
                _watchdog.Enabled = true;
                _do53Mode = DnsServerDo53Mode.Enabled;
                _cacheZoneManager.MaximumNegativeRecordTtl = CacheZoneManager.MAXIMUM_NEGATIVE_RECORD_TTL;
                _blockFirefoxCanaryDomain = false;
                _forceChromePreflight = false;
            }

            if (version >= 11)
                _eDnsPaddingMode = (DnsServerEDnsPaddingMode)bR.ReadByte();
            else
                _eDnsPaddingMode = DnsServerEDnsPaddingMode.WhenRequested;

            if (version >= 12)
            {
                _ddrProxyDoh = bR.ReadBoolean();
                _ddrProxyDohPort = bR.ReadUInt16();
                _ddrProxyDohHttp3 = bR.ReadBoolean();
            }
            else
            {
                _ddrProxyDoh = false;
                _ddrProxyDohPort = 443;
                _ddrProxyDohHttp3 = true;
            }

            if (version >= 13)
                _cachePrefetchTriggerPercent = bR.ReadByte();
            else
                _cachePrefetchTriggerPercent = 10;

            if (version >= 14)
                _cacheZoneManager.AggressiveNsec = bR.ReadBoolean();
            else
                _cacheZoneManager.AggressiveNsec = true;

            if (version >= 15)
            {
                EnableDnsCookies = bR.ReadBoolean();

                byte[] dnsCookieSecret = bR.ReadBytes(bR.ReadByte());
                DnsCookieSecret = dnsCookieSecret.Length == DnsCookie.SECRET_LENGTH ? dnsCookieSecret : null;

                string httpUserAgent = bR.BaseStream.ReadShortString();
                HttpUserAgent = httpUserAgent.Length == 0 ? null : httpUserAgent;

                QnameMinimizationFallback = bR.ReadBoolean();
            }
            else
            {
                EnableDnsCookies = true;
                DnsCookieSecret = null;
                HttpUserAgent = null;
                QnameMinimizationFallback = true;
                _randomizeName = true;
            }

            if (version >= 16)
                _cacheZoneManager.MaximumMemoryMegabytes = bR.ReadInt32();
            else
                _cacheZoneManager.MaximumMemoryMegabytes = 0;

            if (version >= 17)
                EnableCache = bR.ReadBoolean();
            else
                EnableCache = true;

            if (_dnsTlsCertificatePath is null)
            {
                StopTlsCertificateUpdateTimer();
            }
            else
            {
                string dnsTlsCertificateAbsolutePath = ConvertToAbsolutePath(_dnsTlsCertificatePath);

                try
                {
                    LoadDnsTlsCertificate(dnsTlsCertificateAbsolutePath, _dnsTlsCertificatePassword, ConvertToAbsolutePath(_dnsTlsCertificateKeyPath));
                }
                catch (Exception ex)
                {
                    _log.Write("DNS Server encountered an error while loading DNS Server TLS certificate: " + dnsTlsCertificateAbsolutePath, ex);
                }

                StartTlsCertificateUpdateTimer();
            }

            _blockedZoneManager.UpdateServerDomain();
            _blockListZoneManager.UpdateServerDomain();

            UpdateAutoAllowedNames();
        }

        private void WriteConfigTo(Stream s)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("DC"));
            bW.Write((byte)17);

            s.WriteShortString(_serverDomain);

            {
                bW.Write(Convert.ToByte(_localEndPoints.Count));

                foreach (IPEndPoint localEP in _localEndPoints)
                    localEP.WriteTo(bW);
            }

            AuthZoneInfo.WriteNetworkAddressesTo(DnsClientConnection.IPv4SourceAddresses, bW);
            AuthZoneInfo.WriteNetworkAddressesTo(DnsClientConnection.IPv6SourceAddresses, bW);

            bW.Write(_authZoneManager.DefaultRecordTtl);
            bW.Write(_authZoneManager.DefaultNsRecordTtl);
            bW.Write(_authZoneManager.DefaultSoaRecordTtl);

            if (_defaultResponsiblePerson is null)
                s.WriteShortString("");
            else
                s.WriteShortString(_defaultResponsiblePerson.Address);


            bW.Write(_enableCheckForUpdate);
            bW.Write(false);

            bW.Write((byte)_ipv6Mode);
            bW.Write(_enableUdpSocketPool);

            ushort[] socketPoolExcludedPorts = UdpClientConnection.SocketPoolExcludedPorts;
            if (socketPoolExcludedPorts is null)
            {
                bW.Write(ushort.MinValue);
            }
            else
            {
                bW.Write(Convert.ToUInt16(socketPoolExcludedPorts.Length));

                foreach (ushort excludedPort in socketPoolExcludedPorts)
                    bW.Write(excludedPort);
            }

            bW.Write(_udpPayloadSize);
            bW.Write(_dnssecValidation);

            bW.Write(_eDnsClientSubnet);
            bW.Write(_eDnsClientSubnetIPv4PrefixLength);
            bW.Write(_eDnsClientSubnetIPv6PrefixLength);

            if (_eDnsClientSubnetIpv4Override is null)
            {
                bW.Write(false);
            }
            else
            {
                bW.Write(true);
                _eDnsClientSubnetIpv4Override.WriteTo(bW);
            }

            if (_eDnsClientSubnetIpv6Override is null)
            {
                bW.Write(false);
            }
            else
            {
                bW.Write(true);
                _eDnsClientSubnetIpv6Override.WriteTo(bW);
            }

            WritePrefixLimits(bW, _qpsPrefixLimitsIPv4);
            WritePrefixLimits(bW, _qpsPrefixLimitsIPv6);

            bW.Write(_rateLimitBurstSeconds);
            bW.Write(_rateLimitUdpTruncationPercentage);

            AuthZoneInfo.WriteNetworkAddressesTo(_rateLimitBypassList, bW);

            bW.Write(_clientTimeout);
            bW.Write(_tcpSendTimeout);
            bW.Write(_tcpReceiveTimeout);
            bW.Write(_quicIdleTimeout);
            bW.Write(_quicMaxInboundStreams);
            bW.Write(_listenBacklog);
            bW.Write(_udpSendBufferSizeKB);
            bW.Write(_udpReceiveBufferSizeKB);
            bW.Write(MaxConcurrentResolutionsPerCore);

            bW.Write(_enableEDnsClientSubnetSourceAddress);
            bW.Write(_enableDnsOverUdpProxy);
            bW.Write(_enableDnsOverTcpProxy);
            bW.Write(_enableDnsOverHttp);
            bW.Write(_enableDnsOverHttpUnixSocket);
            bW.Write(_enableDnsOverHttpsUnixSocket);
            bW.Write(_enableDnsOverTls);
            bW.Write(_enableDnsOverHttps);
            bW.Write(_enableDnsOverHttp3);
            bW.Write(_enableDnsOverQuic);

            bW.Write(_enableDnsOverHttpHelpRedirect);

            bW.Write(_dnsOverUdpProxyPort);
            bW.Write(_dnsOverTcpProxyPort);
            bW.Write(_dnsOverHttpPort);
            s.WriteShortString(_dnsOverHttpUnixSocket ?? "");
            s.WriteShortString(_dnsOverHttpsUnixSocket ?? "");
            bW.Write(_dnsOverTlsPort);
            bW.Write(_dnsOverHttpsPort);
            bW.Write(_dnsOverQuicPort);

            AuthZoneInfo.WriteNetworkACLTo(_dnsReverseProxyNetworkACL, bW);

            if (_dnsTlsCertificatePath == null)
                s.WriteShortString(string.Empty);
            else
                s.WriteShortString(_dnsTlsCertificatePath);

            if (_dnsTlsCertificatePassword == null)
                s.WriteShortString(string.Empty);
            else
                s.WriteShortString(_dnsTlsCertificatePassword);

            s.WriteShortString(_dnsOverHttpRealIpHeader);

            bW.Write((byte)_recursion);
            AuthZoneInfo.WriteNetworkACLTo(_recursionNetworkACL, bW);

            bW.Write(_randomizeName);
            bW.Write(_qnameMinimization);
            bW.Write(_locallyServedDnsZones);

            bW.Write(_resolverRetries);
            bW.Write(_resolverTimeout);
            bW.Write(_resolverConcurrency);
            bW.Write(_resolverMaxStackCount);

            bW.Write(_saveCacheToDisk);
            bW.Write(_serveStale);
            bW.Write(_cacheZoneManager.ServeStaleTtl);
            bW.Write(_cacheZoneManager.ServeStaleAnswerTtl);
            bW.Write(_cacheZoneManager.ServeStaleResetTtl);
            bW.Write(_serveStaleMaxWaitTime);

            bW.Write(_cacheZoneManager.MaximumEntries);
            bW.Write(_cacheZoneManager.MinimumRecordTtl);
            bW.Write(_cacheZoneManager.MaximumRecordTtl);
            bW.Write(_cacheZoneManager.NegativeRecordTtl);
            bW.Write(_cacheZoneManager.FailureRecordTtl);

            bW.Write(_cachePrefetchEligibility);
            bW.Write(_cachePrefetchTrigger);

            bW.Write(_enableBlocking);
            bW.Write(_allowTxtBlockingReport);

            AuthZoneInfo.WriteNetworkAddressesTo(_blockingBypassList, bW);

            bW.Write((byte)_blockingType);

            {
                bW.Write(Convert.ToByte(_customBlockingARecords.Count + _customBlockingAAAARecords.Count));

                foreach (DnsARecordData record in _customBlockingARecords)
                    record.Address.WriteTo(bW);

                foreach (DnsAAAARecordData record in _customBlockingAAAARecords)
                    record.Address.WriteTo(bW);
            }

            bW.Write(_blockingAnswerTtl);

            if (_proxy == null)
            {
                bW.Write((byte)NetProxyType.None);
            }
            else
            {
                bW.Write((byte)_proxy.Type);
                s.WriteShortString(_proxy.Address);
                bW.Write(_proxy.Port);

                NetworkCredential credential = _proxy.Credential;

                if (credential == null)
                {
                    bW.Write(false);
                }
                else
                {
                    bW.Write(true);
                    s.WriteShortString(credential.UserName);
                    s.WriteShortString(credential.Password);
                }

                {
                    bW.Write(Convert.ToByte(_proxy.BypassList.Count));

                    foreach (NetProxyBypassItem item in _proxy.BypassList)
                        s.WriteShortString(item.Value);
                }
            }

            if (_forwarders == null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(_forwarders.Count));

                foreach (NameServerAddress forwarder in _forwarders)
                    forwarder.WriteTo(bW);
            }

            bW.Write(_concurrentForwarding);
            bW.Write(_forwarderRetries);
            bW.Write(_forwarderTimeout);
            bW.Write(_forwarderConcurrency);

            bW.Write(_resolverLog is null);
            bW.Write(_queryLog is not null);
            bW.Write(_statsManager.EnableInMemoryStats);
            bW.Write(_statsManager.MaxStatFileDays);

            bW.Write(IPv6Reachability.Enabled);
            bW.Write(_udpListenerThreads);
            bW.Write(_maxPendingStreamRequests);

            bW.Write(_requestFilterMalformed);
            bW.Write(_requestFilterMaxSize);
            bW.Write(_requestFilterOpcode);
            bW.Write(_requestFilterClass);
            bW.Write(_requestFilterAny);
            bW.Write(_requestFilterZoneTransfer);
            bW.Write(_requestFilterNoRecursion);
            bW.Write(_requestFilterEdnsVersion);
            bW.Write(_requestFilterRefuseOnly);
            bW.Write(DnsClient.PostQuantumDowngradeProtection);

            s.WriteShortString(_blockingReportText ?? string.Empty);
            bW.Write(_blockingNegativeTtl);

            s.WriteShortString(_dnsTlsCertificateKeyPath ?? string.Empty);
            bW.Write(_enableDdr);
            bW.Write(_ddrOnlyUnencrypted);

            bW.Write(Convert.ToByte(_clientBlockListManager.ListUrls.Count));

            foreach (Uri listUrl in _clientBlockListManager.ListUrls)
                s.WriteShortString(listUrl.AbsoluteUri);

            bW.Write(_clientBlockListManager.UpdateIntervalHours);

            bW.Write((byte)_do53Mode);
            bW.Write(_cacheZoneManager.MaximumNegativeRecordTtl);
            bW.Write(_blockFirefoxCanaryDomain);
            bW.Write(_forceChromePreflight);
            bW.Write(_systemMonitor.Enabled);
            bW.Write(_watchdog.Enabled);
            bW.Write((byte)_ianaDataManager.RootZoneMode);
            bW.Write((byte)_ianaDataManager.ArpaZoneMode);
            bW.Write((byte)_ianaDataManager.TrustAnchorMode);
            bW.Write((byte)_eDnsPaddingMode);
            bW.Write(_ddrProxyDoh);
            bW.Write(_ddrProxyDohPort);
            bW.Write(_ddrProxyDohHttp3);
            bW.Write((byte)_cachePrefetchTriggerPercent);
            bW.Write(_cacheZoneManager.AggressiveNsec);

            bW.Write(_enableDnsCookies);

            if (_dnsCookieSecretConfigured)
            {
                bW.Write((byte)_dnsCookieSecret.Length);
                bW.Write(_dnsCookieSecret);
            }
            else
            {
                bW.Write((byte)0);
            }

            bW.BaseStream.WriteShortString(_httpUserAgent ?? string.Empty);
            bW.Write(ZenitiumLibrary.Net.Dns.QnameMinimizationFallback.Enabled);
            bW.Write(_cacheZoneManager.MaximumMemoryMegabytes);
            bW.Write(_cacheZoneManager.Enabled);
        }

        #endregion

        #region tls

        private void StartTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer is null)
            {
                _tlsCertificateUpdateTimer = new Timer(delegate (object state)
                {
                    if (!string.IsNullOrEmpty(_dnsTlsCertificatePath))
                    {
                        string dnsTlsCertificatePath = ConvertToAbsolutePath(_dnsTlsCertificatePath);

                        try
                        {
                            string dnsTlsCertificateKeyPath = ConvertToAbsolutePath(_dnsTlsCertificateKeyPath);
                            DateTime lastModifiedOn = TlsCertificateFile.GetLastWriteTimeUtc(dnsTlsCertificatePath, dnsTlsCertificateKeyPath);

                            if ((lastModifiedOn != DateTime.MinValue) && (lastModifiedOn != _dnsTlsCertificateLastModifiedOn))
                                LoadDnsTlsCertificate(dnsTlsCertificatePath, _dnsTlsCertificatePassword, dnsTlsCertificateKeyPath);
                        }
                        catch (Exception ex)
                        {
                            _log.Write("DNS Server encountered an error while updating DNS Server TLS Certificate: " + dnsTlsCertificatePath, ex);
                        }
                    }

                }, null, TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL, TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL);
            }
        }

        private void StopTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer is not null)
            {
                _tlsCertificateUpdateTimer.Dispose();
                _tlsCertificateUpdateTimer = null;
            }
        }

        private void LoadDnsTlsCertificate(string tlsCertificatePath, string tlsCertificatePassword, string tlsCertificateKeyPath)
        {
            SslStreamCertificateContext certificateContext = TlsCertificateFile.Load(tlsCertificatePath, tlsCertificateKeyPath, tlsCertificatePassword, out X509Certificate2 serverCertificate);

            _dotSslServerAuthenticationOptions = new SslServerAuthenticationOptions()
            {
                ServerCertificateContext = certificateContext
            };

            _doqSslServerAuthenticationOptions = new SslServerAuthenticationOptions()
            {
                ApplicationProtocols = _doqApplicationProtocols,
                ServerCertificateContext = certificateContext
            };

            List<SslApplicationProtocol> applicationProtocols = new List<SslApplicationProtocol>();

            if (_enableDnsOverHttp3)
                applicationProtocols.Add(new SslApplicationProtocol("h3"));

            if (IsHttp2Supported())
                applicationProtocols.Add(new SslApplicationProtocol("h2"));

            applicationProtocols.Add(new SslApplicationProtocol("http/1.1"));

            _dohSslServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = applicationProtocols,
                ServerCertificateContext = certificateContext,
            };

            _dnsTlsCertificate = serverCertificate;
            _dnsTlsCertificateLastModifiedOn = TlsCertificateFile.GetLastWriteTimeUtc(tlsCertificatePath, tlsCertificateKeyPath);

            UpdateAutoAllowedNames();

            _log.Write("DNS Server TLS certificate was loaded: " + tlsCertificatePath);
        }

        public void RemoveDnsTlsCertificate()
        {
            _dotSslServerAuthenticationOptions = null;
            _doqSslServerAuthenticationOptions = null;
            _dohSslServerAuthenticationOptions = null;

            _dnsTlsCertificate = null;
            _dnsTlsCertificatePath = null;
            _dnsTlsCertificatePassword = null;
            _dnsTlsCertificateKeyPath = null;

            UpdateAutoAllowedNames();

            StopTlsCertificateUpdateTimer();
        }

        public void SetDnsTlsCertificate(string dnsTlsCertificatePath, string dnsTlsCertificatePassword = null, bool throwException = false, string dnsTlsCertificateKeyPath = null)
        {
            if (string.IsNullOrEmpty(dnsTlsCertificatePath))
                throw new ArgumentNullException(nameof(dnsTlsCertificatePath), "DNS optional protocols TLS certificate path cannot be null or empty.");

            if (dnsTlsCertificatePath.Length > 255)
                throw new ArgumentException("DNS optional protocols TLS certificate path length cannot exceed 255 characters.", nameof(dnsTlsCertificatePath));

            if (dnsTlsCertificatePassword?.Length > 255)
                throw new ArgumentException("DNS optional protocols TLS certificate password length cannot exceed 255 characters.", nameof(dnsTlsCertificatePassword));

            if (dnsTlsCertificateKeyPath?.Length > 255)
                throw new ArgumentException("DNS optional protocols TLS private key path length cannot exceed 255 characters.", nameof(dnsTlsCertificateKeyPath));

            if (string.IsNullOrEmpty(dnsTlsCertificateKeyPath))
                dnsTlsCertificateKeyPath = null;

            dnsTlsCertificatePath = ConvertToAbsolutePath(dnsTlsCertificatePath);
            string dnsTlsCertificateKeyAbsolutePath = ConvertToAbsolutePath(dnsTlsCertificateKeyPath);

            if (throwException)
            {
                LoadDnsTlsCertificate(dnsTlsCertificatePath, dnsTlsCertificatePassword, dnsTlsCertificateKeyAbsolutePath);
            }
            else
            {
                try
                {
                    LoadDnsTlsCertificate(dnsTlsCertificatePath, dnsTlsCertificatePassword, dnsTlsCertificateKeyAbsolutePath);
                }
                catch (Exception ex)
                {
                    _log.Write("DNS Server encountered an error while loading DNS Server TLS certificate: " + dnsTlsCertificatePath, ex);
                }
            }

            _dnsTlsCertificatePath = ConvertToRelativePath(dnsTlsCertificatePath);
            _dnsTlsCertificatePassword = dnsTlsCertificatePassword;
            _dnsTlsCertificateKeyPath = dnsTlsCertificateKeyAbsolutePath is null ? null : ConvertToRelativePath(dnsTlsCertificateKeyAbsolutePath);

            StartTlsCertificateUpdateTimer();
        }

        private string ConvertToRelativePath(string path)
        {
            string configFolder = _configFolder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

            if (path.StartsWith(configFolder, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                path = path.Substring(configFolder.Length).TrimStart(Path.DirectorySeparatorChar);

            return path;
        }

        private string ConvertToAbsolutePath(string path)
        {
            if (path is null)
                return null;

            if (Path.IsPathRooted(path))
                return path;

            return Path.Combine(_configFolder, path);
        }

        #endregion

        #region private

        private Socket GetUdpListenerSocket(AddressFamily addressFamily)
        {
            Socket udpListener = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);

            #region this code ignores ICMP port unreachable responses which creates SocketException in ReceiveFrom()

            if (Environment.OSVersion.Platform == PlatformID.Win32NT)
            {
                const uint IOC_IN = 0x80000000;
                const uint IOC_VENDOR = 0x18000000;
                const uint SIO_UDP_CONNRESET = IOC_IN | IOC_VENDOR | 12;

                udpListener.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { Convert.ToByte(false) }, null);
            }

            #endregion

            if (Environment.OSVersion.Platform == PlatformID.Unix)
                udpListener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);

            udpListener.SendBufferSize = _udpSendBufferSizeKB * 1024;
            udpListener.ReceiveBufferSize = _udpReceiveBufferSizeKB * 1024;

            return udpListener;
        }

        private void SocketBindToDevice(Socket socket, InterfaceEndPoint intEP, DnsTransportProtocol protocol)
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                try
                {
                    socket.SetRawSocketOption(SOL_SOCKET, SO_BINDTODEVICE, Encoding.ASCII.GetBytes(intEP.InterfaceName));
                    _log.Write(intEP, protocol, $"Socket was bound to device '{intEP.InterfaceName}' successfully.");
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                try
                {
                    int? interfaceIndex = GetInterfaceIndex(intEP.InterfaceName);
                    if (interfaceIndex is not null)
                    {
                        byte[] interfaceIndexBytes = BitConverter.GetBytes(interfaceIndex.Value);

                        if (intEP.AddressFamily == AddressFamily.InterNetwork)
                            socket.SetRawSocketOption(IPPROTO_IP, IP_BOUND_IF, interfaceIndexBytes);
                        else
                            socket.SetRawSocketOption(IPPROTO_IPV6, IPV6_BOUND_IF, interfaceIndexBytes);

                        _log.Write(intEP, protocol, $"Socket was bound to device '{intEP.InterfaceName} ({interfaceIndex})' successfully.");
                    }
                    else
                    {
                        _log.Write(intEP, protocol, $"Socket failed to bind to device '{intEP.InterfaceName}': interface not found.");
                    }
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }
        }

        private static int? GetInterfaceIndex(string interfaceName)
        {
            foreach (NetworkInterface ni in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.Name.Equals(interfaceName, StringComparison.Ordinal))
                {
                    IPInterfaceProperties ipProps = ni.GetIPProperties();
                    return ipProps.GetIPv4Properties()?.Index ?? ipProps.GetIPv6Properties()?.Index;
                }
            }

            return null;
        }

        private void StartUdpListenerThreads(Socket udpListener, DnsTransportProtocol protocol)
        {
            int listenerThreadCount = _udpListenerThreads > 0 ? _udpListenerThreads : Math.Min(Environment.ProcessorCount, 8);
            UdpListenerGate gate = listenerThreadCount > 1 ? new UdpListenerGate(udpListener, listenerThreadCount - 1) : null;

            for (int i = 0; i < listenerThreadCount; i++)
            {
                bool isHelper = i > 0;

                Thread thread = new Thread(delegate ()
                {
                    ReadUdpRequests(udpListener, protocol, gate, isHelper);
                });

                thread.Name = "UdpListener";
                thread.IsBackground = true;
                thread.Start();
            }
        }

        private void ReadUdpRequests(Socket udpListener, DnsTransportProtocol protocol, UdpListenerGate gate, bool isHelper)
        {
            UdpLimitedResponse limitedResponse;
            byte[] recvBuffer;

            if (protocol == DnsTransportProtocol.UdpProxy)
                recvBuffer = new byte[DnsDatagram.EDNS_MAX_UDP_PAYLOAD_SIZE + 256];
            else
                recvBuffer = new byte[DnsDatagram.EDNS_MAX_UDP_PAYLOAD_SIZE];

            byte[] parseBuffer = new byte[recvBuffer.Length];
            using MemoryStream recvBufferStream = new MemoryStream(parseBuffer);

            try
            {
                IPEndPoint localEP = udpListener.LocalEndPoint as IPEndPoint;
                int localPort = localEP.Port;
                EndPoint epAny;
                bool enableSocketBindingToSourceEP;

                switch (udpListener.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        epAny = new IPEndPoint(IPAddress.Any, 0);
                        enableSocketBindingToSourceEP = localEP.Address.Equals(IPAddress.Any);
                        break;

                    case AddressFamily.InterNetworkV6:
                        epAny = new IPEndPoint(IPAddress.IPv6Any, 0);
                        enableSocketBindingToSourceEP = localEP.Address.Equals(IPAddress.IPv6Any);
                        break;

                    default:
                        throw new NotSupportedException("AddressFamily not supported.");
                }

                int receivedBytes;
                EndPoint remoteEndPoint;
                SocketFlags socketFlags;
                IPPacketInformation packetInformation;
                IPEndPoint sourceEP = null;
                NameServerAddress sourceNameServer = null;

                while (true)
                {
                    if (isHelper)
                        gate.ParkWhileIdle();
                    else
                        gate?.TrackBacklog();

                    remoteEndPoint = epAny;
                    socketFlags = SocketFlags.None;

                    try
                    {
                        receivedBytes = udpListener.ReceiveMessageFrom(recvBuffer, ref socketFlags, ref remoteEndPoint, out packetInformation);
                    }
                    catch (SocketException ex)
                    {
                        switch (ex.SocketErrorCode)
                        {
                            case SocketError.ConnectionReset:
                            case SocketError.HostUnreachable:
                            case SocketError.MessageSize:
                            case SocketError.NetworkReset:
                                receivedBytes = 0;
                                packetInformation = default;
                                break;

                            default:
                                throw;
                        }
                    }

                    if (receivedBytes < 1)
                    {
                        if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                            return;
                    }
                    else
                    {
                        if (remoteEndPoint is not IPEndPoint remoteEP)
                            continue;

                        if ((protocol == DnsTransportProtocol.Udp) && IsClientBlocked(remoteEP.Address))
                            continue;

                        try
                        {
                            recvBufferStream.SetLength(receivedBytes);
                            Buffer.BlockCopy(recvBuffer, 0, parseBuffer, 0, receivedBytes);
                            recvBufferStream.Position = 0;

                            IPEndPoint returnEP = remoteEP;

                            if (protocol == DnsTransportProtocol.UdpProxy)
                            {
                                if (!NetworkAccessControl.IsAddressAllowed(remoteEP.Address, _dnsReverseProxyNetworkACL))
                                {
                                    continue;
                                }

                                ProxyProtocolStream proxyStream = ProxyProtocolStream.CreateAsServerAsync(recvBufferStream).GetAwaiter().GetResult();

                                if (!proxyStream.IsLocal)
                                    remoteEP = new IPEndPoint(proxyStream.SourceAddress, proxyStream.SourcePort);

                                recvBufferStream.Position = proxyStream.DataOffset;
                            }

                            DnsDatagram request = DnsDatagram.ReadFrom(recvBufferStream);

                            IPAddress sourceAddress = packetInformation.Address;

                            if ((sourceNameServer is null) || !sourceEP.Address.Equals(sourceAddress))
                            {
                                sourceEP = new IPEndPoint(sourceAddress, localPort);
                                sourceNameServer = new NameServerAddress(sourceEP, protocol);
                            }

                            request.SetMetadata(sourceNameServer);

                            if ((protocol == DnsTransportProtocol.Udp) && _enableEDnsClientSubnetSourceAddress)
                            {
                                if (NetworkAccessControl.IsAddressAllowed(remoteEP.Address, _dnsReverseProxyNetworkACL))
                                {
                                    EDnsClientSubnetOptionData ecs = request.GetEDnsClientSubnetOption(true);
                                    if (ecs is not null)
                                    {
                                        switch (ecs.SourcePrefixLength)
                                        {
                                            case 32:
                                                if (ecs.Family == EDnsClientSubnetAddressFamily.IPv4)
                                                    remoteEP = new IPEndPoint(ecs.Address, 0);

                                                break;

                                            case 128:
                                                if (ecs.Family == EDnsClientSubnetAddressFamily.IPv6)
                                                    remoteEP = new IPEndPoint(ecs.Address, 0);

                                                break;
                                        }
                                    }
                                }
                            }

                            if (((protocol != DnsTransportProtocol.Udp) || !ReferenceEquals(remoteEP, returnEP)) && IsClientBlocked(remoteEP.Address))
                                continue;

                            if (IsRateLimited(remoteEP.Address, DnsTransportProtocol.Udp))
                            {
                                DnsCookieState cookieState = _enableDnsCookies ? DnsCookie.GetState(request, remoteEP.Address, _dnsCookieSecret) : DnsCookieState.None;

                                if ((cookieState == DnsCookieState.Valid) && !IsRateLimited(remoteEP.Address, DnsTransportProtocol.Tcp))
                                {
                                    limitedResponse = UdpLimitedResponse.None;
                                }
                                else if (SendRateLimitedTruncationResponse())
                                {
                                    limitedResponse = (cookieState == DnsCookieState.ClientOnly) || (cookieState == DnsCookieState.Invalid) ? UdpLimitedResponse.BadCookie : UdpLimitedResponse.Truncation;
                                }
                                else
                                {
                                    _statsManager.QueueUpdate(null, remoteEP, protocol, null, true);
                                    continue;
                                }
                            }
                            else
                            {
                                limitedResponse = UdpLimitedResponse.None;
                            }

                            if (enableSocketBindingToSourceEP)
                            {
                                Socket newUdpListener = null;

                                try
                                {
                                    List<Socket> listeners;

                                    switch (protocol)
                                    {
                                        case DnsTransportProtocol.Udp:
                                            listeners = _udpListeners;
                                            break;

                                        case DnsTransportProtocol.UdpProxy:
                                            listeners = _udpProxyListeners;
                                            break;

                                        default:
                                            throw new InvalidOperationException();
                                    }

                                    lock (listeners)
                                    {
                                        foreach (Socket socket in listeners)
                                        {
                                            if (socket.LocalEndPoint.Equals(sourceEP))
                                            {
                                                newUdpListener = socket;
                                                break;
                                            }
                                        }

                                        if (newUdpListener is null)
                                        {
                                            newUdpListener = GetUdpListenerSocket(sourceEP.AddressFamily);

                                            newUdpListener.Bind(sourceEP);

                                            listeners.Add(newUdpListener);

                                            _log.Write(sourceEP, protocol, "DNS Server was bound successfully.");

                                            StartUdpListenerThreads(newUdpListener, protocol);
                                        }
                                    }
                                }
                                catch (Exception ex)
                                {
                                    enableSocketBindingToSourceEP = false;

                                    _log.Write(sourceEP, protocol, "DNS Server failed to bind.", ex);
                                }

                                if (newUdpListener is not null)
                                {
                                    _ = ProcessUdpRequestAsync(newUdpListener, remoteEP, returnEP, protocol, request, limitedResponse);

                                    continue;
                                }
                            }

                            _ = ProcessUdpRequestAsync(udpListener, remoteEP, returnEP, protocol, request, limitedResponse);
                        }
                        catch (EndOfStreamException)
                        {
                        }
                        catch (Exception ex)
                        {
                            _log.Write(remoteEP, protocol, ex);
                        }
                    }
                }
            }
            catch (ObjectDisposedException)
            {
            }
            catch (SocketException ex)
            {
                switch (ex.SocketErrorCode)
                {
                    case SocketError.OperationAborted:
                    case SocketError.Interrupted:
                        break;

                    default:
                        if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                            return;

                        _log.Write(ex);
                        break;
                }
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return;

                _log.Write(ex);
            }
        }

        private async Task ProcessUdpRequestAsync(Socket udpListener, IPEndPoint remoteEP, IPEndPoint returnEP, DnsTransportProtocol protocol, DnsDatagram request, UdpLimitedResponse limitedResponse)
        {
            long startTimestamp = Stopwatch.GetTimestamp();

            try
            {
                bool recursionAllowed = IsRecursionAllowed(remoteEP.Address);
                DnsDatagram response;

                switch (limitedResponse)
                {
                    case UdpLimitedResponse.Truncation:
                        response = new DnsDatagram(request.Identifier, true, request.OPCODE, false, true, request.RecursionDesired, recursionAllowed, false, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };
                        response = ApplyDnsCookie(request, remoteEP.Address, response);
                        break;

                    case UdpLimitedResponse.BadCookie:
                        response = new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, recursionAllowed, false, request.CheckingDisabled, DnsResponseCode.BADCOOKIE, request.Question, null, null, null, _udpPayloadSize, EDnsHeaderFlags.None, [DnsCookie.CreateServerCookieOption(DnsCookie.GetCookieOption(request).ClientCookie, remoteEP.Address, _dnsCookieSecret)]) { Tag = ResponseTypeTags.Authoritative };
                        break;

                    default:
                        response = await ProcessRequestAsync(request, remoteEP, protocol, recursionAllowed);
                        if (response is null)
                        {
                            _statsManager.QueueUpdate(null, remoteEP, protocol, null, false);
                            return;
                        }

                        response = ApplyDnsCookie(request, remoteEP.Address, response);
                        break;
                }

                int sendBufferSize;

                if (request.EDNS is null)
                    sendBufferSize = 512;
                else if (request.EDNS.UdpPayloadSize > _udpPayloadSize)
                    sendBufferSize = _udpPayloadSize;
                else
                    sendBufferSize = request.EDNS.UdpPayloadSize;

                MemoryStream sendBufferStream = UdpSendBuffers.GetStream(sendBufferSize);

                try
                {
                    response.WriteTo(sendBufferStream);
                }
                catch (NotSupportedException)
                {
                    if (response.IsSigned)
                    {
                        response = new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, true, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, DnsResponseCode.NoError, response.Question, null, null, new DnsResourceRecord[] { response.Additional[response.Additional.Count - 1] }, request.EDNS is null ? ushort.MinValue : _udpPayloadSize) { Tag = ResponseTypeTags.Authoritative };
                    }
                    else
                    {
                        switch (response.Question[0].Type)
                        {
                            case DnsResourceRecordType.MX:
                            case DnsResourceRecordType.SRV:
                            case DnsResourceRecordType.SVCB:
                            case DnsResourceRecordType.HTTPS:
                                response = response.CloneWithoutGlueRecords();
                                sendBufferStream.Position = 0;

                                try
                                {
                                    response.WriteTo(sendBufferStream);
                                }
                                catch (NotSupportedException)
                                {
                                    response = new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, true, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, response.RCODE, response.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize) { Tag = ResponseTypeTags.Authoritative };
                                }
                                break;

                            case DnsResourceRecordType.IXFR:
                                response = new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, false, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, response.RCODE, response.Question, new DnsResourceRecord[] { response.Answer[0] }, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize) { Tag = ResponseTypeTags.Authoritative };
                                break;

                            default:
                                response = new DnsDatagram(response.Identifier, true, response.OPCODE, response.AuthoritativeAnswer, true, response.RecursionDesired, response.RecursionAvailable, response.AuthenticData, response.CheckingDisabled, response.RCODE, response.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize) { Tag = ResponseTypeTags.Authoritative };
                                break;
                        }
                    }

                    sendBufferStream.Position = 0;
                    response.WriteTo(sendBufferStream);
                }

                int responseSize = (int)sendBufferStream.Position;

                udpListener.SendTo(sendBufferStream.GetBuffer(), 0, responseSize, SocketFlags.None, returnEP);

                _queryLog?.Write(remoteEP, protocol, request, response);
                _statsManager.QueueUpdate(request, remoteEP, protocol, response, false, Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds, responseSize);
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return;

                _queryLog?.Write(remoteEP, protocol, request, null);
                _log.Write(remoteEP, protocol, ex);
            }
        }

        private async Task AcceptConnectionAsync(Socket tcpListener, DnsTransportProtocol protocol)
        {
            IPEndPoint localEP = tcpListener.LocalEndPoint as IPEndPoint;

            try
            {
                tcpListener.SendTimeout = _tcpSendTimeout;
                tcpListener.ReceiveTimeout = _tcpReceiveTimeout;
                tcpListener.NoDelay = true;

                while (true)
                {
                    Socket socket = await tcpListener.AcceptAsync();

                    if ((socket.RemoteEndPoint is IPEndPoint acceptedEP) && IsClientBlocked(acceptedEP.Address))
                    {
                        socket.Dispose();
                        continue;
                    }

                    _ = ProcessConnectionAsync(socket, protocol);
                }
            }
            catch (SocketException ex)
            {
                if (ex.SocketErrorCode == SocketError.OperationAborted)
                    return;

                _log.Write(localEP, protocol, ex);
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return;

                _log.Write(localEP, protocol, ex);
            }
        }

        private async Task ProcessConnectionAsync(Socket socket, DnsTransportProtocol protocol)
        {
            IPEndPoint remoteEP = null;

            try
            {
                remoteEP = socket.RemoteEndPoint as IPEndPoint;

                switch (protocol)
                {
                    case DnsTransportProtocol.Tcp:
                        await ReadStreamRequestAsync(new NetworkStream(socket), remoteEP, new NameServerAddress(socket.LocalEndPoint, DnsTransportProtocol.Tcp), protocol);
                        break;

                    case DnsTransportProtocol.Tls:
                        SslStream tlsStream = new SslStream(new NetworkStream(socket));
                        string serverName = null;

                        try
                        {
                            await ZenitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                            {
                                return tlsStream.AuthenticateAsServerAsync(delegate (SslStream stream, SslClientHelloInfo clientHelloInfo, object state, CancellationToken cancellationToken)
                                {
                                    serverName = clientHelloInfo.ServerName;
                                    return ValueTask.FromResult(_dotSslServerAuthenticationOptions);
                                }, null, cancellationToken1);
                            }, _tcpReceiveTimeout);
                        }
                        catch (NotSupportedException)
                        {
                            return;
                        }

                        NameServerAddress dnsEP;

                        if (string.IsNullOrEmpty(serverName) || !DnsClient.IsDomainNameValid(serverName))
                            dnsEP = new NameServerAddress(socket.LocalEndPoint, DnsTransportProtocol.Tls);
                        else
                            dnsEP = new NameServerAddress(serverName, socket.LocalEndPoint as IPEndPoint, DnsTransportProtocol.Tls);

                        await ReadStreamRequestAsync(tlsStream, remoteEP, dnsEP, protocol);
                        break;

                    case DnsTransportProtocol.TcpProxy:
                        if (!NetworkAccessControl.IsAddressAllowed(remoteEP.Address, _dnsReverseProxyNetworkACL))
                        {
                            return;
                        }

                        ProxyProtocolStream proxyStream = await ZenitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                        {
                            return ProxyProtocolStream.CreateAsServerAsync(new NetworkStream(socket), cancellationToken1);
                        }, _tcpReceiveTimeout);

                        if (!proxyStream.IsLocal)
                            remoteEP = new IPEndPoint(proxyStream.SourceAddress, proxyStream.SourcePort);

                        await ReadStreamRequestAsync(proxyStream, remoteEP, new NameServerAddress(socket.LocalEndPoint, DnsTransportProtocol.Tcp), protocol);
                        break;

                    default:
                        throw new InvalidOperationException();
                }
            }
            catch (AuthenticationException)
            {
            }
            catch (TimeoutException)
            {
            }
            catch (IOException)
            {
            }
            catch (Exception ex)
            {
                _log.Write(remoteEP, protocol, ex);
            }
            finally
            {
                socket.Dispose();
            }
        }

        private async Task ReadStreamRequestAsync(Stream stream, IPEndPoint remoteEP, NameServerAddress dnsEP, DnsTransportProtocol protocol)
        {
            try
            {
                using MemoryStream readBuffer = new MemoryStream(64);
                using MemoryStream writeBuffer = new MemoryStream(2048);
                using SemaphoreSlim writeSemaphore = new SemaphoreSlim(1, 1);
                int maxPendingStreamRequests = _maxPendingStreamRequests;
                SemaphoreSlim pendingRequests = new SemaphoreSlim(maxPendingStreamRequests, maxPendingStreamRequests);

                while (true)
                {
                    DnsDatagram request;

                    using (CancellationTokenSource cancellationTokenSource = new CancellationTokenSource())
                    {
                        Task<DnsDatagram> task = DnsDatagram.ReadFromTcpAsync(stream, readBuffer, cancellationTokenSource.Token);

                        if ((await Task.WhenAny(task, Task.Delay(_tcpReceiveTimeout, cancellationTokenSource.Token)) != task) && (task.Status != TaskStatus.RanToCompletion))
                        {
                            await stream.DisposeAsync();
                            return;
                        }

                        cancellationTokenSource.Cancel();

                        request = await task;
                        request.SetMetadata(dnsEP);
                    }

                    if ((protocol == DnsTransportProtocol.Tcp) && _enableEDnsClientSubnetSourceAddress)
                    {
                        if (NetworkAccessControl.IsAddressAllowed(remoteEP.Address, _dnsReverseProxyNetworkACL))
                        {
                            EDnsClientSubnetOptionData ecs = request.GetEDnsClientSubnetOption(true);
                            if (ecs is not null)
                            {
                                switch (ecs.SourcePrefixLength)
                                {
                                    case 32:
                                        if (ecs.Family == EDnsClientSubnetAddressFamily.IPv4)
                                            remoteEP = new IPEndPoint(ecs.Address, 0);

                                        break;

                                    case 128:
                                        if (ecs.Family == EDnsClientSubnetAddressFamily.IPv6)
                                            remoteEP = new IPEndPoint(ecs.Address, 0);

                                        break;
                                }
                            }
                        }
                    }

                    if (IsClientBlocked(remoteEP.Address))
                        break;

                    if (IsRateLimited(remoteEP.Address, DnsTransportProtocol.Tcp))
                    {
                        _statsManager.QueueUpdate(null, remoteEP, protocol, null, true);
                        break;
                    }

                    if (!await pendingRequests.WaitAsync(_tcpReceiveTimeout))
                    {
                        await stream.DisposeAsync();
                        return;
                    }

                    _ = ProcessStreamRequestAsync(stream, writeBuffer, writeSemaphore, pendingRequests, remoteEP, request, protocol);
                }
            }
            catch (ObjectDisposedException)
            {
            }
            catch (IOException)
            {
            }
            catch (Exception ex)
            {
                _log.Write(remoteEP, protocol, ex);
            }
        }

        private async Task ProcessStreamRequestAsync(Stream stream, MemoryStream writeBuffer, SemaphoreSlim writeSemaphore, SemaphoreSlim pendingRequests, IPEndPoint remoteEP, DnsDatagram request, DnsTransportProtocol protocol)
        {
            long startTimestamp = Stopwatch.GetTimestamp();

            try
            {
                DnsDatagram response = await ProcessRequestAsync(request, remoteEP, protocol, IsRecursionAllowed(remoteEP.Address));
                if (response is null)
                {
                    await stream.DisposeAsync();

                    _statsManager.QueueUpdate(null, remoteEP, protocol, null, false);
                    return;
                }

                if (protocol == DnsTransportProtocol.Tls)
                    response = ApplyEDnsPadding(request, response);
                else
                    response = ApplyDnsCookie(request, remoteEP.Address, response);

                int responseSize = -1;

                await ZenitiumLibrary.TaskExtensions.TimeoutAsync(async delegate (CancellationToken cancellationToken1)
                {
                    await writeSemaphore.WaitAsync(cancellationToken1);
                    try
                    {
                        await response.WriteToTcpAsync(stream, writeBuffer, cancellationToken1);
                        responseSize = (int)(writeBuffer.Length - 2);
                        await stream.FlushAsync(cancellationToken1);
                    }
                    finally
                    {
                        writeSemaphore.Release();
                    }
                }, _tcpSendTimeout);

                _queryLog?.Write(remoteEP, protocol, request, response);
                _statsManager.QueueUpdate(request, remoteEP, protocol, response, false, Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds, responseSize);
            }
            catch (ObjectDisposedException)
            {
            }
            catch (IOException)
            {
            }
            catch (TimeoutException)
            {
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                if (request is not null)
                    _queryLog?.Write(remoteEP, protocol, request, null);

                _log.Write(remoteEP, protocol, ex);
            }
            finally
            {
                pendingRequests.Release();
            }
        }

        private async Task AcceptQuicConnectionAsync(QuicListener quicListener)
        {
            try
            {
                while (true)
                {
                    try
                    {
                        QuicConnection quicConnection = await quicListener.AcceptConnectionAsync();

                        _ = ProcessQuicConnectionAsync(quicConnection);
                    }
                    catch (AuthenticationException)
                    {
                    }
                    catch (QuicException)
                    {
                    }
                    catch (ArgumentException)
                    {
                    }
                    catch (OperationCanceledException)
                    {
                    }
                }
            }
            catch (ObjectDisposedException)
            {
            }
            catch (Exception ex)
            {
                if ((_state == ServiceState.Stopping) || (_state == ServiceState.Stopped))
                    return;

                _log.Write(quicListener.LocalEndPoint, DnsTransportProtocol.Quic, ex);
            }
        }

        private async Task ProcessQuicConnectionAsync(QuicConnection quicConnection)
        {
            try
            {
                NameServerAddress dnsEP;

                if (string.IsNullOrEmpty(quicConnection.TargetHostName) || !DnsClient.IsDomainNameValid(quicConnection.TargetHostName))
                    dnsEP = new NameServerAddress(quicConnection.LocalEndPoint, DnsTransportProtocol.Quic);
                else
                    dnsEP = new NameServerAddress(quicConnection.TargetHostName, quicConnection.LocalEndPoint, DnsTransportProtocol.Quic);

                while (true)
                {
                    if (IsClientBlocked(quicConnection.RemoteEndPoint.Address))
                        break;

                    if (IsRateLimited(quicConnection.RemoteEndPoint.Address, DnsTransportProtocol.Tcp))
                    {
                        _statsManager.QueueUpdate(null, quicConnection.RemoteEndPoint, DnsTransportProtocol.Quic, null, true);
                        break;
                    }

                    QuicStream quicStream = await quicConnection.AcceptInboundStreamAsync();

                    _ = ProcessQuicStreamRequestAsync(quicStream, quicConnection.RemoteEndPoint, dnsEP);
                }
            }
            catch (QuicException)
            {
            }
            catch (SocketException)
            {
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                _log.Write(quicConnection.RemoteEndPoint, DnsTransportProtocol.Quic, ex);
            }
            finally
            {
                await quicConnection.DisposeAsync();
            }
        }

        private async Task ProcessQuicStreamRequestAsync(QuicStream quicStream, IPEndPoint remoteEP, NameServerAddress dnsEP)
        {
            MemoryStream sharedBuffer = new MemoryStream(512);
            DnsDatagram request = null;

            try
            {
                using (CancellationTokenSource cancellationTokenSource = new CancellationTokenSource())
                {
                    Task<DnsDatagram> task = DnsDatagram.ReadFromTcpAsync(quicStream, sharedBuffer, cancellationTokenSource.Token);

                    if ((await Task.WhenAny(task, Task.Delay(_tcpReceiveTimeout, cancellationTokenSource.Token)) != task) && (task.Status != TaskStatus.RanToCompletion))
                    {
                        quicStream.Abort(QuicAbortDirection.Both, (long)DnsOverQuicErrorCodes.DOQ_UNSPECIFIED_ERROR);
                        return;
                    }

                    cancellationTokenSource.Cancel();

                    request = await task;
                    request.SetMetadata(dnsEP);
                }

                long startTimestamp = Stopwatch.GetTimestamp();

                DnsDatagram response = await ProcessRequestAsync(request, remoteEP, DnsTransportProtocol.Quic, IsRecursionAllowed(remoteEP.Address));
                if (response is null)
                {
                    _statsManager.QueueUpdate(null, remoteEP, DnsTransportProtocol.Quic, null, false);
                    return;
                }

                response = ApplyEDnsPadding(request, response);

                await response.WriteToTcpAsync(quicStream, sharedBuffer);

                _queryLog?.Write(remoteEP, DnsTransportProtocol.Quic, request, response);
                _statsManager.QueueUpdate(request, remoteEP, DnsTransportProtocol.Quic, response, false, Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds, (int)(sharedBuffer.Length - 2));
            }
            catch (IOException)
            {
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                if (request is not null)
                    _queryLog?.Write(remoteEP, DnsTransportProtocol.Quic, request, null);

                _log.Write(remoteEP, DnsTransportProtocol.Quic, ex);
            }
            finally
            {
                await sharedBuffer.DisposeAsync();
                await quicStream.DisposeAsync();
            }
        }

        private async Task ProcessDoHRequestAsync(HttpContext context, CancellationToken cancellationToken)
        {
            IPEndPoint remoteEP = null;
            {
                try
                {
                    IPAddress remoteIP = context.Connection.RemoteIpAddress;
                    if (remoteIP is not null)
                    {
                        if (remoteIP.IsIPv4MappedToIPv6)
                            remoteIP = remoteIP.MapToIPv4();

                        remoteEP = new IPEndPoint(remoteIP, context.Connection.RemotePort);
                    }
                }
                catch
                { }
            }

            DnsDatagram dnsRequest = null;

            try
            {
                HttpRequest request = context.Request;
                HttpResponse response = context.Response;

                if ((remoteEP is null) || NetworkAccessControl.IsAddressAllowed(remoteEP.Address, _dnsReverseProxyNetworkACL))
                {
                    if (!string.IsNullOrEmpty(_dnsOverHttpRealIpHeader))
                    {
                        string xRealIp = context.Request.Headers[_dnsOverHttpRealIpHeader];
                        if (IPAddress.TryParse(xRealIp, out IPAddress address))
                            remoteEP = new IPEndPoint(address, 0);
                    }

                    if (remoteEP is null)
                        remoteEP = IPENDPOINT_ANY_0;
                }
                else
                {
                    if (!request.IsHttps)
                    {
                        response.StatusCode = 403;
                        await response.WriteAsync("DNS-over-HTTPS (DoH) queries are supported only on HTTPS.", cancellationToken);
                        return;
                    }
                }

                if (IsClientBlocked(remoteEP.Address))
                {
                    context.Abort();
                    return;
                }

                if (IsRateLimited(remoteEP.Address, DnsTransportProtocol.Tcp))
                {
                    _statsManager.QueueUpdate(null, remoteEP, DnsTransportProtocol.Https, null, true);

                    response.StatusCode = 429;
                    await response.WriteAsync("Too Many Requests", cancellationToken);
                    return;
                }

                switch (request.Method)
                {
                    case "GET":
                        if (_enableDnsOverHttpHelpRedirect)
                        {
                            bool acceptsDoH = false;

                            string requestAccept = request.Headers.Accept;
                            if (string.IsNullOrEmpty(requestAccept))
                            {
                                acceptsDoH = true;
                            }
                            else
                            {
                                foreach (string mediaType in requestAccept.Split(','))
                                {
                                    if (mediaType.Equals("application/dns-message", StringComparison.OrdinalIgnoreCase))
                                    {
                                        acceptsDoH = true;
                                        break;
                                    }
                                }
                            }

                            if (!acceptsDoH)
                            {
                                response.Redirect((request.IsHttps ? "https://" : "http://") + request.Headers.Host);
                                return;
                            }
                        }

                        string dnsRequestBase64Url = request.Query["dns"];
                        if (string.IsNullOrEmpty(dnsRequestBase64Url))
                        {
                            response.StatusCode = 400;
                            await response.WriteAsync("Bad Request", cancellationToken);
                            return;
                        }

                        dnsRequestBase64Url = dnsRequestBase64Url.Replace('-', '+');
                        dnsRequestBase64Url = dnsRequestBase64Url.Replace('_', '/');

                        int x = dnsRequestBase64Url.Length % 4;
                        if (x > 0)
                            dnsRequestBase64Url = dnsRequestBase64Url.PadRight(dnsRequestBase64Url.Length - x + 4, '=');

                        byte[] dnsRequestData;

                        try
                        {
                            dnsRequestData = Convert.FromBase64String(dnsRequestBase64Url);
                        }
                        catch (FormatException)
                        {
                            response.StatusCode = 400;
                            await response.WriteAsync("Bad Request", cancellationToken);
                            return;
                        }

                        using (MemoryStream mS = new MemoryStream(dnsRequestData))
                        {
                            dnsRequest = DnsDatagram.ReadFrom(mS);
                            dnsRequest.SetMetadata(new NameServerAddress(new Uri(UriHelper.BuildAbsolute(request.Scheme, request.Host, request.PathBase, request.Path)), context.GetLocalIpAddress()));
                        }

                        break;

                    case "POST":
                        if (!string.Equals(request.Headers.ContentType, "application/dns-message", StringComparison.OrdinalIgnoreCase))
                        {
                            response.StatusCode = 415;
                            await response.WriteAsync("Unsupported Media Type", cancellationToken);
                            return;
                        }

                        if (request.ContentLength > ushort.MaxValue)
                        {
                            response.StatusCode = 413;
                            await response.WriteAsync("Payload Too Large", cancellationToken);
                            return;
                        }

                        using (MemoryStream mS = new MemoryStream(512))
                        {
                            try
                            {
                                await ZenitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                                {
                                    return CopyDnsMessageAsync(request.Body, mS, cancellationToken1);
                                }, _tcpReceiveTimeout, cancellationToken);
                            }
                            catch (OperationCanceledException)
                            {
                                return;
                            }
                            catch (TimeoutException)
                            {
                                context.Abort();
                                return;
                            }
                            catch (InvalidDataException)
                            {
                                response.StatusCode = 413;
                                await response.WriteAsync("Payload Too Large", cancellationToken);
                                return;
                            }

                            mS.Position = 0;
                            dnsRequest = DnsDatagram.ReadFrom(mS);
                            dnsRequest.SetMetadata(new NameServerAddress(new Uri(UriHelper.BuildAbsolute(request.Scheme, request.Host, request.PathBase, request.Path)), context.GetLocalIpAddress()));
                        }

                        break;

                    default:
                        throw new InvalidOperationException();
                }

                long startTimestamp = Stopwatch.GetTimestamp();

                DnsDatagram dnsResponse = await ProcessRequestAsync(dnsRequest, remoteEP, DnsTransportProtocol.Https, IsRecursionAllowed(remoteEP.Address));
                if (dnsResponse is null)
                {
                    context.Connection.RequestClose();

                    _statsManager.QueueUpdate(null, remoteEP, DnsTransportProtocol.Https, null, false);
                    return;
                }

                dnsResponse = ApplyEDnsPadding(dnsRequest, dnsResponse);

                _queryLog?.Write(remoteEP, DnsTransportProtocol.Https, dnsRequest, dnsResponse);

                using (MemoryStream mS = new MemoryStream(512))
                {
                    dnsResponse.WriteTo(mS);

                    _statsManager.QueueUpdate(dnsRequest, remoteEP, DnsTransportProtocol.Https, dnsResponse, false, Stopwatch.GetElapsedTime(startTimestamp).TotalMilliseconds, (int)mS.Length);

                    mS.Position = 0;
                    response.ContentType = "application/dns-message";
                    response.ContentLength = mS.Length;

                    try
                    {
                        await ZenitiumLibrary.TaskExtensions.TimeoutAsync(async delegate (CancellationToken cancellationToken1)
                        {
                            await using (Stream s = response.Body)
                            {
                                await mS.CopyToAsync(s, 512, cancellationToken1);
                            }
                        }, _tcpSendTimeout, cancellationToken);
                    }
                    catch (Exception ex) when ((ex is OperationCanceledException) || (ex is TimeoutException))
                    {
                        context.Abort();
                    }
                }
            }
            catch (IOException)
            {
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                if (dnsRequest is not null)
                    _queryLog?.Write(remoteEP, DnsTransportProtocol.Https, dnsRequest, null);

                _log.Write(remoteEP, DnsTransportProtocol.Https, ex);
            }
        }

        private DnsDatagram ApplyEDnsPadding(DnsDatagram request, DnsDatagram response)
        {
            switch (_eDnsPaddingMode)
            {
                case DnsServerEDnsPaddingMode.WhenRequested:
                    if (!request.HasEDnsPadding())
                        return response;

                    break;

                case DnsServerEDnsPaddingMode.Always:
                    if (request.EDNS is null)
                        return response;

                    break;

                default:
                    return response;
            }

            return response.CloneWithPadding(EDNS_RESPONSE_PADDING_BLOCK_SIZE);
        }

        private static async Task CopyDnsMessageAsync(Stream source, MemoryStream destination, CancellationToken cancellationToken)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(4096);

            try
            {
                int bytesRead;

                while ((bytesRead = await source.ReadAsync(buffer.AsMemory(), cancellationToken)) > 0)
                {
                    if ((destination.Length + bytesRead) > ushort.MaxValue)
                        throw new InvalidDataException("DNS message is too large.");

                    destination.Write(buffer, 0, bytesRead);
                }
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(buffer);
            }
        }

        private bool IsRecursionAllowed(IPAddress remoteIP)
        {
            switch (_recursion)
            {
                case DnsServerRecursion.Allow:
                    return true;

                case DnsServerRecursion.AllowOnlyForPrivateNetworks:
                    switch (remoteIP.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                        case AddressFamily.InterNetworkV6:
                            return NetUtilities.IsPrivateIP(remoteIP);

                        default:
                            return false;
                    }

                case DnsServerRecursion.UseSpecifiedNetworkACL:
                    return NetworkAccessControl.IsAddressAllowed(remoteIP, _recursionNetworkACL, true);

                default:
                    return false;
            }
        }

        private bool IsRequestFiltered(DnsDatagram request, IPEndPoint remoteEP)
        {
            if (IPAddress.IsLoopback(remoteEP.Address))
                return false;

            RequestFilterRule rule;

            if (_requestFilterMalformed && ((request.ParsingException is not null) || ((request.OPCODE == DnsOpcode.StandardQuery) && (request.Question.Count != 1))))
            {
                rule = RequestFilterRule.Malformed;
            }
            else if ((_requestFilterMaxSize > 0) && (request.Size > _requestFilterMaxSize))
            {
                rule = RequestFilterRule.Size;
            }
            else if (_requestFilterOpcode && (request.OPCODE != DnsOpcode.StandardQuery))
            {
                rule = RequestFilterRule.Opcode;
            }
            else if (request.Question.Count == 0)
            {
                return false;
            }
            else
            {
                DnsQuestionRecord question = request.Question[0];

                if (_requestFilterClass && (question.Class != DnsClass.IN))
                    rule = RequestFilterRule.Class;
                else if (_requestFilterAny && (question.Type == DnsResourceRecordType.ANY))
                    rule = RequestFilterRule.Any;
                else if (_requestFilterZoneTransfer && ((question.Type == DnsResourceRecordType.AXFR) || (question.Type == DnsResourceRecordType.IXFR)))
                    rule = RequestFilterRule.ZoneTransfer;
                else if (_requestFilterNoRecursion && !request.RecursionDesired)
                    rule = RequestFilterRule.NoRecursion;
                else if (_requestFilterEdnsVersion && (request.EDNS is not null) && (request.EDNS.Version != 0))
                    rule = RequestFilterRule.EdnsVersion;
                else
                    return false;
            }

            Interlocked.Increment(ref _requestFilterMatches[(int)rule]);
            return true;
        }

        private DnsDatagram GetFilteredRequestResponse(DnsDatagram request, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (!_requestFilterRefuseOnly && ((protocol == DnsTransportProtocol.Udp) || (protocol == DnsTransportProtocol.UdpProxy)))
                return null;

            return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.Refused, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, EDnsHeaderFlags.None, [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Prohibited, null))]) { Tag = ResponseTypeTags.Authoritative };
        }

        private async ValueTask<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
        {
            if (IsDo53Restricted(request, remoteEP, protocol))
            {
                if (_do53Mode == DnsServerDo53Mode.DdrOnlyRefused)
                    return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.Refused, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, EDnsHeaderFlags.None, [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Prohibited, null))]) { Tag = ResponseTypeTags.Authoritative };

                return null;
            }

            if (IsRequestFiltered(request, remoteEP))
                return GetFilteredRequestResponse(request, protocol, isRecursionAllowed);

            foreach (IDnsRequestController requestController in _dnsApplicationManager.DnsRequestControllers)
            {
                try
                {
                    DnsRequestControllerAction action = await requestController.GetRequestActionAsync(request, remoteEP, protocol);
                    switch (action)
                    {
                        case DnsRequestControllerAction.DropSilently:
                            return null;

                        case DnsRequestControllerAction.DropWithRefused:
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.Refused, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };
                    }
                }
                catch (Exception ex)
                {
                    _log.Write(remoteEP, protocol, ex);
                }
            }

            if (request.ParsingException is not null)
            {
                if (request.ParsingException is not IOException)
                    _log.Write(remoteEP, protocol, request.ParsingException);

                return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.FormatError, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };
            }

            if (_enableDnsCookies && DnsCookie.IsMalformed(request))
                return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.FormatError, request.Question, null, null, null, _udpPayloadSize, EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };

            for (int i = 0; i < request.Question.Count; i++)
            {
                if (!DnsClient.IsDomainNameValid(request.Question[i].Name))
                    return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.FormatError, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };
            }

            if (request.IsSigned)
            {
                request.VerifySignedRequest(null, out _, out DnsDatagram errorResponse);

                errorResponse.Tag = ResponseTypeTags.Authoritative;
                return errorResponse;
            }

            if (request.EDNS is not null)
            {
                if (request.EDNS.Version != 0)
                    return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.BADVERS, request.Question, null, null, null, _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };
            }

            DnsDatagram response = await ProcessQueryAsync(request, remoteEP, protocol, isRecursionAllowed, false, _clientTimeout);
            if (response is null)
                return null;

            return await PostProcessQueryAsync(request, remoteEP, protocol, response);
        }

        private async ValueTask<DnsDatagram> PostProcessQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            foreach (IDnsPostProcessor postProcessor in _dnsApplicationManager.DnsPostProcessors)
            {
                try
                {
                    response = await postProcessor.PostProcessAsync(request, remoteEP, protocol, response);
                    if (response is null)
                        return null;
                }
                catch (Exception ex)
                {
                    _log.Write(remoteEP, protocol, ex);
                }
            }

            if (request.EDNS is null)
            {
                if (response.EDNS is not null)
                    response = response.CloneWithoutEDns();

                return response;
            }

            if (response.EDNS is not null)
                return response;

            if (response.NextDatagram is not null)
                return response;

            IReadOnlyList<EDnsOption> options = null;

            EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption(true);
            if (requestECS is not null)
                options = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(requestECS.SourcePrefixLength, 0, requestECS.Address);

            if (response.Additional.Count == 0)
                return response.Clone(null, null, [DnsDatagramEdns.GetOPTFor(_udpPayloadSize, response.RCODE, 0, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options)]);

            DnsResourceRecord[] newAdditional = new DnsResourceRecord[response.Additional.Count + 1];

            for (int i = 0; i < response.Additional.Count; i++)
                newAdditional[i] = response.Additional[i];

            newAdditional[response.Additional.Count] = DnsDatagramEdns.GetOPTFor(_udpPayloadSize, response.RCODE, 0, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options);

            return response.Clone(null, null, newAdditional);
        }

        private async ValueTask<DnsDatagram> ProcessQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers, int clientTimeout)
        {
            if (request.IsResponse)
                return null;

            switch (request.OPCODE)
            {
                case DnsOpcode.StandardQuery:
                    if (request.Question.Count != 1)
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.FormatError, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };

                    if (request.Question[0].Class != DnsClass.IN)
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.Refused, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };

                    try
                    {
                        DnsQuestionRecord question = request.Question[0];

                        switch (question.Type)
                        {
                            case DnsResourceRecordType.AXFR:
                            case DnsResourceRecordType.IXFR:
                            case DnsResourceRecordType.RRSIG:
                            case DnsResourceRecordType.FWD:
                            case DnsResourceRecordType.APP:
                            case DnsResourceRecordType.CHILD_NS:
                            case DnsResourceRecordType.PARENT_NS:
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.Refused, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.NotSupported, null))]) { Tag = ResponseTypeTags.Authoritative };

                            case DnsResourceRecordType.OPT:
                            case DnsResourceRecordType.TSIG:
                            case DnsResourceRecordType.NXNAME:
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.FormatError, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.InvalidQueryType, null))]) { Tag = ResponseTypeTags.Authoritative };
                        }

                        if (isRecursionAllowed && request.RecursionDesired && TryGetSignalDomain(question.Name, out string signalDomain))
                            return GetSignalDomainResponse(request, signalDomain);

                        if (isRecursionAllowed && (_dhcpServer is not null))
                        {
                            DnsDatagram dhcpResponse = GetDhcpResponse(request, question);
                            if (dhcpResponse is not null)
                                return dhcpResponse;
                        }

                        DnsDatagram response = await ProcessAuthoritativeQueryAsync(request, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers);
                        if (response is not null)
                        {
                            if ((question.Type == DnsResourceRecordType.ANY) && (protocol == DnsTransportProtocol.Udp))
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, true, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, response.RCODE, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };

                            return response;
                        }

                        if (!request.RecursionDesired || !isRecursionAllowed)
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.Refused, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };

                        if ((question.Type == DnsResourceRecordType.ANY) && (protocol == DnsTransportProtocol.Udp))
                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, true, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };

                        return await ProcessRecursiveQueryAsync(request, remoteEP, protocol, null, _dnssecValidation, skipDnsAppAuthoritativeRequestHandlers, clientTimeout);
                    }
                    catch (InvalidDomainNameException)
                    {
                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.FormatError, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };
                    }
                    catch (TimeoutException ex)
                    {
                        DnsDatagram response = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.ServerFailure, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };

                        _log.Write(remoteEP, protocol, request, response);
                        _log.Write(remoteEP, protocol, ex);

                        return response;
                    }
                    catch (Exception ex)
                    {
                        _log.Write(remoteEP, protocol, ex);

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.ServerFailure, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };
                    }

                default:
                    return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.NotImplemented, request.Question, null, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };
            }
        }

        private DnsDatagram GetDhcpResponse(DnsDatagram request, DnsQuestionRecord question)
        {
            Dhcp.DhcpServer dhcpServer = _dhcpServer;
            if (dhcpServer is null)
                return null;

            string name = question.Name;
            IReadOnlyList<DnsResourceRecord> answer = null;
            DnsResponseCode rcode = DnsResponseCode.NoError;

            if (question.Type == DnsResourceRecordType.PTR)
            {
                if (!(name.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase) || name.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase)) || !IPAddressExtensions.TryParseReverseDomain(name, out IPAddress address) || !dhcpServer.TryResolveAddress(address, out string hostName, out uint ptrTtl))
                    return null;

                answer = [new DnsResourceRecord(name, DnsResourceRecordType.PTR, DnsClass.IN, ptrTtl, new DnsPTRRecordData(hostName))];
            }
            else if (dhcpServer.TryResolveName(name, out IReadOnlyList<IPAddress> addresses4, out IReadOnlyList<IPAddress> addresses6, out uint ttl))
            {
                List<DnsResourceRecord> records = new List<DnsResourceRecord>();

                if ((question.Type == DnsResourceRecordType.A) || (question.Type == DnsResourceRecordType.ANY))
                {
                    foreach (IPAddress address in addresses4)
                        records.Add(new DnsResourceRecord(name, DnsResourceRecordType.A, DnsClass.IN, ttl, new DnsARecordData(address)));
                }

                if ((question.Type == DnsResourceRecordType.AAAA) || (question.Type == DnsResourceRecordType.ANY))
                {
                    foreach (IPAddress address in addresses6)
                        records.Add(new DnsResourceRecord(name, DnsResourceRecordType.AAAA, DnsClass.IN, ttl, new DnsAAAARecordData(address)));
                }

                if (records.Count > 0)
                    answer = records;
            }
            else if (dhcpServer.IsNameInLocalDomain(name))
            {
                rcode = DnsResponseCode.NxDomain;
            }
            else
            {
                return null;
            }

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, true, false, request.CheckingDisabled, rcode, request.Question, answer, null, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };
        }

        private async ValueTask<DnsDatagram> ProcessAuthoritativeQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers)
        {
            DnsDatagram response = await AuthoritativeQueryAsync(request, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, remoteEP);
            if (response is null)
                return null;

            DnsClient.ResolverContext context = null;

            bool reprocessResponse;
            do
            {
                reprocessResponse = false;

                if (response.RCODE == DnsResponseCode.NoError)
                {
                    if (response.Answer.Count > 0)
                    {
                        DnsResourceRecordType questionType = request.Question[0].Type;
                        DnsResourceRecord lastRR = response.GetLastAnswerRecord();

                        if ((lastRR.Type != questionType) && (questionType != DnsResourceRecordType.ANY))
                        {
                            switch (lastRR.Type)
                            {
                                case DnsResourceRecordType.CNAME:
                                    return await ProcessCNAMEAsync(request, response, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, _clientTimeout, context ?? new DnsClient.ResolverContext());

                                case DnsResourceRecordType.ANAME:
                                case DnsResourceRecordType.ALIAS:
                                    return await ProcessANAMEAsync(request, response, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, _clientTimeout, context ?? new DnsClient.ResolverContext());
                            }
                        }
                    }
                    else if (response.Authority.Count > 0)
                    {
                        DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();
                        switch (firstAuthority.Type)
                        {
                            case DnsResourceRecordType.NS:
                                if (request.RecursionDesired && isRecursionAllowed)
                                {
                                    return await ProcessRecursiveQueryAsync(request, remoteEP, protocol, [], _dnssecValidation, skipDnsAppAuthoritativeRequestHandlers, _clientTimeout);
                                }

                                break;

                            case DnsResourceRecordType.FWD:
                                response = await ProcessRecursiveQueryAsync(request, remoteEP, protocol, response.Authority, _dnssecValidation, skipDnsAppAuthoritativeRequestHandlers, _clientTimeout);

                                if (_dnssecValidation && (response.EDNS is not null) && firstAuthority.RDATA is DnsForwarderRecordData fwd && !fwd.DnssecValidation)
                                {
                                    EDnsOption edeNtaOption = new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.NegativeTrustAnchor, firstAuthority.GetAuthGenericRecordInfo().Comments));
                                    List<EDnsOption> options = [.. response.EDNS.Options, edeNtaOption];

                                    response = response.CloneWithEDnsOptions(options);
                                }

                                return response;

                            case DnsResourceRecordType.APP:
                                if (context is null)
                                    context = new DnsClient.ResolverContext();

                                response = await ProcessAPPAsync(request, response, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, _clientTimeout, context);
                                if (response is null)
                                    return null;

                                reprocessResponse = true;
                                break;
                        }
                    }
                }
            }
            while (reprocessResponse);

            return response;
        }

        internal async ValueTask<DnsDatagram> AuthoritativeQueryAsync(DnsDatagram request, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers, IPEndPoint remoteEP = null)
        {
            if (_enableDdr && isRecursionAllowed && (request.Question.Count > 0) && IsDdrQueryName(request.Question[0].Name) && (!_ddrOnlyUnencrypted || IsUnencryptedProtocol(protocol)))
                return GetDdrResponse(request);

            DnsDatagram authResponse;

            if (remoteEP is null)
                authResponse = _authZoneManager.Query(request, isRecursionAllowed);
            else
                authResponse = _authZoneManager.Query(request, remoteEP.Address, isRecursionAllowed);

            if (request.RecursionDesired && isRecursionAllowed && _locallyServedDnsZones)
            {
                DnsDatagram splResponse = _specialZoneManager.Query(request);
                if (splResponse is not null)
                {
                    if (!skipDnsAppAuthoritativeRequestHandlers)
                    {
                        DnsDatagram appSplResponse = await AppAuthoritativeQueryAsync(request, protocol, isRecursionAllowed, remoteEP);
                        if (appSplResponse is not null)
                            return appSplResponse;
                    }

                    splResponse.Tag = ResponseTypeTags.Authoritative;

                    if (authResponse is null)
                        return splResponse;

                    if (request.Question.Count > 0)
                    {
                        ApexZone apexZone = _authZoneManager.FindApexZone(request.Question[0].Name);
                        if ((apexZone is null) || apexZone.Disabled || (apexZone.Name.Length == 0))
                            return splResponse;
                    }
                }
            }

            if (authResponse is not null)
            {
                authResponse.Tag = ResponseTypeTags.Authoritative;

                if ((authResponse.RCODE != DnsResponseCode.NoError) || (authResponse.Answer.Count > 0) || (authResponse.Authority.Count == 0) || authResponse.IsFirstAuthoritySOAOrFWDOrAPP())
                    return authResponse;
            }

            if (skipDnsAppAuthoritativeRequestHandlers)
                return authResponse;

            DnsDatagram appResponse = await AppAuthoritativeQueryAsync(request, protocol, isRecursionAllowed, remoteEP);
            if (appResponse is not null)
            {
                if ((appResponse.RCODE != DnsResponseCode.NoError) || (appResponse.Answer.Count > 0) || (appResponse.Authority.Count == 0) || appResponse.IsFirstAuthoritySOA())
                    return appResponse;
            }

            if ((authResponse is not null) && (authResponse.Authority.Count > 0))
            {
                if ((appResponse is not null) && (appResponse.Authority.Count > 0))
                {
                    DnsResourceRecord authResponseFirstAuthority = authResponse.FindFirstAuthorityRecord();
                    DnsResourceRecord appResponseFirstAuthority = appResponse.FindFirstAuthorityRecord();

                    if (appResponseFirstAuthority.Name.Length > authResponseFirstAuthority.Name.Length)
                        return appResponse;
                }

                return authResponse;
            }
            else
            {
                return appResponse;
            }
        }

        private async Task<DnsDatagram> AppAuthoritativeQueryAsync(DnsDatagram request, DnsTransportProtocol protocol, bool isRecursionAllowed, IPEndPoint remoteEP = null)
        {
            DnsDatagram lastAppResponse = null;

            if (remoteEP is null)
                remoteEP = IPENDPOINT_ANY_0;

            foreach (IDnsAuthoritativeRequestHandler requestHandler in _dnsApplicationManager.DnsAuthoritativeRequestHandlers)
            {
                try
                {
                    DnsDatagram appResponse = await requestHandler.ProcessRequestAsync(request, remoteEP, protocol, isRecursionAllowed);
                    if (appResponse is not null)
                    {
                        if (appResponse.Tag is null)
                            appResponse.Tag = ResponseTypeTags.Authoritative;

                        if ((appResponse.RCODE != DnsResponseCode.NoError) || (appResponse.Answer.Count > 0) || (appResponse.Authority.Count == 0) || appResponse.IsFirstAuthoritySOA())
                            return appResponse;

                        if (lastAppResponse is null)
                        {
                            lastAppResponse = appResponse;
                        }
                        else
                        {
                            DnsResourceRecord appResponseFirstAuthority = appResponse.FindFirstAuthorityRecord();
                            DnsResourceRecord lastAppResponseFirstAuthority = lastAppResponse.FindFirstAuthorityRecord();

                            if (appResponseFirstAuthority.Name.Length > lastAppResponseFirstAuthority.Name.Length)
                                lastAppResponse = appResponse;
                        }
                    }
                }
                catch (Exception ex)
                {
                    _log.Write(remoteEP, protocol, ex);
                }
            }

            return lastAppResponse;
        }

        private async ValueTask<DnsDatagram> ProcessAPPAsync(DnsDatagram request, DnsDatagram response, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers, int clientTimeout, DnsClient.ResolverContext context)
        {
            DnsResourceRecord appResourceRecord = response.Authority[0];
            DnsApplicationRecordData appRecord = appResourceRecord.RDATA as DnsApplicationRecordData;

            if (_dnsApplicationManager.Applications.TryGetValue(appRecord.AppName, out DnsApplication application))
            {
                if (application.DnsAppRecordRequestHandlers.TryGetValue(appRecord.ClassPath, out IDnsAppRecordRequestHandler appRecordRequestHandler))
                {
                    AuthZoneInfo zoneInfo = _authZoneManager.FindAuthZoneInfo(appResourceRecord.Name);

                    DnsDatagram appResponse = await appRecordRequestHandler.ProcessRequestAsync(request, remoteEP, protocol, isRecursionAllowed, zoneInfo.Name, appResourceRecord.Name, appResourceRecord.TTL, appRecord.Data);
                    if (appResponse is null)
                    {
                        DnsResponseCode rcode;
                        IReadOnlyList<DnsResourceRecord> authority = null;

                        if (zoneInfo.Type == AuthZoneType.Forwarder)
                        {
                            if (!zoneInfo.Name.Equals(appResourceRecord.Name, StringComparison.OrdinalIgnoreCase))
                            {
                                AuthZone authZone = _authZoneManager.GetAuthZone(zoneInfo.Name, appResourceRecord.Name);
                                if (authZone is not null)
                                    authority = authZone.QueryRecords(DnsResourceRecordType.FWD);
                            }

                            if ((authority is null) || (authority.Count == 0))
                                authority = zoneInfo.ApexZone.QueryRecords(DnsResourceRecordType.FWD);

                            if (authority.Count > 0)
                                return await RecursiveResolveAsync(request, remoteEP, authority, _dnssecValidation, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout, context);

                            rcode = DnsResponseCode.NoError;
                        }
                        else
                        {
                            if ((request.Question[0].Name.Length == appResourceRecord.Name.Length) || appResourceRecord.Name.StartsWith('*'))
                                rcode = DnsResponseCode.NoError;
                            else
                                rcode = DnsResponseCode.NxDomain;

                            authority = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.SOA);
                        }

                        return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, rcode, request.Question, null, authority) { Tag = ResponseTypeTags.Authoritative };
                    }
                    else
                    {
                        if (appResponse.AuthoritativeAnswer)
                            appResponse.Tag = ResponseTypeTags.Authoritative;

                        return appResponse;
                    }
                }
                else
                {
                    _log.Write(remoteEP, protocol, "DNS request handler '" + appRecord.ClassPath + "' was not found in the application '" + appRecord.AppName + "': " + appResourceRecord.Name);
                }
            }
            else
            {
                _log.Write(remoteEP, protocol, "DNS application '" + appRecord.AppName + "' was not found: " + appResourceRecord.Name);
            }

            {
                AuthZoneInfo zoneInfo = _authZoneManager.FindAuthZoneInfo(request.Question[0].Name);
                IReadOnlyList<DnsResourceRecord> authority = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.SOA);

                return new DnsDatagram(request.Identifier, true, request.OPCODE, false, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, DnsResponseCode.ServerFailure, request.Question, null, authority) { Tag = ResponseTypeTags.Authoritative };
            }
        }

        private async ValueTask<DnsDatagram> ProcessCNAMEAsync(DnsDatagram request, DnsDatagram response, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers, int clientTimeout, DnsClient.ResolverContext context)
        {
            bool authenticData = response.AuthenticData;

            List<DnsResourceRecord> newAnswer = new List<DnsResourceRecord>(response.Answer.Count + 4);
            newAnswer.AddRange(response.Answer);

            List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(2);

            foreach (DnsResourceRecord record in response.Authority)
            {
                switch (record.Type)
                {
                    case DnsResourceRecordType.NSEC:
                    case DnsResourceRecordType.NSEC3:
                        newAuthority.Add(record);
                        break;

                    case DnsResourceRecordType.RRSIG:
                        switch ((record.RDATA as DnsRRSIGRecordData).TypeCovered)
                        {
                            case DnsResourceRecordType.NSEC:
                            case DnsResourceRecordType.NSEC3:
                                newAuthority.Add(record);
                                break;
                        }
                        break;
                }
            }

            DnsDatagram lastResponse = response;
            bool isAuthoritativeAnswer = response.AuthoritativeAnswer;
            DnsResourceRecord lastRR = response.GetLastAnswerRecord();
            EDnsOption[] eDnsClientSubnetOption = null;
            DnsDatagram newResponse = null;
            string cnameLoopDetectedDomain = null;
            double responseRtt = 0.0;

            if (response.Metadata is not null)
                responseRtt = response.Metadata.RoundTripTime;

            if (_eDnsClientSubnet)
            {
                EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                if (requestECS is not null)
                    eDnsClientSubnetOption = [new EDnsOption(EDnsOptionCode.EDNS_CLIENT_SUBNET, requestECS)];
            }

            int queryCount = 0;
            do
            {
                string cnameDomain = (lastRR.RDATA as DnsCNAMERecordData).Domain;
                if (lastRR.Name.Equals(cnameDomain, StringComparison.OrdinalIgnoreCase))
                {
                    cnameLoopDetectedDomain = cnameDomain;
                    break;
                }

                if (!DnsClient.IsDomainNameValid(cnameDomain))
                {
                    newResponse = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.FormatError, request.Question);
                    break;
                }

                DnsDatagram newRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, request.CheckingDisabled, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(cnameDomain, request.Question[0].Type, request.Question[0].Class) }, null, null, null, _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, eDnsClientSubnetOption);

                newResponse = await AuthoritativeQueryAsync(newRequest, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, remoteEP);
                if (newResponse is null)
                {
                    if (newRequest.RecursionDesired && isRecursionAllowed)
                    {
                        newResponse = await RecursiveResolveAsync(newRequest, remoteEP, null, _dnssecValidation, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout, context);
                        if (newResponse is null)
                            return null;

                        isAuthoritativeAnswer = false;
                    }
                    else
                    {
                        break;
                    }
                }
                else if ((newResponse.Answer.Count > 0) && (newResponse.GetLastAnswerRecord() is DnsResourceRecord lastAnswer) && ((lastAnswer.Type == DnsResourceRecordType.ANAME) || (lastAnswer.Type == DnsResourceRecordType.ALIAS)))
                {
                    newResponse = await ProcessANAMEAsync(request, newResponse, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, clientTimeout, context);
                    if (newResponse is null)
                        return null;
                }
                else if ((newResponse.Answer.Count == 0) && (newResponse.Authority.Count > 0))
                {
                    DnsResourceRecord firstAuthority = newResponse.FindFirstAuthorityRecord();
                    switch (firstAuthority.Type)
                    {
                        case DnsResourceRecordType.NS:
                            if (newRequest.RecursionDesired && isRecursionAllowed)
                            {
                                newResponse = await RecursiveResolveAsync(newRequest, remoteEP, [], _dnssecValidation, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout, context);
                                if (newResponse is null)
                                    return null;

                                isAuthoritativeAnswer = false;
                            }

                            break;

                        case DnsResourceRecordType.FWD:
                            newResponse = await RecursiveResolveAsync(newRequest, remoteEP, newResponse.Authority, _dnssecValidation, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout, context);
                            if (newResponse is null)
                                return null;

                            isAuthoritativeAnswer = false;
                            break;

                        case DnsResourceRecordType.APP:
                            newResponse = await ProcessAPPAsync(newRequest, newResponse, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, clientTimeout, context);
                            if (newResponse is null)
                                return null;

                            break;
                    }
                }

                if (newResponse.Metadata is not null)
                    responseRtt += newResponse.Metadata.RoundTripTime;

                authenticData &= newResponse.AuthenticData;

                if (newResponse.Answer.Count == 0)
                    break;

                lastRR = newResponse.GetLastAnswerRecord();
                if (lastRR.Type != DnsResourceRecordType.CNAME)
                {
                    newAnswer.AddRange(newResponse.Answer);
                    break;
                }

                foreach (DnsResourceRecord newResponseAnswerRecord in newResponse.Answer)
                {
                    if ((newResponseAnswerRecord.Type == DnsResourceRecordType.CNAME) || (newResponseAnswerRecord.Type == DnsResourceRecordType.DNAME))
                    {
                        foreach (DnsResourceRecord answerRecord in newAnswer)
                        {
                            if (newResponseAnswerRecord.Equals(answerRecord))
                            {
                                cnameLoopDetectedDomain = (newResponseAnswerRecord.RDATA as DnsCNAMERecordData).Domain;
                                break;
                            }
                        }

                        if (cnameLoopDetectedDomain is not null)
                            break;
                    }

                    newAnswer.Add(newResponseAnswerRecord);
                }

                if (cnameLoopDetectedDomain is not null)
                    break;

                lastResponse = newResponse;
            }
            while (++queryCount < MAX_CNAME_HOPS);

            DnsDatagram finalResponse;

            if (newResponse is null)
            {
                DnsResponseCode rcode = DnsResponseCode.NoError;
                IReadOnlyList<DnsResourceRecord> authority;
                IReadOnlyList<DnsResourceRecord> additional;

                if (newAuthority.Count == 0)
                {
                    authority = lastResponse.Authority;
                }
                else
                {
                    newAuthority.AddRange(lastResponse.Authority);
                    authority = newAuthority;
                }

                additional = lastResponse.Additional;

                finalResponse = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, isAuthoritativeAnswer, false, request.RecursionDesired, isRecursionAllowed, authenticData, request.CheckingDisabled, rcode, request.Question, newAnswer, authority, additional) { Tag = response.Tag };
            }
            else
            {
                DnsResponseCode rcode;
                IReadOnlyList<DnsResourceRecord> authority;
                IReadOnlyList<DnsResourceRecord> additional;
                List<EDnsOption> options = null;

                if (cnameLoopDetectedDomain is not null)
                {
                    rcode = DnsResponseCode.ServerFailure;

                    options = new List<EDnsOption>(4)
                    {
                        new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Other, "CNAME loop detected at " + cnameLoopDetectedDomain + "."))
                    };
                }
                else
                {
                    if (queryCount >= MAX_CNAME_HOPS)
                        rcode = DnsResponseCode.ServerFailure;
                    else
                        rcode = newResponse.RCODE;
                }

                if (newAuthority.Count == 0)
                {
                    authority = newResponse.Authority;
                }
                else
                {
                    newAuthority.AddRange(newResponse.Authority);
                    authority = newAuthority;
                }

                if (options is null)
                {
                    additional = newResponse.Additional;

                    finalResponse = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, isAuthoritativeAnswer, false, request.RecursionDesired, isRecursionAllowed, authenticData, request.CheckingDisabled, rcode, request.Question, newAnswer, authority, additional) { Tag = response.Tag };
                }
                else
                {
                    if (newResponse.Additional.Count == 0)
                    {
                        additional = newResponse.Additional;
                    }
                    else if ((newResponse.Additional.Count == 1) && (newResponse.Additional[0].RDATA is DnsOPTRecordData opt))
                    {
                        options.AddRange(opt.Options);
                        additional = [];
                    }
                    else
                    {
                        List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>();

                        foreach (DnsResourceRecord additionalRecord in newResponse.Additional)
                        {
                            if (additionalRecord.Type == DnsResourceRecordType.OPT)
                            {
                                options.AddRange((additionalRecord.RDATA as DnsOPTRecordData).Options);
                                continue;
                            }

                            newAdditional.Add(additionalRecord);
                        }

                        additional = newAdditional;
                    }

                    finalResponse = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, isAuthoritativeAnswer, false, request.RecursionDesired, isRecursionAllowed, authenticData, request.CheckingDisabled, rcode, request.Question, newAnswer, authority, additional, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options) { Tag = response.Tag };
                }
            }

            finalResponse.SetMetadata(null, responseRtt);

            return finalResponse;
        }

        private async Task<DnsDatagram> ProcessANAMEAsync(DnsDatagram request, DnsDatagram response, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, bool skipDnsAppAuthoritativeRequestHandlers, int clientTimeout, DnsClient.ResolverContext context)
        {
            EDnsOption[] eDnsClientSubnetOption = null;

            if (_eDnsClientSubnet)
            {
                EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                if (requestECS is not null)
                    eDnsClientSubnetOption = [new EDnsOption(EDnsOptionCode.EDNS_CLIENT_SUBNET, requestECS)];
            }

            Queue<Task<IReadOnlyList<DnsResourceRecord>>> resolveQueue = new Queue<Task<IReadOnlyList<DnsResourceRecord>>>();

            async Task<IReadOnlyList<DnsResourceRecord>> ResolveANAMEAsync(DnsResourceRecord anameRR, int queryCount = 0)
            {
                string lastDomain = (anameRR.RDATA as DnsANAMERecordData).Domain;
                if (anameRR.Name.Equals(lastDomain, StringComparison.OrdinalIgnoreCase))
                    return null;

                do
                {
                    DnsDatagram newRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, request.CheckingDisabled, DnsResponseCode.NoError, new DnsQuestionRecord[] { new DnsQuestionRecord(lastDomain, request.Question[0].Type, request.Question[0].Class) }, null, null, null, _udpPayloadSize, _dnssecValidation && request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, eDnsClientSubnetOption);

                    DnsDatagram newResponse = await AuthoritativeQueryAsync(newRequest, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, remoteEP);
                    if (newResponse is null)
                    {
                        newResponse = await RecursiveResolveAsync(newRequest, remoteEP, null, _dnssecValidation, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout, context);
                        if (newResponse is null)
                            return null;
                    }
                    else if ((newResponse.Answer.Count == 0) && (newResponse.Authority.Count > 0))
                    {
                        DnsResourceRecord firstAuthority = newResponse.FindFirstAuthorityRecord();
                        switch (firstAuthority.Type)
                        {
                            case DnsResourceRecordType.NS:
                                newResponse = await RecursiveResolveAsync(newRequest, remoteEP, [], _dnssecValidation, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout, context);
                                if (newResponse is null)
                                    return null;

                                break;

                            case DnsResourceRecordType.FWD:
                                newResponse = await RecursiveResolveAsync(newRequest, remoteEP, newResponse.Authority, _dnssecValidation, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout, context);
                                if (newResponse is null)
                                    return null;

                                break;

                            case DnsResourceRecordType.APP:
                                newResponse = await ProcessAPPAsync(newRequest, newResponse, remoteEP, protocol, isRecursionAllowed, skipDnsAppAuthoritativeRequestHandlers, clientTimeout, context);
                                if (newResponse is null)
                                    return null;

                                break;
                        }
                    }

                    if (newResponse.RCODE != DnsResponseCode.NoError)
                        return null;

                    if (newResponse.Answer.Count == 0)
                        return Array.Empty<DnsResourceRecord>();

                    DnsResourceRecordType questionType = request.Question[0].Type;
                    DnsResourceRecord lastRR = newResponse.GetLastAnswerRecord();
                    if (lastRR.Type == questionType)
                    {
                        List<DnsResourceRecord> answers = new List<DnsResourceRecord>();

                        foreach (DnsResourceRecord answer in newResponse.Answer)
                        {
                            if (answer.Type != questionType)
                                continue;

                            if (anameRR.TTL < answer.TTL)
                                answers.Add(new DnsResourceRecord(anameRR.Name, answer.Type, answer.Class, anameRR.TTL, answer.RDATA));
                            else
                                answers.Add(new DnsResourceRecord(anameRR.Name, answer.Type, answer.Class, answer.TTL, answer.RDATA));
                        }

                        return answers;
                    }

                    switch (lastRR.Type)
                    {
                        case DnsResourceRecordType.ANAME:
                        case DnsResourceRecordType.ALIAS:
                            if (newResponse.Answer.Count == 1)
                            {
                                lastDomain = (lastRR.RDATA as DnsANAMERecordData).Domain;
                            }
                            else
                            {
                                queryCount++;

                                foreach (DnsResourceRecord newAnswer in newResponse.Answer)
                                    resolveQueue.Enqueue(ResolveANAMEAsync(newAnswer, queryCount));

                                return Array.Empty<DnsResourceRecord>();
                            }
                            break;

                        case DnsResourceRecordType.CNAME:
                            lastDomain = (lastRR.RDATA as DnsCNAMERecordData).Domain;
                            break;

                        default:
                            return Array.Empty<DnsResourceRecord>();
                    }
                }
                while (++queryCount < MAX_CNAME_HOPS);

                return null;
            }

            List<DnsResourceRecord> responseAnswer = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord answer in response.Answer)
            {
                switch (answer.Type)
                {
                    case DnsResourceRecordType.ANAME:
                    case DnsResourceRecordType.ALIAS:
                        resolveQueue.Enqueue(ResolveANAMEAsync(answer));
                        break;

                    default:
                        if (resolveQueue.Count == 0)
                            responseAnswer.Add(answer);

                        break;
                }
            }

            bool foundErrors = false;

            while (resolveQueue.Count > 0)
            {
                IReadOnlyList<DnsResourceRecord> records = await resolveQueue.Dequeue();
                if (records is null)
                    foundErrors = true;
                else if (records.Count > 0)
                    responseAnswer.AddRange(records);
            }

            DnsResponseCode rcode = DnsResponseCode.NoError;
            IReadOnlyList<DnsResourceRecord> authority = null;

            if (responseAnswer.Count == 0)
            {
                if (foundErrors)
                {
                    rcode = DnsResponseCode.ServerFailure;
                }
                else
                {
                    authority = response.Authority;

                    DateTime utcNow = DateTime.UtcNow;

                    foreach (DnsResourceRecord record in authority)
                        record.GetAuthGenericRecordInfo().LastUsedOn = utcNow;
                }
            }

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, request.CheckingDisabled, rcode, request.Question, responseAnswer, authority) { Tag = response.Tag };
        }

        private async Task<bool> IsAllowedAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol)
        {
            if (request.Question.Count > 0)
            {
                DnsQuestionRecord question = request.Question[0];
                if (question.Type == DnsResourceRecordType.DS)
                {
                    DnsQuestionRecord newQuestion = new DnsQuestionRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN);
                    request = new DnsDatagram(request.Identifier, request.IsResponse, request.OPCODE, request.AuthoritativeAnswer, request.Truncation, request.RecursionDesired, request.RecursionAvailable, request.AuthenticData, request.CheckingDisabled, request.RCODE, [newQuestion], request.Answer, request.Authority, request.Additional);
                }
            }

            if ((request.Question.Count > 0) && IsAutoAllowed(request.Question[0].Name))
                return true;

            if (_enableBlocking)
            {
                if (_blockingBypassList is not null)
                {
                    IPAddress remoteIP = remoteEP.Address;

                    foreach (NetworkAddress network in _blockingBypassList)
                    {
                        if (network.Contains(remoteIP))
                            return true;
                    }
                }

                DnsClientIdentity client = _clientProfileManager.Resolve(remoteEP.Address, request);

                if ((client.Profile is not null) && !client.Profile.BlockingEnabled)
                    return true;

                if (_allowedZoneManager.IsAllowed(request) || _blockListZoneManager.IsAllowed(request, client))
                    return true;
            }

            foreach (IDnsRequestBlockingHandler blockingHandler in _dnsApplicationManager.DnsRequestBlockingHandlers)
            {
                try
                {
                    if (await blockingHandler.IsAllowedAsync(request, remoteEP))
                        return true;
                }
                catch (Exception ex)
                {
                    _log.Write(remoteEP, protocol, ex);
                }
            }

            return false;
        }

        private async ValueTask<DnsDatagram> ProcessBlockedQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol)
        {
            if (_enableBlocking)
            {
                DnsDatagram response = _blockedZoneManager.Query(request);
                if (response is null)
                {
                    response = _blockListZoneManager.Query(request, _clientProfileManager.Resolve(remoteEP.Address, request));
                    if (response is not null)
                    {
                        response.Tag = ResponseTypeTags.Blocked;
                        return response;
                    }
                }
                else
                {
                    DnsQuestionRecord question = request.Question[0];

                    string GetBlockedDomain()
                    {
                        DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();
                        if ((firstAuthority is not null) && (firstAuthority.Type == DnsResourceRecordType.SOA))
                            return firstAuthority.Name;
                        else
                            return question.Name;
                    }

                    if (_allowTxtBlockingReport && (question.Type == DnsResourceRecordType.TXT))
                    {
                        string blockedDomain = GetBlockedDomain();

                        IReadOnlyList<DnsResourceRecord> answer = [new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, _blockingAnswerTtl, new DnsTXTRecordData(GetBlockingReportText("blocked-zone", blockedDomain, null)))];

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answer) { Tag = ResponseTypeTags.Blocked };
                    }
                    else
                    {
                        string blockedDomain = null;
                        EDnsOption[] options = null;

                        if (_allowTxtBlockingReport && (request.EDNS is not null))
                        {
                            blockedDomain = GetBlockedDomain();
                            options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, GetBlockingReportText("blocked-zone", blockedDomain, null)))];
                        }

                        IReadOnlyCollection<DnsARecordData> aRecords;
                        IReadOnlyCollection<DnsAAAARecordData> aaaaRecords;

                        switch (_blockingType)
                        {
                            case DnsServerBlockingType.AnyAddress:
                                aRecords = _aRecords;
                                aaaaRecords = _aaaaRecords;
                                break;

                            case DnsServerBlockingType.CustomAddress:
                                aRecords = _customBlockingARecords;
                                aaaaRecords = _customBlockingAAAARecords;
                                break;

                            case DnsServerBlockingType.NxDomain:
                                if (blockedDomain is null)
                                    blockedDomain = GetBlockedDomain();

                                string parentDomain = AuthZoneManager.GetParentZone(blockedDomain);
                                if (parentDomain is null)
                                    parentDomain = string.Empty;

                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, !_allowTxtBlockingReport, false, false, DnsResponseCode.NxDomain, request.Question, null, [new DnsResourceRecord(parentDomain, DnsResourceRecordType.SOA, question.Class, _blockingNegativeTtl, _blockedZoneManager.DnsSOARecord)], null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, EDnsHeaderFlags.None, options) { Tag = ResponseTypeTags.Blocked };

                            default:
                                throw new InvalidOperationException();
                        }

                        IReadOnlyList<DnsResourceRecord> answer;
                        IReadOnlyList<DnsResourceRecord> authority = null;

                        switch (question.Type)
                        {
                            case DnsResourceRecordType.A:
                                {
                                    if (aRecords.Count > 0)
                                    {
                                        DnsResourceRecord[] rrList = new DnsResourceRecord[aRecords.Count];
                                        int i = 0;

                                        foreach (DnsARecordData record in aRecords)
                                            rrList[i++] = new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, _blockingAnswerTtl, record);

                                        answer = rrList;
                                    }
                                    else
                                    {
                                        answer = null;
                                        authority = response.Authority;
                                    }
                                }
                                break;

                            case DnsResourceRecordType.AAAA:
                                {
                                    if (aaaaRecords.Count > 0)
                                    {
                                        DnsResourceRecord[] rrList = new DnsResourceRecord[aaaaRecords.Count];
                                        int i = 0;

                                        foreach (DnsAAAARecordData record in aaaaRecords)
                                            rrList[i++] = new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, _blockingAnswerTtl, record);

                                        answer = rrList;
                                    }
                                    else
                                    {
                                        answer = null;
                                        authority = response.Authority;
                                    }
                                }
                                break;

                            default:
                                answer = response.Answer;
                                authority = response.Authority;
                                break;
                        }

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, !_allowTxtBlockingReport, false, false, DnsResponseCode.NoError, request.Question, answer, authority, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, EDnsHeaderFlags.None, options) { Tag = ResponseTypeTags.Blocked };
                    }
                }
            }

            foreach (IDnsRequestBlockingHandler blockingHandler in _dnsApplicationManager.DnsRequestBlockingHandlers)
            {
                try
                {
                    DnsDatagram appBlockedResponse = await blockingHandler.ProcessRequestAsync(request, remoteEP);
                    if (appBlockedResponse is not null)
                    {
                        if (appBlockedResponse.Tag is null)
                            appBlockedResponse.Tag = ResponseTypeTags.Blocked;

                        return appBlockedResponse;
                    }
                }
                catch (Exception ex)
                {
                    _log.Write(remoteEP, protocol, ex);
                }
            }

            return null;
        }

        private async ValueTask<DnsDatagram> ProcessRecursiveQueryAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, IReadOnlyList<DnsResourceRecord> conditionalForwarders, bool dnssecValidation, bool skipDnsAppAuthoritativeRequestHandlers, int clientTimeout)
        {
            bool isAllowed = await IsAllowedAsync(request, remoteEP, protocol);
            if (!isAllowed)
            {
                DnsDatagram blockedResponse = await ProcessBlockedQueryAsync(request, remoteEP, protocol);
                if (blockedResponse is not null)
                    return blockedResponse;
            }

            DnsClient.ResolverContext context = new DnsClient.ResolverContext();

            DnsDatagram response = await RecursiveResolveAsync(request, remoteEP, conditionalForwarders, dnssecValidation, false, skipDnsAppAuthoritativeRequestHandlers, clientTimeout, context);
            if (response is null)
                return null;

            if (response.Answer.Count > 0)
            {
                DnsResourceRecordType questionType = request.Question[0].Type;
                DnsResourceRecord lastRR = response.GetLastAnswerRecord();

                if ((lastRR.Type != questionType) && (lastRR.Type == DnsResourceRecordType.CNAME) && (questionType != DnsResourceRecordType.ANY))
                {
                    response = await ProcessCNAMEAsync(request, response, remoteEP, protocol, true, skipDnsAppAuthoritativeRequestHandlers, clientTimeout, context);
                    if (response is null)
                        return null;
                }

                if (!isAllowed)
                {
                    for (int i = 0; i < response.Answer.Count; i++)
                    {
                        DnsResourceRecord record = response.Answer[i];

                        if (record.Type != DnsResourceRecordType.CNAME)
                            break;

                        string cnameDomain = (record.RDATA as DnsCNAMERecordData).Domain;

                        if (!DnsClient.IsDomainNameValid(cnameDomain))
                            continue;

                        DnsDatagram newRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(cnameDomain, request.Question[0].Type, request.Question[0].Class)], null, null, null, _udpPayloadSize);

                        if (request.Metadata is not null)
                            newRequest.SetMetadata(request.Metadata.NameServer);

                        isAllowed = await IsAllowedAsync(newRequest, remoteEP, protocol);
                        if (isAllowed)
                            break;

                        DnsDatagram blockedResponse = await ProcessBlockedQueryAsync(newRequest, remoteEP, protocol);
                        if (blockedResponse is not null)
                        {
                            List<DnsResourceRecord> answer = new List<DnsResourceRecord>(i + 1 + blockedResponse.Answer.Count);

                            for (int j = 0; j <= i; j++)
                                answer.Add(response.Answer[j]);

                            answer.AddRange(blockedResponse.Answer);

                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, blockedResponse.RCODE, request.Question, answer, blockedResponse.Authority, blockedResponse.Additional) { Tag = blockedResponse.Tag };
                        }
                    }
                }

                if (!isAllowed && _enableBlocking)
                {
                    DnsDatagram ipBlockedResponse = _blockListZoneManager.QueryAnswerAddresses(request, response, _clientProfileManager.Resolve(remoteEP.Address, request));
                    if (ipBlockedResponse is not null)
                    {
                        ipBlockedResponse.Tag = ResponseTypeTags.Blocked;
                        return ipBlockedResponse;
                    }
                }
            }

            if (response.Tag is null)
            {
                if (response.IsBlockedResponse())
                    response.Tag = ResponseTypeTags.UpstreamBlocked;
            }
            else if ((DnsServerResponseType)response.Tag == DnsServerResponseType.Cached)
            {
                if (response.IsBlockedResponse())
                    response.Tag = ResponseTypeTags.UpstreamBlockedCached;
            }

            return response;
        }

        private async ValueTask<DnsDatagram> RecursiveResolveAsync(DnsDatagram request, IPEndPoint remoteEP, IReadOnlyList<DnsResourceRecord> conditionalForwarders, bool dnssecValidation, bool cachePrefetchOperation, bool skipDnsAppAuthoritativeRequestHandlers, int clientTimeout, DnsClient.ResolverContext context)
        {
            DnsQuestionRecord question = request.Question[0];
            NetworkAddress eDnsClientSubnet = null;
            bool advancedForwardingClientSubnet = false;

            if (_eDnsClientSubnet)
            {
                EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                if (requestECS is null)
                {
                    if ((_eDnsClientSubnetIpv4Override is not null) && (remoteEP.AddressFamily == AddressFamily.InterNetwork))
                    {
                        eDnsClientSubnet = _eDnsClientSubnetIpv4Override;
                        request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                    }
                    else if ((_eDnsClientSubnetIpv6Override is not null) && (remoteEP.AddressFamily == AddressFamily.InterNetworkV6))
                    {
                        eDnsClientSubnet = _eDnsClientSubnetIpv6Override;
                        request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                    }
                    else if (!NetUtilities.IsPrivateIP(remoteEP.Address))
                    {
                        switch (remoteEP.AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                eDnsClientSubnet = new NetworkAddress(remoteEP.Address, _eDnsClientSubnetIPv4PrefixLength);
                                request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                                break;

                            case AddressFamily.InterNetworkV6:
                                eDnsClientSubnet = new NetworkAddress(remoteEP.Address, _eDnsClientSubnetIPv6PrefixLength);
                                request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                                break;

                            default:
                                request.ShadowHideEDnsClientSubnetOption();
                                break;
                        }
                    }
                }
                else if ((requestECS.Family != EDnsClientSubnetAddressFamily.IPv4) && (requestECS.Family != EDnsClientSubnetAddressFamily.IPv6))
                {
                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, request.CheckingDisabled, DnsResponseCode.FormatError, request.Question) { Tag = ResponseTypeTags.Authoritative };
                }
                else if (requestECS.AdvancedForwardingClientSubnet)
                {
                    advancedForwardingClientSubnet = true;
                    eDnsClientSubnet = new NetworkAddress(requestECS.Address, requestECS.SourcePrefixLength);
                }
                else if ((requestECS.SourcePrefixLength == 0) || NetUtilities.IsPrivateIP(requestECS.Address))
                {
                    request.ShadowHideEDnsClientSubnetOption();
                }
                else if ((_eDnsClientSubnetIpv4Override is not null) && (remoteEP.AddressFamily == AddressFamily.InterNetwork))
                {
                    eDnsClientSubnet = _eDnsClientSubnetIpv4Override;
                    request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                }
                else if ((_eDnsClientSubnetIpv6Override is not null) && (remoteEP.AddressFamily == AddressFamily.InterNetworkV6))
                {
                    eDnsClientSubnet = _eDnsClientSubnetIpv6Override;
                    request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                }
                else
                {
                    switch (requestECS.Family)
                    {
                        case EDnsClientSubnetAddressFamily.IPv4:
                            eDnsClientSubnet = new NetworkAddress(requestECS.Address, Math.Min(requestECS.SourcePrefixLength, _eDnsClientSubnetIPv4PrefixLength));
                            request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                            break;

                        case EDnsClientSubnetAddressFamily.IPv6:
                            eDnsClientSubnet = new NetworkAddress(requestECS.Address, Math.Min(requestECS.SourcePrefixLength, _eDnsClientSubnetIPv6PrefixLength));
                            request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet);
                            break;
                    }
                }
            }
            else
            {
                EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                if (requestECS is not null)
                {
                    advancedForwardingClientSubnet = requestECS.AdvancedForwardingClientSubnet;
                    if (advancedForwardingClientSubnet)
                        eDnsClientSubnet = new NetworkAddress(requestECS.Address, requestECS.SourcePrefixLength);
                    else
                        request.ShadowHideEDnsClientSubnetOption();
                }
            }

            bool cacheEnabled = _cacheZoneManager.Enabled;

            if (!cachePrefetchOperation && cacheEnabled)
            {
                DnsDatagram cacheResponse = QueryCache(request, false, false, conditionalForwarders is null);
                if (cacheResponse is not null)
                {
                    if (_cachePrefetchTrigger > 0)
                    {
                        IReadOnlyList<DnsResourceRecord> cacheAnswer = cacheResponse.Answer;

                        for (int i = 0; i < cacheAnswer.Count; i++)
                        {
                            DnsResourceRecord answer = cacheAnswer[i];

                            if ((answer.OriginalTtlValue >= _cachePrefetchEligibility) && ((answer.TTL <= GetPrefetchThreshold(answer.OriginalTtlValue)) || answer.IsStale))
                            {
                                if ((conditionalForwarders is not null) && (conditionalForwarders.Count > 0))
                                {
                                    string conditionalForwardingZoneCut = conditionalForwarders[0].Name;

                                    if (!answer.Name.Equals(conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase) && !answer.Name.EndsWith("." + conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase))
                                        break;
                                }

                                _ = PrefetchCacheAsync(new DnsQuestionRecord(answer.Name, question.Type, question.Class), remoteEP, conditionalForwarders, dnssecValidation, eDnsClientSubnet, advancedForwardingClientSubnet);
                                break;
                            }
                        }
                    }

                    return cacheResponse;
                }
            }

            TaskCompletionSource<RecursiveResolveResponse> resolverTaskCompletionSource = new TaskCompletionSource<RecursiveResolveResponse>();
            Task<RecursiveResolveResponse> resolverTask = _resolverTasks.GetOrAdd(GetResolverQueryKey(question, eDnsClientSubnet), resolverTaskCompletionSource.Task);

            if (resolverTask.Equals(resolverTaskCompletionSource.Task))
            {
                if (!_resolverTaskPool.TryQueueTask(GetRecursiveResolverBackgroundTask(question, eDnsClientSubnet, advancedForwardingClientSubnet, conditionalForwarders, dnssecValidation, cachePrefetchOperation, skipDnsAppAuthoritativeRequestHandlers, resolverTaskCompletionSource, context)))
                {
                    if (!_resolverTasks.TryRemove(GetResolverQueryKey(question, eDnsClientSubnet), out _))
                        throw new InvalidOperationException();

                    return null;
                }
            }

            if (cachePrefetchOperation)
                return null;

            if (_serveStale && cacheEnabled)
            {
                int waitTimeout = Math.Min(_serveStaleMaxWaitTime, clientTimeout - SERVE_STALE_TIME_DIFFERENCE);
                using CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource();

                if ((waitTimeout > 0) && ((await Task.WhenAny(resolverTask, Task.Delay(waitTimeout, timeoutCancellationTokenSource.Token)) == resolverTask) || (resolverTask.Status == TaskStatus.RanToCompletion)))
                {
                    timeoutCancellationTokenSource.Cancel();

                    RecursiveResolveResponse response = await resolverTask;

                    if (response is not null)
                        return PrepareRecursiveResolveResponse(request, response);
                }
                else
                {
                    DnsDatagram staleResponse = QueryCache(request, true, false, conditionalForwarders is null);
                    if (staleResponse is not null)
                        return staleResponse;

                    int timeout = clientTimeout - waitTimeout;

                    if ((await Task.WhenAny(resolverTask, Task.Delay(timeout, timeoutCancellationTokenSource.Token)) == resolverTask) || (resolverTask.Status == TaskStatus.RanToCompletion))
                    {
                        timeoutCancellationTokenSource.Cancel();

                        RecursiveResolveResponse response = await resolverTask;

                        if (response is not null)
                            return PrepareRecursiveResolveResponse(request, response);
                    }
                }
            }
            else
            {
                using CancellationTokenSource timeoutCancellationTokenSource = new CancellationTokenSource();

                if ((await Task.WhenAny(resolverTask, Task.Delay(clientTimeout, timeoutCancellationTokenSource.Token)) == resolverTask) || (resolverTask.Status == TaskStatus.RanToCompletion))
                {
                    timeoutCancellationTokenSource.Cancel();

                    RecursiveResolveResponse response = await resolverTask;

                    if (response is not null)
                        return PrepareRecursiveResolveResponse(request, response);
                }
            }

            EDnsOption[] options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Other, "Waiting for resolver. Please try again."))];
            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, request.CheckingDisabled, DnsResponseCode.ServerFailure, request.Question, null, null, null, _udpPayloadSize, dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options);
        }

        private Func<object, Task> GetRecursiveResolverBackgroundTask(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet, IReadOnlyList<DnsResourceRecord> conditionalForwarders, bool dnssecValidation, bool cachePrefetchOperation, bool skipDnsAppAuthoritativeRequestHandlers, TaskCompletionSource<RecursiveResolveResponse> taskCompletionSource, DnsClient.ResolverContext context)
        {
            return delegate (object state)
            {
                return RecursiveResolverBackgroundTaskAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, conditionalForwarders, dnssecValidation, cachePrefetchOperation, skipDnsAppAuthoritativeRequestHandlers, taskCompletionSource, context);
            };
        }

        private async Task RecursiveResolverBackgroundTaskAsync(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet, IReadOnlyList<DnsResourceRecord> conditionalForwarders, bool dnssecValidation, bool cachePrefetchOperation, bool skipDnsAppAuthoritativeRequestHandlers, TaskCompletionSource<RecursiveResolveResponse> taskCompletionSource, DnsClient.ResolverContext context)
        {
            try
            {
                IDnsCache dnsCache;
                bool aggressiveNsec = conditionalForwarders is null;

                if (!_cacheZoneManager.Enabled)
                    dnsCache = new ResolverDnsCache(this, skipDnsAppAuthoritativeRequestHandlers || advancedForwardingClientSubnet, false, false, new ResolutionScratchCache());
                else if (cachePrefetchOperation)
                    dnsCache = new ResolverPrefetchDnsCache(this, skipDnsAppAuthoritativeRequestHandlers, question, aggressiveNsec);
                else if (skipDnsAppAuthoritativeRequestHandlers || advancedForwardingClientSubnet)
                    dnsCache = aggressiveNsec ? _dnsCacheSkipDnsApps : _forwarderDnsCacheSkipDnsApps;
                else
                    dnsCache = aggressiveNsec ? _dnsCache : _forwarderDnsCache;

                DnsDatagram response;

                if (conditionalForwarders is not null)
                {
                    if (conditionalForwarders.Count > 0)
                    {
                        response = await PriorityConditionalForwarderResolveAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, dnsCache, skipDnsAppAuthoritativeRequestHandlers, conditionalForwarders, context);
                    }
                    else
                    {
                        response = await ZenitiumLibrary.TaskExtensions.TimeoutAsync(async delegate (CancellationToken cancellationToken1)
                        {
                            Stopwatch stopwatch = Stopwatch.StartNew();

                            DnsDatagram response = await DnsClient.RecursiveResolveAsync(question, dnsCache, _proxy, _ipv6Mode, _udpPayloadSize, _randomizeName, _qnameMinimization, dnssecValidation, eDnsClientSubnet, _resolverRetries, _resolverTimeout, _resolverConcurrency, _resolverMaxStackCount, true, true, cancellationToken: cancellationToken1);

                            stopwatch.Stop();
                            response = response.CloneWithMetadata(response.Metadata?.NameServer, stopwatch.Elapsed.TotalMilliseconds);

                            return response;
                        }, RECURSIVE_RESOLUTION_TIMEOUT);
                    }
                }
                else
                {
                    response = await DefaultRecursiveResolveAsync(question, eDnsClientSubnet, dnsCache, dnssecValidation, skipDnsAppAuthoritativeRequestHandlers, context);
                }

                switch (response.RCODE)
                {
                    case DnsResponseCode.NoError:
                    case DnsResponseCode.NxDomain:
                    case DnsResponseCode.YXDomain:
                        taskCompletionSource.SetResult(new RecursiveResolveResponse(response, response));
                        break;

                    default:
                        throw new DnsServerException("All name servers failed to answer the request '" + question.ToString() + "'. Received last response with RCODE=" + response.RCODE.ToString() + (response.Metadata is null ? "." : " from: " + response.Metadata.NameServer));
                }
            }
            catch (Exception ex)
            {
                if (_resolverLog is not null)
                {
                    string strForwarders = null;

                    if (conditionalForwarders is not null)
                    {
                        if (conditionalForwarders.Count > 0)
                        {
                            foreach (DnsResourceRecord conditionalForwarder in conditionalForwarders)
                            {
                                NameServerAddress nameServer = (conditionalForwarder.RDATA as DnsForwarderRecordData).NameServer;

                                if (strForwarders is null)
                                    strForwarders = nameServer.ToString();
                                else
                                    strForwarders += ", " + nameServer.ToString();
                            }
                        }
                    }
                    else if ((_forwarders is not null) && (_forwarders.Count > 0))
                    {
                        foreach (NameServerAddress nameServer in _forwarders)
                        {
                            if (strForwarders is null)
                                strForwarders = nameServer.ToString();
                            else
                                strForwarders += ", " + nameServer.ToString();
                        }
                    }

                    _resolverLog.Write("DNS Server failed to resolve the request '" + question.ToString() + "'" + (strForwarders is null ? "" : " using forwarders: " + strForwarders) + ": " + GetExceptionSummary(ex));
                }

                DnsDatagram cacheRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, dnssecValidation, DnsResponseCode.NoError, [question], null, null, null, _udpPayloadSize, dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(eDnsClientSubnet));
                DnsDatagram cacheResponse = _cacheZoneManager.Enabled ? QueryCache(cacheRequest, _serveStale, _serveStale, conditionalForwarders is null) : null;
                if (cacheResponse is not null)
                {
                    if (!dnssecValidation || cacheResponse.AuthenticData)
                    {
                        taskCompletionSource.SetResult(new RecursiveResolveResponse(cacheResponse, cacheResponse));
                    }
                    else
                    {
                        static bool HasBogusRecords(IReadOnlyList<DnsResourceRecord> records)
                        {
                            foreach (DnsResourceRecord record in records)
                            {
                                switch (record.DnssecStatus)
                                {
                                    case DnssecStatus.Disabled:
                                    case DnssecStatus.Secure:
                                    case DnssecStatus.Insecure:
                                    case DnssecStatus.Indeterminate:
                                        break;

                                    default:
                                        return true;
                                }
                            }

                            return false;
                        }

                        bool isFailureResponse = false;

                        switch (cacheResponse.RCODE)
                        {
                            case DnsResponseCode.NoError:
                            case DnsResponseCode.NxDomain:
                            case DnsResponseCode.YXDomain:
                                isFailureResponse = HasBogusRecords(cacheResponse.Answer);
                                if (!isFailureResponse)
                                    isFailureResponse = HasBogusRecords(cacheResponse.Authority);

                                break;

                            default:
                                isFailureResponse = true;
                                break;
                        }

                        if (isFailureResponse)
                        {
                            List<EDnsOption> options;

                            if ((cacheResponse.EDNS is not null) && (cacheResponse.EDNS.Options.Count > 0))
                            {
                                options = new List<EDnsOption>(cacheResponse.EDNS.Options.Count);

                                foreach (EDnsOption option in cacheResponse.EDNS.Options)
                                {
                                    if (option.Code == EDnsOptionCode.EXTENDED_DNS_ERROR)
                                        options.Add(option);
                                }
                            }
                            else
                            {
                                options = null;
                            }

                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, dnssecValidation, DnsResponseCode.ServerFailure, [question], null, null, null, _udpPayloadSize, dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options);

                            taskCompletionSource.SetResult(new RecursiveResolveResponse(failureResponse, cacheResponse));
                        }
                        else
                        {
                            taskCompletionSource.SetResult(new RecursiveResolveResponse(cacheResponse, cacheResponse));
                        }
                    }
                }
                else
                {
                    IReadOnlyList<EDnsOption> options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Other, "Resolver exception"))];
                    DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, dnssecValidation, DnsResponseCode.ServerFailure, [question], null, null, null, _udpPayloadSize, dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options);

                    taskCompletionSource.SetResult(new RecursiveResolveResponse(failureResponse, failureResponse));
                }
            }
            finally
            {
                _resolverTasks.TryRemove(GetResolverQueryKey(question, eDnsClientSubnet), out _);
            }
        }

        private async Task<DnsDatagram> DefaultRecursiveResolveAsync(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet, IDnsCache dnsCache, bool dnssecValidation, bool skipDnsAppAuthoritativeRequestHandlers, DnsClient.ResolverContext context, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<NameServerAddress> forwarders = _forwarders;

            if ((forwarders is not null) && (forwarders.Count > 0))
            {
                if (_concurrentForwarding)
                {
                    if (_proxy is null)
                    {
                        bool foundStaleEP = false;

                        foreach (NameServerAddress forwarder in forwarders)
                        {
                            if (forwarder.IsIPEndPointStale)
                            {
                                foundStaleEP = true;
                                break;
                            }
                        }

                        if (foundStaleEP)
                        {
                            List<NameServerAddress> newForwarders = new List<NameServerAddress>(forwarders.Count);
                            List<Task<NameServerAddress>> resolveTasks = new List<Task<NameServerAddress>>(forwarders.Count);

                            foreach (NameServerAddress forwarder in forwarders)
                            {
                                if (forwarder.IsIPEndPointStale)
                                {
                                    resolveTasks.Add(ZenitiumLibrary.TaskExtensions.TimeoutAsync(async delegate (CancellationToken cancellationToken1)
                                    {
                                        await forwarder.RecursiveResolveIPAddressAsync(dnsCache, null, _ipv6Mode, _udpPayloadSize, _randomizeName, _resolverRetries, _resolverTimeout, _resolverConcurrency, _resolverMaxStackCount, cancellationToken1);
                                        return forwarder;
                                    }, RECURSIVE_RESOLUTION_TIMEOUT, cancellationToken));
                                }
                                else
                                {
                                    newForwarders.Add(forwarder);
                                }
                            }

                            Exception lastException = null;

                            foreach (Task<NameServerAddress> resolveTask in resolveTasks)
                            {
                                try
                                {
                                    newForwarders.Add(await resolveTask);
                                }
                                catch (Exception ex)
                                {
                                    lastException = ex;
                                    _resolverLog?.Write(GetExceptionSummary(ex));
                                }
                            }

                            if (newForwarders.Count < 1)
                                throw new DnsServerException("Failed to resolve forwarder domain name for all forwarders: " + forwarders.Join(), lastException);

                            forwarders = newForwarders;
                        }
                    }

                    DnsClient dnsClient = new DnsClient(forwarders);

                    dnsClient.Cache = dnsCache;
                    dnsClient.Proxy = _proxy;
                    dnsClient.IPv6Mode = _ipv6Mode;
                    dnsClient.RandomizeName = _randomizeName;
                    dnsClient.EDnsPadding = _eDnsPaddingMode != DnsServerEDnsPaddingMode.Disabled;
                    dnsClient.Retries = _forwarderRetries;
                    dnsClient.Timeout = _forwarderTimeout;
                    dnsClient.Concurrency = _forwarderConcurrency;
                    dnsClient.UdpPayloadSize = _udpPayloadSize;
                    dnsClient.DnssecValidation = dnssecValidation;
                    dnsClient.EDnsClientSubnet = eDnsClientSubnet;
                    dnsClient.ConditionalForwardingZoneCut = question.Name;

                    return await dnsClient.ResolveAsync(question, cancellationToken);
                }
                else
                {
                    DnsDatagram lastResponse = null;
                    Exception lastException = null;

                    foreach (NameServerAddress forwarder in forwarders)
                    {
                        if (_proxy is null)
                        {
                            if (forwarder.IsIPEndPointStale)
                            {
                                try
                                {
                                    await ZenitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                                    {
                                        return forwarder.RecursiveResolveIPAddressAsync(dnsCache, null, _ipv6Mode, _udpPayloadSize, _randomizeName, _resolverRetries, _resolverTimeout, _resolverConcurrency, _resolverMaxStackCount, cancellationToken1);
                                    }, RECURSIVE_RESOLUTION_TIMEOUT, cancellationToken);
                                }
                                catch (Exception ex)
                                {
                                    lastException = ex;
                                    _resolverLog?.Write(GetExceptionSummary(ex));
                                    continue;
                                }
                            }
                        }

                        DnsClient dnsClient = new DnsClient(forwarder);

                        dnsClient.Cache = dnsCache;
                        dnsClient.Proxy = _proxy;
                        dnsClient.IPv6Mode = _ipv6Mode;
                        dnsClient.RandomizeName = _randomizeName;
                        dnsClient.EDnsPadding = _eDnsPaddingMode != DnsServerEDnsPaddingMode.Disabled;
                        dnsClient.Retries = _forwarderRetries;
                        dnsClient.Timeout = _forwarderTimeout;
                        dnsClient.Concurrency = _forwarderConcurrency;
                        dnsClient.UdpPayloadSize = _udpPayloadSize;
                        dnsClient.DnssecValidation = dnssecValidation;
                        dnsClient.EDnsClientSubnet = eDnsClientSubnet;
                        dnsClient.ConditionalForwardingZoneCut = question.Name;

                        try
                        {
                            DnsDatagram response = await dnsClient.ResolveAsync(question, cancellationToken);

                            switch (response.RCODE)
                            {
                                case DnsResponseCode.NoError:
                                case DnsResponseCode.NxDomain:
                                case DnsResponseCode.YXDomain:
                                    return response;

                                default:
                                    if (lastResponse is not null)
                                        response = response.CloneAndAddDnsClientExtendedErrorsFrom(lastResponse);

                                    lastResponse = response;
                                    break;
                            }
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch (Exception ex)
                        {
                            lastException = ex;
                        }

                        if (dnsCache is not ResolverPrefetchDnsCache)
                            dnsCache = new ResolverPrefetchDnsCache(this, skipDnsAppAuthoritativeRequestHandlers, question, dnsCache is not ResolverDnsCache resolverDnsCache || resolverDnsCache.AggressiveNsec);
                    }

                    if (lastResponse is not null)
                        return lastResponse;

                    if (lastException is not null)
                        ExceptionDispatchInfo.Capture(lastException).Throw();

                    throw new InvalidOperationException();
                }
            }
            else
            {
                return await ZenitiumLibrary.TaskExtensions.TimeoutAsync(async delegate (CancellationToken cancellationToken1)
                {
                    Stopwatch stopwatch = Stopwatch.StartNew();

                    DnsDatagram response = await DnsClient.RecursiveResolveAsync(question, dnsCache, _proxy, _ipv6Mode, _udpPayloadSize, _randomizeName, _qnameMinimization, dnssecValidation, eDnsClientSubnet, _resolverRetries, _resolverTimeout, _resolverConcurrency, _resolverMaxStackCount, true, true, null, context, cancellationToken1);

                    stopwatch.Stop();
                    response = response.CloneWithMetadata(response.Metadata?.NameServer, stopwatch.Elapsed.TotalMilliseconds);

                    return response;
                }, RECURSIVE_RESOLUTION_TIMEOUT, cancellationToken);
            }
        }

        internal async Task<DnsDatagram> PriorityConditionalForwarderResolveAsync(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet, IDnsCache dnsCache, bool skipDnsAppAuthoritativeRequestHandlers, IReadOnlyList<DnsResourceRecord> conditionalForwarders, DnsClient.ResolverContext context)
        {
            if (conditionalForwarders.Count == 1)
            {
                DnsResourceRecord conditionalForwarder = conditionalForwarders[0];
                return await ConditionalForwarderResolveAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, dnsCache, conditionalForwarder.RDATA as DnsForwarderRecordData, conditionalForwarder.Name, skipDnsAppAuthoritativeRequestHandlers, context);
            }

            List<Task> resolveTasks = new List<Task>(conditionalForwarders.Count);

            foreach (DnsResourceRecord conditionalForwarder in conditionalForwarders)
            {
                if (conditionalForwarder.Type != DnsResourceRecordType.FWD)
                    continue;

                DnsForwarderRecordData forwarder = conditionalForwarder.RDATA as DnsForwarderRecordData;

                if (forwarder.Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                    continue;

                NetProxy proxy = forwarder.GetProxy(_proxy);
                if (proxy is null)
                {
                    if (forwarder.NameServer.IsIPEndPointStale)
                    {
                        resolveTasks.Add(ZenitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
                        {
                            return forwarder.NameServer.RecursiveResolveIPAddressAsync(dnsCache, null, _ipv6Mode, _udpPayloadSize, _randomizeName, _resolverRetries, _resolverTimeout, _resolverConcurrency, _resolverMaxStackCount, cancellationToken1);
                        }, RECURSIVE_RESOLUTION_TIMEOUT));
                    }
                }
            }

            Exception lastResolverException = null;

            foreach (Task resolverTask in resolveTasks)
            {
                try
                {
                    await resolverTask;
                }
                catch (Exception ex)
                {
                    lastResolverException = ex;
                    _resolverLog?.Write(GetExceptionSummary(ex));
                }
            }

            Dictionary<byte, List<DnsResourceRecord>> conditionalForwarderGroups = new Dictionary<byte, List<DnsResourceRecord>>(conditionalForwarders.Count);
            {
                foreach (DnsResourceRecord conditionalForwarder in conditionalForwarders)
                {
                    if (conditionalForwarder.Type != DnsResourceRecordType.FWD)
                        continue;

                    DnsForwarderRecordData forwarder = conditionalForwarder.RDATA as DnsForwarderRecordData;

                    if (forwarder.NameServer.IsIPEndPointStale && !forwarder.Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (conditionalForwarderGroups.TryGetValue(forwarder.Priority, out List<DnsResourceRecord> conditionalForwardersEntry))
                    {
                        conditionalForwardersEntry.Add(conditionalForwarder);
                    }
                    else
                    {
                        conditionalForwardersEntry = new List<DnsResourceRecord>(2)
                        {
                            conditionalForwarder
                        };

                        conditionalForwarderGroups[forwarder.Priority] = conditionalForwardersEntry;
                    }
                }
            }

            if (conditionalForwarderGroups.Count < 1)
            {
                List<NameServerAddress> forwarders = new List<NameServerAddress>(conditionalForwarders.Count);

                foreach (DnsResourceRecord conditionalForwarder in conditionalForwarders)
                {
                    if (conditionalForwarder.Type != DnsResourceRecordType.FWD)
                        continue;

                    forwarders.Add((conditionalForwarder.RDATA as DnsForwarderRecordData).NameServer);
                }

                throw new DnsServerException("Failed to resolve forwarder domain name for all conditional forwarders: " + forwarders.Join(), lastResolverException);
            }

            if (conditionalForwarderGroups.Count == 1)
            {
                foreach (KeyValuePair<byte, List<DnsResourceRecord>> conditionalForwardersEntry in conditionalForwarderGroups)
                    return await ConcurrentConditionalForwarderResolveAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, dnsCache, conditionalForwardersEntry.Value, skipDnsAppAuthoritativeRequestHandlers, context);
            }

            List<byte> priorities = new List<byte>(conditionalForwarderGroups.Keys);
            priorities.Sort();

            using (CancellationTokenSource cancellationTokenSource = new CancellationTokenSource())
            {
                CancellationToken currentCancellationToken = cancellationTokenSource.Token;

                DnsDatagram lastResponse = null;
                Exception lastException = null;

                foreach (byte priority in priorities)
                {
                    if (!conditionalForwarderGroups.TryGetValue(priority, out List<DnsResourceRecord> conditionalForwardersEntry))
                        continue;

                    Task<DnsDatagram> priorityTask = ConcurrentConditionalForwarderResolveAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, dnsCache, conditionalForwardersEntry, skipDnsAppAuthoritativeRequestHandlers, context, currentCancellationToken);

                    try
                    {
                        DnsDatagram priorityTaskResponse = await priorityTask;

                        switch (priorityTaskResponse.RCODE)
                        {
                            case DnsResponseCode.NoError:
                            case DnsResponseCode.NxDomain:
                            case DnsResponseCode.YXDomain:
                                cancellationTokenSource.Cancel();
                                return priorityTaskResponse;

                            default:
                                lastResponse = priorityTaskResponse;
                                break;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        lastException = ex;

                        if (lastException is AggregateException)
                            lastException = lastException.InnerException;
                    }

                    if (dnsCache is not ResolverPrefetchDnsCache)
                        dnsCache = new ResolverPrefetchDnsCache(this, skipDnsAppAuthoritativeRequestHandlers, question, false);
                }

                if (lastResponse is not null)
                    return lastResponse;

                if (lastException is not null)
                    ExceptionDispatchInfo.Capture(lastException).Throw();

                throw new InvalidOperationException();
            }
        }

        private async Task<DnsDatagram> ConcurrentConditionalForwarderResolveAsync(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet, IDnsCache dnsCache, List<DnsResourceRecord> conditionalForwarders, bool skipDnsAppAuthoritativeRequestHandlers, DnsClient.ResolverContext context, CancellationToken cancellationToken = default)
        {
            if (conditionalForwarders.Count == 1)
            {
                DnsResourceRecord conditionalForwarder = conditionalForwarders[0];
                return await ConditionalForwarderResolveAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, dnsCache, conditionalForwarder.RDATA as DnsForwarderRecordData, conditionalForwarder.Name, skipDnsAppAuthoritativeRequestHandlers, context, cancellationToken);
            }

            using (CancellationTokenSource cancellationTokenSource = new CancellationTokenSource())
            {
                using CancellationTokenRegistration r = cancellationToken.Register(cancellationTokenSource.Cancel);

                CancellationToken currentCancellationToken = cancellationTokenSource.Token;
                List<Task<DnsDatagram>> tasks = new List<Task<DnsDatagram>>(conditionalForwarders.Count);

                foreach (DnsResourceRecord conditionalForwarder in conditionalForwarders)
                {
                    if (conditionalForwarder.Type != DnsResourceRecordType.FWD)
                        continue;

                    DnsForwarderRecordData forwarder = conditionalForwarder.RDATA as DnsForwarderRecordData;

                    tasks.Add(Task.Factory.StartNew(delegate ()
                    {
                        return ConditionalForwarderResolveAsync(question, eDnsClientSubnet, advancedForwardingClientSubnet, dnsCache, forwarder, conditionalForwarder.Name, skipDnsAppAuthoritativeRequestHandlers, context, currentCancellationToken);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current).Unwrap());
                }

                DnsDatagram lastResponse = null;
                Exception lastException = null;

                while (tasks.Count > 0)
                {
                    Task<DnsDatagram> completedTask = await Task.WhenAny(tasks);

                    try
                    {
                        DnsDatagram taskResponse = await completedTask;

                        switch (taskResponse.RCODE)
                        {
                            case DnsResponseCode.NoError:
                            case DnsResponseCode.NxDomain:
                            case DnsResponseCode.YXDomain:
                                cancellationTokenSource.Cancel();
                                return taskResponse;

                            default:
                                if (lastResponse is not null)
                                    taskResponse = taskResponse.CloneAndAddDnsClientExtendedErrorsFrom(lastResponse);

                                lastResponse = taskResponse;
                                break;
                        }
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex)
                    {
                        lastException = ex;

                        if (lastException is AggregateException)
                            lastException = lastException.InnerException;
                    }

                    tasks.Remove(completedTask);
                }

                if (lastResponse is not null)
                    return lastResponse;

                if (lastException is not null)
                    ExceptionDispatchInfo.Capture(lastException).Throw();

                throw new InvalidOperationException();
            }
        }

        private Task<DnsDatagram> ConditionalForwarderResolveAsync(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet, IDnsCache dnsCache, DnsForwarderRecordData forwarder, string conditionalForwardingZoneCut, bool skipDnsAppAuthoritativeRequestHandlers, DnsClient.ResolverContext context, CancellationToken cancellationToken = default)
        {
            if (forwarder.Forwarder.Equals("this-server", StringComparison.OrdinalIgnoreCase))
            {
                return DefaultRecursiveResolveAsync(question, eDnsClientSubnet, dnsCache, forwarder.DnssecValidation, skipDnsAppAuthoritativeRequestHandlers, context, cancellationToken);
            }
            else
            {
                DnsClient dnsClient = new DnsClient(forwarder.NameServer);

                dnsClient.Cache = dnsCache;
                dnsClient.Proxy = forwarder.GetProxy(_proxy);
                dnsClient.IPv6Mode = _ipv6Mode;
                dnsClient.RandomizeName = _randomizeName;
                dnsClient.EDnsPadding = _eDnsPaddingMode != DnsServerEDnsPaddingMode.Disabled;
                dnsClient.Retries = _forwarderRetries;
                dnsClient.Timeout = _forwarderTimeout;
                dnsClient.Concurrency = _forwarderConcurrency;
                dnsClient.UdpPayloadSize = _udpPayloadSize;
                dnsClient.DnssecValidation = forwarder.DnssecValidation;
                dnsClient.EDnsClientSubnet = eDnsClientSubnet;
                dnsClient.AdvancedForwardingClientSubnet = advancedForwardingClientSubnet;
                dnsClient.ConditionalForwardingZoneCut = conditionalForwardingZoneCut;

                return dnsClient.ResolveAsync(question, cancellationToken);
            }
        }

        private DnsDatagram PrepareRecursiveResolveResponse(DnsDatagram request, RecursiveResolveResponse resolveResponse)
        {
            DnsDatagram response;

            bool checkingDisabled = request.CheckingDisabled;
            if (checkingDisabled)
                response = resolveResponse.CheckingDisabledResponse;
            else
                response = resolveResponse.Response;

            DnsResponseCode rCode;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                case DnsResponseCode.NxDomain:
                case DnsResponseCode.YXDomain:
                    rCode = response.RCODE;
                    break;

                default:
                    rCode = DnsResponseCode.ServerFailure;
                    break;
            }

            bool dnssecOk = _dnssecValidation && request.DnssecOk;
            IReadOnlyList<DnsResourceRecord> answer;
            IReadOnlyList<DnsResourceRecord> authority;

            if (dnssecOk)
            {
                answer = response.Answer;
                authority = response.Authority;
            }
            else
            {
                answer = ZenitiumLibrary.Net.Dns.DnsCache.DnsSpecialCacheRecordData.FilterDnssecAnswerRecords(response.Answer);
                authority = ZenitiumLibrary.Net.Dns.DnsCache.DnsSpecialCacheRecordData.FilterDnssecAuthorityRecords(response.Authority);
            }

            IReadOnlyList<DnsResourceRecord> additional = response.Additional;
            if (additional.Count > 0)
            {
                List<DnsResourceRecord> RemoveOPTFromAdditional()
                {
                    if ((additional.Count == 1) && (additional[0].Type == DnsResourceRecordType.OPT))
                        return [];

                    List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>(additional.Count);

                    foreach (DnsResourceRecord record in additional)
                    {
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.OPT:
                                continue;

                            case DnsResourceRecordType.RRSIG:
                            case DnsResourceRecordType.DNSKEY:
                                if (dnssecOk)
                                    break;

                                continue;
                        }

                        newAdditional.Add(record);
                    }

                    return newAdditional;
                }

                List<EDnsOption> FilterEDnsOptions()
                {
                    List<EDnsOption> newOptions = new List<EDnsOption>(response.EDNS.Options.Count + response.DnsClientExtendedErrors.Count);
                    bool foundECS = false;

                    foreach (EDnsOption option in response.EDNS.Options)
                    {
                        switch (option.Code)
                        {
                            case EDnsOptionCode.EXTENDED_DNS_ERROR:
                                newOptions.Add(option);
                                break;

                            case EDnsOptionCode.EDNS_CLIENT_SUBNET:
                                if (request.GetEDnsClientSubnetOption(true) is not null)
                                    newOptions.Add(option);

                                foundECS = true;
                                break;
                        }
                    }

                    if (!foundECS)
                    {
                        EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption(true);
                        if (requestECS is not null)
                            newOptions.Add(new EDnsOption(EDnsOptionCode.EDNS_CLIENT_SUBNET, new EDnsClientSubnetOptionData(requestECS.SourcePrefixLength, 0, requestECS.Address)));
                    }

                    foreach (EDnsExtendedDnsErrorOptionData ee in response.DnsClientExtendedErrors)
                        newOptions.Add(new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, ee));

                    return newOptions;
                }

                if (request.EDNS is null)
                {
                    if (response.EDNS is not null)
                    {
                        additional = RemoveOPTFromAdditional();
                    }
                }
                else
                {
                    if (response.EDNS is null)
                    {
                        additional = RemoveOPTFromAdditional();

                        DnsResourceRecord optRecord = DnsDatagramEdns.GetOPTFor(_udpPayloadSize, rCode, 0, dnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, null);

                        if (additional.Count == 0)
                            additional = [optRecord];
                        else
                            additional = [.. additional, optRecord];
                    }
                    else
                    {
                        List<DnsResourceRecord> newAdditional = RemoveOPTFromAdditional();

                        IReadOnlyList<EDnsOption> options = FilterEDnsOptions();
                        newAdditional.Add(DnsDatagramEdns.GetOPTFor(_udpPayloadSize, rCode, 0, dnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, options));

                        additional = newAdditional;
                    }
                }
            }

            bool authenticData = false;

            if (response.Answer.Count > 0)
            {
                authenticData = true;

                foreach (DnsResourceRecord record in response.Answer)
                {
                    if (record.DnssecStatus != DnssecStatus.Secure)
                    {
                        authenticData = false;
                        break;
                    }
                }
            }
            else if (response.Authority.Count > 0)
            {
                authenticData = true;

                foreach (DnsResourceRecord record in response.Authority)
                {
                    if (record.DnssecStatus != DnssecStatus.Secure)
                    {
                        authenticData = false;
                        break;
                    }
                }
            }

            DnsDatagram finalResponse = new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, true, true, authenticData, checkingDisabled, rCode, request.Question, answer, authority, additional);
            DnsDatagramMetadata metadata = response.Metadata;
            if (metadata is not null)
                finalResponse.SetMetadata(metadata.NameServer, metadata.RoundTripTime);

            return finalResponse;
        }

        private static string GetResolverQueryKey(DnsQuestionRecord question, NetworkAddress eDnsClientSubnet)
        {
            if (eDnsClientSubnet is null)
                return question.ToString();

            return question.ToString() + " " + eDnsClientSubnet.ToString();
        }

        private DnsDatagram QueryCache(DnsDatagram request, bool serveStale, bool resetExpiry, bool aggressiveNsec)
        {
            DnsDatagram cacheResponse = _cacheZoneManager.Query(request, serveStale, false, resetExpiry, aggressiveNsec);
            if (cacheResponse is not null)
            {
                if ((cacheResponse.RCODE != DnsResponseCode.NoError) || (cacheResponse.Answer.Count > 0) || (cacheResponse.Authority.Count == 0) || cacheResponse.IsFirstAuthoritySOA())
                {
                    cacheResponse.Tag = ResponseTypeTags.Cached;

                    return cacheResponse;
                }
            }

            return null;
        }

        internal Task<bool> ProbeIPv6UpstreamAsync()
        {
            return IPv6Reachability.ProbeAsync(Math.Max(_resolverTimeout, 3000));
        }

        private async Task StartupIPv6ProbeAsync()
        {
            try
            {
                await Task.Delay(IPV6_STARTUP_PROBE_DELAY);

                if ((_state != ServiceState.Running) || (_ipv6Mode == IPv6Mode.Disabled) || (_proxy is not null) || !IPv6Reachability.Enabled || IPv6Reachability.IsUnavailable)
                    return;

                await ProbeIPv6UpstreamAsync();
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }
        }

        private void IPv6Reachability_AvailabilityChanged(object sender, bool available)
        {
            if ((_ipv6Mode == IPv6Mode.Disabled) || (_proxy is not null))
                return;

            _log?.Write(available ? "DNS Server detected that IPv6 name servers are reachable again. Outbound IPv6 queries were resumed." : "DNS Server detected that IPv6 name servers are not reachable (confirmed by probing IPv6 root servers). Outbound queries will use IPv4 until IPv6 is reachable again. " + IPv6Reachability.LastProbeError);
        }

        private async void Ipv6ProbeTimerCallback(object state)
        {
            try
            {
                if ((_ipv6Mode != IPv6Mode.Disabled) && (_proxy is null) && IPv6Reachability.IsUnavailable)
                    await ProbeIPv6UpstreamAsync();
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }
            finally
            {
                lock (_ipv6ProbeTimerLock)
                {
                    _ipv6ProbeTimer?.Change(IPV6_PROBE_TIMER_INTERVAL, Timeout.Infinite);
                }
            }
        }

        private uint GetPrefetchThreshold(uint originalTtl)
        {
            uint threshold = Math.Min((uint)_cachePrefetchTrigger, originalTtl / 10);

            if (_cachePrefetchTriggerPercent > 0)
                threshold = Math.Max(threshold, (uint)((ulong)originalTtl * (ulong)_cachePrefetchTriggerPercent / 100));

            return threshold;
        }

        private async Task PrefetchCacheAsync(DnsQuestionRecord question, IPEndPoint remoteEP, IReadOnlyList<DnsResourceRecord> conditionalForwarders, bool dnssecValidation, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet)
        {
            try
            {
                DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [question]);

                if (eDnsClientSubnet is not null)
                    request.SetShadowEDnsClientSubnetOption(eDnsClientSubnet, advancedForwardingClientSubnet);

                _ = await RecursiveResolveAsync(request, remoteEP, conditionalForwarders, dnssecValidation, true, false, _clientTimeout, new DnsClient.ResolverContext());
            }
            catch (Exception ex)
            {
                _resolverLog?.Write(GetExceptionSummary(ex));
            }
        }

        private static Dictionary<int, (int, int)> GetDefaultQpsPrefixLimitsIPv4()
        {
            return new Dictionary<int, (int, int)>()
            {
                { 32, (1000, 5000) }
            };
        }

        private static Dictionary<int, (int, int)> GetDefaultQpsPrefixLimitsIPv6()
        {
            return new Dictionary<int, (int, int)>()
            {
                { 64, (1000, 5000) },
                { 48, (10000, 50000) }
            };
        }

        private static bool HasSameEntries(IReadOnlyDictionary<int, (int, int)> x, IReadOnlyDictionary<int, (int, int)> y)
        {
            if (x.Count != y.Count)
                return false;

            foreach (KeyValuePair<int, (int, int)> entry in x)
            {
                if (!y.TryGetValue(entry.Key, out (int, int) value) || (value != entry.Value))
                    return false;
            }

            return true;
        }

        private static Dictionary<int, (int, int)> ConvertQpmToQps(IReadOnlyDictionary<int, (int, int)> qpmPrefixLimits)
        {
            static int Convert(int qpm)
            {
                if (qpm <= 0)
                    return 0;

                return (int)Math.Min(int.MaxValue, ((long)qpm + 59) / 60);
            }

            Dictionary<int, (int, int)> qpsPrefixLimits = new Dictionary<int, (int, int)>(qpmPrefixLimits.Count);

            foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in qpmPrefixLimits)
                qpsPrefixLimits[qpmPrefixLimit.Key] = (Convert(qpmPrefixLimit.Value.Item1), Convert(qpmPrefixLimit.Value.Item2));

            return qpsPrefixLimits;
        }

        internal static IReadOnlyDictionary<int, (int, int)> ConvertLegacyQpmPrefixLimits(IReadOnlyDictionary<int, (int, int)> qpmPrefixLimits, bool ipv6)
        {
            if (ipv6)
            {
                if (HasSameEntries(qpmPrefixLimits, new Dictionary<int, (int, int)>() { { 128, (600, 600) }, { 64, (1200, 1200) }, { 56, (6000, 6000) } }))
                    return GetDefaultQpsPrefixLimitsIPv6();
            }
            else
            {
                if (HasSameEntries(qpmPrefixLimits, new Dictionary<int, (int, int)>() { { 32, (600, 600) }, { 24, (6000, 6000) } }))
                    return GetDefaultQpsPrefixLimitsIPv4();
            }

            return ConvertQpmToQps(qpmPrefixLimits);
        }

        private static Dictionary<int, (int, int)> ReadPrefixLimits(BinaryReader bR)
        {
            int count = bR.ReadByte();
            Dictionary<int, (int, int)> prefixLimits = new Dictionary<int, (int, int)>(count);

            for (int i = 0; i < count; i++)
                prefixLimits[bR.ReadInt32()] = (bR.ReadInt32(), bR.ReadInt32());

            return prefixLimits;
        }

        private static void WritePrefixLimits(BinaryWriter bW, IReadOnlyDictionary<int, (int, int)> prefixLimits)
        {
            bW.Write(Convert.ToByte(prefixLimits.Count));

            foreach (KeyValuePair<int, (int, int)> prefixLimit in prefixLimits)
            {
                bW.Write(prefixLimit.Key);
                bW.Write(prefixLimit.Value.Item1);
                bW.Write(prefixLimit.Value.Item2);
            }
        }

        private void ApplyRateLimits()
        {
            _rateLimiter.Configure(_qpsPrefixLimitsIPv4, _qpsPrefixLimitsIPv6, _rateLimitBurstSeconds);
        }

        private string GetDdrTargetName()
        {
            X509Certificate2 certificate = _dnsTlsCertificate;
            if (certificate is null)
                return _serverDomain;

            try
            {
                if (certificate.MatchesHostname(_serverDomain))
                    return _serverDomain;

                foreach (X509Extension extension in certificate.Extensions)
                {
                    if (extension.Oid?.Value != "2.5.29.17")
                        continue;

                    X509SubjectAlternativeNameExtension sanExtension = new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);

                    foreach (string dnsName in sanExtension.EnumerateDnsNames())
                    {
                        if (!dnsName.StartsWith('*'))
                            return dnsName;
                    }
                }
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }

            return _serverDomain;
        }

        public IReadOnlyList<string> GetTlsWildcardDomains()
        {
            List<string> domains = new List<string>();

            X509Certificate2 certificate = _dnsTlsCertificate;
            if (certificate is null)
                return domains;

            try
            {
                foreach (X509Extension extension in certificate.Extensions)
                {
                    if (extension.Oid?.Value != "2.5.29.17")
                        continue;

                    foreach (string dnsName in new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical).EnumerateDnsNames())
                    {
                        if (!dnsName.StartsWith("*.", StringComparison.Ordinal))
                            continue;

                        string domain = dnsName.Substring(2).TrimEnd('.').ToLowerInvariant();

                        if ((domain.IndexOf('.') > 0) && DnsClient.IsDomainNameValid(domain) && !domains.Contains(domain))
                            domains.Add(domain);
                    }
                }
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }

            return domains;
        }

        public string TlsHostName
        { get { return GetDdrTargetName(); } }

        public IReadOnlyList<DnsResourceRecord> GetDdrRecords(string ownerName = DDR_DOMAIN)
        {
            List<DnsResourceRecord> records = new List<DnsResourceRecord>(3);
            bool hasCertificate = _dnsTlsCertificate is not null;

            if (!hasCertificate && !_ddrProxyDoh)
                return records;

            string targetName = GetDdrTargetName();

            List<IPAddress> ipv4Hints = new List<IPAddress>();
            List<IPAddress> ipv6Hints = new List<IPAddress>();

            foreach (IPEndPoint localEP in _localEndPoints)
            {
                IPAddress address = localEP.Address;

                if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any) || IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal)
                    continue;

                if (address.AddressFamily == AddressFamily.InterNetwork)
                {
                    if (!ipv4Hints.Contains(address))
                        ipv4Hints.Add(address);
                }
                else if (!ipv6Hints.Contains(address))
                {
                    ipv6Hints.Add(address);
                }
            }

            ushort priority = 1;

            void Add(List<string> alpn, int port, string dohPath)
            {
                Dictionary<DnsSvcParamKey, DnsSvcParamValue> svcParams = new Dictionary<DnsSvcParamKey, DnsSvcParamValue>
                {
                    { DnsSvcParamKey.ALPN, new DnsSvcAlpnParamValue(alpn) },
                    { DnsSvcParamKey.Port, new DnsSvcPortParamValue((ushort)port) }
                };

                if (dohPath is not null)
                    svcParams.Add(DnsSvcParamKey.DoHPath, new DnsSvcDoHPathParamValue(dohPath));

                if (ipv4Hints.Count > 0)
                    svcParams.Add(DnsSvcParamKey.IPv4Hint, new DnsSvcIPv4HintParamValue(ipv4Hints));

                if (ipv6Hints.Count > 0)
                    svcParams.Add(DnsSvcParamKey.IPv6Hint, new DnsSvcIPv6HintParamValue(ipv6Hints));

                records.Add(new DnsResourceRecord(ownerName, DnsResourceRecordType.SVCB, DnsClass.IN, DDR_RECORD_TTL, new DnsSVCBRecordData(priority++, targetName, svcParams)));
            }

            if (_enableDnsOverHttps && hasCertificate)
            {
                List<string> alpn = new List<string>(2);

                if (IsHttp2Supported())
                    alpn.Add("h2");

                if (_enableDnsOverHttp3)
                    alpn.Add("h3");

                if (alpn.Count == 0)
                    alpn.Add("http/1.1");

                Add(alpn, _dnsOverHttpsPort, "/dns-query{?dns}");
            }
            else if (_ddrProxyDoh)
            {
                List<string> alpn = ["h2"];

                if (_ddrProxyDohHttp3)
                    alpn.Add("h3");

                Add(alpn, _ddrProxyDohPort, "/dns-query{?dns}");
            }

            if (_enableDnsOverTls && hasCertificate)
                Add(["dot"], _dnsOverTlsPort, null);

            if (_enableDnsOverQuic && hasCertificate && QuicListener.IsSupported)
                Add(["doq"], _dnsOverQuicPort, null);

            return records;
        }

        internal IReadOnlyList<(string, bool)> GetListenerStatus()
        {
            static bool HasListener(List<Socket> listeners, IPEndPoint endPoint)
            {
                lock (listeners)
                {
                    foreach (Socket listener in listeners)
                    {
                        try
                        {
                            if ((listener.LocalEndPoint is IPEndPoint localEP) && localEP.Address.Equals(endPoint.Address) && (localEP.Port == endPoint.Port))
                                return true;
                        }
                        catch (ObjectDisposedException)
                        { }
                    }
                }

                return false;
            }

            List<(string, bool)> status = new List<(string, bool)>();

            foreach (IPEndPoint localEP in _localEndPoints)
            {
                if (_do53Mode != DnsServerDo53Mode.Disabled)
                {
                    status.Add(("UDP " + localEP, HasListener(_udpListeners, localEP)));
                    status.Add(("TCP " + localEP, HasListener(_tcpListeners, localEP)));
                }

                if (_enableDnsOverTls && (_dotSslServerAuthenticationOptions is not null))
                {
                    IPEndPoint tlsEP = new IPEndPoint(localEP.Address, _dnsOverTlsPort);
                    status.Add(("DoT " + tlsEP, HasListener(_tlsListeners, tlsEP)));
                }
            }

            if (_enableDnsOverQuic && (_doqSslServerAuthenticationOptions is not null))
                status.Add(("DoQ Port " + _dnsOverQuicPort, _quicListeners.Count > 0));

            if (_enableDnsOverHttp || ((_enableDnsOverHttps || _enableDnsOverHttpsUnixSocket) && (_dohSslServerAuthenticationOptions is not null)))
                status.Add(("DoH", _dohWebService is not null));

            return status;
        }

        private static bool IsUnencryptedProtocol(DnsTransportProtocol protocol)
        {
            switch (protocol)
            {
                case DnsTransportProtocol.Udp:
                case DnsTransportProtocol.Tcp:
                case DnsTransportProtocol.UdpProxy:
                case DnsTransportProtocol.TcpProxy:
                    return true;

                default:
                    return false;
            }
        }

        private void UpdateAutoAllowedNames()
        {
            List<string> names = new List<string>();

            void Add(string name)
            {
                if (string.IsNullOrEmpty(name))
                    return;

                name = name.TrimEnd('.').ToLowerInvariant();

                if (name.StartsWith("*.", StringComparison.Ordinal))
                    name = name.Substring(2);

                if ((name.IndexOf('.') < 1) || IPAddress.TryParse(name, out _) || !DnsClient.IsDomainNameValid(name) || names.Contains(name))
                    return;

                names.Add(name);
            }

            Add(_serverDomain);

            X509Certificate2 certificate = _dnsTlsCertificate;
            if (certificate is not null)
            {
                try
                {
                    foreach (X509Extension extension in certificate.Extensions)
                    {
                        if (extension.Oid?.Value != "2.5.29.17")
                            continue;

                        foreach (string dnsName in new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical).EnumerateDnsNames())
                            Add(dnsName);
                    }
                }
                catch (Exception ex)
                {
                    _log?.Write(ex);
                }
            }

            _autoAllowedNames = names.ToArray();
        }

        private bool IsAutoAllowed(string name)
        {
            foreach (string allowedName in _autoAllowedNames)
            {
                if (name.Length == allowedName.Length)
                {
                    if (name.Equals(allowedName, StringComparison.OrdinalIgnoreCase))
                        return true;
                }
                else if ((name.Length > allowedName.Length) && (name[name.Length - allowedName.Length - 1] == '.') && name.EndsWith(allowedName, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        private bool TryGetSignalDomain(string name, out string signalDomain)
        {
            if (_blockFirefoxCanaryDomain && (name.Equals(FIREFOX_CANARY_DOMAIN, StringComparison.OrdinalIgnoreCase) || name.EndsWith("." + FIREFOX_CANARY_DOMAIN, StringComparison.OrdinalIgnoreCase)))
            {
                signalDomain = FIREFOX_CANARY_DOMAIN;
                return true;
            }

            if (_forceChromePreflight && name.Equals(CHROME_PREFLIGHT_DOMAIN, StringComparison.OrdinalIgnoreCase))
            {
                signalDomain = CHROME_PREFLIGHT_DOMAIN;
                return true;
            }

            signalDomain = null;
            return false;
        }

        private DnsDatagram GetSignalDomainResponse(DnsDatagram request, string signalDomain)
        {
            DnsResourceRecord[] authority = [new DnsResourceRecord(signalDomain, DnsResourceRecordType.SOA, DnsClass.IN, _blockingNegativeTtl, new DnsSOARecordData(_serverDomain, _defaultResponsiblePerson?.Address ?? _fallbackResponsiblePerson.Address, 1, 3600, 1200, 604800, _blockingNegativeTtl))];
            EDnsOption[] options = request.EDNS is null ? null : [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, signalDomain.Equals(FIREFOX_CANARY_DOMAIN, StringComparison.Ordinal) ? "Firefox canary domain" : "Chrome preflight mode"))];

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, true, false, request.CheckingDisabled, DnsResponseCode.NxDomain, request.Question, null, authority, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, EDnsHeaderFlags.None, options) { Tag = ResponseTypeTags.Blocked };
        }

        private static string GetExceptionSummary(Exception ex)
        {
            StringBuilder summary = new StringBuilder(ex.Message.Trim());
            string lastMessage = ex.Message;

            for (Exception inner = ex.InnerException; (inner is not null) && (summary.Length < 600); inner = inner.InnerException)
            {
                if (inner.Message.Equals(lastMessage, StringComparison.Ordinal))
                    continue;

                summary.Append(" > ").Append(inner.Message.Trim());
                lastMessage = inner.Message;
            }

            if (summary.Length > 600)
                summary.Length = 600;

            return summary.ToString().Replace('\n', ' ').Replace('\r', ' ');
        }

        private bool IsDo53Restricted(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol)
        {
            switch (_do53Mode)
            {
                case DnsServerDo53Mode.DdrOnlyDrop:
                case DnsServerDo53Mode.DdrOnlyRefused:
                    break;

                default:
                    return false;
            }

            if (!IsUnencryptedProtocol(protocol) || IPAddress.IsLoopback(remoteEP.Address))
                return false;

            if (request.Question.Count != 1)
                return true;

            string name = request.Question[0].Name;

            return !name.Equals("resolver.arpa", StringComparison.OrdinalIgnoreCase) && !name.EndsWith(".resolver.arpa", StringComparison.OrdinalIgnoreCase) && !IsDdrQueryName(name);
        }

        private bool IsDdrQueryName(string name)
        {
            if (name.Equals(DDR_DOMAIN, StringComparison.OrdinalIgnoreCase))
                return true;

            if (!name.StartsWith("_dns.", StringComparison.OrdinalIgnoreCase))
                return false;

            string resolverName = name.Substring(5);

            if (resolverName.IndexOf('.') < 1)
                return false;

            return resolverName.Equals(_serverDomain, StringComparison.OrdinalIgnoreCase) || resolverName.Equals(GetDdrTargetName(), StringComparison.OrdinalIgnoreCase);
        }

        private DnsDatagram GetDdrResponse(DnsDatagram request)
        {
            DnsQuestionRecord question = request.Question[0];
            IReadOnlyList<DnsResourceRecord> answer = null;
            IReadOnlyList<DnsResourceRecord> authority = null;

            if (question.Type == DnsResourceRecordType.SVCB)
            {
                IReadOnlyList<DnsResourceRecord> records = GetDdrRecords(question.Name);
                if (records.Count > 0)
                    answer = records;
            }

            if (answer is null)
            {
                string zone = question.Name.EndsWith("resolver.arpa", StringComparison.OrdinalIgnoreCase) ? "resolver.arpa" : question.Name.Substring(5);
                authority = [new DnsResourceRecord(zone, DnsResourceRecordType.SOA, DnsClass.IN, DDR_RECORD_TTL, new DnsSOARecordData(_serverDomain, _defaultResponsiblePerson?.Address ?? _fallbackResponsiblePerson.Address, 1, 3600, 1200, 604800, DDR_RECORD_TTL))];
            }

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, true, false, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, answer, authority, null, request.EDNS is null ? ushort.MinValue : _udpPayloadSize, EDnsHeaderFlags.None) { Tag = ResponseTypeTags.Authoritative };
        }

        private bool IsRateLimitBypassed(IPAddress remoteIP)
        {
            if (IPAddress.IsLoopback(remoteIP))
                return true;

            IReadOnlyCollection<NetworkAddress> bypassList = _rateLimitBypassList;

            if (bypassList is not null)
            {
                foreach (NetworkAddress networkAddress in bypassList)
                {
                    if (networkAddress.Contains(remoteIP))
                        return true;
                }
            }

            return false;
        }

        internal bool IsClientBlocked(IPAddress remoteIP)
        {
            if (!_clientBlockListManager.IsEnabled || !_clientBlockListManager.Contains(remoteIP))
                return false;

            if (IsRateLimitBypassed(remoteIP))
                return false;

            _clientBlockListManager.CountDrop();
            return true;
        }

        internal bool IsRateLimited(IPAddress remoteIP, DnsTransportProtocol protocol)
        {
            if (!_rateLimiter.IsEnabled)
                return false;

            if (IsRateLimitBypassed(remoteIP))
                return false;

            return !_rateLimiter.TryAcquire(remoteIP, protocol != DnsTransportProtocol.Udp);
        }

        internal bool IsClientRateLimited(IPAddress remoteIP)
        {
            if (!_rateLimiter.IsEnabled || IsRateLimitBypassed(remoteIP))
                return false;

            return _rateLimiter.IsLimited(remoteIP);
        }

        private void RateLimitMaintenanceTimerCallback(object state)
        {
            try
            {
                _rateLimiter.Maintain(delegate (string message) { _log.Write(message); }, _log.HideClientAddresses);
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }
        }

        private DnsDatagram ApplyDnsCookie(DnsDatagram request, IPAddress clientAddress, DnsDatagram response)
        {
            if (!_enableDnsCookies || (request.EDNS is null) || (response.EDNS is null))
                return response;

            EDnsCookieOptionData requestCookie = DnsCookie.GetCookieOption(request, out int count);
            if ((requestCookie is null) || (count > 1) || requestCookie.IsMalformed)
                return response;

            return response.CloneWithEDnsOptions(DnsCookie.ReplaceCookieOption(response.EDNS.Options, DnsCookie.CreateServerCookieOption(requestCookie.ClientCookie, clientAddress, _dnsCookieSecret)));
        }

        private bool SendRateLimitedTruncationResponse()
        {
            switch (_rateLimitUdpTruncationPercentage)
            {
                case 0:
                    return false;

                case 100:
                    return true;

                default:
                    return RandomNumberGenerator.GetInt32(100) < _rateLimitUdpTruncationPercentage;
            }
        }

        private void UpdateThisServer()
        {
            foreach (IPEndPoint localEndPoint in _localEndPoints)
            {
                if (localEndPoint.Address.Equals(IPAddress.Any) || localEndPoint.Address.Equals(IPAddress.Loopback))
                {
                    _thisServer = new NameServerAddress(_serverDomain, new IPEndPoint(IPAddress.Loopback, localEndPoint.Port));
                    return;
                }

                if (localEndPoint.Address.Equals(IPAddress.IPv6Any) || localEndPoint.Address.Equals(IPAddress.IPv6Loopback))
                {
                    _thisServer = new NameServerAddress(_serverDomain, new IPEndPoint(IPAddress.IPv6Loopback, localEndPoint.Port));
                    return;
                }
            }

            _thisServer = new NameServerAddress(_serverDomain, _localEndPoints[0]);
        }

        #endregion

        #region resolver task pool

        private void ReconfigureResolverTaskPool(ushort maxConcurrentResolutionsPerCore)
        {
            TaskPool previousResolverTaskPool = _resolverTaskPool;

            int maxConcurrentResolutions = Environment.ProcessorCount * maxConcurrentResolutionsPerCore;
            int resolverQueueSize = maxConcurrentResolutions * 5 * 10;
            _resolverTaskPool = new TaskPool(resolverQueueSize, maxConcurrentResolutions);

            previousResolverTaskPool?.Dispose();
        }

        #endregion

        #region doh web service

        private async Task StartDoHAsync(bool throwIfBindFails)
        {
            IReadOnlyList<IPAddress> localAddresses = WebUtilities.GetValidKestrelLocalAddresses(_localEndPoints.Convert(delegate (IPEndPoint ep) { return ep.Address; }));

            try
            {
                WebApplicationBuilder builder = WebApplication.CreateBuilder();

                builder.Environment.ContentRootFileProvider = new PhysicalFileProvider(Path.GetDirectoryName(_dohwwwFolder))
                {
                    UseActivePolling = true,
                    UsePollingFileWatcher = true
                };

                builder.Environment.WebRootFileProvider = new PhysicalFileProvider(_dohwwwFolder)
                {
                    UseActivePolling = true,
                    UsePollingFileWatcher = true
                };

                builder.WebHost.ConfigureKestrel(delegate (WebHostBuilderContext context, KestrelServerOptions serverOptions)
                {
                    if (_enableDnsOverHttp)
                    {
                        foreach (IPAddress localAddress in localAddresses)
                            serverOptions.Listen(localAddress, _dnsOverHttpPort);
                    }

                    if (_enableDnsOverHttpUnixSocket && (_dnsOverHttpUnixSocket is not null))
                    {
                        try
                        {
                            if (File.Exists(_dnsOverHttpUnixSocket))
                                File.Delete(_dnsOverHttpUnixSocket);
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }

                        serverOptions.ListenUnixSocket(_dnsOverHttpUnixSocket);
                    }

                    if (_enableDnsOverHttpsUnixSocket && (_dnsOverHttpsUnixSocket is not null) && (_dohSslServerAuthenticationOptions is not null))
                    {
                        try
                        {
                            if (File.Exists(_dnsOverHttpsUnixSocket))
                                File.Delete(_dnsOverHttpsUnixSocket);
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }

                        serverOptions.ListenUnixSocket(_dnsOverHttpsUnixSocket, delegate (ListenOptions listenOptions)
                        {
                            if (IsHttp2Supported())
                                listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
                            else
                                listenOptions.Protocols = HttpProtocols.Http1;

                            listenOptions.UseHttps(delegate (SslStream stream, SslClientHelloInfo clientHelloInfo, object state, CancellationToken cancellationToken)
                            {
                                return ValueTask.FromResult(_dohSslServerAuthenticationOptions);
                            }, null);
                        });
                    }

                    if (_enableDnsOverHttps && (_dohSslServerAuthenticationOptions is not null))
                    {
                        foreach (IPAddress localAddress in localAddresses)
                        {
                            serverOptions.Listen(localAddress, _dnsOverHttpsPort, delegate (ListenOptions listenOptions)
                            {
                                if (_enableDnsOverHttp3)
                                    listenOptions.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
                                else if (IsHttp2Supported())
                                    listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
                                else
                                    listenOptions.Protocols = HttpProtocols.Http1;

                                listenOptions.UseHttps(delegate (SslStream stream, SslClientHelloInfo clientHelloInfo, object state, CancellationToken cancellationToken)
                                {
                                    return ValueTask.FromResult(_dohSslServerAuthenticationOptions);
                                }, null);
                            });
                        }
                    }

                    serverOptions.AddServerHeader = false;
                    serverOptions.Limits.RequestHeadersTimeout = TimeSpan.FromMilliseconds(_tcpReceiveTimeout);
                    serverOptions.Limits.KeepAliveTimeout = TimeSpan.FromMilliseconds(_tcpReceiveTimeout);
                    serverOptions.Limits.MaxRequestHeadersTotalSize = 4096;
                    serverOptions.Limits.MaxRequestLineSize = 4096;
                    serverOptions.Limits.MaxRequestBufferSize = 4096;
                    serverOptions.Limits.MaxRequestBodySize = 64 * 1024;
                    serverOptions.Limits.MaxResponseBufferSize = 4096;
                });

                builder.Logging.ClearProviders();

                _dohWebService = builder.Build();

                _dohWebService.Use(delegate (HttpContext context, RequestDelegate next)
                {
                    IHeaderDictionary headers = context.Response.Headers;

                    headers.XContentTypeOptions = "nosniff";
                    headers["Referrer-Policy"] = "no-referrer";
                    headers.ContentSecurityPolicy = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

                    PathString path = context.Request.Path;

                    if ((path == "/") || (path == "/index.html") || (path == "/index.de.html"))
                    {
                        string file = Path.Combine(_dohwwwFolder, !Lang.IsEnglish && File.Exists(Path.Combine(_dohwwwFolder, "index.de.html")) ? "index.de.html" : "index.html");

                        if (File.Exists(file) && (HttpMethods.IsGet(context.Request.Method) || HttpMethods.IsHead(context.Request.Method)))
                        {
                            string html = File.ReadAllText(file).Replace("{host}", WebUtility.HtmlEncode(context.Request.Host.HasValue ? context.Request.Host.Value : _serverDomain));

                            headers["X-Robots-Tag"] = "noindex, nofollow";
                            headers.CacheControl = "no-cache";
                            context.Response.ContentType = "text/html; charset=utf-8";

                            if (HttpMethods.IsHead(context.Request.Method))
                                return Task.CompletedTask;

                            return context.Response.WriteAsync(html);
                        }
                    }

                    return next(context);
                });

                _dohWebService.UseDefaultFiles();
                _dohWebService.UseStaticFiles(new StaticFileOptions()
                {
                    OnPrepareResponse = delegate (StaticFileResponseContext ctx)
                    {
                        ctx.Context.Response.Headers["X-Robots-Tag"] = "noindex, nofollow";
                        ctx.Context.Response.Headers.CacheControl = "no-cache";
                    },
                    ServeUnknownFileTypes = true
                });

                _dohWebService.UseRouting();
                _dohWebService.MapGet("/dns-query", ProcessDoHRequestAsync);
                _dohWebService.MapPost("/dns-query", ProcessDoHRequestAsync);
                _dohWebService.MapGet("/dns-query/{clientId}", ProcessDoHRequestAsync);
                _dohWebService.MapPost("/dns-query/{clientId}", ProcessDoHRequestAsync);

                await _dohWebService.StartAsync();

                foreach (IPAddress localAddress in localAddresses)
                {
                    if (_enableDnsOverHttp)
                        _log.Write(new IPEndPoint(localAddress, _dnsOverHttpPort), "Http", "DNS Server was bound successfully.");

                    if (_enableDnsOverHttps && (_dohSslServerAuthenticationOptions is not null))
                        _log.Write(new IPEndPoint(localAddress, _dnsOverHttpsPort), "Https", "DNS Server was bound successfully.");
                }

                if (_enableDnsOverHttpUnixSocket && (_dnsOverHttpUnixSocket is not null))
                    _log.Write(new UnixDomainSocketEndPoint(_dnsOverHttpUnixSocket), "HttpUnix", "DNS Server was bound successfully.");

                if (_enableDnsOverHttpsUnixSocket && (_dnsOverHttpsUnixSocket is not null) && (_dohSslServerAuthenticationOptions is not null))
                    _log.Write(new UnixDomainSocketEndPoint(_dnsOverHttpsUnixSocket), "HttpsUnix", "DNS Server was bound successfully.");
            }
            catch (Exception ex)
            {
                await StopDoHAsync();

                foreach (IPAddress localAddress in localAddresses)
                {
                    if (_enableDnsOverHttp)
                        _log.Write(new IPEndPoint(localAddress, _dnsOverHttpPort), "Http", "DNS Server failed to bind.");

                    if (_enableDnsOverHttps && (_dohSslServerAuthenticationOptions is not null))
                        _log.Write(new IPEndPoint(localAddress, _dnsOverHttpsPort), "Https", "DNS Server failed to bind.");
                }

                if (_enableDnsOverHttpUnixSocket && (_dnsOverHttpUnixSocket is not null))
                    _log.Write(new UnixDomainSocketEndPoint(_dnsOverHttpUnixSocket), "HttpUnix", "DNS Server failed to bind.");

                if (_enableDnsOverHttpsUnixSocket && (_dnsOverHttpsUnixSocket is not null) && (_dohSslServerAuthenticationOptions is not null))
                    _log.Write(new UnixDomainSocketEndPoint(_dnsOverHttpsUnixSocket), "HttpsUnix", "DNS Server failed to bind.");

                _log.Write(ex);

                if (throwIfBindFails)
                    throw;
            }
        }

        private async Task StopDoHAsync()
        {
            if (_dohWebService is not null)
            {
                try
                {
                    await _dohWebService.DisposeAsync();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }

                _dohWebService = null;
            }
        }

        private bool IsHttp2Supported()
        {
            if (_enableDnsOverHttp3)
                return true;

            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT:
                    return Environment.OSVersion.Version.Major >= 10;

                case PlatformID.Unix:
                    return true;

                default:
                    return false;
            }
        }

        internal static bool IsUnixDomainSocketSupported()
        {
            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Unix:
                    return true;

                case PlatformID.Win32NT:
                    return Environment.OSVersion.Version.Major >= 10;

                default:
                    return false;
            }
        }

        #endregion

        #region quic

        internal static void ValidateQuicSupport(string protocolName = "DNS-over-QUIC")
        {
            if (!QuicConnection.IsSupported)
            {
                if (!Socket.OSSupportsIPv6)
                    throw new DnsServerException(protocolName + " requires IPv6 support on the system to work.");

                throw new DnsServerException(protocolName + " is supported only on Windows 11 (build 22000 and later), Windows Server 2022 (and later), and Linux. On Linux, you must install 'libmsquic' manually.");
            }
        }

        #endregion

        #region public

        public async Task StartAsync(bool throwIfBindFails = false)
        {
            _ianaDataManager.Start();

            if (_disposed)
                ObjectDisposedException.ThrowIf(_disposed, this);

            if (_state != ServiceState.Stopped)
                throw new InvalidOperationException("DNS Server is already running.");

            _state = ServiceState.Starting;

            foreach (IPEndPoint localEP in _localEndPoints)
            {
                if (_do53Mode != DnsServerDo53Mode.Disabled)
                {
                    Socket udpListener = null;

                    try
                    {
                        udpListener = GetUdpListenerSocket(localEP.AddressFamily);

                        if (localEP is InterfaceEndPoint intEP && intEP.InterfaceName is not null)
                            SocketBindToDevice(udpListener, intEP, DnsTransportProtocol.Udp);

                        try
                        {
                            udpListener.Bind(localEP);
                        }
                        catch (SocketException ex1)
                        {
                            switch (ex1.ErrorCode)
                            {
                                case 99:
                                    await Task.Delay(10000);
                                    udpListener.Bind(localEP);
                                    break;

                                default:
                                    throw;
                            }
                        }

                        _udpListeners.Add(udpListener);

                        _log.Write(localEP, DnsTransportProtocol.Udp, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write(localEP, DnsTransportProtocol.Udp, "DNS Server failed to bind.", ex);

                        udpListener?.Dispose();

                        if (throwIfBindFails)
                            throw;
                    }
                }

                if (_enableDnsOverUdpProxy)
                {
                    IPEndPoint udpProxyEP = new IPEndPoint(localEP.Address, _dnsOverUdpProxyPort);
                    Socket udpProxyListener = null;

                    try
                    {
                        udpProxyListener = GetUdpListenerSocket(udpProxyEP.AddressFamily);

                        if (localEP is InterfaceEndPoint intEP && intEP.InterfaceName is not null)
                            SocketBindToDevice(udpProxyListener, intEP, DnsTransportProtocol.UdpProxy);

                        udpProxyListener.Bind(udpProxyEP);

                        _udpProxyListeners.Add(udpProxyListener);

                        _log.Write(udpProxyEP, DnsTransportProtocol.UdpProxy, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write(udpProxyEP, DnsTransportProtocol.UdpProxy, "DNS Server failed to bind.", ex);

                        udpProxyListener?.Dispose();

                        if (throwIfBindFails)
                            throw;
                    }
                }

                if (_do53Mode != DnsServerDo53Mode.Disabled)
                {
                    Socket tcpListener = null;

                    try
                    {
                        tcpListener = new Socket(localEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        if (localEP is InterfaceEndPoint intEP && intEP.InterfaceName is not null)
                            SocketBindToDevice(tcpListener, intEP, DnsTransportProtocol.Tcp);

                        if (Environment.OSVersion.Platform == PlatformID.Unix)
                            tcpListener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);

                        tcpListener.Bind(localEP);
                        tcpListener.Listen(_listenBacklog);

                        _tcpListeners.Add(tcpListener);

                        _log.Write(localEP, DnsTransportProtocol.Tcp, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write(localEP, DnsTransportProtocol.Tcp, "DNS Server failed to bind.", ex);

                        tcpListener?.Dispose();

                        if (throwIfBindFails)
                            throw;
                    }
                }

                if (_enableDnsOverTcpProxy)
                {
                    IPEndPoint tcpProxyEP = new IPEndPoint(localEP.Address, _dnsOverTcpProxyPort);
                    Socket tcpProxyListner = null;

                    try
                    {
                        tcpProxyListner = new Socket(tcpProxyEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        if (localEP is InterfaceEndPoint intEP && intEP.InterfaceName is not null)
                            SocketBindToDevice(tcpProxyListner, intEP, DnsTransportProtocol.TcpProxy);

                        if (Environment.OSVersion.Platform == PlatformID.Unix)
                            tcpProxyListner.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);

                        tcpProxyListner.Bind(tcpProxyEP);
                        tcpProxyListner.Listen(_listenBacklog);

                        _tcpProxyListeners.Add(tcpProxyListner);

                        _log.Write(tcpProxyEP, DnsTransportProtocol.TcpProxy, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write(tcpProxyEP, DnsTransportProtocol.TcpProxy, "DNS Server failed to bind.", ex);

                        tcpProxyListner?.Dispose();

                        if (throwIfBindFails)
                            throw;
                    }
                }

                if (_enableDnsOverTls && (_dotSslServerAuthenticationOptions is not null))
                {
                    IPEndPoint tlsEP = new IPEndPoint(localEP.Address, _dnsOverTlsPort);
                    Socket tlsListener = null;

                    try
                    {
                        tlsListener = new Socket(tlsEP.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

                        if (localEP is InterfaceEndPoint intEP && intEP.InterfaceName is not null)
                            SocketBindToDevice(tlsListener, intEP, DnsTransportProtocol.Tls);

                        if (Environment.OSVersion.Platform == PlatformID.Unix)
                            tlsListener.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, 1);

                        tlsListener.Bind(tlsEP);
                        tlsListener.Listen(_listenBacklog);

                        _tlsListeners.Add(tlsListener);

                        _log.Write(tlsEP, DnsTransportProtocol.Tls, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write(tlsEP, DnsTransportProtocol.Tls, "DNS Server failed to bind.", ex);

                        tlsListener?.Dispose();

                        if (throwIfBindFails)
                            throw;
                    }
                }

                if (_enableDnsOverQuic && (_doqSslServerAuthenticationOptions is not null))
                {
                    IPEndPoint quicEP = new IPEndPoint(localEP.Address, _dnsOverQuicPort);
                    QuicListener quicListener = null;

                    try
                    {
                        QuicListenerOptions listenerOptions = new QuicListenerOptions()
                        {
                            ListenEndPoint = quicEP,
                            ListenBacklog = _listenBacklog,
                            ApplicationProtocols = _doqApplicationProtocols,
                            ConnectionOptionsCallback = delegate (QuicConnection quicConnection, SslClientHelloInfo sslClientHello, CancellationToken cancellationToken)
                            {
                                QuicServerConnectionOptions serverConnectionOptions = new QuicServerConnectionOptions()
                                {
                                    DefaultCloseErrorCode = (long)DnsOverQuicErrorCodes.DOQ_NO_ERROR,
                                    DefaultStreamErrorCode = (long)DnsOverQuicErrorCodes.DOQ_UNSPECIFIED_ERROR,
                                    MaxInboundUnidirectionalStreams = 0,
                                    MaxInboundBidirectionalStreams = _quicMaxInboundStreams,
                                    IdleTimeout = TimeSpan.FromMilliseconds(_quicIdleTimeout),
                                    ServerAuthenticationOptions = _doqSslServerAuthenticationOptions
                                };

                                return ValueTask.FromResult(serverConnectionOptions);
                            }
                        };

                        quicListener = await QuicListener.ListenAsync(listenerOptions);

                        _quicListeners.Add(quicListener);

                        _log.Write(quicEP, DnsTransportProtocol.Quic, "DNS Server was bound successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write(quicEP, DnsTransportProtocol.Quic, "DNS Server failed to bind.", ex);

                        if (quicListener is not null)
                            await quicListener.DisposeAsync();

                        if (throwIfBindFails)
                            throw;
                    }
                }
            }

            int listenerTaskCount = Environment.ProcessorCount;

            foreach (Socket udpListener in _udpListeners)
                StartUdpListenerThreads(udpListener, DnsTransportProtocol.Udp);

            foreach (Socket udpProxyListener in _udpProxyListeners)
                StartUdpListenerThreads(udpProxyListener, DnsTransportProtocol.UdpProxy);

            foreach (Socket tcpListener in _tcpListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptConnectionAsync(tcpListener, DnsTransportProtocol.Tcp);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Default);
                }
            }

            foreach (Socket tcpProxyListener in _tcpProxyListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptConnectionAsync(tcpProxyListener, DnsTransportProtocol.TcpProxy);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Default);
                }
            }

            foreach (Socket tlsListener in _tlsListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptConnectionAsync(tlsListener, DnsTransportProtocol.Tls);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Default);
                }
            }

            foreach (QuicListener quicListener in _quicListeners)
            {
                for (int i = 0; i < listenerTaskCount; i++)
                {
                    _ = Task.Factory.StartNew(delegate ()
                    {
                        return AcceptQuicConnectionAsync(quicListener);
                    }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Default);
                }
            }

            if (_enableDnsOverHttp || _enableDnsOverHttpUnixSocket || ((_enableDnsOverHttps || _enableDnsOverHttpsUnixSocket) && (_dohSslServerAuthenticationOptions is not null)))
                await StartDoHAsync(throwIfBindFails);

            lock (_rateLimitMaintenanceTimerLock)
            {
                _rateLimitMaintenanceTimer = new Timer(RateLimitMaintenanceTimerCallback, null, RATE_LIMIT_MAINTENANCE_TIMER_INTERVAL, RATE_LIMIT_MAINTENANCE_TIMER_INTERVAL);
            }

            lock (_ipv6ProbeTimerLock)
            {
                _ipv6ProbeTimer = new Timer(Ipv6ProbeTimerCallback, null, IPV6_PROBE_TIMER_INTERVAL, Timeout.Infinite);
            }

            if ((_ipv6Mode != IPv6Mode.Disabled) && (_proxy is null) && IPv6Reachability.Enabled)
                _ = Task.Run(StartupIPv6ProbeAsync);

            _state = ServiceState.Running;

            UpdateThisServer();
        }

        public async Task StopAsync()
        {
            if (_state != ServiceState.Running)
                return;

            _state = ServiceState.Stopping;

            lock (_ipv6ProbeTimerLock)
            {
                if (_ipv6ProbeTimer is not null)
                {
                    _ipv6ProbeTimer.Dispose();
                    _ipv6ProbeTimer = null;
                }
            }

            lock (_rateLimitMaintenanceTimerLock)
            {
                if (_rateLimitMaintenanceTimer is not null)
                {
                    _rateLimitMaintenanceTimer.Dispose();
                    _rateLimitMaintenanceTimer = null;
                }
            }

            foreach (Socket udpListener in _udpListeners)
            {
                try
                {
                    udpListener.Dispose();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            foreach (Socket udpProxyListener in _udpProxyListeners)
            {
                try
                {
                    udpProxyListener.Dispose();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            foreach (Socket tcpListener in _tcpListeners)
            {
                try
                {
                    tcpListener.Dispose();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            foreach (Socket tcpProxyListener in _tcpProxyListeners)
            {
                try
                {
                    tcpProxyListener.Dispose();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            foreach (Socket tlsListener in _tlsListeners)
            {
                try
                {
                    tlsListener.Dispose();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            foreach (QuicListener quicListener in _quicListeners)
            {
                try
                {
                    await quicListener.DisposeAsync();
                }
                catch (Exception ex)
                {
                    _log.Write(ex);
                }
            }

            _udpListeners.Clear();
            _udpProxyListeners.Clear();
            _tcpListeners.Clear();
            _tcpProxyListeners.Clear();
            _tlsListeners.Clear();
            _quicListeners.Clear();

            await StopDoHAsync();

            _state = ServiceState.Stopped;
        }

        public Task<DnsDatagram> DirectQueryAsync(DnsQuestionRecord question, int timeout = 4000, bool skipDnsAppAuthoritativeRequestHandlers = false, CancellationToken cancellationToken = default)
        {
            return DirectQueryAsync(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [question]), IPENDPOINT_ANY_0, timeout, skipDnsAppAuthoritativeRequestHandlers, cancellationToken);
        }

        public Task<DnsDatagram> DirectQueryAsync(DnsDatagram request, int timeout = 4000, bool skipDnsAppAuthoritativeRequestHandlers = false, CancellationToken cancellationToken = default)
        {
            return DirectQueryAsync(request, IPENDPOINT_ANY_0, timeout, skipDnsAppAuthoritativeRequestHandlers, cancellationToken);
        }

        public Task<DnsDatagram> DirectQueryAsync(DnsDatagram request, IPEndPoint remoteEP, int timeout = 4000, bool skipDnsAppAuthoritativeRequestHandlers = false, CancellationToken cancellationToken = default)
        {
            return ZenitiumLibrary.TaskExtensions.TimeoutAsync(delegate (CancellationToken cancellationToken1)
            {
                return ProcessQueryAsync(request, remoteEP, DnsTransportProtocol.Tcp, true, skipDnsAppAuthoritativeRequestHandlers, timeout).AsTask();
            }, timeout, cancellationToken);
        }

        Task<DnsDatagram> IDnsClient.ResolveAsync(DnsQuestionRecord question, CancellationToken cancellationToken)
        {
            return DirectQueryAsync(question, cancellationToken: cancellationToken);
        }

        #endregion

        #region properties

        public string ServerDomain
        {
            get { return _serverDomain; }
            set
            {
                if (!_serverDomain.Equals(value, StringComparison.Ordinal))
                {
                    if (DnsClient.IsDomainNameUnicode(value))
                        value = DnsClient.ConvertDomainNameToAscii(value);

                    DnsClient.IsDomainNameValid(value, true);

                    if (IPAddress.TryParse(value, out _))
                        throw new DnsServerException("Invalid domain name [" + value + "]: IP address cannot be used for DNS server domain name.");

                    _serverDomain = value.ToLowerInvariant();
                    _fallbackResponsiblePerson = new MailAddress("hostadmin@" + _serverDomain);

                    _allowedZoneManager.UpdateServerDomain();
                    _blockedZoneManager.UpdateServerDomain();
                    _blockListZoneManager.UpdateServerDomain();

                    UpdateAutoAllowedNames();
                    UpdateThisServer();
                }
            }
        }

        public string ConfigFolder
        { get { return _configFolder; } }

        public IReadOnlyList<IPEndPoint> LocalEndPoints
        {
            get { return _localEndPoints; }
            set
            {
                if ((value is null) || (value.Count == 0))
                {
                    _localEndPoints = [new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53)];
                }
                else
                {
                    foreach (IPEndPoint ep in value)
                    {
                        if (ep.Port == 853)
                            throw new ArgumentException("Port 853 is reserved for DNS-over-TLS service. Please use a different port for DNS Server Local End Points.", nameof(LocalEndPoints));
                    }

                    _localEndPoints = value;
                }
            }
        }

        public LogManager LogManager
        { get { return _log; } }

        internal MailAddress DefaultResponsiblePerson
        {
            get { return _defaultResponsiblePerson; }
            set { _defaultResponsiblePerson = value; }
        }

        public MailAddress ResponsiblePerson
        {
            get
            {
                if (_defaultResponsiblePerson is not null)
                    return _defaultResponsiblePerson;

                if (_fallbackResponsiblePerson is null)
                    _fallbackResponsiblePerson = new MailAddress("hostadmin@" + _serverDomain);

                return _fallbackResponsiblePerson;
            }
        }

        public NameServerAddress ThisServer
        { get { return _thisServer; } }

        public AuthZoneManager AuthZoneManager
        { get { return _authZoneManager; } }

        public SpecialZoneManager SpecialZoneManager
        { get { return _specialZoneManager; } }

        public AllowedZoneManager AllowedZoneManager
        { get { return _allowedZoneManager; } }

        public BlockedZoneManager BlockedZoneManager
        { get { return _blockedZoneManager; } }

        public BlockListZoneManager BlockListZoneManager
        { get { return _blockListZoneManager; } }

        public Dhcp.DhcpServer DhcpServer
        {
            get { return _dhcpServer; }
            set { _dhcpServer = value; }
        }

        public ClientProfileManager ClientProfileManager
        { get { return _clientProfileManager; } }

        public CacheZoneManager CacheZoneManager
        { get { return _cacheZoneManager; } }

        public DnsApplicationManager DnsApplicationManager
        { get { return _dnsApplicationManager; } }

        public StatsManager StatsManager
        { get { return _statsManager; } }

        internal SystemMonitor SystemMonitor
        { get { return _systemMonitor; } }

        internal Watchdog Watchdog
        { get { return _watchdog; } }

        internal IanaDataManager IanaDataManager
        { get { return _ianaDataManager; } }

        internal bool IsRunning
        { get { return _state == ServiceState.Running; } }

        internal int QueryTaskQueueLength
        { get { return (int)Math.Min(int.MaxValue, ThreadPool.PendingWorkItemCount); } }

        internal int ResolverTaskQueueLength
        { get { return _resolverTaskPool?.QueuedTasks ?? 0; } }

        internal int PendingResolutions
        { get { return _resolverTasks.Count; } }

        internal int RateLimiterTrackedClients
        { get { return _rateLimiter.TrackedClients; } }

        public bool EnableCheckForUpdate
        {
            get { return _enableCheckForUpdate; }
            set { _enableCheckForUpdate = value; }
        }

        public IPv6Mode IPv6Mode
        {
            get { return _ipv6Mode; }
            set
            {
                if (_ipv6Mode != value)
                {
                    _ipv6Mode = value;

                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try
                        {
                            if (_enableUdpSocketPool)
                                UdpClientConnection.CreateSocketPool(_ipv6Mode != IPv6Mode.Disabled);
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }
                    });
                }
            }
        }

        public bool EnableUdpSocketPool
        {
            get { return _enableUdpSocketPool; }
            set
            {
                if (_enableUdpSocketPool != value)
                {
                    _enableUdpSocketPool = value;

                    ThreadPool.QueueUserWorkItem(delegate (object state)
                    {
                        try
                        {
                            if (_enableUdpSocketPool)
                                UdpClientConnection.CreateSocketPool(_ipv6Mode != IPv6Mode.Disabled);
                            else
                                UdpClientConnection.DisposeSocketPool();
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }
                    });
                }
            }
        }

        public ushort UdpPayloadSize
        {
            get { return _udpPayloadSize; }
            set
            {
                if ((value < 512) || (value > 4096))
                    throw new ArgumentOutOfRangeException(nameof(UdpPayloadSize), "Invalid EDNS UDP payload size: valid range is 512-4096 bytes.");

                _udpPayloadSize = value;
            }
        }

        public bool DnssecValidation
        {
            get { return _dnssecValidation; }
            set
            {
                if (_dnssecValidation != value)
                {
                    _dnssecValidation = value;
                    _cacheZoneManager.Flush();
                }
            }
        }

        public bool EDnsClientSubnet
        {
            get { return _eDnsClientSubnet; }
            set
            {
                if (_eDnsClientSubnet != value)
                {
                    _eDnsClientSubnet = value;

                    if (!_eDnsClientSubnet)
                    {
                        ThreadPool.QueueUserWorkItem(delegate (object state)
                        {
                            try
                            {
                                _cacheZoneManager.DeleteEDnsClientSubnetData();
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        });
                    }
                }
            }
        }

        public byte EDnsClientSubnetIPv4PrefixLength
        {
            get { return _eDnsClientSubnetIPv4PrefixLength; }
            set
            {
                if (value > 32)
                    throw new ArgumentOutOfRangeException(nameof(EDnsClientSubnetIPv4PrefixLength), "EDNS Client Subnet IPv4 prefix length cannot be greater than 32.");

                _eDnsClientSubnetIPv4PrefixLength = value;
            }
        }

        public byte EDnsClientSubnetIPv6PrefixLength
        {
            get { return _eDnsClientSubnetIPv6PrefixLength; }
            set
            {
                if (value > 64)
                    throw new ArgumentOutOfRangeException(nameof(EDnsClientSubnetIPv6PrefixLength), "EDNS Client Subnet IPv6 prefix length cannot be greater than 64.");

                _eDnsClientSubnetIPv6PrefixLength = value;
            }
        }

        public NetworkAddress EDnsClientSubnetIpv4Override
        {
            get { return _eDnsClientSubnetIpv4Override; }
            set
            {
                if (value is not null)
                {
                    if (value.AddressFamily != AddressFamily.InterNetwork)
                        throw new ArgumentException("EDNS Client Subnet IPv4 Override must be an IPv4 network address.", nameof(EDnsClientSubnetIpv4Override));

                    if (value.IsHostAddress)
                        value = new NetworkAddress(value.Address, _eDnsClientSubnetIPv4PrefixLength);
                }

                _eDnsClientSubnetIpv4Override = value;
            }
        }

        public NetworkAddress EDnsClientSubnetIpv6Override
        {
            get { return _eDnsClientSubnetIpv6Override; }
            set
            {
                if (value is not null)
                {
                    if (value.AddressFamily != AddressFamily.InterNetworkV6)
                        throw new ArgumentException("EDNS Client Subnet IPv6 Override must be an IPv6 network address.", nameof(EDnsClientSubnetIpv6Override));

                    if (value.IsHostAddress)
                        value = new NetworkAddress(value.Address, _eDnsClientSubnetIPv6PrefixLength);
                }

                _eDnsClientSubnetIpv6Override = value;
            }
        }

        public IReadOnlyDictionary<int, (int, int)> QpsPrefixLimitsIPv4
        {
            get { return _qpsPrefixLimitsIPv4; }
            set
            {
                _qpsPrefixLimitsIPv4 = ValidatePrefixLimits(value, 32, nameof(QpsPrefixLimitsIPv4));
                ApplyRateLimits();
            }
        }

        public IReadOnlyDictionary<int, (int, int)> QpsPrefixLimitsIPv6
        {
            get { return _qpsPrefixLimitsIPv6; }
            set
            {
                _qpsPrefixLimitsIPv6 = ValidatePrefixLimits(value, 128, nameof(QpsPrefixLimitsIPv6));
                ApplyRateLimits();
            }
        }

        private static IReadOnlyDictionary<int, (int, int)> ValidatePrefixLimits(IReadOnlyDictionary<int, (int, int)> value, int maxPrefix, string paramName)
        {
            if (value is null)
                return new Dictionary<int, (int, int)>();

            if (value.Count > byte.MaxValue)
                throw new ArgumentOutOfRangeException(paramName, "Rate limit prefixes cannot have more than 255 entries.");

            foreach (KeyValuePair<int, (int, int)> prefixLimit in value)
            {
                if ((prefixLimit.Key < 0) || (prefixLimit.Key > maxPrefix))
                    throw new ArgumentOutOfRangeException(paramName, "Rate limit prefix valid range is between 0 and " + maxPrefix + ".");

                if ((prefixLimit.Value.Item1 < 0) || (prefixLimit.Value.Item2 < 0) || (prefixLimit.Value.Item1 > MAX_RATE_LIMIT_QPS) || (prefixLimit.Value.Item2 > MAX_RATE_LIMIT_QPS))
                    throw new ArgumentOutOfRangeException(paramName, "Rate limit valid range is between 0 and " + MAX_RATE_LIMIT_QPS + " queries per second.");
            }

            return value;
        }

        public int RateLimitBurstSeconds
        {
            get { return _rateLimitBurstSeconds; }
            set
            {
                if ((value < 1) || (value > 60))
                    throw new ArgumentOutOfRangeException(nameof(RateLimitBurstSeconds), "Valid range is between 1 and 60 seconds.");

                _rateLimitBurstSeconds = value;
                ApplyRateLimits();
            }
        }

        public int RateLimitUdpTruncationPercentage
        {
            get { return _rateLimitUdpTruncationPercentage; }
            set
            {
                if ((value < 0) || (value > 100))
                    throw new ArgumentOutOfRangeException(nameof(RateLimitUdpTruncationPercentage), "Percentage value valid range is between 0 and 100.");

                _rateLimitUdpTruncationPercentage = value;
            }
        }

        public IReadOnlyCollection<NetworkAddress> RateLimitBypassList
        {
            get { return _rateLimitBypassList; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _rateLimitBypassList = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(RateLimitBypassList), "Networks cannot have more than 255 entries.");
                else
                    _rateLimitBypassList = value;
            }
        }

        internal IReadOnlyDictionary<int, (int, int)> LegacyQpmPrefixLimitsIPv4
        {
            set { QpsPrefixLimitsIPv4 = ConvertLegacyQpmPrefixLimits(value, false); }
        }

        internal IReadOnlyDictionary<int, (int, int)> LegacyQpmPrefixLimitsIPv6
        {
            set { QpsPrefixLimitsIPv6 = ConvertLegacyQpmPrefixLimits(value, true); }
        }

        internal ClientBlockListManager ClientBlockListManager
        { get { return _clientBlockListManager; } }

        public int RateLimitTrackedClients
        { get { return _rateLimiter.TrackedClients; } }

        public int ClientTimeout
        {
            get { return _clientTimeout; }
            set
            {
                if ((value < 1000) || (value > 10000))
                    throw new ArgumentOutOfRangeException(nameof(ClientTimeout), "Valid range is from 1000 to 10000.");

                _clientTimeout = value;
            }
        }

        public int TcpSendTimeout
        {
            get { return _tcpSendTimeout; }
            set
            {
                if ((value < 1000) || (value > 90000))
                    throw new ArgumentOutOfRangeException(nameof(TcpSendTimeout), "Valid range is from 1000 to 90000.");

                _tcpSendTimeout = value;
            }
        }

        public int TcpReceiveTimeout
        {
            get { return _tcpReceiveTimeout; }
            set
            {
                if ((value < 1000) || (value > 90000))
                    throw new ArgumentOutOfRangeException(nameof(TcpReceiveTimeout), "Valid range is from 1000 to 90000.");

                _tcpReceiveTimeout = value;
            }
        }

        public int QuicIdleTimeout
        {
            get { return _quicIdleTimeout; }
            set
            {
                if ((value < 1000) || (value > 90000))
                    throw new ArgumentOutOfRangeException(nameof(QuicIdleTimeout), "Valid range is from 1000 to 90000.");

                _quicIdleTimeout = value;
            }
        }

        public int QuicMaxInboundStreams
        {
            get { return _quicMaxInboundStreams; }
            set
            {
                if ((value < 0) || (value > 1000))
                    throw new ArgumentOutOfRangeException(nameof(QuicMaxInboundStreams), "Valid range is from 1 to 1000.");

                _quicMaxInboundStreams = value;
            }
        }

        public int ListenBacklog
        {
            get { return _listenBacklog; }
            set { _listenBacklog = value; }
        }

        public int UdpSendBufferSizeKB
        {
            get { return _udpSendBufferSizeKB; }
            set
            {
                if ((value < 8) || (value > 65536))
                    throw new ArgumentOutOfRangeException(nameof(UdpSendBufferSizeKB), "Valid range is from 8 KB to 65536 KB.");

                _udpSendBufferSizeKB = value;
            }
        }

        public int UdpReceiveBufferSizeKB
        {
            get { return _udpReceiveBufferSizeKB; }
            set
            {
                if ((value < 8) || (value > 65536))
                    throw new ArgumentOutOfRangeException(nameof(UdpReceiveBufferSizeKB), "Valid range is from 8 KB to 65536 KB.");

                _udpReceiveBufferSizeKB = value;
            }
        }

        public ushort MaxConcurrentResolutionsPerCore
        {
            get { return Convert.ToUInt16(_resolverTaskPool.MaximumConcurrencyLevel / Environment.ProcessorCount); }
            set
            {
                if (value < 1)
                    throw new ArgumentOutOfRangeException(nameof(MaxConcurrentResolutionsPerCore), "Value cannot be less than 1.");

                if (MaxConcurrentResolutionsPerCore != value)
                    ReconfigureResolverTaskPool(value);
            }
        }

        public bool EnableEDnsClientSubnetSourceAddress
        {
            get { return _enableEDnsClientSubnetSourceAddress; }
            set { _enableEDnsClientSubnetSourceAddress = value; }
        }

        public bool EnableDnsOverUdpProxy
        {
            get { return _enableDnsOverUdpProxy; }
            set { _enableDnsOverUdpProxy = value; }
        }

        public bool EnableDnsOverTcpProxy
        {
            get { return _enableDnsOverTcpProxy; }
            set { _enableDnsOverTcpProxy = value; }
        }

        public bool EnableDnsOverHttp
        {
            get { return _enableDnsOverHttp; }
            set { _enableDnsOverHttp = value; }
        }

        public bool EnableDnsOverHttpUnixSocket
        {
            get { return _enableDnsOverHttpUnixSocket; }
            set
            {
                if (value)
                {
                    if (!IsUnixDomainSocketSupported())
                        throw new ArgumentException("Unix Domain Sockets (UDS) are supported only on Linux, Windows 10 (build 17063 and later), and Windows Server 2019 (update 1809 and later).", nameof(EnableDnsOverHttpUnixSocket));
                }

                _enableDnsOverHttpUnixSocket = value;
            }
        }

        public bool EnableDnsOverHttpsUnixSocket
        {
            get { return _enableDnsOverHttpsUnixSocket; }
            set
            {
                if (value)
                {
                    if (!IsUnixDomainSocketSupported())
                        throw new ArgumentException("Unix Domain Sockets (UDS) are supported only on Linux, Windows 10 (build 17063 and later), and Windows Server 2019 (update 1809 and later).", nameof(EnableDnsOverHttpsUnixSocket));
                }

                _enableDnsOverHttpsUnixSocket = value;
            }
        }

        public bool EnableDnsOverTls
        {
            get { return _enableDnsOverTls; }
            set { _enableDnsOverTls = value; }
        }

        public bool EnableDnsOverHttps
        {
            get { return _enableDnsOverHttps; }
            set { _enableDnsOverHttps = value; }
        }

        public bool EnableDnsOverHttp3
        {
            get { return _enableDnsOverHttp3; }
            set
            {
                if (value)
                    ValidateQuicSupport("DNS-over-HTTP/3");

                _enableDnsOverHttp3 = value;
            }
        }

        public bool EnableDnsOverQuic
        {
            get { return _enableDnsOverQuic; }
            set
            {
                if (value)
                    ValidateQuicSupport();

                _enableDnsOverQuic = value;
            }
        }

        public bool EnableDnsOverHttpHelpRedirect
        {
            get { return _enableDnsOverHttpHelpRedirect; }
            set { _enableDnsOverHttpHelpRedirect = value; }
        }

        public int DnsOverUdpProxyPort
        {
            get { return _dnsOverUdpProxyPort; }
            set
            {
                if ((value < ushort.MinValue) || (value > ushort.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(DnsOverUdpProxyPort), "Port number valid range is from 0 to 65535.");

                _dnsOverUdpProxyPort = value;
            }
        }

        public int DnsOverTcpProxyPort
        {
            get { return _dnsOverTcpProxyPort; }
            set
            {
                if ((value < ushort.MinValue) || (value > ushort.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(DnsOverTcpProxyPort), "Port number valid range is from 0 to 65535.");

                _dnsOverTcpProxyPort = value;
            }
        }

        public int DnsOverHttpPort
        {
            get { return _dnsOverHttpPort; }
            set
            {
                if ((value < ushort.MinValue) || (value > ushort.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(DnsOverHttpPort), "Port number valid range is from 0 to 65535.");

                if (value == 53)
                    throw new ArgumentOutOfRangeException(nameof(DnsOverHttpPort), "Port 53 cannot be used for DNS-over-HTTP service. Please use a different port.");

                if (value == 853)
                    throw new ArgumentOutOfRangeException(nameof(DnsOverHttpPort), "Port 853 is reserved for DNS-over-TLS service. Please use a different port for DNS-over-HTTP service.");

                _dnsOverHttpPort = value;
            }
        }

        public string DnsOverHttpUnixSocket
        {
            get { return _dnsOverHttpUnixSocket; }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                    value = null;

                _dnsOverHttpUnixSocket = value;
            }
        }

        public string DnsOverHttpsUnixSocket
        {
            get { return _dnsOverHttpsUnixSocket; }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                    value = null;

                _dnsOverHttpsUnixSocket = value;
            }
        }

        public int DnsOverTlsPort
        {
            get { return _dnsOverTlsPort; }
            set
            {
                if ((value < ushort.MinValue) || (value > ushort.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(DnsOverTlsPort), "Port number valid range is from 0 to 65535.");

                if (value == 53)
                    throw new ArgumentOutOfRangeException(nameof(DnsOverTlsPort), "Port 53 cannot be used for DNS-over-TLS service. Please use a different port.");

                _dnsOverTlsPort = value;
            }
        }

        public int DnsOverHttpsPort
        {
            get { return _dnsOverHttpsPort; }
            set
            {
                if ((value < ushort.MinValue) || (value > ushort.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(DnsOverHttpsPort), "Port number valid range is from 0 to 65535.");

                if (value == 53)
                    throw new ArgumentOutOfRangeException(nameof(DnsOverHttpsPort), "Port 53 cannot be used for DNS-over-HTTPS service. Please use a different port.");

                if (value == 853)
                    throw new ArgumentOutOfRangeException(nameof(DnsOverHttpsPort), "Port 853 is reserved for DNS-over-TLS service. Please use a different port for DNS-over-HTTPS service.");

                _dnsOverHttpsPort = value;
            }
        }

        public int DnsOverQuicPort
        {
            get { return _dnsOverQuicPort; }
            set
            {
                if ((value < ushort.MinValue) || (value > ushort.MaxValue))
                    throw new ArgumentOutOfRangeException(nameof(DnsOverQuicPort), "Port number valid range is from 0 to 65535.");

                if (value == 53)
                    throw new ArgumentOutOfRangeException(nameof(DnsOverQuicPort), "Port 53 cannot be used for DNS-over-QUIC service. Please use a different port.");

                _dnsOverQuicPort = value;
            }
        }

        public IReadOnlyCollection<NetworkAccessControl> DnsReverseProxyNetworkACL
        {
            get { return _dnsReverseProxyNetworkACL; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _dnsReverseProxyNetworkACL = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(DnsReverseProxyNetworkACL), "Network Access Control List cannot have more than 255 entries.");
                else
                    _dnsReverseProxyNetworkACL = value;
            }
        }

        public string DnsTlsCertificatePath
        { get { return _dnsTlsCertificatePath; } }

        public string DnsTlsCertificatePassword
        { get { return _dnsTlsCertificatePassword; } }

        public string DnsTlsCertificateKeyPath
        { get { return _dnsTlsCertificateKeyPath; } }

        public X509Certificate2 DnsTlsCertificate
        { get { return _dnsTlsCertificate; } }

        public bool EnableDdr
        {
            get { return _enableDdr; }
            set { _enableDdr = value; }
        }

        public DnsServerDo53Mode Do53Mode
        {
            get { return _do53Mode; }
            set { _do53Mode = value; }
        }

        public DnsServerEDnsPaddingMode EDnsPaddingMode
        {
            get { return _eDnsPaddingMode; }
            set
            {
                if (!Enum.IsDefined(value))
                    throw new ArgumentOutOfRangeException(nameof(EDnsPaddingMode), "Invalid EDNS padding mode.");

                _eDnsPaddingMode = value;
            }
        }

        public bool BlockFirefoxCanaryDomain
        {
            get { return _blockFirefoxCanaryDomain; }
            set { _blockFirefoxCanaryDomain = value; }
        }

        public bool ForceChromePreflight
        {
            get { return _forceChromePreflight; }
            set { _forceChromePreflight = value; }
        }

        public IReadOnlyList<string> AutoAllowedNames
        { get { return _autoAllowedNames; } }

        public bool DdrOnlyUnencrypted
        {
            get { return _ddrOnlyUnencrypted; }
            set { _ddrOnlyUnencrypted = value; }
        }

        public bool DdrProxyDoh
        {
            get { return _ddrProxyDoh; }
            set { _ddrProxyDoh = value; }
        }

        public ushort DdrProxyDohPort
        {
            get { return _ddrProxyDohPort; }
            set
            {
                if (value == 0)
                    throw new ArgumentOutOfRangeException(nameof(DdrProxyDohPort), "Port must be between 1 and 65535.");

                _ddrProxyDohPort = value;
            }
        }

        public bool DdrProxyDohHttp3
        {
            get { return _ddrProxyDohHttp3; }
            set { _ddrProxyDohHttp3 = value; }
        }

        public string DnsOverHttpRealIpHeader
        {
            get { return _dnsOverHttpRealIpHeader; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    _dnsOverHttpRealIpHeader = "X-Real-IP";
                else if (value.Length > 255)
                    throw new ArgumentException("DNS-over-HTTP Real IP header name cannot exceed 255 characters.", nameof(DnsOverHttpRealIpHeader));
                else if (value.Contains(' '))
                    throw new ArgumentException("DNS-over-HTTP Real IP header name cannot contain invalid characters.", nameof(DnsOverHttpRealIpHeader));
                else
                    _dnsOverHttpRealIpHeader = value;
            }
        }

        public DnsServerRecursion Recursion
        {
            get { return _recursion; }
            set { _recursion = value; }
        }

        public IReadOnlyCollection<NetworkAccessControl> RecursionNetworkACL
        {
            get { return _recursionNetworkACL; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _recursionNetworkACL = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(RecursionNetworkACL), "Network Access Control List cannot have more than 255 entries.");
                else
                    _recursionNetworkACL = value;
            }
        }

        public bool RandomizeName
        {
            get { return _randomizeName; }
            set { _randomizeName = value; }
        }

        public string HttpUserAgent
        {
            get { return _httpUserAgent; }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    _httpUserAgent = null;
                }
                else
                {
                    value = value.Trim();

                    if (value.Length > 255)
                        throw new ArgumentException(Lang.T("Der User-Agent darf höchstens 255 Zeichen lang sein.", "The User-Agent cannot exceed 255 characters."), nameof(HttpUserAgent));

                    foreach (char c in value)
                    {
                        if ((c < ' ') || (c > '~'))
                            throw new ArgumentException(Lang.T("Der User-Agent darf nur sichtbare ASCII-Zeichen und Leerzeichen enthalten.", "The User-Agent may only contain visible ASCII characters and spaces."), nameof(HttpUserAgent));
                    }

                    _httpUserAgent = value;
                }

                HttpClientNetworkHandler.DefaultUserAgent = _httpUserAgent ?? DefaultHttpUserAgent;
            }
        }

        public bool EnableDnsCookies
        {
            get { return _enableDnsCookies; }
            set
            {
                _enableDnsCookies = value;
                DnsCookie.ClientEnabled = value;
            }
        }

        public byte[] DnsCookieSecret
        {
            get { return _dnsCookieSecretConfigured ? _dnsCookieSecret : null; }
            set
            {
                if (value is null)
                {
                    if (_dnsCookieSecretConfigured)
                        _dnsCookieSecret = RandomNumberGenerator.GetBytes(DnsCookie.SECRET_LENGTH);

                    _dnsCookieSecretConfigured = false;
                }
                else
                {
                    if (value.Length != DnsCookie.SECRET_LENGTH)
                        throw new ArgumentException(Lang.T("Das Cookie-Geheimnis muss aus 32 Hexadezimalzeichen (16 Byte) bestehen.", "The cookie secret must consist of 32 hexadecimal characters (16 bytes)."), nameof(DnsCookieSecret));

                    _dnsCookieSecret = value;
                    _dnsCookieSecretConfigured = true;
                }
            }
        }

        public bool QnameMinimization
        {
            get { return _qnameMinimization; }
            set { _qnameMinimization = value; }
        }

        public bool QnameMinimizationFallback
        {
            get { return ZenitiumLibrary.Net.Dns.QnameMinimizationFallback.Enabled; }
            set { ZenitiumLibrary.Net.Dns.QnameMinimizationFallback.Enabled = value; }
        }

        public bool LocallyServedDnsZones
        {
            get { return _locallyServedDnsZones; }
            set { _locallyServedDnsZones = value; }
        }

        public int ResolverRetries
        {
            get { return _resolverRetries; }
            set
            {
                if ((value < 1) || (value > 10))
                    throw new ArgumentOutOfRangeException(nameof(ResolverRetries), "Valid range is from 1 to 10.");

                _resolverRetries = value;
            }
        }

        public int ResolverTimeout
        {
            get { return _resolverTimeout; }
            set
            {
                if ((value < 1000) || (value > 10000))
                    throw new ArgumentOutOfRangeException(nameof(ResolverTimeout), "Valid range is from 1000 to 10000.");

                _resolverTimeout = value;
            }
        }

        public int ResolverConcurrency
        {
            get { return _resolverConcurrency; }
            set
            {
                if ((value < 1) || (value > 4))
                    throw new ArgumentOutOfRangeException(nameof(ResolverConcurrency), "Valid range is from 1 to 4.");

                _resolverConcurrency = value;
            }
        }

        public int ResolverMaxStackCount
        {
            get { return _resolverMaxStackCount; }
            set
            {
                if ((value < 10) || (value > 30))
                    throw new ArgumentOutOfRangeException(nameof(ResolverMaxStackCount), "Valid range is from 10 to 30.");

                _resolverMaxStackCount = value;
            }
        }

        public bool EnableCache
        {
            get { return _cacheZoneManager.Enabled; }
            set
            {
                if (_cacheZoneManager.Enabled == value)
                    return;

                _cacheZoneManager.Enabled = value;

                if (!value)
                {
                    try
                    {
                        _cacheZoneManager.DeleteCacheZoneFile();
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                }

                _log.Write(value ? "DNS Server cache was enabled." : "DNS Server cache was disabled; every query is resolved without cached answers and the local root and arpa zones are not used.");

                _ = ApplyCacheStateToIanaDataAsync();
            }
        }

        private async Task ApplyCacheStateToIanaDataAsync()
        {
            try
            {
                await _ianaDataManager.ApplyCacheStateAsync();
            }
            catch (Exception ex)
            {
                _log.Write(ex);
            }
        }

        public bool SaveCacheToDisk
        {
            get { return _saveCacheToDisk; }
            set
            {
                _saveCacheToDisk = value;

                if (!_saveCacheToDisk)
                {
                    try
                    {
                        _cacheZoneManager.DeleteCacheZoneFile();
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                }
            }
        }

        public bool ServeStale
        {
            get { return _serveStale; }
            set { _serveStale = value; }
        }

        public int ServeStaleMaxWaitTime
        {
            get { return _serveStaleMaxWaitTime; }
            set
            {
                if ((value < 0) || (value > 1800))
                    throw new ArgumentOutOfRangeException(nameof(ServeStaleMaxWaitTime), "Serve stale max wait time valid range is 0 to 1800 milliseconds. Default value is 1800 milliseconds.");

                _serveStaleMaxWaitTime = value;
            }
        }

        public int CachePrefetchEligibility
        {
            get { return _cachePrefetchEligibility; }
            set
            {
                if (value < 2)
                    throw new ArgumentOutOfRangeException(nameof(CachePrefetchEligibility), "Valid value is greater that or equal to 2.");

                _cachePrefetchEligibility = value;
            }
        }

        public int CachePrefetchTriggerPercent
        {
            get { return _cachePrefetchTriggerPercent; }
            set
            {
                if ((value < 0) || (value > 50))
                    throw new ArgumentOutOfRangeException(nameof(CachePrefetchTriggerPercent), "Valid range is from 0 to 50 percent.");

                _cachePrefetchTriggerPercent = value;
            }
        }

        public int CachePrefetchTrigger
        {
            get { return _cachePrefetchTrigger; }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(CachePrefetchTrigger), "Valid value is greater that or equal to 0.");

                _cachePrefetchTrigger = value;
            }
        }

        public bool IPv6AutoFallback
        {
            get { return IPv6Reachability.Enabled; }
            set { IPv6Reachability.Enabled = value; }
        }

        public int UdpListenerThreads
        {
            get { return _udpListenerThreads; }
            set
            {
                if ((value < 0) || (value > 64))
                    throw new ArgumentOutOfRangeException(nameof(UdpListenerThreads), "UDP listener threads must be between 0 (automatic) and 64.");

                _udpListenerThreads = value;
            }
        }

        public int MaxPendingStreamRequests
        {
            get { return _maxPendingStreamRequests; }
            set
            {
                if ((value < 1) || (value > 10000))
                    throw new ArgumentOutOfRangeException(nameof(MaxPendingStreamRequests), "Max pending requests per connection must be between 1 and 10000.");

                _maxPendingStreamRequests = value;
            }
        }

        public bool DnssecPostQuantumDowngradeProtection
        {
            get { return DnsClient.PostQuantumDowngradeProtection; }
            set
            {
                if (DnsClient.PostQuantumDowngradeProtection != value)
                {
                    DnsClient.PostQuantumDowngradeProtection = value;
                    _cacheZoneManager.Flush();
                }
            }
        }

        public bool RequestFilterMalformed
        {
            get { return _requestFilterMalformed; }
            set { _requestFilterMalformed = value; }
        }

        public int RequestFilterMaxSize
        {
            get { return _requestFilterMaxSize; }
            set
            {
                if ((value != 0) && ((value < 512) || (value > 65535)))
                    throw new ArgumentOutOfRangeException(nameof(RequestFilterMaxSize), "Maximum request size must be 0 (disabled) or between 512 and 65535 bytes.");

                _requestFilterMaxSize = value;
            }
        }

        public bool RequestFilterOpcode
        {
            get { return _requestFilterOpcode; }
            set { _requestFilterOpcode = value; }
        }

        public bool RequestFilterClass
        {
            get { return _requestFilterClass; }
            set { _requestFilterClass = value; }
        }

        public bool RequestFilterAny
        {
            get { return _requestFilterAny; }
            set { _requestFilterAny = value; }
        }

        public bool RequestFilterZoneTransfer
        {
            get { return _requestFilterZoneTransfer; }
            set { _requestFilterZoneTransfer = value; }
        }

        public bool RequestFilterNoRecursion
        {
            get { return _requestFilterNoRecursion; }
            set { _requestFilterNoRecursion = value; }
        }

        public bool RequestFilterEdnsVersion
        {
            get { return _requestFilterEdnsVersion; }
            set { _requestFilterEdnsVersion = value; }
        }

        public bool RequestFilterRefuseOnly
        {
            get { return _requestFilterRefuseOnly; }
            set { _requestFilterRefuseOnly = value; }
        }

        public long GetRequestFilterMatches(RequestFilterRule rule)
        {
            return Interlocked.Read(ref _requestFilterMatches[(int)rule]);
        }

        public bool EnableBlocking
        {
            get { return _enableBlocking; }
            set
            {
                _enableBlocking = value;

                if (_enableBlocking)
                    _blockListZoneManager.StopTemporaryDisableBlockingTimer();
            }
        }

        public bool AllowTxtBlockingReport
        {
            get { return _allowTxtBlockingReport; }
            set { _allowTxtBlockingReport = value; }
        }

        public IReadOnlyCollection<NetworkAddress> BlockingBypassList
        {
            get { return _blockingBypassList; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _blockingBypassList = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(BlockingBypassList), "Networks cannot have more than 255 entries.");
                else
                    _blockingBypassList = value;
            }
        }

        public DnsServerBlockingType BlockingType
        {
            get { return _blockingType; }
            set { _blockingType = value; }
        }

        public uint BlockingAnswerTtl
        {
            get { return _blockingAnswerTtl; }
            set { _blockingAnswerTtl = value; }
        }

        public uint BlockingNegativeTtl
        {
            get { return _blockingNegativeTtl; }
            set
            {
                if (value > 604800)
                    throw new ArgumentOutOfRangeException(nameof(BlockingNegativeTtl), "Valid range is from 0 to 604800 seconds.");

                if (_blockingNegativeTtl != value)
                {
                    _blockingNegativeTtl = value;

                    _blockedZoneManager.UpdateServerDomain();
                    _blockListZoneManager.UpdateServerDomain();
                }
            }
        }

        public string BlockingReportText
        {
            get { return _blockingReportText; }
            set
            {
                if (string.IsNullOrWhiteSpace(value))
                {
                    _blockingReportText = null;
                    return;
                }

                value = value.Trim();

                if (Encoding.UTF8.GetByteCount(value) > 255)
                    throw new ArgumentOutOfRangeException(nameof(BlockingReportText), "Blocking report text cannot be longer than 255 bytes.");

                _blockingReportText = value;
            }
        }

        internal bool IsBlockingReportTextPerList
        { get { return (_blockingReportText is null) || _blockingReportText.Contains("{list}", StringComparison.Ordinal); } }

        internal string GetBlockingReportText(string source, string blockedDomain, string blockListUrl)
        {
            string text = _blockingReportText;

            if (text is null)
            {
                if (blockListUrl is null)
                    return "source=" + source + "; domain=" + blockedDomain;

                return "source=" + source + "; blockListUrl=" + blockListUrl + "; domain=" + blockedDomain;
            }

            return text.Replace("{domain}", blockedDomain, StringComparison.Ordinal).Replace("{source}", source, StringComparison.Ordinal).Replace("{list}", blockListUrl ?? string.Empty, StringComparison.Ordinal);
        }

        public IReadOnlyCollection<DnsARecordData> CustomBlockingARecords
        {
            get { return _customBlockingARecords; }
            set
            {
                if (value is null)
                    value = [];

                _customBlockingARecords = value;
            }
        }

        public IReadOnlyCollection<DnsAAAARecordData> CustomBlockingAAAARecords
        {
            get { return _customBlockingAAAARecords; }
            set
            {
                if (value is null)
                    value = [];

                _customBlockingAAAARecords = value;
            }
        }

        public NetProxy Proxy
        {
            get { return _proxy; }
            set { _proxy = value; }
        }

        public IReadOnlyList<NameServerAddress> Forwarders
        {
            get { return _forwarders; }
            set { _forwarders = value; }
        }

        public bool ConcurrentForwarding
        {
            get { return _concurrentForwarding; }
            set { _concurrentForwarding = value; }
        }

        public int ForwarderRetries
        {
            get { return _forwarderRetries; }
            set
            {
                if ((value < 1) || (value > 10))
                    throw new ArgumentOutOfRangeException(nameof(ForwarderRetries), "Valid range is from 1 to 10.");

                _forwarderRetries = value;
            }
        }

        public int ForwarderTimeout
        {
            get { return _forwarderTimeout; }
            set
            {
                if ((value < 1000) || (value > 10000))
                    throw new ArgumentOutOfRangeException(nameof(ForwarderTimeout), "Valid range is from 1000 to 10000.");

                _forwarderTimeout = value;
            }
        }

        public int ForwarderConcurrency
        {
            get { return _forwarderConcurrency; }
            set
            {
                if ((value < 1) || (value > 10))
                    throw new ArgumentOutOfRangeException(nameof(ForwarderConcurrency), "Valid range is from 1 to 10.");

                _forwarderConcurrency = value;
            }
        }

        public LogManager ResolverLogManager
        {
            get { return _resolverLog; }
            set { _resolverLog = value; }
        }

        public LogManager QueryLogManager
        {
            get { return _queryLog; }
            set { _queryLog = value; }
        }

        #endregion

        class RecursiveResolveResponse
        {
            public RecursiveResolveResponse(DnsDatagram response, DnsDatagram checkingDisabledResponse)
            {
                Response = response;
                CheckingDisabledResponse = checkingDisabledResponse;
            }

            public DnsDatagram Response { get; }

            public DnsDatagram CheckingDisabledResponse { get; }
        }
    }

#pragma warning restore CA1416
}
