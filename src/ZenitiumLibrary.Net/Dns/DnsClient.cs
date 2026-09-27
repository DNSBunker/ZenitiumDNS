/*
Technitium Library
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

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Xml;
using ZenitiumLibrary.Net.Dns.ClientConnection;
using ZenitiumLibrary.Net.Dns.Dnssec;
using ZenitiumLibrary.Net.Dns.EDnsOptions;
using ZenitiumLibrary.Net.Dns.ResourceRecords;
using ZenitiumLibrary.Net.Proxy;

namespace ZenitiumLibrary.Net.Dns
{
    public enum DnsTransportProtocol : byte
    {
        Udp = 0,
        Tcp = 1,
        Tls = 2,
        Https = 3,
        HttpsJson = 4,
        Quic = 5,
        UdpProxy = 253,
        TcpProxy = 254
    }

    public enum IPv6Mode : byte
    {
        Disabled = 0,
        Enabled = 1,
        Preferred = 2
    }

    public class DnsClient : IDnsClient
    {
        #region variables

        static IReadOnlyList<NameServerAddress> IPv4_ROOT_HINTS;
        static IReadOnlyList<NameServerAddress> IPv6_ROOT_HINTS;

        static IReadOnlyList<DnsResourceRecord> ROOT_TRUST_ANCHORS;
        static volatile bool _postQuantumDowngradeProtection = true;

        readonly static IdnMapping _idnMapping = new IdnMapping() { AllowUnassigned = true };

        const int MAX_DELEGATION_HOPS = 16;
        internal const int MAX_CNAME_HOPS = 16;
        const int MAX_NS_TO_QUERY_PER_REFERRAL = 8;
        const int MAX_ASYNC_NS_RESOLUTIONS_PER_REFERRAL = 4;
        const int MAX_OUTBOUND_REQUESTS = 400;
        const int QUERY_PADDING_BLOCK_SIZE = 128;
        const int IPV6_UNANSWERED_FAILURE_TIME = 1000;
        internal const int MAX_NSEC3_ITERATIONS = 100;

        const int KEY_TRAP_MAX_KEY_TAG_COLLISIONS = 4;
        const int KEY_TRAP_MAX_CRYPTO_FAILURES = 4;
        const int KEY_TRAP_MAX_RRSET_VALIDATIONS_PER_SUSPENSION = 8;
        const int KEY_TRAP_MAX_RRSET_VALIDATION_SUSPENSIONS = 16;

        const int NSEC3_MAX_HASHES_PER_SUSPENSION = 8;
        const int NSEC3_MAX_SUSPENSIONS = 16;

        const int NS_RESOLUTION_TIMEOUT = 60000;

        readonly IReadOnlyList<NameServerAddress> _servers;

        IDnsCache _cache;
        NetProxy _proxy;
        IPv6Mode _ipv6Mode;
        ushort _udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE;
        bool _randomizeName;
        bool _eDnsPadding;
        bool _dnssecValidation;
        NetworkAddress _eDnsClientSubnet;
        bool _advancedForwardingClientSubnet;
        string _conditionalForwardingZoneCut;
        int _retries = 2;
        int _timeout = 2000;
        int _concurrency = 2;

        Dictionary<string, IReadOnlyList<DnsResourceRecord>> _trustAnchors;

        #endregion

        #region constructor

        static DnsClient()
        {
            IPv4_ROOT_HINTS =
            [
                new NameServerAddress("a.root-servers.net", IPAddress.Parse("198.41.0.4")),
                new NameServerAddress("b.root-servers.net", IPAddress.Parse("170.247.170.2")),
                new NameServerAddress("c.root-servers.net", IPAddress.Parse("192.33.4.12")),
                new NameServerAddress("d.root-servers.net", IPAddress.Parse("199.7.91.13")),
                new NameServerAddress("e.root-servers.net", IPAddress.Parse("192.203.230.10")),
                new NameServerAddress("f.root-servers.net", IPAddress.Parse("192.5.5.241")),
                new NameServerAddress("g.root-servers.net", IPAddress.Parse("192.112.36.4")),
                new NameServerAddress("h.root-servers.net", IPAddress.Parse("198.97.190.53")),
                new NameServerAddress("i.root-servers.net", IPAddress.Parse("192.36.148.17")),
                new NameServerAddress("j.root-servers.net", IPAddress.Parse("192.58.128.30")),
                new NameServerAddress("k.root-servers.net", IPAddress.Parse("193.0.14.129")),
                new NameServerAddress("l.root-servers.net", IPAddress.Parse("199.7.83.42")),
                new NameServerAddress("m.root-servers.net", IPAddress.Parse("202.12.27.33"))
            ];

            IPv6_ROOT_HINTS =
            [
                new NameServerAddress("a.root-servers.net", IPAddress.Parse("2001:503:ba3e::2:30")),
                new NameServerAddress("b.root-servers.net", IPAddress.Parse("2801:1b8:10::b")),
                new NameServerAddress("c.root-servers.net", IPAddress.Parse("2001:500:2::c")),
                new NameServerAddress("d.root-servers.net", IPAddress.Parse("2001:500:2d::d")),
                new NameServerAddress("e.root-servers.net", IPAddress.Parse("2001:500:a8::e")),
                new NameServerAddress("f.root-servers.net", IPAddress.Parse("2001:500:2f::f")),
                new NameServerAddress("g.root-servers.net", IPAddress.Parse("2001:500:12::d0d")),
                new NameServerAddress("h.root-servers.net", IPAddress.Parse("2001:500:1::53")),
                new NameServerAddress("i.root-servers.net", IPAddress.Parse("2001:7fe::53")),
                new NameServerAddress("j.root-servers.net", IPAddress.Parse("2001:503:c27::2:30")),
                new NameServerAddress("k.root-servers.net", IPAddress.Parse("2001:7fd::1")),
                new NameServerAddress("l.root-servers.net", IPAddress.Parse("2001:500:9f::42")),
                new NameServerAddress("m.root-servers.net", IPAddress.Parse("2001:dc3::35"))
            ];

            ROOT_TRUST_ANCHORS =
            [
                new DnsResourceRecord("", DnsResourceRecordType.DS, DnsClass.IN, 0, new DnsDSRecordData(20326, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, Convert.FromHexString("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D"))),
                new DnsResourceRecord("", DnsResourceRecordType.DS, DnsClass.IN, 0, new DnsDSRecordData(38696, DnssecAlgorithm.RSASHA256, DnssecDigestType.SHA256, Convert.FromHexString("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")))
            ];

            _ = Task.Run(ReloadRootHintsAsync);

            try
            {
                ReloadRootTrustAnchors();
            }
            catch
            { }
        }

        protected DnsClient()
        { }

        public DnsClient(Uri dohEndPoint)
        {
            _servers = [new NameServerAddress(dohEndPoint)];
        }

        public DnsClient(Uri[] dohEndPoints)
        {
            if (dohEndPoints.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            NameServerAddress[] servers = new NameServerAddress[dohEndPoints.Length];

            for (int i = 0; i < dohEndPoints.Length; i++)
                servers[i] = new NameServerAddress(dohEndPoints[i]);

            _servers = servers;
        }

        public DnsClient(IPv6Mode ipv6Mode = IPv6Mode.Disabled)
        {
            _ipv6Mode = ipv6Mode;

            IReadOnlyList<IPAddress> systemDnsServers = GetSystemDnsServers(_ipv6Mode);
            if (systemDnsServers.Count == 0)
                throw new DnsClientException("No DNS servers were found configured on this system.");

            NameServerAddress[] servers = new NameServerAddress[systemDnsServers.Count];

            for (int i = 0; i < systemDnsServers.Count; i++)
                servers[i] = new NameServerAddress(systemDnsServers[i]);

            _servers = servers;
        }

        public DnsClient(IPAddress[] servers)
        {
            if (servers.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            NameServerAddress[] nameServers = new NameServerAddress[servers.Length];

            for (int i = 0; i < servers.Length; i++)
                nameServers[i] = new NameServerAddress(servers[i]);

            _servers = nameServers;
        }

        public DnsClient(IPAddress server)
            : this(new NameServerAddress(server))
        { }

        public DnsClient(EndPoint server)
            : this(new NameServerAddress(server))
        { }

        public DnsClient(string addresses)
            : this(addresses.Split(NameServerAddress.Parse, ','))
        { }

        public DnsClient(params string[] addresses)
            : this(addresses.Convert(NameServerAddress.Parse))
        { }

        public DnsClient(string address, DnsTransportProtocol protocol)
            : this(NameServerAddress.Parse(address, protocol))
        { }

        public DnsClient(NameServerAddress server)
        {
            _servers = [server];
        }

        public DnsClient(params NameServerAddress[] servers)
        {
            if (servers.Length == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            _servers = servers;
        }

        public DnsClient(IReadOnlyList<NameServerAddress> servers)
        {
            if (servers.Count == 0)
                throw new DnsClientException("At least one name server must be available for DnsClient.");

            _servers = servers;
        }

        #endregion

        #region static

        public static async Task ReloadRootHintsAsync()
        {
            string rootHintsFile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "named.root");
            if (!File.Exists(rootHintsFile))
                return;

            List<DnsResourceRecord> rootZoneRecords = await ZoneFile.ReadZoneFileFromAsync(rootHintsFile);

            List<NameServerAddress> ipv4RootHints = new List<NameServerAddress>(13);
            List<NameServerAddress> ipv6RootHints = new List<NameServerAddress>(13);

            foreach (DnsResourceRecord nsRecord in rootZoneRecords)
            {
                if (nsRecord.Type != DnsResourceRecordType.NS)
                    continue;

                if (nsRecord.Name.Length != 0)
                    continue;

                string name = (nsRecord.RDATA as DnsNSRecordData).NameServer.ToLowerInvariant();

                foreach (DnsResourceRecord record in rootZoneRecords)
                {
                    switch (record.Type)
                    {
                        case DnsResourceRecordType.A:
                            if (name.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                ipv4RootHints.Add(new NameServerAddress(name, (record.RDATA as DnsARecordData).Address));

                            break;

                        case DnsResourceRecordType.AAAA:
                            if (name.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                                ipv6RootHints.Add(new NameServerAddress(name, (record.RDATA as DnsAAAARecordData).Address));

                            break;
                    }
                }
            }

            IPv4_ROOT_HINTS = ipv4RootHints;
            IPv6_ROOT_HINTS = ipv6RootHints;
        }

        public static bool PostQuantumDowngradeProtection
        {
            get { return _postQuantumDowngradeProtection; }
            set { _postQuantumDowngradeProtection = value; }
        }

        public static void ClearRootHintsMisconfiguredMarks()
        {
            foreach (NameServerAddress rootHint in IPv4_ROOT_HINTS)
                rootHint.Metadata.ClearMisconfiguredMark();

            foreach (NameServerAddress rootHint in IPv6_ROOT_HINTS)
                rootHint.Metadata.ClearMisconfiguredMark();
        }

        public static void ReloadRootTrustAnchors()
        {
            string rootTrustXmlFile = Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "root-anchors.xml");

            IReadOnlyList<DnsResourceRecord> rootTrustAnchors = ParseRootTrustAnchors(File.ReadAllText(rootTrustXmlFile));

            if (rootTrustAnchors.Count > 0)
                ROOT_TRUST_ANCHORS = rootTrustAnchors;
        }

        public static IReadOnlyList<DnsResourceRecord> ParseRootTrustAnchors(string xml)
        {
            XmlDocument rootTrustXml = new XmlDocument();
            rootTrustXml.XmlResolver = null;
            rootTrustXml.LoadXml(xml);

            XmlNamespaceManager nsMgr = new XmlNamespaceManager(rootTrustXml.NameTable);
            XmlNodeList nodeList = rootTrustXml.SelectNodes("//TrustAnchor/KeyDigest", nsMgr);

            const string dateFormat = "yyyy-MM-ddTHH:mm:sszzz";
            List<DnsResourceRecord> rootTrustAnchors = new List<DnsResourceRecord>();

            foreach (XmlNode keyDigestNode in nodeList)
            {
                DateTime validFrom = DateTime.MinValue;
                DateTime validUntil = DateTime.MinValue;

                foreach (XmlAttribute attribute in keyDigestNode.Attributes)
                {
                    switch (attribute.Name)
                    {
                        case "validFrom":
                            validFrom = DateTime.ParseExact(attribute.Value, dateFormat, CultureInfo.InvariantCulture);
                            break;

                        case "validUntil":
                            validUntil = DateTime.ParseExact(attribute.Value, dateFormat, CultureInfo.InvariantCulture);
                            break;
                    }
                }

                if ((validFrom != DateTime.MinValue) && (validFrom > DateTime.UtcNow))
                    continue;

                if ((validUntil != DateTime.MinValue) && (validUntil < DateTime.UtcNow))
                    continue;

                ushort keyTag = 0;
                DnssecAlgorithm algorithm = DnssecAlgorithm.Unknown;
                DnssecDigestType digestType = DnssecDigestType.Unknown;
                string digest = null;

                foreach (XmlNode childNode in keyDigestNode.ChildNodes)
                {
                    switch (childNode.Name.ToLowerInvariant())
                    {
                        case "keytag":
                            keyTag = ushort.Parse(childNode.InnerText);
                            break;

                        case "algorithm":
                            algorithm = (DnssecAlgorithm)byte.Parse(childNode.InnerText);
                            break;

                        case "digesttype":
                            digestType = (DnssecDigestType)byte.Parse(childNode.InnerText);
                            break;

                        case "digest":
                            digest = childNode.InnerText;
                            break;
                    }
                }

                rootTrustAnchors.Add(new DnsResourceRecord("", DnsResourceRecordType.DS, DnsClass.IN, 0, new DnsDSRecordData(keyTag, algorithm, digestType, Convert.FromHexString(digest))));
            }

            return rootTrustAnchors;
        }

        public static IReadOnlyList<DnsResourceRecord> RootTrustAnchors
        {
            get { return ROOT_TRUST_ANCHORS; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    throw new ArgumentException("At least one root trust anchor is required.", nameof(RootTrustAnchors));

                ROOT_TRUST_ANCHORS = value;
            }
        }

        public static async Task<DnsDatagram> RecursiveResolveAsync(DnsQuestionRecord question, IDnsCache cache = null, NetProxy proxy = null, IPv6Mode ipv6Mode = IPv6Mode.Disabled, ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, bool randomizeName = false, bool qnameMinimization = false, bool dnssecValidation = false, NetworkAddress eDnsClientSubnet = null, int retries = 2, int timeout = 2000, int concurrency = 2, int maxStackCount = 16, bool minimalResponse = false, bool asyncNsResolution = false, List<DnsDatagram> rawResponses = null, ResolverContext context = null, CancellationToken cancellationToken = default)
        {
            if (context is null)
                context = new ResolverContext();
            else if (!context.CanProceedWithResolution())
                throw new DnsClientNoResponseException("DnsClient failed to recursively resolve the request '" + question.ToString() + "': Resolver limit reached (" + context.GetCannotProceedWithResolutionReason() + ").");

            if ((udpPayloadSize < 512) && (dnssecValidation || (eDnsClientSubnet is not null)))
                throw new ArgumentOutOfRangeException(nameof(udpPayloadSize), "EDNS cannot be disabled by setting UDP payload size to less than 512 when DNSSEC validation or EDNS Client Subnet is enabled.");

            EDnsOption[] eDnsClientSubnetOption = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(eDnsClientSubnet);

            if (cache is null)
                cache = new DnsCache();

            if (qnameMinimization)
            {
                question = question.Clone();
                question.ZoneCut = "";
            }

            List<EDnsExtendedDnsErrorOptionData> extendedDnsErrors = new List<EDnsExtendedDnsErrorOptionData>();

            HashSet<string> asyncNsResolutionTasks = null;

            if (asyncNsResolution)
                asyncNsResolutionTasks = new HashSet<string>();

            void TriggerNsResolution()
            {
                if (!asyncNsResolution || (asyncNsResolutionTasks.Count == 0))
                    return;

                _ = Task.Factory.StartNew(delegate ()
                {
                    return TaskExtensions.TimeoutAsync(async delegate (CancellationToken cancellationToken1)
                    {
                        List<Task> tasks = new List<Task>();

                        foreach (string nsDomain in asyncNsResolutionTasks)
                        {
                            if (IPv6Reachability.GetEffectiveMode(ipv6Mode) != IPv6Mode.Disabled)
                                tasks.Add(RecursiveResolveAsync(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.AAAA, DnsClass.IN), cache, proxy, IPv6Reachability.GetEffectiveMode(ipv6Mode), udpPayloadSize, randomizeName, qnameMinimization, dnssecValidation, null, retries, timeout, concurrency, maxStackCount, context: context, cancellationToken: cancellationToken1));

                            tasks.Add(RecursiveResolveAsync(new DnsQuestionRecord(nsDomain, DnsResourceRecordType.A, DnsClass.IN), cache, proxy, IPv6Reachability.GetEffectiveMode(ipv6Mode), udpPayloadSize, randomizeName, qnameMinimization, dnssecValidation, null, retries, timeout, concurrency, maxStackCount, context: context, cancellationToken: cancellationToken1));
                        }

                        await Task.WhenAll(tasks);
                    }, NS_RESOLUTION_TIMEOUT, CancellationToken.None);
                }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current);
            }

            Stack<ResolverData> resolverStack = new Stack<ResolverData>();

            string zoneCut = null;
            bool dnssecValidationState = dnssecValidation;
            IReadOnlyList<DnsResourceRecord> lastDSRecords = dnssecValidation ? ROOT_TRUST_ANCHORS : null;
            IList<NameServerAddress> nameServers = null;
            int nameServerIndex = 0;
            int hopCount = 0;
            DnsDatagram lastResponse = null;
            Exception lastException = null;

            void PushStack(string nextQName, DnsResourceRecordType nextQType)
            {
                resolverStack.Push(new ResolverData(question, zoneCut, dnssecValidationState, lastDSRecords, nameServers, nameServerIndex, hopCount, lastResponse, lastException));

                question = new DnsQuestionRecord(nextQName, nextQType, question.Class);

                if (qnameMinimization)
                    question.ZoneCut = "";

                zoneCut = null;
                dnssecValidationState = dnssecValidation;
                lastDSRecords = dnssecValidation ? ROOT_TRUST_ANCHORS : null;
                nameServers = null;
                nameServerIndex = 0;
                hopCount = 0;
                lastResponse = null;
                lastException = null;
            }

            void PopStack()
            {
                ResolverData data = resolverStack.Pop();

                question = data.Question;
                zoneCut = data.ZoneCut;
                dnssecValidationState = data.DnssecValidationState;
                lastDSRecords = data.LastDSRecords;
                nameServers = data.NameServers;
                nameServerIndex = data.NameServerIndex;
                hopCount = data.HopCount;
                lastResponse = data.LastResponse;

                if (data.LastException is not null)
                    lastException = data.LastException;
            }

            void InspectCacheNameServersForLoops(List<NameServerAddress> cacheNameServers)
            {
                bool allCacheNameServersHaveGlue = true;

                foreach (NameServerAddress cacheNameServer in cacheNameServers)
                {
                    if (cacheNameServer.IsIPEndPointStale)
                    {
                        allCacheNameServersHaveGlue = false;
                        break;
                    }
                }

                if (allCacheNameServersHaveGlue)
                    return;

                foreach (ResolverData stack in resolverStack)
                {
                    foreach (NameServerAddress stackNameServer in stack.NameServers)
                    {
                        if (cacheNameServers.Contains(stackNameServer))
                        {
                            cacheNameServers.Clear();
                            return;
                        }
                    }
                }
            }

            async Task<List<NameServerAddress>> ResolveNameServerAddressesFromCacheAsync(List<NameServerAddress> nameServers)
            {
                List<NameServerAddress> newNameServers = new List<NameServerAddress>(IPv6Reachability.GetEffectiveMode(ipv6Mode) != IPv6Mode.Disabled ? nameServers.Count * 2 : nameServers.Count);

                foreach (NameServerAddress nameServer in nameServers)
                {
                    if (nameServer.IPEndPoint is not null)
                    {
                        newNameServers.Add(nameServer);
                        continue;
                    }

                    bool resolved = false;

                    if (IPv6Reachability.GetEffectiveMode(ipv6Mode) != IPv6Mode.Disabled)
                    {
                        DnsDatagram cacheRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(nameServer.DomainEndPoint.Address, DnsResourceRecordType.AAAA, DnsClass.IN)]);
                        DnsDatagram cacheResponse = await cache.QueryAsync(cacheRequest);
                        if ((cacheResponse is not null) && (cacheResponse.Answer.Count > 0) && (cacheResponse.Answer[0].Type == DnsResourceRecordType.AAAA))
                        {
                            resolved = true;
                            newNameServers.Add(nameServer.Clone((cacheResponse.Answer[0].RDATA as DnsAAAARecordData).Address));
                        }
                    }

                    {
                        DnsDatagram cacheRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(nameServer.DomainEndPoint.Address, DnsResourceRecordType.A, DnsClass.IN)]);
                        DnsDatagram cacheResponse = await cache.QueryAsync(cacheRequest);
                        if ((cacheResponse is not null) && (cacheResponse.Answer.Count > 0) && (cacheResponse.Answer[0].Type == DnsResourceRecordType.A))
                        {
                            resolved = true;
                            newNameServers.Add(nameServer.Clone((cacheResponse.Answer[0].RDATA as DnsARecordData).Address));
                        }
                    }

                    if (!resolved)
                        newNameServers.Add(nameServer);
                }

                return newNameServers;
            }

            while (true)
            {
                if (resolverStack.Count > maxStackCount)
                {
                    while (resolverStack.Count > 0)
                    {
                        PopStack();
                    }

                    DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                    if (extendedDnsErrors.Count > 0)
                        failureResponse.AddDnsClientExtendedErrors(extendedDnsErrors);

                    failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.ResolverLimitReached, "Resolver limit reached (MaxStackCount) for " + question.ToString());

                    if (eDnsClientSubnet is not null)
                        failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                    cache.CacheResponse(failureResponse);

                    throw new DnsClientException("DnsClient recursive resolution exceeded the maximum stack count for domain: " + question.Name.ToLowerInvariant());
                }

                {
                    DnsDatagram cacheRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [question], null, null, null, udpPayloadSize, dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, resolverStack.Count == 0 ? eDnsClientSubnetOption : null);
                    DnsDatagram cacheResponse = await cache.QueryAsync(cacheRequest, findClosestNameServers: true);
                    if (cacheResponse is not null)
                    {
                        extendedDnsErrors.AddRange(cacheResponse.DnsClientExtendedErrors);

                        switch (cacheResponse.RCODE)
                        {
                            case DnsResponseCode.NoError:
                                {
                                    if (cacheResponse.Answer.Count > 0)
                                    {
                                        if (resolverStack.Count == 0)
                                        {
                                            return cacheResponse;
                                        }
                                        else
                                        {
                                            bool found = false;

                                            for (int i = 0; i < cacheResponse.Answer.Count; i++)
                                            {
                                                DnsResourceRecord answer = cacheResponse.Answer[i];
                                                switch (answer.Type)
                                                {
                                                    case DnsResourceRecordType.AAAA:
                                                        found = true;
                                                        PopStack();
                                                        nameServers[nameServerIndex] = nameServers[nameServerIndex].Clone((answer.RDATA as DnsAAAARecordData).Address);

                                                        for (int j = i + 1, k = 1; j < cacheResponse.Answer.Count; j++)
                                                        {
                                                            answer = cacheResponse.Answer[j];
                                                            if (answer.Type == DnsResourceRecordType.AAAA)
                                                                nameServers.Insert(nameServerIndex + k++, nameServers[nameServerIndex].Clone((answer.RDATA as DnsAAAARecordData).Address));
                                                        }

                                                        break;

                                                    case DnsResourceRecordType.A:
                                                        found = true;
                                                        PopStack();
                                                        nameServers[nameServerIndex] = nameServers[nameServerIndex].Clone((answer.RDATA as DnsARecordData).Address);

                                                        for (int j = i + 1, k = 1; j < cacheResponse.Answer.Count; j++)
                                                        {
                                                            answer = cacheResponse.Answer[j];
                                                            if (answer.Type == DnsResourceRecordType.A)
                                                                nameServers.Insert(nameServerIndex + k++, nameServers[nameServerIndex].Clone((answer.RDATA as DnsARecordData).Address));
                                                        }

                                                        break;

                                                    case DnsResourceRecordType.DS:
                                                        found = true;

                                                        Tuple<bool, IReadOnlyList<DnsResourceRecord>> tupleCacheDSRecords = await TryGetDSFromResponseAsync(cacheResponse, cacheResponse.Question[0].Name, context);
                                                        if (!tupleCacheDSRecords.Item1)
                                                            throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to unable to find DS records for owner name: " + cacheResponse.Question[0].Name.ToLowerInvariant(), cacheResponse);

                                                        IReadOnlyList<DnsResourceRecord> cacheDSRecords = tupleCacheDSRecords.Item2;

                                                        extendedDnsErrors.AddRange(cacheResponse.DnsClientExtendedErrors);

                                                        PopStack();

                                                        if (cacheDSRecords is null)
                                                        {
                                                            dnssecValidationState = false;
                                                            lastDSRecords = null;
                                                        }
                                                        else if (cacheDSRecords.Count > 0)
                                                        {
                                                            lastDSRecords = cacheDSRecords;
                                                        }
                                                        break;
                                                }

                                                if (found)
                                                    break;
                                            }
                                        }
                                    }
                                    else if (cacheResponse.Authority.Count > 0)
                                    {
                                        DnsResourceRecord firstAuthority = cacheResponse.FindFirstAuthorityRecord();

                                        if (firstAuthority.Type == DnsResourceRecordType.SOA)
                                        {
                                            if (resolverStack.Count == 0)
                                            {
                                                return cacheResponse;
                                            }
                                            else
                                            {
                                                DnsQuestionRecord lastQuestion = cacheResponse.Question[0];
                                                PopStack();

                                                switch (lastQuestion.Type)
                                                {
                                                    case DnsResourceRecordType.A:
                                                    case DnsResourceRecordType.AAAA:
                                                        nameServerIndex++;
                                                        extendedDnsErrors.Add(new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Failed to resolve name server " + lastQuestion.Name.ToLowerInvariant() + " at delegation " + zoneCut + "."));
                                                        break;

                                                    case DnsResourceRecordType.DS:
                                                        dnssecValidationState = false;
                                                        lastDSRecords = null;
                                                        break;
                                                }
                                            }
                                        }
                                        else
                                        {
                                            string nextZoneCut = null;
                                            bool nextDnssecValidationState = dnssecValidationState;
                                            IReadOnlyList<DnsResourceRecord> nextDSRecords = lastDSRecords;
                                            List<NameServerAddress> nextNameServers = null;

                                            nextNameServers = NameServerAddress.GetNameServersFromResponse(cacheResponse, IPv6Reachability.GetEffectiveMode(ipv6Mode), false);
                                            InspectCacheNameServersForLoops(nextNameServers);

                                            if (nextNameServers.Count > 0)
                                            {
                                                nextZoneCut = firstAuthority.Name;

                                                if (dnssecValidationState)
                                                {
                                                    Tuple<bool, IReadOnlyList<DnsResourceRecord>> tupleCacheDsRecords = await TryGetDSFromResponseAsync(cacheResponse, nextZoneCut, context);
                                                    if (tupleCacheDsRecords.Item1)
                                                    {
                                                        IReadOnlyList<DnsResourceRecord> cacheDsRecords = tupleCacheDsRecords.Item2;

                                                        extendedDnsErrors.AddRange(cacheResponse.DnsClientExtendedErrors);

                                                        if (cacheDsRecords is null)
                                                        {
                                                            nextDnssecValidationState = false;
                                                            nextDSRecords = null;
                                                        }
                                                        else if (cacheDsRecords.Count > 0)
                                                        {
                                                            nextDSRecords = cacheDsRecords;
                                                        }
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                string currentDomain = question.Name;

                                                while (true)
                                                {
                                                    int i = currentDomain.IndexOf('.');
                                                    if (i < 0)
                                                        break;

                                                    currentDomain = currentDomain.Substring(i + 1);

                                                    DnsDatagram cachedNsResponse = await cache.QueryAsync(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(currentDomain, DnsResourceRecordType.PARENT_NS, DnsClass.IN)]), findClosestNameServers: true);
                                                    if (cachedNsResponse is null)
                                                        continue;

                                                    nextNameServers = NameServerAddress.GetNameServersFromResponse(cachedNsResponse, IPv6Reachability.GetEffectiveMode(ipv6Mode), false);
                                                    InspectCacheNameServersForLoops(nextNameServers);

                                                    if (nextNameServers.Count > 0)
                                                    {
                                                        nextZoneCut = null;

                                                        if (cachedNsResponse.Answer.Count > 0)
                                                        {
                                                            foreach (DnsResourceRecord record in cachedNsResponse.Answer)
                                                            {
                                                                if (record.Type == DnsResourceRecordType.NS)
                                                                {
                                                                    nextZoneCut = record.Name;
                                                                    break;
                                                                }
                                                            }
                                                        }

                                                        if ((nextZoneCut is null) && (cachedNsResponse.Authority.Count > 0))
                                                        {
                                                            foreach (DnsResourceRecord record in cachedNsResponse.Authority)
                                                            {
                                                                if (record.Type == DnsResourceRecordType.NS)
                                                                {
                                                                    nextZoneCut = record.Name;
                                                                    break;
                                                                }
                                                            }
                                                        }

                                                        if (nextZoneCut is null)
                                                            nextNameServers.Clear();

                                                        break;
                                                    }
                                                }
                                            }

                                            if (nextNameServers.Count > 0)
                                            {
                                                bool prioritizeOnesWithIPAddress = asyncNsResolution || (resolverStack.Count > 0);

                                                if (question.ZoneCut is not null)
                                                    question.ZoneCut = nextZoneCut;

                                                zoneCut = nextZoneCut;
                                                dnssecValidationState = nextDnssecValidationState;
                                                lastDSRecords = nextDSRecords;
                                                nameServers = GetOrderedNameServersToPreferPerformance(nextNameServers, prioritizeOnesWithIPAddress, IPv6Reachability.GetEffectiveMode(ipv6Mode));
                                                nameServerIndex = 0;
                                                lastResponse = null;
                                            }
                                        }
                                    }
                                    else
                                    {
                                        if (resolverStack.Count == 0)
                                        {
                                            return cacheResponse;
                                        }
                                        else
                                        {
                                            DnsQuestionRecord lastQuestion = cacheResponse.Question[0];
                                            PopStack();

                                            switch (lastQuestion.Type)
                                            {
                                                case DnsResourceRecordType.A:
                                                case DnsResourceRecordType.AAAA:
                                                    nameServerIndex++;
                                                    extendedDnsErrors.Add(new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Failed to resolve name server " + lastQuestion.Name.ToLowerInvariant() + " at delegation " + zoneCut + "."));
                                                    break;

                                                case DnsResourceRecordType.DS:
                                                    throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to unable to find DS records for owner name: " + lastQuestion.Name.ToLowerInvariant(), cacheResponse);
                                            }
                                        }
                                    }
                                }
                                break;

                            case DnsResponseCode.NxDomain:
                                {
                                    if (resolverStack.Count == 0)
                                    {
                                        return cacheResponse;
                                    }
                                    else
                                    {
                                        DnsQuestionRecord lastQuestion = cacheResponse.Question[0];
                                        PopStack();

                                        switch (lastQuestion.Type)
                                        {
                                            case DnsResourceRecordType.A:
                                            case DnsResourceRecordType.AAAA:
                                                nameServerIndex++;
                                                extendedDnsErrors.Add(new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Failed to resolve name server " + lastQuestion.Name.ToLowerInvariant() + " at delegation " + zoneCut + "."));
                                                break;

                                            case DnsResourceRecordType.DS:
                                                dnssecValidationState = false;
                                                lastDSRecords = null;
                                                break;
                                        }

                                        break;
                                    }
                                }

                            default:
                                {
                                    if (resolverStack.Count == 0)
                                    {
                                        return cacheResponse;
                                    }
                                    else
                                    {
                                        DnsQuestionRecord lastQuestion = cacheResponse.Question[0];
                                        PopStack();

                                        switch (lastQuestion.Type)
                                        {
                                            case DnsResourceRecordType.A:
                                            case DnsResourceRecordType.AAAA:
                                                nameServerIndex++;
                                                extendedDnsErrors.Add(new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Failed to resolve name server " + lastQuestion.Name.ToLowerInvariant() + " at delegation " + zoneCut + "."));
                                                break;

                                            case DnsResourceRecordType.DS:
                                                throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to unable to find DS records for owner name: " + lastQuestion.Name.ToLowerInvariant(), cacheResponse);
                                        }

                                        break;
                                    }
                                }
                        }
                    }
                }

                if ((nameServers is null) || (nameServers.Count == 0))
                {
                    zoneCut = "";
                    nameServers = await GetRootServersUsingRootHintsAsync(cache, proxy, IPv6Reachability.GetEffectiveMode(ipv6Mode), udpPayloadSize, dnssecValidation, retries, timeout, concurrency, cancellationToken);
                    nameServerIndex = 0;
                    lastResponse = null;
                }

                while (true)
                {
                    if ((lastDSRecords is not null) && !lastDSRecords[0].Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase))
                    {
                        PushStack(zoneCut, DnsResourceRecordType.DS);
                        goto stackLoop;
                    }

                    int referralLimit = Math.Min(nameServers.Count, MAX_NS_TO_QUERY_PER_REFERRAL);

                    for (; nameServerIndex < referralLimit; nameServerIndex++)
                    {
                        cancellationToken.ThrowIfCancellationRequested();

                        if (!context.CanProceedWithResolution())
                            break;

                        int currentNameServerIndex = nameServerIndex;

                        List<NameServerAddress> resolvedNameServers = new List<NameServerAddress>(referralLimit - nameServerIndex);

                        for (int i = nameServerIndex; i < referralLimit; i++)
                        {
                            NameServerAddress nameServer = nameServers[i];

                            if (nameServer.IPEndPoint is null)
                                break;

                            resolvedNameServers.Add(nameServer);
                        }

                        DnsClient dnsClient;

                        if (resolvedNameServers.Count > 0)
                        {
                            nameServerIndex += resolvedNameServers.Count - 1;

                            for (int i = resolvedNameServers.Count - 1; i > -1; i--)
                            {
                                if (resolvedNameServers[i].Metadata.IsMisconfigured)
                                {
                                    resolvedNameServers.RemoveAt(i);

                                    if (referralLimit < nameServers.Count)
                                        referralLimit++;
                                }
                            }

                            if (resolvedNameServers.Count == 0)
                                continue;

                            dnsClient = new DnsClient(resolvedNameServers);
                            dnsClient._concurrency = concurrency;

                            if (IPv6Reachability.GetEffectiveMode(ipv6Mode) != IPv6Mode.Disabled)
                            {
                                int nsCount = nameServers.Count;

                                for (int i = 0; i < nsCount; i++)
                                {
                                    NameServerAddress nameServerWithIpv4Glue = nameServers[i];

                                    if ((nameServerWithIpv4Glue.IPEndPoint is null) || (nameServerWithIpv4Glue.IPEndPoint.AddressFamily == AddressFamily.InterNetworkV6))
                                        continue;

                                    bool foundNoOrIpv6Glue = false;

                                    foreach (NameServerAddress nameServer in nameServers)
                                    {
                                        if (nameServerWithIpv4Glue.DomainEndPoint.Address.Equals(nameServer.DomainEndPoint.Address, StringComparison.OrdinalIgnoreCase))
                                        {
                                            if ((nameServer.IPEndPoint is null) || (nameServer.IPEndPoint.AddressFamily == AddressFamily.InterNetworkV6))
                                            {
                                                foundNoOrIpv6Glue = true;
                                                break;
                                            }
                                        }
                                    }

                                    if (!foundNoOrIpv6Glue)
                                    {
                                        NameServerAddress nameServerForIpv6 = nameServerWithIpv4Glue.Clone((IPEndPoint)null);

                                        switch (ipv6Mode)
                                        {
                                            case IPv6Mode.Enabled:
                                                nameServers.Insert(i + 1, nameServerForIpv6);
                                                i++;
                                                nsCount++;
                                                break;

                                            case IPv6Mode.Preferred:
                                                nameServers.Add(nameServerForIpv6);
                                                break;

                                            default:
                                                throw new InvalidOperationException();
                                        }

                                        if ((referralLimit < nameServers.Count) && (referralLimit < MAX_NS_TO_QUERY_PER_REFERRAL))
                                            referralLimit++;
                                    }
                                }
                            }
                        }
                        else
                        {
                            bool foundNsLoop = false;

                            foreach (ResolverData stack in resolverStack)
                            {
                                if (stack.ZoneCut.Equals(zoneCut, StringComparison.OrdinalIgnoreCase))
                                {
                                    foundNsLoop = true;
                                    break;
                                }
                            }

                            if (foundNsLoop)
                            {
                                for (int i = nameServerIndex; i < nameServers.Count; i++)
                                {
                                    if (nameServers[i].Host.EndsWith("." + zoneCut, StringComparison.OrdinalIgnoreCase))
                                        nameServers[i].Metadata.MarkMisconfigured();
                                }

                                break;
                            }

                            NameServerAddress currentNameServer = nameServers[nameServerIndex];

                            if (currentNameServer.Metadata.IsMisconfigured)
                                continue;

                            if (IPv6Reachability.GetEffectiveMode(ipv6Mode) != IPv6Mode.Disabled)
                            {
                                bool wasIPv4Attempted = false;
                                bool wasIPv6Attempted = false;

                                for (int i = 0; i < nameServerIndex; i++)
                                {
                                    NameServerAddress attemptedNameServer = nameServers[i];

                                    if (attemptedNameServer.DomainEndPoint.Address.Equals(currentNameServer.DomainEndPoint.Address, StringComparison.OrdinalIgnoreCase))
                                    {
                                        if (attemptedNameServer.IPEndPoint is null)
                                        {
                                            wasIPv6Attempted = true;
                                            break;
                                        }

                                        switch (attemptedNameServer.IPEndPoint.AddressFamily)
                                        {
                                            case AddressFamily.InterNetwork:
                                                wasIPv4Attempted = true;
                                                break;

                                            case AddressFamily.InterNetworkV6:
                                                wasIPv6Attempted = true;
                                                break;
                                        }
                                    }

                                    if (wasIPv4Attempted && wasIPv6Attempted)
                                        break;
                                }

                                if (wasIPv6Attempted)
                                {
                                    PushStack(currentNameServer.DomainEndPoint.Address, DnsResourceRecordType.A);
                                }
                                else if (!wasIPv4Attempted && IPv6Reachability.IsUnconfirmed)
                                {
                                    nameServers.Insert(nameServerIndex + 1, currentNameServer);

                                    if ((referralLimit < nameServers.Count) && (referralLimit < MAX_NS_TO_QUERY_PER_REFERRAL))
                                        referralLimit++;

                                    PushStack(currentNameServer.DomainEndPoint.Address, DnsResourceRecordType.A);
                                }
                                else
                                {
                                    if (!wasIPv4Attempted)
                                    {
                                        switch (ipv6Mode)
                                        {
                                            case IPv6Mode.Enabled:
                                                nameServers.Insert(nameServerIndex + 1, currentNameServer);
                                                break;

                                            case IPv6Mode.Preferred:
                                                nameServers.Add(currentNameServer);
                                                break;

                                            default:
                                                throw new InvalidOperationException();
                                        }

                                        if ((referralLimit < nameServers.Count) && (referralLimit < MAX_NS_TO_QUERY_PER_REFERRAL))
                                            referralLimit++;
                                    }

                                    PushStack(currentNameServer.DomainEndPoint.Address, DnsResourceRecordType.AAAA);
                                }
                            }
                            else
                            {
                                PushStack(currentNameServer.DomainEndPoint.Address, DnsResourceRecordType.A);
                            }

                            goto stackLoop;
                        }

                        dnsClient._proxy = proxy;
                        dnsClient._randomizeName = randomizeName;
                        dnsClient._dnssecValidation = dnssecValidationState;
                        dnsClient._retries = retries;
                        dnsClient._timeout = timeout;

                        DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [question], null, null, null, udpPayloadSize, dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, (resolverStack.Count == 0) && zoneCut.Contains('.') ? eDnsClientSubnetOption : null);
                        DnsDatagram response;

                        try
                        {
                            string currentZoneCut = zoneCut;
                            IReadOnlyList<DnsResourceRecord> currentLastDSRecords = lastDSRecords;

                            response = await dnsClient.InternalResolveAsync(request, async delegate (DnsDatagram response, CancellationToken cancellationToken1)
                            {
                                cancellationToken1.ThrowIfCancellationRequested();

                                rawResponses?.Add(response);

                                response = SanitizeResponseAnswerForZoneCut(response, currentZoneCut);
                                response = SanitizeResponseAnswerForQName(response);
                                response = SanitizeResponseAuthorityForZoneCut(response, currentZoneCut);
                                response = SanitizeResponseAdditionalForZoneCut(response, currentZoneCut);

                                if (dnsClient._dnssecValidation)
                                {
                                    if (response.Metadata?.NameServer is not null)
                                    {
                                        DnsClient dnsClient1 = new DnsClient(response.Metadata.NameServer);

                                        dnsClient1._proxy = dnsClient._proxy;
                                        dnsClient1._randomizeName = dnsClient._randomizeName;
                                        dnsClient1._dnssecValidation = dnsClient._dnssecValidation;
                                        dnsClient1._retries = dnsClient._retries;
                                        dnsClient1._timeout = dnsClient._timeout;

                                        dnsClient = dnsClient1;
                                    }

                                    try
                                    {
                                        await DnssecValidateResponseAsync(response, currentLastDSRecords, dnsClient, cache, udpPayloadSize, context, cancellationToken1);
                                    }
                                    catch (DnsClientResponseDnssecValidationException ex)
                                    {
                                        if ((ex.Response.Question.Count > 0) && ex.Response.Question[0].Equals(question))
                                            throw;

                                        response.AddDnsClientExtendedErrorsFrom(ex.Response);
                                        throw new DnsClientResponseDnssecValidationException(ex.Message, response, ex);
                                    }

                                    response = SanitizeResponseAfterDnssecValidation(response);
                                }
                                else if (dnssecValidation)
                                {
                                    response.SetDnssecStatusForAllRecords(DnssecStatus.Insecure);
                                }
                                else
                                {
                                    response.SetDnssecStatusForAllRecords(DnssecStatus.Disabled);
                                }

                                if ((response.RCODE == DnsResponseCode.NoError) && (response.Answer.Count == 0) && (response.Authority.Count > 0))
                                {
                                    foreach (DnsResourceRecord authorityRecord in response.Authority)
                                    {
                                        if ((authorityRecord.Type == DnsResourceRecordType.NS) && authorityRecord.Name.Equals(currentZoneCut, StringComparison.OrdinalIgnoreCase))
                                        {
                                            if (authorityRecord.Name.Contains('.'))
                                                response.Metadata?.NameServer?.Metadata.MarkMisconfigured();

                                            throw new DnsClientResponseNotPreferredException(response);
                                        }
                                    }
                                }

                                return response;
                            }, true, context, cancellationToken);
                        }
                        catch (DnsClientResponseDnssecValidationException ex)
                        {
                            if (question.ZoneCut is not null)
                            {
                                bool unsupportedNSEC3IterationsValue = false;

                                if (ex.Response is not null)
                                {
                                    extendedDnsErrors.AddRange(ex.Response.DnsClientExtendedErrors);

                                    foreach (EDnsExtendedDnsErrorOptionData eDnsOption in ex.Response.DnsClientExtendedErrors)
                                    {
                                        if (eDnsOption.InfoCode == EDnsExtendedDnsErrorCode.UnsupportedNSEC3IterationsValue)
                                        {
                                            unsupportedNSEC3IterationsValue = true;
                                            break;
                                        }
                                    }
                                }

                                if (unsupportedNSEC3IterationsValue)
                                {
                                    if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
                                    {
                                        if (question.Type == question.MinimizedType)
                                        {
                                        }
                                        else
                                        {
                                            question.ZoneCut = null;
                                            nameServerIndex = currentNameServerIndex - 1;
                                            continue;
                                        }
                                    }
                                    else
                                    {
                                        question.ZoneCut = question.MinimizedName;
                                        nameServerIndex = currentNameServerIndex - 1;
                                        continue;
                                    }
                                }
                            }

                            lastException = ex;
                            continue;
                        }
                        catch (DnsClientResponseValidationException ex)
                        {
                            if (question.ZoneCut is not null)
                            {
                                if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
                                {
                                    if (question.Type == question.MinimizedType)
                                    {
                                    }
                                    else
                                    {
                                        question.ZoneCut = null;
                                        nameServerIndex = currentNameServerIndex - 1;
                                        continue;
                                    }
                                }
                                else
                                {
                                    question.ZoneCut = question.MinimizedName;
                                    nameServerIndex = currentNameServerIndex - 1;
                                    continue;
                                }
                            }

                            lastException = ex;
                            continue;
                        }
                        catch (Exception ex)
                        {
                            lastException = ex;
                            continue;
                        }

                        if ((response.RCODE != DnsResponseCode.NoError) && (extendedDnsErrors.Count > 0))
                            response.AddDnsClientExtendedErrors(extendedDnsErrors);

                        cache.CacheResponse(response, false, zoneCut);

                        lastResponse = response;

                        extendedDnsErrors.AddRange(response.DnsClientExtendedErrors);

                        switch (response.RCODE)
                        {
                            case DnsResponseCode.NoError:
                                {
                                    if (response.Answer.Count > 0)
                                    {
                                        bool qnameMatches = response.Answer[0].Name.Equals(question.Name, StringComparison.OrdinalIgnoreCase);
                                        bool foundDNAME = false;

                                        if (!qnameMatches)
                                        {
                                            foreach (DnsResourceRecord answer in response.Answer)
                                            {
                                                if ((answer.Type == DnsResourceRecordType.DNAME) && question.Name.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    foundDNAME = true;
                                                    break;
                                                }
                                            }
                                        }

                                        if (qnameMatches || foundDNAME)
                                        {
                                            if (question.Type == question.MinimizedType)
                                            {
                                            }
                                            else if (question.ZoneCut is not null)
                                            {
                                                question.ZoneCut = null;
                                                nameServerIndex = currentNameServerIndex - 1;
                                                continue;
                                            }
                                        }
                                        else if (question.ZoneCut is not null)
                                        {
                                            question.ZoneCut = null;
                                            nameServerIndex = currentNameServerIndex - 1;
                                            continue;
                                        }
                                        else
                                        {
                                            continue;
                                        }

                                        if (resolverStack.Count == 0)
                                        {
                                            TriggerNsResolution();

                                            if (extendedDnsErrors.Count > 0)
                                                response.AddDnsClientExtendedErrors(extendedDnsErrors);

                                            if (minimalResponse)
                                                return GetMinimalResponseWithoutNSAndGlue(response);

                                            return response;
                                        }
                                        else
                                        {
                                            for (int i = 0; i < response.Answer.Count; i++)
                                            {
                                                DnsResourceRecord answer = response.Answer[i];
                                                switch (answer.Type)
                                                {
                                                    case DnsResourceRecordType.AAAA:
                                                        PopStack();
                                                        nameServers[nameServerIndex] = nameServers[nameServerIndex].Clone((answer.RDATA as DnsAAAARecordData).Address);

                                                        for (int j = i + 1, k = 1; j < response.Answer.Count; j++)
                                                        {
                                                            answer = response.Answer[j];
                                                            if (answer.Type == DnsResourceRecordType.AAAA)
                                                                nameServers.Insert(nameServerIndex + k++, nameServers[nameServerIndex].Clone((answer.RDATA as DnsAAAARecordData).Address));
                                                        }

                                                        goto resolverLoop;

                                                    case DnsResourceRecordType.A:
                                                        PopStack();
                                                        nameServers[nameServerIndex] = nameServers[nameServerIndex].Clone((answer.RDATA as DnsARecordData).Address);

                                                        for (int j = i + 1, k = 1; j < response.Answer.Count; j++)
                                                        {
                                                            answer = response.Answer[j];
                                                            if (answer.Type == DnsResourceRecordType.A)
                                                                nameServers.Insert(nameServerIndex + k++, nameServers[nameServerIndex].Clone((answer.RDATA as DnsARecordData).Address));
                                                        }

                                                        goto resolverLoop;

                                                    case DnsResourceRecordType.DS:
                                                        Tuple<bool, IReadOnlyList<DnsResourceRecord>> tupleDsRecords = await TryGetDSFromResponseAsync(response, request.Question[0].Name, context);
                                                        if (!tupleDsRecords.Item1)
                                                            throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to unable to find DS records for owner name: " + request.Question[0].Name.ToLowerInvariant(), response);

                                                        IReadOnlyList<DnsResourceRecord> dsRecords = tupleDsRecords.Item2;

                                                        extendedDnsErrors.AddRange(response.DnsClientExtendedErrors);

                                                        PopStack();

                                                        if (dsRecords is null)
                                                        {
                                                            dnssecValidationState = false;
                                                            lastDSRecords = null;
                                                        }
                                                        else if (dsRecords.Count > 0)
                                                        {
                                                            lastDSRecords = dsRecords;
                                                        }

                                                        goto resolverLoop;
                                                }
                                            }

                                            continue;
                                        }
                                    }
                                    else if (response.Authority.Count > 0)
                                    {
                                        DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();

                                        if (firstAuthority.Type == DnsResourceRecordType.SOA)
                                        {
                                            if (dnssecValidationState && (firstAuthority.DnssecStatus == DnssecStatus.Insecure))
                                            {
                                                dnssecValidationState = false;
                                                lastDSRecords = null;
                                            }

                                            if (question.ZoneCut is not null)
                                            {
                                                if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    if (question.Type == question.MinimizedType)
                                                    {
                                                    }
                                                    else
                                                    {
                                                        question.ZoneCut = null;
                                                        nameServerIndex = currentNameServerIndex - 1;
                                                        continue;
                                                    }
                                                }
                                                else
                                                {
                                                    question.ZoneCut = question.MinimizedName;
                                                    nameServerIndex = currentNameServerIndex - 1;
                                                    continue;
                                                }
                                            }

                                            if (resolverStack.Count == 0)
                                            {
                                                TriggerNsResolution();

                                                if (extendedDnsErrors.Count > 0)
                                                    response.AddDnsClientExtendedErrors(extendedDnsErrors);

                                                if (minimalResponse)
                                                    return GetMinimalResponseWithoutNSAndGlue(response);

                                                return response;
                                            }
                                            else
                                            {
                                                DnsQuestionRecord lastQuestion = request.Question[0];
                                                PopStack();

                                                switch (lastQuestion.Type)
                                                {
                                                    case DnsResourceRecordType.A:
                                                    case DnsResourceRecordType.AAAA:
                                                        nameServerIndex++;
                                                        extendedDnsErrors.Add(new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Failed to resolve name server " + lastQuestion.Name.ToLowerInvariant() + " at delegation " + zoneCut + "."));
                                                        break;

                                                    case DnsResourceRecordType.DS:
                                                        dnssecValidationState = false;
                                                        lastDSRecords = null;
                                                        break;
                                                }

                                                goto resolverLoop;
                                            }
                                        }
                                        else
                                        {
                                            bool continueNextNameServer = false;

                                            foreach (DnsResourceRecord authorityRecord in response.Authority)
                                            {
                                                if ((authorityRecord.Type == DnsResourceRecordType.NS) && authorityRecord.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase))
                                                {
                                                    if (resolverStack.Count == 0)
                                                    {
                                                        continueNextNameServer = true;
                                                        break;
                                                    }
                                                    else
                                                    {
                                                        PopStack();
                                                        nameServerIndex++;

                                                        goto resolverLoop;
                                                    }
                                                }
                                            }

                                            if (continueNextNameServer)
                                                break;

                                            if (hopCount >= MAX_DELEGATION_HOPS)
                                            {
                                                if (resolverStack.Count == 0)
                                                {
                                                    if (extendedDnsErrors.Count > 0)
                                                        response.AddDnsClientExtendedErrors(extendedDnsErrors);

                                                    if (minimalResponse)
                                                        return GetMinimalResponseWithoutNSAndGlue(response);

                                                    return response;
                                                }
                                                else
                                                {
                                                    DnsQuestionRecord lastQuestion = question;
                                                    PopStack();
                                                    nameServerIndex++;
                                                    extendedDnsErrors.Add(new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Failed to resolve name server " + lastQuestion.Name.ToLowerInvariant() + " at delegation " + zoneCut + "."));

                                                    goto resolverLoop;
                                                }
                                            }

                                            List<NameServerAddress> nextNameServers = NameServerAddress.GetNameServersFromResponse(response, IPv6Reachability.GetEffectiveMode(ipv6Mode), true);

                                            if (nextNameServers.Count > 0)
                                            {
                                                string nextZoneCut = firstAuthority.Name;
                                                bool nextDnssecValidationState = dnssecValidationState;
                                                IReadOnlyList<DnsResourceRecord> nextDSRecords = lastDSRecords;

                                                if (dnssecValidationState)
                                                {
                                                    Tuple<bool, IReadOnlyList<DnsResourceRecord>> tupleDsRecords = await TryGetDSFromResponseAsync(response, nextZoneCut, context);
                                                    if (tupleDsRecords.Item1)
                                                    {
                                                        IReadOnlyList<DnsResourceRecord> dsRecords = tupleDsRecords.Item2;

                                                        extendedDnsErrors.AddRange(response.DnsClientExtendedErrors);

                                                        if (dsRecords is null)
                                                        {
                                                            nextDnssecValidationState = false;
                                                            nextDSRecords = null;
                                                        }
                                                        else if (dsRecords.Count > 0)
                                                        {
                                                            nextDSRecords = dsRecords;
                                                        }
                                                    }
                                                }

                                                nextNameServers = await ResolveNameServerAddressesFromCacheAsync(nextNameServers);
                                                nextNameServers.Shuffle();

                                                bool prioritizeOnesWithIPAddress = asyncNsResolution || (resolverStack.Count > 0);

                                                if (question.ZoneCut is not null)
                                                    question.ZoneCut = nextZoneCut;

                                                zoneCut = nextZoneCut;
                                                dnssecValidationState = nextDnssecValidationState;
                                                lastDSRecords = nextDSRecords;
                                                nameServers = GetOrderedNameServersToPreferPerformance(nextNameServers, prioritizeOnesWithIPAddress, IPv6Reachability.GetEffectiveMode(ipv6Mode));
                                                nameServerIndex = 0;
                                                hopCount++;
                                                lastResponse = null;

                                                if (asyncNsResolution)
                                                {
                                                    int maxNsResolutions = Math.Min(nextNameServers.Count, MAX_ASYNC_NS_RESOLUTIONS_PER_REFERRAL);

                                                    foreach (NameServerAddress nextNameServer in nextNameServers)
                                                    {
                                                        if (nextNameServer.IPEndPoint is null)
                                                        {
                                                            if (asyncNsResolutionTasks.Add(nextNameServer.DomainEndPoint.Address.ToLowerInvariant()))
                                                            {
                                                                maxNsResolutions--;

                                                                if (maxNsResolutions < 1)
                                                                    break;
                                                            }
                                                        }
                                                    }
                                                }

                                                goto resolverLoop;
                                            }

                                            break;
                                        }
                                    }
                                    else
                                    {
                                        if (question.ZoneCut is not null)
                                        {
                                            if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
                                            {
                                                if (question.Type == question.MinimizedType)
                                                {
                                                }
                                                else
                                                {
                                                    question.ZoneCut = null;
                                                    nameServerIndex = currentNameServerIndex - 1;
                                                    continue;
                                                }
                                            }
                                            else
                                            {
                                                question.ZoneCut = question.MinimizedName;
                                                nameServerIndex = currentNameServerIndex - 1;
                                                continue;
                                            }
                                        }

                                        break;
                                    }
                                }

                            case DnsResponseCode.NxDomain:
                                {
                                    if (question.ZoneCut is not null)
                                    {
                                        if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase) && (question.Type == question.MinimizedType))
                                        {
                                        }
                                        else
                                        {
                                            question.ZoneCut = null;
                                            nameServerIndex = currentNameServerIndex - 1;
                                            continue;
                                        }
                                    }

                                    if (resolverStack.Count == 0)
                                    {
                                        TriggerNsResolution();

                                        if (extendedDnsErrors.Count > 0)
                                            response.AddDnsClientExtendedErrors(extendedDnsErrors);

                                        if (minimalResponse)
                                            return GetMinimalResponseWithoutNSAndGlue(response);

                                        return response;
                                    }
                                    else
                                    {
                                        DnsQuestionRecord lastQuestion = request.Question[0];
                                        PopStack();

                                        switch (lastQuestion.Type)
                                        {
                                            case DnsResourceRecordType.A:
                                            case DnsResourceRecordType.AAAA:
                                                nameServerIndex++;
                                                extendedDnsErrors.Add(new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Failed to resolve name server " + lastQuestion.Name.ToLowerInvariant() + " at delegation " + zoneCut + "."));
                                                break;

                                            case DnsResourceRecordType.DS:
                                                dnssecValidationState = false;
                                                lastDSRecords = null;
                                                break;
                                        }

                                        goto resolverLoop;
                                    }
                                }

                            default:
                                {
                                    if (question.ZoneCut is not null)
                                    {
                                        if (question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase))
                                        {
                                            if (question.Type == question.MinimizedType)
                                            {
                                            }
                                            else
                                            {
                                                question.ZoneCut = null;
                                                nameServerIndex = currentNameServerIndex - 1;
                                                continue;
                                            }
                                        }
                                        else
                                        {
                                            question.ZoneCut = question.MinimizedName;
                                            nameServerIndex = currentNameServerIndex - 1;
                                            continue;
                                        }
                                    }

                                    break;
                                }
                        }
                    }

                    if ((question.ZoneCut is not null) && ((lastException is DnsClientNoResponseException) || (lastException is SocketException) || (lastException is IOException)) && context.CanProceedWithResolution() && !(question.Name.Equals(question.MinimizedName, StringComparison.OrdinalIgnoreCase) && (question.Type == question.MinimizedType)))
                    {
                        question.ZoneCut = null;
                        nameServerIndex = 0;
                        lastException = null;
                        continue;
                    }

                    if (resolverStack.Count == 0)
                    {
                        if (lastResponse is not null)
                        {
                            if ((lastResponse.Question.Count > 0) && lastResponse.Question[0].Equals(question))
                            {
                                if (extendedDnsErrors.Count > 0)
                                    lastResponse.AddDnsClientExtendedErrors(extendedDnsErrors);

                                if (minimalResponse)
                                    return GetMinimalResponseWithoutNSAndGlue(lastResponse);

                                return lastResponse;
                            }
                        }

                        if (lastException is null)
                        {
                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                            if (extendedDnsErrors.Count > 0)
                                failureResponse.AddDnsClientExtendedErrors(extendedDnsErrors);

                            if (!context.CanProceedWithResolution())
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.ResolverLimitReached, "Resolver limit reached (" + context.GetCannotProceedWithResolutionReason() + ") for " + question.ToString());

                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "No valid response from name servers for " + question.ToString() + " at delegation " + zoneCut + ".");

                            if (eDnsClientSubnet is not null)
                                failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                            cache.CacheResponse(failureResponse);
                        }
                        else if (lastException is DnsClientResponseDnssecValidationException ex)
                        {
                            if (extendedDnsErrors.Count > 0)
                                ex.Response.AddDnsClientExtendedErrors(extendedDnsErrors);

                            cache.CacheResponse(ex.Response, true);

                            if ((ex.Response.Question.Count == 0) || !ex.Response.Question[0].Equals(question))
                            {
                                DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, [question]);

                                failureResponse.AddDnsClientExtendedErrorsFrom(ex.Response);

                                if (!context.CanProceedWithResolution())
                                    failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.ResolverLimitReached, "Resolver limit reached (" + context.GetCannotProceedWithResolutionReason() + ") for " + question.ToString());

                                if (eDnsClientSubnet is not null)
                                    failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                                cache.CacheResponse(failureResponse);
                            }

                            ExceptionDispatchInfo.Throw(lastException);
                        }
                        else if (lastException is DnsClientNoResponseException)
                        {
                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                            if (extendedDnsErrors.Count > 0)
                                failureResponse.AddDnsClientExtendedErrors(extendedDnsErrors);

                            if (!context.CanProceedWithResolution())
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.ResolverLimitReached, "Resolver limit reached (" + context.GetCannotProceedWithResolutionReason() + ") for " + question.ToString());

                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "No valid response from name servers for " + question.ToString() + " at delegation " + zoneCut + ".");

                            if (eDnsClientSubnet is not null)
                                failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                            cache.CacheResponse(failureResponse);
                        }
                        else if (lastException is SocketException ex2)
                        {
                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                            if (extendedDnsErrors.Count > 0)
                                failureResponse.AddDnsClientExtendedErrors(extendedDnsErrors);

                            if (!context.CanProceedWithResolution())
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.ResolverLimitReached, "Resolver limit reached (" + context.GetCannotProceedWithResolutionReason() + ") for " + question.ToString());

                            if (ex2.SocketErrorCode == SocketError.TimedOut)
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Request timed out for " + question.ToString() + " at delegation " + zoneCut + ".");
                            else
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "Socket error for " + question.ToString() + ": " + ex2.SocketErrorCode.ToString());

                            if (eDnsClientSubnet is not null)
                                failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                            cache.CacheResponse(failureResponse);
                        }
                        else if (lastException is IOException ex3)
                        {
                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                            if (extendedDnsErrors.Count > 0)
                                failureResponse.AddDnsClientExtendedErrors(extendedDnsErrors);

                            if (!context.CanProceedWithResolution())
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.ResolverLimitReached, "Resolver limit reached (" + context.GetCannotProceedWithResolutionReason() + ") for " + question.ToString());

                            if (ex3.InnerException is SocketException ex3a)
                            {
                                if (ex3a.SocketErrorCode == SocketError.TimedOut)
                                    failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Request timed out for " + question.ToString() + " at delegation " + zoneCut + ".");
                                else
                                    failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "Socket error for " + question.ToString() + ": " + ex3a.SocketErrorCode.ToString());
                            }
                            else
                            {
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "IO error for " + question.ToString() + ": " + ex3.Message);
                            }

                            if (eDnsClientSubnet is not null)
                                failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                            cache.CacheResponse(failureResponse);
                        }
                        else
                        {
                            DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                            if (extendedDnsErrors.Count > 0)
                                failureResponse.AddDnsClientExtendedErrors(extendedDnsErrors);

                            if (!context.CanProceedWithResolution())
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.ResolverLimitReached, "Resolver limit reached (" + context.GetCannotProceedWithResolutionReason() + ") for " + question.ToString());

                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.Other, "Resolver exception for " + question.ToString() + ": " + lastException.Message);

                            if (eDnsClientSubnet is not null)
                                failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                            cache.CacheResponse(failureResponse);
                        }

                        if (!context.CanProceedWithResolution())
                            throw new DnsClientNoResponseException("DnsClient failed to recursively resolve the request '" + question.ToString() + "': Resolver limit reached (" + context.GetCannotProceedWithResolutionReason() + ") for name servers [" + nameServers.Join() + "] at delegation " + zoneCut + ".", lastException);

                        throw new DnsClientNoResponseException("DnsClient failed to recursively resolve the request '" + question.ToString() + "': no valid response from name servers [" + nameServers.Join() + "] at delegation " + zoneCut + ".", lastException);
                    }
                    else
                    {
                        DnsQuestionRecord lastQuestion = question;
                        PopStack();

                        switch (lastQuestion.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                nameServerIndex++;
                                extendedDnsErrors.Add(new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Failed to resolve name server " + lastQuestion.Name.ToLowerInvariant() + " at delegation " + zoneCut + "."));
                                break;

                            case DnsResourceRecordType.DS:

                                DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { question });

                                if (extendedDnsErrors.Count > 0)
                                    failureResponse.AddDnsClientExtendedErrors(extendedDnsErrors);

                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DnssecIndeterminate, "Attack detected! Unable to resolve DS for " + lastQuestion.Name.ToLowerInvariant());

                                if (eDnsClientSubnet is not null)
                                    failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(eDnsClientSubnet.PrefixLength, eDnsClientSubnet.PrefixLength, eDnsClientSubnet.Address));

                                cache.CacheResponse(failureResponse);

                                throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to unable to find DS records for owner name: " + lastQuestion.Name.ToLowerInvariant(), lastResponse is null ? failureResponse : lastResponse);
                        }
                    }

                resolverLoop:;
                }

            stackLoop:;
            }
        }

        public static Task<DnsDatagram> RecursiveResolveQueryAsync(DnsQuestionRecord question, IDnsCache cache = null, NetProxy proxy = null, IPv6Mode ipv6Mode = IPv6Mode.Disabled, ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, bool randomizeName = false, bool qnameMinimization = false, bool dnssecValidation = false, NetworkAddress eDnsClientSubnet = null, int retries = 2, int timeout = 2000, int concurrency = 2, int maxStackCount = 16, CancellationToken cancellationToken = default)
        {
            if (cache is null)
                cache = new DnsCache();

            ResolverContext context = new ResolverContext();

            return ResolveQueryAsync(question, delegate (DnsQuestionRecord q)
            {
                return RecursiveResolveAsync(q, cache, proxy, ipv6Mode, udpPayloadSize, randomizeName, qnameMinimization, dnssecValidation, eDnsClientSubnet, retries, timeout, concurrency, maxStackCount, true, context: context, cancellationToken: cancellationToken);
            });
        }

        public static async Task<IReadOnlyList<IPAddress>> RecursiveResolveIPAsync(string domain, IDnsCache cache = null, NetProxy proxy = null, IPv6Mode ipv6Mode = IPv6Mode.Disabled, ushort udpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, bool randomizeName = false, bool qnameMinimization = false, bool dnssecValidation = false, NetworkAddress eDnsClientSubnet = null, int retries = 2, int timeout = 2000, int concurrency = 2, int maxStackCount = 16, CancellationToken cancellationToken = default)
        {
            if (cache is null)
                cache = new DnsCache();

            Task<DnsDatagram> ipv6Task = ipv6Mode != IPv6Mode.Disabled ? RecursiveResolveQueryAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN), cache, proxy, ipv6Mode, udpPayloadSize, randomizeName, qnameMinimization, dnssecValidation, eDnsClientSubnet, retries, timeout, concurrency, maxStackCount, cancellationToken) : null;
            Task<DnsDatagram> ipv4Task = RecursiveResolveQueryAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN), cache, proxy, ipv6Mode, udpPayloadSize, randomizeName, qnameMinimization, dnssecValidation, eDnsClientSubnet, retries, timeout, concurrency, maxStackCount, cancellationToken);

            IReadOnlyList<IPAddress> ipv6Addresses = ipv6Mode != IPv6Mode.Disabled ? ParseResponseAAAA(await ipv6Task) : null;
            IReadOnlyList<IPAddress> ipv4Addresses = ParseResponseA(await ipv4Task);

            List<IPAddress> ipAddresses = new List<IPAddress>((ipv6Addresses is null ? 0 : ipv6Addresses.Count) + ipv4Addresses.Count);

            if (ipv6Mode != IPv6Mode.Disabled)
                ipAddresses.AddRange(ipv6Addresses);

            ipAddresses.AddRange(ipv4Addresses);

            return ipAddresses;
        }

        public static async Task<IReadOnlyList<IPAddress>> ResolveIPAsync(IDnsClient dnsClient, string domain, IPv6Mode ipv6Mode = IPv6Mode.Disabled, CancellationToken cancellationToken = default)
        {
            Task<DnsDatagram> ipv6Task = ipv6Mode != IPv6Mode.Disabled ? dnsClient.ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.AAAA, DnsClass.IN), cancellationToken) : null;
            Task<DnsDatagram> ipv4Task = dnsClient.ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.A, DnsClass.IN), cancellationToken);

            IReadOnlyList<IPAddress> ipv6Addresses = ipv6Mode != IPv6Mode.Disabled ? ParseResponseAAAA(await ipv6Task) : null;
            IReadOnlyList<IPAddress> ipv4Addresses = ParseResponseA(await ipv4Task);

            List<IPAddress> ipAddresses = new List<IPAddress>((ipv6Addresses is null ? 0 : ipv6Addresses.Count) + ipv4Addresses.Count);

            if (ipv6Mode != IPv6Mode.Disabled)
                ipAddresses.AddRange(ipv6Addresses);

            ipAddresses.AddRange(ipv4Addresses);

            return ipAddresses;
        }

        public static async Task<IReadOnlyList<string>> ResolveMXAsync(IDnsClient dnsClient, string domain, bool resolveIP = false, IPv6Mode ipv6Mode = IPv6Mode.Disabled, CancellationToken cancellationToken = default)
        {
            if (IPAddress.TryParse(domain, out _))
            {
                return new string[] { domain };
            }

            DnsDatagram response = await dnsClient.ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.MX, DnsClass.IN), cancellationToken);
            IReadOnlyList<string> mxEntries = ParseResponseMX(response);

            if (!resolveIP)
                return mxEntries;

            List<string> mxAddresses = new List<string>(ipv6Mode != IPv6Mode.Disabled ? mxEntries.Count * 2 : mxEntries.Count);

            foreach (string mxEntry in mxEntries)
            {
                bool glueRecordFound = false;

                foreach (DnsResourceRecord record in response.Additional)
                {
                    switch (record.DnssecStatus)
                    {
                        case DnssecStatus.Disabled:
                        case DnssecStatus.Secure:
                        case DnssecStatus.Insecure:
                            break;

                        default:
                            continue;
                    }

                    if (record.Name.Equals(mxEntry, StringComparison.OrdinalIgnoreCase))
                    {
                        switch (record.Type)
                        {
                            case DnsResourceRecordType.A:
                                mxAddresses.Add((record.RDATA as DnsARecordData).Address.ToString());
                                glueRecordFound = true;
                                break;

                            case DnsResourceRecordType.AAAA:
                                if (ipv6Mode != IPv6Mode.Disabled)
                                {
                                    mxAddresses.Add((record.RDATA as DnsAAAARecordData).Address.ToString());
                                    glueRecordFound = true;
                                }
                                break;
                        }
                    }
                }

                if (!glueRecordFound)
                {
                    try
                    {
                        IReadOnlyList<IPAddress> ipList = await ResolveIPAsync(dnsClient, mxEntry, ipv6Mode, cancellationToken);

                        foreach (IPAddress ip in ipList)
                            mxAddresses.Add(ip.ToString());
                    }
                    catch (DnsClientException)
                    { }
                }
            }

            return mxAddresses;
        }

        public static IReadOnlyList<IPAddress> ParseResponseA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<IPAddress>();

                    List<IPAddress> ipAddresses = new List<IPAddress>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.A:
                                    ipAddresses.Add((record.RDATA as DnsARecordData).Address);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return ipAddresses;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<IPAddress> ParseResponseAAAA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<IPAddress>();

                    List<IPAddress> ipAddresses = new List<IPAddress>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.AAAA:
                                    ipAddresses.Add((record.RDATA as DnsAAAARecordData).Address);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return ipAddresses;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<string> ParseResponseTXT(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<string>();

                    List<string> txtRecords = new List<string>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.TXT:
                                    txtRecords.Add((record.RDATA as DnsTXTRecordData).GetText());
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return txtRecords;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<string> ParseResponsePTR(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<string>();

                    List<string> values = new List<string>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.PTR:
                                    values.Add((record.RDATA as DnsPTRRecordData).Domain);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return values;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<string> ParseResponseMX(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<string>();

                    List<DnsMXRecordData> mxRecords = new List<DnsMXRecordData>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.MX:
                                    mxRecords.Add(record.RDATA as DnsMXRecordData);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    if (mxRecords.Count > 0)
                    {
                        mxRecords.Sort();

                        string[] mxEntries = new string[mxRecords.Count];

                        for (int i = 0; i < mxEntries.Length; i++)
                            mxEntries[i] = mxRecords[i].Exchange;

                        return mxEntries;
                    }

                    return Array.Empty<string>();

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<DnsDSRecordData> ParseResponseDS(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<DnsDSRecordData>();

                    List<DnsDSRecordData> dsRecords = new List<DnsDSRecordData>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.DS:
                                    dsRecords.Add(record.RDATA as DnsDSRecordData);
                                    break;
                            }
                        }
                    }

                    return dsRecords;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<DnsTLSARecordData> ParseResponseTLSA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return Array.Empty<DnsTLSARecordData>();

                    List<DnsTLSARecordData> tlsaRecords = new List<DnsTLSARecordData>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.DnssecStatus != DnssecStatus.Secure)
                            continue;

                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.TLSA:
                                    DnsTLSARecordData tlsa = record.RDATA as DnsTLSARecordData;

                                    switch (tlsa.CertificateUsage)
                                    {
                                        case DnsTLSACertificateUsage.PKIX_TA:
                                        case DnsTLSACertificateUsage.PKIX_EE:
                                        case DnsTLSACertificateUsage.DANE_TA:
                                        case DnsTLSACertificateUsage.DANE_EE:
                                            break;

                                        default:
                                            continue;
                                    }

                                    switch (tlsa.Selector)
                                    {
                                        case DnsTLSASelector.Cert:
                                        case DnsTLSASelector.SPKI:
                                            break;

                                        default:
                                            continue;
                                    }

                                    switch (tlsa.MatchingType)
                                    {
                                        case DnsTLSAMatchingType.Full:
                                        case DnsTLSAMatchingType.SHA2_256:
                                        case DnsTLSAMatchingType.SHA2_512:
                                            break;

                                        default:
                                            continue;
                                    }

                                    if (tlsa.CertificateAssociationData.Length == 0)
                                        continue;

                                    tlsaRecords.Add(tlsa);
                                    break;

                                case DnsResourceRecordType.CNAME:
                                    domain = (record.RDATA as DnsCNAMERecordData).Domain;
                                    break;
                            }
                        }
                    }

                    return tlsaRecords;

                case DnsResponseCode.NxDomain:
                    return null;

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<DnsZONEMDRecordData> ParseResponseZONEMD(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return [];

                    List<DnsZONEMDRecordData> zonemdRecords = new List<DnsZONEMDRecordData>(response.Answer.Count);

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.ZONEMD:
                                    zonemdRecords.Add(record.RDATA as DnsZONEMDRecordData);
                                    break;
                            }
                        }
                    }

                    return zonemdRecords;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static DnsSOARecordData ParseResponseSOA(DnsDatagram response)
        {
            string domain = response.Question[0].Name;

            switch (response.RCODE)
            {
                case DnsResponseCode.NoError:
                    if (response.Answer.Count == 0)
                        return null;

                    foreach (DnsResourceRecord record in response.Answer)
                    {
                        if (record.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (record.Type)
                            {
                                case DnsResourceRecordType.SOA:
                                    return record.RDATA as DnsSOARecordData;
                            }
                        }
                    }

                    return null;

                case DnsResponseCode.NxDomain:
                    throw new DnsClientNxDomainException("Domain does not exists: " + domain.ToLowerInvariant() + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : "; Name server: " + response.Metadata.NameServer.ToString()));

                default:
                    throw new DnsClientFailureResponseException("DnsClient failed to resolve the request '" + response.Question[0].ToString() + "'. Received a response with RCODE: " + response.RCODE + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "" : " from Name server: " + response.Metadata.NameServer.ToString()), response);
            }
        }

        public static IReadOnlyList<IPAddress> GetSystemDnsServers(IPv6Mode ipv6Mode = IPv6Mode.Disabled)
        {
            List<IPAddress> dnsAddresses = new List<IPAddress>();

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;

                foreach (IPAddress dnsAddress in nic.GetIPProperties().DnsAddresses)
                {
                    if ((ipv6Mode == IPv6Mode.Disabled) && (dnsAddress.AddressFamily == AddressFamily.InterNetworkV6))
                        continue;

                    if ((dnsAddress.AddressFamily == AddressFamily.InterNetworkV6) && dnsAddress.IsIPv6SiteLocal)
                        continue;

                    if (!dnsAddresses.Contains(dnsAddress))
                        dnsAddresses.Add(dnsAddress);
                }
            }

            return dnsAddresses;
        }

        public static bool IsDomainNameValid(string domain, bool throwException = false)
        {
            if (domain is null)
            {
                if (throwException)
                    throw new ArgumentNullException(nameof(domain));

                return false;
            }

            if (domain.Length == 0)
                return true;

            if (domain.Length > 255)
            {
                if (throwException)
                    throw new DnsClientException("Invalid domain name [" + domain + "]: length cannot exceed 255 bytes.");

                return false;
            }

            int labelStart = 0;
            int labelEnd;
            int labelLength;
            int labelChar;
            int i;

            do
            {
                labelEnd = domain.IndexOf('.', labelStart);
                if (labelEnd < 0)
                    labelEnd = domain.Length;

                labelLength = labelEnd - labelStart;

                if (labelLength == 0)
                {
                    if (throwException)
                        throw new DnsClientException("Invalid domain name [" + domain + "]: label length cannot be 0 byte.");

                    return false;
                }

                if (labelLength > 63)
                {
                    if (throwException)
                        throw new DnsClientException("Invalid domain name [" + domain + "]: label length cannot exceed 63 bytes.");

                    return false;
                }

                if (labelLength != 1 || domain[labelStart] != '*')
                {
                    for (i = labelStart; i < labelEnd; i++)
                    {
                        labelChar = domain[i];

                        if ((labelChar >= 97) && (labelChar <= 122))
                            continue;

                        if ((labelChar >= 65) && (labelChar <= 90))
                            continue;

                        if ((labelChar >= 48) && (labelChar <= 57))
                            continue;

                        if (labelChar == 45)
                            continue;

                        if (labelChar == 95)
                            continue;

                        if (labelChar == 47)
                            continue;

                        if (throwException)
                            throw new DnsClientException("Invalid domain name [" + domain + "]: invalid character [" + labelChar + "] was found.");

                        return false;
                    }
                }

                labelStart = labelEnd + 1;
            }
            while (labelEnd < domain.Length);

            return true;
        }

        public static bool IsDomainNameUnicode(string domain)
        {
            foreach (char c in domain)
            {
                if (!char.IsAscii(c))
                    return true;
            }

            return false;
        }

        public static string ConvertDomainNameToAscii(string domain)
        {
            return _idnMapping.GetAscii(domain);
        }

        public static string ConvertDomainNameToUnicode(string domain)
        {
            return _idnMapping.GetUnicode(domain);
        }

        public static bool TryConvertDomainNameToUnicode(string domain, out string idn)
        {
            if (domain.Contains("xn--", StringComparison.OrdinalIgnoreCase))
            {
                try
                {
                    idn = _idnMapping.GetUnicode(domain);
                    return true;
                }
                catch
                { }
            }

            idn = null;
            return false;
        }

        #endregion

        #region private

        private static int CompareNameServersToPreferIPv6(NameServerAddress x, NameServerAddress y)
        {
            if ((x.IPEndPoint is null) || (y.IPEndPoint is null))
                return 0;

            if ((x.IPEndPoint.AddressFamily == AddressFamily.InterNetwork) && (y.IPEndPoint.AddressFamily == AddressFamily.InterNetworkV6))
                return 1;

            if ((x.IPEndPoint.AddressFamily == AddressFamily.InterNetworkV6) && (y.IPEndPoint.AddressFamily == AddressFamily.InterNetwork))
                return -1;

            return 0;
        }

        private static List<NameServerAddress> GetOrderedNameServersToPreferPerformance(IReadOnlyCollection<NameServerAddress> nameServers, bool prioritizeOnesWithIPAddress, IPv6Mode ipv6Mode)
        {
            List<NameServerAddress> nameServersList = [.. nameServers];

            const int EPSILON = 5;
            bool exploit = RandomNumberGenerator.GetInt32(100) >= EPSILON;

            nameServersList.Shuffle();

            int count = nameServersList.Count;
            if (count < 2)
                return nameServersList;

            NameServerAddress[] items = nameServersList.ToArray();
            NameServerSortKey[] keys = new NameServerSortKey[count];

            for (int i = 0; i < count; i++)
            {
                NameServerAddress nameServer = items[i];
                NameServerMetadata metadata = nameServer.Metadata;
                IPEndPoint ipEndPoint = nameServer.IPEndPoint;

                int health;

                if (metadata.IsMisconfigured)
                    health = 2;
                else if (exploit && metadata.IsUnhealthy)
                    health = 1;
                else if ((ipEndPoint is not null) && (ipEndPoint.AddressFamily == AddressFamily.InterNetworkV6) && (IPv6Reachability.IsUnavailable || IPv6Reachability.IsUnconfirmed))
                    health = 1;
                else
                    health = 0;

                keys[i] = new NameServerSortKey(
                    prioritizeOnesWithIPAddress && (ipEndPoint is null) ? 1 : 0,
                    health,
                    (ipv6Mode == IPv6Mode.Preferred) && (ipEndPoint is not null) && (ipEndPoint.AddressFamily == AddressFamily.InterNetwork) ? 1 : 0,
                    exploit ? metadata.GetNetRTT() : 0,
                    i);
            }

            Array.Sort(keys, items);

            nameServersList.Clear();
            nameServersList.AddRange(items);

            return nameServersList;
        }

        private readonly struct NameServerSortKey : IComparable<NameServerSortKey>
        {
            readonly int _noIPAddress;
            readonly int _health;
            readonly int _addressFamily;
            readonly double _netRtt;
            readonly int _index;

            public NameServerSortKey(int noIPAddress, int health, int addressFamily, double netRtt, int index)
            {
                _noIPAddress = noIPAddress;
                _health = health;
                _addressFamily = addressFamily;
                _netRtt = netRtt;
                _index = index;
            }

            public int CompareTo(NameServerSortKey other)
            {
                int result = _noIPAddress.CompareTo(other._noIPAddress);
                if (result != 0)
                    return result;

                result = _health.CompareTo(other._health);
                if (result != 0)
                    return result;

                result = _addressFamily.CompareTo(other._addressFamily);
                if (result != 0)
                    return result;

                result = _netRtt.CompareTo(other._netRtt);
                if (result != 0)
                    return result;

                return _index.CompareTo(other._index);
            }
        }

        private static async Task<List<NameServerAddress>> GetRootServersUsingRootHintsAsync(IDnsCache cache, NetProxy proxy, IPv6Mode ipv6Mode, ushort udpPayloadSize, bool dnssecValidation, int retries, int timeout, int concurrency, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<NameServerAddress> rootHints;

            switch (ipv6Mode)
            {
                case IPv6Mode.Enabled:
                    {
                        List<NameServerAddress> ipv4Hints = [.. IPv4_ROOT_HINTS];
                        List<NameServerAddress> ipv6Hints = [.. IPv6_ROOT_HINTS];

                        ipv4Hints.Shuffle();
                        ipv6Hints.Shuffle();

                        rootHints = DeprioritizeUnconfirmedIPv6(ipv6Hints.Interleave(ipv4Hints));
                    }
                    break;

                case IPv6Mode.Preferred:
                    {
                        List<NameServerAddress> nameServersList = [.. IPv6_ROOT_HINTS, .. IPv4_ROOT_HINTS];
                        nameServersList.Shuffle();
                        nameServersList.Sort(CompareNameServersToPreferIPv6);

                        rootHints = DeprioritizeUnconfirmedIPv6(nameServersList);
                    }
                    break;

                default:
                    {
                        List<NameServerAddress> ipv4Hints = [.. IPv4_ROOT_HINTS];
                        ipv4Hints.Shuffle();

                        rootHints = ipv4Hints;
                    }
                    break;
            }

            DnsClient dnsClient = new DnsClient(rootHints);

            dnsClient._cache = cache;
            dnsClient._proxy = proxy;
            dnsClient._ipv6Mode = ipv6Mode;
            dnsClient._udpPayloadSize = udpPayloadSize;
            dnsClient._dnssecValidation = dnssecValidation;
            dnsClient._retries = retries;
            dnsClient._timeout = timeout;
            dnsClient._concurrency = concurrency;

            DnsQuestionRecord question = new DnsQuestionRecord("", DnsResourceRecordType.NS, DnsClass.IN);
            DnsDatagram response;

            try
            {
                if (dnssecValidation)
                    response = await dnsClient.InternalDnssecResolveAsync(question, cancellationToken);
                else
                    response = await dnsClient.InternalNoDnssecResolveAsync(new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [question], udpPayloadSize: udpPayloadSize), cancellationToken);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (DnsClientResponseDnssecValidationException)
            {
                throw;
            }
            catch
            {
                return [.. rootHints];
            }

            if ((response.RCODE != DnsResponseCode.NoError) || (response.Answer.Count == 0))
                return [.. rootHints];

            List<NameServerAddress> rootServers = NameServerAddress.GetNameServersFromResponse(response, ipv6Mode, true);

            bool rootServersHaveAddresses = false;

            foreach (NameServerAddress rootServer in rootServers)
            {
                if (rootServer.IPEndPoint is not null)
                {
                    rootServersHaveAddresses = true;
                    break;
                }
            }

            if (!rootServersHaveAddresses)
                return [.. rootHints];

            cache.CacheResponse(response);

            rootServers.Shuffle();

            return DeprioritizeUnconfirmedIPv6(rootServers);
        }

        private static List<NameServerAddress> DeprioritizeUnconfirmedIPv6(IEnumerable<NameServerAddress> nameServers)
        {
            List<NameServerAddress> result = [.. nameServers];

            if (!IPv6Reachability.IsUnavailable && !IPv6Reachability.IsUnconfirmed)
                return result;

            List<NameServerAddress> ipv6 = new List<NameServerAddress>(result.Count);
            int j = 0;

            for (int i = 0; i < result.Count; i++)
            {
                NameServerAddress nameServer = result[i];
                IPEndPoint ep = nameServer.IPEndPoint;

                if ((ep is not null) && (ep.AddressFamily == AddressFamily.InterNetworkV6))
                    ipv6.Add(nameServer);
                else
                    result[j++] = nameServer;
            }

            for (int i = 0; i < ipv6.Count; i++)
                result[j++] = ipv6[i];

            return result;
        }

        private static async Task DnssecValidateResponseAsync(DnsDatagram response, IReadOnlyList<DnsResourceRecord> lastDSRecords, DnsClient dnsClient, IDnsCache cache, ushort udpPayloadSize, ResolverContext context, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<DnsResourceRecord> currentDnsKeyRecords = await GetDnsKeyForAsync(lastDSRecords, dnsClient, cache, udpPayloadSize, context, cancellationToken);

            string lastDSOwnerName = lastDSRecords[0].Name;
            DnsClass @class = response.Question[0].Class;
            List<DnsResourceRecord> allDnsKeyRecords = new List<DnsResourceRecord>(4);
            List<string> unsignedZones = null;

            allDnsKeyRecords.AddRange(currentDnsKeyRecords);

            IReadOnlyCollection<string> signersNames = FindSignersNames(response);

            foreach (string signersName in signersNames)
            {
                if (signersName.Equals(lastDSOwnerName, StringComparison.OrdinalIgnoreCase))
                    continue;

                IReadOnlyList<DnsResourceRecord> dnsKeyRecords;

                if (signersName.EndsWith("." + lastDSOwnerName, StringComparison.OrdinalIgnoreCase) || (lastDSOwnerName.Length == 0))
                {
                    dnsKeyRecords = await FindDnsKeyForAsync(signersName, @class, currentDnsKeyRecords, dnsClient, cache, udpPayloadSize, response, context, cancellationToken);
                }
                else
                {
                    IReadOnlyList<DnsResourceRecord> rootDnsKeyRecords = await GetDnsKeyForAsync(ROOT_TRUST_ANCHORS, dnsClient, cache, udpPayloadSize, context, cancellationToken);

                    if (signersName.Length == 0)
                        dnsKeyRecords = rootDnsKeyRecords;
                    else
                        dnsKeyRecords = await FindDnsKeyForAsync(signersName, @class, rootDnsKeyRecords, dnsClient, cache, udpPayloadSize, response, context, cancellationToken);
                }

                if (dnsKeyRecords is null)
                {
                    if (unsignedZones is null)
                        unsignedZones = new List<string>(2);

                    unsignedZones.Add(signersName);
                }
                else
                {
                    allDnsKeyRecords.AddRange(dnsKeyRecords);
                }
            }

            try
            {
                await DnssecValidateSignatureAsync(response, allDnsKeyRecords, unsignedZones, context);

                switch (response.RCODE)
                {
                    case DnsResponseCode.NoError:
                        if (response.Answer.Count > 0)
                        {
                            foreach (DnsResourceRecord rrsigRecord in response.Answer)
                            {
                                if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                                    continue;

                                if (DnsRRSIGRecordData.IsWildcard(rrsigRecord, out string nextCloserName))
                                {
                                    DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;
                                    DnsResourceRecordType typeCovered = rrsig.TypeCovered;
                                    DnssecProofOfNonExistence proofOfNonExistence = await GetValidatedProofOfNonExistenceAsync(response, rrsigRecord.Name, typeCovered, context, true, nextCloserName, rrsig.SignersName);
                                    switch (proofOfNonExistence)
                                    {
                                        case DnssecProofOfNonExistence.OptOut:
                                        case DnssecProofOfNonExistence.NxDomain:
                                        case DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue:
                                            break;

                                        case DnssecProofOfNonExistence.TooManyNsec3HashOperations:
                                            response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.TooManyCryptoValidations, "Attack detected! Too many NSEC3 hash operations for " + rrsigRecord.Name.ToLowerInvariant() + " " + typeCovered.ToString() + " " + rrsigRecord.Class.ToString());
                                            throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to too many NSEC3 hash operations for owner name: " + rrsigRecord.Name.ToLowerInvariant() + "/" + typeCovered.ToString(), response);

                                        default:
                                            response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NSECMissing, "Attack detected! Missing non-existence proof (Wildcard) for " + rrsigRecord.Name.ToLowerInvariant() + " " + typeCovered.ToString() + " " + rrsigRecord.Class.ToString());
                                            throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed as the response was unable to prove non-existence (Wildcard) for owner name: " + rrsigRecord.Name.ToLowerInvariant() + "/" + typeCovered.ToString(), response);
                                    }
                                }
                            }
                        }

                        if (response.Authority.Count > 0)
                        {
                            DnsQuestionRecord question = response.Question[0];
                            DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();

                            switch (firstAuthority.Type)
                            {
                                case DnsResourceRecordType.SOA:
                                    {
                                        string qname = question.Name.ToLowerInvariant();

                                        if (response.Answer.Count > 0)
                                        {
                                            DnsResourceRecord lastRR = response.GetLastAnswerRecord();
                                            if ((lastRR is not null) && (lastRR.Type == DnsResourceRecordType.CNAME))
                                                qname = (lastRR.RDATA as DnsCNAMERecordData).Domain.ToLowerInvariant();
                                        }

                                        if (IsDomainUnsigned(qname, unsignedZones))
                                            break;

                                        DnssecProofOfNonExistence proofOfNonExistence = await GetValidatedProofOfNonExistenceAsync(response, qname, question.Type, context);
                                        switch (proofOfNonExistence)
                                        {
                                            case DnssecProofOfNonExistence.OptOut:
                                            case DnssecProofOfNonExistence.NoData:
                                            case DnssecProofOfNonExistence.InsecureDelegation:
                                            case DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue:
                                                break;

                                            case DnssecProofOfNonExistence.TooManyNsec3HashOperations:
                                                response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.TooManyCryptoValidations, "Attack detected! Too many NSEC3 hash operations for " + qname + ". " + question.Type.ToString() + " " + question.Class.ToString());
                                                throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to too many NSEC3 hash operations for owner name: " + qname + "/" + question.Type.ToString(), response);

                                            default:
                                                response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NSECMissing, "Attack detected! Missing non-existence proof (No Data) for " + qname + ". " + question.Type.ToString() + " " + question.Class.ToString());
                                                throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed as the response was unable to prove non-existence (No Data) for owner name: " + qname + "/" + question.Type.ToString(), response);
                                        }
                                    }
                                    break;

                                case DnsResourceRecordType.NS:
                                    {
                                        DnssecProofOfNonExistence proofOfNonExistence = await GetValidatedProofOfNonExistenceAsync(response, question.Name, DnsResourceRecordType.DS, context);
                                        switch (proofOfNonExistence)
                                        {
                                            case DnssecProofOfNonExistence.InsecureDelegation:
                                            case DnssecProofOfNonExistence.OptOut:
                                            case DnssecProofOfNonExistence.NoData:
                                            case DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue:
                                                foreach (DnsResourceRecord record in response.Authority)
                                                {
                                                    if (record.Type == DnsResourceRecordType.NS)
                                                        record.SetDnssecStatus(DnssecStatus.Insecure, true);
                                                }

                                                break;
                                        }
                                    }
                                    break;

                                default:
                                    if (response.Answer.Count == 0)
                                    {
                                        response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NSECMissing, "Attack detected! Missing non-existence proof (No Data) for " + question.ToString());
                                        throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed as the response was unable to prove non-existence (No Data) for owner name: " + question.Name.ToLowerInvariant() + "/" + question.Type.ToString(), response);
                                    }

                                    break;
                            }
                        }
                        else if (response.Answer.Count == 0)
                        {
                            DnsQuestionRecord question = response.Question[0];

                            if (IsDomainUnsigned(question.Name, unsignedZones))
                                break;

                            response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NSECMissing, "Attack detected! Missing non-existence proof (No Data) for " + question.ToString());
                            throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed as the response was unable to prove non-existence (No Data) for owner name: " + question.Name.ToLowerInvariant() + "/" + question.Type.ToString(), response);
                        }

                        break;

                    case DnsResponseCode.NxDomain:
                        {
                            DnsQuestionRecord question = response.Question[0];
                            string qname = question.Name.ToLowerInvariant();

                            if (response.Answer.Count > 0)
                            {
                                DnsResourceRecord lastRR = response.GetLastAnswerRecord();
                                if ((lastRR is not null) && (lastRR.Type == DnsResourceRecordType.CNAME))
                                    qname = (lastRR.RDATA as DnsCNAMERecordData).Domain.ToLowerInvariant();
                            }

                            if (IsDomainUnsigned(qname, unsignedZones))
                                break;

                            DnssecProofOfNonExistence proofOfNonExistence = await GetValidatedProofOfNonExistenceAsync(response, qname, question.Type, context);
                            switch (proofOfNonExistence)
                            {
                                case DnssecProofOfNonExistence.OptOut:
                                case DnssecProofOfNonExistence.NxDomain:
                                case DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue:
                                    break;

                                case DnssecProofOfNonExistence.TooManyNsec3HashOperations:
                                    response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.TooManyCryptoValidations, "Attack detected! Too many NSEC3 hash operations for " + qname);
                                    throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to too many NSEC3 hash operations for owner name: " + qname, response);

                                default:
                                    response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NSECMissing, "Attack detected! Missing non-existence proof (NX Domain) for " + qname);
                                    throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed as the response was unable to prove non-existence (NX Domain) for owner name: " + qname, response);
                            }
                        }
                        break;
                }
            }
            catch (DnsClientResponseDnssecValidationException ex)
            {
                cache.CacheResponse(ex.Response, true);
                throw;
            }
        }

        private static async Task DnssecValidateSignatureAsync(DnsDatagram response, IReadOnlyList<DnsResourceRecord> dnsKeyRecords, IReadOnlyList<string> unsignedZones, ResolverContext context)
        {
            if (!DnsDNSKEYRecordData.IsAnyDnssecAlgorithmSupported(dnsKeyRecords))
            {
                response.SetDnssecStatusForAllRecords(DnssecStatus.Insecure);
                return;
            }

            foreach (DnsResourceRecord dnsKeyRecord in dnsKeyRecords)
            {
                if (dnsKeyRecord.Type != DnsResourceRecordType.DNSKEY)
                    continue;

                if (dnsKeyRecord.DnssecStatus == DnssecStatus.Insecure)
                {
                    response.SetDnssecStatusForAllRecords(DnssecStatus.Insecure);
                    return;
                }
            }

            if (response.Answer.Count > 0)
            {
                await DnssecValidateSignatureAsync(response, response.Answer, dnsKeyRecords, unsignedZones, context, false, false);

                if (response.Question[0].Type == DnsResourceRecordType.DNSKEY)
                    dnsKeyRecords = response.Answer;
            }

            if (response.Authority.Count > 0)
                await DnssecValidateSignatureAsync(response, response.Authority, dnsKeyRecords, unsignedZones, context, true, false);

            if (response.Additional.Count > 1)
                await DnssecValidateSignatureAsync(response, response.Additional, dnsKeyRecords, unsignedZones, context, false, true);

            response.SetDnssecStatusForAllRecords(DnssecStatus.Indeterminate);
        }

        private static async Task DnssecValidateSignatureAsync(DnsDatagram response, IReadOnlyList<DnsResourceRecord> records, IReadOnlyList<DnsResourceRecord> dnsKeyRecords, IReadOnlyList<string> unsignedZones, ResolverContext context, bool isAuthoritySection, bool isAdditionalSection)
        {
            Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedRecords = DnsResourceRecord.GroupRecords(records, true);

            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedRecord in groupedRecords)
            {
                string ownerName = groupedRecord.Key;
                Dictionary<DnsResourceRecordType, List<DnsResourceRecord>> rrsets = groupedRecord.Value;

                if (IsDomainUnsigned(ownerName, unsignedZones))
                {
                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrset in rrsets)
                        foreach (DnsResourceRecord record in rrset.Value)
                            record.SetDnssecStatus(DnssecStatus.Insecure);

                    continue;
                }

                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrset in rrsets)
                {
                    DnsResourceRecordType rrsetType = rrset.Key;

                    switch (rrsetType)
                    {
                        case DnsResourceRecordType.RRSIG:
                            continue;

                        case DnsResourceRecordType.OPT:
                            foreach (DnsResourceRecord record in rrset.Value)
                                record.SetDnssecStatus(DnssecStatus.Indeterminate);

                            continue;
                    }

                    if (isAuthoritySection && (response.Answer.Count == 0) && (rrsetType == DnsResourceRecordType.NS))
                    {
                        foreach (DnsResourceRecord record in rrset.Value)
                            record.SetDnssecStatus(DnssecStatus.Indeterminate);

                        continue;
                    }

                    DnsClass rrsetClass = rrset.Value[0].Class;
                    bool foundValidSignature = false;
                    EDnsExtendedDnsErrorCode lastExtendedDnsErrorCode = EDnsExtendedDnsErrorCode.RRSIGsMissing;

                    foreach (DnsResourceRecord rrsigRecord in records)
                    {
                        if (!context.CanProceedWithResolution())
                        {
                            lastExtendedDnsErrorCode = EDnsExtendedDnsErrorCode.TooManyCryptoValidations;
                            break;
                        }

                        if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                            continue;

                        if (rrsigRecord.Name.Equals(ownerName, StringComparison.OrdinalIgnoreCase) && (rrsigRecord.Class == rrsetClass))
                        {
                            DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;

                            if ((rrsig.SignersName.Length > 0) && !ownerName.Equals(rrsig.SignersName, StringComparison.OrdinalIgnoreCase) && !ownerName.EndsWith("." + rrsig.SignersName, StringComparison.OrdinalIgnoreCase))
                                continue;

                            if (rrsig.TypeCovered != rrsetType)
                                continue;

                            if (context.MaxCryptoValidations < 1)
                            {
                                if (context.MaxCryptoSuspensions <= 1)
                                {
                                    lastExtendedDnsErrorCode = EDnsExtendedDnsErrorCode.TooManyCryptoValidations;
                                    break;
                                }

                                context.DecrementMaxCryptoSuspensions();

                                await Task.Yield();

                                context.ResetMaxCryptoValidations();
                            }

                            context.DecrementMaxCryptoValidations();

                            if (rrsig.IsSignatureValid(rrset.Value, dnsKeyRecords, context, out EDnsExtendedDnsErrorCode extendedDnsErrorCode))
                            {
                                foundValidSignature = true;

                                rrsigRecord.SetDnssecStatus(DnssecStatus.Secure);
                            }
                            else
                            {
                                lastExtendedDnsErrorCode = extendedDnsErrorCode;

                                switch (extendedDnsErrorCode)
                                {
                                    case EDnsExtendedDnsErrorCode.DnssecBogus:
                                    case EDnsExtendedDnsErrorCode.SignatureExpired:
                                    case EDnsExtendedDnsErrorCode.SignatureNotYetValid:
                                    case EDnsExtendedDnsErrorCode.RRSIGsMissing:
                                    case EDnsExtendedDnsErrorCode.NoZoneKeyBitSet:
                                    case EDnsExtendedDnsErrorCode.DNSKEYMissing:
                                    case EDnsExtendedDnsErrorCode.TooManyCryptoValidations:
                                        rrsigRecord.SetDnssecStatus(DnssecStatus.Bogus);
                                        break;

                                    case EDnsExtendedDnsErrorCode.UnsupportedDnsKeyAlgorithm:
                                        rrsigRecord.SetDnssecStatus(DnssecStatus.Insecure);
                                        break;

                                    default:
                                        rrsigRecord.SetDnssecStatus(DnssecStatus.Indeterminate);
                                        break;
                                }

                                if (extendedDnsErrorCode == EDnsExtendedDnsErrorCode.TooManyCryptoValidations)
                                    break;
                            }
                        }
                    }

                    if (foundValidSignature)
                    {
                        foreach (DnsResourceRecord record in rrset.Value)
                            record.SetDnssecStatus(DnssecStatus.Secure);
                    }
                    else if (isAuthoritySection && (rrsetType == DnsResourceRecordType.NS) && (lastExtendedDnsErrorCode == EDnsExtendedDnsErrorCode.RRSIGsMissing))
                    {
                        foreach (DnsResourceRecord record in rrset.Value)
                            record.SetDnssecStatus(DnssecStatus.Indeterminate);
                    }
                    else
                    {
                        switch (lastExtendedDnsErrorCode)
                        {
                            case EDnsExtendedDnsErrorCode.DnssecBogus:
                            case EDnsExtendedDnsErrorCode.SignatureExpired:
                            case EDnsExtendedDnsErrorCode.SignatureNotYetValid:
                                foreach (DnsResourceRecord record in rrset.Value)
                                    record.SetDnssecStatus(DnssecStatus.Bogus);

                                response.AddDnsClientExtendedError(lastExtendedDnsErrorCode, "Attack detected! " + ownerName.ToLowerInvariant() + " " + rrsetType + " " + rrsetClass.ToString());

                                if (!isAdditionalSection)
                                    throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to invalid signature [" + lastExtendedDnsErrorCode.ToString() + "] for owner name: " + ownerName.ToLowerInvariant() + "/" + rrsetType, response);

                                break;

                            case EDnsExtendedDnsErrorCode.UnsupportedDnsKeyAlgorithm:
                                foreach (DnsResourceRecord record in rrset.Value)
                                    record.SetDnssecStatus(DnssecStatus.Bogus);

                                response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.RRSIGsMissing, "Attack detected! Missing RRSIG with a supported algorithm for " + ownerName.ToLowerInvariant() + " " + rrsetType + " " + rrsetClass.ToString());

                                if (!isAdditionalSection)
                                    throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due missing RRSIG with a supported algorithm for owner name: " + ownerName.ToLowerInvariant() + "/" + rrsetType, response);

                                break;

                            case EDnsExtendedDnsErrorCode.RRSIGsMissing:

                                if (rrsetType == DnsResourceRecordType.CNAME)
                                {
                                    bool foundDNAME = false;
                                    DnsResourceRecord cnameRecord = rrset.Value[0];

                                    foreach (DnsResourceRecord dnameRecord in records)
                                    {
                                        if (dnameRecord.Type != DnsResourceRecordType.DNAME)
                                            continue;

                                        if (cnameRecord.Name.EndsWith("." + dnameRecord.Name, StringComparison.OrdinalIgnoreCase))
                                        {
                                            string synthesizedCNAME = (dnameRecord.RDATA as DnsDNAMERecordData).Substitute(cnameRecord.Name, dnameRecord.Name);
                                            string CNAME = (cnameRecord.RDATA as DnsCNAMERecordData).Domain;

                                            if (synthesizedCNAME.Equals(CNAME, StringComparison.OrdinalIgnoreCase))
                                            {
                                                cnameRecord.SetDnssecStatus(DnssecStatus.Secure);

                                                foundDNAME = true;
                                                break;
                                            }
                                        }
                                    }

                                    if (foundDNAME)
                                        continue;
                                }

                                if (isAdditionalSection)
                                {
                                    foreach (DnsResourceRecord record in rrset.Value)
                                        record.SetDnssecStatus(DnssecStatus.Indeterminate);
                                }
                                else
                                {
                                    foreach (DnsResourceRecord record in rrset.Value)
                                        record.SetDnssecStatus(DnssecStatus.Bogus);

                                    response.AddDnsClientExtendedError(lastExtendedDnsErrorCode, "Attack detected! " + ownerName.ToLowerInvariant() + "/" + rrsetType);

                                    throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to missing RRSIG for owner name: " + ownerName.ToLowerInvariant() + "/" + rrsetType, response);
                                }

                                break;

                            default:
                                foreach (DnsResourceRecord record in rrset.Value)
                                    record.SetDnssecStatus(DnssecStatus.Bogus);

                                response.AddDnsClientExtendedError(lastExtendedDnsErrorCode, "Attack detected! " + ownerName.ToLowerInvariant() + "/" + rrsetType);

                                if (!isAdditionalSection)
                                    throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to reason: " + lastExtendedDnsErrorCode.ToString() + ", for owner name: " + ownerName.ToLowerInvariant() + "/" + rrsetType, response);

                                break;
                        }
                    }
                }
            }
        }

        private static async Task<IReadOnlyList<DnsResourceRecord>> FindDnsKeyForAsync(string ownerName, DnsClass @class, IReadOnlyList<DnsResourceRecord> currentDnsKeyRecords, DnsClient dnsClient, IDnsCache cache, ushort udpPayloadSize, DnsDatagram originalResponse, ResolverContext context, CancellationToken cancellationToken)
        {
            string dnsKeyOwnerName = currentDnsKeyRecords[0].Name;

            if (ownerName.Equals(dnsKeyOwnerName, StringComparison.OrdinalIgnoreCase) || ((dnsKeyOwnerName.Length > 0) && !ownerName.EndsWith("." + dnsKeyOwnerName, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException();

            string[] labels = ownerName.Split('.');
            string nextDomain = null;

            for (int i = 0; i < labels.Length; i++)
            {
                if (nextDomain is null)
                    nextDomain = labels[labels.Length - 1 - i];
                else
                    nextDomain = labels[labels.Length - 1 - i] + "." + nextDomain;

                if (nextDomain.Length <= dnsKeyOwnerName.Length)
                    continue;

                IReadOnlyList<DnsResourceRecord> nextDSRecords = await GetDSForAsync(nextDomain, @class, currentDnsKeyRecords, dnsClient, cache, udpPayloadSize, originalResponse, context, cancellationToken);

                if (nextDSRecords is null)
                {
                    return null;
                }
                else if (nextDSRecords.Count > 0)
                {
                    currentDnsKeyRecords = await GetDnsKeyForAsync(nextDSRecords, dnsClient, cache, udpPayloadSize, context, cancellationToken);
                }
                else
                {
                }
            }

            return currentDnsKeyRecords;
        }

        private static IReadOnlyList<DnsResourceRecord> GetPostQuantumRecords(IReadOnlyList<DnsResourceRecord> records)
        {
            List<DnsResourceRecord> filteredRecords = new List<DnsResourceRecord>(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                switch (record.RDATA)
                {
                    case DnsDSRecordData ds:
                        if (DnsDSRecordData.IsPostQuantumAlgorithm(ds.Algorithm))
                            filteredRecords.Add(record);

                        break;

                    case DnsDNSKEYRecordData dnsKey:
                        if (DnsDSRecordData.IsPostQuantumAlgorithm(dnsKey.Algorithm))
                            filteredRecords.Add(record);

                        break;

                    default:
                        filteredRecords.Add(record);
                        break;
                }
            }

            return filteredRecords;
        }

        private static async Task<IReadOnlyList<DnsResourceRecord>> GetDnsKeyForAsync(IReadOnlyList<DnsResourceRecord> lastDSRecords, DnsClient dnsClient, IDnsCache cache, ushort udpPayloadSize, ResolverContext context, CancellationToken cancellationToken)
        {
            bool requirePostQuantum = _postQuantumDowngradeProtection && DnsDSRecordData.IsPostQuantumSignaled(lastDSRecords);
            if (requirePostQuantum)
                lastDSRecords = GetPostQuantumRecords(lastDSRecords);

            DnsResourceRecord lastDSRecord = lastDSRecords[0];
            DnsQuestionRecord dnsKeyQuestion = new DnsQuestionRecord(lastDSRecord.Name, DnsResourceRecordType.DNSKEY, lastDSRecord.Class);

            DnsDatagram cacheDnsKeyRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [dnsKeyQuestion], null, null, null, udpPayloadSize, EDnsHeaderFlags.None);
            DnsDatagram cacheDnsKeyResponse = await QueryCacheAsync(cache, cacheDnsKeyRequest);
            if (cacheDnsKeyResponse is not null)
            {
                if (cacheDnsKeyResponse.Answer.Count > 0)
                    return requirePostQuantum ? GetPostQuantumRecords(cacheDnsKeyResponse.Answer) : cacheDnsKeyResponse.Answer;
            }

            DnsDatagram dnsKeyRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, [dnsKeyQuestion], null, null, null, udpPayloadSize, EDnsHeaderFlags.DNSSEC_OK);
            DnsDatagram dnsKeyResponse = await dnsClient.InternalResolveAsync(dnsKeyRequest, async delegate (DnsDatagram dnsKeyResponse, CancellationToken cancellationToken1)
            {
                if (dnsKeyResponse.Answer.Count == 0)
                {
                    switch (dnsKeyResponse.RCODE)
                    {
                        case DnsResponseCode.NoError:
                            dnsKeyResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DNSKEYMissing, "Attack detected! " + ((dnsKeyResponse.Metadata is null) || (dnsKeyResponse.Metadata.NameServer is null) ? "name server" : dnsKeyResponse.Metadata.NameServer.ToString()) + " returned no DNSKEYs for " + dnsKeyQuestion.Name.ToLowerInvariant());
                            cache.CacheResponse(dnsKeyResponse, true);

                            dnsKeyResponse.Metadata?.NameServer?.Metadata.MarkMisconfigured();

                            throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to missing DNSKEY records for owner name: " + dnsKeyQuestion.Name.ToLowerInvariant(), dnsKeyResponse);

                        default:
                            dnsKeyResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DNSKEYMissing, "Attack detected! " + ((dnsKeyResponse.Metadata is null) || (dnsKeyResponse.Metadata.NameServer is null) ? "name server" : dnsKeyResponse.Metadata.NameServer.ToString()) + " returned RCODE=" + dnsKeyResponse.RCODE.ToString() + " for " + dnsKeyQuestion.ToString());
                            cache.CacheResponse(dnsKeyResponse, true);

                            dnsKeyResponse.Metadata?.NameServer?.Metadata.MarkMisconfigured();

                            throw new DnsClientResponseDnssecValidationException("Attack detected! Failed to resolve the request '" + dnsKeyResponse.Question[0].ToString() + "'. Received a response with RCODE: " + dnsKeyResponse.RCODE + ((dnsKeyResponse.Metadata is null) || (dnsKeyResponse.Metadata.NameServer is null) ? "" : " from Name server: " + dnsKeyResponse.Metadata.NameServer.ToString()), dnsKeyResponse);
                    }
                }

                if (lastDSRecords.Count > 1)
                {
                    List<DnsResourceRecord> sortedLastDSRecords = new List<DnsResourceRecord>(lastDSRecords);
                    sortedLastDSRecords.Sort(delegate (DnsResourceRecord x, DnsResourceRecord y)
                    {
                        return (x.RDATA as DnsDSRecordData).DigestType.CompareTo((y.RDATA as DnsDSRecordData).DigestType) * -1;
                    });

                    lastDSRecords = sortedLastDSRecords;
                }

                List<DnsResourceRecord> sepDnsKeyRecords = new List<DnsResourceRecord>(2);
                bool tooManyKeyTagCollisions = false;

                foreach (DnsResourceRecord dnsKeyRecord in dnsKeyResponse.Answer)
                {
                    if (dnsKeyRecord.Type != DnsResourceRecordType.DNSKEY)
                        continue;

                    DnsDNSKEYRecordData dnsKey = dnsKeyRecord.RDATA as DnsDNSKEYRecordData;

                    if (dnsKey.Flags.HasFlag(DnsDnsKeyFlag.Revoke))
                        continue;

                    int maxKeyTagCollisions = KEY_TRAP_MAX_KEY_TAG_COLLISIONS;

                    foreach (DnsResourceRecord dsRecord in lastDSRecords)
                    {
                        if (!dsRecord.Name.Equals(dnsKeyQuestion.Name, StringComparison.OrdinalIgnoreCase))
                            continue;

                        DnsDSRecordData ds = dsRecord.RDATA as DnsDSRecordData;

                        if ((ds.KeyTag == dnsKey.ComputedKeyTag) && (ds.Algorithm == dnsKey.Algorithm) && DnsDSRecordData.IsDigestTypeSupported(ds.DigestType))
                        {
                            if (dnsKey.IsDnsKeyValid(dnsKeyRecord.Name, ds))
                            {
                                sepDnsKeyRecords.Add(dnsKeyRecord);
                                break;
                            }

                            maxKeyTagCollisions--;

                            if (maxKeyTagCollisions < 1)
                            {
                                tooManyKeyTagCollisions = true;
                                break;
                            }
                        }
                    }
                }

                if (sepDnsKeyRecords.Count == 0)
                {
                    if (tooManyKeyTagCollisions)
                    {
                        dnsKeyResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.TooManyCryptoValidations, "Attack detected! Too many Key Tag collisions detected for " + dnsKeyQuestion.Name.ToLowerInvariant());
                        cache.CacheResponse(dnsKeyResponse, true);

                        dnsKeyResponse.Metadata?.NameServer?.Metadata.MarkMisconfigured();

                        throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due too many Key Tag collisions detected for owner name: " + dnsKeyQuestion.Name.ToLowerInvariant(), dnsKeyResponse);
                    }
                    else
                    {
                        dnsKeyResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DNSKEYMissing, "Attack detected! No SEP matching the DS found for " + dnsKeyQuestion.Name.ToLowerInvariant());
                        cache.CacheResponse(dnsKeyResponse, true);

                        dnsKeyResponse.Metadata?.NameServer?.Metadata.MarkMisconfigured();

                        throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to unable to find a SEP DNSKEY matching the DS for owner name: " + dnsKeyQuestion.Name.ToLowerInvariant(), dnsKeyResponse);
                    }
                }

                if (DnsDSRecordData.IsAnyDnssecAlgorithmSupported(lastDSRecords) && !DnsDNSKEYRecordData.IsAnyDnssecAlgorithmSupported(sepDnsKeyRecords))
                {
                    foreach (DnsResourceRecord sepDnsKeyRecord in sepDnsKeyRecords)
                        dnsKeyResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.UnsupportedDnsKeyAlgorithm, sepDnsKeyRecord.Name.ToLowerInvariant() + "; keyTag: " + (sepDnsKeyRecord.RDATA as DnsDNSKEYRecordData).ComputedKeyTag);

                    dnsKeyResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DNSKEYMissing, "Attack detected! No SEP matching the DS found for " + dnsKeyQuestion.Name.ToLowerInvariant());
                    cache.CacheResponse(dnsKeyResponse, true);

                    dnsKeyResponse.Metadata?.NameServer?.Metadata.MarkMisconfigured();

                    throw new DnsClientResponseDnssecValidationException("Attack detected! DNSSEC validation failed due to unable to find a SEP DNSKEY matching the DS for owner name: " + dnsKeyQuestion.Name.ToLowerInvariant(), dnsKeyResponse);
                }

                try
                {
                    await DnssecValidateSignatureAsync(dnsKeyResponse, sepDnsKeyRecords, null, context);
                }
                catch (DnsClientResponseDnssecValidationException ex)
                {
                    cache.CacheResponse(ex.Response, true);
                    throw;
                }

                return dnsKeyResponse;
            }, false, context, cancellationToken);

            cache.CacheResponse(dnsKeyResponse);

            return requirePostQuantum ? GetPostQuantumRecords(dnsKeyResponse.Answer) : dnsKeyResponse.Answer;
        }

        private static async Task<IReadOnlyList<DnsResourceRecord>> GetDSForAsync(string ownerName, DnsClass @class, IReadOnlyList<DnsResourceRecord> currentDnsKeyRecords, DnsClient dnsClient, IDnsCache cache, ushort udpPayloadSize, DnsDatagram originalResponse, ResolverContext context, CancellationToken cancellationToken)
        {
            string dnsKeyOwnerName = currentDnsKeyRecords[0].Name;

            if (ownerName.Equals(dnsKeyOwnerName, StringComparison.OrdinalIgnoreCase) || ((dnsKeyOwnerName.Length > 0) && !ownerName.EndsWith("." + dnsKeyOwnerName, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException();

            DnsQuestionRecord dsQuestion = new DnsQuestionRecord(ownerName, DnsResourceRecordType.DS, @class);

            DnsDatagram cacheDSRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [dsQuestion], null, null, null, udpPayloadSize, EDnsHeaderFlags.DNSSEC_OK);
            DnsDatagram cacheDSResponse = await QueryCacheAsync(cache, cacheDSRequest);
            if (cacheDSResponse is not null)
            {
                Tuple<bool, IReadOnlyList<DnsResourceRecord>> tupleCacheDSRecords = await TryGetDSFromResponseAsync(cacheDSResponse, ownerName, context);
                if (tupleCacheDSRecords.Item1)
                {
                    IReadOnlyList<DnsResourceRecord> cacheDSRecords = tupleCacheDSRecords.Item2;

                    if (cacheDSRecords is null)
                        originalResponse.AddDnsClientExtendedErrorsFrom(cacheDSResponse);

                    return cacheDSRecords;
                }
            }

            DnsDatagram dsRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, [dsQuestion], null, null, null, udpPayloadSize, EDnsHeaderFlags.DNSSEC_OK);
            IReadOnlyList<DnsResourceRecord> dsRecords = [];

            try
            {
                _ = await dnsClient.InternalResolveAsync(dsRequest, async delegate (DnsDatagram dsResponse, CancellationToken cancellationToken1)
                {
                    await DnssecValidateSignatureAsync(dsResponse, currentDnsKeyRecords, null, context);

                    Tuple<bool, IReadOnlyList<DnsResourceRecord>> tupleDsRecords = await TryGetDSFromResponseAsync(dsResponse, ownerName, context);
                    if (tupleDsRecords.Item1)
                    {
                        dsRecords = tupleDsRecords.Item2;

                        if (dsRecords is null)
                            originalResponse.AddDnsClientExtendedErrorsFrom(dsResponse);

                        cache.CacheResponse(dsResponse);
                        return dsResponse;
                    }

                    switch (dsResponse.RCODE)
                    {
                        case DnsResponseCode.NoError:
                        case DnsResponseCode.NxDomain:
                            dsResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DnssecIndeterminate, ((dsResponse.Metadata is null) || (dsResponse.Metadata.NameServer is null) ? "name server" : dsResponse.Metadata.NameServer.ToString()) + " returned no DS for " + ownerName.ToLowerInvariant());
                            cache.CacheResponse(dsResponse, true);
                            throw new DnsClientResponseDnssecValidationException("DNSSEC validation failed due to missing DS records for owner name: " + ownerName.ToLowerInvariant(), dsResponse);

                        default:
                            dsResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.DnssecIndeterminate, "Attack detected! " + ((dsResponse.Metadata is null) || (dsResponse.Metadata.NameServer is null) ? "name server" : dsResponse.Metadata.NameServer.ToString()) + " returned RCODE=" + dsResponse.RCODE.ToString() + " for " + dsQuestion.ToString());
                            cache.CacheResponse(dsResponse, true);
                            throw new DnsClientResponseDnssecValidationException("Attack detected! Failed to resolve the request '" + dsResponse.Question[0].ToString() + "'. Received a response with RCODE: " + dsResponse.RCODE + ((dsResponse.Metadata is null) || (dsResponse.Metadata.NameServer is null) ? "" : " from Name server: " + dsResponse.Metadata.NameServer.ToString()), dsResponse);
                    }
                }, false, context, cancellationToken);
            }
            catch (DnsClientResponseDnssecValidationException ex)
            {
                foreach (DnsResourceRecord record in ex.Response.Answer)
                {
                    if ((record.Type == DnsResourceRecordType.CNAME) && record.Name.Equals(ownerName, StringComparison.OrdinalIgnoreCase))
                    {
                        if (record.DnssecStatus == DnssecStatus.Secure)
                            return [];

                        break;
                    }
                }

                cache.CacheResponse(ex.Response, true);
                throw;
            }

            return dsRecords;
        }

        private static async Task<Tuple<bool, IReadOnlyList<DnsResourceRecord>>> TryGetDSFromResponseAsync(DnsDatagram response, string ownerName, ResolverContext context)
        {
            IReadOnlyList<DnsResourceRecord> dsRecords;

            switch (response.RCODE)
            {
                case DnsResponseCode.NxDomain:
                    dsRecords = null;
                    return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);

                case DnsResponseCode.NoError:
                    if ((response.Question[0].Type == DnsResourceRecordType.DS) && response.Question[0].Name.Equals(ownerName, StringComparison.OrdinalIgnoreCase))
                    {
                        if (response.Answer.Count > 0)
                        {
                            dsRecords = GetFilterdDSRecords(response.Answer, ownerName);
                            if (dsRecords.Count > 0)
                            {
                                if (!DnsDSRecordData.IsAnyDigestTypeSupported(dsRecords))
                                {
                                    response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.UnsupportedDsDigestType, ownerName.ToLowerInvariant());
                                    dsRecords = null;
                                    return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                                }

                                if (!DnsDSRecordData.IsAnyDnssecAlgorithmSupported(dsRecords))
                                {
                                    response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.UnsupportedDnsKeyAlgorithm, ownerName.ToLowerInvariant());
                                    dsRecords = null;
                                    return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                                }

                                foreach (DnsResourceRecord dsRecord in dsRecords)
                                {
                                    if (dsRecord.DnssecStatus == DnssecStatus.Insecure)
                                    {
                                        dsRecords = null;
                                        return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                                    }
                                }

                                return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                            }

                            foreach (DnsResourceRecord record in response.Answer)
                            {
                                if ((record.Type == DnsResourceRecordType.CNAME) && record.Name.Equals(ownerName, StringComparison.OrdinalIgnoreCase))
                                {
                                    if (record.DnssecStatus == DnssecStatus.Secure)
                                        return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);

                                    break;
                                }
                            }
                        }
                        else if (response.Authority.Count > 0)
                        {
                            DnssecProofOfNonExistence proofOfNonExistence = await GetValidatedProofOfNonExistenceAsync(response, ownerName, DnsResourceRecordType.DS, context);
                            switch (proofOfNonExistence)
                            {
                                case DnssecProofOfNonExistence.InsecureDelegation:
                                case DnssecProofOfNonExistence.OptOut:
                                case DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue:
                                    dsRecords = null;
                                    return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);

                                case DnssecProofOfNonExistence.NoData:
                                    dsRecords = Array.Empty<DnsResourceRecord>();
                                    return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                            }

                            DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();
                            if ((firstAuthority.Type == DnsResourceRecordType.SOA) && (firstAuthority.DnssecStatus == DnssecStatus.Insecure))
                            {
                                dsRecords = null;
                                return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                            }
                        }
                    }
                    else
                    {
                        DnsResourceRecord firstAuthority = response.FindFirstAuthorityRecord();
                        if ((firstAuthority is not null) && (firstAuthority.Type == DnsResourceRecordType.NS) && (firstAuthority.DnssecStatus == DnssecStatus.Insecure))
                        {
                            dsRecords = null;
                            return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                        }

                        dsRecords = GetFilterdDSRecords(response.Authority, ownerName);
                        if (dsRecords.Count > 0)
                        {
                            if (!DnsDSRecordData.IsAnyDigestTypeSupported(dsRecords))
                            {
                                response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.UnsupportedDsDigestType, ownerName.ToLowerInvariant());
                                dsRecords = null;
                                return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                            }

                            if (!DnsDSRecordData.IsAnyDnssecAlgorithmSupported(dsRecords))
                            {
                                response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.UnsupportedDnsKeyAlgorithm, ownerName.ToLowerInvariant());
                                dsRecords = null;
                                return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                            }

                            foreach (DnsResourceRecord dsRecord in dsRecords)
                            {
                                if (dsRecord.DnssecStatus == DnssecStatus.Insecure)
                                {
                                    dsRecords = null;
                                    return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                                }
                            }

                            return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                        }

                        DnssecProofOfNonExistence proofOfNonExistence = await GetValidatedProofOfNonExistenceAsync(response, ownerName, DnsResourceRecordType.DS, context);
                        switch (proofOfNonExistence)
                        {
                            case DnssecProofOfNonExistence.InsecureDelegation:
                            case DnssecProofOfNonExistence.OptOut:
                            case DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue:
                                dsRecords = null;
                                return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);

                            case DnssecProofOfNonExistence.NoData:
                                dsRecords = Array.Empty<DnsResourceRecord>();
                                return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(true, dsRecords);
                        }
                    }
                    break;
            }

            dsRecords = null;
            return new Tuple<bool, IReadOnlyList<DnsResourceRecord>>(false, dsRecords);
        }

        private static List<DnsResourceRecord> GetFilterdDSRecords(IReadOnlyList<DnsResourceRecord> records, string ownerName)
        {
            List<DnsResourceRecord> dsRecords = new List<DnsResourceRecord>(2);

            foreach (DnsResourceRecord record in records)
            {
                if ((record.Type == DnsResourceRecordType.DS) && record.Name.Equals(ownerName, StringComparison.OrdinalIgnoreCase))
                    dsRecords.Add(record);
            }

            return dsRecords;
        }

        private static async Task<DnssecProofOfNonExistence> GetValidatedProofOfNonExistenceAsync(DnsDatagram response, string domain, DnsResourceRecordType type, ResolverContext context, bool wildcardAnswerValidation = false, string wildcardNextCloserName = null, string wildcardZoneName = null)
        {
            bool hasNSEC = false;
            bool hasNSEC3 = false;

            foreach (DnsResourceRecord record in response.Authority)
            {
                switch (record.Type)
                {
                    case DnsResourceRecordType.NSEC:
                        hasNSEC = true;
                        break;

                    case DnsResourceRecordType.NSEC3:
                        hasNSEC3 = true;
                        break;
                }
            }

            if (hasNSEC)
            {
                DnssecProofOfNonExistence proof = DnsNSECRecordData.GetValidatedProofOfNonExistence(response.Authority, domain, type, wildcardAnswerValidation);
                if (proof != DnssecProofOfNonExistence.NoProof)
                    return proof;
            }

            if (hasNSEC3)
            {
                DnssecProofOfNonExistence proof = await DnsNSEC3RecordData.GetValidatedProofOfNonExistenceAsync(response.Authority, domain, type, wildcardAnswerValidation, wildcardNextCloserName, wildcardZoneName, context);
                if (proof == DnssecProofOfNonExistence.UnsupportedNSEC3IterationsValue)
                {
                    foreach (DnsResourceRecord authority in response.Authority)
                    {
                        if ((authority.Type == DnsResourceRecordType.SOA) || (authority.Type == DnsResourceRecordType.NS))
                        {
                            response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.UnsupportedNSEC3IterationsValue, "NSEC3 iterations > " + MAX_NSEC3_ITERATIONS + " not supported for " + authority.Name.ToLowerInvariant() + ".");
                            break;
                        }
                    }
                }

                return proof;
            }

            return DnssecProofOfNonExistence.NoProof;
        }

        private static IReadOnlyCollection<string> FindSignersNames(DnsDatagram response)
        {
            if ((response.Answer.Count == 0) && (response.Authority.Count == 0))
            {
                switch (response.RCODE)
                {
                    case DnsResponseCode.NoError:
                    case DnsResponseCode.NxDomain:
                        if (response.Question.Count > 0)
                            return new string[] { response.Question[0].Name };

                        return Array.Empty<string>();

                    default:
                        return Array.Empty<string>();
                }
            }
            else
            {
                List<string> signersNames = new List<string>();

                FindSignersNames(response.Answer, signersNames, false);
                FindSignersNames(response.Authority, signersNames, true);

                return signersNames;
            }
        }

        private static void RecordIPv6Failure(NameServerAddress server, NetProxy proxy, Exception ex)
        {
            if (IPv6Reachability.IsTransportFailure(ex))
                RecordIPv6Failure(server, proxy);
        }

        private static void RecordIPv6Failure(NameServerAddress server, NetProxy proxy)
        {
            if (proxy is not null)
                return;

            IPEndPoint ep = server.IPEndPoint;
            if ((ep is null) || (ep.AddressFamily != AddressFamily.InterNetworkV6))
                return;

            IPv6Reachability.RecordFailure(ep.Address);
        }

        private static void FindSignersNames(IReadOnlyList<DnsResourceRecord> records, List<string> signersNames, bool isAuthoritySection)
        {
            foreach (DnsResourceRecord record in records)
            {
                switch (record.Type)
                {
                    case DnsResourceRecordType.RRSIG:
                    case DnsResourceRecordType.OPT:
                        continue;
                }

                if (record.Name.Length == 0)
                    continue;

                bool isRecordCovered = false;

                foreach (DnsResourceRecord rrsigRecord in records)
                {
                    if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                        continue;

                    DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;

                    if ((rrsig.SignersName.Length > 0) && !rrsigRecord.Name.Equals(rrsig.SignersName, StringComparison.OrdinalIgnoreCase) && !rrsigRecord.Name.EndsWith("." + rrsig.SignersName, StringComparison.OrdinalIgnoreCase))
                        continue;

                    if (rrsigRecord.Name.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        if (rrsig.TypeCovered == record.Type)
                        {
                            string signersName = rrsig.SignersName;

                            if (!signersNames.Contains(signersName))
                                signersNames.Add(signersName);

                            isRecordCovered = true;
                            break;
                        }
                    }
                    else if ((record.Type == DnsResourceRecordType.CNAME) && record.Name.EndsWith("." + rrsigRecord.Name, StringComparison.OrdinalIgnoreCase) && (rrsig.TypeCovered == DnsResourceRecordType.DNAME))
                    {
                        isRecordCovered = true;
                        break;
                    }
                }

                if (!isRecordCovered)
                {
                    if (isAuthoritySection && (record.Type == DnsResourceRecordType.NS))
                    {
                    }
                    else
                    {
                        string signersName = record.Name;

                        if (!signersNames.Contains(signersName))
                            signersNames.Add(signersName);
                    }
                }
            }
        }

        private static bool IsDomainUnsigned(string domain, IReadOnlyList<string> unsignedZones)
        {
            if (unsignedZones is null)
                return false;

            foreach (string unsignedZone in unsignedZones)
            {
                if (domain.Equals(unsignedZone, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + unsignedZone, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private static DnsDatagram SanitizeResponseAnswerForQName(DnsDatagram response)
        {
            if (response.Answer.Count == 0)
                return response;

            List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(response.Answer.Count);

            foreach (DnsQuestionRecord question in response.Question)
            {
                string qName = question.Name;

                do
                {
                    string nextQName = null;

                    foreach (DnsResourceRecord answer in response.Answer)
                    {
                        if (qName.Equals(answer.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (answer.Type)
                            {
                                case DnsResourceRecordType.CNAME:
                                    newAnswers.Add(answer);

                                    nextQName = (answer.RDATA as DnsCNAMERecordData).Domain;

                                    if (nextQName.Equals(qName, StringComparison.OrdinalIgnoreCase))
                                        nextQName = null;

                                    break;

                                case DnsResourceRecordType.RRSIG:
                                    newAnswers.Add(answer);
                                    break;

                                default:
                                    if ((question.Type == answer.Type) || (question.Type == DnsResourceRecordType.ANY))
                                        newAnswers.Add(answer);

                                    break;
                            }
                        }
                        else if ((answer.Type == DnsResourceRecordType.DNAME) && qName.EndsWith("." + answer.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            newAnswers.Add(answer);

                            foreach (DnsResourceRecord rrsigRecord in response.Answer)
                            {
                                if (rrsigRecord.RDATA is DnsRRSIGRecordData rrsig && (rrsig.TypeCovered == DnsResourceRecordType.DNAME) && rrsigRecord.Name.Equals(answer.Name, StringComparison.OrdinalIgnoreCase))
                                {
                                    newAnswers.Add(rrsigRecord);
                                    break;
                                }
                            }
                        }
                    }

                    qName = nextQName;
                }
                while ((qName is not null) && (newAnswers.Count < response.Answer.Count));
            }

            return response.Clone(newAnswers);
        }

        private static DnsDatagram SanitizeResponseAnswerForZoneCut(DnsDatagram response, string zoneCut)
        {
            if (zoneCut.Length == 0)
                return response;

            if (response.Answer.Count == 0)
                return response;

            bool answerNotInZoneCut = false;
            string zoneCutEnd = "." + zoneCut;

            foreach (DnsResourceRecord answer in response.Answer)
            {
                if (!answer.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) && !answer.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                {
                    answerNotInZoneCut = true;
                    break;
                }
            }

            if (!answerNotInZoneCut)
                return response;

            List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(response.Answer.Count);

            foreach (DnsResourceRecord answer in response.Answer)
            {
                if (answer.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) || answer.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                    newAnswers.Add(answer);
            }

            return response.Clone(newAnswers);
        }

        private static DnsDatagram SanitizeResponseAuthorityForZoneCut(DnsDatagram response, string zoneCut)
        {
            if (zoneCut.Length == 0)
                return response;

            if (response.Authority.Count == 0)
                return response;

            bool authorityNotInZoneCut = false;
            string zoneCutEnd = "." + zoneCut;

            foreach (DnsResourceRecord authority in response.Authority)
            {
                if ((authority.Type == DnsResourceRecordType.SOA) || (authority.Type == DnsResourceRecordType.NS))
                {
                    if (!authority.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) && !authority.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                    {
                        authorityNotInZoneCut = true;
                        break;
                    }
                }
            }

            if (!authorityNotInZoneCut)
                return response;

            List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>(response.Authority.Count);

            foreach (DnsResourceRecord authority in response.Authority)
            {
                if (authority.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) || authority.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                    newAuthority.Add(authority);
            }

            return response.Clone(null, newAuthority);
        }

        private static DnsDatagram SanitizeResponseAdditionalForZoneCut(DnsDatagram response, string zoneCut)
        {
            if (zoneCut.Length == 0)
                return response;

            if (response.Additional.Count == 0)
                return response;

            bool additionalNotInZoneCut = false;
            string zoneCutEnd = "." + zoneCut;

            foreach (DnsResourceRecord additional in response.Additional)
            {
                if ((additional.Type == DnsResourceRecordType.OPT) && (additional.Name.Length == 0))
                    continue;

                if (!additional.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) && !additional.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                {
                    additionalNotInZoneCut = true;
                    break;
                }
            }

            if (!additionalNotInZoneCut)
                return response;

            List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>(response.Additional.Count);

            foreach (DnsResourceRecord additional in response.Additional)
            {
                if ((additional.Type == DnsResourceRecordType.OPT) && (additional.Name.Length == 0))
                {
                    newAdditional.Add(additional);
                    continue;
                }

                if (additional.Name.Equals(zoneCut, StringComparison.OrdinalIgnoreCase) || additional.Name.EndsWith(zoneCutEnd, StringComparison.OrdinalIgnoreCase))
                    newAdditional.Add(additional);
            }

            return response.Clone(null, null, newAdditional);
        }

        private static DnsDatagram SanitizeResponseAfterDnssecValidation(DnsDatagram response)
        {
            List<DnsResourceRecord> newAnswer = null;
            List<DnsResourceRecord> newAuthority = null;

            foreach (DnsResourceRecord record in response.Answer)
            {
                if (record.DnssecStatus != DnssecStatus.Indeterminate)
                    continue;

                newAnswer = new List<DnsResourceRecord>(response.Answer.Count);

                foreach (DnsResourceRecord record2 in response.Answer)
                {
                    if (record2.DnssecStatus == DnssecStatus.Indeterminate)
                        continue;

                    newAnswer.Add(record2);
                }

                break;
            }

            foreach (DnsResourceRecord record in response.Authority)
            {
                if (record.DnssecStatus != DnssecStatus.Indeterminate)
                    continue;

                if (record.Type == DnsResourceRecordType.NS)
                    continue;

                newAuthority = new List<DnsResourceRecord>(response.Authority.Count);

                foreach (DnsResourceRecord record2 in response.Authority)
                {
                    if (record2.DnssecStatus == DnssecStatus.Indeterminate)
                    {
                        if (record2.Type != DnsResourceRecordType.NS)
                            continue;
                    }

                    newAuthority.Add(record2);
                }

                break;
            }

            if ((newAnswer is null) && (newAuthority is null))
                return response;

            return response.Clone(newAnswer, newAuthority);
        }

        private static DnsDatagram GetMinimalResponseWithoutNSAndGlue(DnsDatagram response)
        {
            bool foundNS = false;

            foreach (DnsResourceRecord record in response.Authority)
            {
                if (record.Type == DnsResourceRecordType.NS)
                {
                    foundNS = true;
                    break;
                }
            }

            IReadOnlyList<DnsResourceRecord> authority;

            if (foundNS)
            {
                List<DnsResourceRecord> newAuthority = new List<DnsResourceRecord>();

                foreach (DnsResourceRecord record in response.Authority)
                {
                    switch (record.Type)
                    {
                        case DnsResourceRecordType.NS:
                        case DnsResourceRecordType.DS:
                            break;

                        case DnsResourceRecordType.RRSIG:
                            switch ((record.RDATA as DnsRRSIGRecordData).TypeCovered)
                            {
                                case DnsResourceRecordType.NS:
                                case DnsResourceRecordType.DS:
                                    break;

                                default:
                                    newAuthority.Add(record);
                                    break;
                            }
                            break;

                        default:
                            newAuthority.Add(record);
                            break;
                    }
                }

                authority = newAuthority;
            }
            else
            {
                authority = response.Authority;
            }

            bool foundIndeterminate = false;

            if (!foundNS)
            {
                foreach (DnsResourceRecord additionalRecord in response.Additional)
                {
                    switch (additionalRecord.DnssecStatus)
                    {
                        case DnssecStatus.Disabled:
                        case DnssecStatus.Secure:
                        case DnssecStatus.Insecure:
                            continue;
                    }

                    foundIndeterminate = true;
                    break;
                }
            }

            if (foundNS || foundIndeterminate)
            {
                IReadOnlyList<DnsResourceRecord> additional;

                if ((response.Additional.Count == 0) || ((response.Additional.Count == 1) && (response.Additional[0].Type == DnsResourceRecordType.OPT)))
                {
                    additional = response.Additional;
                }
                else
                {
                    List<DnsResourceRecord> newAdditional = new List<DnsResourceRecord>();

                    foreach (DnsResourceRecord additionalRecord in response.Additional)
                    {
                        switch (additionalRecord.DnssecStatus)
                        {
                            case DnssecStatus.Disabled:
                            case DnssecStatus.Secure:
                            case DnssecStatus.Insecure:
                                break;

                            default:
                                if (additionalRecord.Type == DnsResourceRecordType.OPT)
                                    break;

                                continue;
                        }

                        switch (additionalRecord.Type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                            case DnsResourceRecordType.RRSIG:
                                if (foundNS)
                                {
                                    bool foundGlue = false;

                                    foreach (DnsResourceRecord nsRecord in response.Authority)
                                    {
                                        if ((nsRecord.Type == DnsResourceRecordType.NS) && additionalRecord.Name.Equals((nsRecord.RDATA as DnsNSRecordData).NameServer, StringComparison.OrdinalIgnoreCase))
                                        {
                                            foundGlue = true;
                                            break;
                                        }
                                    }

                                    if (!foundGlue)
                                        newAdditional.Add(additionalRecord);
                                }
                                else
                                {
                                    newAdditional.Add(additionalRecord);
                                }
                                break;

                            default:
                                newAdditional.Add(additionalRecord);
                                break;
                        }
                    }

                    additional = newAdditional;
                }

                return response.Clone(null, authority, additional);
            }

            return response;
        }

        private static async Task<DnsDatagram> ResolveQueryAsync(DnsQuestionRecord question, Func<DnsQuestionRecord, Task<DnsDatagram>> resolveAsync)
        {
            DnsDatagram response = await resolveAsync(question);
            if (response is null)
                return new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.Refused, new DnsQuestionRecord[] { question });

            if (response.Answer.Count > 0)
            {
                DnsResourceRecord lastRR = response.GetLastAnswerRecord();

                if ((lastRR.Type != question.Type) && (lastRR.Type == DnsResourceRecordType.CNAME) && (question.Type != DnsResourceRecordType.ANY))
                {
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
                    DnsDatagram newResponse = null;
                    bool cnameLoopDetected = false;
                    double responseRtt = 0.0;

                    if (response.Metadata is not null)
                        responseRtt = response.Metadata.RoundTripTime;

                    int queryCount = 0;
                    do
                    {
                        string cnameDomain = (lastRR.RDATA as DnsCNAMERecordData).Domain;
                        if (lastRR.Name.Equals(cnameDomain, StringComparison.OrdinalIgnoreCase))
                        {
                            cnameLoopDetected = true;
                            break;
                        }

                        newResponse = await resolveAsync(new DnsQuestionRecord(cnameDomain, question.Type, question.Class));
                        if (newResponse is null)
                            break;

                        if (newResponse.Metadata is not null)
                            responseRtt += newResponse.Metadata.RoundTripTime;

                        if (newResponse.Answer.Count == 0)
                            break;

                        lastRR = newResponse.GetLastAnswerRecord();
                        if (lastRR.Type != DnsResourceRecordType.CNAME)
                        {
                            newAnswer.AddRange(newResponse.Answer);
                            break;
                        }

                        foreach (DnsResourceRecord answerRecord in newAnswer)
                        {
                            if (answerRecord.Type != DnsResourceRecordType.CNAME)
                                continue;

                            if (answerRecord.RDATA.Equals(lastRR.RDATA))
                            {
                                cnameLoopDetected = true;
                                break;
                            }
                        }

                        if (cnameLoopDetected)
                            break;

                        newAnswer.AddRange(newResponse.Answer);
                        lastResponse = newResponse;
                    }
                    while (++queryCount < MAX_CNAME_HOPS);

                    DnsResponseCode rcode;
                    IReadOnlyList<DnsResourceRecord> authority;
                    IReadOnlyList<DnsResourceRecord> additional;

                    if (newResponse is null)
                    {
                        rcode = DnsResponseCode.NoError;

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
                    }
                    else
                    {
                        if (cnameLoopDetected || (queryCount >= MAX_CNAME_HOPS))
                            rcode = DnsResponseCode.ServerFailure;
                        else
                            rcode = newResponse.RCODE;

                        if (newAuthority.Count == 0)
                        {
                            authority = newResponse.Authority;
                        }
                        else
                        {
                            newAuthority.AddRange(newResponse.Authority);
                            authority = newAuthority;
                        }

                        additional = newResponse.Additional;
                    }

                    DnsDatagram finalResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, rcode, [question], newAnswer, authority, additional);
                    finalResponse.SetMetadata(null, responseRtt);

                    return finalResponse;
                }
            }

            return response;
        }

        protected virtual async Task<DnsDatagram> InternalResolveAsync(DnsDatagram request, Func<DnsDatagram, CancellationToken, Task<DnsDatagram>> getValidatedResponseAsync = null, bool doNotReorderNameServers = false, ResolverContext context = null, CancellationToken cancellationToken = default)
        {
            IReadOnlyList<NameServerAddress> servers;
            int concurrency;

            if (_servers.Count > _concurrency)
            {
                if (doNotReorderNameServers)
                    servers = _servers;
                else
                    servers = GetOrderedNameServersToPreferPerformance(_servers, false, _ipv6Mode);

                concurrency = _concurrency;
            }
            else
            {
                servers = _servers;
                concurrency = _servers.Count;
            }

            object nextServerLock = new object();
            int nextServerIndex = 0;
            List<NameServerAddress> deferredServers = null;
            int nextDeferredServerIndex = 0;
            IDnsCache nsResolveCache = null;

            NameServerAddress GetNextServer()
            {
                lock (nextServerLock)
                {
                    while (nextServerIndex < servers.Count)
                    {
                        NameServerAddress nextServer = servers[nextServerIndex++];
                        IPEndPoint nextServerEP = nextServer.IPEndPoint;

                        if ((nextServerEP is not null) && (nextServerEP.AddressFamily == AddressFamily.InterNetworkV6) && IPv6Reachability.IsUnavailable)
                        {
                            deferredServers ??= new List<NameServerAddress>();
                            deferredServers.Add(nextServer);
                            continue;
                        }

                        return nextServer;
                    }

                    if ((deferredServers is not null) && (nextDeferredServerIndex < deferredServers.Count))
                        return deferredServers[nextDeferredServerIndex++];

                    return null;
                }
            }

            async Task<DnsDatagram> DoResolveAsync(CancellationToken cancellationToken)
            {
                DnsDatagram asyncRequest = request.CloneHeadersAndQuestions();
                DnsDatagram lastResponse = null;
                Exception lastException = null;

                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    if ((context is not null) && !context.CanProceedWithResolution())
                        throw new DnsClientNoResponseException("DnsClient failed to resolve the request" + (asyncRequest.Question.Count > 0 ? " '" + asyncRequest.Question[0].ToString() + "'" : "") + ": Resolver limit reached (" + context.GetCannotProceedWithResolutionReason() + ").");

                    NameServerAddress server = GetNextServer();
                    if (server is null)
                    {
                        if (lastResponse is not null)
                            return lastResponse;

                        if (lastException is not null)
                            ExceptionDispatchInfo.Throw(lastException);

                        throw new DnsClientNoResponseException("DnsClient failed to resolve the request" + (asyncRequest.Question.Count > 0 ? " '" + asyncRequest.Question[0].ToString() + "'" : "") + ": no valid response from name servers [" + servers.Join() + "].");
                    }

                    NetProxy proxy = _proxy;

                    if ((proxy is not null) && proxy.IsBypassed(server.EndPoint))
                        proxy = null;

                    if (proxy is null)
                    {
                        if (server.IsIPEndPointStale)
                        {
                            if (nsResolveCache is null)
                                nsResolveCache = _cache is null ? new DnsCache() : _cache;

                            try
                            {
                                await server.RecursiveResolveIPAddressAsync(nsResolveCache, null, _ipv6Mode, _udpPayloadSize, _randomizeName, _retries, _timeout, concurrency, cancellationToken: cancellationToken);
                            }
                            catch (OperationCanceledException)
                            {
                                throw;
                            }
                            catch (Exception ex)
                            {
                                lastException = ex;
                                continue;
                            }
                        }
                    }
                    else
                    {
                        if ((server.Protocol == DnsTransportProtocol.Udp) && !await proxy.IsUdpAvailableAsync(cancellationToken))
                            server = server.Clone(DnsTransportProtocol.Tcp);
                    }

                    switch (server.Protocol)
                    {
                        case DnsTransportProtocol.Https:
                        case DnsTransportProtocol.Quic:
                            asyncRequest.SetIdentifier(0);
                            break;

                        default:
                            asyncRequest.SetRandomIdentifier();
                            break;
                    }

                    DateTime startTime = DateTime.UtcNow;
                    DateTime successTime = default;

                    bool protocolWasSwitched = false;
                    bool startedWithUdp = server.Protocol == DnsTransportProtocol.Udp;
                    try
                    {
                        bool retryRequest;
                        do
                        {
                            cancellationToken.ThrowIfCancellationRequested();

                            if ((context is not null) && !context.CanProceedWithResolution())
                                throw new DnsClientNoResponseException("DnsClient failed to resolve the request" + (asyncRequest.Question.Count > 0 ? " '" + asyncRequest.Question[0].ToString() + "'" : "") + ": Resolver limit reached (" + context.GetCannotProceedWithResolutionReason() + ").");

                            retryRequest = false;

                            if (server.Protocol == DnsTransportProtocol.Udp)
                            {
                                if ((asyncRequest.Question.Count > 0) && (asyncRequest.Question[0].Type == DnsResourceRecordType.AXFR))
                                {
                                    server = server.Clone(DnsTransportProtocol.Tcp);
                                }
                                else if (_randomizeName)
                                {
                                    foreach (DnsQuestionRecord question in asyncRequest.Question)
                                        question.RandomizeName();
                                }
                            }

                            await using (DnsClientConnection connection = startedWithUdp && (server.Protocol == DnsTransportProtocol.Tcp) ? new TcpClientConnection(server, proxy) : DnsClientConnection.GetConnection(server, proxy))
                            {
                                try
                                {
                                    if (context is not null)
                                        context.DecrementMaxOutboundRequests();

                                    DnsDatagram queryRequest = asyncRequest;

                                    if (_eDnsPadding && (asyncRequest.EDNS is not null))
                                    {
                                        switch (server.Protocol)
                                        {
                                            case DnsTransportProtocol.Tls:
                                            case DnsTransportProtocol.Https:
                                            case DnsTransportProtocol.Quic:
                                                queryRequest = asyncRequest.CloneWithPadding(QUERY_PADDING_BLOCK_SIZE);
                                                break;
                                        }
                                    }

                                    DnsDatagram response = await connection.QueryAsync(queryRequest, _timeout, _retries, cancellationToken);

                                    if ((proxy is null) && (server.IPEndPoint is not null) && (server.IPEndPoint.AddressFamily == AddressFamily.InterNetworkV6))
                                        IPv6Reachability.RecordSuccess();
                                    if (response.Truncation)
                                    {
                                        if (server.Protocol == DnsTransportProtocol.Udp)
                                        {
                                            server = server.Clone(DnsTransportProtocol.Tcp);

                                            if (_randomizeName)
                                            {
                                                foreach (DnsQuestionRecord question in asyncRequest.Question)
                                                    question.NormalizeName();
                                            }

                                            if (response.Metadata is not null)
                                                server.Metadata.UpdateSuccess(response.Metadata.RoundTripTime);

                                            retryRequest = true;
                                            protocolWasSwitched = true;
                                        }
                                        else
                                        {
                                            server.Metadata.UpdateFailure(_timeout * _retries);
                                            lastException = new DnsClientResponseValidationException("Invalid response was received: truncated response over " + server.Protocol.ToString().ToUpperInvariant() + " transport.");
                                        }
                                    }
                                    else
                                    {
                                        if (response.ParsingException is not null)
                                        {
                                            if ((asyncRequest.EDNS is not null) && !_dnssecValidation)
                                            {
                                                asyncRequest = asyncRequest.CloneWithoutEDns();
                                                retryRequest = true;
                                            }

                                            server.Metadata.UpdateFailure(_timeout * _retries);
                                            lastException = response.ParsingException;
                                        }
                                        else
                                        {
                                            EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                                            if (requestECS is not null)
                                            {
                                                EDnsClientSubnetOptionData responseECS = response.GetEDnsClientSubnetOption();
                                                if (responseECS is null)
                                                {
                                                    response.SetShadowEDnsClientSubnetOption(requestECS);
                                                }
                                            }

                                            if (getValidatedResponseAsync is not null)
                                                response = await getValidatedResponseAsync(response, cancellationToken);

                                            switch (response.RCODE)
                                            {
                                                case DnsResponseCode.NoError:
                                                case DnsResponseCode.YXDomain:
                                                    successTime = DateTime.UtcNow;

                                                    if (response.Metadata is not null)
                                                        server.Metadata.UpdateSuccess(response.Metadata.RoundTripTime);

                                                    response.SetIdentifier(request.Identifier);
                                                    return response;

                                                case DnsResponseCode.NxDomain:
                                                    successTime = DateTime.UtcNow;

                                                    if (response.Metadata is not null)
                                                        server.Metadata.UpdateSuccess(response.Metadata.RoundTripTime);

                                                    response.SetIdentifier(request.Identifier);

                                                    if (request.RecursionDesired && !response.RecursionAvailable && !response.AuthoritativeAnswer)
                                                        response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.BlockedByUpstreamDnsServer, response.Question[0].Name.ToLowerInvariant() + " was blocked by " + ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "upstream server" : response.Metadata.NameServer.ToString()));

                                                    return response;

                                                case DnsResponseCode.FormatError:
                                                    if ((asyncRequest.EDNS is not null) && !_dnssecValidation)
                                                    {
                                                        asyncRequest = asyncRequest.CloneWithoutEDns();

                                                        server.Metadata.UpdateFailure(_timeout);
                                                        retryRequest = true;
                                                        protocolWasSwitched = false;
                                                    }
                                                    else
                                                    {
                                                        server.Metadata.UpdateFailure(_timeout * _retries);
                                                        response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "name server" : response.Metadata.NameServer.ToString()) + " returned RCODE=" + response.RCODE.ToString() + " for " + request.Question[0].ToString());

                                                        if (lastResponse is not null)
                                                            response.AddDnsClientExtendedErrorsFrom(lastResponse);

                                                        lastResponse = response;
                                                    }
                                                    break;

                                                case DnsResponseCode.Refused:
                                                    EDnsClientSubnetOptionData asyncRequestECS = asyncRequest.GetEDnsClientSubnetOption(true);
                                                    if (asyncRequestECS is not null)
                                                    {
                                                        asyncRequest = asyncRequest.CloneWithoutEDnsClientSubnet();

                                                        server.Metadata.UpdateFailure(_timeout);
                                                        retryRequest = true;
                                                        protocolWasSwitched = false;
                                                    }
                                                    else
                                                    {
                                                        server.Metadata.UpdateFailure(_timeout * _retries);
                                                        response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "name server" : response.Metadata.NameServer.ToString()) + " returned RCODE=" + response.RCODE.ToString() + " for " + request.Question[0].ToString());

                                                        if (lastResponse is not null)
                                                            response.AddDnsClientExtendedErrorsFrom(lastResponse);

                                                        lastResponse = response;
                                                    }
                                                    break;

                                                default:
                                                    server.Metadata.UpdateFailure(_timeout * _retries);
                                                    response.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, ((response.Metadata is null) || (response.Metadata.NameServer is null) ? "name server" : response.Metadata.NameServer.ToString()) + " returned RCODE=" + response.RCODE.ToString() + " for " + request.Question[0].ToString());

                                                    if (lastResponse is not null)
                                                        response.AddDnsClientExtendedErrorsFrom(lastResponse);

                                                    lastResponse = response;
                                                    break;
                                            }
                                        }
                                    }
                                }
                                catch (SocketException ex)
                                {
                                    switch (ex.SocketErrorCode)
                                    {
                                        case SocketError.MessageSize:
                                            if (server.Protocol == DnsTransportProtocol.Udp)
                                            {
                                                server = server.Clone(DnsTransportProtocol.Tcp);

                                                if (_randomizeName)
                                                {
                                                    foreach (DnsQuestionRecord question in asyncRequest.Question)
                                                        question.NormalizeName();
                                                }

                                                server.Metadata.UpdateFailure(_timeout);
                                                lastException = ex;
                                                retryRequest = true;
                                                protocolWasSwitched = true;
                                            }
                                            else
                                            {
                                                throw;
                                            }

                                            break;

                                        default:
                                            throw;
                                    }
                                }
                                catch (DnsClientNoResponseException ex)
                                {
                                    if ((server.Protocol == DnsTransportProtocol.Udp) && (asyncRequest.EDNS is not null) && !_dnssecValidation)
                                    {
                                        asyncRequest = asyncRequest.CloneWithoutEDns();

                                        RecordIPv6Failure(server, proxy, ex);

                                        server.Metadata.UpdateFailure(_timeout);
                                        lastException = ex;
                                        retryRequest = true;
                                        protocolWasSwitched = false;
                                    }
                                    else
                                    {
                                        throw;
                                    }
                                }
                                catch (DnsClientResponseDnssecValidationException)
                                {
                                    throw;
                                }
                                catch (DnsClientResponseValidationException ex)
                                {
                                    if (server.Protocol == DnsTransportProtocol.Udp)
                                    {
                                        server = server.Clone(DnsTransportProtocol.Tcp);

                                        if (_randomizeName)
                                        {
                                            foreach (DnsQuestionRecord question in asyncRequest.Question)
                                                question.NormalizeName();
                                        }

                                        server.Metadata.UpdateFailure(_timeout);
                                        lastException = ex;
                                        retryRequest = true;
                                        protocolWasSwitched = true;
                                    }
                                    else
                                    {
                                        throw;
                                    }
                                }
                            }
                        }
                        while (retryRequest);
                    }
                    catch (OperationCanceledException)
                    {
                        double timeTaken;

                        if (successTime == default)
                        {
                            timeTaken = (DateTime.UtcNow - startTime).TotalMilliseconds;
                        }
                        else
                        {
                            timeTaken = (successTime - startTime).TotalMilliseconds;
                        }

                        double maxWaitTime = _timeout * _retries;

                        if ((successTime == default) && (timeTaken >= Math.Min(_timeout, IPV6_UNANSWERED_FAILURE_TIME)))
                            RecordIPv6Failure(server, proxy);

                        if (maxWaitTime > timeTaken)
                        {
                            double mean = timeTaken + ((maxWaitTime - timeTaken) / 2);
                            server.Metadata.UpdateFailure(mean);
                        }
                        else
                        {
                            server.Metadata.UpdateFailure(maxWaitTime);
                        }

                        throw;
                    }
                    catch (DnsClientNoResponseException ex)
                    {
                        server.Metadata.UpdateFailure(_timeout * _retries);
                        lastException = ex;

                        RecordIPv6Failure(server, proxy, ex);
                    }
                    catch (DnsClientResponseValidationException ex)
                    {
                        server.Metadata.UpdateFailure(_timeout * _retries);
                        lastException = ex;
                    }
                    catch (DnsClientResponseNotPreferredException ex)
                    {
                        server.Metadata.UpdateFailure(_timeout);
                        lastException = ex;
                    }
                    catch (Exception ex)
                    {
                        server.Metadata.UpdateFailure(_timeout * _retries);

                        RecordIPv6Failure(server, proxy, ex);

                        if (protocolWasSwitched && (lastException is DnsClientResponseValidationException) && (ex is SocketException))
                        {
                        }
                        else
                        {
                            lastException = ex;
                        }
                    }
                }
            }

            if (concurrency > 1)
            {
                using (CancellationTokenSource cancellationTokenSource = new CancellationTokenSource())
                {
                    await using (CancellationTokenRegistration ctr = cancellationToken.Register(cancellationTokenSource.Cancel))
                    {
                        CancellationToken currentCancellationToken = cancellationTokenSource.Token;
                        List<Task> tasks = new List<Task>(concurrency + 1);

                        for (int i = 0; i < concurrency; i++)
                            tasks.Add(Task.Factory.StartNew(delegate () { return DoResolveAsync(currentCancellationToken); }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, TaskScheduler.Current).Unwrap());

                        Task delayTask = Task.Delay(_timeout * _retries * (int)Math.Ceiling((double)servers.Count / concurrency) * 2, currentCancellationToken);
                        tasks.Add(delayTask);

                        DnsDatagram lastResponse = null;
                        Exception lastException = null;

                        while (true)
                        {
                            Task completedTask = await Task.WhenAny(tasks);

                            if (completedTask == delayTask)
                            {
                                cancellationTokenSource.Cancel();

                                if (lastResponse is not null)
                                    return lastResponse;

                                if (lastException is DnsClientResponseNotPreferredException ex)
                                    return ex.Response;

                                if (lastException is not null)
                                    ExceptionDispatchInfo.Throw(lastException);

                                throw new DnsClientNoResponseException("DnsClient failed to resolve the request" + (request.Question.Count > 0 ? " '" + request.Question[0].ToString() + "'" : "") + ": request timed out for name servers [" + servers.Join() + "].");
                            }

                            if (completedTask.Status == TaskStatus.RanToCompletion)
                            {
                                DnsDatagram response = await (completedTask as Task<DnsDatagram>);

                                switch (response.RCODE)
                                {
                                    case DnsResponseCode.NoError:
                                    case DnsResponseCode.NxDomain:
                                    case DnsResponseCode.YXDomain:
                                        cancellationTokenSource.Cancel();
                                        return response;

                                    default:
                                        if (lastResponse is not null)
                                            response.AddDnsClientExtendedErrorsFrom(lastResponse);

                                        lastResponse = response;
                                        break;
                                }
                            }

                            if (tasks.Count == 2)
                            {
                                cancellationTokenSource.Cancel();

                                if (lastResponse is not null)
                                    return lastResponse;

                                if (completedTask.Exception?.InnerException is DnsClientResponseNotPreferredException ex1)
                                    return ex1.Response;

                                if (lastException is DnsClientResponseNotPreferredException ex2)
                                    return ex2.Response;

                                return await (completedTask as Task<DnsDatagram>);
                            }

                            tasks.Remove(completedTask);
                            lastException = completedTask.Exception?.InnerException;
                        }
                    }
                }
            }
            else
            {
                try
                {
                    return await DoResolveAsync(cancellationToken);
                }
                catch (DnsClientResponseNotPreferredException ex)
                {
                    return ex.Response;
                }
            }
        }

        private async Task<DnsDatagram> InternalNoDnssecResolveAsync(DnsDatagram request, CancellationToken cancellationToken = default)
        {
            if ((_conditionalForwardingZoneCut is not null) && (request.Question.Count == 1))
            {
                DnsQuestionRecord question = request.Question[0];

                if (!question.Name.Equals(_conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase) && !question.Name.EndsWith("." + _conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase))
                    return new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.Refused, new DnsQuestionRecord[] { question });
            }

            DnsDatagram response = await InternalResolveAsync(request, cancellationToken: cancellationToken);

            if (_conditionalForwardingZoneCut is not null)
            {
                response = SanitizeResponseAnswerForZoneCut(response, _conditionalForwardingZoneCut);
                response = SanitizeResponseAnswerForQName(response);

                foreach (DnsResourceRecord answer in response.Answer)
                {
                    if ((answer.Type == DnsResourceRecordType.CNAME) && (answer.Name.Equals(_conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase) || answer.Name.EndsWith("." + _conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase)))
                    {
                        response = SanitizeResponseAuthorityForZoneCut(response, _conditionalForwardingZoneCut);
                        break;
                    }
                }

                response = SanitizeResponseAdditionalForZoneCut(response, _conditionalForwardingZoneCut);
            }
            else
            {
                response = SanitizeResponseAnswerForQName(response);
            }

            response.SetDnssecStatusForAllRecords(DnssecStatus.Disabled);

            return response;
        }

        private async Task<DnsDatagram> InternalDnssecResolveAsync(DnsQuestionRecord question, CancellationToken cancellationToken = default)
        {
            if ((_conditionalForwardingZoneCut is not null) && !question.Name.Equals(_conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase) && !question.Name.EndsWith("." + _conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase))
                return new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, true, true, false, false, DnsResponseCode.Refused, [question]);

            IDnsCache cache;

            if (_cache is null)
                cache = new DnsCache();
            else
                cache = _cache;

            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, true, DnsResponseCode.NoError, [question], null, null, null, _udpPayloadSize, EDnsHeaderFlags.DNSSEC_OK, _advancedForwardingClientSubnet ? null : EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(_eDnsClientSubnet));
            if (_advancedForwardingClientSubnet)
                request.SetShadowEDnsClientSubnetOption(_eDnsClientSubnet, true);

            ResolverContext context = new ResolverContext();
            bool dnssecRRSigMissingRetry = false;

            while (true)
            {
                try
                {
                    return await InternalResolveAsync(request, async delegate (DnsDatagram response, CancellationToken cancellationToken1)
                    {
                        if (_conditionalForwardingZoneCut is not null)
                        {
                            response = SanitizeResponseAnswerForZoneCut(response, _conditionalForwardingZoneCut);
                            response = SanitizeResponseAnswerForQName(response);

                            foreach (DnsResourceRecord answer in response.Answer)
                            {
                                if ((answer.Type == DnsResourceRecordType.CNAME) && (answer.Name.Equals(_conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase) || answer.Name.EndsWith("." + _conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase)))
                                {
                                    response = SanitizeResponseAuthorityForZoneCut(response, _conditionalForwardingZoneCut);
                                    break;
                                }
                            }

                            response = SanitizeResponseAdditionalForZoneCut(response, _conditionalForwardingZoneCut);
                        }
                        else
                        {
                            response = SanitizeResponseAnswerForQName(response);
                        }

                        try
                        {
                            await DnssecValidateResponseAsync(response, GetTrustAnchorsFor(response), this, cache, _udpPayloadSize, context, cancellationToken1);
                        }
                        catch (DnsClientResponseDnssecValidationException ex)
                        {
                            if ((ex.Response.Question.Count > 0) && ex.Response.Question[0].Equals(question))
                                throw;

                            response.AddDnsClientExtendedErrorsFrom(ex.Response);
                            throw new DnsClientResponseDnssecValidationException(ex.Message, response, ex);
                        }

                        response = SanitizeResponseAfterDnssecValidation(response);

                        return response;
                    }, false, null, cancellationToken);
                }
                catch (DnsClientResponseDnssecValidationException ex)
                {
                    if (!dnssecRRSigMissingRetry)
                    {
                        if (ex.Response is not null)
                        {
                            foreach (EDnsExtendedDnsErrorOptionData eDnsError in ex.Response.DnsClientExtendedErrors)
                            {
                                if (eDnsError.InfoCode == EDnsExtendedDnsErrorCode.RRSIGsMissing)
                                {
                                    dnssecRRSigMissingRetry = true;
                                    break;
                                }
                            }

                            if (dnssecRRSigMissingRetry)
                                continue;
                        }
                    }

                    throw;
                }
            }
        }

        private IReadOnlyList<DnsResourceRecord> GetTrustAnchorsFor(DnsDatagram response)
        {
            if (_trustAnchors is null)
                return ROOT_TRUST_ANCHORS;

            IReadOnlyCollection<string> signersNames = FindSignersNames(response);
            List<DnsResourceRecord> selectedTrustAnchors = new List<DnsResourceRecord>();

            foreach (string signersName in signersNames)
            {
                string domain = signersName;

                while (domain is not null)
                {
                    if (_trustAnchors.TryGetValue(domain, out IReadOnlyList<DnsResourceRecord> dsRecords))
                    {
                        foreach (DnsResourceRecord dsRecord in dsRecords)
                        {
                            if (!selectedTrustAnchors.Contains(dsRecord))
                                selectedTrustAnchors.Add(dsRecord);
                        }

                        break;
                    }

                    domain = DnsCache.GetParentZone(domain);
                }
            }

            if (selectedTrustAnchors.Count > 0)
                return selectedTrustAnchors;

            return ROOT_TRUST_ANCHORS;
        }

        private async Task<DnsDatagram> InternalCachedResolveQueryAsync(DnsQuestionRecord question, CancellationToken cancellationToken)
        {
            return await ResolveQueryAsync(question, async delegate (DnsQuestionRecord q)
            {
                if ((_conditionalForwardingZoneCut is not null) && !q.Name.Equals(_conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase) && !q.Name.EndsWith("." + _conditionalForwardingZoneCut, StringComparison.OrdinalIgnoreCase))
                    return null;

                DnsDatagram newRequest = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, _dnssecValidation, DnsResponseCode.NoError, new DnsQuestionRecord[] { q }, null, null, null, _udpPayloadSize, _dnssecValidation ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None, _advancedForwardingClientSubnet ? null : EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(_eDnsClientSubnet));
                if (_advancedForwardingClientSubnet)
                    newRequest.SetShadowEDnsClientSubnetOption(_eDnsClientSubnet, true);

                DnsDatagram cacheResponse = await QueryCacheAsync(_cache, newRequest);
                if (cacheResponse is not null)
                    return cacheResponse;

                try
                {
                    DnsDatagram newResponse;

                    if (_dnssecValidation)
                        newResponse = await InternalDnssecResolveAsync(q, cancellationToken);
                    else
                        newResponse = await InternalNoDnssecResolveAsync(newRequest, cancellationToken);

                    newResponse = GetMinimalResponseWithoutNSAndGlue(newResponse);

                    _cache.CacheResponse(newResponse);

                    return newResponse;
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    if (ex is DnsClientResponseDnssecValidationException ex2)
                    {
                        _cache.CacheResponse(ex2.Response, true);
                    }
                    else if (ex is DnsClientNoResponseException)
                    {
                        DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { q });

                        if (ex.InnerException is SocketException ex3)
                        {
                            if (ex3.SocketErrorCode == SocketError.TimedOut)
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Request timed out for " + q.ToString());
                            else
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "Socket error for " + q.ToString() + ": " + ex3.SocketErrorCode.ToString());
                        }
                        else
                        {
                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "No valid response from name servers for " + q.ToString());
                        }

                        if (_eDnsClientSubnet is not null)
                            failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(_eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.Address));

                        _cache.CacheResponse(failureResponse);
                    }
                    else if (ex is SocketException ex4)
                    {
                        DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { q });

                        if (ex4.SocketErrorCode == SocketError.TimedOut)
                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Request timed out for " + q.ToString());
                        else
                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "Socket error for " + q.ToString() + ": " + ex4.SocketErrorCode.ToString());

                        if (_eDnsClientSubnet is not null)
                            failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(_eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.Address));

                        _cache.CacheResponse(failureResponse);
                    }
                    else if (ex is IOException ex5)
                    {
                        DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { q });

                        if (ex5.InnerException is SocketException ex4a)
                        {
                            if (ex4a.SocketErrorCode == SocketError.TimedOut)
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NoReachableAuthority, "Request timed out for " + q.ToString());
                            else
                                failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "Socket error for " + q.ToString() + ": " + ex4a.SocketErrorCode.ToString());
                        }
                        else
                        {
                            failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.NetworkError, "IO error for " + q.ToString() + ": " + ex5.Message);
                        }

                        if (_eDnsClientSubnet is not null)
                            failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(_eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.Address));

                        _cache.CacheResponse(failureResponse);
                    }
                    else
                    {
                        DnsDatagram failureResponse = new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.ServerFailure, new DnsQuestionRecord[] { q });
                        failureResponse.AddDnsClientExtendedError(EDnsExtendedDnsErrorCode.Other, "Resolver exception for " + q.ToString() + ": " + ex.Message);

                        if (_eDnsClientSubnet is not null)
                            failureResponse.SetShadowEDnsClientSubnetOption(new EDnsClientSubnetOptionData(_eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.PrefixLength, _eDnsClientSubnet.Address));

                        _cache.CacheResponse(failureResponse);
                    }

                    throw;
                }
            });
        }

        private static async Task<DnsDatagram> QueryCacheAsync(IDnsCache cache, DnsDatagram request)
        {
            DnsDatagram cacheResponse = await cache.QueryAsync(request);
            if (cacheResponse is not null)
            {
                if ((cacheResponse.RCODE != DnsResponseCode.NoError) || (cacheResponse.Answer.Count > 0) || (cacheResponse.Authority.Count == 0) || cacheResponse.IsFirstAuthoritySOA())
                    return cacheResponse;
            }

            return null;
        }

        #endregion

        #region public

        public Task<DnsDatagram> RawResolveAsync(DnsDatagram request, CancellationToken cancellationToken = default)
        {
            return InternalResolveAsync(request, cancellationToken: cancellationToken);
        }

        public async Task<DnsDatagram> TsigResolveAsync(DnsDatagram request, TsigKey key, ushort fudge = 300, CancellationToken cancellationToken = default)
        {
            if (request.Identifier == 0)
                request.SetRandomIdentifier();

            DnsDatagram signedRequest = request.SignRequest(key, fudge);

            return await InternalResolveAsync(signedRequest, delegate (DnsDatagram signedResponse, CancellationToken cancellationToken1)
            {
                if (!signedResponse.VerifySignedResponse(signedRequest, key, out DnsDatagram unsignedResponse, out bool requestFailed, out DnsResponseCode rCode, out DnsTsigError error, out string errorMessage))
                {
                    if (requestFailed)
                        throw new DnsClientTsigRequestFailedException(rCode, error, "TSIG Request failed (Server RCODE=" + rCode.ToString() + ", Server TSIG Error=" + error.ToString() + ").");
                    else
                        throw new DnsClientTsigResponseVerificationException(rCode, error, "Response failed TSIG signature verification (Client RCODE=" + rCode.ToString() + "; Client TSIG Error=" + error.ToString() + (string.IsNullOrEmpty(errorMessage) ? "" : "; Client Error Mesage: " + errorMessage) + ").");
                }

                return Task.FromResult(unsignedResponse);
            }, false, null, cancellationToken);
        }

        public Task<DnsDatagram> TsigResolveAsync(DnsQuestionRecord question, TsigKey key, ushort fudge = 300, CancellationToken cancellationToken = default)
        {
            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }, null, null, null, _udpPayloadSize, EDnsHeaderFlags.None, _advancedForwardingClientSubnet ? null : EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(_eDnsClientSubnet));
            if (_advancedForwardingClientSubnet)
                request.SetShadowEDnsClientSubnetOption(_eDnsClientSubnet, true);

            return TsigResolveAsync(request, key, fudge, cancellationToken);
        }

        public Task<DnsDatagram> TsigResolveAsync(string domain, DnsResourceRecordType type, TsigKey key, ushort fudge = 300, CancellationToken cancellationToken = default)
        {
            if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress address))
                return TsigResolveAsync(new DnsQuestionRecord(address, DnsClass.IN), key, fudge, cancellationToken);
            else
                return TsigResolveAsync(new DnsQuestionRecord(domain, type, DnsClass.IN), key, fudge, cancellationToken);
        }

        public Task<DnsDatagram> ResolveAsync(DnsQuestionRecord question, CancellationToken cancellationToken = default)
        {
            if (_cache is not null)
                return InternalCachedResolveQueryAsync(question, cancellationToken);

            if (_dnssecValidation)
                return InternalDnssecResolveAsync(question, cancellationToken);

            DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, new DnsQuestionRecord[] { question }, null, null, null, _udpPayloadSize, EDnsHeaderFlags.None, _advancedForwardingClientSubnet ? null : EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(_eDnsClientSubnet));
            if (_advancedForwardingClientSubnet)
                request.SetShadowEDnsClientSubnetOption(_eDnsClientSubnet, true);

            return InternalNoDnssecResolveAsync(request, cancellationToken);
        }

        public Task<DnsDatagram> ResolveAsync(string domain, DnsResourceRecordType type, CancellationToken cancellationToken = default)
        {
            if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress address))
                return ResolveAsync(new DnsQuestionRecord(address, DnsClass.IN), cancellationToken);
            else
                return ResolveAsync(new DnsQuestionRecord(domain, type, DnsClass.IN), cancellationToken);
        }

        public Task<IReadOnlyList<string>> ResolveMXAsync(string domain, bool resolveIP = false, IPv6Mode ipv6Mode = IPv6Mode.Disabled, CancellationToken cancellationToken = default)
        {
            return ResolveMXAsync(this, domain, resolveIP, ipv6Mode, cancellationToken);
        }

        public async Task<IReadOnlyList<string>> ResolvePTRAsync(IPAddress ip, CancellationToken cancellationToken = default)
        {
            return ParseResponsePTR(await ResolveAsync(new DnsQuestionRecord(ip, DnsClass.IN), cancellationToken));
        }

        public async Task<IReadOnlyList<string>> ResolveTXTAsync(string domain, CancellationToken cancellationToken = default)
        {
            return ParseResponseTXT(await ResolveAsync(new DnsQuestionRecord(domain, DnsResourceRecordType.TXT, DnsClass.IN), cancellationToken));
        }

        public Task<IReadOnlyList<IPAddress>> ResolveIPAsync(string domain, IPv6Mode ipv6Mode = IPv6Mode.Disabled, CancellationToken cancellationToken = default)
        {
            return ResolveIPAsync(this, domain, ipv6Mode, cancellationToken);
        }

        public void AddTrustAnchor(string domain, DnsDSRecordData dsRecord)
        {
            if (_trustAnchors is null)
                _trustAnchors = new Dictionary<string, IReadOnlyList<DnsResourceRecord>>();

            DnsResourceRecord dsRR = new DnsResourceRecord(domain, DnsResourceRecordType.DS, DnsClass.IN, 0, dsRecord);

            if (_trustAnchors.TryGetValue(domain, out IReadOnlyList<DnsResourceRecord> existingRecords))
                _trustAnchors[domain] = [.. existingRecords, dsRR];
            else
                _trustAnchors.Add(domain, [dsRR]);
        }

        public void AddTrustAnchor(string domain, ushort keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType, byte[] digest)
        {
            AddTrustAnchor(domain, new DnsDSRecordData(keyTag, algorithm, digestType, digest));
        }

        public void AddTrustAnchor(string domain, ushort keyTag, DnssecAlgorithm algorithm, DnssecDigestType digestType, string digest)
        {
            AddTrustAnchor(domain, keyTag, algorithm, digestType, Convert.FromHexString(digest));
        }

        public void AddTrustAnchor(string domain, DnsDNSKEYRecordData dnskeyRecord)
        {
            AddTrustAnchor(domain, dnskeyRecord.CreateDS(domain, DnssecDigestType.SHA256));
        }

        public void AddTrustAnchor(string domain, DnsDnsKeyFlag flags, DnssecAlgorithm algorithm, DnssecPublicKey publicKey)
        {
            AddTrustAnchor(domain, new DnsDNSKEYRecordData(flags, 3, algorithm, publicKey));
        }

        public void AddTrustAnchor(string domain, DnsDnsKeyFlag flags, DnssecAlgorithm algorithm, byte[] publicKey)
        {
            AddTrustAnchor(domain, flags, algorithm, DnssecPublicKey.Parse(algorithm, publicKey));
        }

        public void AddTrustAnchor(string domain, DnsDnsKeyFlag flags, DnssecAlgorithm algorithm, string publicKey)
        {
            AddTrustAnchor(domain, flags, algorithm, Convert.FromBase64String(publicKey));
        }

        #endregion

        #region property

        internal static IReadOnlyList<NameServerAddress> IPv4RootHints
        { get { return IPv4_ROOT_HINTS; } }

        internal static IReadOnlyList<NameServerAddress> IPv6RootHints
        { get { return IPv6_ROOT_HINTS; } }

        public IReadOnlyList<NameServerAddress> Servers
        { get { return _servers; } }

        public IDnsCache Cache
        {
            get { return _cache; }
            set { _cache = value; }
        }

        public NetProxy Proxy
        {
            get { return _proxy; }
            set { _proxy = value; }
        }

        public IPv6Mode IPv6Mode
        {
            get { return _ipv6Mode; }
            set { _ipv6Mode = value; }
        }

        public ushort UdpPayloadSize
        {
            get { return _udpPayloadSize; }
            set { _udpPayloadSize = value; }
        }

        public bool RandomizeName
        {
            get { return _randomizeName; }
            set { _randomizeName = value; }
        }

        public bool EDnsPadding
        {
            get { return _eDnsPadding; }
            set { _eDnsPadding = value; }
        }

        public bool DnssecValidation
        {
            get { return _dnssecValidation; }
            set { _dnssecValidation = value; }
        }

        public NetworkAddress EDnsClientSubnet
        {
            get { return _eDnsClientSubnet; }
            set { _eDnsClientSubnet = value; }
        }

        public bool AdvancedForwardingClientSubnet
        {
            get { return _advancedForwardingClientSubnet; }
            set { _advancedForwardingClientSubnet = value; }
        }

        public string ConditionalForwardingZoneCut
        {
            get { return _conditionalForwardingZoneCut; }
            set
            {
                if (string.IsNullOrEmpty(value))
                    _conditionalForwardingZoneCut = null;
                else
                    _conditionalForwardingZoneCut = value;
            }
        }

        public int Retries
        {
            get { return _retries; }
            set { _retries = value; }
        }

        public int Timeout
        {
            get { return _timeout; }
            set { _timeout = value; }
        }

        public int Concurrency
        {
            get { return _concurrency; }
            set { _concurrency = value; }
        }

        public IDictionary<string, IReadOnlyList<DnsResourceRecord>> TrustAnchors
        {
            get
            {
                if (_trustAnchors is null)
                    _trustAnchors = new Dictionary<string, IReadOnlyList<DnsResourceRecord>>();

                return _trustAnchors;
            }
        }

        #endregion

        class ResolverData
        {
            public readonly DnsQuestionRecord Question;
            public readonly string ZoneCut;
            public readonly bool DnssecValidationState;
            public readonly IReadOnlyList<DnsResourceRecord> LastDSRecords;
            public readonly IList<NameServerAddress> NameServers;
            public readonly int NameServerIndex;
            public readonly int HopCount;
            public readonly DnsDatagram LastResponse;
            public readonly Exception LastException;

            public ResolverData(DnsQuestionRecord question, string zoneCut, bool dnssecValidationState, IReadOnlyList<DnsResourceRecord> lastDSRecords, IList<NameServerAddress> nameServers, int nameServerIndex, int hopCount, DnsDatagram lastResponse, Exception lastException)
            {
                Question = question;
                ZoneCut = zoneCut;
                DnssecValidationState = dnssecValidationState;
                LastDSRecords = lastDSRecords;
                NameServers = nameServers;
                NameServerIndex = nameServerIndex;
                HopCount = hopCount;
                LastResponse = lastResponse;
                LastException = lastException;
            }
        }

        public class ResolverContext
        {
            #region variables

            int _maxOutboundRequests = MAX_OUTBOUND_REQUESTS;

            int _maxCryptoFailures = KEY_TRAP_MAX_CRYPTO_FAILURES;
            int _maxCryptoValidations = KEY_TRAP_MAX_RRSET_VALIDATIONS_PER_SUSPENSION;
            int _maxCryptoSuspensions = KEY_TRAP_MAX_RRSET_VALIDATION_SUSPENSIONS;

            int _maxNsec3Hashes = NSEC3_MAX_HASHES_PER_SUSPENSION;
            int _maxNsec3Suspensions = NSEC3_MAX_SUSPENSIONS;

            #endregion

            #region public

            public void DecrementMaxOutboundRequests()
            {
                _maxOutboundRequests--;
            }

            public void DecrementMaxCryptoFailures()
            {
                _maxCryptoFailures--;
            }

            public void DecrementMaxCryptoValidations()
            {
                _maxCryptoValidations--;
            }

            public void DecrementMaxCryptoSuspensions()
            {
                _maxCryptoSuspensions--;
            }

            public void DecrementMaxNsec3Hashes()
            {
                _maxNsec3Hashes--;
            }

            public void DecrementMaxNsec3Suspensions()
            {
                _maxNsec3Suspensions--;
            }

            public void ResetMaxCryptoValidations()
            {
                _maxCryptoValidations = KEY_TRAP_MAX_RRSET_VALIDATIONS_PER_SUSPENSION;
            }

            public void ResetMaxNsec3Hashes()
            {
                _maxNsec3Hashes = NSEC3_MAX_HASHES_PER_SUSPENSION;
            }

            public bool CanProceedWithResolution()
            {
                if (_maxOutboundRequests < 1)
                    return false;

                if (_maxCryptoFailures < 1)
                    return false;

                if (_maxCryptoSuspensions <= 1)
                    return false;

                if (_maxNsec3Suspensions <= 1)
                    return false;

                return true;
            }

            public string GetCannotProceedWithResolutionReason()
            {
                if (_maxOutboundRequests < 1)
                    return "MaxOutboundRequests";

                if (_maxCryptoFailures < 1)
                    return "MaxCryptoFailures";

                if (_maxCryptoSuspensions <= 1)
                    return "MaxCryptoSuspensions";

                if (_maxNsec3Suspensions <= 1)
                    return "MaxNsec3Suspensions";

                return "Unknown";
            }

            #endregion

            #region properties

            public int MaxOutboundRequests
            { get { return _maxOutboundRequests; } }

            public int MaxCryptoFailures
            { get { return _maxCryptoFailures; } }

            public int MaxCryptoValidations
            { get { return _maxCryptoValidations; } }

            public int MaxCryptoSuspensions
            { get { return _maxCryptoSuspensions; } }

            public int MaxNsec3Hashes
            { get { return _maxNsec3Hashes; } }

            public int MaxNsec3Suspensions
            { get { return _maxNsec3Suspensions; } }

            #endregion
        }
    }
}
