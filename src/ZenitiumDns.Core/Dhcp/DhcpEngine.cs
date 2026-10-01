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
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace ZenitiumDns.Core.Dhcp
{
    public sealed class DhcpInterfaceAddress
    {
        public DhcpInterfaceAddress(IPAddress address, int prefixLength)
        {
            Address = address;
            PrefixLength = prefixLength;
        }

        public IPAddress Address { get; }

        public int PrefixLength { get; }

        public bool Contains(IPAddress address)
        {
            return DhcpUtilities.IsInNetwork(address, Address, PrefixLength);
        }
    }

    public sealed class DhcpInterfaceInfo
    {
        public string Name { get; init; }

        public int Index { get; init; }

        public IReadOnlyList<DhcpInterfaceAddress> Addresses { get; init; } = [];

        public IPAddress Gateway { get; init; }

        public byte[] HardwareAddress { get; init; } = [];
    }

    public enum DhcpReplyMode
    {
        Broadcast,
        Unicast,
        HardwareUnicast
    }

    public sealed class DhcpReply
    {
        public DhcpMessage Message { get; init; }

        public DhcpReplyMode Mode { get; init; }

        public IPEndPoint Destination { get; init; }

        public int DelayMs { get; init; }

        public IPAddress SourceAddress { get; init; }

        public int MaxMessageSize { get; init; } = DhcpMessage.DEFAULT_MAX_MESSAGE_SIZE;
    }

    public sealed class DhcpEngineSettings
    {
        public bool PingCheck { get; init; } = true;

        public int PingTimeoutMs { get; init; } = 500;

        public int ResponseDelayMs { get; init; }

        public int MinSecs { get; init; }

        public bool OffersPaused { get; init; }

        public bool Serving { get; init; } = true;

        public uint DefaultLeaseTime { get; init; } = 3600;
    }

    public sealed class DhcpEngine
    {
        #region variables

        const int OFFER_HOLD_SECONDS = 60;
        const int DECLINE_HOLD_SECONDS = 600;
        const int MAX_PING_ATTEMPTS = 5;

        static readonly byte[] _essentialOrder = [(byte)DhcpOptionCode.SubnetMask, (byte)DhcpOptionCode.Router, (byte)DhcpOptionCode.DomainNameServer, (byte)DhcpOptionCode.DomainName, (byte)DhcpOptionCode.BroadcastAddress, (byte)DhcpOptionCode.HostName];

        readonly DhcpLeaseStore _store;
        readonly Func<IPAddress, int, Task<bool>> _ping;
        readonly Action<string> _log;

        DhcpConfiguration _config = DhcpConfiguration.Empty;
        DhcpEngineSettings _settings = new DhcpEngineSettings();
        Func<IPAddress, bool> _isOwnServerIdentifier = delegate (IPAddress address) { return false; };

        readonly Dictionary<string, SemaphoreSlim> _clientLocks = new Dictionary<string, SemaphoreSlim>(StringComparer.Ordinal);

        long _discovers;
        long _offers;
        long _requests;
        long _acks;
        long _naks;
        long _declines;
        long _releases;
        long _informs;
        long _ignored;
        long _poolExhausted;
        long _conflicts;

        #endregion

        #region constructor

        public DhcpEngine(DhcpLeaseStore store, Func<IPAddress, int, Task<bool>> ping, Action<string> log)
        {
            _store = store;
            _ping = ping;
            _log = log ?? delegate (string message) { };
        }

        #endregion

        #region private types

        private sealed class RequestContext
        {
            public DhcpMessage Request;
            public DhcpInterfaceInfo Interface;
            public DhcpConfiguration Config;
            public DhcpEngineSettings Settings;
            public HashSet<string> Tags;
            public string ClientKey;
            public byte[] ClientId;
            public bool Relayed;
            public bool UseLinkAddress;
            public IPAddress LinkAddress;
            public IPAddress ServerAddress;
            public List<DhcpInterfaceAddress> Networks;
            public DhcpHostRule Host;
            public List<RangeCandidate> Ranges;
            public string ClientHostName;
            public string VendorClass;
            public bool Bootp;
            public DateTime Now;
        }

        private sealed class RangeCandidate
        {
            public DhcpRangeRule Rule;
            public IPAddress Network;
            public int PrefixLength;
            public IPAddress ServerAddress;

            public bool ContainsNetwork(IPAddress address)
            {
                return DhcpUtilities.IsInNetwork(address, Network, PrefixLength);
            }
        }

        #endregion

        #region private

        private SemaphoreSlim GetClientLock(string clientKey)
        {
            lock (_clientLocks)
            {
                if (!_clientLocks.TryGetValue(clientKey, out SemaphoreSlim semaphore))
                {
                    if (_clientLocks.Count > 10000)
                    {
                        List<string> idle = new List<string>();

                        foreach (KeyValuePair<string, SemaphoreSlim> entry in _clientLocks)
                        {
                            if (entry.Value.CurrentCount == 1)
                                idle.Add(entry.Key);
                        }

                        foreach (string key in idle)
                            _clientLocks.Remove(key);
                    }

                    semaphore = new SemaphoreSlim(1, 1);
                    _clientLocks.Add(clientKey, semaphore);
                }

                return semaphore;
            }
        }

        private static string GetClientHostName(DhcpMessage request)
        {
            string name = request.GetStringOption(DhcpOptionCode.HostName);

            if (name is null)
            {
                byte[] fqdn = request.GetOptionValue(DhcpOptionCode.ClientFqdn);

                if ((fqdn is not null) && (fqdn.Length > 3))
                {
                    if ((fqdn[0] & 0x04) != 0)
                    {
                        int length = fqdn[3];
                        if ((length > 0) && (4 + length <= fqdn.Length))
                            name = Encoding.ASCII.GetString(fqdn, 4, length);
                    }
                    else
                    {
                        name = Encoding.ASCII.GetString(fqdn, 3, fqdn.Length - 3);
                    }
                }
            }

            return DhcpUtilities.SanitizeHostName(name);
        }

        private static byte[] GetRelaySubOption(DhcpMessage request, byte subCode)
        {
            byte[] relay = request.GetOptionValue(DhcpOptionCode.RelayAgentInformation);
            if (relay is null)
                return null;

            int i = 0;

            while (i + 2 <= relay.Length)
            {
                byte code = relay[i];
                int length = relay[i + 1];

                if (i + 2 + length > relay.Length)
                    return null;

                if (code == subCode)
                    return relay.AsSpan(i + 2, length).ToArray();

                i += 2 + length;
            }

            return null;
        }

        private static bool ContainsSequence(byte[] haystack, byte[] needle, bool anyOffset)
        {
            if ((haystack is null) || (needle is null))
                return false;

            if (needle.Length == 0)
                return true;

            int step = anyOffset ? 1 : needle.Length;

            for (int i = 0; i + needle.Length <= haystack.Length; i += step)
            {
                if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle))
                    return true;
            }

            return false;
        }

        private static bool ContainsText(byte[] haystack, byte[] needle)
        {
            if ((haystack is null) || (needle is null))
                return false;

            string hay = Encoding.UTF8.GetString(haystack);
            string need = Encoding.UTF8.GetString(needle);
            return hay.Contains(need, StringComparison.OrdinalIgnoreCase);
        }

        private static bool MatchesViEnterprise(byte[] value, uint enterprise)
        {
            if (value is null)
                return false;

            int i = 0;

            while (i + 5 <= value.Length)
            {
                uint number = BinaryPrimitives.ReadUInt32BigEndian(value.AsSpan(i));
                int length = value[i + 4];

                if (number == enterprise)
                    return true;

                i += 5 + length;
            }

            return false;
        }

        private static void ApplyMatches(RequestContext ctx)
        {
            DhcpMessage request = ctx.Request;

            foreach (DhcpMatchRule rule in ctx.Config.Matches)
            {
                bool matched = false;

                switch (rule.Kind)
                {
                    case DhcpMatchKind.Option:
                        {
                            byte[] value = request.GetOption(rule.OptionCode)?.Value;

                            if (value is not null)
                            {
                                if (rule.Value is null)
                                    matched = true;
                                else if (rule.ValueIsText)
                                    matched = ContainsText(value, rule.Value);
                                else
                                    matched = ContainsSequence(value, rule.Value, false);
                            }
                        }
                        break;

                    case DhcpMatchKind.ViEncapsulated:
                        matched = MatchesViEnterprise(request.GetOptionValue(DhcpOptionCode.VendorIdentifyingVendorSpecific), rule.Enterprise) || MatchesViEnterprise(request.GetOption(124)?.Value, rule.Enterprise);
                        break;

                    case DhcpMatchKind.VendorClass:
                        if (rule.Enterprise != 0)
                            matched = MatchesViEnterprise(request.GetOption(124)?.Value, rule.Enterprise) && ContainsText(request.GetOption(124)?.Value, rule.Value);
                        else
                            matched = ContainsText(request.GetOptionValue(DhcpOptionCode.VendorClassIdentifier), rule.Value);

                        break;

                    case DhcpMatchKind.UserClass:
                        matched = ContainsText(request.GetOptionValue(DhcpOptionCode.UserClass), rule.Value);
                        break;

                    case DhcpMatchKind.HardwareAddress:
                        matched = rule.HardwarePattern.Matches(request.HardwareType, request.ClientHardwareAddress);
                        break;

                    case DhcpMatchKind.CircuitId:
                        matched = SequenceEquals(GetRelaySubOption(request, 1), rule.Value);
                        break;

                    case DhcpMatchKind.RemoteId:
                        matched = SequenceEquals(GetRelaySubOption(request, 2), rule.Value);
                        break;

                    case DhcpMatchKind.SubscriberId:
                        matched = SequenceEquals(GetRelaySubOption(request, 6), rule.Value);
                        break;
                }

                if (matched)
                    ctx.Tags.Add(rule.SetTag);
            }
        }

        private static bool SequenceEquals(byte[] a, byte[] b)
        {
            if ((a is null) || (b is null))
                return false;

            return a.AsSpan().SequenceEqual(b);
        }

        private static DhcpHostRule FindHost(RequestContext ctx)
        {
            DhcpConfiguration config = ctx.Config;
            DhcpMessage request = ctx.Request;

            if (ctx.ClientId is not null)
            {
                foreach (DhcpHostRule host in config.Hosts)
                {
                    if (!DhcpTagCondition.AllMatch(host.Conditions, ctx.Tags))
                        continue;

                    foreach (byte[] id in host.ClientIds)
                    {
                        if (id.AsSpan().SequenceEqual(ctx.ClientId))
                            return host;
                    }
                }
            }

            DhcpHostRule wildcardMatch = null;

            foreach (DhcpHostRule host in config.Hosts)
            {
                if ((host.ClientIds.Count > 0) && (ctx.ClientId is not null) && !host.IgnoreClientId && (host.HardwareAddresses.Count == 0))
                    continue;

                if (!DhcpTagCondition.AllMatch(host.Conditions, ctx.Tags))
                    continue;

                foreach (DhcpHardwarePattern pattern in host.HardwareAddresses)
                {
                    if (pattern.Matches(request.HardwareType, request.ClientHardwareAddress))
                    {
                        if (!pattern.HasWildcard)
                            return host;

                        wildcardMatch ??= host;
                    }
                }
            }

            if (wildcardMatch is not null)
                return wildcardMatch;

            if (ctx.ClientHostName is not null)
            {
                foreach (DhcpHostRule host in config.Hosts)
                {
                    if (host.MatchByHostName && DhcpTagCondition.AllMatch(host.Conditions, ctx.Tags) && string.Equals(host.HostName, ctx.ClientHostName, StringComparison.OrdinalIgnoreCase))
                        return host;
                }
            }

            return null;
        }

        private static List<RangeCandidate> FindRanges(RequestContext ctx)
        {
            List<RangeCandidate> result = new List<RangeCandidate>();

            foreach (DhcpRangeRule rule in ctx.Config.Ranges)
            {
                if (!DhcpTagCondition.AllMatch(rule.Conditions, ctx.Tags))
                    continue;

                if (ctx.UseLinkAddress)
                {
                    if (rule.Netmask is null)
                        continue;

                    DhcpUtilities.TryGetPrefixLength(rule.Netmask, out int prefix);

                    if (!DhcpUtilities.IsInNetwork(ctx.LinkAddress, rule.Start, prefix))
                        continue;

                    result.Add(new RangeCandidate() { Rule = rule, Network = rule.Start, PrefixLength = prefix, ServerAddress = ctx.ServerAddress });
                    continue;
                }

                foreach (DhcpInterfaceAddress network in ctx.Networks)
                {
                    int prefix = network.PrefixLength;

                    if (rule.Netmask is not null)
                        DhcpUtilities.TryGetPrefixLength(rule.Netmask, out prefix);

                    if (network.Contains(rule.Start) && DhcpUtilities.IsInNetwork(network.Address, rule.Start, prefix))
                    {
                        result.Add(new RangeCandidate() { Rule = rule, Network = rule.Start, PrefixLength = prefix, ServerAddress = network.Address });
                        break;
                    }
                }
            }

            return result;
        }

        private static RangeCandidate FindRangeForAddress(RequestContext ctx, IPAddress address)
        {
            foreach (RangeCandidate candidate in ctx.Ranges)
            {
                if (candidate.ContainsNetwork(address))
                    return candidate;
            }

            return null;
        }

        private bool IsReservedForOther(RequestContext ctx, IPAddress address)
        {
            foreach (DhcpHostRule host in ctx.Config.Hosts)
            {
                if ((host.Address is not null) && host.Address.Equals(address) && !ReferenceEquals(host, ctx.Host))
                    return true;
            }

            return false;
        }

        private static bool IsUsableHostAddress(RangeCandidate range, uint value)
        {
            uint mask = DhcpUtilities.GetMask(range.PrefixLength);
            uint network = DhcpUtilities.ToUInt32(range.Network) & mask;
            uint broadcast = network | ~mask;

            return (value != network) && (value != broadcast);
        }

        private bool IsInfrastructureAddress(RequestContext ctx, IPAddress address)
        {
            foreach (DhcpInterfaceAddress local in ctx.Interface.Addresses)
            {
                if (local.Address.Equals(address))
                    return true;
            }

            if ((ctx.Interface.Gateway is not null) && ctx.Interface.Gateway.Equals(address))
                return true;

            if (ctx.Relayed && ctx.Request.RelayAddress.Equals(address))
                return true;

            return _isOwnServerIdentifier(address);
        }

        private bool IsAddressValidForClient(RequestContext ctx, IPAddress address, out RangeCandidate range)
        {
            range = FindRangeForAddress(ctx, address);

            if (range is null)
                return false;

            if (!IsUsableHostAddress(range, DhcpUtilities.ToUInt32(address)))
                return false;

            if ((ctx.Host is not null) && (ctx.Host.Address is not null) && (FindRangeForAddress(ctx, ctx.Host.Address) is not null))
                return ctx.Host.Address.Equals(address);

            if (IsReservedForOther(ctx, address) || IsInfrastructureAddress(ctx, address))
                return false;

            foreach (RangeCandidate candidate in ctx.Ranges)
            {
                if (candidate.Rule.ContainsInPool(address))
                {
                    range = candidate;
                    return true;
                }
            }

            return false;
        }

        private bool IsFreeFor(DhcpLease lease, string clientKey, DateTime now)
        {
            if (lease is null)
                return true;

            if (lease.ClientKey == clientKey)
                return lease.State != DhcpLeaseState.Declined || (lease.Expires <= now);

            switch (lease.State)
            {
                case DhcpLeaseState.Free:
                case DhcpLeaseState.Released:
                case DhcpLeaseState.Expired:
                    return true;

                case DhcpLeaseState.Offered:
                case DhcpLeaseState.Bound:
                case DhcpLeaseState.Declined:
                    return lease.Expires <= now;

                default:
                    return false;
            }
        }

        private uint GetLeaseTime(RequestContext ctx, RangeCandidate range)
        {
            uint leaseTime = 0;

            if ((ctx.Host is not null) && (ctx.Host.LeaseTime != 0))
                leaseTime = ctx.Host.LeaseTime;
            else if ((range is not null) && (range.Rule.LeaseTime != 0))
                leaseTime = range.Rule.LeaseTime;
            else
                leaseTime = ctx.Settings.DefaultLeaseTime;

            if (ctx.Bootp)
                return DhcpUtilities.INFINITE_LEASE;

            byte[] requested = ctx.Request.GetOptionValue(DhcpOptionCode.LeaseTime);
            if ((requested is not null) && (requested.Length == 4))
            {
                uint wanted = BinaryPrimitives.ReadUInt32BigEndian(requested);
                if ((wanted >= DhcpUtilities.MIN_LEASE_TIME) && (wanted < leaseTime))
                    leaseTime = wanted;
            }

            return Math.Max(DhcpUtilities.MIN_LEASE_TIME, leaseTime);
        }

        private string GetEffectiveHostName(RequestContext ctx)
        {
            if ((ctx.Host is not null) && (ctx.Host.HostName is not null))
                return ctx.Host.HostName;

            bool ignoreNames = false;

            foreach (DhcpTagListRule rule in ctx.Config.IgnoreNamesRules)
            {
                if (DhcpTagCondition.AllMatch(rule.Conditions, ctx.Tags))
                {
                    ignoreNames = true;
                    break;
                }
            }

            if (!ignoreNames && (ctx.ClientHostName is not null))
                return ctx.ClientHostName;

            foreach (DhcpTagListRule rule in ctx.Config.GenerateNamesRules)
            {
                if (DhcpTagCondition.AllMatch(rule.Conditions, ctx.Tags))
                    return DhcpUtilities.FormatHardwareAddress(ctx.Request.ClientHardwareAddress).Replace(':', '-');
            }

            return null;
        }

        private DhcpLease CreateLease(RequestContext ctx, IPAddress address, DhcpLeaseState state, DateTime expires)
        {
            return new DhcpLease()
            {
                Address = address,
                ClientKey = ctx.ClientKey,
                HardwareType = ctx.Request.HardwareType,
                HardwareAddress = ctx.Request.ClientHardwareAddress,
                ClientId = ctx.ClientId,
                ClientHostName = ctx.ClientHostName,
                HostName = GetEffectiveHostName(ctx),
                VendorClass = ctx.VendorClass,
                Start = ctx.Now,
                Expires = expires,
                State = state,
                Reserved = (ctx.Host is not null) && (ctx.Host.Address is not null) && ctx.Host.Address.Equals(address),
                Updated = ctx.Now
            };
        }

        private static DateTime GetExpiry(DateTime now, uint leaseTime)
        {
            if (leaseTime == DhcpUtilities.INFINITE_LEASE)
                return DateTime.MaxValue;

            return now.AddSeconds(leaseTime);
        }

        private int CountActiveLeases(DateTime now)
        {
            return _store.CountActive(now);
        }

        private async Task<(IPAddress Address, RangeCandidate Range)> AllocateAsync(RequestContext ctx)
        {
            DateTime now = ctx.Now;

            if ((ctx.Host is not null) && (ctx.Host.Address is not null))
            {
                RangeCandidate range = FindRangeForAddress(ctx, ctx.Host.Address);

                if (range is not null)
                {
                    DhcpLease existing = _store.Get(ctx.Host.Address);

                    if (IsFreeFor(existing, ctx.ClientKey, now))
                    {
                        DhcpLease offer = CreateLease(ctx, ctx.Host.Address, DhcpLeaseState.Offered, now.AddSeconds(OFFER_HOLD_SECONDS));

                        if (_store.TryPut(offer, delegate (DhcpLease current) { return IsFreeFor(current, ctx.ClientKey, now); }, out _))
                            return (ctx.Host.Address, range);
                    }

                    _log("DHCP Server cannot offer the reserved address " + ctx.Host.Address + " to " + ctx.ClientKey + " because another client still holds a lease for it.");
                }
            }

            foreach (DhcpLease lease in _store.GetByClient(ctx.ClientKey))
            {
                if ((lease.State == DhcpLeaseState.Declined) || (lease.State == DhcpLeaseState.Free))
                    continue;

                if (!IsAddressValidForClient(ctx, lease.Address, out RangeCandidate range))
                    continue;

                if (lease.IsActive(now) && (lease.State == DhcpLeaseState.Bound))
                    return (lease.Address, range);

                DhcpLease offer = CreateLease(ctx, lease.Address, DhcpLeaseState.Offered, now.AddSeconds(OFFER_HOLD_SECONDS));

                if (_store.TryPut(offer, delegate (DhcpLease current) { return IsFreeFor(current, ctx.ClientKey, now); }, out _))
                    return (lease.Address, range);
            }

            if (ctx.Host is null || ctx.Host.Address is null || (FindRangeForAddress(ctx, ctx.Host.Address) is null))
            {
                if (CountActiveLeases(now) >= ctx.Config.LeaseMax)
                {
                    Interlocked.Increment(ref _poolExhausted);
                    _log("DHCP Server reached the maximum of " + ctx.Config.LeaseMax + " leases (dhcp-lease-max).");
                    return (null, null);
                }
            }

            IPAddress requested = ctx.Request.GetAddressOption(DhcpOptionCode.RequestedAddress);

            if ((requested is not null) && IsAddressValidForClient(ctx, requested, out RangeCandidate requestedRange))
            {
                if (IsFreeFor(_store.Get(requested), ctx.ClientKey, now) && await TryReserveAsync(ctx, requested, true))
                    return (requested, requestedRange);
            }

            for (int attempt = 0; attempt < MAX_PING_ATTEMPTS; attempt++)
            {
                (IPAddress candidate, RangeCandidate range) = FindFreeAddress(ctx);

                if (candidate is null)
                    break;

                if (await TryReserveAsync(ctx, candidate, false))
                    return (candidate, range);
            }

            Interlocked.Increment(ref _poolExhausted);
            _log("DHCP Server has no free address for " + ctx.ClientKey + " on " + (ctx.Relayed ? "relay " + ctx.Request.RelayAddress : ctx.Interface.Name) + ".");
            return (null, null);
        }

        private async Task<bool> TryReserveAsync(RequestContext ctx, IPAddress address, bool requestedByClient)
        {
            DateTime now = ctx.Now;
            DhcpLease offer = CreateLease(ctx, address, DhcpLeaseState.Offered, now.AddSeconds(OFFER_HOLD_SECONDS));

            if (!_store.TryPut(offer, delegate (DhcpLease current) { return IsFreeFor(current, ctx.ClientKey, now); }, out _))
                return false;

            if (!ctx.Settings.PingCheck || ctx.Config.NoPing || (_ping is null))
                return true;

            bool inUse;

            try
            {
                inUse = await _ping(address, ctx.Settings.PingTimeoutMs);
            }
            catch
            {
                inUse = false;
            }

            if (!inUse)
                return true;

            Interlocked.Increment(ref _conflicts);
            _log("DHCP Server found " + address + " already in use (ping answered) and blocks it for " + (DECLINE_HOLD_SECONDS / 60) + " minutes.");

            _store.Put(new DhcpLease()
            {
                Address = address,
                ClientKey = "",
                HardwareAddress = [],
                Start = now,
                Expires = now.AddSeconds(DECLINE_HOLD_SECONDS),
                State = DhcpLeaseState.Declined,
                Updated = now
            });

            return false;
        }

        private (IPAddress, RangeCandidate) FindFreeAddress(RequestContext ctx)
        {
            DateTime now = ctx.Now;

            foreach (RangeCandidate range in ctx.Ranges)
            {
                DhcpRangeRule rule = range.Rule;

                if (rule.StaticOnly)
                    continue;

                uint start = rule.StartValue;
                uint end = rule.EndValue;
                uint size = end - start + 1;
                uint offset = ctx.Config.SequentialIp ? 0 : DhcpUtilities.GetStableHash(ctx.ClientKey) % size;

                IPAddress oldestAddress = null;
                DateTime oldestUpdated = DateTime.MaxValue;

                for (uint i = 0; i < size; i++)
                {
                    uint value = start + ((offset + i) % size);

                    if (!IsUsableHostAddress(range, value))
                        continue;

                    IPAddress candidate = DhcpUtilities.ToAddress(value);

                    if (IsReservedForOther(ctx, candidate) || IsInfrastructureAddress(ctx, candidate))
                        continue;

                    DhcpLease lease = _store.Get(value);

                    if (lease is null)
                        return (candidate, range);

                    if (!IsFreeFor(lease, ctx.ClientKey, now))
                        continue;

                    if ((lease.State == DhcpLeaseState.Free) || (lease.ClientKey == ctx.ClientKey))
                        return (candidate, range);

                    if (lease.Updated < oldestUpdated)
                    {
                        oldestUpdated = lease.Updated;
                        oldestAddress = candidate;
                    }
                }

                if (oldestAddress is not null)
                    return (oldestAddress, range);
            }

            return (null, null);
        }

        private List<DhcpOptionRule> SelectOptionRules(RequestContext ctx)
        {
            Dictionary<(byte Encap, bool Vi, uint Enterprise, byte Code), (DhcpOptionRule Rule, int Score)> selected = new Dictionary<(byte, bool, uint, byte), (DhcpOptionRule, int)>();

            foreach (DhcpOptionRule rule in ctx.Config.Options)
            {
                if (!DhcpTagCondition.AllMatch(rule.Conditions, ctx.Tags))
                    continue;

                byte encap = rule.EncapsulatedIn;

                if (rule.VendorClass is not null)
                {
                    if ((ctx.VendorClass is null) || !ctx.VendorClass.Contains(rule.VendorClass, StringComparison.OrdinalIgnoreCase))
                        continue;

                    encap = (byte)DhcpOptionCode.VendorSpecific;
                }

                int score = rule.Conditions.Count * 2 + (rule.VendorClass is not null ? 1 : 0) - (rule.Weak ? 1000 : 0);
                (byte, bool, uint, byte) key = (encap, rule.IsViEncapsulated, rule.ViEnterprise, rule.Code);

                if (!selected.TryGetValue(key, out (DhcpOptionRule Rule, int Score) existing) || (score >= existing.Score))
                    selected[key] = (rule, score);
            }

            List<DhcpOptionRule> result = new List<DhcpOptionRule>(selected.Count);
            foreach ((DhcpOptionRule rule, int _) in selected.Values)
                result.Add(rule);

            result.Sort(delegate (DhcpOptionRule x, DhcpOptionRule y) { return x.Line.CompareTo(y.Line); });
            return result;
        }

        private static byte[] ResolveValue(DhcpOptionRule rule, IPAddress serverAddress)
        {
            if (!rule.UsesServerAddress || (serverAddress is null))
                return rule.Value;

            byte[] value = (byte[])rule.Value.Clone();
            byte[] server = serverAddress.GetAddressBytes();

            for (int i = 0; i + 4 <= value.Length; i += 4)
            {
                if ((value[i] == 0) && (value[i + 1] == 0) && (value[i + 2] == 0) && (value[i + 3] == 0))
                    server.CopyTo(value, i);
            }

            return value;
        }

        private static byte[] EncodeFqdnReply(byte[] clientFqdn, string hostName, string domain)
        {
            byte clientFlags = clientFqdn[0];
            bool encoded = (clientFlags & 0x04) != 0;
            bool clientWantsUpdate = (clientFlags & 0x01) != 0;

            byte flags = 0x01;
            if (!clientWantsUpdate)
                flags |= 0x02;

            if (encoded)
                flags |= 0x04;

            List<byte> value = new List<byte>() { flags, 255, 255 };

            if (hostName is not null)
            {
                string fqdn = domain is null ? hostName : hostName + "." + domain;

                if (encoded)
                {
                    foreach (string label in fqdn.Split('.'))
                    {
                        byte[] bytes = Encoding.ASCII.GetBytes(label);
                        value.Add((byte)bytes.Length);
                        value.AddRange(bytes);
                    }

                    if (domain is not null)
                        value.Add(0);
                }
                else
                {
                    value.AddRange(Encoding.ASCII.GetBytes(fqdn));
                }
            }

            return value.ToArray();
        }

        private string GetDomain(RequestContext ctx, IPAddress address)
        {
            foreach (DhcpDomainRule rule in ctx.Config.Domains)
            {
                if ((rule.Start is not null) && (address is not null) && rule.Matches(address))
                    return rule.Domain;
            }

            foreach (DhcpDomainRule rule in ctx.Config.Domains)
            {
                if (rule.Start is null)
                    return rule.Domain;
            }

            return null;
        }

        private DhcpMessage BuildReply(RequestContext ctx, DhcpMessageType type, IPAddress yourAddress, RangeCandidate range, uint leaseTime, bool rapidCommit)
        {
            DhcpMessage request = ctx.Request;
            IPAddress serverAddress = range?.ServerAddress ?? ctx.ServerAddress;

            DhcpMessage reply = new DhcpMessage()
            {
                Op = DhcpMessage.OP_BOOTREPLY,
                HardwareType = request.HardwareType,
                HardwareAddressLength = request.HardwareAddressLength,
                Hops = 0,
                TransactionId = request.TransactionId,
                Seconds = 0,
                Flags = request.Flags,
                ClientAddress = (type == DhcpMessageType.Ack) && !request.ClientAddress.Equals(IPAddress.Any) ? request.ClientAddress : IPAddress.Any,
                YourAddress = ((type == DhcpMessageType.Nak) || (type == DhcpMessageType.Inform)) ? IPAddress.Any : (yourAddress ?? IPAddress.Any),
                ServerAddress = IPAddress.Any,
                RelayAddress = request.RelayAddress,
                ClientHardwareAddress = request.ClientHardwareAddress,
                HasMagicCookie = request.HasMagicCookie,
                AllowOverload = !ctx.Config.NoOverride
            };

            if (type == DhcpMessageType.Inform)
                reply.ClientAddress = request.ClientAddress;

            if (!request.HasMagicCookie)
            {
                ApplyBoot(ctx, reply);
                return reply;
            }

            if (!ctx.Bootp)
            {
                reply.SetOption(DhcpOptionCode.MessageType, [(byte)(type == DhcpMessageType.Inform ? DhcpMessageType.Ack : type)]);
                reply.SetOption(DhcpOptionCode.ServerIdentifier, serverAddress.GetAddressBytes());
            }

            byte[] requestClientId = request.GetOptionValue(DhcpOptionCode.ClientIdentifier);

            if (type == DhcpMessageType.Nak)
            {
                reply.SetOption(DhcpOptionCode.Message, Encoding.ASCII.GetBytes("wrong address or network"));

                if (requestClientId is not null)
                    reply.SetOption(DhcpOptionCode.ClientIdentifier, requestClientId);

                AppendRelayInformation(ctx, reply);
                return reply;
            }

            ApplyBoot(ctx, reply);

            if ((type != DhcpMessageType.Inform) && !ctx.Bootp)
            {
                byte[] lease = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(lease, leaseTime);
                reply.SetOption(DhcpOptionCode.LeaseTime, lease);

                if (leaseTime != DhcpUtilities.INFINITE_LEASE)
                {
                    byte[] t1 = new byte[4];
                    byte[] t2 = new byte[4];
                    BinaryPrimitives.WriteUInt32BigEndian(t1, leaseTime / 2);
                    BinaryPrimitives.WriteUInt32BigEndian(t2, (uint)(leaseTime * 7UL / 8));
                    reply.SetOption(DhcpOptionCode.RenewalTime, t1);
                    reply.SetOption(DhcpOptionCode.RebindingTime, t2);
                }
            }

            if (rapidCommit)
                reply.SetOption(DhcpOptionCode.RapidCommit, []);

            Dictionary<byte, byte[]> candidates = new Dictionary<byte, byte[]>();
            HashSet<byte> forced = new HashSet<byte>();
            HashSet<byte> suppressed = new HashSet<byte>();
            IPAddress addressForOptions = yourAddress ?? request.ClientAddress;

            if (range is not null)
            {
                IPAddress netmask = range.Rule.Netmask ?? DhcpUtilities.ToAddress(DhcpUtilities.GetMask(range.PrefixLength));
                candidates[(byte)DhcpOptionCode.SubnetMask] = netmask.GetAddressBytes();

                IPAddress broadcast = range.Rule.Broadcast ?? DhcpUtilities.ToAddress((DhcpUtilities.ToUInt32(range.Network) & DhcpUtilities.GetMask(range.PrefixLength)) | ~DhcpUtilities.GetMask(range.PrefixLength));
                candidates[(byte)DhcpOptionCode.BroadcastAddress] = broadcast.GetAddressBytes();

                if (!ctx.Relayed && (ctx.Interface.Gateway is not null) && range.ContainsNetwork(ctx.Interface.Gateway))
                    candidates[(byte)DhcpOptionCode.Router] = ctx.Interface.Gateway.GetAddressBytes();
            }

            candidates[(byte)DhcpOptionCode.DomainNameServer] = serverAddress.GetAddressBytes();

            string domain = GetDomain(ctx, addressForOptions);
            if (domain is not null)
                candidates[(byte)DhcpOptionCode.DomainName] = Encoding.ASCII.GetBytes(domain);

            string hostName = GetEffectiveHostName(ctx);
            if ((ctx.Host is not null) && (ctx.Host.HostName is not null))
                candidates[(byte)DhcpOptionCode.HostName] = Encoding.ASCII.GetBytes(ctx.Host.HostName);

            Dictionary<byte, List<byte>> encapsulated = new Dictionary<byte, List<byte>>();
            Dictionary<uint, List<byte>> viEncapsulated = new Dictionary<uint, List<byte>>();

            foreach (DhcpOptionRule rule in SelectOptionRules(ctx))
            {
                byte[] value = ResolveValue(rule, serverAddress);

                if (rule.IsViEncapsulated)
                {
                    if (rule.Suppress)
                        continue;

                    if (!viEncapsulated.TryGetValue(rule.ViEnterprise, out List<byte> list))
                    {
                        list = new List<byte>();
                        viEncapsulated.Add(rule.ViEnterprise, list);
                    }

                    list.Add(rule.Code);
                    list.Add((byte)value.Length);
                    list.AddRange(value);
                    continue;
                }

                byte encap = rule.VendorClass is not null ? (byte)DhcpOptionCode.VendorSpecific : rule.EncapsulatedIn;

                if (encap != 0)
                {
                    if (rule.Suppress)
                        continue;

                    if (!encapsulated.TryGetValue(encap, out List<byte> list))
                    {
                        list = new List<byte>();
                        encapsulated.Add(encap, list);
                    }

                    list.Add(rule.Code);
                    list.Add((byte)value.Length);
                    list.AddRange(value);

                    if (rule.Force)
                        forced.Add(encap);

                    continue;
                }

                if (rule.Suppress)
                {
                    candidates.Remove(rule.Code);
                    suppressed.Add(rule.Code);
                    continue;
                }

                if ((rule.Code == (byte)DhcpOptionCode.RenewalTime) || (rule.Code == (byte)DhcpOptionCode.RebindingTime))
                {
                    if ((type != DhcpMessageType.Inform) && (leaseTime != DhcpUtilities.INFINITE_LEASE) && !ctx.Bootp)
                        reply.SetOption(rule.Code, value);

                    continue;
                }

                if ((rule.Code == (byte)DhcpOptionCode.HostName) && (ctx.Host is not null) && (ctx.Host.HostName is not null))
                    continue;

                candidates[rule.Code] = value;

                if (rule.Force)
                    forced.Add(rule.Code);
            }

            foreach (KeyValuePair<byte, List<byte>> entry in encapsulated)
            {
                if (!suppressed.Contains(entry.Key))
                    candidates[entry.Key] = entry.Value.ToArray();
            }

            if (viEncapsulated.Count > 0)
            {
                List<byte> vi = new List<byte>();

                foreach (KeyValuePair<uint, List<byte>> entry in viEncapsulated)
                {
                    if (entry.Value.Count > 255)
                        continue;

                    byte[] enterprise = new byte[4];
                    BinaryPrimitives.WriteUInt32BigEndian(enterprise, entry.Key);
                    vi.AddRange(enterprise);
                    vi.Add((byte)entry.Value.Count);
                    vi.AddRange(entry.Value);
                }

                if (vi.Count > 0)
                    candidates[(byte)DhcpOptionCode.VendorIdentifyingVendorSpecific] = vi.ToArray();
            }

            byte[] parameterRequest = request.GetOptionValue(DhcpOptionCode.ParameterRequestList);
            HashSet<byte> added = new HashSet<byte>();

            if (parameterRequest is not null)
            {
                foreach (byte code in parameterRequest)
                {
                    if (candidates.TryGetValue(code, out byte[] value) && added.Add(code))
                        reply.SetOption(code, value);
                }
            }

            foreach (byte code in _essentialOrder)
            {
                if (candidates.TryGetValue(code, out byte[] value) && added.Add(code))
                    reply.SetOption(code, value);
            }

            foreach (KeyValuePair<byte, byte[]> entry in candidates)
            {
                if (added.Contains(entry.Key))
                    continue;

                if ((parameterRequest is null) || forced.Contains(entry.Key))
                {
                    reply.SetOption(entry.Key, entry.Value);
                    added.Add(entry.Key);
                }
            }

            if ((requestClientId is not null) && !ctx.Bootp)
                reply.SetOption(DhcpOptionCode.ClientIdentifier, requestClientId);

            byte[] clientFqdn = request.GetOptionValue(DhcpOptionCode.ClientFqdn);
            if ((clientFqdn is not null) && (clientFqdn.Length >= 3))
                reply.SetOption(DhcpOptionCode.ClientFqdn, EncodeFqdnReply(clientFqdn, hostName, domain));

            byte[] subnetSelection = request.GetOptionValue(DhcpOptionCode.SubnetSelection);
            if ((subnetSelection is not null) && (subnetSelection.Length == 4))
                reply.SetOption(DhcpOptionCode.SubnetSelection, subnetSelection);

            AppendRelayInformation(ctx, reply);

            return reply;
        }

        private static void AppendRelayInformation(RequestContext ctx, DhcpMessage reply)
        {
            byte[] relay = ctx.Request.GetOptionValue(DhcpOptionCode.RelayAgentInformation);

            if ((relay is not null) && ctx.Relayed)
            {
                reply.RemoveOption((byte)DhcpOptionCode.RelayAgentInformation);
                reply.SetOption(DhcpOptionCode.RelayAgentInformation, relay);
            }
        }

        private static void ApplyBoot(RequestContext ctx, DhcpMessage reply)
        {
            foreach (DhcpBootRule rule in ctx.Config.Boots)
            {
                if (!DhcpTagCondition.AllMatch(rule.Conditions, ctx.Tags))
                    continue;

                reply.BootFileName = rule.FileName ?? "";
                reply.ServerHostName = rule.ServerName ?? "";

                if (rule.ServerAddress is not null)
                    reply.ServerAddress = rule.ServerAddress;

                return;
            }
        }

        private DhcpReply CreateReply(RequestContext ctx, DhcpMessage message, int delayMs = 0)
        {
            DhcpMessage request = ctx.Request;
            DhcpMessageType type = message.MessageType;

            if (ctx.Relayed)
            {
                if (type == DhcpMessageType.Nak)
                    message.Flags |= DhcpMessage.FLAG_BROADCAST;

                return new DhcpReply() { Message = message, Mode = DhcpReplyMode.Unicast, Destination = new IPEndPoint(request.RelayAddress, 67), DelayMs = delayMs, SourceAddress = ctx.ServerAddress, MaxMessageSize = request.GetMaxMessageSize() };
            }

            if (type == DhcpMessageType.Nak)
                return new DhcpReply() { Message = message, Mode = DhcpReplyMode.Broadcast, Destination = new IPEndPoint(IPAddress.Broadcast, 68), DelayMs = delayMs, SourceAddress = ctx.ServerAddress, MaxMessageSize = request.GetMaxMessageSize() };

            if (!request.ClientAddress.Equals(IPAddress.Any))
                return new DhcpReply() { Message = message, Mode = DhcpReplyMode.Unicast, Destination = new IPEndPoint(request.ClientAddress, 68), DelayMs = delayMs, SourceAddress = ctx.ServerAddress, MaxMessageSize = request.GetMaxMessageSize() };

            bool broadcast = request.IsBroadcast;

            if (!broadcast)
            {
                foreach (DhcpTagListRule rule in ctx.Config.BroadcastRules)
                {
                    if (DhcpTagCondition.AllMatch(rule.Conditions, ctx.Tags))
                    {
                        broadcast = true;
                        break;
                    }
                }
            }

            if (broadcast || message.YourAddress.Equals(IPAddress.Any) || (request.HardwareType != 1) || (request.HardwareAddressLength != 6))
                return new DhcpReply() { Message = message, Mode = DhcpReplyMode.Broadcast, Destination = new IPEndPoint(IPAddress.Broadcast, 68), DelayMs = delayMs, SourceAddress = ctx.ServerAddress, MaxMessageSize = request.GetMaxMessageSize() };

            return new DhcpReply() { Message = message, Mode = DhcpReplyMode.HardwareUnicast, Destination = new IPEndPoint(message.YourAddress, 68), DelayMs = delayMs, SourceAddress = ctx.ServerAddress, MaxMessageSize = request.GetMaxMessageSize() };
        }

        private int GetReplyDelayMs(RequestContext ctx)
        {
            int delay = ctx.Settings.ResponseDelayMs;

            foreach ((int _, List<DhcpTagCondition> conditions, int seconds) in ctx.Config.ReplyDelays)
            {
                if (DhcpTagCondition.AllMatch(conditions, ctx.Tags))
                {
                    delay = Math.Max(delay, seconds * 1000);
                    break;
                }
            }

            return delay;
        }

        private RequestContext BuildContext(DhcpMessage request, DhcpInterfaceInfo iface, DhcpConfiguration config, DhcpEngineSettings settings)
        {
            RequestContext ctx = new RequestContext()
            {
                Request = request,
                Interface = iface,
                Config = config,
                Settings = settings,
                Tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                Now = DateTime.UtcNow,
                Networks = new List<DhcpInterfaceAddress>()
            };

            ctx.Bootp = !request.HasMagicCookie || (request.MessageType == DhcpMessageType.None);

            if (iface.Name is not null)
                ctx.Tags.Add(iface.Name);

            if (ctx.Bootp)
                ctx.Tags.Add("bootp");

            byte[] clientId = config.IgnoreClientIds ? null : request.GetOptionValue(DhcpOptionCode.ClientIdentifier);
            if ((clientId is not null) && (clientId.Length < 2))
                clientId = null;

            ctx.ClientId = clientId;
            ctx.ClientKey = DhcpUtilities.GetClientKey(request.HardwareType, request.ClientHardwareAddress, clientId);
            ctx.ClientHostName = GetClientHostName(request);
            ctx.VendorClass = request.GetStringOption(DhcpOptionCode.VendorClassIdentifier);

            ctx.Relayed = !request.RelayAddress.Equals(IPAddress.Any);

            IPAddress selection = request.GetAddressOption(DhcpOptionCode.SubnetSelection);

            if (ctx.Relayed)
            {
                byte[] linkSelection = GetRelaySubOption(request, 5);

                if ((linkSelection is not null) && (linkSelection.Length == 4))
                    selection = new IPAddress(linkSelection);
            }

            if ((selection is not null) && selection.Equals(IPAddress.Any))
                selection = null;

            if (ctx.Relayed)
            {
                ctx.UseLinkAddress = true;
                ctx.LinkAddress = selection ?? request.RelayAddress;
                ctx.ServerAddress = iface.Addresses.Count > 0 ? iface.Addresses[0].Address : IPAddress.Any;
            }
            else
            {
                IPAddress hint = selection;

                if (hint is null)
                {
                    if (!request.ClientAddress.Equals(IPAddress.Any))
                        hint = request.ClientAddress;
                    else
                        hint = request.GetAddressOption(DhcpOptionCode.RequestedAddress);
                }

                DhcpInterfaceAddress preferred = null;

                if (hint is not null)
                {
                    foreach (DhcpInterfaceAddress address in iface.Addresses)
                    {
                        if (address.Contains(hint))
                        {
                            preferred = address;
                            break;
                        }
                    }
                }

                if ((selection is not null) && (preferred is null))
                {
                    ctx.UseLinkAddress = true;
                    ctx.LinkAddress = selection;
                    ctx.ServerAddress = iface.Addresses.Count > 0 ? iface.Addresses[0].Address : IPAddress.Any;
                }
                else
                {
                    if (preferred is not null)
                        ctx.Networks.Add(preferred);

                    foreach (DhcpInterfaceAddress address in iface.Addresses)
                    {
                        if (!ReferenceEquals(address, preferred) && (selection is null))
                            ctx.Networks.Add(address);
                    }

                    ctx.ServerAddress = ctx.Networks.Count > 0 ? ctx.Networks[0].Address : IPAddress.Any;
                }
            }

            ApplyMatches(ctx);

            ctx.Host = FindHost(ctx);

            if (ctx.Host is not null)
            {
                ctx.Tags.Add("known");

                foreach (string tag in ctx.Host.SetTags)
                    ctx.Tags.Add(tag);
            }

            ctx.Ranges = FindRanges(ctx);

            if (ctx.Host?.Address is not null)
            {
                RangeCandidate hostRange = FindRangeForAddress(ctx, ctx.Host.Address);

                if (hostRange is not null)
                {
                    ctx.Ranges.Remove(hostRange);
                    ctx.Ranges.Insert(0, hostRange);
                }
            }

            if (ctx.Ranges.Count > 0)
            {
                if (ctx.Ranges[0].Rule.SetTag is not null)
                    ctx.Tags.Add(ctx.Ranges[0].Rule.SetTag);

                ctx.ServerAddress = ctx.Ranges[0].ServerAddress ?? ctx.ServerAddress;
            }

            foreach (DhcpTagIfRule rule in config.TagIfs)
            {
                if (DhcpTagCondition.AllMatch(rule.Conditions, ctx.Tags))
                {
                    foreach (string tag in rule.SetTags)
                        ctx.Tags.Add(tag);
                }
            }

            return ctx;
        }

        private bool IsIgnored(RequestContext ctx)
        {
            if ((ctx.Host is not null) && ctx.Host.Ignore)
                return true;

            foreach (DhcpTagListRule rule in ctx.Config.IgnoreRules)
            {
                if (DhcpTagCondition.AllMatch(rule.Conditions, ctx.Tags))
                    return true;
            }

            return false;
        }

        private async Task<DhcpReply> HandleDiscoverAsync(RequestContext ctx)
        {
            Interlocked.Increment(ref _discovers);

            if (ctx.Settings.OffersPaused)
            {
                bool hasLease = false;

                foreach (DhcpLease lease in _store.GetByClient(ctx.ClientKey))
                {
                    if (lease.IsActive(ctx.Now) && (lease.State == DhcpLeaseState.Bound))
                    {
                        hasLease = true;
                        break;
                    }
                }

                if (!hasLease)
                    return null;
            }

            if ((ctx.Settings.MinSecs > 0) && (ctx.Request.Seconds < ctx.Settings.MinSecs))
                return null;

            (IPAddress address, RangeCandidate range) = await AllocateAsync(ctx);

            if (address is null)
                return null;

            uint leaseTime = GetLeaseTime(ctx, range);

            bool rapidCommit = ctx.Config.RapidCommit && ctx.Request.HasOption(DhcpOptionCode.RapidCommit);

            if (rapidCommit)
            {
                DhcpLease bound = CreateLease(ctx, address, DhcpLeaseState.Bound, GetExpiry(ctx.Now, leaseTime));
                _store.Put(bound);
                Interlocked.Increment(ref _acks);
                return CreateReply(ctx, BuildReply(ctx, DhcpMessageType.Ack, address, range, leaseTime, true));
            }

            Interlocked.Increment(ref _offers);
            return CreateReply(ctx, BuildReply(ctx, DhcpMessageType.Offer, address, range, leaseTime, false), GetReplyDelayMs(ctx));
        }

        private DhcpReply Ack(RequestContext ctx, IPAddress address, RangeCandidate range)
        {
            uint leaseTime = GetLeaseTime(ctx, range);
            DhcpLease bound = CreateLease(ctx, address, DhcpLeaseState.Bound, GetExpiry(ctx.Now, leaseTime));

            DhcpLease existing = _store.Get(address);
            if ((existing is not null) && (existing.ClientKey == ctx.ClientKey) && (existing.State == DhcpLeaseState.Bound))
                bound = new DhcpLease()
                {
                    Address = bound.Address,
                    ClientKey = bound.ClientKey,
                    HardwareType = bound.HardwareType,
                    HardwareAddress = bound.HardwareAddress,
                    ClientId = bound.ClientId,
                    ClientHostName = bound.ClientHostName ?? existing.ClientHostName,
                    HostName = bound.HostName ?? existing.HostName,
                    VendorClass = bound.VendorClass ?? existing.VendorClass,
                    Start = existing.Start,
                    Expires = bound.Expires,
                    State = DhcpLeaseState.Bound,
                    Reserved = bound.Reserved,
                    Updated = ctx.Now
                };

            if (!_store.TryPut(bound, delegate (DhcpLease current) { return IsFreeFor(current, ctx.ClientKey, ctx.Now); }, out _))
                return Nak(ctx);

            Interlocked.Increment(ref _acks);
            return CreateReply(ctx, BuildReply(ctx, DhcpMessageType.Ack, address, range, leaseTime, false));
        }

        private DhcpReply Nak(RequestContext ctx)
        {
            Interlocked.Increment(ref _naks);
            return CreateReply(ctx, BuildReply(ctx, DhcpMessageType.Nak, null, null, 0, false));
        }

        private bool OwnsServerIdentifier(RequestContext ctx, IPAddress serverId)
        {
            foreach (DhcpInterfaceAddress address in ctx.Interface.Addresses)
            {
                if (address.Address.Equals(serverId))
                    return true;
            }

            if ((ctx.ServerAddress is not null) && ctx.ServerAddress.Equals(serverId))
                return true;

            return _isOwnServerIdentifier(serverId);
        }

        private DhcpReply HandleRequest(RequestContext ctx)
        {
            Interlocked.Increment(ref _requests);

            DhcpMessage request = ctx.Request;
            IPAddress serverId = request.GetAddressOption(DhcpOptionCode.ServerIdentifier);
            IPAddress requested = request.GetAddressOption(DhcpOptionCode.RequestedAddress);
            IPAddress ciaddr = request.ClientAddress;
            bool hasCiaddr = !ciaddr.Equals(IPAddress.Any);

            if (serverId is not null)
            {
                if (!OwnsServerIdentifier(ctx, serverId))
                {
                    foreach (DhcpLease lease in _store.GetByClient(ctx.ClientKey))
                    {
                        if ((lease.State == DhcpLeaseState.Offered) && lease.IsActive(ctx.Now))
                            _store.Put(lease.With(DhcpLeaseState.Free, lease.Expires, ctx.Now));
                    }

                    ForeignServerSeen?.Invoke(serverId, ctx.Interface.Name);

                    return null;
                }

                IPAddress address = requested ?? (hasCiaddr ? ciaddr : null);
                if (address is null)
                    return Nak(ctx);

                DhcpLease existing = _store.Get(address);

                if ((existing is null) || (existing.ClientKey != ctx.ClientKey) || ((existing.State != DhcpLeaseState.Offered) && (existing.State != DhcpLeaseState.Bound)) || !existing.IsActive(ctx.Now))
                    return Nak(ctx);

                if (!IsAddressValidForClient(ctx, address, out RangeCandidate range))
                    return Nak(ctx);

                return Ack(ctx, address, range);
            }

            if ((requested is not null) && !hasCiaddr)
            {
                if (!IsAddressOnLink(ctx, requested))
                    return Nak(ctx);

                return RenewOrLearn(ctx, requested);
            }

            if (hasCiaddr)
            {
                if (!IsAddressOnLink(ctx, ciaddr))
                    return ctx.Config.Authoritative ? Nak(ctx) : null;

                return RenewOrLearn(ctx, ciaddr);
            }

            return null;
        }

        private bool IsAddressOnLink(RequestContext ctx, IPAddress address)
        {
            return FindRangeForAddress(ctx, address) is not null;
        }

        private DhcpReply RenewOrLearn(RequestContext ctx, IPAddress address)
        {
            DhcpLease existing = _store.Get(address);
            bool valid = IsAddressValidForClient(ctx, address, out RangeCandidate range);

            if ((existing is not null) && (existing.ClientKey == ctx.ClientKey) && (existing.State != DhcpLeaseState.Free) && (existing.State != DhcpLeaseState.Declined))
                return valid ? Ack(ctx, address, range) : Nak(ctx);

            bool authoritative = ctx.Config.Authoritative;

            if ((existing is not null) && !IsFreeFor(existing, ctx.ClientKey, ctx.Now))
                return authoritative ? Nak(ctx) : null;

            if (!valid)
                return authoritative ? Nak(ctx) : null;

            if (!authoritative)
                return null;

            if (ctx.Settings.OffersPaused)
                return null;

            _log("DHCP Server accepted the lease of " + ctx.ClientKey + " for " + address + " that was not in its lease database.");
            return Ack(ctx, address, range);
        }

        private DhcpReply HandleDecline(RequestContext ctx)
        {
            Interlocked.Increment(ref _declines);

            IPAddress requested = ctx.Request.GetAddressOption(DhcpOptionCode.RequestedAddress);
            IPAddress serverId = ctx.Request.GetAddressOption(DhcpOptionCode.ServerIdentifier);

            if ((requested is null) || ((serverId is not null) && !OwnsServerIdentifier(ctx, serverId)))
                return null;

            DhcpLease existing = _store.Get(requested);

            if ((existing is null) || (existing.ClientKey != ctx.ClientKey))
                return null;

            _log("DHCP Server received DHCPDECLINE for " + requested + " from " + ctx.ClientKey + ", the address is blocked for " + (DECLINE_HOLD_SECONDS / 60) + " minutes.");

            _store.Put(new DhcpLease()
            {
                Address = requested,
                ClientKey = "",
                HardwareAddress = [],
                Start = ctx.Now,
                Expires = ctx.Now.AddSeconds(DECLINE_HOLD_SECONDS),
                State = DhcpLeaseState.Declined,
                Updated = ctx.Now
            });

            return null;
        }

        private DhcpReply HandleRelease(RequestContext ctx)
        {
            Interlocked.Increment(ref _releases);

            IPAddress address = ctx.Request.ClientAddress;
            IPAddress serverId = ctx.Request.GetAddressOption(DhcpOptionCode.ServerIdentifier);

            if (address.Equals(IPAddress.Any) || ((serverId is not null) && !OwnsServerIdentifier(ctx, serverId)))
                return null;

            DhcpLease existing = _store.Get(address);

            if ((existing is null) || (existing.ClientKey != ctx.ClientKey) || (existing.State != DhcpLeaseState.Bound))
                return null;

            _store.Put(existing.With(DhcpLeaseState.Released, ctx.Now, ctx.Now));
            return null;
        }

        private DhcpReply HandleInform(RequestContext ctx)
        {
            Interlocked.Increment(ref _informs);

            IPAddress ciaddr = ctx.Request.ClientAddress;
            if (ciaddr.Equals(IPAddress.Any))
                return null;

            RangeCandidate range = FindRangeForAddress(ctx, ciaddr);
            if (range is null)
                return null;

            DhcpMessage reply = BuildReply(ctx, DhcpMessageType.Inform, null, range, 0, false);
            return CreateReply(ctx, reply);
        }

        private DhcpReply HandleBootp(RequestContext ctx)
        {
            IPAddress address = null;
            RangeCandidate range = null;

            if ((ctx.Host is not null) && (ctx.Host.Address is not null))
            {
                range = FindRangeForAddress(ctx, ctx.Host.Address);
                if (range is not null)
                    address = ctx.Host.Address;
            }

            if (address is null)
            {
                if (!ctx.Config.BootpDynamic)
                    return null;

                foreach (DhcpLease lease in _store.GetByClient(ctx.ClientKey))
                {
                    if (IsAddressValidForClient(ctx, lease.Address, out range))
                    {
                        address = lease.Address;
                        break;
                    }
                }

                if (address is null)
                {
                    (address, range) = FindFreeAddress(ctx);

                    if (address is null)
                        return null;
                }
            }

            DhcpLease bound = CreateLease(ctx, address, DhcpLeaseState.Bound, DateTime.MaxValue);

            if (!_store.TryPut(bound, delegate (DhcpLease current) { return IsFreeFor(current, ctx.ClientKey, ctx.Now); }, out _))
                return null;

            return CreateReply(ctx, BuildReply(ctx, DhcpMessageType.Ack, address, range, DhcpUtilities.INFINITE_LEASE, false));
        }

        #endregion

        #region public

        public event Action<IPAddress, string> ForeignServerSeen;

        public void Configure(DhcpConfiguration config, DhcpEngineSettings settings, Func<IPAddress, bool> isOwnServerIdentifier = null)
        {
            _config = config ?? DhcpConfiguration.Empty;
            _settings = settings ?? new DhcpEngineSettings();

            if (isOwnServerIdentifier is not null)
                _isOwnServerIdentifier = isOwnServerIdentifier;
        }

        public async Task<DhcpReply> ProcessAsync(DhcpMessage request, DhcpInterfaceInfo iface)
        {
            DhcpEngineSettings settings = _settings;
            DhcpConfiguration config = _config;

            if (!settings.Serving)
                return null;

            if ((request.Op != DhcpMessage.OP_BOOTREQUEST) || (request.HardwareAddressLength == 0) || (request.HardwareAddressLength > 16))
                return null;

            if (request.Hops > 16)
                return null;

            RequestContext ctx = BuildContext(request, iface, config, settings);

            if (IsIgnored(ctx))
            {
                Interlocked.Increment(ref _ignored);
                return null;
            }

            if ((ctx.Ranges.Count == 0) && (request.MessageType != DhcpMessageType.Release) && (request.MessageType != DhcpMessageType.Decline))
            {
                if (request.MessageType == DhcpMessageType.Request)
                {
                    IPAddress serverId = request.GetAddressOption(DhcpOptionCode.ServerIdentifier);
                    if ((serverId is not null) && !OwnsServerIdentifier(ctx, serverId))
                        ForeignServerSeen?.Invoke(serverId, iface.Name);
                }

                return null;
            }

            SemaphoreSlim clientLock = GetClientLock(ctx.ClientKey);
            await clientLock.WaitAsync();

            try
            {
                ctx.Now = DateTime.UtcNow;

                if (ctx.Bootp)
                    return HandleBootp(ctx);

                switch (request.MessageType)
                {
                    case DhcpMessageType.Discover:
                        return await HandleDiscoverAsync(ctx);

                    case DhcpMessageType.Request:
                        return HandleRequest(ctx);

                    case DhcpMessageType.Decline:
                        return HandleDecline(ctx);

                    case DhcpMessageType.Release:
                        return HandleRelease(ctx);

                    case DhcpMessageType.Inform:
                        return HandleInform(ctx);

                    default:
                        return null;
                }
            }
            finally
            {
                clientLock.Release();
            }
        }

        public IReadOnlyDictionary<string, long> GetCounters()
        {
            return new Dictionary<string, long>()
            {
                { "discover", Interlocked.Read(ref _discovers) },
                { "offer", Interlocked.Read(ref _offers) },
                { "request", Interlocked.Read(ref _requests) },
                { "ack", Interlocked.Read(ref _acks) },
                { "nak", Interlocked.Read(ref _naks) },
                { "decline", Interlocked.Read(ref _declines) },
                { "release", Interlocked.Read(ref _releases) },
                { "inform", Interlocked.Read(ref _informs) },
                { "ignored", Interlocked.Read(ref _ignored) },
                { "poolExhausted", Interlocked.Read(ref _poolExhausted) },
                { "conflicts", Interlocked.Read(ref _conflicts) }
            };
        }

        #endregion

        #region properties

        public DhcpConfiguration Configuration
        { get { return _config; } }

        public DhcpEngineSettings Settings
        { get { return _settings; } }

        #endregion
    }
}
