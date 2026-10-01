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
using System.Text;
using System.Threading;

namespace ZenitiumDns.Core.Dhcp
{
    public sealed class Dhcp6EngineSettings
    {
        public bool Serving { get; init; }

        public bool OffersPaused { get; init; }

        public int ResponseDelayMs { get; init; }

        public bool PreferMe { get; init; }

        public bool RegisterDns { get; init; }

        public uint DefaultLeaseTime { get; init; } = 86400;
    }

    public sealed class Dhcp6Reply
    {
        public Dhcp6Message Message { get; init; }

        public int DelayMs { get; init; }

        public bool ToRelay { get; init; }
    }

    public sealed class Dhcp6RangeCandidate
    {
        public Dhcp6RangeRule Rule { get; init; }

        public UInt128 Prefix { get; init; }

        public int PrefixLength { get; init; }

        public UInt128 First
        { get { return Rule.Constructor is null ? Rule.Start : Prefix | (Rule.Start & Rule.HostMask); } }

        public UInt128 Last
        { get { return Rule.Constructor is null ? Rule.End : Prefix | (Rule.End & Rule.HostMask); } }

        public bool InPrefix(UInt128 address)
        {
            return Dhcp6Utilities.IsInPrefix(address, Prefix, PrefixLength);
        }

        public bool InPool(UInt128 address)
        {
            return Rule.AssignsAddresses && (address >= First) && (address <= Last);
        }

        public static List<Dhcp6RangeCandidate> GetForInterface(DhcpConfiguration config, Dhcp6InterfaceInfo iface)
        {
            List<Dhcp6RangeCandidate> result = new List<Dhcp6RangeCandidate>();

            foreach (Dhcp6RangeRule rule in config.Ranges6)
            {
                if (rule.Constructor is not null)
                {
                    if (!rule.MatchesConstructor(iface.Name))
                        continue;

                    foreach (Dhcp6InterfaceAddress address in iface.GetPrefixAddresses(rule.PrefixLength))
                        result.Add(new Dhcp6RangeCandidate() { Rule = rule, Prefix = Dhcp6Utilities.GetPrefix(Dhcp6Utilities.ToUInt128(address.Address), rule.PrefixLength), PrefixLength = rule.PrefixLength });
                }
                else if (iface.IsOnLink(Dhcp6Utilities.ToAddress(rule.Start)))
                {
                    result.Add(new Dhcp6RangeCandidate() { Rule = rule, Prefix = Dhcp6Utilities.GetPrefix(rule.Start, rule.PrefixLength), PrefixLength = rule.PrefixLength });
                }
            }

            return result;
        }

        public static List<Dhcp6RangeCandidate> GetForLinkAddress(DhcpConfiguration config, UInt128 linkAddress)
        {
            List<Dhcp6RangeCandidate> result = new List<Dhcp6RangeCandidate>();

            foreach (Dhcp6RangeRule rule in config.Ranges6)
            {
                if ((rule.Constructor is null) && Dhcp6Utilities.IsInPrefix(linkAddress, rule.Start, rule.PrefixLength))
                    result.Add(new Dhcp6RangeCandidate() { Rule = rule, Prefix = Dhcp6Utilities.GetPrefix(rule.Start, rule.PrefixLength), PrefixLength = rule.PrefixLength });
            }

            return result;
        }
    }

    public sealed class Dhcp6Engine
    {
        #region variables

        const int OFFER_HOLD_SECONDS = 60;
        const int DECLINE_HOLD_SECONDS = 3600;
        const uint MAX_ALLOCATION_ATTEMPTS = 2048;
        const int MAX_ADDRESSES_PER_IA = 4;
        const int MAX_IAS = 8;

        readonly Dhcp6LeaseStore _store;
        readonly Action<string> _log;
        readonly object _allocationLock = new object();

        DhcpConfiguration _config = DhcpConfiguration.Empty;
        Dhcp6EngineSettings _settings = new Dhcp6EngineSettings();
        byte[] _serverDuid = [];
        Func<byte[], string> _findHostNameByMac;
        Func<UInt128, bool> _isLocalAddress;
        Func<byte[], IPAddress, byte[]> _resolveClientMac;

        long _solicits;
        long _requests;
        long _renews;
        long _rebinds;
        long _releases;
        long _declines;
        long _confirms;
        long _informationRequests;
        long _advertises;
        long _replies;
        long _noAddresses;
        long _ignored;
        long _relayed;

        #endregion

        #region constructor

        public Dhcp6Engine(Dhcp6LeaseStore store, Action<string> log)
        {
            _store = store;
            _log = log ?? delegate (string message) { };
        }

        #endregion

        #region events

        public event Action<byte[], string> ForeignServerSeen;

        #endregion

        #region private types

        private sealed class Context
        {
            public Dhcp6Message Request;
            public Dhcp6InterfaceInfo Interface;
            public DhcpConfiguration Config;
            public Dhcp6EngineSettings Settings;
            public HashSet<string> Tags;
            public byte[] ClientDuid;
            public byte[] HardwareAddress;
            public string ClientHostName;
            public byte[] ClientFqdn;
            public DhcpHostRule Host;
            public List<Dhcp6RangeCandidate> Candidates;
            public UInt128? LinkAddress;
            public IPAddress ServerAddress;
            public DateTime Now;
        }

        #endregion

        #region private

        private static uint Hash(byte[] duid, uint iaid, int attempt)
        {
            ulong hash = 14695981039346656037;

            foreach (byte b in duid)
            {
                hash ^= b;
                hash *= 1099511628211;
            }

            for (int i = 0; i < 4; i++)
            {
                hash ^= (byte)(iaid >> (i * 8));
                hash *= 1099511628211;
            }

            hash ^= (ulong)attempt;
            hash *= 1099511628211;

            return (uint)(hash ^ (hash >> 32));
        }

        private static string GetClientHostName(byte[] fqdn)
        {
            if ((fqdn is null) || (fqdn.Length < 2))
                return null;

            int offset = 1;
            int length = fqdn[offset++];

            if ((length == 0) || (length > 63) || (offset + length > fqdn.Length))
                return null;

            string label = Encoding.ASCII.GetString(fqdn, offset, length);
            string sanitized = DhcpUtilities.SanitizeHostName(label);

            return string.IsNullOrEmpty(sanitized) ? null : sanitized;
        }

        private static byte[] GetRelayHardwareAddress(List<Dhcp6Message> relays)
        {
            for (int i = relays.Count - 1; i >= 0; i--)
            {
                byte[] data = relays[i].GetOptionData(79);

                if ((data is not null) && (data.Length == 8) && (BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(0, 2)) == 1))
                    return data.AsSpan(2, 6).ToArray();
            }

            return null;
        }

        private static bool HardwareMatches(DhcpHardwarePattern pattern, byte[] hardwareAddress)
        {
            return (hardwareAddress is not null) && (hardwareAddress.Length == 6) && pattern.Matches(1, hardwareAddress);
        }

        private static DhcpHostRule FindHost(Context ctx)
        {
            foreach (DhcpHostRule host in ctx.Config.Hosts)
            {
                if (!DhcpTagCondition.AllMatch(host.Conditions, ctx.Tags))
                    continue;

                foreach (byte[] id in host.ClientIds)
                {
                    if (id.AsSpan().SequenceEqual(ctx.ClientDuid))
                        return host;
                }
            }

            DhcpHostRule wildcardMatch = null;

            if (ctx.HardwareAddress is not null)
            {
                foreach (DhcpHostRule host in ctx.Config.Hosts)
                {
                    if (!DhcpTagCondition.AllMatch(host.Conditions, ctx.Tags))
                        continue;

                    foreach (DhcpHardwarePattern pattern in host.HardwareAddresses)
                    {
                        if (HardwareMatches(pattern, ctx.HardwareAddress))
                        {
                            if (!pattern.HasWildcard)
                                return host;

                            wildcardMatch ??= host;
                        }
                    }
                }
            }

            if (wildcardMatch is not null)
                return wildcardMatch;

            if (ctx.ClientHostName is not null)
            {
                foreach (DhcpHostRule host in ctx.Config.Hosts)
                {
                    if (host.MatchByHostName && DhcpTagCondition.AllMatch(host.Conditions, ctx.Tags) && string.Equals(host.HostName, ctx.ClientHostName, StringComparison.OrdinalIgnoreCase))
                        return host;
                }
            }

            return null;
        }

        private Context BuildContext(Dhcp6Message request, List<Dhcp6Message> relays, Dhcp6InterfaceInfo iface, IPAddress source, DhcpConfiguration config, Dhcp6EngineSettings settings)
        {
            Context ctx = new Context()
            {
                Request = request,
                Interface = iface,
                Config = config,
                Settings = settings,
                Tags = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                ClientDuid = request.GetOptionData(Dhcp6OptionCode.ClientId),
                ClientFqdn = request.GetOptionData(Dhcp6OptionCode.ClientFqdn),
                Now = DateTime.UtcNow
            };

            if (iface.Name is not null)
                ctx.Tags.Add(iface.Name);

            ctx.HardwareAddress = Dhcp6Message.GetHardwareAddressFromDuid(ctx.ClientDuid) ?? GetRelayHardwareAddress(relays);

            if ((ctx.HardwareAddress is null) && (_resolveClientMac is not null))
                ctx.HardwareAddress = _resolveClientMac(ctx.ClientDuid, relays.Count == 0 ? source : null);
            ctx.ClientHostName = GetClientHostName(ctx.ClientFqdn);

            foreach (DhcpMatchRule rule in config.Matches)
            {
                if ((rule.Kind == DhcpMatchKind.HardwareAddress) && HardwareMatches(rule.HardwarePattern, ctx.HardwareAddress))
                    ctx.Tags.Add(rule.SetTag);
            }

            for (int i = relays.Count - 1; i >= 0; i--)
            {
                IPAddress link = relays[i].LinkAddress;

                if (!link.Equals(IPAddress.IPv6Any) && !link.IsIPv6LinkLocal)
                {
                    ctx.LinkAddress = Dhcp6Utilities.ToUInt128(link);
                    break;
                }
            }

            List<Dhcp6RangeCandidate> all = ctx.LinkAddress.HasValue ? Dhcp6RangeCandidate.GetForLinkAddress(config, ctx.LinkAddress.Value) : Dhcp6RangeCandidate.GetForInterface(config, iface);

            ctx.Host = FindHost(ctx);

            if (ctx.Host is not null)
            {
                ctx.Tags.Add("known");

                foreach (string tag in ctx.Host.SetTags)
                    ctx.Tags.Add(tag);
            }

            ctx.Candidates = new List<Dhcp6RangeCandidate>();

            foreach (Dhcp6RangeCandidate candidate in all)
            {
                if (DhcpTagCondition.AllMatch(candidate.Rule.Conditions, ctx.Tags))
                    ctx.Candidates.Add(candidate);
            }

            foreach (Dhcp6RangeCandidate candidate in ctx.Candidates)
            {
                if (candidate.Rule.SetTag is not null)
                {
                    ctx.Tags.Add(candidate.Rule.SetTag);
                    break;
                }
            }

            foreach (DhcpTagIfRule rule in config.TagIfs)
            {
                if (DhcpTagCondition.AllMatch(rule.Conditions, ctx.Tags))
                {
                    foreach (string tag in rule.SetTags)
                        ctx.Tags.Add(tag);
                }
            }

            UInt128? hint = ctx.Candidates.Count > 0 ? ctx.Candidates[0].Prefix : ctx.LinkAddress;
            ctx.ServerAddress = iface.GetBestServerAddress(hint, ctx.Candidates.Count > 0 ? ctx.Candidates[0].PrefixLength : 64);

            return ctx;
        }

        private bool IsIgnored(Context ctx)
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

        private string GetHostName(Context ctx)
        {
            if (ctx.Host?.HostName is not null)
                return ctx.Host.HostName;

            bool ignoreClientName = false;

            foreach (DhcpTagListRule rule in ctx.Config.IgnoreNamesRules)
            {
                if (DhcpTagCondition.AllMatch(rule.Conditions, ctx.Tags))
                {
                    ignoreClientName = true;
                    break;
                }
            }

            if (!ignoreClientName && (ctx.ClientHostName is not null))
                return ctx.ClientHostName;

            if ((ctx.HardwareAddress is not null) && (_findHostNameByMac is not null))
                return _findHostNameByMac(ctx.HardwareAddress);

            return null;
        }

        private string GetDomain(Context ctx)
        {
            foreach (DhcpDomainRule rule in ctx.Config.Domains)
            {
                if (rule.Start is null)
                    return rule.Domain;
            }

            return null;
        }

        private uint GetLeaseTime(Context ctx, Dhcp6RangeCandidate candidate)
        {
            if ((ctx.Host is not null) && (ctx.Host.LeaseTime != 0))
                return ctx.Host.LeaseTime;

            if ((candidate is not null) && (candidate.Rule.LeaseTime != 0))
                return candidate.Rule.LeaseTime;

            return ctx.Settings.DefaultLeaseTime;
        }

        private static DateTime GetExpiry(DateTime now, uint seconds)
        {
            if (seconds == uint.MaxValue)
                return DateTime.MaxValue;

            return now.AddSeconds(seconds);
        }

        private bool IsReservedForOther(Context ctx, UInt128 address, Dhcp6RangeCandidate candidate)
        {
            foreach (DhcpHostRule host in ctx.Config.Hosts)
            {
                if ((host.Address6 is null) || ReferenceEquals(host, ctx.Host))
                    continue;

                UInt128 reserved = Dhcp6Utilities.ToUInt128(host.Address6);

                if (host.Address6IsSuffix)
                    reserved = candidate.Prefix | (reserved & candidate.Rule.HostMask);

                if (reserved == address)
                    return true;
            }

            return false;
        }

        private bool IsAvailableFor(Context ctx, UInt128 address, string clientKey, Dhcp6RangeCandidate candidate)
        {
            if ((address & candidate.Rule.HostMask) == UInt128.Zero)
                return false;

            if ((_isLocalAddress is not null) && _isLocalAddress(address))
                return false;

            Dhcp6Lease lease = _store.Get(address);

            if (lease is not null)
            {
                if (lease.ClientKey == clientKey)
                    return lease.State != DhcpLeaseState.Declined;

                if (lease.State == DhcpLeaseState.Declined)
                    return lease.Expires <= ctx.Now;

                if (lease.IsActive(ctx.Now))
                    return false;
            }

            return !IsReservedForOther(ctx, address, candidate);
        }

        private UInt128? GetReservedAddress(Context ctx, Dhcp6RangeCandidate candidate)
        {
            if (ctx.Host?.Address6 is null)
                return null;

            UInt128 value = Dhcp6Utilities.ToUInt128(ctx.Host.Address6);

            if (ctx.Host.Address6IsSuffix)
                return candidate.Prefix | (value & candidate.Rule.HostMask);

            if (candidate.InPrefix(value))
                return value;

            return null;
        }

        private List<(UInt128 Address, Dhcp6RangeCandidate Candidate, bool Reserved)> Allocate(Context ctx, uint iaid, List<UInt128> hints)
        {
            List<(UInt128, Dhcp6RangeCandidate, bool)> result = new List<(UInt128, Dhcp6RangeCandidate, bool)>();
            string clientKey = Dhcp6Lease.GetClientKey(ctx.ClientDuid, iaid);
            HashSet<UInt128> prefixesDone = new HashSet<UInt128>();
            List<Dhcp6Lease> existing = _store.GetByClient(clientKey);

            if ((existing.Count == 0) && ((_store.Count >= ctx.Config.LeaseMax * 4L) || (_store.CountActive(ctx.Now) >= ctx.Config.LeaseMax)))
                return result;

            foreach (Dhcp6RangeCandidate candidate in ctx.Candidates)
            {
                if (result.Count >= MAX_ADDRESSES_PER_IA)
                    break;

                if (prefixesDone.Contains(candidate.Prefix))
                    continue;

                UInt128? reserved = GetReservedAddress(ctx, candidate);

                if (reserved.HasValue)
                {
                    if (!candidate.Rule.OffersDhcp)
                        continue;

                    Dhcp6Lease lease = _store.Get(reserved.Value);

                    if ((lease is null) || (lease.ClientKey == clientKey) || !lease.IsActive(ctx.Now))
                    {
                        result.Add((reserved.Value, candidate, true));
                        prefixesDone.Add(candidate.Prefix);
                        continue;
                    }
                }

                if (!candidate.Rule.AssignsAddresses)
                    continue;

                UInt128? chosen = null;

                foreach (Dhcp6Lease lease in existing)
                {
                    UInt128 value = Dhcp6Utilities.ToUInt128(lease.Address);

                    if (candidate.InPool(value) && (lease.State != DhcpLeaseState.Declined) && IsAvailableFor(ctx, value, clientKey, candidate))
                    {
                        chosen = value;
                        break;
                    }
                }

                if (!chosen.HasValue)
                {
                    foreach (UInt128 hint in hints)
                    {
                        if (candidate.InPool(hint) && IsAvailableFor(ctx, hint, clientKey, candidate))
                        {
                            chosen = hint;
                            break;
                        }
                    }
                }

                if (!chosen.HasValue)
                {
                    UInt128 size = candidate.Last - candidate.First + UInt128.One;
                    UInt128 start = new UInt128(0, Hash(ctx.ClientDuid, iaid, 0)) % size;
                    int attempts = size < MAX_ALLOCATION_ATTEMPTS ? (int)size : (int)MAX_ALLOCATION_ATTEMPTS;

                    for (int i = 0; i < attempts; i++)
                    {
                        UInt128 offset = size <= MAX_ALLOCATION_ATTEMPTS ? (start + (UInt128)(uint)i) % size : new UInt128(Hash(ctx.ClientDuid, iaid, i + 1), Hash(ctx.ClientDuid, iaid, -i - 1)) % size;
                        UInt128 value = candidate.First + offset;

                        if (IsAvailableFor(ctx, value, clientKey, candidate))
                        {
                            chosen = value;
                            break;
                        }
                    }
                }

                if (chosen.HasValue)
                {
                    result.Add((chosen.Value, candidate, false));
                    prefixesDone.Add(candidate.Prefix);
                }
            }

            return result;
        }

        private Dhcp6Lease StoreLease(Context ctx, uint iaid, UInt128 address, bool reserved, DhcpLeaseState state, DateTime expires)
        {
            Dhcp6Lease previous = _store.Get(address);
            bool sameClient = (previous is not null) && (previous.ClientKey == Dhcp6Lease.GetClientKey(ctx.ClientDuid, iaid));

            Dhcp6Lease lease = new Dhcp6Lease()
            {
                Address = Dhcp6Utilities.ToAddress(address),
                Duid = ctx.ClientDuid,
                Iaid = iaid,
                HardwareAddress = ctx.HardwareAddress ?? [],
                ClientHostName = ctx.ClientHostName,
                HostName = GetHostName(ctx),
                Interface = ctx.Interface.Name,
                Start = sameClient && (previous.State == DhcpLeaseState.Bound) ? previous.Start : ctx.Now,
                Expires = expires,
                State = state,
                Reserved = reserved,
                Updated = ctx.Now
            };

            _store.Put(lease);
            return lease;
        }

        private static List<UInt128> GetHints(Dhcp6Ia ia)
        {
            List<UInt128> hints = new List<UInt128>();

            foreach (Dhcp6IaAddress address in ia.Addresses)
                hints.Add(Dhcp6Utilities.ToUInt128(address.Address));

            return hints;
        }

        private static List<Dhcp6Ia> GetIas(Dhcp6Message request, ushort code)
        {
            List<Dhcp6Ia> result = new List<Dhcp6Ia>();

            foreach (Dhcp6Option option in request.Options)
            {
                if (option.Code != code)
                    continue;

                if (Dhcp6Ia.TryParse(option, out Dhcp6Ia ia))
                    result.Add(ia);

                if (result.Count >= MAX_IAS)
                    break;
            }

            return result;
        }

        private static Dhcp6Ia CreateIa(Dhcp6Ia request, uint t1, uint t2)
        {
            return new Dhcp6Ia() { Code = request.Code, Iaid = request.Iaid, T1 = t1, T2 = t2 };
        }

        private static Dhcp6Ia CreateIaStatus(Dhcp6Ia request, Dhcp6Status status, string message)
        {
            Dhcp6Ia ia = CreateIa(request, 0, 0);
            ia.Options.Add(new Dhcp6Option(Dhcp6OptionCode.StatusCode, Dhcp6Message.EncodeStatus(status, message)));
            return ia;
        }

        private static (uint T1, uint T2) GetRenewalTimes(uint leaseTime)
        {
            if (leaseTime == uint.MaxValue)
                return (uint.MaxValue, uint.MaxValue);

            return (leaseTime / 2, (uint)((ulong)leaseTime * 4 / 5));
        }

        private Dhcp6Ia AssignIa(Context ctx, Dhcp6Ia request, bool commit)
        {
            List<(UInt128 Address, Dhcp6RangeCandidate Candidate, bool Reserved)> addresses;

            lock (_allocationLock)
            {
                addresses = Allocate(ctx, request.Iaid, GetHints(request));

                if (addresses.Count == 0)
                    return null;

                uint minLease = uint.MaxValue;
                Dhcp6Ia ia = CreateIa(request, 0, 0);

                foreach ((UInt128 address, Dhcp6RangeCandidate candidate, bool reserved) in addresses)
                {
                    uint leaseTime = GetLeaseTime(ctx, candidate);
                    minLease = Math.Min(minLease, leaseTime);

                    DateTime expires = commit ? GetExpiry(ctx.Now, leaseTime) : ctx.Now.AddSeconds(OFFER_HOLD_SECONDS);
                    StoreLease(ctx, request.Iaid, address, reserved, commit ? DhcpLeaseState.Bound : DhcpLeaseState.Offered, expires);

                    ia.Addresses.Add(new Dhcp6IaAddress() { Address = Dhcp6Utilities.ToAddress(address), PreferredLifetime = leaseTime, ValidLifetime = leaseTime });
                }

                (ia.T1, ia.T2) = GetRenewalTimes(minLease);
                return ia;
            }
        }

        private Dhcp6Ia ExtendIa(Context ctx, Dhcp6Ia request, bool rebind, out bool answerable)
        {
            answerable = false;
            string clientKey = Dhcp6Lease.GetClientKey(ctx.ClientDuid, request.Iaid);
            Dhcp6Ia ia = CreateIa(request, 0, 0);
            uint minLease = uint.MaxValue;
            bool anyValid = false;

            lock (_allocationLock)
            {
                List<Dhcp6Lease> bindings = _store.GetByClient(clientKey);
                HashSet<UInt128> handled = new HashSet<UInt128>();

                foreach (Dhcp6IaAddress requested in request.Addresses)
                {
                    UInt128 value = Dhcp6Utilities.ToUInt128(requested.Address);
                    handled.Add(value);

                    Dhcp6RangeCandidate candidate = null;

                    foreach (Dhcp6RangeCandidate c in ctx.Candidates)
                    {
                        if (c.InPrefix(value) && c.Rule.OffersDhcp)
                        {
                            candidate = c;
                            break;
                        }
                    }

                    if (candidate is null)
                    {
                        answerable = true;
                        ia.Addresses.Add(new Dhcp6IaAddress() { Address = requested.Address, PreferredLifetime = 0, ValidLifetime = 0 });
                        continue;
                    }

                    answerable = true;

                    UInt128? reserved = GetReservedAddress(ctx, candidate);
                    bool isReserved = reserved.HasValue && (reserved.Value == value);
                    bool ownedOrFree = isReserved ? !IsReservedForOther(ctx, value, candidate) && IsOwnedOrFree(ctx, value, clientKey) : candidate.InPool(value) && IsAvailableFor(ctx, value, clientKey, candidate);

                    if (reserved.HasValue && !isReserved)
                        ownedOrFree = false;

                    if (!ownedOrFree)
                    {
                        ia.Addresses.Add(new Dhcp6IaAddress() { Address = requested.Address, PreferredLifetime = 0, ValidLifetime = 0 });
                        continue;
                    }

                    uint leaseTime = GetLeaseTime(ctx, candidate);
                    minLease = Math.Min(minLease, leaseTime);
                    anyValid = true;

                    StoreLease(ctx, request.Iaid, value, isReserved, DhcpLeaseState.Bound, GetExpiry(ctx.Now, leaseTime));
                    ia.Addresses.Add(new Dhcp6IaAddress() { Address = requested.Address, PreferredLifetime = leaseTime, ValidLifetime = leaseTime });
                }

                foreach (Dhcp6Lease binding in bindings)
                {
                    UInt128 value = Dhcp6Utilities.ToUInt128(binding.Address);

                    if (handled.Contains(value) || (binding.State != DhcpLeaseState.Bound) || !binding.IsActive(ctx.Now))
                        continue;

                    Dhcp6RangeCandidate candidate = null;

                    foreach (Dhcp6RangeCandidate c in ctx.Candidates)
                    {
                        if (c.InPrefix(value) && (c.InPool(value) || binding.Reserved))
                        {
                            candidate = c;
                            break;
                        }
                    }

                    if (candidate is null)
                        continue;

                    answerable = true;
                    uint leaseTime = GetLeaseTime(ctx, candidate);
                    minLease = Math.Min(minLease, leaseTime);
                    anyValid = true;

                    StoreLease(ctx, request.Iaid, value, binding.Reserved, DhcpLeaseState.Bound, GetExpiry(ctx.Now, leaseTime));
                    ia.Addresses.Add(new Dhcp6IaAddress() { Address = binding.Address, PreferredLifetime = leaseTime, ValidLifetime = leaseTime });
                }
            }

            if (!anyValid && HasStatefulForLink(ctx))
            {
                Dhcp6Ia assigned = AssignIa(ctx, request, true);

                if (assigned is not null)
                {
                    answerable = true;
                    ia.Addresses.AddRange(assigned.Addresses);
                    ia.T1 = assigned.T1;
                    ia.T2 = assigned.T2;
                    return ia;
                }
            }

            if (!anyValid && (request.Addresses.Count == 0))
            {
                if (rebind)
                    return null;

                answerable = true;
                return CreateIaStatus(request, Dhcp6Status.NoBinding, "no binding for this IA");
            }

            if (anyValid)
                (ia.T1, ia.T2) = GetRenewalTimes(minLease);

            return ia;
        }

        private bool IsOwnedOrFree(Context ctx, UInt128 address, string clientKey)
        {
            Dhcp6Lease lease = _store.Get(address);
            return (lease is null) || (lease.ClientKey == clientKey) || !lease.IsActive(ctx.Now);
        }

        private List<Dhcp6OptionRule> SelectOptionRules(Context ctx)
        {
            Dictionary<ushort, (Dhcp6OptionRule Rule, int Score)> selected = new Dictionary<ushort, (Dhcp6OptionRule, int)>();

            foreach (Dhcp6OptionRule rule in ctx.Config.Options6)
            {
                if (!DhcpTagCondition.AllMatch(rule.Conditions, ctx.Tags))
                    continue;

                int score = rule.Conditions.Count * 2 - (rule.Weak ? 1000 : 0);

                if (!selected.TryGetValue(rule.Code, out (Dhcp6OptionRule Rule, int Score) existing) || (score >= existing.Score))
                    selected[rule.Code] = (rule, score);
            }

            List<Dhcp6OptionRule> result = new List<Dhcp6OptionRule>(selected.Count);
            foreach ((Dhcp6OptionRule rule, int _) in selected.Values)
                result.Add(rule);

            result.Sort(delegate (Dhcp6OptionRule x, Dhcp6OptionRule y) { return x.Line.CompareTo(y.Line); });
            return result;
        }

        private static byte[] ResolveValue(Dhcp6OptionRule rule, IPAddress serverAddress, out bool unresolved)
        {
            unresolved = false;

            if (!rule.UsesServerAddress)
                return rule.Value;

            if (serverAddress is null)
            {
                unresolved = true;
                return null;
            }

            byte[] value = (byte[])rule.Value.Clone();
            byte[] server = serverAddress.GetAddressBytes();

            if (rule.Code == 56)
            {
                int offset = 0;

                while (offset + 4 <= value.Length)
                {
                    ushort subCode = BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(offset, 2));
                    ushort length = BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(offset + 2, 2));

                    if ((subCode == 1) && (length == 16) && value.AsSpan(offset + 4, 16).IndexOfAnyExcept((byte)0) < 0)
                        server.CopyTo(value, offset + 4);

                    offset += 4 + length;
                }

                return value;
            }

            for (int i = 0; i + 16 <= value.Length; i += 16)
            {
                if (value.AsSpan(i, 16).IndexOfAnyExcept((byte)0) < 0)
                    server.CopyTo(value, i);
            }

            return value;
        }

        private byte[] BuildFqdnReply(Context ctx, string hostName)
        {
            byte clientFlags = ctx.ClientFqdn.Length > 0 ? ctx.ClientFqdn[0] : (byte)0;
            bool register = ctx.Settings.RegisterDns && (hostName is not null);
            byte flags;

            if (register)
            {
                flags = 0x01;

                if ((clientFlags & 0x01) == 0)
                    flags |= 0x02;
            }
            else
            {
                flags = 0x04;
            }

            using (System.IO.MemoryStream mS = new System.IO.MemoryStream())
            {
                mS.WriteByte(flags);

                if (hostName is not null)
                {
                    string domain = GetDomain(ctx);
                    byte[] label = Encoding.ASCII.GetBytes(hostName);
                    mS.WriteByte((byte)label.Length);
                    mS.Write(label);

                    if (domain is not null)
                    {
                        foreach (string part in domain.Split('.'))
                        {
                            byte[] bytes = Encoding.ASCII.GetBytes(part);
                            mS.WriteByte((byte)bytes.Length);
                            mS.Write(bytes);
                        }

                        mS.WriteByte(0);
                    }
                }

                return mS.ToArray();
            }
        }

        private void AddInformationOptions(Context ctx, Dhcp6Message reply, bool informationRequest)
        {
            HashSet<ushort> requested = new HashSet<ushort>(ctx.Request.GetRequestedOptions());
            HashSet<ushort> added = new HashSet<ushort>();

            foreach (Dhcp6OptionRule rule in SelectOptionRules(ctx))
            {
                if (rule.Suppress)
                {
                    added.Add(rule.Code);
                    continue;
                }

                bool always = (rule.Code == Dhcp6OptionCode.DnsServers) || (rule.Code == Dhcp6OptionCode.DomainList);

                if (!always && !rule.Force && !requested.Contains(rule.Code))
                    continue;

                byte[] value = ResolveValue(rule, ctx.ServerAddress, out bool unresolved);
                added.Add(rule.Code);

                if (unresolved)
                    continue;

                reply.AddOption(new Dhcp6Option(rule.Code, value));
            }

            if (!added.Contains(Dhcp6OptionCode.DnsServers) && (ctx.ServerAddress is not null))
                reply.AddOption(new Dhcp6Option(Dhcp6OptionCode.DnsServers, ctx.ServerAddress.GetAddressBytes()));

            if (!added.Contains(Dhcp6OptionCode.DomainList))
            {
                string domain = GetDomain(ctx);

                if (domain is not null)
                    reply.AddOption(new Dhcp6Option(Dhcp6OptionCode.DomainList, Dhcp6Message.EncodeDomainList([domain])));
            }

            if (informationRequest && !added.Contains(Dhcp6OptionCode.InformationRefreshTime))
            {
                uint refresh = ctx.Settings.DefaultLeaseTime;

                foreach (Dhcp6RangeCandidate candidate in ctx.Candidates)
                {
                    if (candidate.Rule.LeaseTime != 0)
                    {
                        refresh = candidate.Rule.LeaseTime;
                        break;
                    }
                }

                refresh = Math.Clamp(refresh, 600, 86400);
                byte[] data = new byte[4];
                BinaryPrimitives.WriteUInt32BigEndian(data, refresh);
                reply.AddOption(new Dhcp6Option(Dhcp6OptionCode.InformationRefreshTime, data));
            }
        }

        private Dhcp6Message CreateReply(Context ctx, Dhcp6MessageType type)
        {
            Dhcp6Message reply = new Dhcp6Message() { Type = type, TransactionId = ctx.Request.TransactionId };
            reply.AddOption(new Dhcp6Option(Dhcp6OptionCode.ServerId, _serverDuid));

            if (ctx.ClientDuid is not null)
                reply.AddOption(new Dhcp6Option(Dhcp6OptionCode.ClientId, ctx.ClientDuid));

            return reply;
        }

        private void AddFqdn(Context ctx, Dhcp6Message reply)
        {
            if (ctx.ClientFqdn is not null)
                reply.AddOption(new Dhcp6Option(Dhcp6OptionCode.ClientFqdn, BuildFqdnReply(ctx, GetHostName(ctx))));
        }

        private bool HasDhcpForLink(Context ctx)
        {
            foreach (Dhcp6RangeCandidate candidate in ctx.Candidates)
            {
                if (candidate.Rule.OffersDhcp)
                    return true;
            }

            return false;
        }

        private bool HasStatefulForLink(Context ctx)
        {
            foreach (Dhcp6RangeCandidate candidate in ctx.Candidates)
            {
                if (candidate.Rule.AssignsAddresses || ((ctx.Host?.Address6 is not null) && candidate.Rule.OffersDhcp))
                    return true;
            }

            return false;
        }

        private Dhcp6Message HandleSolicit(Context ctx, out int delayMs)
        {
            delayMs = 0;
            Interlocked.Increment(ref _solicits);

            if (ctx.Settings.OffersPaused || !HasStatefulForLink(ctx))
                return null;

            bool rapid = ctx.Config.RapidCommit && ctx.Request.HasOption(Dhcp6OptionCode.RapidCommit);
            Dhcp6Message reply = CreateReply(ctx, rapid ? Dhcp6MessageType.Reply : Dhcp6MessageType.Advertise);

            if (rapid)
                reply.AddOption(new Dhcp6Option(Dhcp6OptionCode.RapidCommit, []));

            if (ctx.Settings.PreferMe && !rapid)
                reply.AddOption(new Dhcp6Option(Dhcp6OptionCode.Preference, [255]));

            int assigned = 0;
            List<Dhcp6Ia> ias = GetIas(ctx.Request, Dhcp6OptionCode.IaNa);

            foreach (Dhcp6Ia request in ias)
            {
                Dhcp6Ia ia = AssignIa(ctx, request, rapid);

                if (ia is null)
                {
                    reply.AddOption(CreateIaStatus(request, Dhcp6Status.NoAddrsAvail, "no addresses available").ToOption());
                    continue;
                }

                assigned++;
                reply.AddOption(ia.ToOption());
            }

            foreach (Dhcp6Ia request in GetIas(ctx.Request, Dhcp6OptionCode.IaPd))
                reply.AddOption(CreateIaStatus(request, Dhcp6Status.NoPrefixAvail, "prefix delegation is not supported").ToOption());

            if ((assigned == 0) && (ias.Count > 0))
            {
                Interlocked.Increment(ref _noAddresses);
                reply.AddOption(new Dhcp6Option(Dhcp6OptionCode.StatusCode, Dhcp6Message.EncodeStatus(Dhcp6Status.NoAddrsAvail, "no addresses available")));
            }

            AddFqdn(ctx, reply);
            AddInformationOptions(ctx, reply, false);

            delayMs = ctx.Settings.ResponseDelayMs;

            if (rapid)
                Interlocked.Increment(ref _replies);
            else
                Interlocked.Increment(ref _advertises);

            return reply;
        }

        private Dhcp6Message HandleRequest(Context ctx)
        {
            Interlocked.Increment(ref _requests);

            if (!HasStatefulForLink(ctx))
                return null;

            Dhcp6Message reply = CreateReply(ctx, Dhcp6MessageType.Reply);
            int assigned = 0;
            List<Dhcp6Ia> ias = GetIas(ctx.Request, Dhcp6OptionCode.IaNa);

            foreach (Dhcp6Ia request in ias)
            {
                Dhcp6Ia ia = AssignIa(ctx, request, true);

                if (ia is null)
                {
                    reply.AddOption(CreateIaStatus(request, Dhcp6Status.NoAddrsAvail, "no addresses available").ToOption());
                    continue;
                }

                assigned++;
                reply.AddOption(ia.ToOption());
            }

            foreach (Dhcp6Ia request in GetIas(ctx.Request, Dhcp6OptionCode.IaPd))
                reply.AddOption(CreateIaStatus(request, Dhcp6Status.NoPrefixAvail, "prefix delegation is not supported").ToOption());

            if ((assigned == 0) && (ias.Count > 0))
                Interlocked.Increment(ref _noAddresses);

            AddFqdn(ctx, reply);
            AddInformationOptions(ctx, reply, false);
            Interlocked.Increment(ref _replies);
            return reply;
        }

        private Dhcp6Message HandleRenewOrRebind(Context ctx, bool rebind)
        {
            if (rebind)
                Interlocked.Increment(ref _rebinds);
            else
                Interlocked.Increment(ref _renews);

            if (!HasDhcpForLink(ctx) && (ctx.Candidates.Count == 0) && rebind)
                return null;

            Dhcp6Message reply = CreateReply(ctx, Dhcp6MessageType.Reply);
            bool any = false;

            foreach (Dhcp6Ia request in GetIas(ctx.Request, Dhcp6OptionCode.IaNa))
            {
                Dhcp6Ia ia = ExtendIa(ctx, request, rebind, out bool answerable);

                if (ia is null)
                    continue;

                if (answerable)
                    any = true;

                reply.AddOption(ia.ToOption());
            }

            foreach (Dhcp6Ia request in GetIas(ctx.Request, Dhcp6OptionCode.IaPd))
            {
                any |= !rebind;

                if (!rebind)
                    reply.AddOption(CreateIaStatus(request, Dhcp6Status.NoBinding, "prefix delegation is not supported").ToOption());
            }

            if (!any)
                return null;

            AddFqdn(ctx, reply);
            AddInformationOptions(ctx, reply, false);
            Interlocked.Increment(ref _replies);
            return reply;
        }

        private Dhcp6Message HandleConfirm(Context ctx)
        {
            Interlocked.Increment(ref _confirms);

            if (ctx.Candidates.Count == 0)
                return null;

            int count = 0;
            bool allOnLink = true;

            foreach (Dhcp6Ia ia in GetIas(ctx.Request, Dhcp6OptionCode.IaNa))
            {
                foreach (Dhcp6IaAddress address in ia.Addresses)
                {
                    count++;
                    UInt128 value = Dhcp6Utilities.ToUInt128(address.Address);
                    bool onLink = false;

                    foreach (Dhcp6RangeCandidate candidate in ctx.Candidates)
                    {
                        if (candidate.InPrefix(value))
                        {
                            onLink = true;
                            break;
                        }
                    }

                    if (!onLink)
                        allOnLink = false;
                }
            }

            if (count == 0)
                return null;

            Dhcp6Message reply = CreateReply(ctx, Dhcp6MessageType.Reply);
            reply.AddOption(new Dhcp6Option(Dhcp6OptionCode.StatusCode, Dhcp6Message.EncodeStatus(allOnLink ? Dhcp6Status.Success : Dhcp6Status.NotOnLink, allOnLink ? "all addresses are on link" : "an address is not on link")));
            Interlocked.Increment(ref _replies);
            return reply;
        }

        private Dhcp6Message HandleReleaseOrDecline(Context ctx, bool decline)
        {
            if (decline)
                Interlocked.Increment(ref _declines);
            else
                Interlocked.Increment(ref _releases);

            Dhcp6Message reply = CreateReply(ctx, Dhcp6MessageType.Reply);

            lock (_allocationLock)
            {
                foreach (Dhcp6Ia ia in GetIas(ctx.Request, Dhcp6OptionCode.IaNa))
                {
                    string clientKey = Dhcp6Lease.GetClientKey(ctx.ClientDuid, ia.Iaid);
                    bool found = false;

                    foreach (Dhcp6IaAddress address in ia.Addresses)
                    {
                        Dhcp6Lease lease = _store.Get(address.Address);

                        if ((lease is null) || (lease.ClientKey != clientKey))
                            continue;

                        found = true;

                        if (decline)
                        {
                            _store.Put(lease.With(DhcpLeaseState.Declined, ctx.Now.AddSeconds(DECLINE_HOLD_SECONDS), ctx.Now));
                            _log("DHCPv6 client " + DhcpUtilities.FormatHex(ctx.ClientDuid) + " declined " + address.Address + ", the address is blocked for one hour.");
                        }
                        else
                        {
                            _store.Put(lease.With(DhcpLeaseState.Released, ctx.Now, ctx.Now));
                        }
                    }

                    if (!found)
                        reply.AddOption(CreateIaStatus(ia, Dhcp6Status.NoBinding, "no binding for this IA").ToOption());
                }
            }

            reply.AddOption(new Dhcp6Option(Dhcp6OptionCode.StatusCode, Dhcp6Message.EncodeStatus(Dhcp6Status.Success, decline ? "declined" : "released")));
            Interlocked.Increment(ref _replies);
            return reply;
        }

        private Dhcp6Message HandleInformationRequest(Context ctx)
        {
            Interlocked.Increment(ref _informationRequests);

            if (!HasDhcpForLink(ctx))
                return null;

            Dhcp6Message reply = CreateReply(ctx, Dhcp6MessageType.Reply);
            AddInformationOptions(ctx, reply, true);
            Interlocked.Increment(ref _replies);
            return reply;
        }

        private static Dhcp6Message WrapRelayReply(Dhcp6Message reply, List<Dhcp6Message> relays)
        {
            Dhcp6Message current = reply;

            for (int i = relays.Count - 1; i >= 0; i--)
            {
                Dhcp6Message relay = relays[i];
                Dhcp6Message wrapper = new Dhcp6Message() { Type = Dhcp6MessageType.RelayReply, HopCount = relay.HopCount, LinkAddress = relay.LinkAddress, PeerAddress = relay.PeerAddress };

                byte[] interfaceId = relay.GetOptionData(Dhcp6OptionCode.InterfaceId);
                if (interfaceId is not null)
                    wrapper.AddOption(new Dhcp6Option(Dhcp6OptionCode.InterfaceId, interfaceId));

                wrapper.AddOption(new Dhcp6Option(Dhcp6OptionCode.RelayMessage, current.Serialize()));
                current = wrapper;
            }

            return current;
        }

        #endregion

        #region public

        public void Configure(DhcpConfiguration config, Dhcp6EngineSettings settings, byte[] serverDuid, Func<byte[], string> findHostNameByMac, Func<UInt128, bool> isLocalAddress, Func<byte[], IPAddress, byte[]> resolveClientMac = null)
        {
            _resolveClientMac = resolveClientMac;
            _config = config;
            _settings = settings;
            _serverDuid = serverDuid;
            _findHostNameByMac = findHostNameByMac;
            _isLocalAddress = isLocalAddress;
        }

        public Dhcp6Reply Process(Dhcp6Message message, Dhcp6InterfaceInfo iface, IPAddress source, bool multicastDestination)
        {
            DhcpConfiguration config = _config;
            Dhcp6EngineSettings settings = _settings;

            if (!settings.Serving || (config.Ranges6.Count == 0))
                return null;

            List<Dhcp6Message> relays = new List<Dhcp6Message>();
            Dhcp6Message request = message;

            while (request.Type == Dhcp6MessageType.RelayForward)
            {
                if (relays.Count >= Dhcp6Message.MAX_HOP_COUNT)
                    return null;

                relays.Add(request);
                byte[] inner = request.GetOptionData(Dhcp6OptionCode.RelayMessage);

                if ((inner is null) || !Dhcp6Message.TryParse(inner, out request, out _))
                    return null;
            }

            if (request.IsRelay || (request.Type == Dhcp6MessageType.Advertise) || (request.Type == Dhcp6MessageType.Reply) || (request.Type == Dhcp6MessageType.Reconfigure))
                return null;

            if (relays.Count > 0)
                Interlocked.Increment(ref _relayed);

            byte[] clientDuid = request.GetOptionData(Dhcp6OptionCode.ClientId);
            byte[] serverDuid = request.GetOptionData(Dhcp6OptionCode.ServerId);

            if ((clientDuid is not null) && ((clientDuid.Length < 2) || (clientDuid.Length > 130)))
                return null;

            bool serverMatches = (serverDuid is not null) && serverDuid.AsSpan().SequenceEqual(_serverDuid);

            switch (request.Type)
            {
                case Dhcp6MessageType.Solicit:
                case Dhcp6MessageType.Confirm:
                case Dhcp6MessageType.Rebind:
                    if ((clientDuid is null) || (serverDuid is not null))
                    {
                        Interlocked.Increment(ref _ignored);
                        return null;
                    }

                    break;

                case Dhcp6MessageType.Request:
                case Dhcp6MessageType.Renew:
                case Dhcp6MessageType.Release:
                case Dhcp6MessageType.Decline:
                    if ((clientDuid is null) || (serverDuid is null))
                    {
                        Interlocked.Increment(ref _ignored);
                        return null;
                    }

                    if (!serverMatches)
                    {
                        ForeignServerSeen?.Invoke(serverDuid, iface.Name);
                        return null;
                    }

                    break;

                case Dhcp6MessageType.InformationRequest:
                    if ((serverDuid is not null) && !serverMatches)
                        return null;

                    if (request.HasOption(Dhcp6OptionCode.IaNa) || request.HasOption(Dhcp6OptionCode.IaTa) || request.HasOption(Dhcp6OptionCode.IaPd))
                        return null;

                    break;

                default:
                    return null;
            }

            Context ctx = BuildContext(request, relays, iface, source, config, settings);
            ctx.ClientDuid ??= [];

            if (IsIgnored(ctx))
            {
                Interlocked.Increment(ref _ignored);
                return null;
            }

            if (!multicastDestination && (relays.Count == 0))
            {
                if ((source is null) || !(source.IsIPv6LinkLocal || iface.IsOnLink(source)))
                {
                    Interlocked.Increment(ref _ignored);
                    return null;
                }

                switch (request.Type)
                {
                    case Dhcp6MessageType.Request:
                    case Dhcp6MessageType.Renew:
                    case Dhcp6MessageType.Release:
                    case Dhcp6MessageType.Decline:
                        {
                            Dhcp6Message useMulticast = CreateReply(ctx, Dhcp6MessageType.Reply);
                            useMulticast.AddOption(new Dhcp6Option(Dhcp6OptionCode.StatusCode, Dhcp6Message.EncodeStatus(Dhcp6Status.UseMulticast, "use multicast")));
                            return new Dhcp6Reply() { Message = useMulticast };
                        }

                    default:
                        Interlocked.Increment(ref _ignored);
                        return null;
                }
            }

            Dhcp6Message reply = null;
            int delayMs = 0;

            switch (request.Type)
            {
                case Dhcp6MessageType.Solicit:
                    reply = HandleSolicit(ctx, out delayMs);
                    break;

                case Dhcp6MessageType.Request:
                    reply = HandleRequest(ctx);
                    break;

                case Dhcp6MessageType.Renew:
                    reply = HandleRenewOrRebind(ctx, false);
                    break;

                case Dhcp6MessageType.Rebind:
                    reply = HandleRenewOrRebind(ctx, true);
                    break;

                case Dhcp6MessageType.Confirm:
                    reply = HandleConfirm(ctx);
                    break;

                case Dhcp6MessageType.Release:
                    reply = HandleReleaseOrDecline(ctx, false);
                    break;

                case Dhcp6MessageType.Decline:
                    reply = HandleReleaseOrDecline(ctx, true);
                    break;

                case Dhcp6MessageType.InformationRequest:
                    reply = HandleInformationRequest(ctx);
                    break;
            }

            if (reply is null)
                return null;

            if (relays.Count > 0)
                return new Dhcp6Reply() { Message = WrapRelayReply(reply, relays), DelayMs = delayMs, ToRelay = true };

            return new Dhcp6Reply() { Message = reply, DelayMs = delayMs };
        }

        public IReadOnlyDictionary<string, long> GetCounters()
        {
            return new Dictionary<string, long>()
            {
                { "solicit", Interlocked.Read(ref _solicits) },
                { "request", Interlocked.Read(ref _requests) },
                { "renew", Interlocked.Read(ref _renews) },
                { "rebind", Interlocked.Read(ref _rebinds) },
                { "release", Interlocked.Read(ref _releases) },
                { "decline", Interlocked.Read(ref _declines) },
                { "confirm", Interlocked.Read(ref _confirms) },
                { "informationRequest", Interlocked.Read(ref _informationRequests) },
                { "advertise", Interlocked.Read(ref _advertises) },
                { "reply", Interlocked.Read(ref _replies) },
                { "noAddresses", Interlocked.Read(ref _noAddresses) },
                { "ignored", Interlocked.Read(ref _ignored) },
                { "relayed", Interlocked.Read(ref _relayed) }
            };
        }

        public Dhcp6EngineSettings Settings
        { get { return _settings; } }

        #endregion
    }
}
