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
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.ZoneManagers
{
    enum ListRuleAction : byte
    {
        None = 0,
        Allow = 1,
        Block = 2
    }

    enum ListRuleMatchKind : byte
    {
        Tree = 0,
        SubdomainsOnly = 1,
        Exact = 2,
        Regex = 3
    }

    readonly struct ListRuleMatch
    {
        public readonly ListRuleAction Action;
        public readonly string Domain;
        public readonly IReadOnlyList<Uri> Lists;

        public ListRuleMatch(ListRuleAction action, string domain, IReadOnlyList<Uri> lists)
        {
            Action = action;
            Domain = domain;
            Lists = lists;
        }
    }

    sealed class ListRuleCounts
    {
        public int Domains;
        public int Exceptions;
        public int Regexes;
        public int Ips;
        public int Advanced;
        public int Skipped;
    }

    readonly struct ListClientInfo
    {
        public readonly IPAddress Address;
        public readonly string Name;
        public readonly string ClientId;

        public ListClientInfo(IPAddress address, string name, string clientId)
        {
            Address = address;
            Name = name;
            ClientId = clientId;
        }
    }

    sealed class ListRuleFilter
    {
        public readonly bool[] Lists;
        public readonly bool[] Combinations;
        public readonly bool IsEmpty;

        public ListRuleFilter(bool[] lists, bool[] combinations)
        {
            Lists = lists;
            Combinations = combinations;
            IsEmpty = Array.IndexOf(lists, true) < 0;
        }
    }

    sealed class ListClientMatcher
    {
        readonly NetworkAddress[] _includeNetworks;
        readonly string[] _includeNames;
        readonly NetworkAddress[] _excludeNetworks;
        readonly string[] _excludeNames;

        private ListClientMatcher(NetworkAddress[] includeNetworks, string[] includeNames, NetworkAddress[] excludeNetworks, string[] excludeNames)
        {
            _includeNetworks = includeNetworks;
            _includeNames = includeNames;
            _excludeNetworks = excludeNetworks;
            _excludeNames = excludeNames;
        }

        public static bool TryParse(string value, out ListClientMatcher matcher)
        {
            matcher = null;

            List<NetworkAddress> includeNetworks = new List<NetworkAddress>();
            List<string> includeNames = new List<string>();
            List<NetworkAddress> excludeNetworks = new List<NetworkAddress>();
            List<string> excludeNames = new List<string>();

            foreach (string rawEntry in ListRuleSetBuilder.SplitUnquoted(value, '|'))
            {
                string entry = rawEntry.Trim();
                bool negated = entry.StartsWith('~');

                if (negated)
                    entry = entry.Substring(1).Trim();

                entry = ListRuleSetBuilder.Unquote(entry);

                if (entry.Length == 0)
                    return false;

                if (NetworkAddress.TryParse(entry, out NetworkAddress network))
                    (negated ? excludeNetworks : includeNetworks).Add(network);
                else
                    (negated ? excludeNames : includeNames).Add(entry);
            }

            if ((includeNetworks.Count + includeNames.Count + excludeNetworks.Count + excludeNames.Count) == 0)
                return false;

            matcher = new ListClientMatcher(includeNetworks.ToArray(), includeNames.ToArray(), excludeNetworks.ToArray(), excludeNames.ToArray());
            return true;
        }

        private static bool MatchesAny(NetworkAddress[] networks, string[] names, in ListClientInfo client)
        {
            if (client.Address is not null)
            {
                foreach (NetworkAddress network in networks)
                {
                    if (network.Contains(client.Address))
                        return true;
                }
            }

            foreach (string name in names)
            {
                if ((client.Name is not null) && name.Equals(client.Name, StringComparison.OrdinalIgnoreCase))
                    return true;

                if ((client.ClientId is not null) && name.Equals(client.ClientId, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        public bool Matches(in ListClientInfo client)
        {
            if (MatchesAny(_excludeNetworks, _excludeNames, client))
                return false;

            if ((_includeNetworks.Length == 0) && (_includeNames.Length == 0))
                return true;

            return MatchesAny(_includeNetworks, _includeNames, client);
        }
    }

    sealed class ListRuleTables
    {
        public DomainTable Tree = DomainTable.Empty;
        public DomainTable SubdomainsOnly = DomainTable.Empty;
        public DomainTable Exact = DomainTable.Empty;
        public DomainTable BadTree = DomainTable.Empty;
        public DomainTable BadSubdomainsOnly = DomainTable.Empty;
        public DomainTable BadExact = DomainTable.Empty;

        public bool IsEmpty
        { get { return (Tree.Count == 0) && (SubdomainsOnly.Count == 0) && (Exact.Count == 0); } }

        public int Count
        { get { return Tree.Count + SubdomainsOnly.Count + Exact.Count; } }

        public long MemoryUsage
        { get { return Tree.MemoryUsage + SubdomainsOnly.MemoryUsage + Exact.MemoryUsage + BadTree.MemoryUsage + BadSubdomainsOnly.MemoryUsage + BadExact.MemoryUsage; } }

        public DomainTable Get(ListRuleMatchKind kind, bool bad)
        {
            switch (kind)
            {
                case ListRuleMatchKind.SubdomainsOnly:
                    return bad ? BadSubdomainsOnly : SubdomainsOnly;

                case ListRuleMatchKind.Exact:
                    return bad ? BadExact : Exact;

                default:
                    return bad ? BadTree : Tree;
            }
        }

        public void Set(ListRuleMatchKind kind, bool bad, DomainTable table)
        {
            switch (kind)
            {
                case ListRuleMatchKind.SubdomainsOnly:
                    if (bad)
                        BadSubdomainsOnly = table;
                    else
                        SubdomainsOnly = table;

                    break;

                case ListRuleMatchKind.Exact:
                    if (bad)
                        BadExact = table;
                    else
                        Exact = table;

                    break;

                default:
                    if (bad)
                        BadTree = table;
                    else
                        Tree = table;

                    break;
            }
        }

        public bool TryMatch(ReadOnlySpan<char> name, bool[] combinations, out ushort value, out string matchedDomain)
        {
            ReadOnlySpan<char> current = name;
            bool full = true;

            while (true)
            {
                if ((Tree.Count > 0) && Tree.TryGetValue(current, out value) && ((combinations is null) || combinations[value]) && ((BadTree.Count == 0) || !BadTree.Contains(current)))
                {
                    matchedDomain = current.ToString();
                    return true;
                }

                if (full)
                {
                    if ((Exact.Count > 0) && Exact.TryGetValue(current, out value) && ((combinations is null) || combinations[value]) && ((BadExact.Count == 0) || !BadExact.Contains(current)))
                    {
                        matchedDomain = current.ToString();
                        return true;
                    }
                }
                else
                {
                    if ((SubdomainsOnly.Count > 0) && SubdomainsOnly.TryGetValue(current, out value) && ((combinations is null) || combinations[value]) && ((BadSubdomainsOnly.Count == 0) || !BadSubdomainsOnly.Contains(current)))
                    {
                        matchedDomain = current.ToString();
                        return true;
                    }
                }

                int i = current.IndexOf('.');
                if (i < 0)
                    break;

                current = current.Slice(i + 1);
                full = false;
            }

            value = 0;
            matchedDomain = null;
            return false;
        }

        public void TrimExcess()
        {
            Tree.TrimExcess();
            SubdomainsOnly.TrimExcess();
            Exact.TrimExcess();
        }
    }

    sealed class ListAdvancedRule
    {
        public bool Exception;
        public bool Important;
        public ListRuleMatchKind Kind;
        public string Domain;
        public Regex Regex;
        public HashSet<ushort> DnsTypes;
        public bool DnsTypesNegated;
        public string[] DenyAllow;
        public ListClientMatcher Clients;
        public Uri List;
        public ushort ListIndex;
        public string Key;

        public bool AppliesTo(string name, ushort qtype, ListRuleFilter filter, in ListClientInfo client)
        {
            if ((filter is not null) && !filter.Lists[ListIndex])
                return false;

            if ((Clients is not null) && !Clients.Matches(client))
                return false;

            if (DnsTypes is not null)
            {
                bool contained = DnsTypes.Contains(qtype);
                if (contained == DnsTypesNegated)
                    return false;
            }

            if (DenyAllow is not null)
            {
                foreach (string domain in DenyAllow)
                {
                    if (name.Equals(domain, StringComparison.Ordinal) || name.EndsWith("." + domain, StringComparison.Ordinal))
                        return false;
                }
            }

            return true;
        }
    }

    sealed class ListRegexGroup
    {
        public Regex Regex;
        public Uri List;
        public ushort ListIndex;
        public bool Exception;
    }

    sealed class ListIpRuleSet
    {
        readonly Dictionary<int, Dictionary<uint, ushort>> _ipv4 = new Dictionary<int, Dictionary<uint, ushort>>();
        readonly Dictionary<int, Dictionary<UInt128, ushort>> _ipv6 = new Dictionary<int, Dictionary<UInt128, ushort>>();
        int[] _ipv4Prefixes = [];
        int[] _ipv6Prefixes = [];
        int _count;

        private static uint Mask4(uint value, int prefix)
        {
            return prefix == 0 ? 0 : value & (uint.MaxValue << (32 - prefix));
        }

        private static UInt128 Mask6(UInt128 value, int prefix)
        {
            return prefix == 0 ? UInt128.Zero : value & (UInt128.MaxValue << (128 - prefix));
        }

        public int Get(IPAddress address, int prefix)
        {
            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                if (_ipv4.TryGetValue(prefix, out Dictionary<uint, ushort> table) && table.TryGetValue(Mask4(BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes()), prefix), out ushort combination))
                    return combination;
            }
            else
            {
                if (_ipv6.TryGetValue(prefix, out Dictionary<UInt128, ushort> table) && table.TryGetValue(Mask6(BinaryPrimitives.ReadUInt128BigEndian(address.GetAddressBytes()), prefix), out ushort combination))
                    return combination;
            }

            return -1;
        }

        public void Set(IPAddress address, int prefix, ushort combination)
        {
            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            bool added;

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                uint value = Mask4(BinaryPrimitives.ReadUInt32BigEndian(address.GetAddressBytes()), prefix);

                if (!_ipv4.TryGetValue(prefix, out Dictionary<uint, ushort> table))
                {
                    table = new Dictionary<uint, ushort>();
                    _ipv4[prefix] = table;
                    _ipv4Prefixes = [.. _ipv4Prefixes, prefix];
                    Array.Sort(_ipv4Prefixes);
                    Array.Reverse(_ipv4Prefixes);
                }

                added = !table.ContainsKey(value);
                table[value] = combination;
            }
            else
            {
                UInt128 value = Mask6(BinaryPrimitives.ReadUInt128BigEndian(address.GetAddressBytes()), prefix);

                if (!_ipv6.TryGetValue(prefix, out Dictionary<UInt128, ushort> table))
                {
                    table = new Dictionary<UInt128, ushort>();
                    _ipv6[prefix] = table;
                    _ipv6Prefixes = [.. _ipv6Prefixes, prefix];
                    Array.Sort(_ipv6Prefixes);
                    Array.Reverse(_ipv6Prefixes);
                }

                added = !table.ContainsKey(value);
                table[value] = combination;
            }

            if (added)
                _count++;
        }

        public bool TryMatch(IPAddress address, bool[] combinations, out ushort combination)
        {
            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                if (_ipv4Prefixes.Length > 0)
                {
                    Span<byte> bytes = stackalloc byte[4];
                    address.TryWriteBytes(bytes, out _);
                    uint value = BinaryPrimitives.ReadUInt32BigEndian(bytes);

                    foreach (int prefix in _ipv4Prefixes)
                    {
                        if (_ipv4[prefix].TryGetValue(Mask4(value, prefix), out combination) && ((combinations is null) || combinations[combination]))
                            return true;
                    }
                }
            }
            else if (_ipv6Prefixes.Length > 0)
            {
                Span<byte> bytes = stackalloc byte[16];
                address.TryWriteBytes(bytes, out _);
                UInt128 value = BinaryPrimitives.ReadUInt128BigEndian(bytes);

                foreach (int prefix in _ipv6Prefixes)
                {
                    if (_ipv6[prefix].TryGetValue(Mask6(value, prefix), out combination) && ((combinations is null) || combinations[combination]))
                        return true;
                }
            }

            combination = 0;
            return false;
        }

        public int Count
        { get { return _count; } }
    }

    sealed class ListRuleSet
    {
        #region variables

        public static readonly ListRuleSet Empty = new ListRuleSetBuilder().Build();

        internal readonly ListRuleTables Block;
        internal readonly ListRuleTables Allow;
        internal readonly ListRuleTables ImportantBlock;
        internal readonly ListRuleTables ImportantAllow;
        internal readonly Uri[][] Combinations;
        internal readonly ushort[][] CombinationLists;
        internal readonly Uri[] Lists;
        internal readonly bool[] ListIsAllow;

        readonly Dictionary<string, List<ListAdvancedRule>> _advancedByDomain;
        readonly ListAdvancedRule[] _advancedRegex;
        readonly ListRegexGroup[] _regexGroups;
        readonly bool _hasImportantAdvanced;
        readonly bool _hasExceptionAdvanced;
        readonly bool _hasBlockAdvanced;
        readonly bool _hasExceptionRegex;
        readonly bool _hasBlockRegex;

        internal readonly ListIpRuleSet IpBlock;
        internal readonly ListIpRuleSet IpAllow;

        #endregion

        #region constructor

        internal ListRuleSet(ListRuleTables block, ListRuleTables allow, ListRuleTables importantBlock, ListRuleTables importantAllow, Uri[][] combinations, ushort[][] combinationLists, Uri[] lists, bool[] listIsAllow, Dictionary<string, List<ListAdvancedRule>> advancedByDomain, ListAdvancedRule[] advancedRegex, ListRegexGroup[] regexGroups, ListIpRuleSet ipBlock, ListIpRuleSet ipAllow)
        {
            Block = block;
            Allow = allow;
            ImportantBlock = importantBlock;
            ImportantAllow = importantAllow;
            Combinations = combinations;
            CombinationLists = combinationLists;
            Lists = lists;
            ListIsAllow = listIsAllow;
            _advancedByDomain = advancedByDomain;
            _advancedRegex = advancedRegex;
            _regexGroups = regexGroups;
            IpBlock = ipBlock;
            IpAllow = ipAllow;

            bool hasImportantAdvanced = false;
            bool hasExceptionAdvanced = false;
            bool hasBlockAdvanced = false;

            void Classify(ListAdvancedRule rule)
            {
                if (rule.Important)
                    hasImportantAdvanced = true;
                else if (rule.Exception)
                    hasExceptionAdvanced = true;
                else
                    hasBlockAdvanced = true;
            }

            foreach (List<ListAdvancedRule> rules in advancedByDomain.Values)
            {
                foreach (ListAdvancedRule rule in rules)
                    Classify(rule);
            }

            foreach (ListAdvancedRule rule in advancedRegex)
                Classify(rule);

            _hasImportantAdvanced = hasImportantAdvanced;
            _hasExceptionAdvanced = hasExceptionAdvanced;
            _hasBlockAdvanced = hasBlockAdvanced;

            foreach (ListRegexGroup group in regexGroups)
            {
                if (group.Exception)
                    _hasExceptionRegex = true;
                else
                    _hasBlockRegex = true;
            }
        }

        #endregion

        #region private

        private ListAdvancedRule MatchAdvanced(string name, ushort qtype, bool exception, bool important, ListRuleFilter filter, in ListClientInfo client, out string matchedDomain)
        {
            if (_advancedByDomain.Count > 0)
            {
                string current = name;
                bool full = true;

                while (true)
                {
                    if (_advancedByDomain.TryGetValue(current, out List<ListAdvancedRule> rules))
                    {
                        foreach (ListAdvancedRule rule in rules)
                        {
                            if ((rule.Exception != exception) || (rule.Important != important))
                                continue;

                            if ((rule.Kind == ListRuleMatchKind.Exact) && !full)
                                continue;

                            if ((rule.Kind == ListRuleMatchKind.SubdomainsOnly) && full)
                                continue;

                            if (rule.AppliesTo(name, qtype, filter, client))
                            {
                                matchedDomain = current;
                                return rule;
                            }
                        }
                    }

                    int i = current.IndexOf('.');
                    if (i < 0)
                        break;

                    current = current.Substring(i + 1);
                    full = false;
                }
            }

            foreach (ListAdvancedRule rule in _advancedRegex)
            {
                if ((rule.Exception != exception) || (rule.Important != important))
                    continue;

                if (rule.AppliesTo(name, qtype, filter, client) && rule.Regex.IsMatch(name))
                {
                    matchedDomain = name;
                    return rule;
                }
            }

            matchedDomain = null;
            return null;
        }

        private ListRegexGroup MatchRegexGroups(string name, bool exception, ListRuleFilter filter)
        {
            foreach (ListRegexGroup group in _regexGroups)
            {
                if ((group.Exception == exception) && ((filter is null) || filter.Lists[group.ListIndex]) && group.Regex.IsMatch(name))
                    return group;
            }

            return null;
        }

        private IReadOnlyList<Uri> GetLists(ushort combination, ListRuleFilter filter)
        {
            if (filter is null)
                return Combinations[combination];

            ushort[] indexes = CombinationLists[combination];
            List<Uri> lists = new List<Uri>(indexes.Length);

            foreach (ushort index in indexes)
            {
                if (filter.Lists[index])
                    lists.Add(Lists[index]);
            }

            return lists;
        }

        #endregion

        #region public

        public ListRuleMatch Evaluate(string domain, DnsResourceRecordType type)
        {
            return Evaluate(domain, type, null, default);
        }

        public ListRuleMatch Evaluate(string domain, DnsResourceRecordType type, ListRuleFilter filter, in ListClientInfo client)
        {
            if ((filter is not null) && filter.IsEmpty)
                return default;

            Span<char> buffer = domain.Length <= 256 ? stackalloc char[domain.Length] : new char[domain.Length];
            ReadOnlySpan<char> name = buffer.Slice(0, domain.AsSpan().ToLowerInvariant(buffer));
            ushort qtype = (ushort)type;
            bool[] combinations = filter?.Combinations;
            string lowerName = null;

            string GetName(ReadOnlySpan<char> span)
            {
                return lowerName ??= span.ToString();
            }

            if (!ImportantAllow.IsEmpty && ImportantAllow.TryMatch(name, combinations, out _, out string importantAllowDomain))
                return new ListRuleMatch(ListRuleAction.Allow, importantAllowDomain, null);

            if (_hasImportantAdvanced)
            {
                ListAdvancedRule rule = MatchAdvanced(GetName(name), qtype, true, true, filter, client, out string matched);
                if (rule is not null)
                    return new ListRuleMatch(ListRuleAction.Allow, matched, null);
            }

            if (!ImportantBlock.IsEmpty && ImportantBlock.TryMatch(name, combinations, out ushort importantCombination, out string importantBlockDomain))
                return new ListRuleMatch(ListRuleAction.Block, importantBlockDomain, GetLists(importantCombination, filter));

            if (_hasImportantAdvanced)
            {
                ListAdvancedRule rule = MatchAdvanced(GetName(name), qtype, false, true, filter, client, out string matched);
                if (rule is not null)
                    return new ListRuleMatch(ListRuleAction.Block, matched, [rule.List]);
            }

            if (!Allow.IsEmpty && Allow.TryMatch(name, combinations, out _, out string allowDomain))
                return new ListRuleMatch(ListRuleAction.Allow, allowDomain, null);

            if (_hasExceptionAdvanced)
            {
                ListAdvancedRule rule = MatchAdvanced(GetName(name), qtype, true, false, filter, client, out string matched);
                if (rule is not null)
                    return new ListRuleMatch(ListRuleAction.Allow, matched, null);
            }

            if (_hasExceptionRegex && (MatchRegexGroups(GetName(name), true, filter) is not null))
                return new ListRuleMatch(ListRuleAction.Allow, GetName(name), null);

            if (!Block.IsEmpty && Block.TryMatch(name, combinations, out ushort combination, out string blockDomain))
                return new ListRuleMatch(ListRuleAction.Block, blockDomain, GetLists(combination, filter));

            if (_hasBlockAdvanced)
            {
                ListAdvancedRule rule = MatchAdvanced(GetName(name), qtype, false, false, filter, client, out string matched);
                if (rule is not null)
                    return new ListRuleMatch(ListRuleAction.Block, matched, [rule.List]);
            }

            if (_hasBlockRegex)
            {
                ListRegexGroup group = MatchRegexGroups(GetName(name), false, filter);
                if (group is not null)
                    return new ListRuleMatch(ListRuleAction.Block, GetName(name), [group.List]);
            }

            return default;
        }

        public bool TryMatchAnswerAddress(IPAddress address, out Uri list)
        {
            return TryMatchAnswerAddress(address, null, out list);
        }

        public bool TryMatchAnswerAddress(IPAddress address, ListRuleFilter filter, out Uri list)
        {
            bool[] combinations = filter?.Combinations;

            if ((IpBlock.Count > 0) && IpBlock.TryMatch(address, combinations, out ushort combination))
            {
                if ((IpAllow.Count > 0) && IpAllow.TryMatch(address, combinations, out _))
                {
                    list = null;
                    return false;
                }

                list = GetLists(combination, filter)[0];
                return true;
            }

            list = null;
            return false;
        }

        public ListRuleFilter CreateFilter(Func<Uri, bool, bool> isEnabled)
        {
            bool[] lists = new bool[Lists.Length];
            bool all = true;

            for (int i = 0; i < lists.Length; i++)
            {
                lists[i] = isEnabled(Lists[i], ListIsAllow[i]);

                if (!lists[i])
                    all = false;
            }

            if (all)
                return null;

            bool[] combinations = new bool[CombinationLists.Length];

            for (int i = 0; i < combinations.Length; i++)
            {
                foreach (ushort index in CombinationLists[i])
                {
                    if (lists[index])
                    {
                        combinations[i] = true;
                        break;
                    }
                }
            }

            return new ListRuleFilter(lists, combinations);
        }

        #endregion

        #region properties

        public bool IsEmpty
        {
            get
            {
                return Block.IsEmpty && Allow.IsEmpty && ImportantBlock.IsEmpty && ImportantAllow.IsEmpty && (_advancedByDomain.Count == 0) && (_advancedRegex.Length == 0) && (_regexGroups.Length == 0) && (IpBlock.Count == 0);
            }
        }

        public bool HasAllowRules
        {
            get { return !Allow.IsEmpty || !ImportantAllow.IsEmpty || _hasExceptionAdvanced || _hasExceptionRegex || _hasImportantAdvanced; }
        }

        public bool HasBlockRules
        {
            get { return !Block.IsEmpty || !ImportantBlock.IsEmpty || _hasBlockAdvanced || _hasBlockRegex || _hasImportantAdvanced; }
        }

        public bool HasIpRules
        { get { return IpBlock.Count > 0; } }

        public int BlockedDomainCount
        { get { return Block.Count + ImportantBlock.Count; } }

        public int AllowedDomainCount
        { get { return Allow.Count + ImportantAllow.Count; } }

        public int RegexCount
        { get { return _regexGroups.Length + _advancedRegex.Length; } }

        public int AdvancedCount
        {
            get
            {
                int count = _advancedRegex.Length;

                foreach (List<ListAdvancedRule> rules in _advancedByDomain.Values)
                    count += rules.Count;

                return count;
            }
        }

        public long MemoryUsage
        { get { return Block.MemoryUsage + Allow.MemoryUsage + ImportantBlock.MemoryUsage + ImportantAllow.MemoryUsage; } }

        #endregion
    }

    sealed partial class ListRuleSetBuilder
    {
        #region variables

        const int MAX_REGEX_LENGTH = 1024;
        const int MAX_REGEX_RULES_PER_LIST = 10000;
        const int MIN_IPV4_PREFIX = 8;
        const int MIN_IPV6_PREFIX = 16;

        static readonly RegexOptions REGEX_OPTIONS = RegexOptions.NonBacktracking | RegexOptions.CultureInvariant | RegexOptions.IgnoreCase;
        static readonly TimeSpan REGEX_TIMEOUT = TimeSpan.FromMilliseconds(50);
        static readonly char[] _whitespace = [' ', '\t'];

        readonly ListRuleTables _block = new ListRuleTables();
        readonly ListRuleTables _allow = new ListRuleTables();
        readonly ListRuleTables _importantBlock = new ListRuleTables();
        readonly ListRuleTables _importantAllow = new ListRuleTables();

        readonly List<Uri[]> _combinations = new List<Uri[]>();
        readonly List<ushort[]> _combinationLists = new List<ushort[]>();
        readonly Dictionary<(int, int), int> _extendedCombinations = new Dictionary<(int, int), int>();
        readonly List<Uri> _lists = new List<Uri>();
        readonly List<bool> _listIsAllow = new List<bool>();

        readonly Dictionary<string, List<ListAdvancedRule>> _advancedByDomain = new Dictionary<string, List<ListAdvancedRule>>(StringComparer.Ordinal);
        readonly List<ListAdvancedRule> _advancedRegex = new List<ListAdvancedRule>();
        readonly List<ListRegexGroup> _regexGroups = new List<ListRegexGroup>();
        readonly HashSet<string> _badfilters = new HashSet<string>(StringComparer.Ordinal);

        readonly ListIpRuleSet _ipBlock = new ListIpRuleSet();
        readonly ListIpRuleSet _ipAllow = new ListIpRuleSet();

        readonly long _blockCapacity;

        #endregion

        #region constructor

        public ListRuleSetBuilder(long blockCapacity = 0)
        {
            _blockCapacity = blockCapacity;
        }

        #endregion

        #region private

        [GeneratedRegex("^[a-z0-9_*]([a-z0-9_*.-]*[a-z0-9_*])?$")]
        private static partial Regex AdblockPatternRegex();

        private sealed class ListState
        {
            public Uri Url;
            public int Index;
            public int SingleCombination = -1;
            public ListRuleCounts Counts = new ListRuleCounts();
            public List<(string Pattern, string Key)> BlockRegexPatterns = new List<(string Pattern, string Key)>();
            public List<(string Pattern, string Key)> AllowRegexPatterns = new List<(string Pattern, string Key)>();
        }

        private DomainTable GetOrCreateTable(ListRuleTables tables, ListRuleMatchKind kind, bool bad, long capacity)
        {
            DomainTable table = tables.Get(kind, bad);

            if (ReferenceEquals(table, DomainTable.Empty))
            {
                table = new DomainTable(capacity);
                tables.Set(kind, bad, table);
            }

            return table;
        }

        private int GetCombination(ListState state, int existing)
        {
            if (existing < 0)
            {
                if (state.SingleCombination < 0)
                {
                    if (_combinations.Count > ushort.MaxValue)
                        return -1;

                    state.SingleCombination = _combinations.Count;
                    _combinations.Add([state.Url]);
                    _combinationLists.Add([(ushort)state.Index]);
                }

                return state.SingleCombination;
            }

            if (Array.IndexOf(_combinationLists[existing], (ushort)state.Index) >= 0)
                return -1;

            if (!_extendedCombinations.TryGetValue((existing, state.Index), out int extendedCombination))
            {
                if (_combinations.Count > ushort.MaxValue)
                    return -1;

                extendedCombination = _combinations.Count;
                _combinations.Add([.. _combinations[existing], state.Url]);
                _combinationLists.Add([.. _combinationLists[existing], (ushort)state.Index]);
                _extendedCombinations.Add((existing, state.Index), extendedCombination);
            }

            return extendedCombination;
        }

        private void AddDomainRule(ListState state, string domain, ListRuleMatchKind kind, bool exception, bool important, bool badfilter)
        {
            ListRuleTables tables = exception ? (important ? _importantAllow : _allow) : (important ? _importantBlock : _block);

            if (badfilter)
            {
                GetOrCreateTable(tables, kind, true, 16).TryAdd(domain, 0, out _);
                return;
            }

            long capacity = (!exception && !important && (kind == ListRuleMatchKind.Tree)) ? Math.Max(16, _blockCapacity) : 16;
            DomainTable table = GetOrCreateTable(tables, kind, false, capacity);

            int combination;

            if (table.TryAdd(domain, 0, out int handle))
            {
                combination = GetCombination(state, -1);
            }
            else if (handle >= 0)
            {
                combination = GetCombination(state, table.GetValue(handle));
                if (combination < 0)
                    return;
            }
            else
            {
                return;
            }

            if (combination >= 0)
                table.SetValue(handle, (ushort)combination);

            if (exception)
                state.Counts.Exceptions++;
            else
                state.Counts.Domains++;
        }

        private void AddAdvancedRule(ListState state, ListAdvancedRule rule)
        {
            rule.List = state.Url;
            rule.ListIndex = (ushort)state.Index;

            if (rule.Kind == ListRuleMatchKind.Regex)
            {
                _advancedRegex.Add(rule);
            }
            else
            {
                if (!_advancedByDomain.TryGetValue(rule.Domain, out List<ListAdvancedRule> rules))
                {
                    rules = new List<ListAdvancedRule>(1);
                    _advancedByDomain.Add(rule.Domain, rules);
                }

                rules.Add(rule);
            }

            state.Counts.Advanced++;

            if (rule.Kind == ListRuleMatchKind.Regex)
                return;

            if (rule.Exception)
                state.Counts.Exceptions++;
            else
                state.Counts.Domains++;
        }

        private static bool TryCreateRegex(string pattern, out Regex regex)
        {
            regex = null;

            if ((pattern.Length == 0) || (pattern.Length > MAX_REGEX_LENGTH))
                return false;

            try
            {
                regex = new Regex(pattern, REGEX_OPTIONS, REGEX_TIMEOUT);
                return true;
            }
            catch (ArgumentException)
            {
                return false;
            }
            catch (NotSupportedException)
            {
                return false;
            }
        }

        private static string ConvertAdblockPatternToRegex(bool hostnameAnchor, bool startAnchor, string pattern, bool endAnchor)
        {
            StringBuilder sb = new StringBuilder(pattern.Length + 16);

            if (hostnameAnchor)
                sb.Append("(?:^|\\.)");
            else if (startAnchor)
                sb.Append('^');

            foreach (char c in pattern)
            {
                if (c == '*')
                    sb.Append(".*");
                else if (c == '.')
                    sb.Append("\\.");
                else
                    sb.Append(c);
            }

            if (endAnchor)
                sb.Append('$');

            return sb.ToString();
        }

        private static bool TryParseModifiers(string modifiers, ListAdvancedRule rule, out bool important, out bool badfilter, out bool hasAdvancedModifier)
        {
            important = false;
            badfilter = false;
            hasAdvancedModifier = false;

            if (string.IsNullOrEmpty(modifiers))
                return true;

            foreach (string rawModifier in SplitUnquoted(modifiers, ','))
            {
                string modifier = rawModifier.Trim();
                if (modifier.Length == 0)
                    continue;

                string name = modifier;
                string value = null;

                int i = modifier.IndexOf('=');
                if (i > 0)
                {
                    name = modifier.Substring(0, i);
                    value = modifier.Substring(i + 1);
                }

                switch (name.ToLowerInvariant())
                {
                    case "important":
                        important = true;
                        break;

                    case "badfilter":
                        badfilter = true;
                        break;

                    case "all":
                    case "doc":
                    case "document":
                    case "match-case":
                        break;

                    case "dnstype":
                        {
                            if (string.IsNullOrEmpty(value))
                                return false;

                            HashSet<ushort> types = new HashSet<ushort>();
                            bool? negated = null;

                            foreach (string rawType in value.Split('|'))
                            {
                                string type = rawType.Trim();
                                bool isNegated = type.StartsWith('~');

                                if (isNegated)
                                    type = type.Substring(1);

                                if ((negated is not null) && (negated.Value != isNegated))
                                    return false;

                                negated = isNegated;

                                if (!Enum.TryParse(type, true, out DnsResourceRecordType recordType))
                                    return false;

                                types.Add((ushort)recordType);
                            }

                            rule.DnsTypes = types;
                            rule.DnsTypesNegated = negated == true;
                            hasAdvancedModifier = true;
                        }
                        break;

                    case "denyallow":
                        {
                            if (string.IsNullOrEmpty(value))
                                return false;

                            List<string> domains = new List<string>();

                            foreach (string rawDomain in value.Split('|'))
                            {
                                string domain = rawDomain.Trim().Trim('.').ToLowerInvariant();

                                if ((domain.Length == 0) || domain.StartsWith('~') || !DnsClient.IsDomainNameValid(domain))
                                    return false;

                                domains.Add(domain);
                            }

                            rule.DenyAllow = domains.ToArray();
                            hasAdvancedModifier = true;
                        }
                        break;

                    case "client":
                        {
                            if (string.IsNullOrEmpty(value) || !ListClientMatcher.TryParse(value, out ListClientMatcher matcher))
                                return false;

                            rule.Clients = matcher;
                            hasAdvancedModifier = true;
                        }
                        break;

                    default:
                        return false;
                }
            }

            return true;
        }

        internal static List<string> SplitUnquoted(string value, char separator)
        {
            List<string> parts = new List<string>();
            StringBuilder sb = new StringBuilder(value.Length);
            char quote = '\0';

            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];

                if ((c == '\\') && (i + 1 < value.Length))
                {
                    sb.Append(c).Append(value[++i]);
                    continue;
                }

                if (quote != '\0')
                {
                    if (c == quote)
                        quote = '\0';

                    sb.Append(c);
                    continue;
                }

                if ((c == '\'') || (c == '"'))
                {
                    quote = c;
                    sb.Append(c);
                    continue;
                }

                if (c == separator)
                {
                    parts.Add(sb.ToString());
                    sb.Clear();
                    continue;
                }

                sb.Append(c);
            }

            parts.Add(sb.ToString());
            return parts;
        }

        internal static string Unquote(string value)
        {
            if ((value.Length >= 2) && ((value[0] == '\'') || (value[0] == '"')) && (value[^1] == value[0]))
                value = value.Substring(1, value.Length - 2);

            if (!value.Contains('\\'))
                return value;

            StringBuilder sb = new StringBuilder(value.Length);

            for (int i = 0; i < value.Length; i++)
            {
                if ((value[i] == '\\') && (i + 1 < value.Length))
                    i++;

                sb.Append(value[i]);
            }

            return sb.ToString();
        }

        private static bool TryParseNetwork(string value, out IPAddress address, out int prefix)
        {
            address = null;
            prefix = -1;

            int i = value.IndexOf('/');
            string addressPart = i < 0 ? value : value.Substring(0, i);

            if (!IPAddress.TryParse(addressPart, out address))
                return false;

            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            int maxPrefix = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;

            if (i < 0)
            {
                prefix = maxPrefix;
            }
            else if (!int.TryParse(value.AsSpan(i + 1), out prefix) || (prefix < 0) || (prefix > maxPrefix))
            {
                return false;
            }

            if (address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
                return false;

            return prefix >= (address.AddressFamily == AddressFamily.InterNetwork ? MIN_IPV4_PREFIX : MIN_IPV6_PREFIX);
        }

        private void AddIpRule(ListState state, IPAddress address, int prefix, bool exception)
        {
            ListIpRuleSet set = exception ? _ipAllow : _ipBlock;

            int combination = GetCombination(state, set.Get(address, prefix));
            if (combination < 0)
                return;

            set.Set(address, prefix, (ushort)combination);
            state.Counts.Ips++;
        }

        private static bool LooksLikePiholeRegex(string line)
        {
            if (line.StartsWith('^') || line.EndsWith('$'))
                return true;

            foreach (char c in line)
            {
                switch (c)
                {
                    case '\\':
                    case '(':
                    case ')':
                    case '[':
                    case ']':
                    case '{':
                    case '}':
                    case '+':
                    case '?':
                        return true;
                }
            }

            return false;
        }

        private void AddRegex(ListState state, string pattern, string modifiers, bool exception, bool fromPihole)
        {
            ListAdvancedRule rule = new ListAdvancedRule() { Exception = exception, Kind = ListRuleMatchKind.Regex };
            bool important = false;
            bool badfilter = false;
            bool hasAdvancedModifier = false;

            if (fromPihole)
            {
                if (!string.IsNullOrEmpty(modifiers))
                {
                    foreach (string option in modifiers.Split(';', StringSplitOptions.RemoveEmptyEntries))
                    {
                        if (!option.StartsWith("querytype=", StringComparison.OrdinalIgnoreCase))
                        {
                            state.Counts.Skipped++;
                            return;
                        }

                        string types = option.Substring(10);
                        bool negated = types.StartsWith('!');

                        if (negated)
                            types = types.Substring(1);

                        HashSet<ushort> set = new HashSet<ushort>();

                        foreach (string type in types.Split(','))
                        {
                            if (!Enum.TryParse(type.Trim(), true, out DnsResourceRecordType recordType))
                            {
                                state.Counts.Skipped++;
                                return;
                            }

                            set.Add((ushort)recordType);
                        }

                        rule.DnsTypes = set;
                        rule.DnsTypesNegated = negated;
                        hasAdvancedModifier = true;
                    }
                }
            }
            else if (!TryParseModifiers(modifiers, rule, out important, out badfilter, out hasAdvancedModifier))
            {
                state.Counts.Skipped++;
                return;
            }

            string key = (exception ? "@@" : "") + "/" + pattern + "/" + (important ? "i" : "");

            if (badfilter)
            {
                _badfilters.Add(key);
                return;
            }

            pattern = ConvertPosixClasses(pattern);

            if (important || hasAdvancedModifier)
            {
                if (!TryCreateRegex(pattern, out Regex regex))
                {
                    state.Counts.Skipped++;
                    return;
                }

                rule.Important = important;
                rule.Regex = regex;
                rule.Key = key;
                AddAdvancedRule(state, rule);
                state.Counts.Regexes++;
                return;
            }

            AddGroupedRegex(state, pattern, key, exception);
        }

        private void AddGroupedRegex(ListState state, string pattern, string key, bool exception)
        {
            List<(string Pattern, string Key)> patterns = exception ? state.AllowRegexPatterns : state.BlockRegexPatterns;

            if (patterns.Count >= MAX_REGEX_RULES_PER_LIST)
            {
                state.Counts.Skipped++;
                return;
            }

            if (!TryCreateRegex(pattern, out _))
            {
                state.Counts.Skipped++;
                return;
            }

            patterns.Add((pattern, key));
            state.Counts.Regexes++;
        }

        private static string ConvertPosixClasses(string pattern)
        {
            if (!pattern.Contains("[:", StringComparison.Ordinal))
                return pattern;

            StringBuilder sb = new StringBuilder(pattern.Length + 16);
            bool inClass = false;

            for (int i = 0; i < pattern.Length; i++)
            {
                char c = pattern[i];

                if (c == '\\')
                {
                    sb.Append(c);

                    if (i + 1 < pattern.Length)
                        sb.Append(pattern[++i]);

                    continue;
                }

                if (!inClass)
                {
                    if (c == '[')
                    {
                        inClass = true;
                        sb.Append(c);

                        if ((i + 1 < pattern.Length) && (pattern[i + 1] == '^'))
                            sb.Append(pattern[++i]);

                        if ((i + 1 < pattern.Length) && (pattern[i + 1] == ']'))
                            sb.Append('\\').Append(pattern[++i]);

                        continue;
                    }

                    sb.Append(c);
                    continue;
                }

                if ((c == '[') && (i + 1 < pattern.Length) && (pattern[i + 1] == ':'))
                {
                    int end = pattern.IndexOf(":]", i + 2, StringComparison.Ordinal);

                    if (end > 0)
                    {
                        string replacement = pattern.Substring(i + 2, end - i - 2) switch
                        {
                            "alnum" => "a-zA-Z0-9",
                            "alpha" => "a-zA-Z",
                            "ascii" => "\\x00-\\x7F",
                            "blank" => " \\t",
                            "cntrl" => "\\x00-\\x1F\\x7F",
                            "digit" => "0-9",
                            "graph" => "\\x21-\\x7E",
                            "lower" => "a-z",
                            "print" => "\\x20-\\x7E",
                            "punct" => "!-/:-@\\[-`{-~",
                            "space" => "\\s",
                            "upper" => "A-Z",
                            "word" => "\\w",
                            "xdigit" => "0-9A-Fa-f",
                            _ => null
                        };

                        if (replacement is not null)
                        {
                            if ((sb.Length > 1) && (sb[^1] == '-') && (sb[^2] != '\\') && (sb[^2] != '['))
                            {
                                sb.Length--;
                                sb.Append("\\-");
                            }

                            sb.Append(replacement);
                            i = end + 1;
                            continue;
                        }
                    }

                    sb.Append("\\[");
                    continue;
                }

                if (c == '[')
                {
                    sb.Append("\\[");
                    continue;
                }

                if (c == ']')
                    inClass = false;

                sb.Append(c);
            }

            return sb.ToString();
        }

        private void ParseAdblockRule(ListState state, string line, bool exception)
        {
            if (line.StartsWith('/'))
            {
                int end = line.LastIndexOf('/');
                if (end < 1)
                {
                    state.Counts.Skipped++;
                    return;
                }

                string modifiers = null;

                if ((end + 1 < line.Length) && (line[end + 1] == '$'))
                    modifiers = line.Substring(end + 2);
                else if (end + 1 < line.Length)
                {
                    int dollar = line.LastIndexOf("/$", StringComparison.Ordinal);
                    if (dollar < 1)
                    {
                        state.Counts.Skipped++;
                        return;
                    }

                    end = dollar;
                    modifiers = line.Substring(dollar + 2);
                }

                AddRegex(state, line.Substring(1, end - 1), modifiers, exception, false);
                return;
            }

            string pattern = line;
            string modifierText = null;

            int modifierIndex = line.IndexOf('$');
            if (modifierIndex >= 0)
            {
                pattern = line.Substring(0, modifierIndex);
                modifierText = line.Substring(modifierIndex + 1);
            }

            bool hostnameAnchor = false;
            bool startAnchor = false;
            bool endAnchor = false;

            if (pattern.StartsWith("||", StringComparison.Ordinal))
            {
                hostnameAnchor = true;
                pattern = pattern.Substring(2);
            }
            else if (pattern.StartsWith('|'))
            {
                startAnchor = true;
                pattern = pattern.Substring(1);
            }

            if (pattern.EndsWith("^|", StringComparison.Ordinal))
            {
                endAnchor = true;
                pattern = pattern.Substring(0, pattern.Length - 2);
            }
            else if (pattern.EndsWith('^') || pattern.EndsWith('|'))
            {
                endAnchor = true;
                pattern = pattern.Substring(0, pattern.Length - 1);
            }

            pattern = pattern.TrimEnd('.').ToLowerInvariant();

            ListAdvancedRule rule = new ListAdvancedRule() { Exception = exception };

            if (!TryParseModifiers(modifierText, rule, out bool important, out bool badfilter, out bool hasAdvancedModifier))
            {
                state.Counts.Skipped++;
                return;
            }

            if ((pattern.Length == 0) || !AdblockPatternRegex().IsMatch(pattern))
            {
                if ((pattern.Length > 0) && TryParseNetwork(pattern, out IPAddress ipAddress, out int ipPrefix) && !hasAdvancedModifier && !important)
                {
                    if (!badfilter)
                        AddIpRule(state, ipAddress, ipPrefix, exception);

                    return;
                }

                state.Counts.Skipped++;
                return;
            }

            if (IPAddress.TryParse(pattern, out IPAddress ip))
            {
                if (!badfilter && !hasAdvancedModifier && !important)
                    AddIpRule(state, ip, ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128, exception);

                return;
            }

            ListRuleMatchKind kind;
            string domain;

            if (!pattern.Contains('*'))
            {
                domain = pattern.Trim('.');
                kind = (startAnchor && endAnchor) ? ListRuleMatchKind.Exact : ListRuleMatchKind.Tree;

                if (!hostnameAnchor && !startAnchor && !endAnchor && pattern.Contains('.'))
                    kind = ListRuleMatchKind.Tree;
            }
            else if (hostnameAnchor && pattern.StartsWith("*.", StringComparison.Ordinal) && (pattern.IndexOf('*', 1) < 0) && endAnchor)
            {
                domain = pattern.Substring(2);
                kind = ListRuleMatchKind.SubdomainsOnly;
            }
            else
            {
                domain = null;
                kind = ListRuleMatchKind.Regex;
            }

            if ((kind != ListRuleMatchKind.Regex) && ((domain.Length == 0) || !DnsClient.IsDomainNameValid(domain)))
            {
                state.Counts.Skipped++;
                return;
            }

            if (kind == ListRuleMatchKind.Regex)
            {
                string regexPattern = ConvertAdblockPatternToRegex(hostnameAnchor, startAnchor, pattern, endAnchor);
                string key = (exception ? "@@" : "") + "w" + regexPattern + (important ? "i" : "");

                if (badfilter)
                {
                    _badfilters.Add(key);
                    return;
                }

                if (!important && !hasAdvancedModifier)
                {
                    AddGroupedRegex(state, regexPattern, key, exception);
                    return;
                }

                if (!TryCreateRegex(regexPattern, out Regex regex))
                {
                    state.Counts.Skipped++;
                    return;
                }

                rule.Kind = ListRuleMatchKind.Regex;
                rule.Important = important;
                rule.Regex = regex;
                rule.Key = key;
                AddAdvancedRule(state, rule);
                state.Counts.Regexes++;
                return;
            }

            if (hasAdvancedModifier)
            {
                string key = (exception ? "@@" : "") + (int)kind + ":" + domain + (important ? "i" : "") + "$" + modifierText;

                if (badfilter)
                {
                    _badfilters.Add(key.Replace(",badfilter", "", StringComparison.OrdinalIgnoreCase).Replace("badfilter,", "", StringComparison.OrdinalIgnoreCase));
                    return;
                }

                rule.Kind = kind;
                rule.Domain = domain;
                rule.Important = important;
                rule.Key = key;
                AddAdvancedRule(state, rule);
                return;
            }

            AddDomainRule(state, domain, kind, exception, important, badfilter);
        }

        private void ParseHostsOrDomainLine(ListState state, string line, bool exception)
        {
            int commentIndex = line.IndexOf(" #", StringComparison.Ordinal);
            if (commentIndex < 0)
                commentIndex = line.IndexOf("\t#", StringComparison.Ordinal);

            if (commentIndex >= 0)
                line = line.Substring(0, commentIndex);

            string[] words = line.Split(_whitespace, StringSplitOptions.RemoveEmptyEntries);
            if (words.Length == 0)
                return;

            if (words.Length == 1)
            {
                string word = words[0];

                if (TryParseNetwork(word, out IPAddress address, out int prefix))
                {
                    AddIpRule(state, address, prefix, exception);
                    return;
                }

                AddHostname(state, word, exception);
                return;
            }

            if (!IPAddress.TryParse(words[0], out _))
            {
                state.Counts.Skipped++;
                return;
            }

            for (int i = 1; i < words.Length; i++)
                AddHostname(state, words[i], exception);
        }

        private void AddHostname(ListState state, string hostname, bool exception)
        {
            hostname = hostname.TrimStart('*').Trim('.').ToLowerInvariant();

            switch (hostname)
            {
                case "":
                case "localhost":
                case "localhost.localdomain":
                case "local":
                case "broadcasthost":
                case "ip6-localhost":
                case "ip6-loopback":
                case "ip6-localnet":
                case "ip6-mcastprefix":
                case "ip6-allnodes":
                case "ip6-allrouters":
                case "ip6-allhosts":
                case "0.0.0.0":
                    return;
            }

            if (!DnsClient.IsDomainNameValid(hostname) || IPAddress.TryParse(hostname, out _))
            {
                state.Counts.Skipped++;
                return;
            }

            AddDomainRule(state, hostname, ListRuleMatchKind.Tree, exception, false, false);
        }

        private static Regex CombineRegexPatterns(List<string> patterns)
        {
            if (patterns.Count == 0)
                return null;

            if (patterns.Count == 1)
                return new Regex(patterns[0], REGEX_OPTIONS, REGEX_TIMEOUT);

            StringBuilder sb = new StringBuilder();

            for (int i = 0; i < patterns.Count; i++)
            {
                if (i > 0)
                    sb.Append('|');

                sb.Append("(?:").Append(patterns[i]).Append(')');
            }

            try
            {
                return new Regex(sb.ToString(), REGEX_OPTIONS, REGEX_TIMEOUT);
            }
            catch (Exception)
            {
                return null;
            }
        }

        #endregion

        #region public

        public ListRuleCounts ParseList(Uri listUrl, bool isAllowList, TextReader reader)
        {
            ListState state = new ListState() { Url = listUrl, Index = _lists.Count };
            _lists.Add(listUrl);
            _listIsAllow.Add(isAllowList);

            string rawLine;

            while ((rawLine = reader.ReadLine()) is not null)
            {
                string line = rawLine.Trim();

                if (line.Length == 0)
                    continue;

                switch (line[0])
                {
                    case '!':
                    case '#':
                    case '[':
                        continue;
                }

                if (line.Contains("##", StringComparison.Ordinal) || line.Contains("#@#", StringComparison.Ordinal) || line.Contains("#?#", StringComparison.Ordinal) || line.Contains("#$#", StringComparison.Ordinal) || line.Contains("$$", StringComparison.Ordinal))
                {
                    state.Counts.Skipped++;
                    continue;
                }

                bool exception = isAllowList;

                if (line.StartsWith("@@", StringComparison.Ordinal))
                {
                    exception = !exception;
                    line = line.Substring(2);

                    if (line.Length == 0)
                        continue;
                }

                bool hasWhitespace = (line.IndexOf(' ') >= 0) || (line.IndexOf('\t') >= 0);

                if (line.StartsWith('|') || line.StartsWith('/'))
                {
                    ParseAdblockRule(state, line, exception);
                    continue;
                }

                if (!hasWhitespace && LooksLikePiholeRegex(line))
                {
                    string options = null;
                    int optionIndex = line.IndexOf(';');

                    if (optionIndex > 0)
                    {
                        options = line.Substring(optionIndex + 1);
                        line = line.Substring(0, optionIndex);
                    }

                    AddRegex(state, line, options, exception, true);
                    continue;
                }

                if (!hasWhitespace && (line.Contains('^') || (line.IndexOf('$') > 0)))
                {
                    ParseAdblockRule(state, line, exception);
                    continue;
                }

                if (!hasWhitespace && line.Contains('*') && !line.StartsWith("*.", StringComparison.Ordinal))
                {
                    ParseAdblockRule(state, line, exception);
                    continue;
                }

                ParseHostsOrDomainLine(state, line, exception);
            }

            if (state.BlockRegexPatterns.Count > 0)
                AddRegexGroups(state, state.BlockRegexPatterns, false);

            if (state.AllowRegexPatterns.Count > 0)
                AddRegexGroups(state, state.AllowRegexPatterns, true);

            return state.Counts;
        }

        private void AddRegexGroups(ListState state, List<(string Pattern, string Key)> patterns, bool exception)
        {
            List<string> active = new List<string>(patterns.Count);

            foreach ((string pattern, string key) in patterns)
            {
                if (!_badfilters.Contains(key))
                    active.Add(pattern);
            }

            Regex combined = CombineRegexPatterns(active);

            if (combined is not null)
            {
                _regexGroups.Add(new ListRegexGroup() { Regex = combined, List = state.Url, ListIndex = (ushort)state.Index, Exception = exception });
                return;
            }

            foreach (string pattern in active)
            {
                if (TryCreateRegex(pattern, out Regex regex))
                    _regexGroups.Add(new ListRegexGroup() { Regex = regex, List = state.Url, ListIndex = (ushort)state.Index, Exception = exception });
            }
        }

        public ListRuleSet Build()
        {
            if (_badfilters.Count > 0)
            {
                foreach (List<ListAdvancedRule> rules in _advancedByDomain.Values)
                    rules.RemoveAll(delegate (ListAdvancedRule rule) { return (rule.Key is not null) && _badfilters.Contains(rule.Key); });

                _advancedRegex.RemoveAll(delegate (ListAdvancedRule rule) { return (rule.Key is not null) && _badfilters.Contains(rule.Key); });
            }

            List<string> emptyDomains = new List<string>();

            foreach (KeyValuePair<string, List<ListAdvancedRule>> entry in _advancedByDomain)
            {
                if (entry.Value.Count == 0)
                    emptyDomains.Add(entry.Key);
            }

            foreach (string domain in emptyDomains)
                _advancedByDomain.Remove(domain);

            _block.TrimExcess();
            _allow.TrimExcess();
            _importantBlock.TrimExcess();
            _importantAllow.TrimExcess();

            return new ListRuleSet(_block, _allow, _importantBlock, _importantAllow, _combinations.ToArray(), _combinationLists.ToArray(), _lists.ToArray(), _listIsAllow.ToArray(), _advancedByDomain, _advancedRegex.ToArray(), _regexGroups.ToArray(), _ipBlock, _ipAllow);
        }

        #endregion
    }
}
