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
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using ZenitiumLibrary.Net;

namespace ZenitiumDns.Core.Dhcp
{
    public static class DhcpConfigParser
    {
        #region variables

        public const int MAX_LINES = 20000;
        public const int MAX_LINE_LENGTH = 4096;

        static readonly HashSet<string> _unsupported = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "dhcp-script", "dhcp-luascript", "dhcp-scriptuser", "dhcp-leasefile", "leasefile-ro", "dhcp-relay", "dhcp-proxy",
            "pxe-service", "pxe-prompt", "enable-ra", "ra-param", "dhcp-fqdn", "dhcp-hostsfile", "dhcp-hostsdir", "dhcp-optsfile",
            "dhcp-optsdir", "read-ethers", "dhcp-duid", "dhcp-name-match", "dhcp-client-update", "dhcp-split-relay", "conf-file",
            "conf-dir", "dhcp-pxe-vendor", "dhcp-ttl", "script-arp", "script-on-renewal", "dhcp-alternate-port", "listen-address",
            "bind-interfaces", "bind-dynamic", "port"
        };

        #endregion

        #region private

        private sealed class Token
        {
            public Token(string text, bool quoted)
            {
                Text = text;
                Quoted = quoted;
            }

            public string Text { get; }

            public bool Quoted { get; }

            public override string ToString()
            {
                return Text;
            }
        }

        private static List<Token> Tokenize(string value)
        {
            List<Token> tokens = new List<Token>();
            StringBuilder sb = new StringBuilder();
            bool inQuotes = false;
            bool quoted = false;

            for (int i = 0; i < value.Length; i++)
            {
                char c = value[i];

                if (inQuotes)
                {
                    if ((c == '\\') && (i + 1 < value.Length) && ((value[i + 1] == '"') || (value[i + 1] == '\\')))
                    {
                        sb.Append(value[++i]);
                        continue;
                    }

                    if (c == '"')
                    {
                        inQuotes = false;
                        continue;
                    }

                    sb.Append(c);
                    continue;
                }

                if (c == '"')
                {
                    inQuotes = true;
                    quoted = true;
                    continue;
                }

                if (c == ',')
                {
                    tokens.Add(new Token(quoted ? sb.ToString() : sb.ToString().Trim(), quoted));
                    sb.Clear();
                    quoted = false;
                    continue;
                }

                sb.Append(c);
            }

            if (inQuotes)
                throw new FormatException("missing closing quote");

            tokens.Add(new Token(quoted ? sb.ToString() : sb.ToString().Trim(), quoted));
            return tokens;
        }

        private static string StripComment(string line)
        {
            bool inQuotes = false;

            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];

                if (c == '"')
                    inQuotes = !inQuotes;
                else if ((c == '#') && !inQuotes && ((i == 0) || char.IsWhiteSpace(line[i - 1])))
                    return line.Substring(0, i);
            }

            return line;
        }

        private static bool TryReadTag(Token token, string prefix, out string tag, out bool negated)
        {
            tag = null;
            negated = false;

            if (token.Quoted || !token.Text.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                return false;

            string value = token.Text.Substring(prefix.Length).Trim();

            if (value.StartsWith('!'))
            {
                negated = true;
                value = value.Substring(1).Trim();
            }

            if (!IsValidTag(value))
                throw new FormatException("invalid tag name '" + value + "'");

            tag = value;
            return true;
        }

        private static bool IsValidTag(string tag)
        {
            if (string.IsNullOrEmpty(tag) || (tag.Length > 64))
                return false;

            foreach (char c in tag)
            {
                if (!(char.IsAsciiLetterOrDigit(c) || (c == '-') || (c == '_') || (c == '.')))
                    return false;
            }

            return true;
        }

        private static int ReadConditions(List<Token> tokens, int index, List<DhcpTagCondition> conditions, List<string> setTags, bool netMeansSet)
        {
            while (index < tokens.Count)
            {
                Token token = tokens[index];

                if (TryReadTag(token, "tag:", out string tag, out bool negated))
                {
                    conditions.Add(new DhcpTagCondition(tag, negated));
                    index++;
                    continue;
                }

                if (TryReadTag(token, "set:", out tag, out negated))
                {
                    if (negated)
                        throw new FormatException("set: cannot be negated");

                    if (setTags is null)
                        throw new FormatException("set: is not allowed here");

                    setTags.Add(tag);
                    index++;
                    continue;
                }

                if (TryReadTag(token, "net:", out tag, out negated))
                {
                    if (netMeansSet && !negated && (setTags is not null))
                        setTags.Add(tag);
                    else
                        conditions.Add(new DhcpTagCondition(tag, negated));

                    index++;
                    continue;
                }

                break;
            }

            return index;
        }

        private static IPAddress ParseIPv4(string text, string what)
        {
            text = text.Trim();

            if (!IPAddressExtensions.TryParseStrict(text, out IPAddress address))
                throw new FormatException("'" + text + "' is not a valid " + what);

            if (address.AddressFamily != AddressFamily.InterNetwork)
                throw new FormatException("IPv6 is not supported by the DHCP server ('" + text + "')");

            return address;
        }

        private static bool IsIPv4(string text)
        {
            return IPAddressExtensions.TryParseStrict(text.Trim(), out IPAddress address) && (address.AddressFamily == AddressFamily.InterNetwork);
        }

        private static void ParseRange(DhcpConfiguration config, int line, List<Token> tokens)
        {
            DhcpRangeRule rule = new DhcpRangeRule() { Line = line };
            List<string> setTags = new List<string>();

            int i = ReadConditions(tokens, 0, rule.Conditions, setTags, true);

            if (setTags.Count > 1)
                throw new FormatException("dhcp-range accepts only one set: tag");

            if (setTags.Count == 1)
                rule.SetTag = setTags[0];

            if (i >= tokens.Count)
                throw new FormatException("the start address is missing");

            string startText = tokens[i].Text;

            if (startText.StartsWith("constructor:", StringComparison.OrdinalIgnoreCase) || startText.Contains(':'))
                throw new FormatException("IPv6 ranges are not supported by the DHCP server");

            rule.Start = ParseIPv4(startText, "start address");
            i++;

            if (i < tokens.Count)
            {
                string second = tokens[i].Text.Trim();

                if (second.Equals("static", StringComparison.OrdinalIgnoreCase))
                {
                    rule.StaticOnly = true;
                    rule.End = rule.Start;
                    i++;
                }
                else if (second.Equals("proxy", StringComparison.OrdinalIgnoreCase))
                {
                    throw new FormatException("proxy DHCP is not supported");
                }
                else if (IsIPv4(second))
                {
                    rule.End = ParseIPv4(second, "end address");
                    i++;
                }
            }

            if (rule.End is null)
                throw new FormatException("the end address is missing (or use 'static')");

            if (DhcpUtilities.ToUInt32(rule.End) < DhcpUtilities.ToUInt32(rule.Start))
                throw new FormatException("the end address is lower than the start address");

            if ((i < tokens.Count) && IsIPv4(tokens[i].Text))
            {
                rule.Netmask = ParseIPv4(tokens[i].Text, "netmask");

                if (!DhcpUtilities.TryGetPrefixLength(rule.Netmask, out int prefix) || (prefix < 8) || (prefix > 30))
                    throw new FormatException("'" + tokens[i].Text + "' is not a usable netmask (/8 to /30)");

                if (!DhcpUtilities.IsInNetwork(rule.End, rule.Start, prefix))
                    throw new FormatException("start and end address are not in the same network");

                i++;

                if ((i < tokens.Count) && IsIPv4(tokens[i].Text))
                {
                    rule.Broadcast = ParseIPv4(tokens[i].Text, "broadcast address");
                    i++;
                }
            }

            if (i < tokens.Count)
            {
                if (!DhcpUtilities.TryParseLeaseTime(tokens[i].Text, out uint leaseTime))
                    throw new FormatException("'" + tokens[i].Text + "' is not a valid lease time");

                rule.LeaseTime = leaseTime;
                i++;
            }

            if (i < tokens.Count)
                throw new FormatException("unexpected value '" + tokens[i].Text + "'");

            if (!rule.StaticOnly && ((long)rule.EndValue - rule.StartValue + 1 > 65536))
                throw new FormatException("a range can contain at most 65536 addresses");

            config.Ranges.Add(rule);
        }

        private static void ParseHost(DhcpConfiguration config, int line, List<Token> tokens)
        {
            DhcpHostRule rule = new DhcpHostRule() { Line = line };

            foreach (Token token in tokens)
            {
                string text = token.Text.Trim();

                if (text.Length == 0)
                    continue;

                if (!token.Quoted)
                {
                    if (TryReadTag(token, "set:", out string setTag, out bool negated) || TryReadTag(token, "net:", out setTag, out negated))
                    {
                        if (negated)
                            throw new FormatException("set: cannot be negated");

                        rule.SetTags.Add(setTag);
                        continue;
                    }

                    if (TryReadTag(token, "tag:", out string tag, out negated))
                    {
                        rule.Conditions.Add(new DhcpTagCondition(tag, negated));
                        continue;
                    }

                    if (text.StartsWith("id:", StringComparison.OrdinalIgnoreCase))
                    {
                        string id = text.Substring(3);

                        if (id == "*")
                        {
                            rule.IgnoreClientId = true;
                            continue;
                        }

                        if (id.Length == 0)
                            throw new FormatException("the client ID is empty");

                        if (DhcpUtilities.TryParseHex(id, out byte[] idBytes))
                            rule.ClientIds.Add(idBytes);
                        else
                            rule.ClientIds.Add(Encoding.UTF8.GetBytes(id));

                        continue;
                    }

                    if (text.Equals("ignore", StringComparison.OrdinalIgnoreCase))
                    {
                        rule.Ignore = true;
                        continue;
                    }

                    if (text.StartsWith('['))
                        throw new FormatException("IPv6 addresses are not supported by the DHCP server");

                    if (IsIPv4(text))
                    {
                        if (rule.Address is not null)
                            throw new FormatException("more than one IPv4 address");

                        rule.Address = ParseIPv4(text, "address");
                        continue;
                    }

                    if (text.Contains(':') && DhcpHardwarePattern.TryParse(text, out DhcpHardwarePattern pattern))
                    {
                        rule.HardwareAddresses.Add(pattern);
                        continue;
                    }

                    if (DhcpUtilities.LooksLikeLeaseTime(text))
                    {
                        if (!DhcpUtilities.TryParseLeaseTime(text, out uint leaseTime))
                            throw new FormatException("'" + text + "' is not a valid lease time");

                        rule.LeaseTime = leaseTime;
                        continue;
                    }
                }

                if (rule.HostName is not null)
                    throw new FormatException("unexpected value '" + text + "'");

                string hostName = text.TrimEnd('.');
                string label = hostName;
                int dot = hostName.IndexOf('.');
                if (dot >= 0)
                    label = hostName.Substring(0, dot);

                if (!DhcpUtilities.IsValidHostLabel(label) || ((dot >= 0) && !DhcpUtilities.IsValidDomainName(hostName)))
                    throw new FormatException("'" + text + "' is neither a MAC address, client ID, IPv4 address, lease time nor a valid host name");

                rule.HostName = label.ToLowerInvariant();
            }

            if ((rule.HardwareAddresses.Count == 0) && (rule.ClientIds.Count == 0))
            {
                if (rule.HostName is null)
                    throw new FormatException("a MAC address, client ID or host name is required");

                rule.MatchByHostName = true;
            }

            config.Hosts.Add(rule);
        }

        private static void ParseOption(DhcpConfiguration config, int line, List<Token> tokens, bool force)
        {
            DhcpOptionRule rule = new DhcpOptionRule() { Line = line, Force = force };

            int i = ReadConditions(tokens, 0, rule.Conditions, null, false);

            while (i < tokens.Count)
            {
                Token token = tokens[i];
                string text = token.Text;

                if (token.Quoted)
                    break;

                if (text.StartsWith("encap:", StringComparison.OrdinalIgnoreCase))
                {
                    if (!byte.TryParse(text.AsSpan(6), NumberStyles.None, CultureInfo.InvariantCulture, out byte encap) || (encap == 0) || (encap == 255))
                        throw new FormatException("invalid encap: option number");

                    rule.EncapsulatedIn = encap;
                    i++;
                    continue;
                }

                if (text.StartsWith("vi-encap:", StringComparison.OrdinalIgnoreCase))
                {
                    if (!uint.TryParse(text.AsSpan(9), NumberStyles.None, CultureInfo.InvariantCulture, out uint enterprise))
                        throw new FormatException("invalid vi-encap: enterprise number");

                    rule.IsViEncapsulated = true;
                    rule.ViEnterprise = enterprise;
                    i++;
                    continue;
                }

                if (text.StartsWith("vendor:", StringComparison.OrdinalIgnoreCase))
                {
                    string vendor = text.Substring(7);
                    if (vendor.Length == 0)
                        throw new FormatException("the vendor class is empty");

                    rule.VendorClass = vendor;
                    i++;
                    continue;
                }

                break;
            }

            if (i >= tokens.Count)
                throw new FormatException("the option is missing");

            string optionText = tokens[i].Text.Trim();
            i++;

            DhcpOptionDefinition definition = null;

            if (optionText.StartsWith("option6:", StringComparison.OrdinalIgnoreCase))
                throw new FormatException("DHCPv6 options are not supported by the DHCP server");

            if (optionText.StartsWith("option:", StringComparison.OrdinalIgnoreCase))
            {
                string name = optionText.Substring(7);

                if (!DhcpOptionCatalog.TryGetDefinition(name, out definition))
                    throw new FormatException("unknown option name '" + name + "'");

                rule.Code = definition.Code;
            }
            else
            {
                if (!byte.TryParse(optionText, NumberStyles.None, CultureInfo.InvariantCulture, out byte code) || (code == 0) || (code == 255))
                    throw new FormatException("'" + optionText + "' is not a valid option number (1 to 254) or option:name");

                rule.Code = code;

                if ((rule.EncapsulatedIn == 0) && !rule.IsViEncapsulated && (rule.VendorClass is null))
                    DhcpOptionCatalog.TryGetDefinition(code, out definition);
            }

            if ((rule.EncapsulatedIn != 0) || rule.IsViEncapsulated || (rule.VendorClass is not null))
                definition = null;

            if ((definition is not null) && definition.Protected)
                throw new FormatException("option " + definition.Name + " is managed by the DHCP server and cannot be set");

            List<string> values = new List<string>();
            bool anyQuoted = false;

            for (; i < tokens.Count; i++)
            {
                values.Add(tokens[i].Text);
                anyQuoted |= tokens[i].Quoted;
            }

            if ((values.Count == 0) || ((values.Count == 1) && (values[0].Length == 0) && !anyQuoted))
            {
                rule.Suppress = true;
                rule.Value = [];
                config.Options.Add(rule);
                return;
            }

            DhcpOptionType type = definition?.Type ?? DhcpOptionType.Guess;

            if (anyQuoted && ((type == DhcpOptionType.Guess) || (type == DhcpOptionType.Bytes)))
                type = DhcpOptionType.Text;

            if ((type == DhcpOptionType.Address) || (type == DhcpOptionType.AddressList))
            {
                foreach (string value in values)
                {
                    if (value.Trim() == "0.0.0.0")
                        rule.UsesServerAddress = true;
                }
            }

            rule.Value = DhcpOptionCatalog.Encode(type, values);

            if ((rule.Value.Length > 255) && ((rule.EncapsulatedIn != 0) || rule.IsViEncapsulated))
                throw new FormatException("an encapsulated option cannot be longer than 255 bytes");

            config.Options.Add(rule);
        }

        private static void ParseMatch(DhcpConfiguration config, int line, List<Token> tokens, DhcpMatchKind kind)
        {
            DhcpMatchRule rule = new DhcpMatchRule() { Line = line, Kind = kind };
            List<DhcpTagCondition> conditions = new List<DhcpTagCondition>();
            List<string> setTags = new List<string>();

            int i = ReadConditions(tokens, 0, conditions, setTags, true);

            if (conditions.Count > 0)
                throw new FormatException("tag: conditions are not allowed here, use tag-if");

            if (setTags.Count != 1)
                throw new FormatException("exactly one set:<tag> is required");

            rule.SetTag = setTags[0];

            if (i >= tokens.Count)
                throw new FormatException("the value to match is missing");

            switch (kind)
            {
                case DhcpMatchKind.Option:
                    {
                        string optionText = tokens[i].Text.Trim();
                        i++;
                        DhcpOptionDefinition definition = null;

                        if (optionText.StartsWith("vi-encap:", StringComparison.OrdinalIgnoreCase))
                        {
                            if (!uint.TryParse(optionText.AsSpan(9), NumberStyles.None, CultureInfo.InvariantCulture, out uint enterprise))
                                throw new FormatException("invalid vi-encap: enterprise number");

                            rule.Kind = DhcpMatchKind.ViEncapsulated;
                            rule.Enterprise = enterprise;
                        }
                        else if (optionText.StartsWith("option:", StringComparison.OrdinalIgnoreCase))
                        {
                            if (!DhcpOptionCatalog.TryGetDefinition(optionText.Substring(7), out definition))
                                throw new FormatException("unknown option name '" + optionText.Substring(7) + "'");

                            rule.OptionCode = definition.Code;
                        }
                        else if (byte.TryParse(optionText, NumberStyles.None, CultureInfo.InvariantCulture, out byte code) && (code != 0) && (code != 255))
                        {
                            rule.OptionCode = code;
                            DhcpOptionCatalog.TryGetDefinition(code, out definition);
                        }
                        else
                        {
                            throw new FormatException("'" + optionText + "' is not a valid option number or option:name");
                        }

                        if (i < tokens.Count)
                        {
                            List<string> values = new List<string>();
                            bool quoted = false;

                            for (; i < tokens.Count; i++)
                            {
                                values.Add(tokens[i].Text);
                                quoted |= tokens[i].Quoted;
                            }

                            DhcpOptionType type = quoted ? DhcpOptionType.Text : (definition?.Type ?? DhcpOptionType.Guess);

                            if ((type == DhcpOptionType.Text) || (type == DhcpOptionType.Domain))
                                rule.ValueIsText = true;

                            if (type == DhcpOptionType.UInt16List)
                                type = DhcpOptionType.UInt16;

                            rule.Value = DhcpOptionCatalog.Encode(type, values);
                        }
                    }
                    break;

                case DhcpMatchKind.VendorClass:
                    {
                        if (tokens[i].Text.StartsWith("enterprise:", StringComparison.OrdinalIgnoreCase))
                        {
                            if (!uint.TryParse(tokens[i].Text.AsSpan(11), NumberStyles.None, CultureInfo.InvariantCulture, out uint enterprise))
                                throw new FormatException("invalid enterprise number");

                            rule.Enterprise = enterprise;
                            i++;

                            if (i >= tokens.Count)
                                throw new FormatException("the vendor class is missing");
                        }

                        rule.Value = Encoding.UTF8.GetBytes(tokens[i].Text);
                        rule.ValueIsText = true;
                        i++;
                    }
                    break;

                case DhcpMatchKind.UserClass:
                    rule.Value = Encoding.UTF8.GetBytes(tokens[i].Text);
                    rule.ValueIsText = true;
                    i++;
                    break;

                case DhcpMatchKind.HardwareAddress:
                    {
                        if (!DhcpHardwarePattern.TryParse(tokens[i].Text, out DhcpHardwarePattern pattern))
                            throw new FormatException("'" + tokens[i].Text + "' is not a valid MAC address pattern");

                        rule.HardwarePattern = pattern;
                        i++;
                    }
                    break;

                case DhcpMatchKind.CircuitId:
                case DhcpMatchKind.RemoteId:
                case DhcpMatchKind.SubscriberId:
                    {
                        string text = tokens[i].Text;

                        if (!tokens[i].Quoted && DhcpUtilities.TryParseHex(text, out byte[] bytes))
                        {
                            rule.Value = bytes;
                        }
                        else
                        {
                            rule.Value = Encoding.UTF8.GetBytes(text);
                            rule.ValueIsText = true;
                        }

                        if (rule.Value.Length == 0)
                            throw new FormatException("the value to match is empty");

                        i++;
                    }
                    break;
            }

            if (i < tokens.Count)
                throw new FormatException("unexpected value '" + tokens[i].Text + "'");

            config.Matches.Add(rule);
        }

        private static void ParseTagIf(DhcpConfiguration config, int line, List<Token> tokens)
        {
            DhcpTagIfRule rule = new DhcpTagIfRule() { Line = line };

            int i = ReadConditions(tokens, 0, rule.Conditions, rule.SetTags, false);

            if (i < tokens.Count)
                throw new FormatException("unexpected value '" + tokens[i].Text + "'");

            if (rule.SetTags.Count == 0)
                throw new FormatException("at least one set:<tag> is required");

            config.TagIfs.Add(rule);
        }

        private static DhcpTagListRule ParseTagList(int line, List<Token> tokens, bool allowEmpty)
        {
            DhcpTagListRule rule = new DhcpTagListRule() { Line = line };

            if ((tokens.Count == 1) && (tokens[0].Text.Length == 0))
            {
                if (!allowEmpty)
                    throw new FormatException("at least one tag:<tag> is required");

                return rule;
            }

            int i = ReadConditions(tokens, 0, rule.Conditions, null, false);

            if (i < tokens.Count)
                throw new FormatException("unexpected value '" + tokens[i].Text + "'");

            if ((rule.Conditions.Count == 0) && !allowEmpty)
                throw new FormatException("at least one tag:<tag> is required");

            return rule;
        }

        private static void ParseBoot(DhcpConfiguration config, int line, List<Token> tokens)
        {
            DhcpBootRule rule = new DhcpBootRule() { Line = line };

            int i = ReadConditions(tokens, 0, rule.Conditions, null, false);

            if ((i >= tokens.Count) || (tokens[i].Text.Length == 0))
                throw new FormatException("the boot file name is missing");

            rule.FileName = tokens[i++].Text;

            if (Encoding.ASCII.GetByteCount(rule.FileName) > 127)
                throw new FormatException("the boot file name is longer than 127 characters");

            if (i < tokens.Count)
            {
                string server = tokens[i++].Text;

                if (IsIPv4(server))
                {
                    rule.ServerAddress = ParseIPv4(server, "server address");
                }
                else if (server.Length > 0)
                {
                    if (server.Length > 63)
                        throw new FormatException("the server name is longer than 63 characters");

                    rule.ServerName = server;
                }
            }

            if (i < tokens.Count)
                rule.ServerAddress = ParseIPv4(tokens[i++].Text, "server address");

            if (i < tokens.Count)
                throw new FormatException("unexpected value '" + tokens[i].Text + "'");

            config.Boots.Add(rule);
        }

        private static void ParseDomain(DhcpConfiguration config, int line, List<Token> tokens)
        {
            DhcpDomainRule rule = new DhcpDomainRule() { Line = line };

            string domain = tokens[0].Text.Trim().TrimEnd('.').ToLowerInvariant();

            if (!DhcpUtilities.IsValidDomainName(domain))
                throw new FormatException("'" + tokens[0].Text + "' is not a valid domain name");

            rule.Domain = domain;

            int i = 1;

            if ((i < tokens.Count) && tokens[i].Text.Trim().Equals("local", StringComparison.OrdinalIgnoreCase))
            {
                rule.Local = true;
                i++;
            }
            else if (i < tokens.Count)
            {
                string range = tokens[i].Text.Trim();

                if (range.Contains('/'))
                {
                    string[] parts = range.Split('/', 2);
                    IPAddress network = ParseIPv4(parts[0], "network");

                    if (!int.TryParse(parts[1], NumberStyles.None, CultureInfo.InvariantCulture, out int prefix) || (prefix < 8) || (prefix > 32))
                        throw new FormatException("'" + range + "' is not a valid network");

                    uint mask = DhcpUtilities.GetMask(prefix);
                    uint start = DhcpUtilities.ToUInt32(network) & mask;
                    rule.Start = DhcpUtilities.ToAddress(start);
                    rule.End = DhcpUtilities.ToAddress(start | ~mask);
                    i++;
                }
                else
                {
                    rule.Start = ParseIPv4(range, "start address");
                    i++;

                    if (i >= tokens.Count)
                        throw new FormatException("the end address is missing");

                    rule.End = ParseIPv4(tokens[i].Text, "end address");
                    i++;

                    if (DhcpUtilities.ToUInt32(rule.End) < DhcpUtilities.ToUInt32(rule.Start))
                        throw new FormatException("the end address is lower than the start address");
                }

                if ((i < tokens.Count) && tokens[i].Text.Equals("local", StringComparison.OrdinalIgnoreCase))
                {
                    rule.Local = true;
                    i++;
                }
            }

            if (i < tokens.Count)
                throw new FormatException("unexpected value '" + tokens[i].Text + "'");

            config.Domains.Add(rule);
        }

        private static void ParseLine(DhcpConfiguration config, int line, string rawLine)
        {
            string text = StripComment(rawLine).Trim();

            if (text.Length == 0)
                return;

            string key;
            string value;
            int equals = text.IndexOf('=');

            if (equals < 0)
            {
                key = text;
                value = null;
            }
            else
            {
                key = text.Substring(0, equals).Trim();
                value = text.Substring(equals + 1).Trim();
            }

            key = key.ToLowerInvariant();

            if (key.StartsWith("--", StringComparison.Ordinal))
                key = key.Substring(2);

            if (_unsupported.Contains(key))
                throw new FormatException("'" + key + "' is not supported by the DHCP server");

            switch (key)
            {
                case "dhcp-authoritative":
                    RequireNoValue(key, value);
                    config.Authoritative = true;
                    return;

                case "dhcp-rapid-commit":
                    RequireNoValue(key, value);
                    config.RapidCommit = true;
                    return;

                case "dhcp-sequential-ip":
                    RequireNoValue(key, value);
                    config.SequentialIp = true;
                    return;

                case "dhcp-ignore-clid":
                    RequireNoValue(key, value);
                    config.IgnoreClientIds = true;
                    return;

                case "dhcp-no-override":
                    RequireNoValue(key, value);
                    config.NoOverride = true;
                    return;

                case "bootp-dynamic":
                    config.BootpDynamic = true;
                    return;

                case "no-ping":
                    RequireNoValue(key, value);
                    config.NoPing = true;
                    return;

                case "dhcp-lease-max":
                    {
                        if (!int.TryParse(RequireValue(key, value), NumberStyles.None, CultureInfo.InvariantCulture, out int max) || (max < 1) || (max > 1000000))
                            throw new FormatException("dhcp-lease-max must be a number between 1 and 1000000");

                        config.LeaseMax = max;
                    }
                    return;

                case "interface":
                    foreach (Token token in Tokenize(RequireValue(key, value)))
                        config.Interfaces.Add(ValidateInterfaceName(token.Text));

                    return;

                case "except-interface":
                    foreach (Token token in Tokenize(RequireValue(key, value)))
                        config.ExceptInterfaces.Add(ValidateInterfaceName(token.Text));

                    return;
            }

            List<Token> tokens = Tokenize(value ?? "");

            switch (key)
            {
                case "dhcp-range":
                    RequireValue(key, value);
                    ParseRange(config, line, tokens);
                    return;

                case "dhcp-host":
                    RequireValue(key, value);
                    ParseHost(config, line, tokens);
                    return;

                case "dhcp-option":
                    RequireValue(key, value);
                    ParseOption(config, line, tokens, false);
                    return;

                case "dhcp-option-force":
                    RequireValue(key, value);
                    ParseOption(config, line, tokens, true);
                    return;

                case "dhcp-match":
                    RequireValue(key, value);
                    ParseMatch(config, line, tokens, DhcpMatchKind.Option);
                    return;

                case "dhcp-vendorclass":
                    RequireValue(key, value);
                    ParseMatch(config, line, tokens, DhcpMatchKind.VendorClass);
                    return;

                case "dhcp-userclass":
                    RequireValue(key, value);
                    ParseMatch(config, line, tokens, DhcpMatchKind.UserClass);
                    return;

                case "dhcp-mac":
                    RequireValue(key, value);
                    ParseMatch(config, line, tokens, DhcpMatchKind.HardwareAddress);
                    return;

                case "dhcp-circuitid":
                    RequireValue(key, value);
                    ParseMatch(config, line, tokens, DhcpMatchKind.CircuitId);
                    return;

                case "dhcp-remoteid":
                    RequireValue(key, value);
                    ParseMatch(config, line, tokens, DhcpMatchKind.RemoteId);
                    return;

                case "dhcp-subscrid":
                    RequireValue(key, value);
                    ParseMatch(config, line, tokens, DhcpMatchKind.SubscriberId);
                    return;

                case "tag-if":
                    RequireValue(key, value);
                    ParseTagIf(config, line, tokens);
                    return;

                case "dhcp-ignore":
                    RequireValue(key, value);
                    config.IgnoreRules.Add(ParseTagList(line, tokens, false));
                    return;

                case "dhcp-ignore-names":
                    config.IgnoreNamesRules.Add(ParseTagList(line, tokens, true));
                    return;

                case "dhcp-generate-names":
                    config.GenerateNamesRules.Add(ParseTagList(line, tokens, true));
                    return;

                case "dhcp-broadcast":
                    config.BroadcastRules.Add(ParseTagList(line, tokens, true));
                    return;

                case "dhcp-boot":
                    RequireValue(key, value);
                    ParseBoot(config, line, tokens);
                    return;

                case "domain":
                    RequireValue(key, value);
                    ParseDomain(config, line, tokens);
                    return;

                case "dhcp-reply-delay":
                    {
                        RequireValue(key, value);
                        List<DhcpTagCondition> conditions = new List<DhcpTagCondition>();
                        int i = ReadConditions(tokens, 0, conditions, null, false);

                        if ((i != tokens.Count - 1) || !int.TryParse(tokens[i].Text, NumberStyles.None, CultureInfo.InvariantCulture, out int seconds) || (seconds > 10))
                            throw new FormatException("dhcp-reply-delay expects [tag:<tag>,]<seconds> with at most 10 seconds");

                        config.ReplyDelays.Add((line, conditions, seconds));
                    }
                    return;
            }

            throw new FormatException("unknown directive '" + key + "'");
        }

        private static string ValidateInterfaceName(string name)
        {
            name = name.Trim();

            if ((name.Length == 0) || (name.Length > 15))
                throw new FormatException("'" + name + "' is not a valid interface name");

            foreach (char c in name)
            {
                if (char.IsWhiteSpace(c) || (c == '/') || (c == ','))
                    throw new FormatException("'" + name + "' is not a valid interface name");
            }

            return name;
        }

        private static void RequireNoValue(string key, string value)
        {
            if (!string.IsNullOrEmpty(value))
                throw new FormatException(key + " does not take a value");
        }

        private static string RequireValue(string key, string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new FormatException(key + " needs a value");

            return value;
        }

        #endregion

        #region public

        public static DhcpConfiguration Parse(string text, int weakLines = 0)
        {
            DhcpConfiguration config = new DhcpConfiguration();

            if (string.IsNullOrEmpty(text))
                return config;

            using (StringReader reader = new StringReader(text))
            {
                int line = 0;
                string rawLine;

                while ((rawLine = reader.ReadLine()) is not null)
                {
                    line++;

                    if (line > MAX_LINES)
                    {
                        config.Errors.Add(new DhcpConfigError(line, "the configuration has more than " + MAX_LINES + " lines"));
                        break;
                    }

                    if (rawLine.Length > MAX_LINE_LENGTH)
                    {
                        config.Errors.Add(new DhcpConfigError(line, "the line is longer than " + MAX_LINE_LENGTH + " characters"));
                        continue;
                    }

                    try
                    {
                        ParseLine(config, line, rawLine);
                    }
                    catch (FormatException ex)
                    {
                        config.Errors.Add(new DhcpConfigError(line, ex.Message));
                    }
                }
            }

            foreach (DhcpOptionRule rule in config.Options)
            {
                if (rule.Line <= weakLines)
                    rule.Weak = true;
            }

            Validate(config);

            return config;
        }

        private static void Validate(DhcpConfiguration config)
        {
            for (int i = 0; i < config.Ranges.Count; i++)
            {
                DhcpRangeRule a = config.Ranges[i];

                if (a.StaticOnly)
                    continue;

                for (int j = i + 1; j < config.Ranges.Count; j++)
                {
                    DhcpRangeRule b = config.Ranges[j];

                    if (b.StaticOnly)
                        continue;

                    if ((a.StartValue <= b.EndValue) && (b.StartValue <= a.EndValue))
                        config.Errors.Add(new DhcpConfigError(b.Line, "the range overlaps the range in line " + a.Line));
                }
            }

            Dictionary<uint, int> reservedAddresses = new Dictionary<uint, int>();

            foreach (DhcpHostRule host in config.Hosts)
            {
                if (host.Address is null)
                    continue;

                uint value = DhcpUtilities.ToUInt32(host.Address);

                if (reservedAddresses.TryGetValue(value, out int otherLine))
                {
                    bool sameClient = false;

                    foreach (DhcpHostRule other in config.Hosts)
                    {
                        if ((other.Line == otherLine) && (other.Conditions.Count + host.Conditions.Count > 0))
                            sameClient = true;
                    }

                    if (!sameClient)
                        config.Errors.Add(new DhcpConfigError(host.Line, host.Address + " is already reserved in line " + otherLine));
                }
                else
                {
                    reservedAddresses.Add(value, host.Line);
                }
            }
        }

        #endregion
    }
}
