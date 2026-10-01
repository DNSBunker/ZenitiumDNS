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

namespace ZenitiumDns.Core.Dhcp
{
    public sealed class DhcpTagCondition
    {
        public DhcpTagCondition(string tag, bool negated)
        {
            Tag = tag;
            Negated = negated;
        }

        public string Tag { get; }

        public bool Negated { get; }

        public override string ToString()
        {
            return "tag:" + (Negated ? "!" : "") + Tag;
        }

        public static bool AllMatch(IReadOnlyList<DhcpTagCondition> conditions, ISet<string> tags)
        {
            foreach (DhcpTagCondition condition in conditions)
            {
                if (tags.Contains(condition.Tag) == condition.Negated)
                    return false;
            }

            return true;
        }
    }

    public sealed class DhcpHardwarePattern
    {
        public DhcpHardwarePattern(int hardwareType, short[] bytes)
        {
            HardwareType = hardwareType;
            Bytes = bytes;
        }

        public int HardwareType { get; }

        public short[] Bytes { get; }

        public bool HasWildcard
        {
            get
            {
                foreach (short b in Bytes)
                {
                    if (b < 0)
                        return true;
                }

                return false;
            }
        }

        public bool Matches(byte hardwareType, byte[] address)
        {
            if ((HardwareType >= 0) && (HardwareType != hardwareType))
                return false;

            if ((address is null) || (address.Length != Bytes.Length))
                return false;

            for (int i = 0; i < Bytes.Length; i++)
            {
                if ((Bytes[i] >= 0) && (Bytes[i] != address[i]))
                    return false;
            }

            return true;
        }

        public override string ToString()
        {
            string[] parts = new string[Bytes.Length];

            for (int i = 0; i < Bytes.Length; i++)
                parts[i] = Bytes[i] < 0 ? "*" : Bytes[i].ToString("x2");

            return (HardwareType >= 0 ? HardwareType + "-" : "") + string.Join(':', parts);
        }

        public static bool TryParse(string text, out DhcpHardwarePattern pattern)
        {
            pattern = null;
            text = text.Trim();

            int hardwareType = -1;
            int dash = text.IndexOf('-');

            if ((dash > 0) && (dash <= 3) && int.TryParse(text.AsSpan(0, dash), out int type) && (type >= 0) && (type <= 255) && (text.IndexOf(':') > dash))
            {
                hardwareType = type;
                text = text.Substring(dash + 1);
            }

            string[] parts = text.Split(':');
            if ((parts.Length < 2) || (parts.Length > 16))
                return false;

            short[] bytes = new short[parts.Length];

            for (int i = 0; i < parts.Length; i++)
            {
                string part = parts[i];

                if (part == "*")
                {
                    bytes[i] = -1;
                    continue;
                }

                if ((part.Length < 1) || (part.Length > 2) || !byte.TryParse(part, System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture, out byte value))
                    return false;

                bytes[i] = value;
            }

            pattern = new DhcpHardwarePattern(hardwareType, bytes);
            return true;
        }
    }

    public sealed class DhcpRangeRule
    {
        public int Line { get; set; }

        public List<DhcpTagCondition> Conditions { get; } = new List<DhcpTagCondition>();

        public string SetTag { get; set; }

        public IPAddress Start { get; set; }

        public IPAddress End { get; set; }

        public bool StaticOnly { get; set; }

        public IPAddress Netmask { get; set; }

        public IPAddress Broadcast { get; set; }

        public uint LeaseTime { get; set; }

        public uint StartValue
        { get { return DhcpUtilities.ToUInt32(Start); } }

        public uint EndValue
        { get { return DhcpUtilities.ToUInt32(End ?? Start); } }

        public bool ContainsInPool(IPAddress address)
        {
            if (StaticOnly)
                return false;

            uint value = DhcpUtilities.ToUInt32(address);
            return (value >= StartValue) && (value <= EndValue);
        }
    }

    public sealed class DhcpHostRule
    {
        public int Line { get; set; }

        public List<DhcpHardwarePattern> HardwareAddresses { get; } = new List<DhcpHardwarePattern>();

        public List<byte[]> ClientIds { get; } = new List<byte[]>();

        public bool IgnoreClientId { get; set; }

        public List<DhcpTagCondition> Conditions { get; } = new List<DhcpTagCondition>();

        public List<string> SetTags { get; } = new List<string>();

        public IPAddress Address { get; set; }

        public string HostName { get; set; }

        public bool MatchByHostName { get; set; }

        public uint LeaseTime { get; set; }

        public bool Ignore { get; set; }
    }

    public sealed class DhcpOptionRule
    {
        public int Line { get; set; }

        public List<DhcpTagCondition> Conditions { get; } = new List<DhcpTagCondition>();

        public string VendorClass { get; set; }

        public byte EncapsulatedIn { get; set; }

        public uint ViEnterprise { get; set; }

        public bool IsViEncapsulated { get; set; }

        public byte Code { get; set; }

        public byte[] Value { get; set; }

        public bool Force { get; set; }

        public bool Suppress { get; set; }

        public bool UsesServerAddress { get; set; }

        public bool Weak { get; set; }
    }

    public enum DhcpMatchKind
    {
        Option,
        ViEncapsulated,
        VendorClass,
        UserClass,
        HardwareAddress,
        CircuitId,
        RemoteId,
        SubscriberId
    }

    public sealed class DhcpMatchRule
    {
        public int Line { get; set; }

        public string SetTag { get; set; }

        public DhcpMatchKind Kind { get; set; }

        public byte OptionCode { get; set; }

        public uint Enterprise { get; set; }

        public byte[] Value { get; set; }

        public bool ValueIsText { get; set; }

        public DhcpHardwarePattern HardwarePattern { get; set; }
    }

    public sealed class DhcpTagIfRule
    {
        public int Line { get; set; }

        public List<string> SetTags { get; } = new List<string>();

        public List<DhcpTagCondition> Conditions { get; } = new List<DhcpTagCondition>();
    }

    public sealed class DhcpBootRule
    {
        public int Line { get; set; }

        public List<DhcpTagCondition> Conditions { get; } = new List<DhcpTagCondition>();

        public string FileName { get; set; }

        public string ServerName { get; set; }

        public IPAddress ServerAddress { get; set; }
    }

    public sealed class DhcpDomainRule
    {
        public int Line { get; set; }

        public string Domain { get; set; }

        public IPAddress Start { get; set; }

        public IPAddress End { get; set; }

        public bool Local { get; set; }

        public bool Matches(IPAddress address)
        {
            if (Start is null)
                return true;

            uint value = DhcpUtilities.ToUInt32(address);
            return (value >= DhcpUtilities.ToUInt32(Start)) && (value <= DhcpUtilities.ToUInt32(End));
        }
    }

    public sealed class DhcpTagListRule
    {
        public int Line { get; set; }

        public List<DhcpTagCondition> Conditions { get; } = new List<DhcpTagCondition>();
    }

    public sealed class DhcpConfigError
    {
        public DhcpConfigError(int line, string message)
        {
            Line = line;
            Message = message;
        }

        public int Line { get; }

        public string Message { get; }

        public override string ToString()
        {
            return "line " + Line + ": " + Message;
        }
    }

    public sealed class DhcpConfiguration
    {
        public static readonly DhcpConfiguration Empty = new DhcpConfiguration();

        public List<string> Interfaces { get; } = new List<string>();

        public List<string> ExceptInterfaces { get; } = new List<string>();

        public List<DhcpRangeRule> Ranges { get; } = new List<DhcpRangeRule>();

        public List<DhcpHostRule> Hosts { get; } = new List<DhcpHostRule>();

        public List<DhcpOptionRule> Options { get; } = new List<DhcpOptionRule>();

        public List<DhcpMatchRule> Matches { get; } = new List<DhcpMatchRule>();

        public List<DhcpTagIfRule> TagIfs { get; } = new List<DhcpTagIfRule>();

        public List<DhcpBootRule> Boots { get; } = new List<DhcpBootRule>();

        public List<DhcpDomainRule> Domains { get; } = new List<DhcpDomainRule>();

        public List<DhcpTagListRule> IgnoreRules { get; } = new List<DhcpTagListRule>();

        public List<DhcpTagListRule> IgnoreNamesRules { get; } = new List<DhcpTagListRule>();

        public List<DhcpTagListRule> GenerateNamesRules { get; } = new List<DhcpTagListRule>();

        public List<DhcpTagListRule> BroadcastRules { get; } = new List<DhcpTagListRule>();

        public List<(int Line, List<DhcpTagCondition> Conditions, int Seconds)> ReplyDelays { get; } = new List<(int, List<DhcpTagCondition>, int)>();

        public List<DhcpConfigError> Errors { get; } = new List<DhcpConfigError>();

        public bool Authoritative { get; set; }

        public bool RapidCommit { get; set; }

        public bool SequentialIp { get; set; }

        public bool IgnoreClientIds { get; set; }

        public bool NoOverride { get; set; }

        public bool BootpDynamic { get; set; }

        public bool NoPing { get; set; }

        public int LeaseMax { get; set; } = 1000;

        public bool IsInterfaceAllowed(string name)
        {
            foreach (string except in ExceptInterfaces)
            {
                if (string.Equals(except, name, StringComparison.Ordinal))
                    return false;
            }

            if (Interfaces.Count == 0)
                return true;

            foreach (string allowed in Interfaces)
            {
                if (string.Equals(allowed, name, StringComparison.Ordinal))
                    return true;

                if (allowed.EndsWith('*') && name.StartsWith(allowed.Substring(0, allowed.Length - 1), StringComparison.Ordinal))
                    return true;
            }

            return false;
        }
    }
}
