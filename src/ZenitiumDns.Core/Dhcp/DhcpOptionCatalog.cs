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
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ZenitiumDns.Core.Dhcp
{
    public enum DhcpOptionCode : byte
    {
        Pad = 0,
        SubnetMask = 1,
        TimeOffset = 2,
        Router = 3,
        DomainNameServer = 6,
        HostName = 12,
        DomainName = 15,
        BroadcastAddress = 28,
        StaticRoute = 33,
        NtpServer = 42,
        VendorSpecific = 43,
        RequestedAddress = 50,
        LeaseTime = 51,
        OptionOverload = 52,
        MessageType = 53,
        ServerIdentifier = 54,
        ParameterRequestList = 55,
        Message = 56,
        MaxMessageSize = 57,
        RenewalTime = 58,
        RebindingTime = 59,
        VendorClassIdentifier = 60,
        ClientIdentifier = 61,
        TftpServerName = 66,
        BootFileName = 67,
        UserClass = 77,
        RapidCommit = 80,
        ClientFqdn = 81,
        RelayAgentInformation = 82,
        ClientArchitecture = 93,
        SubnetSelection = 118,
        DomainSearch = 119,
        ClasslessStaticRoute = 121,
        VendorIdentifyingVendorSpecific = 125,
        End = 255
    }

    public enum DhcpOptionType
    {
        Bytes,
        Address,
        AddressList,
        AddressPairList,
        Text,
        Domain,
        DomainList,
        UInt8,
        UInt16,
        UInt32,
        Int32,
        Boolean,
        UInt16List,
        ClasslessRoutes,
        Guess
    }

    public sealed class DhcpOptionDefinition
    {
        public DhcpOptionDefinition(byte code, string name, DhcpOptionType type, bool protectedOption = false)
        {
            Code = code;
            Name = name;
            Type = type;
            Protected = protectedOption;
        }

        public byte Code { get; }

        public string Name { get; }

        public DhcpOptionType Type { get; }

        public bool Protected { get; }
    }

    public static class DhcpOptionCatalog
    {
        #region variables

        static readonly Dictionary<byte, DhcpOptionDefinition> _byCode = new Dictionary<byte, DhcpOptionDefinition>();
        static readonly Dictionary<string, DhcpOptionDefinition> _byName = new Dictionary<string, DhcpOptionDefinition>(StringComparer.OrdinalIgnoreCase);

        #endregion

        #region constructor

        static DhcpOptionCatalog()
        {
            Add(1, "netmask", DhcpOptionType.Address);
            Add(2, "time-offset", DhcpOptionType.Int32);
            Add(3, "router", DhcpOptionType.AddressList);
            Add(4, "time-server", DhcpOptionType.AddressList);
            Add(5, "name-server", DhcpOptionType.AddressList);
            Add(6, "dns-server", DhcpOptionType.AddressList);
            Add(7, "log-server", DhcpOptionType.AddressList);
            Add(8, "cookie-server", DhcpOptionType.AddressList);
            Add(9, "lpr-server", DhcpOptionType.AddressList);
            Add(10, "impress-server", DhcpOptionType.AddressList);
            Add(11, "resource-location-server", DhcpOptionType.AddressList);
            Add(12, "hostname", DhcpOptionType.Text);
            Add(13, "boot-file-size", DhcpOptionType.UInt16);
            Add(14, "merit-dump-file", DhcpOptionType.Text);
            Add(15, "domain-name", DhcpOptionType.Domain);
            Add(16, "swap-server", DhcpOptionType.Address);
            Add(17, "root-path", DhcpOptionType.Text);
            Add(18, "extension-path", DhcpOptionType.Text);
            Add(19, "ip-forward-enable", DhcpOptionType.Boolean);
            Add(20, "non-local-source-routing", DhcpOptionType.Boolean);
            Add(21, "policy-filter", DhcpOptionType.AddressPairList);
            Add(22, "max-datagram-reassembly", DhcpOptionType.UInt16);
            Add(23, "default-ttl", DhcpOptionType.UInt8);
            Add(24, "path-mtu-aging-timeout", DhcpOptionType.UInt32);
            Add(25, "path-mtu-plateau-table", DhcpOptionType.UInt16List);
            Add(26, "mtu", DhcpOptionType.UInt16);
            Add(27, "all-subnets-local", DhcpOptionType.Boolean);
            Add(28, "broadcast", DhcpOptionType.Address);
            Add(29, "perform-mask-discovery", DhcpOptionType.Boolean);
            Add(30, "mask-supplier", DhcpOptionType.Boolean);
            Add(31, "router-discovery", DhcpOptionType.Boolean);
            Add(32, "router-solicitation", DhcpOptionType.Address);
            Add(33, "static-route", DhcpOptionType.AddressPairList);
            Add(34, "trailer-encapsulation", DhcpOptionType.Boolean);
            Add(35, "arp-timeout", DhcpOptionType.UInt32);
            Add(36, "ethernet-encap", DhcpOptionType.Boolean);
            Add(37, "tcp-ttl", DhcpOptionType.UInt8);
            Add(38, "tcp-keepalive", DhcpOptionType.UInt32);
            Add(39, "tcp-keepalive-garbage", DhcpOptionType.Boolean);
            Add(40, "nis-domain", DhcpOptionType.Text);
            Add(41, "nis-server", DhcpOptionType.AddressList);
            Add(42, "ntp-server", DhcpOptionType.AddressList);
            Add(43, "vendor-encap", DhcpOptionType.Bytes);
            Add(44, "netbios-ns", DhcpOptionType.AddressList);
            Add(45, "netbios-dd", DhcpOptionType.AddressList);
            Add(46, "netbios-nodetype", DhcpOptionType.UInt8);
            Add(47, "netbios-scope", DhcpOptionType.Text);
            Add(48, "x-windows-fs", DhcpOptionType.AddressList);
            Add(49, "x-windows-dm", DhcpOptionType.AddressList);
            Add(50, "requested-address", DhcpOptionType.Address, true);
            Add(51, "lease-time", DhcpOptionType.UInt32, true);
            Add(52, "option-overload", DhcpOptionType.UInt8, true);
            Add(53, "message-type", DhcpOptionType.UInt8, true);
            Add(54, "server-identifier", DhcpOptionType.Address, true);
            Add(55, "parameter-request", DhcpOptionType.Bytes, true);
            Add(56, "message", DhcpOptionType.Text);
            Add(57, "max-message-size", DhcpOptionType.UInt16, true);
            Add(58, "T1", DhcpOptionType.UInt32);
            Add(59, "T2", DhcpOptionType.UInt32);
            Add(60, "vendor-class", DhcpOptionType.Text);
            Add(61, "client-id", DhcpOptionType.Bytes, true);
            Add(62, "netware-ip-domain", DhcpOptionType.Text);
            Add(64, "nis+-domain", DhcpOptionType.Text);
            Add(65, "nis+-server", DhcpOptionType.AddressList);
            Add(66, "tftp-server", DhcpOptionType.Text);
            Add(67, "bootfile-name", DhcpOptionType.Text);
            Add(68, "mobile-ip-home", DhcpOptionType.AddressList);
            Add(69, "smtp-server", DhcpOptionType.AddressList);
            Add(70, "pop3-server", DhcpOptionType.AddressList);
            Add(71, "nntp-server", DhcpOptionType.AddressList);
            Add(72, "www-server", DhcpOptionType.AddressList);
            Add(73, "finger-server", DhcpOptionType.AddressList);
            Add(74, "irc-server", DhcpOptionType.AddressList);
            Add(75, "streettalk-server", DhcpOptionType.AddressList);
            Add(76, "stda-server", DhcpOptionType.AddressList);
            Add(77, "user-class", DhcpOptionType.Bytes);
            Add(80, "rapid-commit", DhcpOptionType.Bytes, true);
            Add(81, "FQDN", DhcpOptionType.Bytes, true);
            Add(82, "agent-id", DhcpOptionType.Bytes, true);
            Add(93, "client-arch", DhcpOptionType.UInt16List);
            Add(94, "client-interface-id", DhcpOptionType.Bytes);
            Add(97, "client-machine-id", DhcpOptionType.Bytes);
            Add(100, "posix-timezone", DhcpOptionType.Text);
            Add(101, "tzdb-timezone", DhcpOptionType.Text);
            Add(108, "ipv6-only", DhcpOptionType.UInt32);
            Add(114, "captive-portal", DhcpOptionType.Text);
            Add(116, "auto-config", DhcpOptionType.UInt8);
            Add(118, "subnet-select", DhcpOptionType.Address, true);
            Add(119, "domain-search", DhcpOptionType.DomainList);
            Add(120, "sip-server", DhcpOptionType.Bytes);
            Add(121, "classless-static-route", DhcpOptionType.ClasslessRoutes);
            Add(124, "vendor-id-class", DhcpOptionType.Bytes);
            Add(125, "vendor-id-encap", DhcpOptionType.Bytes);
            Add(150, "tftp-server-address", DhcpOptionType.AddressList);
            Add(249, "ms-classless-static-route", DhcpOptionType.ClasslessRoutes);
            Add(252, "wpad", DhcpOptionType.Text);
        }

        #endregion

        #region private

        private static void Add(byte code, string name, DhcpOptionType type, bool protectedOption = false)
        {
            DhcpOptionDefinition definition = new DhcpOptionDefinition(code, name, type, protectedOption);
            _byCode[code] = definition;
            _byName[name] = definition;
        }

        private static IPAddress ParseAddress(string value)
        {
            value = value.Trim();

            if (!ZenitiumLibrary.Net.IPAddressExtensions.TryParseStrict(value, out IPAddress address) || (address.AddressFamily != AddressFamily.InterNetwork))
                throw new FormatException("'" + value + "' is not an IPv4 address");

            return address;
        }

        private static ulong ParseUnsigned(string value, ulong max)
        {
            value = value.Trim();
            ulong result;

            if (value.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                if (!ulong.TryParse(value.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out result))
                    throw new FormatException("'" + value + "' is not a number");
            }
            else if (!ulong.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out result))
            {
                throw new FormatException("'" + value + "' is not a number");
            }

            if (result > max)
                throw new FormatException(value + " is larger than " + max);

            return result;
        }

        private static void WriteDomainName(MemoryStream stream, string domain, Dictionary<string, int> offsets)
        {
            domain = domain.Trim().TrimEnd('.');

            if (domain.Length == 0)
            {
                stream.WriteByte(0);
                return;
            }

            if (!DhcpUtilities.IsValidDomainName(domain))
                throw new FormatException("'" + domain + "' is not a valid domain name");

            string remaining = domain.ToLowerInvariant();

            while (remaining.Length > 0)
            {
                if ((offsets is not null) && offsets.TryGetValue(remaining, out int pointer) && (pointer < 0x3FFF))
                {
                    stream.WriteByte((byte)(0xC0 | (pointer >> 8)));
                    stream.WriteByte((byte)(pointer & 0xFF));
                    return;
                }

                offsets?.TryAdd(remaining, (int)stream.Position);

                int dot = remaining.IndexOf('.');
                string label = dot < 0 ? remaining : remaining.Substring(0, dot);
                byte[] bytes = Encoding.ASCII.GetBytes(label);
                stream.WriteByte((byte)bytes.Length);
                stream.Write(bytes);

                remaining = dot < 0 ? "" : remaining.Substring(dot + 1);
            }

            stream.WriteByte(0);
        }

        private static string ReadDomainList(byte[] value)
        {
            List<string> names = new List<string>();
            int offset = 0;

            while (offset < value.Length)
            {
                StringBuilder sb = new StringBuilder();
                int position = offset;
                int jumps = 0;
                bool jumped = false;

                while (true)
                {
                    if (position >= value.Length)
                        return null;

                    byte length = value[position];

                    if (length == 0)
                    {
                        if (!jumped)
                            offset = position + 1;

                        break;
                    }

                    if ((length & 0xC0) == 0xC0)
                    {
                        if ((position + 1 >= value.Length) || (++jumps > 32))
                            return null;

                        int pointer = ((length & 0x3F) << 8) | value[position + 1];

                        if (!jumped)
                            offset = position + 2;

                        jumped = true;
                        position = pointer;
                        continue;
                    }

                    if (position + 1 + length > value.Length)
                        return null;

                    if (sb.Length > 0)
                        sb.Append('.');

                    sb.Append(Encoding.ASCII.GetString(value, position + 1, length));
                    position += 1 + length;
                }

                names.Add(sb.ToString());
            }

            return string.Join(", ", names);
        }

        #endregion

        #region public

        public static bool TryGetDefinition(byte code, out DhcpOptionDefinition definition)
        {
            return _byCode.TryGetValue(code, out definition);
        }

        public static bool TryGetDefinition(string name, out DhcpOptionDefinition definition)
        {
            return _byName.TryGetValue(name, out definition);
        }

        public static string GetName(byte code)
        {
            if (_byCode.TryGetValue(code, out DhcpOptionDefinition definition))
                return definition.Name;

            return code.ToString(CultureInfo.InvariantCulture);
        }

        public static IReadOnlyCollection<DhcpOptionDefinition> Definitions
        { get { return _byCode.Values; } }

        public static byte[] Encode(DhcpOptionType type, IReadOnlyList<string> values)
        {
            switch (type)
            {
                case DhcpOptionType.Address:
                    if (values.Count != 1)
                        throw new FormatException("exactly one IPv4 address is expected");

                    return ParseAddress(values[0]).GetAddressBytes();

                case DhcpOptionType.AddressList:
                    {
                        if (values.Count == 0)
                            throw new FormatException("at least one IPv4 address is expected");

                        byte[] result = new byte[values.Count * 4];
                        for (int i = 0; i < values.Count; i++)
                            ParseAddress(values[i]).GetAddressBytes().CopyTo(result, i * 4);

                        return result;
                    }

                case DhcpOptionType.AddressPairList:
                    {
                        if ((values.Count == 0) || ((values.Count % 2) != 0))
                            throw new FormatException("pairs of IPv4 addresses are expected");

                        byte[] result = new byte[values.Count * 4];
                        for (int i = 0; i < values.Count; i++)
                            ParseAddress(values[i]).GetAddressBytes().CopyTo(result, i * 4);

                        return result;
                    }

                case DhcpOptionType.Text:
                    {
                        string text = string.Join(",", values);
                        byte[] result = Encoding.UTF8.GetBytes(text);
                        if (result.Length == 0)
                            throw new FormatException("a text value is expected");

                        return result;
                    }

                case DhcpOptionType.Domain:
                    {
                        if (values.Count != 1)
                            throw new FormatException("exactly one domain name is expected");

                        string domain = values[0].Trim().TrimEnd('.');
                        if (!DhcpUtilities.IsValidDomainName(domain))
                            throw new FormatException("'" + values[0] + "' is not a valid domain name");

                        return Encoding.ASCII.GetBytes(domain);
                    }

                case DhcpOptionType.DomainList:
                    {
                        if (values.Count == 0)
                            throw new FormatException("at least one domain name is expected");

                        using (MemoryStream stream = new MemoryStream())
                        {
                            Dictionary<string, int> offsets = new Dictionary<string, int>(StringComparer.Ordinal);

                            foreach (string value in values)
                                WriteDomainName(stream, value, offsets);

                            return stream.ToArray();
                        }
                    }

                case DhcpOptionType.UInt8:
                    if (values.Count != 1)
                        throw new FormatException("exactly one number is expected");

                    return [(byte)ParseUnsigned(values[0], byte.MaxValue)];

                case DhcpOptionType.UInt16:
                    {
                        if (values.Count != 1)
                            throw new FormatException("exactly one number is expected");

                        byte[] result = new byte[2];
                        BinaryPrimitives.WriteUInt16BigEndian(result, (ushort)ParseUnsigned(values[0], ushort.MaxValue));
                        return result;
                    }

                case DhcpOptionType.UInt32:
                    {
                        if (values.Count != 1)
                            throw new FormatException("exactly one number is expected");

                        byte[] result = new byte[4];
                        BinaryPrimitives.WriteUInt32BigEndian(result, (uint)ParseUnsigned(values[0], uint.MaxValue));
                        return result;
                    }

                case DhcpOptionType.Int32:
                    {
                        if ((values.Count != 1) || !int.TryParse(values[0].Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out int number))
                            throw new FormatException("exactly one signed number is expected");

                        byte[] result = new byte[4];
                        BinaryPrimitives.WriteInt32BigEndian(result, number);
                        return result;
                    }

                case DhcpOptionType.Boolean:
                    {
                        if (values.Count != 1)
                            throw new FormatException("0 or 1 is expected");

                        switch (values[0].Trim().ToLowerInvariant())
                        {
                            case "0":
                            case "false":
                            case "no":
                                return [0];

                            case "1":
                            case "true":
                            case "yes":
                                return [1];

                            default:
                                throw new FormatException("0 or 1 is expected");
                        }
                    }

                case DhcpOptionType.UInt16List:
                    {
                        if (values.Count == 0)
                            throw new FormatException("at least one number is expected");

                        byte[] result = new byte[values.Count * 2];
                        for (int i = 0; i < values.Count; i++)
                            BinaryPrimitives.WriteUInt16BigEndian(result.AsSpan(i * 2), (ushort)ParseUnsigned(values[i], ushort.MaxValue));

                        return result;
                    }

                case DhcpOptionType.ClasslessRoutes:
                    {
                        if ((values.Count == 0) || ((values.Count % 2) != 0))
                            throw new FormatException("pairs of network/prefix and router are expected");

                        using (MemoryStream stream = new MemoryStream())
                        {
                            for (int i = 0; i < values.Count; i += 2)
                            {
                                string network = values[i].Trim();
                                int slash = network.IndexOf('/');
                                int prefix = 32;

                                if (slash >= 0)
                                {
                                    prefix = (int)ParseUnsigned(network.Substring(slash + 1), 32);
                                    network = network.Substring(0, slash);
                                }

                                byte[] networkBytes = ParseAddress(network).GetAddressBytes();
                                int significant = (prefix + 7) / 8;

                                stream.WriteByte((byte)prefix);
                                stream.Write(networkBytes, 0, significant);
                                stream.Write(ParseAddress(values[i + 1]).GetAddressBytes());
                            }

                            return stream.ToArray();
                        }
                    }

                case DhcpOptionType.Bytes:
                    return EncodeBytes(values);

                case DhcpOptionType.Guess:
                default:
                    return EncodeGuess(values);
            }
        }

        public static byte[] EncodeBytes(IReadOnlyList<string> values)
        {
            string text = string.Join(",", values).Trim();

            if (text.Length == 0)
                return [];

            if (DhcpUtilities.TryParseHex(text, out byte[] bytes))
                return bytes;

            return Encoding.UTF8.GetBytes(text);
        }

        public static byte[] EncodeGuess(IReadOnlyList<string> values)
        {
            if (values.Count == 0)
                return [];

            bool allAddresses = true;
            foreach (string value in values)
            {
                if (!ZenitiumLibrary.Net.IPAddressExtensions.TryParseStrict(value.Trim(), out IPAddress address) || (address.AddressFamily != AddressFamily.InterNetwork))
                {
                    allAddresses = false;
                    break;
                }
            }

            if (allAddresses)
                return Encode(DhcpOptionType.AddressList, values);

            if ((values.Count == 1) && ulong.TryParse(values[0].Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out ulong number))
            {
                if (number <= byte.MaxValue)
                    return [(byte)number];

                if (number <= ushort.MaxValue)
                    return Encode(DhcpOptionType.UInt16, values);

                if (number <= uint.MaxValue)
                    return Encode(DhcpOptionType.UInt32, values);
            }

            return EncodeBytes(values);
        }

        public static string Decode(byte code, byte[] value)
        {
            if (value is null)
                return "";

            DhcpOptionType type = _byCode.TryGetValue(code, out DhcpOptionDefinition definition) ? definition.Type : DhcpOptionType.Bytes;

            try
            {
                switch (type)
                {
                    case DhcpOptionType.Address:
                    case DhcpOptionType.AddressList:
                    case DhcpOptionType.AddressPairList:
                        if ((value.Length == 0) || ((value.Length % 4) != 0))
                            break;

                        {
                            List<string> addresses = new List<string>(value.Length / 4);
                            for (int i = 0; i < value.Length; i += 4)
                                addresses.Add(new IPAddress(value.AsSpan(i, 4)).ToString());

                            return string.Join(", ", addresses);
                        }

                    case DhcpOptionType.Text:
                    case DhcpOptionType.Domain:
                        if (DhcpUtilities.IsPrintable(value))
                            return Encoding.UTF8.GetString(value).TrimEnd('\0');

                        break;

                    case DhcpOptionType.DomainList:
                        {
                            string names = ReadDomainList(value);
                            if (names is not null)
                                return names;
                        }
                        break;

                    case DhcpOptionType.UInt8:
                    case DhcpOptionType.Boolean:
                        if (value.Length == 1)
                            return value[0].ToString(CultureInfo.InvariantCulture);

                        break;

                    case DhcpOptionType.UInt16:
                        if (value.Length == 2)
                            return BinaryPrimitives.ReadUInt16BigEndian(value).ToString(CultureInfo.InvariantCulture);

                        break;

                    case DhcpOptionType.UInt32:
                        if (value.Length == 4)
                            return BinaryPrimitives.ReadUInt32BigEndian(value).ToString(CultureInfo.InvariantCulture);

                        break;

                    case DhcpOptionType.Int32:
                        if (value.Length == 4)
                            return BinaryPrimitives.ReadInt32BigEndian(value).ToString(CultureInfo.InvariantCulture);

                        break;

                    case DhcpOptionType.UInt16List:
                        if ((value.Length > 0) && ((value.Length % 2) == 0))
                        {
                            List<string> numbers = new List<string>(value.Length / 2);
                            for (int i = 0; i < value.Length; i += 2)
                                numbers.Add(BinaryPrimitives.ReadUInt16BigEndian(value.AsSpan(i)).ToString(CultureInfo.InvariantCulture));

                            return string.Join(", ", numbers);
                        }

                        break;
                }
            }
            catch
            { }

            if (DhcpUtilities.IsPrintable(value) && (value.Length > 0))
                return Encoding.UTF8.GetString(value);

            return DhcpUtilities.FormatHex(value);
        }

        #endregion
    }
}
