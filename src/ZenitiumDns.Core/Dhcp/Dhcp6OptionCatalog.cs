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
    public enum Dhcp6OptionType
    {
        Bytes,
        AddressList,
        Domain,
        DomainList,
        UInt8,
        UInt16,
        UInt32,
        Text,
        TextList,
        NtpServer,
        Guess
    }

    public sealed class Dhcp6OptionDefinition
    {
        public Dhcp6OptionDefinition(ushort code, string name, Dhcp6OptionType type, bool protectedOption = false)
        {
            Code = code;
            Name = name;
            Type = type;
            Protected = protectedOption;
        }

        public ushort Code { get; }

        public string Name { get; }

        public Dhcp6OptionType Type { get; }

        public bool Protected { get; }
    }

    public static class Dhcp6OptionCatalog
    {
        #region variables

        static readonly Dictionary<ushort, Dhcp6OptionDefinition> _byCode = new Dictionary<ushort, Dhcp6OptionDefinition>();
        static readonly Dictionary<string, Dhcp6OptionDefinition> _byName = new Dictionary<string, Dhcp6OptionDefinition>(StringComparer.OrdinalIgnoreCase);

        #endregion

        #region constructor

        static Dhcp6OptionCatalog()
        {
            Add(1, "client-id", Dhcp6OptionType.Bytes, true);
            Add(2, "server-id", Dhcp6OptionType.Bytes, true);
            Add(3, "ia-na", Dhcp6OptionType.Bytes, true);
            Add(4, "ia-ta", Dhcp6OptionType.Bytes, true);
            Add(5, "iaaddr", Dhcp6OptionType.Bytes, true);
            Add(6, "oro", Dhcp6OptionType.Bytes, true);
            Add(7, "preference", Dhcp6OptionType.UInt8, true);
            Add(8, "elapsed-time", Dhcp6OptionType.UInt16, true);
            Add(9, "relay-msg", Dhcp6OptionType.Bytes, true);
            Add(12, "unicast", Dhcp6OptionType.Bytes, true);
            Add(13, "status", Dhcp6OptionType.Bytes, true);
            Add(14, "rapid-commit", Dhcp6OptionType.Bytes, true);
            Add(15, "user-class", Dhcp6OptionType.Bytes);
            Add(16, "vendor-class", Dhcp6OptionType.Bytes);
            Add(17, "vendor-opts", Dhcp6OptionType.Bytes);
            Add(18, "interface-id", Dhcp6OptionType.Bytes, true);
            Add(21, "sip-server-domain", Dhcp6OptionType.DomainList);
            Add(22, "sip-server", Dhcp6OptionType.AddressList);
            Add(23, "dns-server", Dhcp6OptionType.AddressList);
            Add(24, "domain-search", Dhcp6OptionType.DomainList);
            Add(25, "ia-pd", Dhcp6OptionType.Bytes, true);
            Add(26, "iaprefix", Dhcp6OptionType.Bytes, true);
            Add(27, "nis-server", Dhcp6OptionType.AddressList);
            Add(28, "nis+-server", Dhcp6OptionType.AddressList);
            Add(29, "nis-domain", Dhcp6OptionType.Domain);
            Add(30, "nis+-domain", Dhcp6OptionType.Domain);
            Add(31, "sntp-server", Dhcp6OptionType.AddressList);
            Add(32, "information-refresh-time", Dhcp6OptionType.UInt32);
            Add(39, "FQDN", Dhcp6OptionType.Bytes, true);
            Add(56, "ntp-server", Dhcp6OptionType.NtpServer);
            Add(59, "bootfile-url", Dhcp6OptionType.Text);
            Add(60, "bootfile-param", Dhcp6OptionType.TextList);
            Add(64, "aftr-name", Dhcp6OptionType.Domain);
            Add(82, "sol-max-rt", Dhcp6OptionType.UInt32);
            Add(83, "inf-max-rt", Dhcp6OptionType.UInt32);
        }

        #endregion

        #region private

        private static void Add(ushort code, string name, Dhcp6OptionType type, bool protectedOption = false)
        {
            Dhcp6OptionDefinition definition = new Dhcp6OptionDefinition(code, name, type, protectedOption);
            _byCode[code] = definition;
            _byName[name] = definition;
        }

        private static IPAddress ParseAddress(string value, out bool isServerAddress)
        {
            string text = value.Trim();

            if (text.StartsWith('[') && text.EndsWith(']'))
                text = text.Substring(1, text.Length - 2);

            if (!IPAddress.TryParse(text, out IPAddress address) || (address.AddressFamily != AddressFamily.InterNetworkV6) || (address.ScopeId != 0))
                throw new FormatException("'" + value + "' is not a valid IPv6 address");

            isServerAddress = address.Equals(IPAddress.IPv6Any);
            return address;
        }

        private static bool IsAddressText(string value)
        {
            string text = value.Trim();

            if (text.StartsWith('[') && text.EndsWith(']'))
                text = text.Substring(1, text.Length - 2);

            return text.Contains(':') && IPAddress.TryParse(text, out IPAddress address) && (address.AddressFamily == AddressFamily.InterNetworkV6);
        }

        private static uint ParseNumber(string value, uint max)
        {
            string text = value.Trim();
            uint number;

            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                if (!uint.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out number))
                    throw new FormatException("'" + value + "' is not a valid number");
            }
            else if (!uint.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out number))
            {
                if (DhcpUtilities.LooksLikeLeaseTime(text) && DhcpUtilities.TryParseLeaseTime(text, out uint seconds))
                    number = seconds;
                else
                    throw new FormatException("'" + value + "' is not a valid number");
            }

            if (number > max)
                throw new FormatException("'" + value + "' is too large (maximum " + max + ")");

            return number;
        }

        #endregion

        #region public

        public static bool TryGetDefinition(ushort code, out Dhcp6OptionDefinition definition)
        {
            return _byCode.TryGetValue(code, out definition);
        }

        public static bool TryGetDefinition(string name, out Dhcp6OptionDefinition definition)
        {
            return _byName.TryGetValue(name, out definition);
        }

        public static string GetName(ushort code)
        {
            if (_byCode.TryGetValue(code, out Dhcp6OptionDefinition definition))
                return definition.Name;

            return code.ToString(CultureInfo.InvariantCulture);
        }

        public static IReadOnlyCollection<Dhcp6OptionDefinition> Definitions
        { get { return _byCode.Values; } }

        public static byte[] Encode(Dhcp6OptionType type, IReadOnlyList<string> values, out bool usesServerAddress)
        {
            usesServerAddress = false;

            switch (type)
            {
                case Dhcp6OptionType.AddressList:
                    {
                        List<IPAddress> addresses = new List<IPAddress>();

                        foreach (string value in values)
                        {
                            if (value.Trim().Length == 0)
                                continue;

                            addresses.Add(ParseAddress(value, out bool isServer));
                            usesServerAddress |= isServer;
                        }

                        if (addresses.Count == 0)
                            throw new FormatException("at least one IPv6 address is required");

                        return Dhcp6Message.EncodeAddresses(addresses);
                    }

                case Dhcp6OptionType.Domain:
                    {
                        if (values.Count != 1)
                            throw new FormatException("exactly one domain name is expected");

                        string domain = values[0].Trim().TrimEnd('.');
                        if (!DhcpUtilities.IsValidDomainName(domain))
                            throw new FormatException("'" + values[0] + "' is not a valid domain name");

                        return Dhcp6Message.EncodeDomainList([domain]);
                    }

                case Dhcp6OptionType.DomainList:
                    {
                        List<string> domains = new List<string>();

                        foreach (string value in values)
                        {
                            string domain = value.Trim().TrimEnd('.');

                            if (domain.Length == 0)
                                continue;

                            if (!DhcpUtilities.IsValidDomainName(domain))
                                throw new FormatException("'" + value + "' is not a valid domain name");

                            domains.Add(domain);
                        }

                        if (domains.Count == 0)
                            throw new FormatException("at least one domain name is required");

                        return Dhcp6Message.EncodeDomainList(domains);
                    }

                case Dhcp6OptionType.UInt8:
                    if (values.Count != 1)
                        throw new FormatException("exactly one number is expected");

                    return [(byte)ParseNumber(values[0], byte.MaxValue)];

                case Dhcp6OptionType.UInt16:
                    {
                        if (values.Count != 1)
                            throw new FormatException("exactly one number is expected");

                        byte[] data = new byte[2];
                        BinaryPrimitives.WriteUInt16BigEndian(data, (ushort)ParseNumber(values[0], ushort.MaxValue));
                        return data;
                    }

                case Dhcp6OptionType.UInt32:
                    {
                        if (values.Count != 1)
                            throw new FormatException("exactly one number is expected");

                        byte[] data = new byte[4];
                        BinaryPrimitives.WriteUInt32BigEndian(data, ParseNumber(values[0], uint.MaxValue));
                        return data;
                    }

                case Dhcp6OptionType.Text:
                    return Encoding.UTF8.GetBytes(string.Join(',', values));

                case Dhcp6OptionType.TextList:
                    using (MemoryStream mS = new MemoryStream())
                    {
                        foreach (string value in values)
                        {
                            byte[] text = Encoding.UTF8.GetBytes(value);
                            if (text.Length > ushort.MaxValue)
                                throw new FormatException("a value is too long");

                            mS.WriteByte((byte)(text.Length >> 8));
                            mS.WriteByte((byte)text.Length);
                            mS.Write(text);
                        }

                        return mS.ToArray();
                    }

                case Dhcp6OptionType.NtpServer:
                    using (MemoryStream mS = new MemoryStream())
                    {
                        foreach (string value in values)
                        {
                            string text = value.Trim();

                            if (text.Length == 0)
                                continue;

                            if (IsAddressText(text))
                            {
                                IPAddress address = ParseAddress(text, out bool isServer);
                                usesServerAddress |= isServer;
                                Dhcp6Message.WriteOption(mS, new Dhcp6Option(address.IsIPv6Multicast ? (ushort)2 : (ushort)1, address.GetAddressBytes()));
                            }
                            else
                            {
                                string domain = text.TrimEnd('.');
                                if (!DhcpUtilities.IsValidDomainName(domain))
                                    throw new FormatException("'" + value + "' is neither an IPv6 address nor a host name");

                                Dhcp6Message.WriteOption(mS, new Dhcp6Option(3, Dhcp6Message.EncodeDomainList([domain])));
                            }
                        }

                        if (mS.Length == 0)
                            throw new FormatException("at least one NTP server is required");

                        return mS.ToArray();
                    }

                case Dhcp6OptionType.Bytes:
                    return DhcpOptionCatalog.EncodeBytes(values);

                default:
                    {
                        bool allAddresses = values.Count > 0;

                        foreach (string value in values)
                        {
                            if (!IsAddressText(value))
                            {
                                allAddresses = false;
                                break;
                            }
                        }

                        if (allAddresses)
                            return Encode(Dhcp6OptionType.AddressList, values, out usesServerAddress);

                        return DhcpOptionCatalog.EncodeGuess(values);
                    }
            }
        }

        public static string Decode(ushort code, byte[] value)
        {
            if (value is null)
                return "";

            Dhcp6OptionType type = _byCode.TryGetValue(code, out Dhcp6OptionDefinition definition) ? definition.Type : Dhcp6OptionType.Bytes;

            try
            {
                switch (type)
                {
                    case Dhcp6OptionType.AddressList:
                        if ((value.Length % 16) == 0)
                        {
                            List<string> addresses = new List<string>();
                            for (int i = 0; i < value.Length; i += 16)
                                addresses.Add(new IPAddress(value.AsSpan(i, 16)).ToString());

                            return string.Join(", ", addresses);
                        }
                        break;

                    case Dhcp6OptionType.Domain:
                    case Dhcp6OptionType.DomainList:
                        {
                            List<string> domains = new List<string>();
                            int offset = 0;

                            while (offset < value.Length)
                            {
                                if (!Dhcp6Message.TryReadDomain(value, ref offset, out string domain))
                                    return DhcpUtilities.FormatHex(value);

                                domains.Add(domain);
                            }

                            return string.Join(", ", domains);
                        }

                    case Dhcp6OptionType.UInt8:
                        if (value.Length == 1)
                            return value[0].ToString(CultureInfo.InvariantCulture);
                        break;

                    case Dhcp6OptionType.UInt16:
                        if (value.Length == 2)
                            return BinaryPrimitives.ReadUInt16BigEndian(value).ToString(CultureInfo.InvariantCulture);
                        break;

                    case Dhcp6OptionType.UInt32:
                        if (value.Length == 4)
                            return BinaryPrimitives.ReadUInt32BigEndian(value).ToString(CultureInfo.InvariantCulture);
                        break;

                    case Dhcp6OptionType.Text:
                        if (DhcpUtilities.IsPrintable(value))
                            return Encoding.UTF8.GetString(value);
                        break;
                }
            }
            catch
            { }

            return DhcpUtilities.FormatHex(value);
        }

        #endregion
    }
}
