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
using System.Text;

namespace ZenitiumDns.Core.Dhcp
{
    public enum Dhcp6MessageType : byte
    {
        Solicit = 1,
        Advertise = 2,
        Request = 3,
        Confirm = 4,
        Renew = 5,
        Rebind = 6,
        Reply = 7,
        Release = 8,
        Decline = 9,
        Reconfigure = 10,
        InformationRequest = 11,
        RelayForward = 12,
        RelayReply = 13
    }

    public enum Dhcp6Status : ushort
    {
        Success = 0,
        UnspecFail = 1,
        NoAddrsAvail = 2,
        NoBinding = 3,
        NotOnLink = 4,
        UseMulticast = 5,
        NoPrefixAvail = 6
    }

    public static class Dhcp6OptionCode
    {
        public const ushort ClientId = 1;
        public const ushort ServerId = 2;
        public const ushort IaNa = 3;
        public const ushort IaTa = 4;
        public const ushort IaAddr = 5;
        public const ushort OptionRequest = 6;
        public const ushort Preference = 7;
        public const ushort ElapsedTime = 8;
        public const ushort RelayMessage = 9;
        public const ushort Authentication = 11;
        public const ushort Unicast = 12;
        public const ushort StatusCode = 13;
        public const ushort RapidCommit = 14;
        public const ushort UserClass = 15;
        public const ushort VendorClass = 16;
        public const ushort VendorOptions = 17;
        public const ushort InterfaceId = 18;
        public const ushort ReconfigureMessage = 19;
        public const ushort ReconfigureAccept = 20;
        public const ushort DnsServers = 23;
        public const ushort DomainList = 24;
        public const ushort IaPd = 25;
        public const ushort IaPrefix = 26;
        public const ushort InformationRefreshTime = 32;
        public const ushort ClientFqdn = 39;
        public const ushort NtpServer = 56;
        public const ushort SolMaxRt = 82;
        public const ushort InfMaxRt = 83;
    }

    public sealed class Dhcp6Option
    {
        public Dhcp6Option(ushort code, byte[] data)
        {
            Code = code;
            Data = data ?? [];
        }

        public ushort Code { get; }

        public byte[] Data { get; }
    }

    public sealed class Dhcp6IaAddress
    {
        public IPAddress Address { get; set; }

        public uint PreferredLifetime { get; set; }

        public uint ValidLifetime { get; set; }

        public List<Dhcp6Option> Options { get; } = new List<Dhcp6Option>();
    }

    public sealed class Dhcp6IaPrefix
    {
        public IPAddress Prefix { get; set; }

        public byte PrefixLength { get; set; }

        public uint PreferredLifetime { get; set; }

        public uint ValidLifetime { get; set; }

        public List<Dhcp6Option> Options { get; } = new List<Dhcp6Option>();
    }

    public sealed class Dhcp6Ia
    {
        public ushort Code { get; set; }

        public uint Iaid { get; set; }

        public uint T1 { get; set; }

        public uint T2 { get; set; }

        public List<Dhcp6IaAddress> Addresses { get; } = new List<Dhcp6IaAddress>();

        public List<Dhcp6IaPrefix> Prefixes { get; } = new List<Dhcp6IaPrefix>();

        public List<Dhcp6Option> Options { get; } = new List<Dhcp6Option>();

        public bool IsPrefixDelegation
        { get { return Code == Dhcp6OptionCode.IaPd; } }

        public static bool TryParse(Dhcp6Option option, out Dhcp6Ia ia)
        {
            ia = null;

            if ((option.Code != Dhcp6OptionCode.IaNa) && (option.Code != Dhcp6OptionCode.IaPd))
                return false;

            byte[] data = option.Data;
            if (data.Length < 12)
                return false;

            Dhcp6Ia result = new Dhcp6Ia()
            {
                Code = option.Code,
                Iaid = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(0, 4)),
                T1 = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(4, 4)),
                T2 = BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(8, 4))
            };

            if (!Dhcp6Message.TryParseOptions(data.AsSpan(12), result.Options, out _))
                return false;

            List<Dhcp6Option> rest = new List<Dhcp6Option>();

            foreach (Dhcp6Option inner in result.Options)
            {
                if ((inner.Code == Dhcp6OptionCode.IaAddr) && !result.IsPrefixDelegation)
                {
                    if (inner.Data.Length < 24)
                        return false;

                    Dhcp6IaAddress address = new Dhcp6IaAddress()
                    {
                        Address = new IPAddress(inner.Data.AsSpan(0, 16)),
                        PreferredLifetime = BinaryPrimitives.ReadUInt32BigEndian(inner.Data.AsSpan(16, 4)),
                        ValidLifetime = BinaryPrimitives.ReadUInt32BigEndian(inner.Data.AsSpan(20, 4))
                    };

                    if (!Dhcp6Message.TryParseOptions(inner.Data.AsSpan(24), address.Options, out _))
                        return false;

                    result.Addresses.Add(address);
                }
                else if ((inner.Code == Dhcp6OptionCode.IaPrefix) && result.IsPrefixDelegation)
                {
                    if (inner.Data.Length < 25)
                        return false;

                    byte prefixLength = inner.Data[8];
                    if (prefixLength > 128)
                        return false;

                    Dhcp6IaPrefix prefix = new Dhcp6IaPrefix()
                    {
                        PreferredLifetime = BinaryPrimitives.ReadUInt32BigEndian(inner.Data.AsSpan(0, 4)),
                        ValidLifetime = BinaryPrimitives.ReadUInt32BigEndian(inner.Data.AsSpan(4, 4)),
                        PrefixLength = prefixLength,
                        Prefix = new IPAddress(inner.Data.AsSpan(9, 16))
                    };

                    if (!Dhcp6Message.TryParseOptions(inner.Data.AsSpan(25), prefix.Options, out _))
                        return false;

                    result.Prefixes.Add(prefix);
                }
                else
                {
                    rest.Add(inner);
                }
            }

            result.Options.Clear();
            result.Options.AddRange(rest);

            if (result.Addresses.Count + result.Prefixes.Count > 16)
                return false;

            ia = result;
            return true;
        }

        public Dhcp6Option ToOption()
        {
            using (MemoryStream mS = new MemoryStream())
            {
                Span<byte> header = stackalloc byte[12];
                Span<byte> lifetimes = stackalloc byte[9];
                BinaryPrimitives.WriteUInt32BigEndian(header.Slice(0, 4), Iaid);
                BinaryPrimitives.WriteUInt32BigEndian(header.Slice(4, 4), T1);
                BinaryPrimitives.WriteUInt32BigEndian(header.Slice(8, 4), T2);
                mS.Write(header);

                foreach (Dhcp6IaAddress address in Addresses)
                {
                    using (MemoryStream inner = new MemoryStream())
                    {
                        inner.Write(address.Address.GetAddressBytes());
                        BinaryPrimitives.WriteUInt32BigEndian(lifetimes.Slice(0, 4), address.PreferredLifetime);
                        BinaryPrimitives.WriteUInt32BigEndian(lifetimes.Slice(4, 4), address.ValidLifetime);
                        inner.Write(lifetimes.Slice(0, 8));

                        foreach (Dhcp6Option option in address.Options)
                            Dhcp6Message.WriteOption(inner, option);

                        Dhcp6Message.WriteOption(mS, new Dhcp6Option(Dhcp6OptionCode.IaAddr, inner.ToArray()));
                    }
                }

                foreach (Dhcp6IaPrefix prefix in Prefixes)
                {
                    using (MemoryStream inner = new MemoryStream())
                    {
                        BinaryPrimitives.WriteUInt32BigEndian(lifetimes.Slice(0, 4), prefix.PreferredLifetime);
                        BinaryPrimitives.WriteUInt32BigEndian(lifetimes.Slice(4, 4), prefix.ValidLifetime);
                        lifetimes[8] = prefix.PrefixLength;
                        inner.Write(lifetimes);
                        inner.Write(prefix.Prefix.GetAddressBytes());

                        foreach (Dhcp6Option option in prefix.Options)
                            Dhcp6Message.WriteOption(inner, option);

                        Dhcp6Message.WriteOption(mS, new Dhcp6Option(Dhcp6OptionCode.IaPrefix, inner.ToArray()));
                    }
                }

                foreach (Dhcp6Option option in Options)
                    Dhcp6Message.WriteOption(mS, option);

                return new Dhcp6Option(Code, mS.ToArray());
            }
        }
    }

    public sealed class Dhcp6Message
    {
        #region variables

        public const int CLIENT_PORT = 546;
        public const int SERVER_PORT = 547;
        public const int MAX_OPTIONS = 256;
        public const int MAX_HOP_COUNT = 32;

        public static readonly IPAddress AllServersAndRelays = IPAddress.Parse("ff02::1:2");

        #endregion

        #region properties

        public Dhcp6MessageType Type { get; set; }

        public uint TransactionId { get; set; }

        public byte HopCount { get; set; }

        public IPAddress LinkAddress { get; set; } = IPAddress.IPv6Any;

        public IPAddress PeerAddress { get; set; } = IPAddress.IPv6Any;

        public List<Dhcp6Option> Options { get; } = new List<Dhcp6Option>();

        public bool IsRelay
        { get { return (Type == Dhcp6MessageType.RelayForward) || (Type == Dhcp6MessageType.RelayReply); } }

        #endregion

        #region static

        public static bool TryParse(ReadOnlySpan<byte> buffer, out Dhcp6Message message, out string error)
        {
            message = null;

            if (buffer.Length < 4)
            {
                error = "message too short";
                return false;
            }

            Dhcp6Message result = new Dhcp6Message() { Type = (Dhcp6MessageType)buffer[0] };
            ReadOnlySpan<byte> options;

            if (result.IsRelay)
            {
                if (buffer.Length < 34)
                {
                    error = "relay message too short";
                    return false;
                }

                result.HopCount = buffer[1];
                result.LinkAddress = new IPAddress(buffer.Slice(2, 16));
                result.PeerAddress = new IPAddress(buffer.Slice(18, 16));
                options = buffer.Slice(34);
            }
            else
            {
                if ((buffer[0] == 0) || (buffer[0] > (byte)Dhcp6MessageType.InformationRequest))
                {
                    error = "unknown message type " + buffer[0];
                    return false;
                }

                result.TransactionId = ((uint)buffer[1] << 16) | ((uint)buffer[2] << 8) | buffer[3];
                options = buffer.Slice(4);
            }

            if (!TryParseOptions(options, result.Options, out error))
                return false;

            message = result;
            error = null;
            return true;
        }

        public static bool TryParseOptions(ReadOnlySpan<byte> buffer, List<Dhcp6Option> options, out string error)
        {
            int offset = 0;

            while (offset < buffer.Length)
            {
                if (buffer.Length - offset < 4)
                {
                    error = "truncated option header";
                    return false;
                }

                ushort code = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(offset, 2));
                ushort length = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(offset + 2, 2));
                offset += 4;

                if (length > buffer.Length - offset)
                {
                    error = "option " + code + " exceeds the message";
                    return false;
                }

                if (options.Count >= MAX_OPTIONS)
                {
                    error = "too many options";
                    return false;
                }

                options.Add(new Dhcp6Option(code, buffer.Slice(offset, length).ToArray()));
                offset += length;
            }

            error = null;
            return true;
        }

        public static void WriteOption(Stream stream, Dhcp6Option option)
        {
            if (option.Data.Length > ushort.MaxValue)
                throw new InvalidDataException("DHCPv6 option " + option.Code + " is too large");

            Span<byte> header = stackalloc byte[4];
            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(0, 2), option.Code);
            BinaryPrimitives.WriteUInt16BigEndian(header.Slice(2, 2), (ushort)option.Data.Length);
            stream.Write(header);
            stream.Write(option.Data);
        }

        public static byte[] EncodeStatus(Dhcp6Status status, string message)
        {
            byte[] text = Encoding.UTF8.GetBytes(message ?? "");
            byte[] data = new byte[2 + text.Length];
            BinaryPrimitives.WriteUInt16BigEndian(data.AsSpan(0, 2), (ushort)status);
            text.CopyTo(data, 2);
            return data;
        }

        public static bool TryDecodeStatus(byte[] data, out Dhcp6Status status, out string message)
        {
            status = Dhcp6Status.Success;
            message = null;

            if ((data is null) || (data.Length < 2))
                return false;

            status = (Dhcp6Status)BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(0, 2));
            message = Encoding.UTF8.GetString(data, 2, data.Length - 2);
            return true;
        }

        public static byte[] EncodeAddresses(IReadOnlyList<IPAddress> addresses)
        {
            byte[] data = new byte[addresses.Count * 16];

            for (int i = 0; i < addresses.Count; i++)
                addresses[i].GetAddressBytes().CopyTo(data, i * 16);

            return data;
        }

        public static byte[] EncodeDomainList(IReadOnlyList<string> domains)
        {
            using (MemoryStream mS = new MemoryStream())
            {
                foreach (string domain in domains)
                    WriteDomain(mS, domain);

                return mS.ToArray();
            }
        }

        public static void WriteDomain(Stream stream, string domain)
        {
            string trimmed = domain.Trim().TrimEnd('.');

            if (trimmed.Length > 0)
            {
                foreach (string label in trimmed.Split('.'))
                {
                    byte[] bytes = Encoding.ASCII.GetBytes(label);

                    if ((bytes.Length == 0) || (bytes.Length > 63))
                        throw new FormatException("'" + domain + "' is not a valid domain name");

                    stream.WriteByte((byte)bytes.Length);
                    stream.Write(bytes);
                }
            }

            stream.WriteByte(0);
        }

        public static bool TryReadDomain(ReadOnlySpan<byte> data, ref int offset, out string domain)
        {
            StringBuilder sb = new StringBuilder();
            domain = null;

            while (true)
            {
                if (offset >= data.Length)
                    return false;

                byte length = data[offset++];

                if (length == 0)
                    break;

                if ((length > 63) || (offset + length > data.Length) || (sb.Length + length > 253))
                    return false;

                if (sb.Length > 0)
                    sb.Append('.');

                sb.Append(Encoding.ASCII.GetString(data.Slice(offset, length)));
                offset += length;
            }

            domain = sb.ToString();
            return true;
        }

        public static string FormatDuid(byte[] duid)
        {
            return DhcpUtilities.FormatHex(duid);
        }

        public static byte[] GetHardwareAddressFromDuid(byte[] duid)
        {
            if ((duid is null) || (duid.Length < 4))
                return null;

            ushort type = BinaryPrimitives.ReadUInt16BigEndian(duid.AsSpan(0, 2));
            ushort hardwareType = BinaryPrimitives.ReadUInt16BigEndian(duid.AsSpan(2, 2));

            if (hardwareType != 1)
                return null;

            switch (type)
            {
                case 1:
                    return duid.Length == 14 ? duid.AsSpan(8, 6).ToArray() : null;

                case 3:
                    return duid.Length == 10 ? duid.AsSpan(4, 6).ToArray() : null;

                default:
                    return null;
            }
        }

        #endregion

        #region public

        public Dhcp6Option GetOption(ushort code)
        {
            foreach (Dhcp6Option option in Options)
            {
                if (option.Code == code)
                    return option;
            }

            return null;
        }

        public byte[] GetOptionData(ushort code)
        {
            return GetOption(code)?.Data;
        }

        public bool HasOption(ushort code)
        {
            return GetOption(code) is not null;
        }

        public List<Dhcp6Option> GetOptions(ushort code)
        {
            List<Dhcp6Option> result = new List<Dhcp6Option>();

            foreach (Dhcp6Option option in Options)
            {
                if (option.Code == code)
                    result.Add(option);
            }

            return result;
        }

        public void SetOption(ushort code, byte[] data)
        {
            Options.RemoveAll(delegate (Dhcp6Option option) { return option.Code == code; });
            Options.Add(new Dhcp6Option(code, data));
        }

        public void AddOption(Dhcp6Option option)
        {
            Options.Add(option);
        }

        public List<ushort> GetRequestedOptions()
        {
            List<ushort> result = new List<ushort>();
            byte[] data = GetOptionData(Dhcp6OptionCode.OptionRequest);

            if (data is null)
                return result;

            for (int i = 0; i + 1 < data.Length; i += 2)
                result.Add(BinaryPrimitives.ReadUInt16BigEndian(data.AsSpan(i, 2)));

            return result;
        }

        public byte[] Serialize()
        {
            using (MemoryStream mS = new MemoryStream())
            {
                mS.WriteByte((byte)Type);

                if (IsRelay)
                {
                    mS.WriteByte(HopCount);
                    mS.Write(LinkAddress.GetAddressBytes());
                    mS.Write(PeerAddress.GetAddressBytes());
                }
                else
                {
                    mS.WriteByte((byte)(TransactionId >> 16));
                    mS.WriteByte((byte)(TransactionId >> 8));
                    mS.WriteByte((byte)TransactionId);
                }

                foreach (Dhcp6Option option in Options)
                    WriteOption(mS, option);

                return mS.ToArray();
            }
        }

        #endregion
    }
}
