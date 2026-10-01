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

namespace ZenitiumDns.Core.Dhcp
{
    public enum DhcpMessageType : byte
    {
        None = 0,
        Discover = 1,
        Offer = 2,
        Request = 3,
        Decline = 4,
        Ack = 5,
        Nak = 6,
        Release = 7,
        Inform = 8
    }

    public sealed class DhcpMessage
    {
        #region variables

        public const int HEADER_SIZE = 236;
        public const int MIN_PACKET_SIZE = 300;
        public const int DEFAULT_MAX_MESSAGE_SIZE = 576;
        public const int MAX_PACKET_SIZE = 1472;
        public const byte OP_BOOTREQUEST = 1;
        public const byte OP_BOOTREPLY = 2;
        public const ushort FLAG_BROADCAST = 0x8000;

        const int SNAME_OFFSET = 44;
        const int SNAME_SIZE = 64;
        const int FILE_OFFSET = 108;
        const int FILE_SIZE = 128;
        const int IP_UDP_HEADER_SIZE = 28;

        static readonly byte[] _magicCookie = [99, 130, 83, 99];

        readonly List<DhcpOption> _options = new List<DhcpOption>();

        #endregion

        #region constructor

        public DhcpMessage()
        {
            ClientHardwareAddress = [];
            ClientAddress = IPAddress.Any;
            YourAddress = IPAddress.Any;
            ServerAddress = IPAddress.Any;
            RelayAddress = IPAddress.Any;
            ServerHostName = "";
            BootFileName = "";
            HasMagicCookie = true;
        }

        #endregion

        #region static

        public static bool TryParse(ReadOnlySpan<byte> buffer, out DhcpMessage message, out string error)
        {
            message = null;
            error = null;

            if (buffer.Length < HEADER_SIZE)
            {
                error = "packet shorter than the BOOTP header";
                return false;
            }

            DhcpMessage m = new DhcpMessage();
            m.Op = buffer[0];
            m.HardwareType = buffer[1];
            m.HardwareAddressLength = buffer[2];
            m.Hops = buffer[3];
            m.TransactionId = BinaryPrimitives.ReadUInt32BigEndian(buffer.Slice(4));
            m.Seconds = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(8));
            m.Flags = BinaryPrimitives.ReadUInt16BigEndian(buffer.Slice(10));
            m.ClientAddress = new IPAddress(buffer.Slice(12, 4));
            m.YourAddress = new IPAddress(buffer.Slice(16, 4));
            m.ServerAddress = new IPAddress(buffer.Slice(20, 4));
            m.RelayAddress = new IPAddress(buffer.Slice(24, 4));

            if (m.HardwareAddressLength > 16)
            {
                error = "invalid hardware address length " + m.HardwareAddressLength;
                return false;
            }

            m.ClientHardwareAddress = buffer.Slice(28, m.HardwareAddressLength).ToArray();

            ReadOnlySpan<byte> sname = buffer.Slice(SNAME_OFFSET, SNAME_SIZE);
            ReadOnlySpan<byte> file = buffer.Slice(FILE_OFFSET, FILE_SIZE);

            if ((buffer.Length < HEADER_SIZE + 4) || !buffer.Slice(HEADER_SIZE, 4).SequenceEqual(_magicCookie))
            {
                m.HasMagicCookie = false;
                m.ServerHostName = ReadCString(sname);
                m.BootFileName = ReadCString(file);
                message = m;
                return true;
            }

            Dictionary<byte, List<byte[]>> parts = new Dictionary<byte, List<byte[]>>();
            List<byte> order = new List<byte>();

            if (!ReadOptions(buffer.Slice(HEADER_SIZE + 4), parts, order, out error))
                return false;

            byte overload = 0;

            if (parts.TryGetValue((byte)DhcpOptionCode.OptionOverload, out List<byte[]> overloadParts) && (overloadParts.Count > 0) && (overloadParts[0].Length == 1))
                overload = overloadParts[0][0];

            if ((overload & 1) != 0)
            {
                if (!ReadOptions(file, parts, order, out error))
                    return false;
            }
            else
            {
                m.BootFileName = ReadCString(file);
            }

            if ((overload & 2) != 0)
            {
                if (!ReadOptions(sname, parts, order, out error))
                    return false;
            }
            else
            {
                m.ServerHostName = ReadCString(sname);
            }

            foreach (byte code in order)
            {
                List<byte[]> values = parts[code];
                byte[] value;

                if (values.Count == 1)
                {
                    value = values[0];
                }
                else
                {
                    int length = 0;
                    foreach (byte[] part in values)
                        length += part.Length;

                    value = new byte[length];
                    int offset = 0;

                    foreach (byte[] part in values)
                    {
                        Buffer.BlockCopy(part, 0, value, offset, part.Length);
                        offset += part.Length;
                    }
                }

                if (code != (byte)DhcpOptionCode.OptionOverload)
                    m._options.Add(new DhcpOption(code, value));
            }

            message = m;
            return true;
        }

        private static bool ReadOptions(ReadOnlySpan<byte> data, Dictionary<byte, List<byte[]>> parts, List<byte> order, out string error)
        {
            error = null;
            int i = 0;

            while (i < data.Length)
            {
                byte code = data[i++];

                if (code == 0)
                    continue;

                if (code == 255)
                    return true;

                if (i >= data.Length)
                {
                    error = "option " + code + " has no length";
                    return false;
                }

                int length = data[i++];

                if (i + length > data.Length)
                {
                    error = "option " + code + " is longer than the packet";
                    return false;
                }

                if (!parts.TryGetValue(code, out List<byte[]> list))
                {
                    list = new List<byte[]>(1);
                    parts.Add(code, list);
                    order.Add(code);
                }

                list.Add(data.Slice(i, length).ToArray());
                i += length;
            }

            return true;
        }

        private static string ReadCString(ReadOnlySpan<byte> data)
        {
            int end = data.IndexOf((byte)0);
            if (end < 0)
                end = data.Length;

            if (end == 0)
                return "";

            return Encoding.ASCII.GetString(data.Slice(0, end));
        }

        private static void WriteCString(Span<byte> target, string value)
        {
            target.Clear();

            if (string.IsNullOrEmpty(value))
                return;

            int count = Encoding.ASCII.GetBytes(value.AsSpan(0, Math.Min(value.Length, target.Length - 1)), target);
            if (count < target.Length)
                target[count] = 0;
        }

        private static int GetEncodedSize(DhcpOption option)
        {
            if (option.Value.Length == 0)
                return 2;

            int chunks = (option.Value.Length + 254) / 255;
            return option.Value.Length + (chunks * 2);
        }

        private static int WriteOption(Span<byte> target, DhcpOption option)
        {
            int offset = 0;

            if (option.Value.Length == 0)
            {
                target[offset++] = option.Code;
                target[offset++] = 0;
                return offset;
            }

            int remaining = option.Value.Length;
            int source = 0;

            while (remaining > 0)
            {
                int chunk = Math.Min(255, remaining);
                target[offset++] = option.Code;
                target[offset++] = (byte)chunk;
                option.Value.AsSpan(source, chunk).CopyTo(target.Slice(offset));
                offset += chunk;
                source += chunk;
                remaining -= chunk;
            }

            return offset;
        }

        private static void WriteAddress(Span<byte> target, IPAddress address)
        {
            if ((address is null) || !address.TryWriteBytes(target, out int written) || (written != 4))
                target.Slice(0, 4).Clear();
        }

        #endregion

        #region public

        public DhcpOption GetOption(DhcpOptionCode code)
        {
            return GetOption((byte)code);
        }

        public DhcpOption GetOption(byte code)
        {
            foreach (DhcpOption option in _options)
            {
                if (option.Code == code)
                    return option;
            }

            return null;
        }

        public byte[] GetOptionValue(DhcpOptionCode code)
        {
            return GetOption((byte)code)?.Value;
        }

        public bool HasOption(DhcpOptionCode code)
        {
            return GetOption((byte)code) is not null;
        }

        public void SetOption(DhcpOptionCode code, byte[] value)
        {
            SetOption((byte)code, value);
        }

        public void SetOption(byte code, byte[] value)
        {
            for (int i = 0; i < _options.Count; i++)
            {
                if (_options[i].Code == code)
                {
                    _options[i] = new DhcpOption(code, value);
                    return;
                }
            }

            _options.Add(new DhcpOption(code, value));
        }

        public void RemoveOption(byte code)
        {
            _options.RemoveAll(delegate (DhcpOption option) { return option.Code == code; });
        }

        public IPAddress GetAddressOption(DhcpOptionCode code)
        {
            byte[] value = GetOptionValue(code);
            if ((value is null) || (value.Length != 4))
                return null;

            return new IPAddress(value);
        }

        public string GetStringOption(DhcpOptionCode code)
        {
            byte[] value = GetOptionValue(code);
            if ((value is null) || (value.Length == 0))
                return null;

            int end = Array.IndexOf(value, (byte)0);
            if (end < 0)
                end = value.Length;

            return Encoding.UTF8.GetString(value, 0, end);
        }

        public int GetMaxMessageSize()
        {
            byte[] value = GetOptionValue(DhcpOptionCode.MaxMessageSize);
            if ((value is null) || (value.Length != 2))
                return DEFAULT_MAX_MESSAGE_SIZE;

            int size = BinaryPrimitives.ReadUInt16BigEndian(value);
            if (size < DEFAULT_MAX_MESSAGE_SIZE)
                return DEFAULT_MAX_MESSAGE_SIZE;

            return Math.Min(size, MAX_PACKET_SIZE + IP_UDP_HEADER_SIZE);
        }

        private sealed class Area
        {
            public Area(int capacity)
            {
                Remaining = capacity;
            }

            public int Remaining;
            public readonly List<(byte Code, byte[] Value, int Offset, int Length)> Entries = new List<(byte, byte[], int, int)>();
        }

        private static bool TryPlace(List<Area> areas, DhcpOption option, bool commit)
        {
            int length = option.Value.Length;

            if (length <= 255)
            {
                foreach (Area area in areas)
                {
                    if (area.Remaining >= length + 2)
                    {
                        if (commit)
                        {
                            area.Entries.Add((option.Code, option.Value, 0, length));
                            area.Remaining -= length + 2;
                        }

                        return true;
                    }
                }

                return false;
            }

            int[] remaining = new int[areas.Count];
            for (int i = 0; i < areas.Count; i++)
                remaining[i] = areas[i].Remaining;

            List<(int Area, int Offset, int Length)> placements = new List<(int, int, int)>();
            int areaIndex = 0;
            int offset = 0;

            while (offset < length)
            {
                while ((areaIndex < areas.Count) && (remaining[areaIndex] < 3))
                    areaIndex++;

                if (areaIndex >= areas.Count)
                    return false;

                int chunk = Math.Min(Math.Min(255, length - offset), remaining[areaIndex] - 2);
                placements.Add((areaIndex, offset, chunk));
                remaining[areaIndex] -= chunk + 2;
                offset += chunk;
            }

            if (commit)
            {
                foreach ((int area, int chunkOffset, int chunkLength) in placements)
                    areas[area].Entries.Add((option.Code, option.Value, chunkOffset, chunkLength));

                for (int i = 0; i < areas.Count; i++)
                    areas[i].Remaining = remaining[i];
            }

            return true;
        }

        private static int WriteEntries(Span<byte> target, Area area)
        {
            int offset = 0;

            foreach ((byte code, byte[] value, int valueOffset, int length) in area.Entries)
            {
                target[offset++] = code;
                target[offset++] = (byte)length;
                value.AsSpan(valueOffset, length).CopyTo(target.Slice(offset));
                offset += length;
            }

            return offset;
        }

        public byte[] Serialize(int maxMessageSize = DEFAULT_MAX_MESSAGE_SIZE)
        {
            int limit = Math.Max(DEFAULT_MAX_MESSAGE_SIZE, maxMessageSize) - IP_UDP_HEADER_SIZE;
            int mainCapacity = limit - HEADER_SIZE - 4 - 1;

            DhcpOption messageType = GetOption(DhcpOptionCode.MessageType);
            List<DhcpOption> others = new List<DhcpOption>(_options.Count);

            int total = 0;

            foreach (DhcpOption option in _options)
            {
                if (option.Code == (byte)DhcpOptionCode.MessageType)
                    continue;

                others.Add(option);
                total += GetEncodedSize(option);
            }

            if (messageType is not null)
                mainCapacity -= GetEncodedSize(messageType);

            bool canUseFile = AllowOverload && string.IsNullOrEmpty(BootFileName);
            bool canUseSname = AllowOverload && string.IsNullOrEmpty(ServerHostName);
            bool overload = (total > mainCapacity) && (canUseFile || canUseSname) && HasMagicCookie;

            List<Area> areas = new List<Area>(3);
            Area main = new Area(overload ? mainCapacity - 3 : mainCapacity);
            Area file = null;
            Area sname = null;
            areas.Add(main);

            if (overload)
            {
                if (canUseFile)
                {
                    file = new Area(FILE_SIZE - 1);
                    areas.Add(file);
                }

                if (canUseSname)
                {
                    sname = new Area(SNAME_SIZE - 1);
                    areas.Add(sname);
                }
            }

            foreach (DhcpOption option in others)
            {
                if (TryPlace(areas, option, false))
                    TryPlace(areas, option, true);
            }

            byte overloadValue = (byte)(((file is not null) && (file.Entries.Count > 0) ? 1 : 0) | ((sname is not null) && (sname.Entries.Count > 0) ? 2 : 0));

            int length = HEADER_SIZE + 4 + 1;

            if (messageType is not null)
                length += GetEncodedSize(messageType);

            if (overloadValue != 0)
                length += 3;

            foreach ((byte _, byte[] _, int _, int entryLength) in main.Entries)
                length += entryLength + 2;

            byte[] buffer = new byte[Math.Max(MIN_PACKET_SIZE, length)];
            Span<byte> span = buffer;

            span[0] = Op;
            span[1] = HardwareType;
            span[2] = HardwareAddressLength;
            span[3] = Hops;
            BinaryPrimitives.WriteUInt32BigEndian(span.Slice(4), TransactionId);
            BinaryPrimitives.WriteUInt16BigEndian(span.Slice(8), Seconds);
            BinaryPrimitives.WriteUInt16BigEndian(span.Slice(10), Flags);
            WriteAddress(span.Slice(12), ClientAddress);
            WriteAddress(span.Slice(16), YourAddress);
            WriteAddress(span.Slice(20), ServerAddress);
            WriteAddress(span.Slice(24), RelayAddress);
            ClientHardwareAddress.AsSpan(0, Math.Min(16, ClientHardwareAddress.Length)).CopyTo(span.Slice(28));

            if ((overloadValue & 2) != 0)
            {
                Span<byte> target = span.Slice(SNAME_OFFSET, SNAME_SIZE);
                target[WriteEntries(target, sname)] = 255;
            }
            else
            {
                WriteCString(span.Slice(SNAME_OFFSET, SNAME_SIZE), ServerHostName);
            }

            if ((overloadValue & 1) != 0)
            {
                Span<byte> target = span.Slice(FILE_OFFSET, FILE_SIZE);
                target[WriteEntries(target, file)] = 255;
            }
            else
            {
                WriteCString(span.Slice(FILE_OFFSET, FILE_SIZE), BootFileName);
            }

            if (!HasMagicCookie)
                return buffer;

            _magicCookie.CopyTo(span.Slice(HEADER_SIZE));

            int position = HEADER_SIZE + 4;

            if (messageType is not null)
                position += WriteOption(span.Slice(position), messageType);

            if (overloadValue != 0)
            {
                span[position++] = (byte)DhcpOptionCode.OptionOverload;
                span[position++] = 1;
                span[position++] = overloadValue;
            }

            position += WriteEntries(span.Slice(position), main);
            span[position] = 255;

            return buffer;
        }

        public string GetClientHardwareAddressString()
        {
            return DhcpUtilities.FormatHardwareAddress(ClientHardwareAddress);
        }

        #endregion

        #region properties

        public byte Op { get; set; }

        public byte HardwareType { get; set; }

        public byte HardwareAddressLength { get; set; }

        public byte Hops { get; set; }

        public uint TransactionId { get; set; }

        public ushort Seconds { get; set; }

        public ushort Flags { get; set; }

        public IPAddress ClientAddress { get; set; }

        public IPAddress YourAddress { get; set; }

        public IPAddress ServerAddress { get; set; }

        public IPAddress RelayAddress { get; set; }

        public byte[] ClientHardwareAddress { get; set; }

        public string ServerHostName { get; set; }

        public string BootFileName { get; set; }

        public bool HasMagicCookie { get; set; }

        public bool AllowOverload { get; set; } = true;

        public bool IsBroadcast
        { get { return (Flags & FLAG_BROADCAST) != 0; } }

        public DhcpMessageType MessageType
        {
            get
            {
                byte[] value = GetOptionValue(DhcpOptionCode.MessageType);
                if ((value is null) || (value.Length != 1))
                    return DhcpMessageType.None;

                return (DhcpMessageType)value[0];
            }
        }

        public IReadOnlyList<DhcpOption> Options
        { get { return _options; } }

        #endregion
    }

    public sealed class DhcpOption
    {
        public DhcpOption(byte code, byte[] value)
        {
            Code = code;
            Value = value ?? [];
        }

        public byte Code { get; }

        public byte[] Value { get; }
    }
}
