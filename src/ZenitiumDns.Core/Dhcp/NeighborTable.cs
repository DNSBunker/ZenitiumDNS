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
using System.Runtime.InteropServices;
using System.Threading;

namespace ZenitiumDns.Core.Dhcp
{
    public sealed class NeighborEntry
    {
        public IPAddress Address { get; init; }

        public byte[] HardwareAddress { get; init; }

        public int InterfaceIndex { get; init; }
    }

    public sealed class NeighborTable
    {
        #region variables

        const int AF_UNSPEC = 0;
        const int AF_INET = 2;
        const int AF_INET6 = 10;
        const int AF_NETLINK = 16;
        const int SOCK_RAW = 3;
        const int SOCK_CLOEXEC = 0x80000;
        const int NETLINK_ROUTE = 0;
        const int SOL_SOCKET = 1;
        const int SO_RCVTIMEO = 20;

        const ushort RTM_NEWNEIGH = 28;
        const ushort RTM_GETNEIGH = 30;
        const ushort NLMSG_ERROR = 2;
        const ushort NLMSG_DONE = 3;
        const ushort NLM_F_REQUEST = 0x1;
        const ushort NLM_F_DUMP = 0x300;
        const ushort NDA_DST = 1;
        const ushort NDA_LLADDR = 2;
        const ushort NUD_USABLE = 0x02 | 0x04 | 0x08 | 0x10 | 0x80;

        const int MIN_REFRESH_INTERVAL_MS = 2000;
        const int MAX_ENTRIES = 65536;

        Dictionary<IPAddress, NeighborEntry> _entries = new Dictionary<IPAddress, NeighborEntry>();
        long _lastRefresh = -MIN_REFRESH_INTERVAL_MS;
        int _refreshing;
        uint _sequence;
        string _lastError;

        #endregion

        #region native

        [DllImport("libc", SetLastError = true, EntryPoint = "socket")]
        static extern int NativeSocket(int domain, int type, int protocol);

        [DllImport("libc", SetLastError = true, EntryPoint = "close")]
        static extern int NativeClose(int fd);

        [DllImport("libc", SetLastError = true, EntryPoint = "send")]
        static extern unsafe nint NativeSend(int fd, byte* buffer, nuint length, int flags);

        [DllImport("libc", SetLastError = true, EntryPoint = "recv")]
        static extern unsafe nint NativeRecv(int fd, byte* buffer, nuint length, int flags);

        [DllImport("libc", SetLastError = true, EntryPoint = "setsockopt")]
        static extern unsafe int NativeSetSockOpt(int fd, int level, int name, byte* value, int length);

        #endregion

        #region private

        private static IPAddress Normalize(IPAddress address)
        {
            if (address.IsIPv4MappedToIPv6)
                return address.MapToIPv4();

            if ((address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6) && (address.ScopeId != 0))
                return new IPAddress(address.GetAddressBytes());

            return address;
        }

        private unsafe Dictionary<IPAddress, NeighborEntry> ReadNetlink()
        {
            Dictionary<IPAddress, NeighborEntry> result = new Dictionary<IPAddress, NeighborEntry>();
            int fd = NativeSocket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);

            if (fd < 0)
                throw new InvalidOperationException("netlink socket failed with error " + Marshal.GetLastPInvokeError());

            try
            {
                byte* timeout = stackalloc byte[16];
                new Span<byte>(timeout, 16).Clear();
                BinaryPrimitives.WriteInt64LittleEndian(new Span<byte>(timeout, 8), 1);
                NativeSetSockOpt(fd, SOL_SOCKET, SO_RCVTIMEO, timeout, 16);

                uint sequence = Interlocked.Increment(ref _sequence);
                byte* request = stackalloc byte[28];
                Span<byte> req = new Span<byte>(request, 28);
                req.Clear();
                BinaryPrimitives.WriteUInt32LittleEndian(req.Slice(0, 4), 28);
                BinaryPrimitives.WriteUInt16LittleEndian(req.Slice(4, 2), RTM_GETNEIGH);
                BinaryPrimitives.WriteUInt16LittleEndian(req.Slice(6, 2), NLM_F_REQUEST | NLM_F_DUMP);
                BinaryPrimitives.WriteUInt32LittleEndian(req.Slice(8, 4), sequence);
                req[16] = AF_UNSPEC;

                if (NativeSend(fd, request, 28, 0) != 28)
                    throw new InvalidOperationException("netlink send failed with error " + Marshal.GetLastPInvokeError());

                byte[] buffer = new byte[65536];

                fixed (byte* bufferPtr = buffer)
                {
                    while (true)
                    {
                        nint received = NativeRecv(fd, bufferPtr, (nuint)buffer.Length, 0);

                        if (received <= 0)
                            return result;

                        int offset = 0;

                        while (offset + 16 <= received)
                        {
                            uint length = BinaryPrimitives.ReadUInt32LittleEndian(buffer.AsSpan(offset, 4));
                            ushort type = BinaryPrimitives.ReadUInt16LittleEndian(buffer.AsSpan(offset + 4, 2));

                            if ((length < 16) || (offset + length > received))
                                return result;

                            if ((type == NLMSG_DONE) || (type == NLMSG_ERROR))
                                return result;

                            if ((type == RTM_NEWNEIGH) && (length >= 28))
                                ParseNeighbor(buffer.AsSpan(offset + 16, (int)length - 16), result);

                            offset += (int)((length + 3) & ~3u);
                        }

                        if (result.Count >= MAX_ENTRIES)
                            return result;
                    }
                }
            }
            finally
            {
                NativeClose(fd);
            }
        }

        private static void ParseNeighbor(ReadOnlySpan<byte> data, Dictionary<IPAddress, NeighborEntry> result)
        {
            byte family = data[0];
            int ifindex = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(4, 4));
            ushort state = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(8, 2));

            if ((state & NUD_USABLE) == 0)
                return;

            IPAddress address = null;
            byte[] hardwareAddress = null;
            int offset = 12;

            while (offset + 4 <= data.Length)
            {
                ushort length = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset, 2));
                ushort type = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(offset + 2, 2));

                if ((length < 4) || (offset + length > data.Length))
                    break;

                ReadOnlySpan<byte> value = data.Slice(offset + 4, length - 4);

                if ((type == NDA_DST) && (((family == AF_INET) && (value.Length == 4)) || ((family == AF_INET6) && (value.Length == 16))))
                    address = new IPAddress(value);
                else if ((type == NDA_LLADDR) && (value.Length == 6))
                    hardwareAddress = value.ToArray();

                offset += (length + 3) & ~3;
            }

            if ((address is null) || (hardwareAddress is null) || IsZero(hardwareAddress) || (result.Count >= MAX_ENTRIES))
                return;

            result[address] = new NeighborEntry() { Address = address, HardwareAddress = hardwareAddress, InterfaceIndex = ifindex };
        }

        private static bool IsZero(byte[] value)
        {
            foreach (byte b in value)
            {
                if (b != 0)
                    return false;
            }

            return true;
        }

        #endregion

        #region public

        public void Refresh()
        {
            if (!OperatingSystem.IsLinux())
                return;

            if (Interlocked.Exchange(ref _refreshing, 1) == 1)
                return;

            try
            {
                _entries = ReadNetlink();
                _lastError = null;
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
            }
            finally
            {
                Volatile.Write(ref _lastRefresh, Environment.TickCount64);
                Volatile.Write(ref _refreshing, 0);
            }
        }

        public bool TryGetHardwareAddress(IPAddress address, out byte[] hardwareAddress)
        {
            hardwareAddress = null;

            if (address is null)
                return false;

            address = Normalize(address);

            if (_entries.TryGetValue(address, out NeighborEntry entry))
            {
                hardwareAddress = entry.HardwareAddress;
                return true;
            }

            if (Environment.TickCount64 - Volatile.Read(ref _lastRefresh) < MIN_REFRESH_INTERVAL_MS)
                return false;

            Refresh();

            if (_entries.TryGetValue(address, out entry))
            {
                hardwareAddress = entry.HardwareAddress;
                return true;
            }

            return false;
        }

        public List<NeighborEntry> GetEntries()
        {
            if (Environment.TickCount64 - Volatile.Read(ref _lastRefresh) >= MIN_REFRESH_INTERVAL_MS)
                Refresh();

            return new List<NeighborEntry>(_entries.Values);
        }

        public string LastError
        { get { return _lastError; } }

        #endregion
    }
}
