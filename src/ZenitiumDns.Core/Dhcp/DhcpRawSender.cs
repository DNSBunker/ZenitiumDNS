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
using System.Net;
using System.Runtime.InteropServices;

namespace ZenitiumDns.Core.Dhcp
{
    sealed class DhcpRawSender : IDisposable
    {
        #region variables

        const int AF_PACKET = 17;
        const int SOCK_DGRAM = 2;
        const int SOCK_CLOEXEC = 0x80000;
        const ushort ETH_P_IP = 0x0800;

        readonly int _fd;
        readonly object _lock = new object();
        ushort _identification;
        bool _disposed;

        #endregion

        #region native

        [StructLayout(LayoutKind.Sequential)]
        unsafe struct SockAddrLl
        {
            public ushort Family;
            public ushort Protocol;
            public int IfIndex;
            public ushort HaType;
            public byte PktType;
            public byte HaLen;
            public fixed byte Addr[8];
        }

        [DllImport("libc", SetLastError = true, EntryPoint = "socket")]
        static extern int NativeSocket(int domain, int type, int protocol);

        [DllImport("libc", SetLastError = true, EntryPoint = "close")]
        static extern int NativeClose(int fd);

        [DllImport("libc", SetLastError = true, EntryPoint = "sendto")]
        static extern unsafe nint NativeSendTo(int fd, byte* buffer, nuint length, int flags, SockAddrLl* address, int addressLength);

        #endregion

        #region constructor

        private DhcpRawSender(int fd)
        {
            _fd = fd;
            _identification = (ushort)Random.Shared.Next(0, ushort.MaxValue);
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            lock (_lock)
            {
                if (_disposed)
                    return;

                _disposed = true;
                NativeClose(_fd);
            }
        }

        #endregion

        #region static

        public static DhcpRawSender TryCreate(out string error)
        {
            error = null;

            if (!OperatingSystem.IsLinux())
            {
                error = "raw sending is only available on Linux";
                return null;
            }

            try
            {
                int fd = NativeSocket(AF_PACKET, SOCK_DGRAM | SOCK_CLOEXEC, BinaryPrimitives.ReverseEndianness((short)ETH_P_IP));

                if (fd < 0)
                {
                    error = "socket(AF_PACKET) failed with errno " + Marshal.GetLastPInvokeError() + " (CAP_NET_RAW missing?)";
                    return null;
                }

                return new DhcpRawSender(fd);
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return null;
            }
        }

        private static ushort Checksum(ReadOnlySpan<byte> data, uint initial)
        {
            uint sum = initial;
            int i = 0;

            for (; i + 1 < data.Length; i += 2)
                sum += (uint)((data[i] << 8) | data[i + 1]);

            if (i < data.Length)
                sum += (uint)(data[i] << 8);

            while ((sum >> 16) != 0)
                sum = (sum & 0xFFFF) + (sum >> 16);

            return (ushort)~sum;
        }

        #endregion

        #region public

        public unsafe bool Send(int interfaceIndex, byte[] destinationMac, IPAddress source, IPAddress destination, int sourcePort, int destinationPort, byte[] payload)
        {
            if ((destinationMac is null) || (destinationMac.Length != 6))
                return false;

            int udpLength = 8 + payload.Length;
            int totalLength = 20 + udpLength;
            byte[] packet = new byte[totalLength];
            Span<byte> span = packet;

            byte[] src = source.GetAddressBytes();
            byte[] dst = destination.GetAddressBytes();

            span[0] = 0x45;
            span[1] = 0x10;
            BinaryPrimitives.WriteUInt16BigEndian(span.Slice(2), (ushort)totalLength);

            lock (_lock)
            {
                BinaryPrimitives.WriteUInt16BigEndian(span.Slice(4), _identification++);
            }

            span[8] = 64;
            span[9] = 17;
            src.CopyTo(span.Slice(12));
            dst.CopyTo(span.Slice(16));
            BinaryPrimitives.WriteUInt16BigEndian(span.Slice(10), Checksum(span.Slice(0, 20), 0));

            Span<byte> udp = span.Slice(20);
            BinaryPrimitives.WriteUInt16BigEndian(udp, (ushort)sourcePort);
            BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(2), (ushort)destinationPort);
            BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(4), (ushort)udpLength);
            payload.CopyTo(udp.Slice(8));

            uint pseudo = 0;
            pseudo += (uint)((src[0] << 8) | src[1]) + (uint)((src[2] << 8) | src[3]);
            pseudo += (uint)((dst[0] << 8) | dst[1]) + (uint)((dst[2] << 8) | dst[3]);
            pseudo += 17;
            pseudo += (uint)udpLength;

            ushort udpChecksum = Checksum(udp.Slice(0, udpLength), pseudo);
            if (udpChecksum == 0)
                udpChecksum = 0xFFFF;

            BinaryPrimitives.WriteUInt16BigEndian(udp.Slice(6), udpChecksum);

            SockAddrLl address = new SockAddrLl()
            {
                Family = AF_PACKET,
                Protocol = BinaryPrimitives.ReverseEndianness(ETH_P_IP),
                IfIndex = interfaceIndex,
                HaLen = 6
            };

            for (int i = 0; i < 6; i++)
                address.Addr[i] = destinationMac[i];

            lock (_lock)
            {
                if (_disposed)
                    return false;

                fixed (byte* buffer = packet)
                {
                    nint sent = NativeSendTo(_fd, buffer, (nuint)packet.Length, 0, &address, sizeof(SockAddrLl));
                    return sent == packet.Length;
                }
            }
        }

        #endregion
    }
}
