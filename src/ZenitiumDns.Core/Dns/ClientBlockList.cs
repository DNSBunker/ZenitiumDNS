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
using System.Net.Sockets;

namespace ZenitiumDns.Core.Dns
{
    sealed class ClientBlockList
    {
        #region variables

        public static readonly ClientBlockList Empty = new ClientBlockList([], [], [], []);

        readonly uint[] _ipv4Starts;
        readonly uint[] _ipv4Ends;
        readonly UInt128[] _ipv6Starts;
        readonly UInt128[] _ipv6Ends;

        #endregion

        #region constructor

        ClientBlockList(uint[] ipv4Starts, uint[] ipv4Ends, UInt128[] ipv6Starts, UInt128[] ipv6Ends)
        {
            _ipv4Starts = ipv4Starts;
            _ipv4Ends = ipv4Ends;
            _ipv6Starts = ipv6Starts;
            _ipv6Ends = ipv6Ends;
        }

        #endregion

        #region private

        private static bool Search<T>(T[] starts, T[] ends, T value) where T : IComparable<T>
        {
            if (starts.Length == 0)
                return false;

            int i = Array.BinarySearch(starts, value);
            if (i >= 0)
                return true;

            i = ~i - 1;

            return (i >= 0) && (value.CompareTo(ends[i]) <= 0);
        }

        private static void Merge<T>(List<(T, T)> ranges, out T[] starts, out T[] ends) where T : IComparable<T>, IEquatable<T>
        {
            ranges.Sort(delegate ((T, T) x, (T, T) y) { return x.Item1.CompareTo(y.Item1); });

            List<T> mergedStarts = new List<T>(ranges.Count);
            List<T> mergedEnds = new List<T>(ranges.Count);

            foreach ((T start, T end) in ranges)
            {
                int last = mergedEnds.Count - 1;

                if ((last >= 0) && (start.CompareTo(mergedEnds[last]) <= 0))
                {
                    if (end.CompareTo(mergedEnds[last]) > 0)
                        mergedEnds[last] = end;
                }
                else
                {
                    mergedStarts.Add(start);
                    mergedEnds.Add(end);
                }
            }

            starts = mergedStarts.ToArray();
            ends = mergedEnds.ToArray();
        }

        #endregion

        #region public

        public static bool TryParseEntry(string line, out IPAddress address, out int prefixLength)
        {
            address = null;
            prefixLength = 0;

            ReadOnlySpan<char> entry = line.AsSpan().Trim();
            if ((entry.Length == 0) || (entry[0] == '#') || (entry[0] == ';'))
                return false;

            int end = entry.IndexOfAny(" \t;,");
            if (end > 0)
                entry = entry.Slice(0, end);

            int slash = entry.IndexOf('/');
            ReadOnlySpan<char> ip = slash < 0 ? entry : entry.Slice(0, slash);

            if (!IPAddress.TryParse(ip, out address))
                return false;

            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            int maxPrefixLength = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;

            if (slash < 0)
            {
                prefixLength = maxPrefixLength;
                return true;
            }

            return int.TryParse(entry.Slice(slash + 1), out prefixLength) && (prefixLength >= 0) && (prefixLength <= maxPrefixLength);
        }

        public static ClientBlockList Build(IEnumerable<(IPAddress, int)> entries)
        {
            List<(uint, uint)> ipv4Ranges = new List<(uint, uint)>();
            List<(UInt128, UInt128)> ipv6Ranges = new List<(UInt128, UInt128)>();
            Span<byte> bytes = stackalloc byte[16];

            foreach ((IPAddress address, int prefixLength) in entries)
            {
                if (!address.TryWriteBytes(bytes, out int length))
                    continue;

                if (length == 4)
                {
                    uint value = BinaryPrimitives.ReadUInt32BigEndian(bytes);
                    uint mask = prefixLength == 0 ? 0 : uint.MaxValue << (32 - prefixLength);
                    uint start = value & mask;

                    ipv4Ranges.Add((start, start | ~mask));
                }
                else
                {
                    UInt128 value = new UInt128(BinaryPrimitives.ReadUInt64BigEndian(bytes), BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(8)));
                    UInt128 mask = prefixLength == 0 ? UInt128.Zero : UInt128.MaxValue << (128 - prefixLength);
                    UInt128 start = value & mask;

                    ipv6Ranges.Add((start, start | ~mask));
                }
            }

            Merge(ipv4Ranges, out uint[] ipv4Starts, out uint[] ipv4Ends);
            Merge(ipv6Ranges, out UInt128[] ipv6Starts, out UInt128[] ipv6Ends);

            return new ClientBlockList(ipv4Starts, ipv4Ends, ipv6Starts, ipv6Ends);
        }

        public bool Contains(IPAddress address)
        {
            Span<byte> bytes = stackalloc byte[16];

            if (!address.TryWriteBytes(bytes, out int length))
                return false;

            if (length == 4)
                return Search(_ipv4Starts, _ipv4Ends, BinaryPrimitives.ReadUInt32BigEndian(bytes));

            if (address.IsIPv4MappedToIPv6)
                return Search(_ipv4Starts, _ipv4Ends, BinaryPrimitives.ReadUInt32BigEndian(bytes.Slice(12)));

            return Search(_ipv6Starts, _ipv6Ends, new UInt128(BinaryPrimitives.ReadUInt64BigEndian(bytes), BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(8))));
        }

        #endregion

        #region properties

        public int Count
        { get { return _ipv4Starts.Length + _ipv6Starts.Length; } }

        #endregion
    }
}
