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
using System.IO;

namespace ZenitiumDns.Core.Dns
{
    sealed class UdpSendBuffers
    {
        [ThreadStatic]
        static UdpSendBuffers t_current;

        readonly MemoryStream[] _streams = new MemoryStream[4];
        int _next;

        public static MemoryStream GetStream(int size)
        {
            UdpSendBuffers current = t_current;
            if (current is null)
            {
                current = new UdpSendBuffers();
                t_current = current;
            }

            return current.GetOrCreateStream(size);
        }

        private MemoryStream GetOrCreateStream(int size)
        {
            for (int i = 0; i < _streams.Length; i++)
            {
                MemoryStream stream = _streams[i];
                if ((stream is not null) && (stream.Capacity == size))
                {
                    stream.Position = 0;
                    return stream;
                }
            }

            MemoryStream newStream = new MemoryStream(new byte[size], 0, size, true, true);
            _streams[_next] = newStream;
            _next = (_next + 1) % _streams.Length;

            return newStream;
        }
    }
}
