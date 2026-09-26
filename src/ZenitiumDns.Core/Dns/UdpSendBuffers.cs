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
