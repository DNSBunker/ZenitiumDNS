using System;
using System.Buffers.Binary;
using System.Net;
using System.Numerics;

namespace ZenitiumDns.Core.Dns
{
    sealed class UniqueAddressCounter
    {
        const int PRECISION = 14;
        const int REGISTER_COUNT = 1 << PRECISION;

        readonly byte[] _registers = new byte[REGISTER_COUNT];

        public void Add(IPAddress address)
        {
            Span<byte> bytes = stackalloc byte[16];

            if (!address.TryWriteBytes(bytes, out int length))
                return;

            ulong hash;

            if (length == 4)
            {
                hash = Mix(BinaryPrimitives.ReadUInt32BigEndian(bytes) | 0x0400000000000000UL);
            }
            else
            {
                ulong high = BinaryPrimitives.ReadUInt64BigEndian(bytes);
                ulong low = BinaryPrimitives.ReadUInt64BigEndian(bytes.Slice(8));
                hash = Mix(high ^ Mix(low ^ 0x0600000000000000UL));
            }

            int index = (int)(hash >> (64 - PRECISION));
            ulong remaining = (hash << PRECISION) | (1UL << (PRECISION - 1));
            byte rank = (byte)(BitOperations.LeadingZeroCount(remaining) + 1);

            if (_registers[index] < rank)
                _registers[index] = rank;
        }

        public long Estimate()
        {
            double sum = 0;
            int zeros = 0;

            for (int i = 0; i < REGISTER_COUNT; i++)
            {
                byte register = _registers[i];
                sum += 1.0 / (1UL << register);

                if (register == 0)
                    zeros++;
            }

            double alpha = 0.7213 / (1 + (1.079 / REGISTER_COUNT));
            double estimate = alpha * REGISTER_COUNT * REGISTER_COUNT / sum;

            if ((estimate <= 2.5 * REGISTER_COUNT) && (zeros > 0))
                estimate = REGISTER_COUNT * Math.Log((double)REGISTER_COUNT / zeros);

            return (long)Math.Round(estimate);
        }

        private static ulong Mix(ulong value)
        {
            value ^= value >> 33;
            value *= 0xff51afd7ed558ccdUL;
            value ^= value >> 33;
            value *= 0xc4ceb9fe1a85ec53UL;
            value ^= value >> 33;

            return value;
        }
    }
}
