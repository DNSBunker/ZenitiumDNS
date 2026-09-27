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
using System.IO;
using System.Net;
using System.Numerics;

namespace ZenitiumDns.Core.Dns
{
    sealed class UniqueAddressCounter
    {
        #region variables

        const int MIN_PRECISION = 4;
        const int MAX_PRECISION = 16;

        readonly int _precision;
        readonly byte[] _registers;

        #endregion

        #region constructor

        public UniqueAddressCounter(int precision = 14)
        {
            if ((precision < MIN_PRECISION) || (precision > MAX_PRECISION))
                throw new ArgumentOutOfRangeException(nameof(precision));

            _precision = precision;
            _registers = new byte[1 << precision];
        }

        public UniqueAddressCounter(BinaryReader bR)
        {
            _precision = bR.ReadByte();

            if ((_precision < MIN_PRECISION) || (_precision > MAX_PRECISION))
                throw new InvalidDataException("Unique address counter precision is invalid.");

            _registers = bR.ReadBytes(1 << _precision);

            if (_registers.Length != (1 << _precision))
                throw new EndOfStreamException();
        }

        #endregion

        #region private

        private static ulong Mix(ulong value)
        {
            value ^= value >> 33;
            value *= 0xff51afd7ed558ccdUL;
            value ^= value >> 33;
            value *= 0xc4ceb9fe1a85ec53UL;
            value ^= value >> 33;

            return value;
        }

        #endregion

        #region public

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

            int index = (int)(hash >> (64 - _precision));
            ulong remaining = (hash << _precision) | (1UL << (_precision - 1));
            byte rank = (byte)(BitOperations.LeadingZeroCount(remaining) + 1);

            if (_registers[index] < rank)
                _registers[index] = rank;
        }

        public void Merge(UniqueAddressCounter counter)
        {
            if (counter._precision != _precision)
                throw new ArgumentException("Unique address counters with different precision cannot be merged.", nameof(counter));

            byte[] registers = counter._registers;

            for (int i = 0; i < _registers.Length; i++)
            {
                if (_registers[i] < registers[i])
                    _registers[i] = registers[i];
            }
        }

        public UniqueAddressCounter Clone()
        {
            UniqueAddressCounter clone = new UniqueAddressCounter(_precision);
            Buffer.BlockCopy(_registers, 0, clone._registers, 0, _registers.Length);

            return clone;
        }

        public long Estimate()
        {
            int registerCount = _registers.Length;
            double sum = 0;
            int zeros = 0;

            for (int i = 0; i < registerCount; i++)
            {
                byte register = _registers[i];
                sum += 1.0 / (1UL << register);

                if (register == 0)
                    zeros++;
            }

            double alpha = 0.7213 / (1 + (1.079 / registerCount));
            double estimate = alpha * registerCount * registerCount / sum;

            if ((estimate <= 2.5 * registerCount) && (zeros > 0))
                estimate = registerCount * Math.Log((double)registerCount / zeros);

            return (long)Math.Round(estimate);
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)_precision);
            bW.Write(_registers);
        }

        #endregion

        #region properties

        public int Precision
        { get { return _precision; } }

        #endregion
    }
}
