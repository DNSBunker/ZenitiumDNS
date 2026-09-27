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
using System.Text;

namespace ZenitiumDns.Core.Dns.ZoneManagers
{
    sealed class DomainTable
    {
        #region variables

        const int CHUNK_BITS = 20;
        const int CHUNK_SIZE = 1 << CHUNK_BITS;
        const int CHUNK_MASK = CHUNK_SIZE - 1;
        const int ENTRY_HEADER_SIZE = 3;
        const int MAX_KEY_LENGTH = 255;
        const int MIN_SLOTS = 16;

        public static readonly DomainTable Empty = new DomainTable(0);

        readonly List<byte[]> _chunks = new List<byte[]>();
        int _chunkPosition = CHUNK_SIZE;
        ulong[] _slots;
        int _count;

        #endregion

        #region constructor

        public DomainTable(long capacity)
        {
            _slots = new ulong[GetSlotCount(capacity)];
        }

        #endregion

        #region private

        private static int GetSlotCount(long capacity)
        {
            long slots = MIN_SLOTS;

            while ((slots * 7) < (capacity * 10))
                slots <<= 1;

            if (slots > (1L << 30))
                throw new ArgumentOutOfRangeException(nameof(capacity));

            return (int)slots;
        }

        private static uint GetHash(ReadOnlySpan<char> key)
        {
            return (uint)string.GetHashCode(key);
        }

        private static bool IsValidKey(ReadOnlySpan<char> key)
        {
            return (key.Length > 0) && (key.Length <= MAX_KEY_LENGTH) && Ascii.IsValid(key);
        }

        private bool KeyEquals(int handle, ReadOnlySpan<char> key)
        {
            byte[] chunk = _chunks[handle >> CHUNK_BITS];
            int position = handle & CHUNK_MASK;

            if (chunk[position] != key.Length)
                return false;

            return Ascii.Equals(chunk.AsSpan(position + ENTRY_HEADER_SIZE, key.Length), key);
        }

        private int FindSlot(ReadOnlySpan<char> key, uint hash)
        {
            ulong[] slots = _slots;
            int mask = slots.Length - 1;
            int index = (int)(hash & (uint)mask);

            while (true)
            {
                ulong slot = slots[index];
                if (slot == 0)
                    return ~index;

                if (((uint)(slot >> 32) == hash) && KeyEquals((int)(uint)slot - 1, key))
                    return index;

                index = (index + 1) & mask;
            }
        }

        private void Resize()
        {
            ulong[] oldSlots = _slots;
            ulong[] newSlots = new ulong[oldSlots.Length * 2];
            int mask = newSlots.Length - 1;

            foreach (ulong slot in oldSlots)
            {
                if (slot == 0)
                    continue;

                int index = (int)((uint)(slot >> 32) & (uint)mask);

                while (newSlots[index] != 0)
                    index = (index + 1) & mask;

                newSlots[index] = slot;
            }

            _slots = newSlots;
        }

        private int Append(ReadOnlySpan<char> key, ushort value)
        {
            int size = ENTRY_HEADER_SIZE + key.Length;

            if ((_chunkPosition + size) > CHUNK_SIZE)
            {
                _chunks.Add(new byte[CHUNK_SIZE]);
                _chunkPosition = 0;
            }

            byte[] chunk = _chunks[_chunks.Count - 1];
            int position = _chunkPosition;

            chunk[position] = (byte)key.Length;
            BinaryPrimitives.WriteUInt16LittleEndian(chunk.AsSpan(position + 1, 2), value);
            Ascii.FromUtf16(key, chunk.AsSpan(position + ENTRY_HEADER_SIZE, key.Length), out _);

            _chunkPosition += size;

            return ((_chunks.Count - 1) << CHUNK_BITS) | position;
        }

        #endregion

        #region public

        public bool TryAdd(ReadOnlySpan<char> key, ushort value, out int handle)
        {
            if (!IsValidKey(key))
            {
                handle = -1;
                return false;
            }

            uint hash = GetHash(key);
            int index = FindSlot(key, hash);

            if (index >= 0)
            {
                handle = (int)(uint)_slots[index] - 1;
                return false;
            }

            if (((_count + 1) * 10L) > (_slots.Length * 7L))
            {
                Resize();
                index = FindSlot(key, hash);
            }

            handle = Append(key, value);
            _slots[~index] = ((ulong)hash << 32) | (uint)(handle + 1);
            _count++;

            return true;
        }

        public bool TryGetValue(ReadOnlySpan<char> key, out ushort value)
        {
            if ((_count == 0) || (key.Length == 0) || (key.Length > MAX_KEY_LENGTH))
            {
                value = 0;
                return false;
            }

            int index = FindSlot(key, GetHash(key));
            if (index < 0)
            {
                value = 0;
                return false;
            }

            value = GetValue((int)(uint)_slots[index] - 1);
            return true;
        }

        public bool Contains(ReadOnlySpan<char> key)
        {
            return TryGetValue(key, out _);
        }

        public ushort GetValue(int handle)
        {
            byte[] chunk = _chunks[handle >> CHUNK_BITS];

            return BinaryPrimitives.ReadUInt16LittleEndian(chunk.AsSpan((handle & CHUNK_MASK) + 1, 2));
        }

        public void SetValue(int handle, ushort value)
        {
            byte[] chunk = _chunks[handle >> CHUNK_BITS];

            BinaryPrimitives.WriteUInt16LittleEndian(chunk.AsSpan((handle & CHUNK_MASK) + 1, 2), value);
        }

        public string GetKey(int handle)
        {
            byte[] chunk = _chunks[handle >> CHUNK_BITS];
            int position = handle & CHUNK_MASK;

            return Encoding.ASCII.GetString(chunk, position + ENTRY_HEADER_SIZE, chunk[position]);
        }

        public void TrimExcess()
        {
            if ((_chunks.Count == 0) || (_chunkPosition >= CHUNK_SIZE))
                return;

            byte[] chunk = _chunks[_chunks.Count - 1];
            Array.Resize(ref chunk, _chunkPosition);

            _chunks[_chunks.Count - 1] = chunk;
            _chunkPosition = CHUNK_SIZE;
        }

        #endregion

        #region properties

        public int Count
        { get { return _count; } }

        public long MemoryUsage
        {
            get
            {
                long total = _slots.LongLength * sizeof(ulong);

                foreach (byte[] chunk in _chunks)
                    total += chunk.LongLength;

                return total;
            }
        }

        #endregion
    }
}
