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
using System.Collections.Generic;
using System.Threading;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.Zones
{
    readonly struct CacheEntry
    {
        public readonly DnsResourceRecordType Type;
        public readonly IReadOnlyList<DnsResourceRecord> Records;

        public CacheEntry(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            Type = type;
            Records = records;
        }
    }

    interface ICacheEntrySet
    {
        bool TryGetValue(DnsResourceRecordType type, out IReadOnlyList<DnsResourceRecord> records);

        bool Set(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records);

        bool TryRemove(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> expectedRecords = null);

        CacheEntry[] Items { get; }

        bool IsEmpty { get; }

        int Count { get; }
    }

    static class CacheEntries
    {
        public static bool TryGetValue(CacheEntry[] items, DnsResourceRecordType type, out IReadOnlyList<DnsResourceRecord> records)
        {
            for (int i = 0; i < items.Length; i++)
            {
                if (items[i].Type == type)
                {
                    records = items[i].Records;
                    return true;
                }
            }

            records = null;
            return false;
        }

        public static bool Set(ref CacheEntry[] items, object lockObject, DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            lock (lockObject)
            {
                CacheEntry[] current = items;

                for (int i = 0; i < current.Length; i++)
                {
                    if (current[i].Type == type)
                    {
                        CacheEntry[] updated = (CacheEntry[])current.Clone();
                        updated[i] = new CacheEntry(type, records);
                        Volatile.Write(ref items, updated);
                        return false;
                    }
                }

                CacheEntry[] added = new CacheEntry[current.Length + 1];
                Array.Copy(current, added, current.Length);
                added[current.Length] = new CacheEntry(type, records);
                Volatile.Write(ref items, added);
                return true;
            }
        }

        public static bool TryRemove(ref CacheEntry[] items, object lockObject, DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> expectedRecords)
        {
            lock (lockObject)
            {
                CacheEntry[] current = items;

                for (int i = 0; i < current.Length; i++)
                {
                    if (current[i].Type != type)
                        continue;

                    if ((expectedRecords is not null) && !ReferenceEquals(current[i].Records, expectedRecords))
                        return false;

                    if (current.Length == 1)
                    {
                        Volatile.Write(ref items, []);
                        return true;
                    }

                    CacheEntry[] removed = new CacheEntry[current.Length - 1];
                    Array.Copy(current, 0, removed, 0, i);
                    Array.Copy(current, i + 1, removed, i, current.Length - i - 1);
                    Volatile.Write(ref items, removed);
                    return true;
                }

                return false;
            }
        }
    }

    sealed class CacheEntrySet : ICacheEntrySet
    {
        #region variables

        CacheEntry[] _items;

        #endregion

        #region constructor

        public CacheEntrySet()
        {
            _items = [];
        }

        public CacheEntrySet(CacheEntry[] items)
        {
            _items = items;
        }

        #endregion

        #region public

        public bool TryGetValue(DnsResourceRecordType type, out IReadOnlyList<DnsResourceRecord> records)
        {
            return CacheEntries.TryGetValue(Volatile.Read(ref _items), type, out records);
        }

        public bool Set(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            return CacheEntries.Set(ref _items, this, type, records);
        }

        public bool TryRemove(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> expectedRecords = null)
        {
            return CacheEntries.TryRemove(ref _items, this, type, expectedRecords);
        }

        #endregion

        #region properties

        public CacheEntry[] Items
        { get { return Volatile.Read(ref _items); } }

        public bool IsEmpty
        { get { return Volatile.Read(ref _items).Length == 0; } }

        public int Count
        { get { return Volatile.Read(ref _items).Length; } }

        #endregion
    }
}
