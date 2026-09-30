/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)
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

using ZenitiumDns.Core.Dns.ResourceRecords;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using ZenitiumLibrary;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.Zones
{
    class CacheZone : Zone, ICacheEntrySet
    {
        #region variables

        CacheEntry[] _items;
        ConcurrentDictionary<NetworkAddress, CacheEntrySet> _ecsEntries;

        #endregion

        #region constructor

        public CacheZone(string name, int capacity)
            : base(name, true)
        {
            _items = [];
        }

        private CacheZone(string name, CacheEntry[] items)
            : base(name, true)
        {
            _items = items;
        }

        #endregion

        #region static

        public static CacheZone ReadFrom(BinaryReader bR, bool serveStale)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    string name = bR.ReadString();
                    CacheZone cacheZone = new CacheZone(name, ReadEntriesFrom(bR, serveStale));

                    {
                        int ecsCount = bR.ReadInt32();
                        if (ecsCount > 0)
                        {
                            ConcurrentDictionary<NetworkAddress, CacheEntrySet> ecsEntries = new ConcurrentDictionary<NetworkAddress, CacheEntrySet>(1, ecsCount);

                            for (int i = 0; i < ecsCount; i++)
                            {
                                NetworkAddress key = NetworkAddress.ReadFrom(bR);
                                CacheEntry[] ecsItems = ReadEntriesFrom(bR, serveStale);

                                if (ecsItems.Length > 0)
                                    ecsEntries.TryAdd(key, new CacheEntrySet(ecsItems));
                            }

                            if (!ecsEntries.IsEmpty)
                                cacheZone._ecsEntries = ecsEntries;
                        }
                    }

                    return cacheZone;

                default:
                    throw new InvalidDataException("CacheZone format version not supported.");
            }
        }

        #endregion

        #region private

        private static IReadOnlyList<DnsResourceRecord> ValidateRRSet(IReadOnlyList<DnsResourceRecord> records, bool serveStale, bool skipSpecialCacheRecord)
        {
            for (int i = 0; i < records.Count; i++)
            {
                DnsResourceRecord record = records[i];

                if (record.IsExpired(serveStale))
                    return [];

                if (record.RDATA is DnsCache.DnsSpecialCacheRecordData specialRecord)
                {
                    if (skipSpecialCacheRecord)
                        return [];

                    if (serveStale && specialRecord.IsFailureOrBadCache && record.IsExpired(false))
                        return [];
                }
            }

            DateTime utcNow = DateTime.UtcNow;

            for (int i = 0; i < records.Count; i++)
            {
                CacheRecordInfo recordInfo = records[i].GetCacheRecordInfo();

                if ((utcNow - recordInfo.LastUsedOn).Ticks >= TimeSpan.TicksPerSecond)
                    recordInfo.LastUsedOn = utcNow;
            }

            if (records.Count > 1)
            {
                switch (records[0].Type)
                {
                    case DnsResourceRecordType.A:
                    case DnsResourceRecordType.AAAA:
                        List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records);
                        newRecords.Shuffle();
                        return newRecords;
                }
            }

            return records;
        }

        private static CacheEntry[] ReadEntriesFrom(BinaryReader bR, bool serveStale)
        {
            int count = bR.ReadInt32();
            List<CacheEntry> entries = new List<CacheEntry>(count);

            for (int i = 0; i < count; i++)
            {
                DnsResourceRecordType key = (DnsResourceRecordType)bR.ReadUInt16();
                int rrCount = bR.ReadInt32();
                DnsResourceRecord[] records = new DnsResourceRecord[rrCount];

                for (int j = 0; j < rrCount; j++)
                {
                    records[j] = DnsResourceRecord.ReadCacheRecordFrom(bR, delegate (DnsResourceRecord record)
                    {
                        record.Tag = new CacheRecordInfo(bR);
                    });
                }

                if (!DnsResourceRecord.IsRRSetExpired(records, serveStale))
                    entries.Add(new CacheEntry(key, records));
            }

            return entries.ToArray();
        }

        private static void WriteEntriesTo(ICacheEntrySet entries, BinaryWriter bW)
        {
            CacheEntry[] items = entries.Items;

            bW.Write(items.Length);

            foreach (CacheEntry entry in items)
            {
                bW.Write((ushort)entry.Type);
                bW.Write(entry.Records.Count);

                foreach (DnsResourceRecord record in entry.Records)
                {
                    record.WriteCacheRecordTo(bW, delegate ()
                    {
                        if (record.Tag is not CacheRecordInfo rrInfo)
                            rrInfo = CacheRecordInfo.Default;

                        rrInfo.WriteTo(bW);
                    });
                }
            }
        }

        private static int RemoveExpiredEntries(ICacheEntrySet entries, bool serveStale)
        {
            int removedEntries = 0;

            foreach (CacheEntry entry in entries.Items)
            {
                if (DnsResourceRecord.IsRRSetExpired(entry.Records, serveStale))
                {
                    if (entries.TryRemove(entry.Type, entry.Records))
                        removedEntries++;
                }
            }

            return removedEntries;
        }

        private static int RemoveLeastUsedEntries(ICacheEntrySet entries, DateTime cutoff)
        {
            int removedEntries = 0;

            foreach (CacheEntry entry in entries.Items)
            {
                if ((entry.Records.Count == 0) || (entry.Records[0].GetCacheRecordInfo().LastUsedOn < cutoff))
                {
                    if (entries.TryRemove(entry.Type, entry.Records))
                        removedEntries++;
                }
            }

            return removedEntries;
        }

        #endregion

        #region public

        public bool SetRecords(IReadOnlyList<DnsResourceRecord> records, bool serveStale)
        {
            if (records.Count == 0)
                return false;

            DnsResourceRecord firstRecord = records[0];
            CacheRecordInfo cacheRecordInfo = firstRecord.GetCacheRecordInfo();
            NetworkAddress eDnsClientSubnet = cacheRecordInfo.EDnsClientSubnet;

            ICacheEntrySet entries;

            if (eDnsClientSubnet is null)
            {
                entries = this;
            }
            else
            {
                if (_ecsEntries is null)
                {
                    _ecsEntries = new ConcurrentDictionary<NetworkAddress, CacheEntrySet>(1, 5);
                    CacheEntrySet ecsEntry = new CacheEntrySet();
                    if (!_ecsEntries.TryAdd(eDnsClientSubnet, ecsEntry))
                        return false;

                    entries = ecsEntry;
                }
                else if (_ecsEntries.TryGetValue(eDnsClientSubnet, out CacheEntrySet existingEcsEntry))
                {
                    entries = existingEcsEntry;
                }
                else
                {
                    CacheEntrySet ecsEntry = new CacheEntrySet();
                    if (!_ecsEntries.TryAdd(eDnsClientSubnet, ecsEntry))
                        return false;

                    entries = ecsEntry;
                }
            }

            DnsResourceRecordType type = firstRecord.Type;

            if (firstRecord.RDATA is DnsCache.DnsSpecialCacheRecordData splRecord)
            {
                if (splRecord.IsFailureOrBadCache)
                {
                    if (entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords) && (existingRecords.Count > 0) && !DnsResourceRecord.IsRRSetExpired(existingRecords, serveStale))
                    {
                        if ((existingRecords[0].RDATA is not DnsCache.DnsSpecialCacheRecordData existingSplRecord) || !existingSplRecord.IsFailureOrBadCache)
                            return false;

                        splRecord.CopyExtendedDnsErrorsFrom(existingSplRecord);
                    }
                }
                else if (serveStale)
                {
                    switch (type)
                    {
                        case DnsResourceRecordType.CNAME:
                        case DnsResourceRecordType.SOA:
                        case DnsResourceRecordType.NS:
                        case DnsResourceRecordType.DS:
                            break;

                        default:

                            if (entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                            {
                                if ((existingCNAMERecords.Count > 0) && (existingCNAMERecords[0].RDATA is DnsCNAMERecordData) && existingCNAMERecords[0].IsStale)
                                {
                                    entries.TryRemove(DnsResourceRecordType.CNAME);
                                }
                            }
                            break;
                    }
                }

                if (type == DnsResourceRecordType.NS)
                {
                    if (entries.TryGetValue(DnsResourceRecordType.CHILD_NS, out IReadOnlyList<DnsResourceRecord> existingChildNSRecords))
                    {
                        if ((existingChildNSRecords.Count > 0) && (existingChildNSRecords[0].RDATA is DnsNSRecordData) && existingChildNSRecords[0].IsStale)
                        {
                            entries.TryRemove(DnsResourceRecordType.CHILD_NS);
                        }
                    }
                }
            }
            else if (type == DnsResourceRecordType.CHILD_NS)
            {
                DnsResourceRecord[] newRecords = new DnsResourceRecord[records.Count];

                for (int i = 0; i < records.Count; i++)
                {
                    DnsResourceRecord record = records[i];

                    if (record.Type == DnsResourceRecordType.CHILD_NS)
                        record = record.CloneAs(DnsResourceRecordType.NS);

                    newRecords[i] = record;
                }

                records = newRecords;
            }

            if (records is not DnsResourceRecord[])
            {
                DnsResourceRecord[] compactRecords = new DnsResourceRecord[records.Count];

                for (int i = 0; i < compactRecords.Length; i++)
                    compactRecords[i] = records[i];

                records = compactRecords;
            }

            DateTime utcNow = DateTime.UtcNow;

            foreach (DnsResourceRecord record in records)
                record.GetCacheRecordInfo().LastUsedOn = utcNow;

            return entries.Set(type, records);
        }

        public int RemoveExpiredRecords(bool serveStale)
        {
            int removedEntries = 0;

            if (_ecsEntries is not null)
            {
                foreach (KeyValuePair<NetworkAddress, CacheEntrySet> ecsEntry in _ecsEntries)
                {
                    removedEntries += RemoveExpiredEntries(ecsEntry.Value, serveStale);

                    if (ecsEntry.Value.IsEmpty)
                        _ecsEntries.TryRemove(ecsEntry.Key, out _);
                }
            }

            removedEntries += RemoveExpiredEntries(this, serveStale);

            return removedEntries;
        }

        public int RemoveLeastUsedRecords(DateTime cutoff)
        {
            int removedEntries = 0;

            if (_ecsEntries is not null)
            {
                foreach (KeyValuePair<NetworkAddress, CacheEntrySet> ecsEntry in _ecsEntries)
                {
                    removedEntries += RemoveLeastUsedEntries(ecsEntry.Value, cutoff);

                    if (ecsEntry.Value.IsEmpty)
                        _ecsEntries.TryRemove(ecsEntry.Key, out _);
                }
            }

            removedEntries += RemoveLeastUsedEntries(this, cutoff);

            return removedEntries;
        }

        public int DeleteEDnsClientSubnetData()
        {
            if (_ecsEntries is null)
                return 0;

            int count = 0;

            foreach (KeyValuePair<NetworkAddress, CacheEntrySet> ecsEntry in _ecsEntries)
                count += ecsEntry.Value.Count;

            _ecsEntries = null;

            return count;
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type, bool serveStale, bool skipSpecialCacheRecord, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet)
        {
            ICacheEntrySet entries;

            if (eDnsClientSubnet is null)
            {
                entries = this;
            }
            else
            {
                if (_ecsEntries is null)
                    return [];

                if (advancedForwardingClientSubnet)
                {
                    if (!_ecsEntries.TryGetValue(eDnsClientSubnet, out CacheEntrySet ecsEntry))
                        return [];

                    entries = ecsEntry;
                }
                else
                {
                    NetworkAddress selectedNetwork = null;
                    entries = null;

                    foreach (KeyValuePair<NetworkAddress, CacheEntrySet> ecsEntry in _ecsEntries)
                    {
                        NetworkAddress cacheSubnet = ecsEntry.Key;

                        if (cacheSubnet.PrefixLength > eDnsClientSubnet.PrefixLength)
                            continue;

                        if (cacheSubnet.Equals(eDnsClientSubnet) || cacheSubnet.Contains(eDnsClientSubnet.Address))
                        {
                            if ((selectedNetwork is null) || (cacheSubnet.PrefixLength < selectedNetwork.PrefixLength))
                            {
                                selectedNetwork = cacheSubnet;
                                entries = ecsEntry.Value;
                            }
                        }
                    }

                    if (entries is null)
                        return [];
                }
            }

            switch (type)
            {
                case DnsResourceRecordType.DS:
                    {
                        if (entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                            return ValidateRRSet(existingRecords, serveStale, skipSpecialCacheRecord);
                    }
                    break;

                case DnsResourceRecordType.ANY:
                    CacheEntry[] items = entries.Items;
                    List<DnsResourceRecord> anyRecords = new List<DnsResourceRecord>(items.Length * 2);

                    foreach (CacheEntry entry in items)
                    {
                        switch (entry.Type)
                        {
                            case DnsResourceRecordType.DS:
                            case DnsResourceRecordType.NS:
                                continue;
                        }

                        anyRecords.AddRange(ValidateRRSet(entry.Records, serveStale, true));
                    }

                    return anyRecords;

                default:
                    {
                        switch (type)
                        {
                            case DnsResourceRecordType.NS:
                                type = DnsResourceRecordType.CHILD_NS;
                                break;

                            case DnsResourceRecordType.PARENT_NS:
                                type = DnsResourceRecordType.NS;
                                break;
                        }

                        if (entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                            return ValidateRRSet(existingRecords, serveStale, skipSpecialCacheRecord);

                        if (type == DnsResourceRecordType.CHILD_NS)
                        {
                            if (entries.TryGetValue(DnsResourceRecordType.NS, out IReadOnlyList<DnsResourceRecord> existingParentNSRecords))
                            {
                                if ((existingParentNSRecords.Count > 0) && (existingParentNSRecords[0].RDATA is DnsCache.DnsSpecialCacheRecordData))
                                    return ValidateRRSet(existingParentNSRecords, serveStale, skipSpecialCacheRecord);
                            }
                        }

                        if (entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                        {
                            IReadOnlyList<DnsResourceRecord> rrset = ValidateRRSet(existingCNAMERecords, serveStale, skipSpecialCacheRecord);
                            if (rrset.Count > 0)
                            {
                                if ((type == DnsResourceRecordType.CNAME) || (rrset[0].RDATA is DnsCNAMERecordData))
                                    return rrset;
                            }
                        }
                    }
                    break;
            }

            return [];
        }

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

        public override void ListAllRecords(List<DnsResourceRecord> records)
        {
            if (_ecsEntries is not null)
            {
                foreach (KeyValuePair<NetworkAddress, CacheEntrySet> ecsEntry in _ecsEntries)
                {
                    foreach (CacheEntry entry in ecsEntry.Value.Items)
                        records.AddRange(entry.Records);
                }
            }

            foreach (CacheEntry entry in Items)
                records.AddRange(entry.Records);
        }

        public override bool ContainsNameServerRecords()
        {
            if (!TryGetValue(DnsResourceRecordType.NS, out IReadOnlyList<DnsResourceRecord> records))
            {
                if ((_name.Length > 0) || !TryGetValue(DnsResourceRecordType.CHILD_NS, out records))
                    return false;
            }

            foreach (DnsResourceRecord record in records)
            {
                if (record.IsStale)
                    continue;

                if (record.RDATA is DnsNSRecordData)
                    return true;
            }

            return false;
        }

        public override bool ContainsDNAMERecord()
        {
            if (!TryGetValue(DnsResourceRecordType.DNAME, out IReadOnlyList<DnsResourceRecord> records))
                return false;

            foreach (DnsResourceRecord record in records)
            {
                if (record.IsStale)
                    continue;

                if (record.RDATA is DnsDNAMERecordData)
                    return true;
            }

            return false;
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)1);

            bW.Write(_name);

            WriteEntriesTo(this, bW);

            if (_ecsEntries is null)
            {
                bW.Write(0);
            }
            else
            {
                bW.Write(_ecsEntries.Count);

                foreach (KeyValuePair<NetworkAddress, CacheEntrySet> ecsEntry in _ecsEntries)
                {
                    ecsEntry.Key.WriteTo(bW);
                    WriteEntriesTo(ecsEntry.Value, bW);
                }
            }
        }

        #endregion

        #region properties

        public override bool IsEmpty
        {
            get
            {
                if (_ecsEntries is null)
                    return Volatile.Read(ref _items).Length == 0;

                return _ecsEntries.IsEmpty && (Volatile.Read(ref _items).Length == 0);
            }
        }

        public CacheEntry[] Items
        { get { return Volatile.Read(ref _items); } }

        bool ICacheEntrySet.IsEmpty
        { get { return Volatile.Read(ref _items).Length == 0; } }

        int ICacheEntrySet.Count
        { get { return Volatile.Read(ref _items).Length; } }

        public int TotalEntries
        {
            get
            {
                if (_ecsEntries is null)
                    return Volatile.Read(ref _items).Length;

                int count = Volatile.Read(ref _items).Length;

                foreach (KeyValuePair<NetworkAddress, CacheEntrySet> ecsEntry in _ecsEntries)
                    count += ecsEntry.Value.Count;

                return count;
            }
        }

        #endregion
    }
}
