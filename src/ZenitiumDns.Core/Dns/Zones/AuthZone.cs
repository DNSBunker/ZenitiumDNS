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
using System.Collections.Generic;
using ZenitiumLibrary;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.Zones
{
    abstract class AuthZone : Zone
    {
        #region variables

        bool _disabled;

        #endregion

        #region constructor

        protected AuthZone(AuthZoneInfo zoneInfo)
            : base(zoneInfo.Name)
        {
            _disabled = zoneInfo.Disabled;
        }

        protected AuthZone(string name)
            : base(name)
        { }

        #endregion

        #region private

        private IReadOnlyList<DnsResourceRecord> FilterDisabledRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if (_disabled)
                return Array.Empty<DnsResourceRecord>();

            if (records.Count == 1)
            {
                GenericRecordInfo authRecordInfo = records[0].GetAuthGenericRecordInfo();

                if (authRecordInfo.Disabled)
                    return Array.Empty<DnsResourceRecord>();

                DateTime now = DateTime.UtcNow;

                if ((now - authRecordInfo.LastUsedOn).Ticks >= TimeSpan.TicksPerSecond)
                    authRecordInfo.LastUsedOn = now;

                return records;
            }

            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(records.Count);
            DateTime utcNow = DateTime.UtcNow;

            for (int i = 0; i < records.Count; i++)
            {
                DnsResourceRecord record = records[i];
                GenericRecordInfo authRecordInfo = record.GetAuthGenericRecordInfo();

                if (authRecordInfo.Disabled)
                    continue;

                if ((utcNow - authRecordInfo.LastUsedOn).Ticks >= TimeSpan.TicksPerSecond)
                    authRecordInfo.LastUsedOn = utcNow;

                newRecords.Add(record);
            }

            if (newRecords.Count > 1)
            {
                switch (type)
                {
                    case DnsResourceRecordType.A:
                    case DnsResourceRecordType.AAAA:
                    case DnsResourceRecordType.NS:
                        newRecords.Shuffle();
                        break;
                }
            }

            return newRecords;
        }

        #endregion

        #region versioning

        internal bool TrySetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records, out IReadOnlyList<DnsResourceRecord> deletedRecords)
        {
            switch (type)
            {
                case DnsResourceRecordType.CNAME:
                    if ((!_entries.IsEmpty) && !_entries.ContainsKey(DnsResourceRecordType.CNAME))
                        throw new InvalidOperationException("Cannot add record: a CNAME record cannot exists with other record types for the same name.");

                    break;

                default:
                    if (_entries.ContainsKey(DnsResourceRecordType.CNAME))
                        throw new InvalidOperationException("Cannot add record: a CNAME record cannot exists with other record types for the same name.");

                    break;
            }

            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
            {
                deletedRecords = existingRecords;
                return _entries.TryUpdate(type, records, existingRecords);
            }
            else
            {
                deletedRecords = Array.Empty<DnsResourceRecord>();
                return _entries.TryAdd(type, records);
            }
        }

        internal bool TryDeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata, out DnsResourceRecord deletedRecord)
        {
            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
            {
                if (existingRecords.Count == 1)
                {
                    if (rdata.Equals(existingRecords[0].RDATA))
                    {
                        if (_entries.TryRemove(type, out IReadOnlyList<DnsResourceRecord> removedRecords))
                        {
                            deletedRecord = removedRecords[0];
                            return true;
                        }
                    }
                }
                else
                {
                    deletedRecord = null;
                    List<DnsResourceRecord> updatedRecords = new List<DnsResourceRecord>(existingRecords.Count);

                    foreach (DnsResourceRecord existingRecord in existingRecords)
                    {
                        if ((deletedRecord is null) && rdata.Equals(existingRecord.RDATA))
                            deletedRecord = existingRecord;
                        else
                            updatedRecords.Add(existingRecord);
                    }

                    if (deletedRecord is null)
                        return false;

                    return _entries.TryUpdate(type, updatedRecords, existingRecords);
                }
            }

            deletedRecord = null;
            return false;
        }

        internal void AddRecord(DnsResourceRecord record, out IReadOnlyList<DnsResourceRecord> addedRecords, out IReadOnlyList<DnsResourceRecord> deletedRecords)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.DNAME:
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot add record: use SetRecords() for " + record.Type.ToString() + " record.");

                default:
                    if (_entries.ContainsKey(DnsResourceRecordType.CNAME))
                        throw new InvalidOperationException("Cannot add record: a CNAME record cannot exists with other record types for the same name.");

                    break;
            }

            List<DnsResourceRecord> added = new List<DnsResourceRecord>();
            List<DnsResourceRecord> deleted = new List<DnsResourceRecord>();

            addedRecords = added;
            deletedRecords = deleted;

            _entries.AddOrUpdate(record.Type, delegate (DnsResourceRecordType key)
            {
                added.Add(record);
                return [record];
            },
            delegate (DnsResourceRecordType key, IReadOnlyList<DnsResourceRecord> existingRecords)
            {
                bool rdataFound = false;

                DnsResourceRecordData rdata;

                if (record.Type == DnsResourceRecordType.FWD)
                {
                    DnsForwarderRecordData fwd = record.RDATA as DnsForwarderRecordData;
                    rdata = DnsForwarderRecordData.CreatePartialRecordData(fwd.Protocol, fwd.Forwarder);
                }
                else
                {
                    rdata = record.RDATA;
                }

                foreach (DnsResourceRecord existingRecord in existingRecords)
                {
                    if (rdata.Equals(existingRecord.RDATA))
                    {
                        if (record.OriginalTtlValue == existingRecord.OriginalTtlValue)
                            return existingRecords;

                        rdataFound = true;
                        break;
                    }
                }

                List<DnsResourceRecord> updatedRecords = new List<DnsResourceRecord>(existingRecords.Count + 1);

                foreach (DnsResourceRecord existingRecord in existingRecords)
                {
                    if (existingRecord.OriginalTtlValue == record.OriginalTtlValue)
                    {
                        updatedRecords.Add(existingRecord);
                    }
                    else
                    {
                        DnsResourceRecord updatedExistingRecord = new DnsResourceRecord(existingRecord.Name, existingRecord.Type, existingRecord.Class, record.OriginalTtlValue, existingRecord.RDATA);
                        updatedRecords.Add(updatedExistingRecord);

                        added.Add(updatedExistingRecord);
                        deleted.Add(existingRecord);
                    }
                }

                if (!rdataFound)
                {
                    updatedRecords.Add(record);
                    added.Add(record);
                }

                return updatedRecords;
            });
        }

        #endregion

        #region public

        public void LoadRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            _entries[type] = records;
        }

        public virtual void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.DNAME:
                case DnsResourceRecordType.APP:
                    if ((!_entries.IsEmpty) && !_entries.ContainsKey(type))
                        throw new InvalidOperationException($"Cannot add record: {type} record already exists for the same name.");

                    break;

                default:
                    if (_entries.ContainsKey(DnsResourceRecordType.CNAME))
                        throw new InvalidOperationException("Cannot add record: a CNAME record cannot exists with other record types for the same name.");

                    break;
            }

            _entries[type] = records;
        }

        public virtual bool AddRecord(DnsResourceRecord record)
        {
            AddRecord(record, out IReadOnlyList<DnsResourceRecord> addedRecords, out _);

            return addedRecords.Count > 0;
        }

        public virtual bool DeleteRecords(DnsResourceRecordType type)
        {
            return _entries.TryRemove(type, out _);
        }

        public virtual bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            return TryDeleteRecord(type, rdata, out _);
        }

        public virtual void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            if (oldRecord.Type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot update record: use SetRecords() for " + oldRecord.Type.ToString() + " record");

            if (oldRecord.Type != newRecord.Type)
                throw new InvalidOperationException("Old and new record types do not match.");

            if (!DeleteRecord(oldRecord.Type, oldRecord.RDATA))
                throw new DnsWebServiceException("Cannot update record: the old record does not exists.");

            AddRecord(newRecord);
        }

        public virtual IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type)
        {
            switch (type)
            {
                case DnsResourceRecordType.APP:
                case DnsResourceRecordType.FWD:
                    {
                        if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                        {
                            IReadOnlyList<DnsResourceRecord> filteredRecords = FilterDisabledRecords(type, existingRecords);
                            if (filteredRecords.Count > 0)
                                return filteredRecords;
                        }
                    }
                    break;

                case DnsResourceRecordType.ANY:
                    List<DnsResourceRecord> records = new List<DnsResourceRecord>(_entries.Count * 2);

                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in _entries)
                    {
                        switch (entry.Key)
                        {
                            case DnsResourceRecordType.FWD:
                            case DnsResourceRecordType.APP:
                                continue;

                            default:
                                records.AddRange(entry.Value);
                                break;
                        }
                    }

                    return FilterDisabledRecords(type, records);

                default:
                    {
                        if (_entries.TryGetValue(DnsResourceRecordType.CNAME, out IReadOnlyList<DnsResourceRecord> existingCNAMERecords))
                        {
                            IReadOnlyList<DnsResourceRecord> filteredRecords = FilterDisabledRecords(type, existingCNAMERecords);
                            if (filteredRecords.Count > 0)
                                return filteredRecords;
                        }

                        if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> existingRecords))
                        {
                            IReadOnlyList<DnsResourceRecord> filteredRecords = FilterDisabledRecords(type, existingRecords);
                            if (filteredRecords.Count > 0)
                                return filteredRecords;
                        }

                        switch (type)
                        {
                            case DnsResourceRecordType.A:
                            case DnsResourceRecordType.AAAA:
                                if (_entries.TryGetValue(DnsResourceRecordType.ANAME, out IReadOnlyList<DnsResourceRecord> anameRecords))
                                    return FilterDisabledRecords(type, anameRecords);

                                if (_entries.TryGetValue(DnsResourceRecordType.ALIAS, out IReadOnlyList<DnsResourceRecord> aliasRecords))
                                {
                                    List<DnsResourceRecord> newAliasRecords = new List<DnsResourceRecord>(aliasRecords.Count);

                                    foreach (DnsResourceRecord aliasRecord in aliasRecords)
                                    {
                                        if ((aliasRecord.RDATA is DnsALIASRecordData alias) && (alias.Type == type))
                                            newAliasRecords.Add(aliasRecord);
                                    }

                                    if (newAliasRecords.Count > 0)
                                        return FilterDisabledRecords(type, newAliasRecords);
                                }

                                break;
                        }
                    }
                    break;
            }

            return Array.Empty<DnsResourceRecord>();
        }

        public IReadOnlyList<DnsResourceRecord> QueryRecordsWildcard(DnsResourceRecordType type, string queryDomain)
        {
            IReadOnlyList<DnsResourceRecord> answers = QueryRecords(type);

            if ((answers.Count > 0) && _name.StartsWith('*') && !_name.Equals(queryDomain, StringComparison.OrdinalIgnoreCase))
            {
                DnsResourceRecord[] wildcardAnswers = new DnsResourceRecord[answers.Count];

                for (int i = 0; i < answers.Count; i++)
                    wildcardAnswers[i] = new DnsResourceRecord(queryDomain, answers[i].Type, answers[i].Class, answers[i].TTL, answers[i].RDATA) { Tag = answers[i].Tag };

                answers = wildcardAnswers;
            }

            return answers;
        }

        public IReadOnlyList<DnsResourceRecord> GetRecords(DnsResourceRecordType type)
        {
            if (_entries.TryGetValue(type, out IReadOnlyList<DnsResourceRecord> records))
                return records;

            return Array.Empty<DnsResourceRecord>();
        }

        public override bool ContainsNameServerRecords()
        {
            if (!_entries.TryGetValue(DnsResourceRecordType.NS, out IReadOnlyList<DnsResourceRecord> records))
                return false;

            foreach (DnsResourceRecord record in records)
            {
                if (record.GetAuthGenericRecordInfo().Disabled)
                    continue;

                return true;
            }

            return false;
        }

        public override bool ContainsDNAMERecord()
        {
            if (!_entries.TryGetValue(DnsResourceRecordType.DNAME, out IReadOnlyList<DnsResourceRecord> records))
                return false;

            foreach (DnsResourceRecord record in records)
            {
                if (record.GetAuthGenericRecordInfo().Disabled)
                    continue;

                return true;
            }

            return false;
        }

        #endregion

        #region properties

        public IReadOnlyDictionary<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> Entries
        { get { return _entries; } }

        public virtual bool Disabled
        {
            get { return _disabled; }
            set { _disabled = value; }
        }

        public virtual bool IsActive
        {
            get { return !_disabled; }
        }

        #endregion
    }
}
