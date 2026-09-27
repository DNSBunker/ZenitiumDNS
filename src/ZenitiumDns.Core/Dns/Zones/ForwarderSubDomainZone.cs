/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)
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
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.Zones
{
    class ForwarderSubDomainZone : SubDomainZone
    {
        #region variables

        readonly ForwarderZone _forwarderZone;

        #endregion

        #region constructor

        public ForwarderSubDomainZone(ForwarderZone forwarderZone, string name)
            : base(forwarderZone, name)
        {
            _forwarderZone = forwarderZone;
        }

        #endregion

        #region public

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            switch (type)
            {
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot set SOA record on sub domain.");

                case DnsResourceRecordType.DS:
                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot set DNSSEC records.");

                default:
                    if (records[0].OriginalTtlValue > _forwarderZone.GetZoneSoaExpire())
                        throw new DnsServerException("Cannot set records: TTL cannot be greater than SOA EXPIRE.");

                    if (!TrySetRecords(type, records, out _))
                        throw new DnsServerException("Cannot set records. Please try again.");

                    _forwarderZone.CommitChanges(records);
                    break;
            }
        }

        public override bool AddRecord(DnsResourceRecord record)
        {
            switch (record.Type)
            {
                case DnsResourceRecordType.DS:
                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot add DNSSEC record.");

                default:
                    if (record.OriginalTtlValue > _forwarderZone.GetZoneSoaExpire())
                        throw new DnsServerException("Cannot add record: TTL cannot be greater than SOA EXPIRE.");

                    AddRecord(record, out IReadOnlyList<DnsResourceRecord> addedRecords, out _);

                    if (addedRecords.Count > 0)
                    {
                        _forwarderZone.CommitChanges(addedRecords);

                        return true;
                    }

                    return false;
            }
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            if (_entries.TryRemove(type, out _))
            {
                _forwarderZone.CommitChanges();

                return true;
            }

            return false;
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            if (TryDeleteRecord(type, rdata, out _))
            {
                _forwarderZone.CommitChanges();

                return true;
            }

            return false;
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            switch (oldRecord.Type)
            {
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("Cannot update record: use SetRecords() for " + oldRecord.Type.ToString() + " record.");

                default:
                    if (oldRecord.Type != newRecord.Type)
                        throw new InvalidOperationException("Old and new record types do not match.");

                    if (newRecord.OriginalTtlValue > _forwarderZone.GetZoneSoaExpire())
                        throw new DnsServerException("Cannot update record: TTL cannot be greater than SOA EXPIRE.");

                    if (!TryDeleteRecord(oldRecord.Type, oldRecord.RDATA, out _))
                        throw new InvalidOperationException("Cannot update record: the record does not exists to be updated.");

                    AddRecord(newRecord, out IReadOnlyList<DnsResourceRecord> addedRecords, out _);

                    _forwarderZone.CommitChanges(addedRecords);
                    break;
            }
        }

        #endregion
    }
}
