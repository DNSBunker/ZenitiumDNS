/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.Zones
{
    class ForwarderZone : ApexZone
    {
        #region constructor

        public ForwarderZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(dnsServer, zoneInfo)
        {
            InitZone();
            InitRecordExpiry();
        }

        public ForwarderZone(DnsServer dnsServer, string name)
            : base(dnsServer, name)
        {
            InitZone();
            InitRecordExpiry();
        }

        public ForwarderZone(DnsServer dnsServer, string name, DnsTransportProtocol forwarderProtocol, string forwarder, bool dnssecValidation, DnsForwarderRecordProxyType proxyType, string proxyAddress, ushort proxyPort, string proxyUsername, string proxyPassword, string fwdRecordComments)
            : base(dnsServer, name)
        {
            DnsResourceRecord fwdRecord = new DnsResourceRecord(name, DnsResourceRecordType.FWD, DnsClass.IN, 0, new DnsForwarderRecordData(forwarderProtocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword, 0));

            if (!string.IsNullOrEmpty(fwdRecordComments))
                fwdRecord.GetAuthGenericRecordInfo().Comments = fwdRecordComments;

            fwdRecord.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

            _entries[DnsResourceRecordType.FWD] = [fwdRecord];

            InitZone();
            InitRecordExpiry();
        }

        #endregion

        #region private

        private void InitZone()
        {
            DnsSOARecordData soa = new DnsSOARecordData(_dnsServer.ServerDomain, "invalid", 1, 900, 300, 604800, 900);
            DnsResourceRecord soaRecord = new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, 0, soa);
            soaRecord.GetAuthGenericRecordInfo().LastModified = DateTime.UtcNow;

            _entries[DnsResourceRecordType.SOA] = [soaRecord];
        }

        private static void ValidateRecordType(DnsResourceRecordType type)
        {
            switch (type)
            {
                case DnsResourceRecordType.SOA:
                    throw new InvalidOperationException("The SOA record of a Conditional Forwarder zone cannot be modified.");

                case DnsResourceRecordType.DS:
                case DnsResourceRecordType.DNSKEY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3PARAM:
                case DnsResourceRecordType.NSEC3:
                    throw new InvalidOperationException("Cannot set DNSSEC records.");
            }
        }

        #endregion

        #region public

        public override string GetZoneTypeName()
        {
            return "Conditional Forwarder";
        }

        public override void SetRecords(DnsResourceRecordType type, IReadOnlyList<DnsResourceRecord> records)
        {
            if (type == DnsResourceRecordType.CNAME)
                throw new InvalidOperationException("Cannot set CNAME record at zone apex.");

            ValidateRecordType(type);

            if (records[0].OriginalTtlValue > GetZoneSoaExpire())
                throw new DnsServerException("Cannot set records: TTL cannot be greater than SOA EXPIRE.");

            if (!TrySetRecords(type, records, out _))
                throw new DnsServerException("Cannot set records. Please try again.");

            CommitChanges(records);
        }

        public override bool AddRecord(DnsResourceRecord record)
        {
            ValidateRecordType(record.Type);

            if (record.OriginalTtlValue > GetZoneSoaExpire())
                throw new DnsServerException("Cannot add record: TTL cannot be greater than SOA EXPIRE.");

            AddRecord(record, out IReadOnlyList<DnsResourceRecord> addedRecords, out _);

            if (addedRecords.Count == 0)
                return false;

            CommitChanges(addedRecords);
            return true;
        }

        public override bool DeleteRecords(DnsResourceRecordType type)
        {
            if (type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot delete SOA record.");

            if (!_entries.TryRemove(type, out _))
                return false;

            CommitChanges();
            return true;
        }

        public override bool DeleteRecord(DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            if (type == DnsResourceRecordType.SOA)
                throw new InvalidOperationException("Cannot delete SOA record.");

            if (!TryDeleteRecord(type, rdata, out _))
                return false;

            CommitChanges();
            return true;
        }

        public override void UpdateRecord(DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            ValidateRecordType(oldRecord.Type);

            if (oldRecord.Type != newRecord.Type)
                throw new InvalidOperationException("Old and new record types do not match.");

            if (newRecord.OriginalTtlValue > GetZoneSoaExpire())
                throw new DnsServerException("Cannot update record: TTL cannot be greater than SOA EXPIRE.");

            if (!TryDeleteRecord(oldRecord.Type, oldRecord.RDATA, out _))
                throw new DnsServerException("Cannot update record: the record does not exists to be updated.");

            AddRecord(newRecord, out IReadOnlyList<DnsResourceRecord> addedRecords, out _);

            CommitChanges(addedRecords);
        }

        public override IReadOnlyList<DnsResourceRecord> QueryRecords(DnsResourceRecordType type)
        {
            if (type == DnsResourceRecordType.SOA)
                return [];

            return base.QueryRecords(type);
        }

        #endregion

        #region properties

        public override AuthZoneQueryAccess QueryAccess
        {
            get { return base.QueryAccess; }
            set
            {
                switch (value)
                {
                    case AuthZoneQueryAccess.AllowOnlyZoneNameServers:
                    case AuthZoneQueryAccess.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                        throw new ArgumentException("The Query Access option is invalid for " + GetZoneTypeName() + " zones: " + value.ToString(), nameof(QueryAccess));
                }

                base.QueryAccess = value;
            }
        }

        #endregion
    }
}
