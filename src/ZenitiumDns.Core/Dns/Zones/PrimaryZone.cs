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

using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.Zones
{
    class PrimaryZone : ApexZone
    {
        #region constructor

        internal PrimaryZone(DnsServer dnsServer, string name, DnsSOARecordData soa, DnsNSRecordData ns)
            : base(dnsServer, name)
        {
            _entries[DnsResourceRecordType.SOA] = [new DnsResourceRecord(_name, DnsResourceRecordType.SOA, DnsClass.IN, soa.Minimum, soa)];
            _entries[DnsResourceRecordType.NS] = [new DnsResourceRecord(_name, DnsResourceRecordType.NS, DnsClass.IN, soa.Minimum, ns)];
        }

        #endregion

        #region public

        public override string GetZoneTypeName()
        {
            return "Primary";
        }

        #endregion
    }
}
