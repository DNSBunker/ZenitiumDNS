/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using System.Threading;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.Zones
{
    public enum AuthZoneQueryAccess : byte
    {
        Deny = 0,
        Allow = 1,
        AllowOnlyPrivateNetworks = 2,
        AllowOnlyZoneNameServers = 3,
        UseSpecifiedNetworkACL = 4,
        AllowZoneNameServersAndUseSpecifiedNetworkACL = 5
    }

    abstract class ApexZone : AuthZone, IDisposable
    {
        #region variables

        protected readonly DnsServer _dnsServer;
        protected DateTime _lastModified;

        protected AuthZoneQueryAccess _queryAccess;
        IReadOnlyCollection<NetworkAccessControl> _queryAccessNetworkACL;

        Timer _recordExpiryTimer;
        readonly Lock _recordExpiryTimerLock = new Lock();
        DateTime _recordExpiryTimerStartedOn;
        uint _recordExpiryTimerTtl;
        bool _recordExpiryTimerRunning;

        #endregion

        #region constructor

        protected ApexZone(DnsServer dnsServer, AuthZoneInfo zoneInfo)
            : base(zoneInfo)
        {
            _dnsServer = dnsServer;

            _queryAccess = zoneInfo.QueryAccess;
            _queryAccessNetworkACL = zoneInfo.QueryAccessNetworkACL;

            _lastModified = zoneInfo.LastModified;
        }

        protected ApexZone(DnsServer dnsServer, string name)
            : base(name)
        {
            _dnsServer = dnsServer;

            _queryAccess = AuthZoneQueryAccess.Allow;

            _lastModified = DateTime.UtcNow;
        }

        #endregion

        #region IDisposable

        bool _disposed;

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                lock (_recordExpiryTimerLock)
                {
                    if (_recordExpiryTimer is not null)
                    {
                        _recordExpiryTimer.Dispose();
                        _recordExpiryTimer = null;
                    }
                }
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region record expiry

        protected void InitRecordExpiry()
        {
            _recordExpiryTimer = new Timer(RecordExpiryTimerCallback, null, Timeout.Infinite, Timeout.Infinite);
        }

        private uint GetMinRecordExpiryTtl(uint minExpiryTtl)
        {
            if (!_recordExpiryTimerRunning)
                return Math.Min(minExpiryTtl, uint.MaxValue / 1000);

            uint elapsedSeconds = Convert.ToUInt32((DateTime.UtcNow - _recordExpiryTimerStartedOn).TotalSeconds);
            if (elapsedSeconds >= _recordExpiryTimerTtl)
                return 0u;

            uint pendingExpiryTtl = _recordExpiryTimerTtl - elapsedSeconds;

            return Math.Min(Math.Min(pendingExpiryTtl, minExpiryTtl), uint.MaxValue / 1000);
        }

        public void StartRecordExpiryTimer(uint minExpiryTtl)
        {
            lock (_recordExpiryTimerLock)
            {
                if (_recordExpiryTimer is not null)
                {
                    uint minTtl = GetMinRecordExpiryTtl(minExpiryTtl);

                    _recordExpiryTimer.Change(minTtl * 1000, Timeout.Infinite);
                    _recordExpiryTimerStartedOn = DateTime.UtcNow;
                    _recordExpiryTimerTtl = minTtl;
                    _recordExpiryTimerRunning = true;
                }
            }
        }

        private void RecordExpiryTimerCallback(object state)
        {
            _recordExpiryTimerRunning = false;
            uint minExpiryTtl = 0u;

            try
            {
                IReadOnlyList<AuthZone> authZones = _dnsServer.AuthZoneManager.GetApexZoneWithSubDomainZones(_name);
                bool recordsDeleted = false;

                foreach (AuthZone authZone in authZones)
                {
                    foreach (KeyValuePair<DnsResourceRecordType, IReadOnlyList<DnsResourceRecord>> entry in authZone.Entries)
                    {
                        foreach (DnsResourceRecord record in entry.Value)
                        {
                            GenericRecordInfo recordInfo = record.GetAuthGenericRecordInfo();
                            if (recordInfo.ExpiryTtl > 0u)
                            {
                                uint pendingExpiryTtl = recordInfo.GetPendingExpiryTtl();
                                if (pendingExpiryTtl == 0u)
                                {
                                    if (_dnsServer.AuthZoneManager.DeleteRecord(_name, record))
                                        recordsDeleted = true;
                                }
                                else
                                {
                                    if (minExpiryTtl == 0u)
                                        minExpiryTtl = pendingExpiryTtl;
                                    else
                                        minExpiryTtl = Math.Min(minExpiryTtl, pendingExpiryTtl);
                                }
                            }
                        }
                    }
                }

                if (recordsDeleted)
                    _dnsServer.AuthZoneManager.SaveZoneFile(_name);
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }
            finally
            {
                if (minExpiryTtl > 0u)
                    StartRecordExpiryTimer(minExpiryTtl);
            }
        }

        #endregion

        #region internal

        internal void CommitChanges(IReadOnlyList<DnsResourceRecord> addedRecords = null)
        {
            _lastModified = DateTime.UtcNow;

            if (addedRecords is null)
                return;

            uint minExpiryTtl = 0u;

            foreach (DnsResourceRecord addedRecord in addedRecords)
            {
                uint expiryTtl = addedRecord.GetAuthGenericRecordInfo().ExpiryTtl;
                if (expiryTtl > 0u)
                {
                    if (minExpiryTtl == 0u)
                        minExpiryTtl = expiryTtl;
                    else
                        minExpiryTtl = Math.Min(minExpiryTtl, expiryTtl);
                }
            }

            if (minExpiryTtl > 0u)
                StartRecordExpiryTimer(minExpiryTtl);
        }

        #endregion

        #region public

        public uint GetZoneSoaExpire()
        {
            return (_entries[DnsResourceRecordType.SOA][0].RDATA as DnsSOARecordData).Expire;
        }

        public abstract string GetZoneTypeName();

        public override string ToString()
        {
            return _name.Length == 0 ? "<root>" : _name;
        }

        #endregion

        #region properties

        public DateTime LastModified
        { get { return _lastModified; } }

        public virtual AuthZoneQueryAccess QueryAccess
        {
            get { return _queryAccess; }
            set { _queryAccess = value; }
        }

        public IReadOnlyCollection<NetworkAccessControl> QueryAccessNetworkACL
        {
            get { return _queryAccessNetworkACL; }
            set
            {
                if ((value is null) || (value.Count == 0))
                    _queryAccessNetworkACL = null;
                else if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(QueryAccessNetworkACL), "Network ACL cannot have more than 255 entries.");
                else
                    _queryAccessNetworkACL = value;
            }
        }

        #endregion
    }
}
