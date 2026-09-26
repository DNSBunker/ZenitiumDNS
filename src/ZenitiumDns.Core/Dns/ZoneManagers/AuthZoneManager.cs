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
using ZenitiumDns.Core.Dns.Trees;
using ZenitiumDns.Core.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using ZenitiumLibrary.IO;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.ZoneManagers
{
    public sealed class AuthZoneManager : IDisposable
    {
        #region variables

        readonly DnsServer _dnsServer;

        uint _defaultRecordTtl = 3600;
        uint _defaultNsRecordTtl = 14400;
        uint _defaultSoaRecordTtl = 900;

        readonly AuthZoneTree _root = new AuthZoneTree();

        readonly List<AuthZoneInfo> _zoneIndex = new List<AuthZoneInfo>(10);
        readonly ReaderWriterLockSlim _zoneIndexLock = new ReaderWriterLockSlim();

        readonly Lock _saveLock = new Lock();
        readonly Dictionary<string, object> _pendingSaveZones = new Dictionary<string, object>();
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        #endregion

        #region constructor

        public AuthZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _saveTimer = new Timer(delegate (object state)
            {
                SavePendingZoneFiles();
            });
        }

        #endregion

        #region IDisposable

        bool _disposed;

        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                lock (_saveLock)
                {
                    _saveTimer?.Dispose();

                    try
                    {
                        foreach (KeyValuePair<string, object> pendingSaveZone in _pendingSaveZones)
                        {
                            try
                            {
                                SaveZoneFileInternal(pendingSaveZone.Key);
                            }
                            catch (Exception ex)
                            {
                                _dnsServer.LogManager.Write(ex);
                            }
                        }
                    }
                    finally
                    {
                        _pendingSaveZones.Clear();
                    }
                }

                foreach (AuthZoneNode zoneNode in _root)
                    zoneNode.Dispose();

                _zoneIndexLock.Dispose();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        #endregion

        #region zone file serialization and loading

        public void LoadAllZoneFiles()
        {
            string zonesFolder = Path.Combine(_dnsServer.ConfigFolder, "zones");
            if (!Directory.Exists(zonesFolder))
                Directory.CreateDirectory(zonesFolder);

            {
                string[] oldZoneFiles = ["localhost.zone", "1.0.0.127.in-addr.arpa.zone", "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.zone"];

                foreach (string oldZoneFile in oldZoneFiles)
                {
                    string filePath = Path.Combine(zonesFolder, oldZoneFile);

                    if (File.Exists(filePath))
                    {
                        try
                        {
                            File.Delete(filePath);
                        }
                        catch
                        { }
                    }
                }
            }

            Flush();

            _zoneIndexLock.EnterWriteLock();
            try
            {
                string[] zoneFiles = Directory.GetFiles(zonesFolder, "*.zone", SearchOption.TopDirectoryOnly);

                foreach (string zoneFile in zoneFiles)
                {
                    try
                    {
                        using (FileStream fS = new FileStream(zoneFile, FileMode.Open, FileAccess.Read))
                        {
                            AuthZoneInfo zoneInfo = LoadZoneFrom(fS, File.GetLastWriteTimeUtc(fS.SafeFileHandle));
                            _zoneIndex.Add(zoneInfo);
                        }

                        _dnsServer.LogManager.Write("DNS Server successfully loaded zone file: " + zoneFile);
                    }
                    catch (NotSupportedException ex)
                    {
                        _dnsServer.LogManager.Write("DNS Server skipped zone file: " + zoneFile + "\r\n" + ex.Message);
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write("DNS Server failed to load zone file: " + zoneFile, ex);
                    }
                }

                _zoneIndex.Sort();
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        private void SaveZoneFileInternal(string zoneName)
        {
            zoneName = zoneName.ToLowerInvariant();

            string tmpZoneFile = Path.Combine(_dnsServer.ConfigFolder, "zones", zoneName + ".tmp");
            string zoneFile = Path.Combine(_dnsServer.ConfigFolder, "zones", zoneName + ".zone");

            using (FileStream fS = new FileStream(tmpZoneFile, FileMode.Create, FileAccess.Write))
            {
                WriteZoneTo(zoneName, fS);

                if (fS.Position == 0)
                {
                    fS.Dispose();

                    try
                    {
                        File.Delete(tmpZoneFile);
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }

                    return;
                }
            }

            File.Move(tmpZoneFile, zoneFile, true);

            _dnsServer.LogManager.Write("Saved zone file for domain: " + (zoneName == "" ? "<root>" : zoneName));
        }

        public void SavePendingZoneFiles()
        {
            lock (_saveLock)
            {
                if (_disposed)
                    return;

                List<string> failedZones = new List<string>();

                foreach (KeyValuePair<string, object> pendingSaveZone in _pendingSaveZones)
                {
                    try
                    {
                        SaveZoneFileInternal(pendingSaveZone.Key);
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);

                        failedZones.Add(pendingSaveZone.Key);
                    }
                }

                _pendingSaveZones.Clear();

                foreach (string zoneName in failedZones)
                    _pendingSaveZones.TryAdd(zoneName, null);

                if (_pendingSaveZones.Count > 0)
                    _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        public void SaveZoneFile(string zoneName)
        {
            zoneName = zoneName.ToLowerInvariant();

            lock (_saveLock)
            {
                if (!_pendingSaveZones.TryAdd(zoneName, null))
                    return;

                if (_pendingSaveZones.Count == 1)
                    _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private static uint GetMinExpiryTtlFor(IReadOnlyList<DnsResourceRecord> records)
        {
            uint minExpiryTtl = 0u;

            foreach (DnsResourceRecord record in records)
            {
                GenericRecordInfo recordInfo = record.GetAuthGenericRecordInfo();
                if (recordInfo.ExpiryTtl > 0u)
                {
                    uint pendingExpiryTtl = recordInfo.GetPendingExpiryTtl();
                    if (pendingExpiryTtl == 0)
                    {
                        minExpiryTtl = 10;
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

            return minExpiryTtl;
        }

        private void LoadAndInitZone(AuthZoneInfo zoneInfo, IReadOnlyList<DnsResourceRecord> records)
        {
            ApexZone apexZone = zoneInfo.ApexZone;

            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> zoneEntry in DnsResourceRecord.GroupRecords(records))
            {
                if (apexZone.Name.Equals(zoneEntry.Key, StringComparison.OrdinalIgnoreCase))
                {
                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                    {
                        if (rrsetEntry.Key == DnsResourceRecordType.SOA)
                            continue;

                        apexZone.LoadRecords(rrsetEntry.Key, rrsetEntry.Value);
                    }
                }
                else
                {
                    ValidateIfDomainBelongsToZone(apexZone.Name, zoneEntry.Key);

                    AuthZone authZone = GetOrAddSubDomainZone(apexZone.Name, zoneEntry.Key);

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                        authZone.LoadRecords(rrsetEntry.Key, rrsetEntry.Value);

                    if (authZone is SubDomainZone subDomainZone)
                        subDomainZone.AutoUpdateState();
                }
            }

            uint minExpiryTtl = GetMinExpiryTtlFor(records);
            if (minExpiryTtl > 0u)
                apexZone.StartRecordExpiryTimer(minExpiryTtl);
        }

        public AuthZoneInfo LoadZoneFrom(Stream s, DateTime lastModified)
        {
            if (Encoding.ASCII.GetString(s.ReadExactly(2)) != "DZ")
                throw new InvalidDataException("DnsServer zone file format is invalid.");

            BinaryReader bR = new BinaryReader(s);

            switch (bR.ReadByte())
            {
                case 2:
                case 3:
                    throw new NotSupportedException("Authoritative zones are not supported by ZenitiumDNS. Only Conditional Forwarder zones are supported.");

                case 4:
                    {
                        AuthZoneInfo zoneInfo = new AuthZoneInfo(bR, lastModified);

                        ApexZone apexZone = CreateEmptyApexZone(zoneInfo);
                        zoneInfo = new AuthZoneInfo(apexZone);

                        try
                        {
                            DnsResourceRecord[] records = new DnsResourceRecord[bR.ReadInt32()];

                            for (int i = 0; i < records.Length; i++)
                            {
                                records[i] = new DnsResourceRecord(s);
                                records[i].Tag = AuthRecordInfo.ReadGenericRecordInfoFrom(bR, records[i].Type);
                            }

                            LoadAndInitZone(zoneInfo, records);
                        }
                        catch
                        {
                            if (_root.TryRemove(zoneInfo.Name, out ApexZone removedApexZone))
                                removedApexZone.Dispose();

                            throw;
                        }

                        return zoneInfo;
                    }

                default:
                    throw new InvalidDataException("DNS Zone file version not supported.");
            }
        }

        public void WriteZoneTo(string zoneName, Stream s)
        {
            AuthZoneInfo zoneInfo = GetAuthZoneInfo(zoneName);
            if ((zoneInfo is null) || (zoneInfo.Type != AuthZoneType.Forwarder))
                return;

            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("DZ"));
            bW.Write((byte)4);

            zoneInfo.WriteTo(bW);

            List<DnsResourceRecord> records = new List<DnsResourceRecord>();
            ListAllZoneRecords(zoneInfo.Name, records);

            bW.Write(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                record.WriteTo(s);
                record.GetAuthGenericRecordInfo().WriteTo(bW);
            }
        }

        #endregion

        #region internal

        internal static string GetParentZone(string domain)
        {
            int i = domain.IndexOf('.');
            if (i > -1)
                return domain.Substring(i + 1);

            return null;
        }

        internal static bool DomainBelongsToZone(string zoneName, string domain)
        {
            return domain.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || domain.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase) || (zoneName.Length == 0);
        }

        internal static void ValidateIfDomainBelongsToZone(string zoneName, string domain)
        {
            if (!DomainBelongsToZone(zoneName, domain))
                throw new DnsServerException("The domain name '" + domain + "' does not belong to the zone: " + zoneName);
        }

        #endregion

        #region auth zone tree methods

        private ApexZone CreateEmptyApexZone(AuthZoneInfo zoneInfo)
        {
            if (zoneInfo.Type != AuthZoneType.Forwarder)
                throw new InvalidDataException("DNS zone type not supported.");

            ApexZone apexZone = new ForwarderZone(_dnsServer, zoneInfo);

            if (_root.TryAdd(apexZone))
                return apexZone;

            throw new DnsServerException("Zone already exists: " + zoneInfo.DisplayName);
        }

        internal AuthZone GetOrAddSubDomainZone(string zoneName, string domain)
        {
            return _root.GetOrAddSubDomainZone(zoneName, domain, delegate ()
            {
                if (!_root.TryGet(zoneName, out ApexZone apexZone))
                    throw new DnsServerException("Zone was not found for domain: " + domain);

                if (apexZone is PrimaryZone primaryZone)
                    return new PrimarySubDomainZone(primaryZone, domain);
                else if (apexZone is ForwarderZone forwarderZone)
                    return new ForwarderSubDomainZone(forwarderZone, domain);

                throw new DnsServerException("Zone cannot have sub domains.");
            });
        }

        internal IReadOnlyList<AuthZone> GetApexZoneWithSubDomainZones(string zoneName)
        {
            return _root.GetApexZoneWithSubDomainZones(zoneName);
        }

        public AuthZoneInfo GetAuthZoneInfo(string zoneName)
        {
            if (_root.TryGet(zoneName, out AuthZoneNode authZoneNode) && (authZoneNode.ApexZone is not null))
                return new AuthZoneInfo(authZoneNode.ApexZone);

            return null;
        }

        public AuthZoneInfo FindAuthZoneInfo(string domain)
        {
            _ = _root.FindZone(domain, out _, out _, out ApexZone apexZone, out _);
            if (apexZone is null)
                return null;

            return new AuthZoneInfo(apexZone);
        }

        internal ApexZone FindApexZone(string domain)
        {
            _ = _root.FindZone(domain, out _, out _, out ApexZone apexZone, out _);
            return apexZone;
        }

        internal AuthZone GetAuthZone(string zoneName, string domain)
        {
            return _root.GetAuthZone(zoneName, domain);
        }

        public void ListSubDomains(string domain, List<string> subDomains)
        {
            _root.ListSubDomains(domain, subDomains);
        }

        internal void Flush()
        {
            _zoneIndexLock.EnterWriteLock();
            try
            {
                foreach (AuthZoneNode zoneNode in _root)
                    zoneNode.Dispose();

                _root.Clear();
                _zoneIndex.Clear();
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        #endregion

        #region zone create / delete / clone

        private static void ValidateZoneName(string zoneName)
        {
            if (zoneName.Contains('*'))
                throw new DnsWebServiceException("Domain name for a zone cannot contain wildcard character.");

            foreach (char invalidChar in Path.GetInvalidFileNameChars())
            {
                if (zoneName.Contains(invalidChar))
                    throw new DnsWebServiceException("The zone name contains an invalid character: " + invalidChar);
            }
        }

        private AuthZoneInfo AddApexZone(ApexZone apexZone, bool saveZoneFile)
        {
            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryAdd(apexZone))
                {
                    AuthZoneInfo zoneInfo = new AuthZoneInfo(apexZone);
                    _zoneIndex.Add(zoneInfo);
                    _zoneIndex.Sort();

                    if (saveZoneFile)
                        SaveZoneFile(zoneInfo.Name);

                    return zoneInfo;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            apexZone.Dispose();
            return null;
        }

        internal AuthZoneInfo CreateSpecialPrimaryZone(string zoneName, DnsSOARecordData soaRecord, DnsNSRecordData ns)
        {
            return AddApexZone(new PrimaryZone(_dnsServer, zoneName, soaRecord, ns), false);
        }

        internal void LoadSpecialPrimaryZones(IReadOnlyList<string> zoneNames, DnsSOARecordData soaRecord, DnsNSRecordData ns)
        {
            _zoneIndexLock.EnterWriteLock();
            try
            {
                foreach (string zoneName in zoneNames)
                {
                    PrimaryZone apexZone = new PrimaryZone(_dnsServer, zoneName, soaRecord, ns);

                    if (_root.TryAdd(apexZone))
                        _zoneIndex.Add(new AuthZoneInfo(apexZone));
                }

                _zoneIndex.Sort();
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        internal void LoadSpecialPrimaryZones(Func<string> getZoneName, DnsSOARecordData soaRecord, DnsNSRecordData ns)
        {
            _zoneIndexLock.EnterWriteLock();
            try
            {
                string zoneName;

                while (true)
                {
                    zoneName = getZoneName();
                    if (zoneName is null)
                        break;

                    PrimaryZone apexZone = new PrimaryZone(_dnsServer, zoneName, soaRecord, ns);

                    if (_root.TryAdd(apexZone))
                        _zoneIndex.Add(new AuthZoneInfo(apexZone));
                }

                _zoneIndex.Sort();
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }
        }

        public AuthZoneInfo CreateForwarderZone(string zoneName)
        {
            ValidateZoneName(zoneName);

            return AddApexZone(new ForwarderZone(_dnsServer, zoneName), true);
        }

        public AuthZoneInfo CreateForwarderZone(string zoneName, DnsTransportProtocol forwarderProtocol, string forwarder, bool dnssecValidation, DnsForwarderRecordProxyType proxyType, string proxyAddress, ushort proxyPort, string proxyUsername, string proxyPassword, string fwdRecordComments)
        {
            ValidateZoneName(zoneName);

            return AddApexZone(new ForwarderZone(_dnsServer, zoneName, forwarderProtocol, forwarder, dnssecValidation, proxyType, proxyAddress, proxyPort, proxyUsername, proxyPassword, fwdRecordComments), true);
        }

        public bool DeleteZone(string zoneName, bool deleteZoneFile = false)
        {
            AuthZoneInfo zoneInfo = GetAuthZoneInfo(zoneName);
            if (zoneInfo is null)
                return false;

            return DeleteZone(zoneInfo, deleteZoneFile);
        }

        public bool DeleteZone(AuthZoneInfo zoneInfo, bool deleteZoneFile = false)
        {
            _zoneIndexLock.EnterWriteLock();
            try
            {
                if (_root.TryRemove(zoneInfo.Name, out ApexZone removedApexZone))
                {
                    removedApexZone.Dispose();

                    _zoneIndex.Remove(zoneInfo);

                    if (deleteZoneFile)
                    {
                        File.Delete(Path.Combine(_dnsServer.ConfigFolder, "zones", zoneInfo.Name + ".zone"));

                        _dnsServer.LogManager.Write("Deleted zone file for domain: " + zoneInfo.DisplayName);
                    }

                    return true;
                }
            }
            finally
            {
                _zoneIndexLock.ExitWriteLock();
            }

            return false;
        }

        public AuthZoneInfo CloneZone(string zoneName, string sourceZoneName)
        {
            AuthZoneInfo sourceZoneInfo = GetAuthZoneInfo(sourceZoneName);
            if (sourceZoneInfo is null)
                throw new DnsServerException("No such zone was found: " + (sourceZoneName.Length == 0 ? "." : sourceZoneName));

            if (sourceZoneInfo.Type != AuthZoneType.Forwarder)
                throw new DnsServerException("Cannot clone the zone: source zone must be a Conditional Forwarder zone.");

            AuthZoneInfo zoneInfo = CreateForwarderZone(zoneName);
            if (zoneInfo is null)
                throw new DnsServerException("Failed to clone the zone: zone already exists.");

            zoneInfo.Disabled = sourceZoneInfo.Disabled;
            zoneInfo.QueryAccess = sourceZoneInfo.QueryAccess;
            zoneInfo.QueryAccessNetworkACL = sourceZoneInfo.QueryAccessNetworkACL;

            List<DnsResourceRecord> sourceRecords = new List<DnsResourceRecord>();
            ListAllZoneRecords(sourceZoneName, sourceRecords);

            List<DnsResourceRecord> newRecords = new List<DnsResourceRecord>(sourceRecords.Count);

            foreach (DnsResourceRecord sourceRecord in sourceRecords)
            {
                if (sourceRecord.Type == DnsResourceRecordType.SOA)
                    continue;

                DnsResourceRecord newRecord = new DnsResourceRecord(string.Concat(sourceRecord.Name.AsSpan(0, sourceRecord.Name.Length - sourceZoneName.Length), zoneName), sourceRecord.Type, sourceRecord.Class, sourceRecord.TTL, sourceRecord.RDATA);

                if (sourceRecord.Tag is NSRecordInfo nsInfo)
                {
                    NSRecordInfo nrInfo = new NSRecordInfo();

                    nrInfo.Disabled = nsInfo.Disabled;
                    nrInfo.Comments = nsInfo.Comments;
                    nrInfo.GlueRecords = nsInfo.GlueRecords;

                    newRecord.Tag = nrInfo;
                }
                else if (sourceRecord.Tag is SVCBRecordInfo svcbInfo)
                {
                    SVCBRecordInfo nrInfo = new SVCBRecordInfo();

                    nrInfo.Disabled = svcbInfo.Disabled;
                    nrInfo.Comments = svcbInfo.Comments;
                    nrInfo.AutoIpv4Hint = svcbInfo.AutoIpv4Hint;
                    nrInfo.AutoIpv6Hint = svcbInfo.AutoIpv6Hint;

                    newRecord.Tag = nrInfo;
                }
                else if (sourceRecord.Tag is GenericRecordInfo srInfo)
                {
                    GenericRecordInfo nrInfo = new GenericRecordInfo();

                    nrInfo.Disabled = srInfo.Disabled;
                    nrInfo.Comments = srInfo.Comments;

                    newRecord.Tag = nrInfo;
                }

                newRecords.Add(newRecord);
            }

            LoadAndInitZone(zoneInfo, newRecords);

            SaveZoneFile(zoneInfo.Name);

            return zoneInfo;
        }

        #endregion

        #region zone listing

        public IReadOnlyList<AuthZoneInfo> GetAllZones()
        {
            _zoneIndexLock.EnterReadLock();
            try
            {
                return _zoneIndex.ToArray();
            }
            finally
            {
                _zoneIndexLock.ExitReadLock();
            }
        }

        public IReadOnlyList<AuthZoneInfo> GetZones(Func<AuthZoneInfo, bool> predicate)
        {
            _zoneIndexLock.EnterReadLock();
            try
            {
                List<AuthZoneInfo> zoneInfoList = new List<AuthZoneInfo>();

                foreach (AuthZoneInfo zoneInfo in _zoneIndex)
                {
                    if (predicate(zoneInfo))
                        zoneInfoList.Add(zoneInfo);
                }

                return zoneInfoList;
            }
            finally
            {
                _zoneIndexLock.ExitReadLock();
            }
        }

        #endregion

        #region zone record management

        public void ListAllZoneRecords(string zoneName, List<DnsResourceRecord> records)
        {
            foreach (AuthZone authZone in _root.GetApexZoneWithSubDomainZones(zoneName))
                authZone.ListAllRecords(records);
        }

        public void ListAllZoneRecords(string zoneName, DnsResourceRecordType[] types, List<DnsResourceRecord> records)
        {
            foreach (AuthZone authZone in _root.GetApexZoneWithSubDomainZones(zoneName))
            {
                foreach (DnsResourceRecordType type in types)
                    records.AddRange(authZone.GetRecords(type));
            }
        }

        public void ListAllRecords(string zoneName, string domain, List<DnsResourceRecord> records)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (_root.TryGet(zoneName, domain, out AuthZone authZone))
                authZone.ListAllRecords(records);
        }

        public IReadOnlyList<DnsResourceRecord> GetRecords(string zoneName, string domain, DnsResourceRecordType type)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (_root.TryGet(zoneName, domain, out AuthZone authZone))
                return authZone.GetRecords(type);

            return Array.Empty<DnsResourceRecord>();
        }

        private void AutoUpdateOrRemoveSubDomainZone(AuthZone authZone)
        {
            if (authZone is SubDomainZone subDomainZone)
            {
                if (authZone.IsEmpty)
                    _root.TryRemove(authZone.Name, out SubDomainZone _);
                else
                    subDomainZone.AutoUpdateState();
            }
        }

        public void SetRecords(string zoneName, IReadOnlyList<DnsResourceRecord> records)
        {
            for (int i = 1; i < records.Count; i++)
            {
                if (!records[i].Name.Equals(records[0].Name, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidOperationException();

                if (records[i].Type != records[0].Type)
                    throw new InvalidOperationException();

                if (records[i].Class != records[0].Class)
                    throw new InvalidOperationException();
            }

            ValidateIfDomainBelongsToZone(zoneName, records[0].Name);

            AuthZone authZone = GetOrAddSubDomainZone(zoneName, records[0].Name);

            authZone.SetRecords(records[0].Type, records);

            if (authZone is SubDomainZone subDomainZone)
                subDomainZone.AutoUpdateState();
        }

        public void SetRecord(string zoneName, DnsResourceRecord record)
        {
            SetRecords(zoneName, [record]);
        }

        public bool AddRecord(string zoneName, DnsResourceRecord record)
        {
            ValidateIfDomainBelongsToZone(zoneName, record.Name);

            AuthZone authZone = GetOrAddSubDomainZone(zoneName, record.Name);

            if (authZone.AddRecord(record))
            {
                if (authZone is SubDomainZone subDomainZone)
                    subDomainZone.AutoUpdateState();

                return true;
            }

            return false;
        }

        public void UpdateRecord(string zoneName, DnsResourceRecord oldRecord, DnsResourceRecord newRecord)
        {
            ValidateIfDomainBelongsToZone(zoneName, oldRecord.Name);
            ValidateIfDomainBelongsToZone(zoneName, newRecord.Name);

            if (oldRecord.Type != newRecord.Type)
                throw new DnsServerException("Cannot update record: new record must be of same type.");

            if (oldRecord.Type == DnsResourceRecordType.SOA)
                throw new DnsServerException("Cannot update record: the SOA record cannot be modified.");

            if (!_root.TryGet(zoneName, oldRecord.Name, out AuthZone authZone))
                throw new DnsServerException("Cannot update record: zone '" + zoneName + "' does not exists.");

            bool sameName = oldRecord.Name.Equals(newRecord.Name, StringComparison.OrdinalIgnoreCase);

            switch (oldRecord.Type)
            {
                case DnsResourceRecordType.CNAME:
                case DnsResourceRecordType.DNAME:
                case DnsResourceRecordType.APP:
                    if (sameName)
                    {
                        authZone.SetRecords(newRecord.Type, [newRecord]);

                        if (authZone is SubDomainZone subDomainZone)
                            subDomainZone.AutoUpdateState();
                    }
                    else
                    {
                        authZone.DeleteRecords(oldRecord.Type);
                        AutoUpdateOrRemoveSubDomainZone(authZone);

                        AuthZone newZone = GetOrAddSubDomainZone(zoneName, newRecord.Name);

                        newZone.SetRecords(newRecord.Type, [newRecord]);

                        if (newZone is SubDomainZone newSubDomainZone)
                            newSubDomainZone.AutoUpdateState();
                    }
                    break;

                default:
                    if (sameName)
                    {
                        authZone.UpdateRecord(oldRecord, newRecord);

                        if (authZone is SubDomainZone subDomainZone)
                            subDomainZone.AutoUpdateState();
                    }
                    else
                    {
                        if (!authZone.DeleteRecord(oldRecord.Type, oldRecord.RDATA))
                            throw new DnsWebServiceException("Cannot update record: the old record does not exists.");

                        AutoUpdateOrRemoveSubDomainZone(authZone);

                        AuthZone newZone = GetOrAddSubDomainZone(zoneName, newRecord.Name);

                        newZone.AddRecord(newRecord);

                        if (newZone is SubDomainZone newSubDomainZone)
                            newSubDomainZone.AutoUpdateState();
                    }
                    break;
            }
        }

        public bool DeleteRecord(string zoneName, DnsResourceRecord record)
        {
            return DeleteRecord(zoneName, record.Name, record.Type, record.RDATA);
        }

        public bool DeleteRecord(string zoneName, string domain, DnsResourceRecordType type, DnsResourceRecordData rdata)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (_root.TryGet(zoneName, domain, out AuthZone authZone) && authZone.DeleteRecord(type, rdata))
            {
                AutoUpdateOrRemoveSubDomainZone(authZone);
                return true;
            }

            return false;
        }

        public bool DeleteRecords(string zoneName, string domain, DnsResourceRecordType type)
        {
            ValidateIfDomainBelongsToZone(zoneName, domain);

            if (_root.TryGet(zoneName, domain, out AuthZone authZone) && authZone.DeleteRecords(type))
            {
                AutoUpdateOrRemoveSubDomainZone(authZone);
                return true;
            }

            return false;
        }

        public void DeleteAllRecords(string zoneName)
        {
            foreach (AuthZone authZone in _root.GetApexZoneWithSubDomainZones(zoneName))
            {
                foreach (DnsResourceRecordType recordType in authZone.Entries.Keys)
                {
                    if (recordType == DnsResourceRecordType.SOA)
                        continue;

                    authZone.DeleteRecords(recordType);
                }

                AutoUpdateOrRemoveSubDomainZone(authZone);
            }
        }

        internal void ImportRecords(string zoneName, IReadOnlyList<DnsResourceRecord> records, bool overwriteRecords, bool overwriteZone)
        {
            _ = _root.FindZone(zoneName, out _, out _, out ApexZone apexZone, out _);
            if ((apexZone is null) || !apexZone.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                throw new DnsServerException("No such zone was found: " + zoneName);

            if (apexZone is not ForwarderZone)
                throw new DnsServerException("Zone must be a Conditional Forwarder zone: " + apexZone.ToString());

            if (overwriteZone)
            {
                DeleteAllRecords(zoneName);
                overwriteRecords = true;
            }

            foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> zoneEntry in DnsResourceRecord.GroupRecords(records))
            {
                ValidateIfDomainBelongsToZone(zoneName, zoneEntry.Key);

                AuthZone authZone = GetOrAddSubDomainZone(zoneName, zoneEntry.Key);

                foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> rrsetEntry in zoneEntry.Value)
                {
                    switch (rrsetEntry.Key)
                    {
                        case DnsResourceRecordType.SOA:
                            break;

                        case DnsResourceRecordType.CNAME:
                        case DnsResourceRecordType.DNAME:
                            authZone.SetRecords(rrsetEntry.Key, rrsetEntry.Value);
                            break;

                        default:
                            if (overwriteRecords)
                            {
                                authZone.SetRecords(rrsetEntry.Key, rrsetEntry.Value);
                            }
                            else
                            {
                                foreach (DnsResourceRecord record in rrsetEntry.Value)
                                    authZone.AddRecord(record);
                            }
                            break;
                    }
                }

                AutoUpdateOrRemoveSubDomainZone(authZone);
            }

            SaveZoneFile(apexZone.Name);
        }

        #endregion

        #region query processing

        public DnsDatagram QueryClosestDelegation(DnsDatagram request)
        {
            _ = _root.FindZone(request.Question[0].Name, out _, out SubDomainZone delegation, out _, out _);
            if (delegation is not null)
                return GetReferralResponse(request, delegation);

            return null;
        }

        public DnsDatagram Query(DnsDatagram request, IPAddress remoteIP, bool isRecursionAllowed)
        {
            AuthZone zone = _root.FindZone(request.Question[0].Name, out SubDomainZone closest, out SubDomainZone delegation, out ApexZone apexZone, out bool hasSubDomains);

            if ((apexZone is null) || !apexZone.IsActive)
                return null;

            if (!IsQueryAllowed(apexZone, remoteIP))
                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.Refused, request.Question);

            return InternalQuery(request, isRecursionAllowed, zone, closest, delegation, apexZone, hasSubDomains);
        }

        public DnsDatagram Query(DnsDatagram request, bool isRecursionAllowed)
        {
            AuthZone zone = _root.FindZone(request.Question[0].Name, out SubDomainZone closest, out SubDomainZone delegation, out ApexZone apexZone, out bool hasSubDomains);

            if ((apexZone is null) || !apexZone.IsActive)
                return null;

            return InternalQuery(request, isRecursionAllowed, zone, closest, delegation, apexZone, hasSubDomains);
        }

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        private DnsDatagram InternalQuery(DnsDatagram request, bool isRecursionAllowed, AuthZone zone, SubDomainZone closest, SubDomainZone delegation, ApexZone apexZone, bool hasSubDomains)
        {
            DnsQuestionRecord question = request.Question[0];

            if ((zone is null) || !zone.IsActive)
            {
                if ((delegation is not null) && delegation.IsActive && (delegation.Name.Length > apexZone.Name.Length))
                    return GetReferralResponse(request, delegation);

                DnsResponseCode rCode = DnsResponseCode.NoError;
                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;

                if (closest is not null)
                {
                    answer = closest.QueryRecords(DnsResourceRecordType.DNAME);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                    else
                    {
                        answer = null;
                        authority = closest.QueryRecords(DnsResourceRecordType.APP);
                    }
                }

                if (((answer is null) || (answer.Count == 0)) && ((authority is null) || (authority.Count == 0)))
                {
                    answer = apexZone.QueryRecords(DnsResourceRecordType.DNAME);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                    else
                    {
                        answer = null;
                        authority = apexZone.QueryRecords(DnsResourceRecordType.APP);
                        if (authority.Count == 0)
                        {
                            if (apexZone is ForwarderZone)
                                return GetForwarderResponse(request, null, closest, apexZone);

                            if (!hasSubDomains)
                                rCode = DnsResponseCode.NxDomain;

                            authority = apexZone.QueryRecords(DnsResourceRecordType.SOA);
                        }
                    }
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, rCode, request.Question, answer, authority);
            }
            else
            {
                if (question.Type == DnsResourceRecordType.DS)
                {
                    if (zone is ApexZone)
                    {
                        if ((delegation is null) || !delegation.IsActive || !delegation.AuthoritativeZone.IsActive || (delegation.Name.Length > apexZone.Name.Length))
                            return null;

                        zone = delegation;
                    }
                }
                else if ((delegation is not null) && delegation.IsActive && (delegation.Name.Length > apexZone.Name.Length))
                {
                    return GetReferralResponse(request, delegation);
                }

                DnsResponseCode rCode = DnsResponseCode.NoError;
                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;
                IReadOnlyList<DnsResourceRecord> additional = null;

                if (closest is not null)
                {
                    answer = closest.QueryRecords(DnsResourceRecordType.DNAME);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                }

                if (((answer is null) || (answer.Count == 0)) && (question.Name.Length > apexZone.Name.Length))
                {
                    answer = apexZone.QueryRecords(DnsResourceRecordType.DNAME);
                    if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                    {
                        if (!DoDNAMESubstitution(question, answer, out answer))
                            rCode = DnsResponseCode.YXDomain;
                    }
                }

                if ((answer is null) || (answer.Count == 0))
                {
                    answer = zone.QueryRecords(question.Type);
                    if (answer.Count == 0)
                    {
                        if (question.Type == DnsResourceRecordType.DS)
                        {
                            if (apexZone.Name.Equals(question.Name, StringComparison.OrdinalIgnoreCase))
                            {
                                string parentZone = GetParentZone(question.Name) ?? string.Empty;

                                _ = _root.FindZone(parentZone, out _, out _, out apexZone, out _);

                                if ((apexZone is null) || !apexZone.IsActive)
                                    return null;
                            }
                        }
                        else if ((delegation is not null) && delegation.IsActive && (delegation.Name.Length > apexZone.Name.Length))
                        {
                            return GetReferralResponse(request, delegation);
                        }

                        authority = zone.QueryRecords(DnsResourceRecordType.APP);
                        if (authority.Count == 0)
                        {
                            if (apexZone is ForwarderZone)
                                return GetForwarderResponse(request, zone, closest, apexZone);

                            authority = apexZone.QueryRecords(DnsResourceRecordType.SOA);
                        }
                    }
                    else
                    {
                        if (zone.Name.StartsWith('*') && !zone.Name.Equals(question.Name, StringComparison.OrdinalIgnoreCase))
                        {
                            DnsResourceRecord[] wildcardAnswers = new DnsResourceRecord[answer.Count];

                            for (int i = 0; i < answer.Count; i++)
                                wildcardAnswers[i] = new DnsResourceRecord(question.Name, answer[i].Type, answer[i].Class, answer[i].TTL, answer[i].RDATA) { Tag = answer[i].Tag };

                            answer = wildcardAnswers;
                        }

                        DnsResourceRecord lastRR = answer[answer.Count - 1];
                        if ((lastRR.Type != question.Type) && (question.Type != DnsResourceRecordType.ANY))
                        {
                            switch (lastRR.Type)
                            {
                                case DnsResourceRecordType.CNAME:
                                    List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(answer.Count + 1);
                                    newAnswers.AddRange(answer);

                                    ResolveCNAME(question, lastRR, newAnswers);

                                    answer = newAnswers;
                                    break;

                                case DnsResourceRecordType.ANAME:
                                case DnsResourceRecordType.ALIAS:
                                    authority = apexZone.GetRecords(DnsResourceRecordType.SOA);
                                    break;
                            }
                        }

                        switch (question.Type)
                        {
                            case DnsResourceRecordType.NS:
                            case DnsResourceRecordType.MX:
                            case DnsResourceRecordType.SRV:
                            case DnsResourceRecordType.SVCB:
                            case DnsResourceRecordType.HTTPS:
                                additional = GetAdditionalRecords(answer);
                                break;
                        }
                    }
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, isRecursionAllowed, false, false, rCode, request.Question, answer, authority, additional, _dnsServer.UdpPayloadSize);
            }
        }

        private static bool IsQueryAllowed(ApexZone apexZone, IPAddress remoteIP)
        {
            if (apexZone.QueryAccess == AuthZoneQueryAccess.Allow)
                return true;

            if (IPAddress.IsLoopback(remoteIP) || IPAddress.Any.Equals(remoteIP))
                return true;

            switch (apexZone.QueryAccess)
            {
                case AuthZoneQueryAccess.AllowOnlyPrivateNetworks:
                    switch (remoteIP.AddressFamily)
                    {
                        case AddressFamily.InterNetwork:
                        case AddressFamily.InterNetworkV6:
                            return NetUtilities.IsPrivateIP(remoteIP);

                        default:
                            return false;
                    }

                case AuthZoneQueryAccess.UseSpecifiedNetworkACL:
                case AuthZoneQueryAccess.AllowZoneNameServersAndUseSpecifiedNetworkACL:
                    return NetworkAccessControl.IsAddressAllowed(remoteIP, apexZone.QueryAccessNetworkACL);

                default:
                    return false;
            }
        }

        private void ResolveCNAME(DnsQuestionRecord question, DnsResourceRecord lastCNAME, List<DnsResourceRecord> answerRecords)
        {
            int queryCount = 0;

            do
            {
                string cnameDomain = (lastCNAME.RDATA as DnsCNAMERecordData).Domain;
                if (lastCNAME.Name.Equals(cnameDomain, StringComparison.OrdinalIgnoreCase))
                    break;

                if (!_root.TryGet(cnameDomain, out AuthZoneNode zoneNode))
                    break;

                IReadOnlyList<DnsResourceRecord> records = zoneNode.QueryRecords(question.Type);
                if (records.Count < 1)
                    break;

                DnsResourceRecord lastRR = records[records.Count - 1];
                if (lastRR.Type != DnsResourceRecordType.CNAME)
                {
                    answerRecords.AddRange(records);
                    break;
                }

                foreach (DnsResourceRecord answerRecord in answerRecords)
                {
                    if (answerRecord.Type != DnsResourceRecordType.CNAME)
                        continue;

                    if (answerRecord.RDATA.Equals(lastRR.RDATA))
                        return;
                }

                answerRecords.AddRange(records);

                lastCNAME = lastRR;
            }
            while (++queryCount < DnsServer.MAX_CNAME_HOPS);
        }

        private bool DoDNAMESubstitution(DnsQuestionRecord question, IReadOnlyList<DnsResourceRecord> answer, out IReadOnlyList<DnsResourceRecord> newAnswer)
        {
            DnsResourceRecord dnameRR = answer[0];

            string result = (dnameRR.RDATA as DnsDNAMERecordData).Substitute(question.Name, dnameRR.Name);

            if (DnsClient.IsDomainNameValid(result))
            {
                DnsResourceRecord cnameRR = new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, question.Class, dnameRR.TTL, new DnsCNAMERecordData(result));

                List<DnsResourceRecord> list = new List<DnsResourceRecord>(5);

                list.AddRange(answer);
                list.Add(cnameRR);

                ResolveCNAME(question, cnameRR, list);

                newAnswer = list;
                return true;
            }
            else
            {
                newAnswer = answer;
                return false;
            }
        }

        private List<DnsResourceRecord> GetAdditionalRecords(IReadOnlyList<DnsResourceRecord> refRecords)
        {
            List<DnsResourceRecord> additionalRecords = new List<DnsResourceRecord>(refRecords.Count);

            foreach (DnsResourceRecord refRecord in refRecords)
            {
                switch (refRecord.Type)
                {
                    case DnsResourceRecordType.NS:
                        IReadOnlyList<DnsResourceRecord> glueRecords = refRecord.GetAuthNSRecordInfo().GlueRecords;
                        if (glueRecords is not null)
                            additionalRecords.AddRange(glueRecords);
                        else
                            ResolveAdditionalRecords(refRecord, (refRecord.RDATA as DnsNSRecordData).NameServer, additionalRecords);

                        break;

                    case DnsResourceRecordType.MX:
                        ResolveAdditionalRecords(refRecord, (refRecord.RDATA as DnsMXRecordData).Exchange, additionalRecords);
                        break;

                    case DnsResourceRecordType.SRV:
                        ResolveAdditionalRecords(refRecord, (refRecord.RDATA as DnsSRVRecordData).Target, additionalRecords);
                        break;

                    case DnsResourceRecordType.SVCB:
                    case DnsResourceRecordType.HTTPS:
                        DnsSVCBRecordData svcb = refRecord.RDATA as DnsSVCBRecordData;
                        string targetName = svcb.TargetName;

                        if (svcb.SvcPriority == 0)
                        {
                            if ((targetName.Length == 0) || targetName.Equals(refRecord.Name, StringComparison.OrdinalIgnoreCase))
                                break;
                        }
                        else
                        {
                            if (targetName.Length == 0)
                                targetName = refRecord.Name;
                        }

                        ResolveAdditionalRecords(refRecord, targetName, additionalRecords);
                        break;
                }
            }

            return additionalRecords;
        }

        private void ResolveAdditionalRecords(DnsResourceRecord refRecord, string domain, List<DnsResourceRecord> additionalRecords)
        {
            int count = 0;

            while (count++ < DnsServer.MAX_CNAME_HOPS)
            {
                AuthZone zone = _root.FindZone(domain, out _, out _, out _, out _);
                if ((zone is null) || !zone.IsActive)
                    break;

                if (((refRecord.Type == DnsResourceRecordType.SVCB) || (refRecord.Type == DnsResourceRecordType.HTTPS)) && ((refRecord.RDATA as DnsSVCBRecordData).SvcPriority == 0))
                {
                    IReadOnlyList<DnsResourceRecord> records = zone.QueryRecordsWildcard(refRecord.Type, domain);
                    if ((records.Count > 0) && (records[0].Type == refRecord.Type) && (records[0].RDATA is DnsSVCBRecordData svcb))
                    {
                        additionalRecords.AddRange(records);

                        string targetName = svcb.TargetName;

                        if (svcb.SvcPriority == 0)
                        {
                            if ((targetName.Length == 0) || targetName.Equals(records[0].Name, StringComparison.OrdinalIgnoreCase))
                                break;

                            foreach (DnsResourceRecord additionalRecord in additionalRecords)
                            {
                                if (additionalRecord.Name.Equals(targetName, StringComparison.OrdinalIgnoreCase))
                                    return;
                            }

                            domain = targetName;
                            refRecord = records[0];
                            continue;
                        }
                        else if (targetName.Length > 0)
                        {
                            domain = targetName;
                            refRecord = records[0];
                            continue;
                        }
                    }
                }

                bool hasA = false;
                bool hasAAAA = false;

                if ((refRecord.Type == DnsResourceRecordType.SRV) || (refRecord.Type == DnsResourceRecordType.SVCB) || (refRecord.Type == DnsResourceRecordType.HTTPS))
                {
                    foreach (DnsResourceRecord additionalRecord in additionalRecords)
                    {
                        if (additionalRecord.Name.Equals(domain, StringComparison.OrdinalIgnoreCase))
                        {
                            switch (additionalRecord.Type)
                            {
                                case DnsResourceRecordType.A:
                                    hasA = true;
                                    break;

                                case DnsResourceRecordType.AAAA:
                                    hasAAAA = true;
                                    break;
                            }
                        }

                        if (hasA && hasAAAA)
                            break;
                    }
                }

                if (!hasA)
                {
                    IReadOnlyList<DnsResourceRecord> records = zone.QueryRecordsWildcard(DnsResourceRecordType.A, domain);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.A))
                        additionalRecords.AddRange(records);
                }

                if (!hasAAAA)
                {
                    IReadOnlyList<DnsResourceRecord> records = zone.QueryRecordsWildcard(DnsResourceRecordType.AAAA, domain);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.AAAA))
                        additionalRecords.AddRange(records);
                }

                break;
            }
        }

        private DnsDatagram GetReferralResponse(DnsDatagram request, AuthZone delegationZone)
        {
            IReadOnlyList<DnsResourceRecord> authority = delegationZone.QueryRecords(DnsResourceRecordType.NS);
            IReadOnlyList<DnsResourceRecord> additional = GetAdditionalRecords(authority);

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, null, authority, additional);
        }

        private DnsDatagram GetForwarderResponse(DnsDatagram request, AuthZone zone, SubDomainZone closestZone, ApexZone forwarderZone)
        {
            IReadOnlyList<DnsResourceRecord> authority = null;

            if (zone is not null)
            {
                if (zone.ContainsNameServerRecords())
                    return GetReferralResponse(request, zone);

                authority = zone.QueryRecords(DnsResourceRecordType.FWD);
            }

            if (((authority is null) || (authority.Count == 0)) && (closestZone is not null))
            {
                if (closestZone.ContainsNameServerRecords())
                    return GetReferralResponse(request, closestZone);

                authority = closestZone.QueryRecords(DnsResourceRecordType.FWD);
            }

            if ((authority is null) || (authority.Count == 0))
            {
                if (forwarderZone.ContainsNameServerRecords())
                    return GetReferralResponse(request, forwarderZone);

                authority = forwarderZone.QueryRecords(DnsResourceRecordType.FWD);
            }

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, null, authority);
        }

        #endregion

        #region properties

        public uint DefaultRecordTtl
        {
            get { return _defaultRecordTtl; }
            set { _defaultRecordTtl = value; }
        }

        public uint DefaultNsRecordTtl
        {
            get { return _defaultNsRecordTtl; }
            set { _defaultNsRecordTtl = value; }
        }

        public uint DefaultSoaRecordTtl
        {
            get { return _defaultSoaRecordTtl; }
            set { _defaultSoaRecordTtl = value; }
        }

        public int TotalZones
        { get { return _zoneIndex.Count; } }

        #endregion
    }
}
