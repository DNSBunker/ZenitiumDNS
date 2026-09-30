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
using ZenitiumDns.Core.Dns.Trees;
using ZenitiumDns.Core.Dns.Zones;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumLibrary.IO;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.EDnsOptions;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.ZoneManagers
{
    public sealed class CacheZoneManager : DnsCache, IDisposable
    {
        #region variables

        public const uint FAILURE_RECORD_TTL = 10u;
        public const uint NEGATIVE_RECORD_TTL = 300u;
        public const uint MINIMUM_RECORD_TTL = 10u;
        public const uint MAXIMUM_RECORD_TTL = 24 * 60 * 60;
        public const uint MAXIMUM_NEGATIVE_RECORD_TTL = 60 * 60;
        public const uint SERVE_STALE_TTL = 3 * 24 * 60 * 60;
        public const uint SERVE_STALE_ANSWER_TTL = 30;
        public const uint SERVE_STALE_RESET_TTL = 30;

        const uint SERVE_STALE_MIN_RESET_TTL = 10;
        const uint SERVE_STALE_MAX_RESET_TTL = 900;

        readonly DnsServer _dnsServer;

        readonly CacheZoneTree _root = new CacheZoneTree();

        readonly AggressiveNsecCache _aggressiveNsecCache = new AggressiveNsecCache();
        bool _aggressiveNsec = true;

        uint _serveStaleResetTtl = SERVE_STALE_RESET_TTL;
        long _maximumEntries;
        long _totalEntries;

        Timer _cacheMaintenanceTimer;
        readonly Lock _cacheMaintenanceTimerLock = new Lock();
        const int CACHE_MAINTENANCE_TIMER_INITIAL_INTEVAL = 1 * 60 * 1000;
        const int CACHE_MAINTENANCE_TIMER_PERIODIC_INTERVAL = 1 * 60 * 1000;
        const int CACHE_MAINTENANCE_GC_COLLECTION_THRESHOLD = 10000;
        const long MEMORY_TRIM_MINIMUM_ENTRIES = 10000;

        const int MEMORY_COMPACTION_MINIMUM_INTERVAL_MINUTES = 15;

        volatile bool _enabled = true;

        int _maximumMemoryMegabytes;
        long _lastEvaluatedFullGcIndex;
        long _gcRequestIndex;
        DateTime _gcRequestTime;
        long _entriesAtGcRequest;
        DateTime _lastMemoryCompaction;
        long _memoryTrimmedEntries;

        #endregion

        #region constructor

        public CacheZoneManager(DnsServer dnsServer)
            : base(FAILURE_RECORD_TTL, NEGATIVE_RECORD_TTL, MINIMUM_RECORD_TTL, MAXIMUM_RECORD_TTL, SERVE_STALE_TTL, SERVE_STALE_ANSWER_TTL)
        {
            _dnsServer = dnsServer;

            MaximumNegativeRecordTtl = MAXIMUM_NEGATIVE_RECORD_TTL;

            _cacheMaintenanceTimer = new Timer(CacheMaintenanceTimerCallback, null, CACHE_MAINTENANCE_TIMER_INITIAL_INTEVAL, Timeout.Infinite);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            lock (_cacheMaintenanceTimerLock)
            {
                if (_cacheMaintenanceTimer is not null)
                {
                    _cacheMaintenanceTimer.Dispose();
                    _cacheMaintenanceTimer = null;
                }
            }

            _disposed = true;
        }

        #endregion

        #region zone file

        public void LoadCacheZoneFile()
        {
            string cacheZoneFile = Path.Combine(_dnsServer.ConfigFolder, "cache.bin");

            if (!_enabled || !File.Exists(cacheZoneFile))
                return;

            _dnsServer.LogManager.Write("Loading DNS Cache from disk...");

            using (FileStream fS = new FileStream(cacheZoneFile, FileMode.Open, FileAccess.Read))
            {
                if (Encoding.ASCII.GetString(fS.ReadExactly(2)) != "CZ")
                    throw new InvalidDataException("CacheZoneManager format is invalid.");

                BinaryReader bR = new BinaryReader(fS);

                int version = bR.ReadByte();
                switch (version)
                {
                    case 1:
                        int addedEntries = 0;

                        try
                        {
                            bool serveStale = _dnsServer.ServeStale;

                            while ((bR.BaseStream.Position < bR.BaseStream.Length) && _enabled)
                            {
                                CacheZone zone = CacheZone.ReadFrom(bR, serveStale);
                                if (!zone.IsEmpty)
                                {
                                    if (_root.TryAdd(zone.Name, zone))
                                        addedEntries += zone.TotalEntries;
                                }
                            }
                        }
                        finally
                        {
                            if (addedEntries > 0)
                                Interlocked.Add(ref _totalEntries, addedEntries);
                        }
                        break;

                    default:
                        throw new InvalidDataException("CacheZoneManager format version not supported: " + version);
                }
            }

            _dnsServer.LogManager.Write("DNS Cache was loaded from disk successfully.");
        }

        public void SaveCacheZoneFile()
        {
            if (!_enabled)
                return;

            _dnsServer.LogManager.Write("Saving DNS Cache to disk...");

            string cacheZoneFile = Path.Combine(_dnsServer.ConfigFolder, "cache.bin");

            using (FileStream fS = new FileStream(cacheZoneFile, FileMode.Create, FileAccess.Write))
            {
                BinaryWriter bW = new BinaryWriter(fS);

                bW.Write(Encoding.ASCII.GetBytes("CZ"));
                bW.Write((byte)1);

                foreach (CacheZone zone in _root)
                    zone.WriteTo(bW);
            }

            _dnsServer.LogManager.Write("DNS Cache was saved to disk successfully.");
        }

        public void DeleteCacheZoneFile()
        {
            string cacheZoneFile = Path.Combine(_dnsServer.ConfigFolder, "cache.bin");

            if (File.Exists(cacheZoneFile))
                File.Delete(cacheZoneFile);
        }

        #endregion

        #region protected

        protected override void CacheRecords(IReadOnlyList<DnsResourceRecord> resourceRecords, NetworkAddress eDnsClientSubnet, DnsDatagramMetadata responseMetadata)
        {
            if (!_enabled)
                return;

            List<DnsResourceRecord> dnameRecords = null;

            responseMetadata = CacheRecordInfo.InternMetadata(responseMetadata);

            foreach (DnsResourceRecord resourceRecord in resourceRecords)
            {
                DnsResourceRecordInfo recordInfo = GetRecordInfo(resourceRecord);

                IReadOnlyList<DnsResourceRecord> glueRecords = recordInfo.GlueRecords;
                IReadOnlyList<DnsResourceRecord> rrsigRecords = recordInfo.RRSIGRecords;
                IReadOnlyList<DnsResourceRecord> nsecRecords = recordInfo.NSECRecords;

                CacheRecordInfo rrInfo = resourceRecord.GetCacheRecordInfo();

                rrInfo.GlueRecords = glueRecords;
                rrInfo.RRSIGRecords = rrsigRecords;
                rrInfo.NSECRecords = nsecRecords;
                rrInfo.EDnsClientSubnet = eDnsClientSubnet;
                rrInfo.ResponseMetadata = responseMetadata;

                if (glueRecords is not null)
                {
                    foreach (DnsResourceRecord glueRecord in glueRecords)
                    {
                        IReadOnlyList<DnsResourceRecord> glueRRSIGRecords = GetRecordInfo(glueRecord).RRSIGRecords;
                        if (glueRRSIGRecords is not null)
                            glueRecord.GetCacheRecordInfo().RRSIGRecords = glueRRSIGRecords;
                    }
                }

                if (nsecRecords is not null)
                {
                    foreach (DnsResourceRecord nsecRecord in nsecRecords)
                    {
                        IReadOnlyList<DnsResourceRecord> nsecRRSIGRecords = GetRecordInfo(nsecRecord).RRSIGRecords;
                        if (nsecRRSIGRecords is not null)
                            nsecRecord.GetCacheRecordInfo().RRSIGRecords = nsecRRSIGRecords;
                    }
                }

                if (resourceRecord.Type == DnsResourceRecordType.DNAME)
                {
                    if (dnameRecords is null)
                        dnameRecords = new List<DnsResourceRecord>(1);

                    dnameRecords.Add(resourceRecord);
                }
            }

            if (resourceRecords.Count == 1)
            {
                DnsResourceRecord resourceRecord = resourceRecords[0];

                CacheZone zone = _root.GetOrAdd(resourceRecord.Name, delegate (string key)
                {
                    return new CacheZone(resourceRecord.Name, 1);
                });

                if (zone.SetRecords(resourceRecords, _dnsServer.ServeStale))
                    Interlocked.Increment(ref _totalEntries);
            }
            else
            {
                Dictionary<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByDomainRecords = DnsResourceRecord.GroupRecords(resourceRecords);
                bool serveStale = _dnsServer.ServeStale;

                int addedEntries = 0;

                foreach (KeyValuePair<string, Dictionary<DnsResourceRecordType, List<DnsResourceRecord>>> groupedByTypeRecords in groupedByDomainRecords)
                {
                    if (dnameRecords is not null)
                    {
                        bool foundSynthesizedCNAME = false;

                        foreach (DnsResourceRecord dnameRecord in dnameRecords)
                        {
                            if (groupedByTypeRecords.Key.EndsWith("." + dnameRecord.Name, StringComparison.OrdinalIgnoreCase))
                            {
                                foundSynthesizedCNAME = true;
                                break;
                            }
                        }

                        if (foundSynthesizedCNAME)
                            continue;
                    }

                    CacheZone zone = _root.GetOrAdd(groupedByTypeRecords.Key, delegate (string key)
                    {
                        return new CacheZone(groupedByTypeRecords.Key, groupedByTypeRecords.Value.Count);
                    });

                    foreach (KeyValuePair<DnsResourceRecordType, List<DnsResourceRecord>> groupedRecords in groupedByTypeRecords.Value)
                    {
                        if (zone.SetRecords(groupedRecords.Value, serveStale))
                            addedEntries++;
                    }
                }

                if (addedEntries > 0)
                    Interlocked.Add(ref _totalEntries, addedEntries);
            }
        }

        protected override void CacheDenialOfExistence(DnsDatagram response, NetworkAddress eDnsClientSubnet)
        {
            if (!_enabled)
                return;

            if (!_aggressiveNsec || !_dnsServer.DnssecValidation)
                return;

            if ((eDnsClientSubnet is not null) && (eDnsClientSubnet.PrefixLength > 0))
                return;

            try
            {
                _aggressiveNsecCache.Add(response, MaximumNegativeRecordTtl);
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }
        }

        #endregion

        #region private

        private void CacheMaintenanceTimerCallback(object state)
        {
            try
            {
                int totalRemovedEntries = RemoveExpiredRecords();
                totalRemovedEntries += TrimToMemoryLimit();

                if (totalRemovedEntries > CACHE_MAINTENANCE_GC_COLLECTION_THRESHOLD)
                    GC.Collect(GC.MaxGeneration, GCCollectionMode.Optimized, false);
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }
            finally
            {
                lock (_cacheMaintenanceTimerLock)
                {
                    _cacheMaintenanceTimer?.Change(CACHE_MAINTENANCE_TIMER_PERIODIC_INTERVAL, Timeout.Infinite);
                }
            }
        }

        private static GCMemoryInfo GetLastFullGcInfo()
        {
            GCMemoryInfo blocking = GC.GetGCMemoryInfo(GCKind.FullBlocking);
            GCMemoryInfo background = GC.GetGCMemoryInfo(GCKind.Background);

            return background.Index > blocking.Index ? background : blocking;
        }

        private void RequestFullGc()
        {
            _gcRequestIndex = GC.GetGCMemoryInfo().Index;
            _gcRequestTime = DateTime.UtcNow;
            _entriesAtGcRequest = Volatile.Read(ref _totalEntries);

            GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, false);
        }

        private int TrimToMemoryLimit()
        {
            int maximumMemoryMegabytes = _maximumMemoryMegabytes;
            if (maximumMemoryMegabytes < 1)
                return 0;

            long limit = maximumMemoryMegabytes * 1024L * 1024L;

            GCMemoryInfo latest = GC.GetGCMemoryInfo();
            if ((latest.HeapSizeBytes - latest.FragmentedBytes) <= limit)
                return 0;

            GCMemoryInfo info = GetLastFullGcInfo();

            if ((info.Index <= _lastEvaluatedFullGcIndex) || (info.Index <= _gcRequestIndex))
            {
                if ((_gcRequestIndex == 0) || (DateTime.UtcNow > _gcRequestTime.AddMinutes(5)))
                    RequestFullGc();

                return 0;
            }

            _lastEvaluatedFullGcIndex = info.Index;

            long totalEntries = Volatile.Read(ref _totalEntries);
            long used = info.HeapSizeBytes - info.FragmentedBytes;
            long entriesAtGc = _entriesAtGcRequest > 0 ? _entriesAtGcRequest : totalEntries;
            double projected = entriesAtGc > 0 ? (double)used / entriesAtGc * totalEntries : used;

            if ((projected <= limit) || (totalEntries <= MEMORY_TRIM_MINIMUM_ENTRIES))
            {
                _gcRequestIndex = 0;
                return 0;
            }

            double fraction = Math.Clamp(1.0 - (limit * 0.9 / projected), 0.05, 0.9);
            long entriesToRemove = Math.Min((long)(totalEntries * fraction), totalEntries - MEMORY_TRIM_MINIMUM_ENTRIES);

            int removedEntries = TrimEntries(entriesToRemove);
            Interlocked.Add(ref _memoryTrimmedEntries, removedEntries);

            string compaction = "";
            DateTime utcNow = DateTime.UtcNow;

            if ((removedEntries >= totalEntries / 10) && (utcNow >= _lastMemoryCompaction.AddMinutes(MEMORY_COMPACTION_MINIMUM_INTERVAL_MINUTES)))
            {
                _lastMemoryCompaction = utcNow;

                long start = Stopwatch.GetTimestamp();
                GC.Collect(GC.MaxGeneration, GCCollectionMode.Aggressive, true, true);
                compaction = " Memory was compacted in " + Stopwatch.GetElapsedTime(start).TotalMilliseconds.ToString("0") + " ms.";

                _gcRequestIndex = GC.GetGCMemoryInfo().Index - 1;
                _gcRequestTime = DateTime.UtcNow;
                _entriesAtGcRequest = Volatile.Read(ref _totalEntries);
            }
            else
            {
                RequestFullGc();
            }

            _dnsServer.LogManager.Write("DNS Cache memory usage (about " + (long)(projected / 1024 / 1024) + " MB) exceeded the configured limit of " + maximumMemoryMegabytes + " MB; " + removedEntries + " least recently used cache entries were removed." + compaction);

            return removedEntries;
        }

        private static IReadOnlyList<DnsResourceRecord> AddDSRecordsTo(CacheZone delegation, bool serveStale, IReadOnlyList<DnsResourceRecord> nsRecords, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet)
        {
            IReadOnlyList<DnsResourceRecord> records = delegation.QueryRecords(DnsResourceRecordType.DS, serveStale, true, eDnsClientSubnet, advancedForwardingClientSubnet);
            if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.DS))
            {
                List<DnsResourceRecord> newNSRecords = new List<DnsResourceRecord>(nsRecords.Count + records.Count);

                newNSRecords.AddRange(nsRecords);
                newNSRecords.AddRange(records);

                return newNSRecords;
            }

            IReadOnlyList<DnsResourceRecord> nsecRecords = nsRecords[0].GetCacheRecordInfo().NSECRecords;
            if (nsecRecords is not null)
            {
                List<DnsResourceRecord> newNSRecords = new List<DnsResourceRecord>(nsRecords.Count + nsecRecords.Count);

                newNSRecords.AddRange(nsRecords);
                newNSRecords.AddRange(nsecRecords);

                return newNSRecords;
            }

            return nsRecords;
        }

        private static void AddRRSIGRecords(IReadOnlyList<DnsResourceRecord> answer, out IReadOnlyList<DnsResourceRecord> newAnswer, out IReadOnlyList<DnsResourceRecord> newAuthority)
        {
            List<DnsResourceRecord> newAnswerList = new List<DnsResourceRecord>(answer.Count * 2);
            List<DnsResourceRecord> newAuthorityList = null;

            foreach (DnsResourceRecord record in answer)
            {
                if (record.Type == DnsResourceRecordType.RRSIG)
                    continue;

                newAnswerList.Add(record);

                CacheRecordInfo rrInfo = record.GetCacheRecordInfo();

                IReadOnlyList<DnsResourceRecord> rrsigRecords = rrInfo.RRSIGRecords;
                if (rrsigRecords is not null)
                {
                    newAnswerList.AddRange(rrsigRecords);

                    foreach (DnsResourceRecord rrsigRecord in rrsigRecords)
                    {
                        if (!DnsRRSIGRecordData.IsWildcard(rrsigRecord))
                            continue;

                        if (newAuthorityList is null)
                            newAuthorityList = new List<DnsResourceRecord>(2);

                        IReadOnlyList<DnsResourceRecord> nsecRecords = rrInfo.NSECRecords;
                        if (nsecRecords is not null)
                        {
                            foreach (DnsResourceRecord nsecRecord in nsecRecords)
                            {
                                newAuthorityList.Add(nsecRecord);

                                IReadOnlyList<DnsResourceRecord> nsecRRSIGRecords = nsecRecord.GetCacheRecordInfo().RRSIGRecords;
                                if (nsecRRSIGRecords is not null)
                                    newAuthorityList.AddRange(nsecRRSIGRecords);
                            }
                        }
                    }
                }
            }

            newAnswer = newAnswerList;
            newAuthority = newAuthorityList;
        }

        private void ResolveCNAME(DnsQuestionRecord question, DnsResourceRecord lastCNAME, bool serveStale, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet, List<DnsResourceRecord> answerRecords)
        {
            int queryCount = 0;

            do
            {
                string cnameDomain = (lastCNAME.RDATA as DnsCNAMERecordData).Domain;
                if (lastCNAME.Name.Equals(cnameDomain, StringComparison.OrdinalIgnoreCase))
                    break;

                if (!_root.TryGet(cnameDomain, out CacheZone cacheZone))
                    break;

                IReadOnlyList<DnsResourceRecord> records = cacheZone.QueryRecords(question.Type, serveStale, true, eDnsClientSubnet, advancedForwardingClientSubnet);
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

        private bool DoDNAMESubstitution(DnsQuestionRecord question, IReadOnlyList<DnsResourceRecord> answer, bool serveStale, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet, out IReadOnlyList<DnsResourceRecord> newAnswer)
        {
            DnsResourceRecord dnameRR = answer[0];

            string result = (dnameRR.RDATA as DnsDNAMERecordData).Substitute(question.Name, dnameRR.Name);

            if (DnsClient.IsDomainNameValid(result))
            {
                DnsResourceRecord cnameRR = new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, question.Class, dnameRR.TTL, new DnsCNAMERecordData(result));

                List<DnsResourceRecord> list = new List<DnsResourceRecord>(5)
                {
                    dnameRR,
                    cnameRR
                };

                ResolveCNAME(question, cnameRR, serveStale, eDnsClientSubnet, advancedForwardingClientSubnet, list);

                newAnswer = list;
                return true;
            }
            else
            {
                newAnswer = answer;
                return false;
            }
        }

        private List<DnsResourceRecord> GetAdditionalRecords(IReadOnlyList<DnsResourceRecord> refRecords, bool serveStale, bool dnssecOk, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet)
        {
            List<DnsResourceRecord> additionalRecords = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord refRecord in refRecords)
            {
                switch (refRecord.Type)
                {
                    case DnsResourceRecordType.NS:
                        if (refRecord.RDATA is DnsNSRecordData ns)
                            ResolveAdditionalRecords(refRecord, ns.NameServer, serveStale, dnssecOk, eDnsClientSubnet, advancedForwardingClientSubnet, additionalRecords);

                        break;

                    case DnsResourceRecordType.MX:
                        if (refRecord.RDATA is DnsMXRecordData mx)
                            ResolveAdditionalRecords(refRecord, mx.Exchange, serveStale, dnssecOk, eDnsClientSubnet, advancedForwardingClientSubnet, additionalRecords);

                        break;

                    case DnsResourceRecordType.SRV:
                        if (refRecord.RDATA is DnsSRVRecordData srv)
                            ResolveAdditionalRecords(refRecord, srv.Target, serveStale, dnssecOk, eDnsClientSubnet, advancedForwardingClientSubnet, additionalRecords);

                        break;

                    case DnsResourceRecordType.SVCB:
                    case DnsResourceRecordType.HTTPS:
                        if (refRecord.RDATA is DnsSVCBRecordData svcb)
                        {
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

                            ResolveAdditionalRecords(refRecord, targetName, serveStale, dnssecOk, eDnsClientSubnet, advancedForwardingClientSubnet, additionalRecords);
                        }

                        break;
                }
            }

            return additionalRecords;
        }

        private void ResolveAdditionalRecords(DnsResourceRecord refRecord, string domain, bool serveStale, bool dnssecOk, NetworkAddress eDnsClientSubnet, bool advancedForwardingClientSubnet, List<DnsResourceRecord> additionalRecords)
        {
            IReadOnlyList<DnsResourceRecord> glueRecords = refRecord.GetCacheRecordInfo().GlueRecords;
            if (glueRecords is not null)
            {
                bool added = false;

                foreach (DnsResourceRecord glueRecord in glueRecords)
                {
                    if (!glueRecord.IsStale)
                    {
                        added = true;
                        additionalRecords.Add(glueRecord);

                        if (dnssecOk)
                        {
                            IReadOnlyList<DnsResourceRecord> rrsigRecords = glueRecord.GetCacheRecordInfo().RRSIGRecords;
                            if (rrsigRecords is not null)
                                additionalRecords.AddRange(rrsigRecords);
                        }
                    }
                }

                if (added)
                    return;
            }

            int count = 0;

            while ((count++ < DnsServer.MAX_CNAME_HOPS) && _root.TryGet(domain, out CacheZone cacheZone))
            {
                if (((refRecord.Type == DnsResourceRecordType.SVCB) || (refRecord.Type == DnsResourceRecordType.HTTPS)) && ((refRecord.RDATA as DnsSVCBRecordData).SvcPriority == 0))
                {
                    IReadOnlyList<DnsResourceRecord> records = cacheZone.QueryRecords(refRecord.Type, serveStale, true, eDnsClientSubnet, advancedForwardingClientSubnet);
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
                        else
                        {
                            if (targetName.Length > 0)
                            {
                                domain = targetName;
                                refRecord = records[0];
                                continue;
                            }
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
                    IReadOnlyList<DnsResourceRecord> records = cacheZone.QueryRecords(DnsResourceRecordType.A, serveStale, true, eDnsClientSubnet, advancedForwardingClientSubnet);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.A))
                        additionalRecords.AddRange(records);
                }

                if (!hasAAAA)
                {
                    IReadOnlyList<DnsResourceRecord> records = cacheZone.QueryRecords(DnsResourceRecordType.AAAA, serveStale, true, eDnsClientSubnet, advancedForwardingClientSubnet);
                    if ((records.Count > 0) && (records[0].Type == DnsResourceRecordType.AAAA))
                        additionalRecords.AddRange(records);
                }

                break;
            }
        }

        private DnsDatagram QueryAggressiveNsec(DnsDatagram request, bool dnssecOk)
        {
            AuthZoneManager authZoneManager = _dnsServer.AuthZoneManager;

            if ((authZoneManager is not null) && (authZoneManager.TotalZones > 0) && (authZoneManager.FindApexZone(request.Question[0].Name) is not null))
                return null;

            try
            {
                return _aggressiveNsecCache.Query(request, dnssecOk, _dnsServer.UdpPayloadSize);
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
                return null;
            }
        }

        private int RemoveZoneIfEmpty(CacheZone zone)
        {
            if (!zone.IsEmpty || !_root.TryRemove(zone.Name, out CacheZone removedZone) || removedZone.IsEmpty)
                return 0;

            if (ReferenceEquals(_root.GetOrAdd(removedZone.Name, removedZone), removedZone))
                return 0;

            return removedZone.TotalEntries;
        }

        private int RemoveExpiredRecordsInternal(bool serveStale, long minimumEntriesToRemove)
        {
            int removedEntries = 0;

            foreach (CacheZone zone in _root)
            {
                removedEntries += zone.RemoveExpiredRecords(serveStale);

                removedEntries += RemoveZoneIfEmpty(zone);

                if ((minimumEntriesToRemove > 0) && (removedEntries >= minimumEntriesToRemove))
                    break;
            }

            if (removedEntries > 0)
            {
                long totalEntries = Interlocked.Add(ref _totalEntries, -removedEntries);
                if (totalEntries < 0)
                    Interlocked.Add(ref _totalEntries, -totalEntries);
            }

            return removedEntries;
        }

        private int RemoveLeastUsedRecordsInternal(DateTime cutoff, long minimumEntriesToRemove)
        {
            int removedEntries = 0;

            foreach (CacheZone zone in _root)
            {
                removedEntries += zone.RemoveLeastUsedRecords(cutoff);

                removedEntries += RemoveZoneIfEmpty(zone);

                if ((minimumEntriesToRemove > 0) && (removedEntries >= minimumEntriesToRemove))
                    break;
            }

            if (removedEntries > 0)
            {
                long totalEntries = Interlocked.Add(ref _totalEntries, -removedEntries);
                if (totalEntries < 0)
                    Interlocked.Add(ref _totalEntries, -totalEntries);
            }

            return removedEntries;
        }

        #endregion

        #region public

        public override int RemoveExpiredRecords()
        {
            bool serveStale = _dnsServer.ServeStale;

            int totalRemovedEntries = RemoveExpiredRecordsInternal(serveStale, 0);

            _aggressiveNsecCache.RemoveExpired();

            if (_maximumEntries < 1)
                return totalRemovedEntries;

            long minimumEntriesToRemove = Volatile.Read(ref _totalEntries) - _maximumEntries;
            if (minimumEntriesToRemove < 1)
                return totalRemovedEntries;

            if (serveStale)
            {
                int removedEntries = RemoveExpiredRecordsInternal(false, minimumEntriesToRemove);

                totalRemovedEntries += removedEntries;
                minimumEntriesToRemove -= removedEntries;
            }

            if (minimumEntriesToRemove < 1)
                return totalRemovedEntries;

            for (int seconds = 86400; seconds > 0; seconds /= 2)
            {
                DateTime cutoff = DateTime.UtcNow.AddSeconds(-seconds);

                int removedEntries = RemoveLeastUsedRecordsInternal(cutoff, minimumEntriesToRemove);

                totalRemovedEntries += removedEntries;
                minimumEntriesToRemove -= removedEntries;

                if (minimumEntriesToRemove < 1)
                    break;
            }

            return totalRemovedEntries;
        }

        public int TrimEntries(long entriesToRemove)
        {
            if (entriesToRemove < 1)
                return 0;

            int totalRemovedEntries = RemoveExpiredRecordsInternal(false, entriesToRemove);
            entriesToRemove -= totalRemovedEntries;

            for (int seconds = 86400; (seconds > 0) && (entriesToRemove > 0); seconds /= 2)
            {
                int removedEntries = RemoveLeastUsedRecordsInternal(DateTime.UtcNow.AddSeconds(-seconds), entriesToRemove);

                totalRemovedEntries += removedEntries;
                entriesToRemove -= removedEntries;
            }

            return totalRemovedEntries;
        }

        public void DeleteEDnsClientSubnetData()
        {
            int removedEntries = 0;

            foreach (CacheZone zone in _root)
            {
                removedEntries += zone.DeleteEDnsClientSubnetData();

                removedEntries += RemoveZoneIfEmpty(zone);
            }

            if (removedEntries > 0)
            {
                long totalEntries = Interlocked.Add(ref _totalEntries, -removedEntries);
                if (totalEntries < 0)
                    Interlocked.Add(ref _totalEntries, -totalEntries);
            }
        }

        public override void Flush()
        {
            _root.Clear();

            long totalEntries = _totalEntries;
            totalEntries = Interlocked.Add(ref _totalEntries, -totalEntries);
            if (totalEntries < 0)
                Interlocked.Add(ref _totalEntries, -totalEntries);

            _aggressiveNsecCache.Flush();

            DnsClient.ClearRootHintsMisconfiguredMarks();
        }

        public bool DeleteZone(string domain)
        {
            _aggressiveNsecCache.RemoveTree(domain);

            if (_root.TryRemoveTree(domain, out _, out int removedEntries))
            {
                if (removedEntries > 0)
                {
                    long totalEntries = Interlocked.Add(ref _totalEntries, -removedEntries);
                    if (totalEntries < 0)
                        Interlocked.Add(ref _totalEntries, -totalEntries);
                }

                return true;
            }

            return false;
        }

        public void ListSubDomains(string domain, List<string> subDomains)
        {
            _root.ListSubDomains(domain, subDomains);
        }

        public void ListAllRecords(string domain, List<DnsResourceRecord> records)
        {
            if (_root.TryGet(domain, out CacheZone zone))
                zone.ListAllRecords(records);
        }

        public DnsDatagram QueryClosestDelegation(DnsDatagram request)
        {
            if (!_enabled)
                return null;

            DnsQuestionRecord question = request.Question[0];
            string domain = question.Name;

            NetworkAddress eDnsClientSubnet = null;
            bool advancedForwardingClientSubnet = false;
            {
                EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                if (requestECS is not null)
                {
                    eDnsClientSubnet = new NetworkAddress(requestECS.Address, requestECS.SourcePrefixLength);
                    advancedForwardingClientSubnet = requestECS.AdvancedForwardingClientSubnet;
                }
            }

            if (question.Type == DnsResourceRecordType.DS)
            {
                domain = AuthZoneManager.GetParentZone(question.Name);
                if (domain is null)
                    return null;
            }

            do
            {
                _ = _root.FindZone(domain, out _, out CacheZone delegation);
                if (delegation is null)
                    return null;

                IReadOnlyList<DnsResourceRecord> closestAuthority = delegation.QueryRecords(DnsResourceRecordType.PARENT_NS, false, true, eDnsClientSubnet, advancedForwardingClientSubnet);
                if ((closestAuthority.Count == 0) && (delegation.Name.Length == 0))
                    closestAuthority = delegation.QueryRecords(DnsResourceRecordType.CHILD_NS, false, true, eDnsClientSubnet, advancedForwardingClientSubnet);

                if ((closestAuthority.Count > 0) && (closestAuthority[0].Type == DnsResourceRecordType.NS))
                {
                    if (request.DnssecOk)
                    {
                        if (closestAuthority[0].DnssecStatus != DnssecStatus.Disabled)
                        {
                            closestAuthority = AddDSRecordsTo(delegation, false, closestAuthority, eDnsClientSubnet, advancedForwardingClientSubnet);

                            IReadOnlyList<DnsResourceRecord> additional = GetAdditionalRecords(closestAuthority, false, true, eDnsClientSubnet, advancedForwardingClientSubnet);

                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, null, closestAuthority, additional);
                        }
                    }
                    else
                    {
                        IReadOnlyList<DnsResourceRecord> additional = GetAdditionalRecords(closestAuthority, false, false, eDnsClientSubnet, advancedForwardingClientSubnet);

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, DnsResponseCode.NoError, request.Question, null, closestAuthority, additional);
                    }
                }

                domain = AuthZoneManager.GetParentZone(delegation.Name);
            }
            while (domain is not null);

            return null;
        }

        public override Task<DnsDatagram> QueryAsync(DnsDatagram request, bool serveStale = false, bool findClosestNameServers = false, bool resetExpiry = false)
        {
            return Task.FromResult(Query(request, serveStale, findClosestNameServers, resetExpiry));
        }

        public DnsDatagram Query(DnsDatagram request, bool serveStale = false, bool findClosestNameServers = false, bool resetExpiry = false, bool aggressiveNsec = false)
        {
            if (!_enabled)
                return null;

            DnsQuestionRecord question = request.Question[0];

            NetworkAddress eDnsClientSubnet = null;
            bool advancedForwardingClientSubnet = false;
            {
                EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption();
                if (requestECS is not null)
                {
                    eDnsClientSubnet = new NetworkAddress(requestECS.Address, requestECS.SourcePrefixLength);
                    advancedForwardingClientSubnet = requestECS.AdvancedForwardingClientSubnet;
                }
            }

            CacheZone zone;
            CacheZone closest = null;
            CacheZone delegation = null;

            if (findClosestNameServers)
                zone = _root.FindZone(question.Name, out closest, out delegation);
            else
                _ = _root.TryGet(question.Name, out zone);

            bool dnssecOk = request.DnssecOk && _dnsServer.DnssecValidation;

            if (zone is not null)
            {
                IReadOnlyList<DnsResourceRecord> answer = zone.QueryRecords(question.Type, serveStale, false, eDnsClientSubnet, advancedForwardingClientSubnet);
                if (answer.Count > 0)
                {
                    DnsResourceRecord firstRR = answer[0];

                    if (firstRR.RDATA is DnsSpecialCacheRecordData dnsSpecialCacheRecord)
                    {
                        if (dnssecOk)
                        {
                            foreach (DnsResourceRecord originalAuthority in dnsSpecialCacheRecord.OriginalAuthority)
                            {
                                if (originalAuthority.DnssecStatus == DnssecStatus.Disabled)
                                    goto beforeFindClosestNameServers;
                            }
                        }

                        if (resetExpiry)
                        {
                            if (firstRR.IsStale)
                                firstRR.ResetExpiry(_serveStaleResetTtl);

                            if (dnsSpecialCacheRecord.Authority is not null)
                            {
                                foreach (DnsResourceRecord record in dnsSpecialCacheRecord.Authority)
                                {
                                    if (record.IsStale)
                                        record.ResetExpiry(_serveStaleResetTtl);
                                }
                            }
                        }

                        IReadOnlyList<EDnsOption> specialOptions;

                        if (firstRR.WasExpiryReset || firstRR.IsStale)
                        {
                            List<EDnsOption> newOptions = new List<EDnsOption>(dnsSpecialCacheRecord.EDnsOptions.Count + 1);

                            newOptions.AddRange(dnsSpecialCacheRecord.EDnsOptions);

                            if (dnsSpecialCacheRecord.RCODE == DnsResponseCode.NxDomain)
                                newOptions.Add(new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.StaleNxDomainAnswer, firstRR.Name.ToLowerInvariant() + " " + firstRR.Type.ToString() + " " + firstRR.Class.ToString())));
                            else
                                newOptions.Add(new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.StaleAnswer, firstRR.Name.ToLowerInvariant() + " " + firstRR.Type.ToString() + " " + firstRR.Class.ToString())));

                            specialOptions = newOptions;
                        }
                        else
                        {
                            specialOptions = dnsSpecialCacheRecord.EDnsOptions;
                        }

                        if (eDnsClientSubnet is not null)
                        {
                            EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption(true);
                            if (requestECS is not null)
                            {
                                NetworkAddress recordECS = firstRR.GetCacheRecordInfo().EDnsClientSubnet;
                                if (recordECS is not null)
                                {
                                    EDnsOption[] ecsOption = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(requestECS.SourcePrefixLength, recordECS.PrefixLength, requestECS.Address);

                                    if ((specialOptions is null) || (specialOptions.Count == 0))
                                    {
                                        specialOptions = ecsOption;
                                    }
                                    else
                                    {
                                        List<EDnsOption> newOptions = new List<EDnsOption>(specialOptions.Count + 1);

                                        newOptions.AddRange(specialOptions);
                                        newOptions.Add(ecsOption[0]);

                                        specialOptions = newOptions;
                                    }
                                }
                            }
                        }

                        if (dnssecOk)
                        {
                            bool authenticData;

                            switch (dnsSpecialCacheRecord.Type)
                            {
                                case DnsSpecialCacheRecordType.NegativeCache:
                                    authenticData = true;
                                    break;

                                default:
                                    authenticData = false;
                                    break;
                            }

                            if (request.CheckingDisabled)
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, authenticData, true, dnsSpecialCacheRecord.OriginalRCODE, request.Question, dnsSpecialCacheRecord.OriginalAnswer, dnsSpecialCacheRecord.OriginalAuthority, dnsSpecialCacheRecord.OriginalAdditional, _dnsServer.UdpPayloadSize, EDnsHeaderFlags.DNSSEC_OK, specialOptions);
                            else
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, authenticData, false, dnsSpecialCacheRecord.RCODE, request.Question, dnsSpecialCacheRecord.Answer, dnsSpecialCacheRecord.Authority, null, _dnsServer.UdpPayloadSize, EDnsHeaderFlags.DNSSEC_OK, specialOptions);
                        }
                        else
                        {
                            if (request.CheckingDisabled)
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, true, dnsSpecialCacheRecord.OriginalRCODE, request.Question, dnsSpecialCacheRecord.OriginalNoDnssecAnswer, dnsSpecialCacheRecord.OriginalNoDnssecAuthority, dnsSpecialCacheRecord.OriginalAdditional, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, specialOptions);
                            else
                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, false, dnsSpecialCacheRecord.RCODE, request.Question, dnsSpecialCacheRecord.NoDnssecAnswer, dnsSpecialCacheRecord.NoDnssecAuthority, null, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, specialOptions);
                        }
                    }

                    DnsResourceRecord lastRR = answer[answer.Count - 1];
                    if ((lastRR.Type != question.Type) && (lastRR.Type == DnsResourceRecordType.CNAME) && (question.Type != DnsResourceRecordType.ANY))
                    {
                        List<DnsResourceRecord> newAnswers = new List<DnsResourceRecord>(answer.Count + 3);
                        newAnswers.AddRange(answer);

                        ResolveCNAME(question, lastRR, serveStale, eDnsClientSubnet, advancedForwardingClientSubnet, newAnswers);

                        answer = newAnswers;
                    }

                    IReadOnlyList<DnsResourceRecord> authority = null;
                    EDnsHeaderFlags ednsFlags = EDnsHeaderFlags.None;

                    if (dnssecOk)
                    {
                        for (int ri = 0; ri < answer.Count; ri++)
                        {
                            DnsResourceRecord record = answer[ri];

                            if (record.DnssecStatus == DnssecStatus.Disabled)
                                goto beforeFindClosestNameServers;
                        }

                        AddRRSIGRecords(answer, out answer, out authority);

                        ednsFlags = EDnsHeaderFlags.DNSSEC_OK;
                    }

                    IReadOnlyList<DnsResourceRecord> additional = null;

                    switch (question.Type)
                    {
                        case DnsResourceRecordType.NS:
                        case DnsResourceRecordType.MX:
                        case DnsResourceRecordType.SRV:
                        case DnsResourceRecordType.SVCB:
                        case DnsResourceRecordType.HTTPS:
                            additional = GetAdditionalRecords(answer, serveStale, dnssecOk, eDnsClientSubnet, advancedForwardingClientSubnet);
                            break;
                    }

                    if (resetExpiry)
                    {
                        for (int ri = 0; ri < answer.Count; ri++)
                        {
                            DnsResourceRecord record = answer[ri];

                            if (record.IsStale)
                                record.ResetExpiry(_serveStaleResetTtl);
                        }

                        if (additional is not null)
                        {
                            for (int ri = 0; ri < additional.Count; ri++)
                            {
                                DnsResourceRecord record = additional[ri];

                                if (record.IsStale)
                                    record.ResetExpiry(_serveStaleResetTtl);
                            }
                        }
                    }

                    IReadOnlyList<EDnsOption> options = null;

                    for (int ri = 0; ri < answer.Count; ri++)
                    {
                        DnsResourceRecord record = answer[ri];

                        if (record.WasExpiryReset || record.IsStale)
                            options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.StaleAnswer, record.Name.ToLowerInvariant() + " " + record.Type.ToString() + " " + record.Class.ToString()))];
                    }

                    if (eDnsClientSubnet is not null)
                    {
                        EDnsClientSubnetOptionData requestECS = request.GetEDnsClientSubnetOption(true);
                        if (requestECS is not null)
                        {
                            NetworkAddress suitableECS = null;

                            for (int ri = 0; ri < answer.Count; ri++)
                            {
                                DnsResourceRecord record = answer[ri];

                                NetworkAddress recordECS = record.GetCacheRecordInfo().EDnsClientSubnet;
                                if (recordECS is not null)
                                {
                                    if ((suitableECS is null) || (recordECS.PrefixLength > suitableECS.PrefixLength))
                                        suitableECS = recordECS;
                                }
                            }

                            if (suitableECS is not null)
                            {
                                EDnsOption[] ecsOption = EDnsClientSubnetOptionData.GetEDnsClientSubnetOption(requestECS.SourcePrefixLength, suitableECS.PrefixLength, requestECS.Address);

                                if (options is null)
                                {
                                    options = ecsOption;
                                }
                                else
                                {
                                    List<EDnsOption> newOptions = new List<EDnsOption>(options.Count + 1);

                                    newOptions.AddRange(options);
                                    newOptions.Add(ecsOption[0]);

                                    options = newOptions;
                                }
                            }
                        }
                    }

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, dnssecOk && (answer.Count > 0) && (answer[0].DnssecStatus == DnssecStatus.Secure), request.CheckingDisabled, DnsResponseCode.NoError, request.Question, answer, authority, additional, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, ednsFlags, options);
                }
            }

            if (!findClosestNameServers)
                _ = _root.FindZone(question.Name, out closest, out _);

            if (closest is not null)
            {
                IReadOnlyList<DnsResourceRecord> answer = closest.QueryRecords(DnsResourceRecordType.DNAME, serveStale, true, eDnsClientSubnet, advancedForwardingClientSubnet);
                if ((answer.Count > 0) && (answer[0].Type == DnsResourceRecordType.DNAME))
                {
                    DnsResponseCode rCode;

                    if (DoDNAMESubstitution(question, answer, serveStale, eDnsClientSubnet, advancedForwardingClientSubnet, out answer))
                        rCode = DnsResponseCode.NoError;
                    else
                        rCode = DnsResponseCode.YXDomain;

                    IReadOnlyList<DnsResourceRecord> authority = null;
                    EDnsHeaderFlags ednsFlags = EDnsHeaderFlags.None;

                    if (dnssecOk)
                    {
                        for (int ri = 0; ri < answer.Count; ri++)
                        {
                            DnsResourceRecord record = answer[ri];

                            if (record.DnssecStatus == DnssecStatus.Disabled)
                                goto beforeFindClosestNameServers;
                        }

                        AddRRSIGRecords(answer, out answer, out authority);

                        ednsFlags = EDnsHeaderFlags.DNSSEC_OK;
                    }

                    if (resetExpiry)
                    {
                        for (int ri = 0; ri < answer.Count; ri++)
                        {
                            DnsResourceRecord record = answer[ri];

                            if (record.IsStale)
                                record.ResetExpiry(_serveStaleResetTtl);
                        }
                    }

                    EDnsOption[] options = null;

                    for (int ri = 0; ri < answer.Count; ri++)
                    {
                        DnsResourceRecord record = answer[ri];

                        if (record.WasExpiryReset || record.IsStale)
                            options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.StaleAnswer, record.Name.ToLowerInvariant() + " " + record.Type.ToString() + " " + record.Class.ToString()))];
                    }

                    return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, dnssecOk && (answer.Count > 0) && (answer[0].DnssecStatus == DnssecStatus.Secure), request.CheckingDisabled, rCode, request.Question, answer, authority, null, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, ednsFlags, options);
                }
            }

            if (aggressiveNsec && _aggressiveNsec && _dnsServer.DnssecValidation)
            {
                DnsDatagram synthesizedResponse = QueryAggressiveNsec(request, dnssecOk);
                if (synthesizedResponse is not null)
                    return synthesizedResponse;
            }

        beforeFindClosestNameServers:

            if (findClosestNameServers && (delegation is not null))
            {
                if (question.Type == DnsResourceRecordType.DS)
                {
                    string domain = AuthZoneManager.GetParentZone(question.Name);
                    if (domain is null)
                        return null;

                    _ = _root.FindZone(domain, out _, out delegation);
                    if (delegation is null)
                        return null;
                }

                while (true)
                {
                    IReadOnlyList<DnsResourceRecord> closestAuthority = delegation.QueryRecords(DnsResourceRecordType.PARENT_NS, serveStale, true, eDnsClientSubnet, advancedForwardingClientSubnet);
                    if ((closestAuthority.Count == 0) && (delegation.Name.Length == 0))
                        closestAuthority = delegation.QueryRecords(DnsResourceRecordType.CHILD_NS, serveStale, true, eDnsClientSubnet, advancedForwardingClientSubnet);

                    if ((closestAuthority.Count > 0) && (closestAuthority[0].Type == DnsResourceRecordType.NS))
                    {
                        if (dnssecOk)
                        {
                            if (closestAuthority[0].DnssecStatus != DnssecStatus.Disabled)
                            {
                                closestAuthority = AddDSRecordsTo(delegation, serveStale, closestAuthority, eDnsClientSubnet, advancedForwardingClientSubnet);

                                IReadOnlyList<DnsResourceRecord> additional = GetAdditionalRecords(closestAuthority, serveStale, true, eDnsClientSubnet, advancedForwardingClientSubnet);

                                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, closestAuthority[0].DnssecStatus == DnssecStatus.Secure, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, null, closestAuthority, additional);
                            }
                        }
                        else
                        {
                            IReadOnlyList<DnsResourceRecord> additional = GetAdditionalRecords(closestAuthority, serveStale, false, eDnsClientSubnet, advancedForwardingClientSubnet);

                            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, request.CheckingDisabled, DnsResponseCode.NoError, request.Question, null, closestAuthority, additional);
                        }
                    }

                    string domain = AuthZoneManager.GetParentZone(delegation.Name);
                    if (domain is null)
                        return null;

                    _ = _root.FindZone(domain, out _, out delegation);
                    if (delegation is null)
                        return null;
                }
            }

            return null;
        }

        #endregion

        #region properties

        public uint ServeStaleResetTtl
        {
            get { return _serveStaleResetTtl; }
            set
            {
                if ((value < SERVE_STALE_MIN_RESET_TTL) || (value > SERVE_STALE_MAX_RESET_TTL))
                    throw new ArgumentOutOfRangeException(nameof(ServeStaleResetTtl), "Serve stale reset TTL must be between " + SERVE_STALE_MIN_RESET_TTL + " and " + SERVE_STALE_MAX_RESET_TTL + " seconds. Recommended value is 30 seconds.");

                _serveStaleResetTtl = value;
            }
        }

        public bool Enabled
        {
            get { return _enabled; }
            set
            {
                if (_enabled == value)
                    return;

                _enabled = value;

                if (!value)
                    Flush();
            }
        }

        public int MaximumMemoryMegabytes
        {
            get { return _maximumMemoryMegabytes; }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(MaximumMemoryMegabytes), "Invalid cache maximum memory value. Valid range is 0 and above.");

                _maximumMemoryMegabytes = value;
            }
        }

        public long MemoryTrimmedEntries
        { get { return Interlocked.Read(ref _memoryTrimmedEntries); } }

        public long MaximumEntries
        {
            get { return _maximumEntries; }
            set
            {
                if (value < 0)
                    throw new ArgumentOutOfRangeException(nameof(MaximumEntries), "Invalid cache maximum entries value. Valid range is 0 and above.");

                _maximumEntries = value;
            }
        }

        public long TotalEntries
        { get { return _totalEntries; } }

        public bool AggressiveNsec
        {
            get { return _aggressiveNsec; }
            set
            {
                if (_aggressiveNsec != value)
                {
                    _aggressiveNsec = value;

                    if (!value)
                        _aggressiveNsecCache.Flush();
                }
            }
        }

        public long AggressiveNsecEntries
        { get { return _aggressiveNsecCache.TotalEntries; } }

        public long AggressiveNsecSynthesizedResponses
        { get { return _aggressiveNsecCache.SynthesizedResponses; } }

        #endregion
    }
}
