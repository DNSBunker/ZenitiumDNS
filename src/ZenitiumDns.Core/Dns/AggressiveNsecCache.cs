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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Text;
using System.Threading;
using ZenitiumLibrary;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.EDnsOptions;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns
{
    sealed class AggressiveNsecCache
    {
        #region variables

        const int MAXIMUM_ENTRIES = 50000;
        const int MAXIMUM_ZONE_ENTRIES = 4096;
        const int MAXIMUM_NSEC3_ITERATIONS = 50;
        const int MAXIMUM_NSEC3_HASHES = 12;

        readonly ConcurrentDictionary<string, NsecZone> _zones = new ConcurrentDictionary<string, NsecZone>(StringComparer.OrdinalIgnoreCase);

        long _totalEntries;
        long _synthesizedResponses;

        #endregion

        #region private

        private static long GetUnixTime()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        private static bool IsSubDomainOrEqual(string domain, string zone)
        {
            if (zone.Length == 0)
                return true;

            if (domain.Length == zone.Length)
                return domain.Equals(zone, StringComparison.OrdinalIgnoreCase);

            if (domain.Length < zone.Length)
                return false;

            return (domain[domain.Length - zone.Length - 1] == '.') && domain.EndsWith(zone, StringComparison.OrdinalIgnoreCase);
        }

        private static bool IsSubDomain(string domain, string zone)
        {
            if (domain.Length <= zone.Length)
                return false;

            return IsSubDomainOrEqual(domain, zone);
        }

        private static string GetParentZone(string domain)
        {
            if (domain.Length == 0)
                return null;

            int i = domain.IndexOf('.');
            if (i < 0)
                return string.Empty;

            return domain.Substring(i + 1);
        }

        private static int GetLabelCount(string domain)
        {
            if (domain.Length == 0)
                return 0;

            int count = 1;

            foreach (char c in domain)
            {
                if (c == '.')
                    count++;
            }

            return count;
        }

        private static string GetCanonicalKey(string domain)
        {
            if (domain.Length == 0)
                return string.Empty;

            return string.Create(domain.Length + 1, domain, static delegate (Span<char> span, string domain)
            {
                int position = 0;
                int end = domain.Length;

                while (true)
                {
                    int dot = end > 0 ? domain.LastIndexOf('.', end - 1) : -1;

                    for (int i = dot + 1; i < end; i++)
                    {
                        char c = domain[i];

                        if ((c >= 'A') && (c <= 'Z'))
                            c = (char)(c + 32);

                        span[position++] = (char)(c + 1);
                    }

                    span[position++] = '\0';

                    if (dot < 0)
                        break;

                    end = dot;
                }
            });
        }

        private static string GetClosestEncloser(string domain, string other)
        {
            string[] labels = domain.Split('.');
            string[] otherLabels = other.Split('.');
            int count = 0;

            while ((count < labels.Length) && (count < otherLabels.Length) && labels[labels.Length - 1 - count].Equals(otherLabels[otherLabels.Length - 1 - count], StringComparison.OrdinalIgnoreCase))
                count++;

            if (count == 0)
                return string.Empty;

            return string.Join('.', labels, labels.Length - count, count);
        }

        private static int FindFloor(NsecEntry[] entries, string key)
        {
            int low = 0;
            int high = entries.Length - 1;
            int result = -1;

            while (low <= high)
            {
                int mid = (low + high) >>> 1;
                int comparison = string.CompareOrdinal(entries[mid].Key, key);

                if (comparison == 0)
                    return mid;

                if (comparison < 0)
                {
                    result = mid;
                    low = mid + 1;
                }
                else
                {
                    high = mid - 1;
                }
            }

            return result;
        }

        private static NsecEntry FindExact(NsecEntry[] entries, string key)
        {
            int i = FindFloor(entries, key);
            if ((i >= 0) && entries[i].Key.Equals(key, StringComparison.Ordinal))
                return entries[i];

            return null;
        }

        private static NsecEntry FindCovering(NsecEntry[] entries, string key)
        {
            if (entries.Length == 0)
                return null;

            int i = FindFloor(entries, key);
            if (i >= 0)
            {
                NsecEntry entry = entries[i];

                if (entry.Key.Equals(key, StringComparison.Ordinal))
                    return null;

                if (string.CompareOrdinal(entry.Key, entry.NextKey) < 0)
                {
                    if (string.CompareOrdinal(key, entry.NextKey) < 0)
                        return entry;

                    return null;
                }

                return entry;
            }
            else
            {
                NsecEntry last = entries[entries.Length - 1];

                if ((string.CompareOrdinal(last.NextKey, last.Key) <= 0) && (string.CompareOrdinal(key, last.NextKey) < 0))
                    return last;

                return null;
            }
        }

        private static DnsResourceRecord[] GetRRSIGRecords(IReadOnlyList<DnsResourceRecord> section, DnsResourceRecord record, out string signersName, out long signatureExpires, out uint ttl)
        {
            List<DnsResourceRecord> rrsigRecords = null;

            signersName = null;
            signatureExpires = long.MaxValue;
            ttl = uint.MaxValue;

            foreach (DnsResourceRecord rrsigRecord in section)
            {
                if (rrsigRecord.Type != DnsResourceRecordType.RRSIG)
                    continue;

                if (rrsigRecord.DnssecStatus != DnssecStatus.Secure)
                    continue;

                if (!rrsigRecord.Name.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                    continue;

                DnsRRSIGRecordData rrsig = rrsigRecord.RDATA as DnsRRSIGRecordData;

                if (rrsig.TypeCovered != record.Type)
                    continue;

                if (DnsRRSIGRecordData.IsWildcard(rrsigRecord))
                    continue;

                if (signersName is null)
                    signersName = rrsig.SignersName;
                else if (!signersName.Equals(rrsig.SignersName, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (rrsigRecords is null)
                    rrsigRecords = new List<DnsResourceRecord>(2);

                rrsigRecords.Add(rrsigRecord);

                signatureExpires = Math.Min(signatureExpires, rrsig.SignatureExpiration);
                ttl = Math.Min(ttl, Math.Min(rrsigRecord.TTL, rrsig.OriginalTtl));
            }

            if (rrsigRecords is null)
                return null;

            return rrsigRecords.ToArray();
        }

        private NsecZone GetZone(string zoneName)
        {
            return _zones.GetOrAdd(zoneName, static delegate (string key)
            {
                return new NsecZone(key.ToLowerInvariant());
            });
        }

        private void AddEntry(string zoneName, NsecEntry entry, bool isNsec3, DnssecNSEC3HashAlgorithm hashAlgorithm, ushort iterations, byte[] salt, long now)
        {
            while (true)
            {
                NsecZone zone = GetZone(zoneName);

                lock (zone.Lock)
                {
                    if (zone.Removed)
                        continue;

                    int delta;

                    if (isNsec3)
                    {
                        Nsec3Chain chain = zone.Nsec3Chain;
                        NsecEntry[] entries;
                        int oldCount;

                        if ((chain is null) || (chain.HashAlgorithm != hashAlgorithm) || (chain.Iterations != iterations) || !chain.Salt.AsSpan().SequenceEqual(salt))
                        {
                            entries = [];
                            oldCount = chain is null ? 0 : chain.Entries.Length;
                        }
                        else
                        {
                            entries = chain.Entries;
                            oldCount = entries.Length;
                        }

                        entries = Insert(entries, entry, now);
                        zone.Nsec3Chain = new Nsec3Chain(hashAlgorithm, iterations, salt, entries);

                        delta = entries.Length - oldCount;
                    }
                    else
                    {
                        NsecEntry[] entries = zone.NsecEntries;
                        int oldCount = entries.Length;

                        entries = Insert(entries, entry, now);
                        zone.NsecEntries = entries;

                        delta = entries.Length - oldCount;
                    }

                    if (delta != 0)
                        Interlocked.Add(ref _totalEntries, delta);

                    return;
                }
            }
        }

        private NsecEntry[] Insert(NsecEntry[] entries, NsecEntry entry, long now)
        {
            int i = FindFloor(entries, entry.Key);

            if ((i >= 0) && entries[i].Key.Equals(entry.Key, StringComparison.Ordinal))
            {
                NsecEntry[] replaced = (NsecEntry[])entries.Clone();
                replaced[i] = entry;
                return replaced;
            }

            if (entries.Length >= MAXIMUM_ZONE_ENTRIES)
            {
                entries = RemoveExpired(entries, now);

                if (entries.Length >= MAXIMUM_ZONE_ENTRIES)
                {
                    int evict = 0;

                    for (int j = 1; j < entries.Length; j++)
                    {
                        if (entries[j].Expires < entries[evict].Expires)
                            evict = j;
                    }

                    NsecEntry[] trimmed = new NsecEntry[entries.Length - 1];
                    Array.Copy(entries, 0, trimmed, 0, evict);
                    Array.Copy(entries, evict + 1, trimmed, evict, entries.Length - evict - 1);
                    entries = trimmed;
                }

                i = FindFloor(entries, entry.Key);
            }
            else if (Volatile.Read(ref _totalEntries) >= MAXIMUM_ENTRIES)
            {
                return entries;
            }

            int insertAt = i + 1;
            NsecEntry[] result = new NsecEntry[entries.Length + 1];

            Array.Copy(entries, 0, result, 0, insertAt);
            result[insertAt] = entry;
            Array.Copy(entries, insertAt, result, insertAt + 1, entries.Length - insertAt);

            return result;
        }

        private static NsecEntry[] RemoveExpired(NsecEntry[] entries, long now)
        {
            int valid = 0;

            foreach (NsecEntry entry in entries)
            {
                if (entry.Expires > now)
                    valid++;
            }

            if (valid == entries.Length)
                return entries;

            NsecEntry[] result = new NsecEntry[valid];
            int j = 0;

            foreach (NsecEntry entry in entries)
            {
                if (entry.Expires > now)
                    result[j++] = entry;
            }

            return result;
        }

        private static bool IsDelegation(NsecEntry entry)
        {
            return entry.HasType(DnsResourceRecordType.NS) && !entry.HasType(DnsResourceRecordType.SOA);
        }

        private static bool CanDenyNamesBelow(NsecEntry entry)
        {
            return !IsDelegation(entry) && !entry.HasType(DnsResourceRecordType.DNAME);
        }

        private static bool IsNoData(NsecEntry entry, DnsResourceRecordType type)
        {
            if (type == DnsResourceRecordType.DS)
            {
                if (entry.HasType(DnsResourceRecordType.SOA))
                    return false;
            }
            else
            {
                if (IsDelegation(entry))
                    return false;
            }

            if (entry.HasType(type) || entry.HasType(DnsResourceRecordType.CNAME))
                return false;

            return true;
        }

        private static DnsResponseCode SynthesizeFromNsec(NsecEntry[] entries, string qname, DnsResourceRecordType qtype, long now, List<NsecEntry> proof)
        {
            if (entries.Length == 0)
                return DnsResponseCode.Refused;

            string qkey = GetCanonicalKey(qname);

            NsecEntry exact = FindExact(entries, qkey);
            if (exact is not null)
            {
                if ((exact.Expires <= now) || !IsNoData(exact, qtype))
                    return DnsResponseCode.Refused;

                proof.Add(exact);
                return DnsResponseCode.NoError;
            }

            NsecEntry covering = FindCovering(entries, qkey);
            if ((covering is null) || (covering.Expires <= now))
                return DnsResponseCode.Refused;

            string ownerName = covering.Record.Name;

            if (IsSubDomain(qname, ownerName) && !CanDenyNamesBelow(covering))
                return DnsResponseCode.Refused;

            if (IsSubDomain(covering.NextDomainName, qname))
            {
                proof.Add(covering);
                return DnsResponseCode.NoError;
            }

            string closestEncloser = GetClosestEncloser(qname, ownerName);
            string closestEncloserNext = GetClosestEncloser(qname, covering.NextDomainName);

            if (closestEncloserNext.Length > closestEncloser.Length)
                closestEncloser = closestEncloserNext;

            string wildcard = closestEncloser.Length == 0 ? "*" : "*." + closestEncloser;
            string wildcardKey = GetCanonicalKey(wildcard);

            if (FindExact(entries, wildcardKey) is not null)
                return DnsResponseCode.Refused;

            NsecEntry wildcardCovering = FindCovering(entries, wildcardKey);
            if ((wildcardCovering is null) || (wildcardCovering.Expires <= now))
                return DnsResponseCode.Refused;

            if (IsSubDomain(wildcard, wildcardCovering.Record.Name) && !CanDenyNamesBelow(wildcardCovering))
                return DnsResponseCode.Refused;

            if (IsSubDomain(wildcardCovering.NextDomainName, wildcard))
                return DnsResponseCode.Refused;

            proof.Add(covering);

            if (!ReferenceEquals(wildcardCovering, covering))
                proof.Add(wildcardCovering);

            return DnsResponseCode.NxDomain;
        }

        private static DnsResponseCode SynthesizeFromNsec3(Nsec3Chain chain, NsecZone zone, string qname, DnsResourceRecordType qtype, long now, List<NsecEntry> proof)
        {
            if ((chain is null) || (chain.Entries.Length == 0))
                return DnsResponseCode.Refused;

            int labelsBelowZone = GetLabelCount(qname) - zone.LabelCount;
            if ((labelsBelowZone < 0) || (labelsBelowZone + 2 > MAXIMUM_NSEC3_HASHES))
                return DnsResponseCode.Refused;

            NsecEntry[] entries = chain.Entries;

            string qnameHash = chain.GetHashKey(qname);

            NsecEntry exact = FindExact(entries, qnameHash);
            if (exact is not null)
            {
                if ((exact.Expires <= now) || !IsNoData(exact, qtype))
                    return DnsResponseCode.Refused;

                proof.Add(exact);
                return DnsResponseCode.NoError;
            }

            string nextCloserHash = qnameHash;
            string closestEncloser = GetParentZone(qname);
            NsecEntry closestEncloserEntry;

            while (true)
            {
                if ((closestEncloser is null) || !IsSubDomainOrEqual(closestEncloser, zone.Name))
                    return DnsResponseCode.Refused;

                string closestEncloserHash = chain.GetHashKey(closestEncloser);

                closestEncloserEntry = FindExact(entries, closestEncloserHash);
                if (closestEncloserEntry is not null)
                    break;

                nextCloserHash = closestEncloserHash;
                closestEncloser = GetParentZone(closestEncloser);
            }

            if ((closestEncloserEntry.Expires <= now) || !CanDenyNamesBelow(closestEncloserEntry))
                return DnsResponseCode.Refused;

            NsecEntry nextCloserCovering = FindCovering(entries, nextCloserHash);
            if ((nextCloserCovering is null) || (nextCloserCovering.Expires <= now) || nextCloserCovering.OptOut)
                return DnsResponseCode.Refused;

            string wildcardHash = chain.GetHashKey(closestEncloser.Length == 0 ? "*" : "*." + closestEncloser);

            if (FindExact(entries, wildcardHash) is not null)
                return DnsResponseCode.Refused;

            NsecEntry wildcardCovering = FindCovering(entries, wildcardHash);
            if ((wildcardCovering is null) || (wildcardCovering.Expires <= now) || wildcardCovering.OptOut)
                return DnsResponseCode.Refused;

            proof.Add(closestEncloserEntry);

            if (!ReferenceEquals(nextCloserCovering, closestEncloserEntry))
                proof.Add(nextCloserCovering);

            if (!ReferenceEquals(wildcardCovering, closestEncloserEntry) && !ReferenceEquals(wildcardCovering, nextCloserCovering))
                proof.Add(wildcardCovering);

            return DnsResponseCode.NxDomain;
        }

        private static void AddWithSignatures(List<DnsResourceRecord> authority, DnsResourceRecord record, DnsResourceRecord[] rrsigRecords, uint ttl, bool dnssecOk)
        {
            DnsResourceRecord copy = record.CloneWithTtl(ttl);
            copy.SetDnssecStatus(DnssecStatus.Secure);
            authority.Add(copy);

            if (!dnssecOk)
                return;

            foreach (DnsResourceRecord rrsigRecord in rrsigRecords)
            {
                DnsResourceRecord rrsigCopy = rrsigRecord.CloneWithTtl(ttl);
                rrsigCopy.SetDnssecStatus(DnssecStatus.Secure);
                authority.Add(rrsigCopy);
            }
        }

        #endregion

        #region public

        public void Add(DnsDatagram response, uint maximumNegativeTtl)
        {
            IReadOnlyList<DnsResourceRecord> authority = response.Authority;
            if (authority.Count == 0)
                return;

            bool hasProof = false;

            foreach (DnsResourceRecord record in authority)
            {
                if (((record.Type == DnsResourceRecordType.NSEC) || (record.Type == DnsResourceRecordType.NSEC3)) && (record.DnssecStatus == DnssecStatus.Secure))
                {
                    hasProof = true;
                    break;
                }
            }

            if (!hasProof)
                return;

            long now = GetUnixTime();

            DnsResourceRecord soaRecord = null;
            DnsResourceRecord[] soaRRSIGRecords = null;
            uint soaNegativeTtl = maximumNegativeTtl;
            long soaExpires = 0;

            foreach (DnsResourceRecord record in authority)
            {
                if ((record.Type == DnsResourceRecordType.SOA) && (record.DnssecStatus == DnssecStatus.Secure))
                {
                    soaRRSIGRecords = GetRRSIGRecords(authority, record, out string soaSignersName, out long soaSignatureExpires, out uint soaRRSIGTtl);

                    if ((soaRRSIGRecords is not null) && soaSignersName.Equals(record.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        DnsSOARecordData soa = record.RDATA as DnsSOARecordData;

                        soaRecord = record;
                        soaNegativeTtl = Math.Min(Math.Min(record.TTL, soa.Minimum), Math.Min(soaRRSIGTtl, maximumNegativeTtl));
                        soaExpires = Math.Min(now + soaNegativeTtl, soaSignatureExpires);
                    }

                    break;
                }
            }

            bool addedForSoaZone = false;

            foreach (DnsResourceRecord record in authority)
            {
                if (record.DnssecStatus != DnssecStatus.Secure)
                    continue;

                bool isNsec3;

                switch (record.Type)
                {
                    case DnsResourceRecordType.NSEC:
                        isNsec3 = false;
                        break;

                    case DnsResourceRecordType.NSEC3:
                        isNsec3 = true;
                        break;

                    default:
                        continue;
                }

                DnsResourceRecord[] rrsigRecords = GetRRSIGRecords(authority, record, out string zoneName, out long signatureExpires, out uint rrsigTtl);
                if (rrsigRecords is null)
                    continue;

                if (!IsSubDomainOrEqual(record.Name, zoneName))
                    continue;

                bool isSoaZone = (soaRecord is not null) && soaRecord.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase);

                uint ttl = Math.Min(Math.Min(record.TTL, rrsigTtl), isSoaZone ? soaNegativeTtl : maximumNegativeTtl);
                long expires = Math.Min(now + ttl, signatureExpires);

                if (expires <= now)
                    continue;

                try
                {
                    if (isNsec3)
                    {
                        DnsNSEC3RecordData nsec3 = record.RDATA as DnsNSEC3RecordData;

                        if ((nsec3.HashAlgorithm != DnssecNSEC3HashAlgorithm.SHA1) || (nsec3.Iterations > MAXIMUM_NSEC3_ITERATIONS))
                            continue;

                        string parent = GetParentZone(record.Name);
                        if ((parent is null) || !parent.Equals(zoneName, StringComparison.OrdinalIgnoreCase))
                            continue;

                        string hashLabel = record.Name.Substring(0, record.Name.Length - parent.Length - (parent.Length > 0 ? 1 : 0)).ToUpperInvariant();
                        byte[] hash = Base32.FromBase32HexString(hashLabel);
                        byte[] nextHash = nsec3.NextHashedOwnerNameValue;

                        if ((hash.Length != 20) || (nextHash.Length != 20) || !Base32.ToBase32HexString(hash).Equals(hashLabel, StringComparison.Ordinal))
                            continue;

                        NsecEntry entry = new NsecEntry(Encoding.Latin1.GetString(hash), Encoding.Latin1.GetString(nextHash), null, record, rrsigRecords, nsec3.Types, nsec3.Flags.HasFlag(DnssecNSEC3Flags.OptOut), expires);

                        AddEntry(zoneName, entry, true, nsec3.HashAlgorithm, nsec3.Iterations, nsec3.Salt, now);
                    }
                    else
                    {
                        DnsNSECRecordData nsec = record.RDATA as DnsNSECRecordData;
                        string nextDomainName = nsec.NextDomainName;

                        if (!IsSubDomainOrEqual(nextDomainName, zoneName))
                            continue;

                        if ((nextDomainName.Length == record.Name.Length + 2) && (nextDomainName[0] == '\0') && (nextDomainName[1] == '.') && nextDomainName.EndsWith(record.Name, StringComparison.OrdinalIgnoreCase))
                            continue;

                        NsecEntry entry = new NsecEntry(GetCanonicalKey(record.Name), GetCanonicalKey(nextDomainName), nextDomainName, record, rrsigRecords, nsec.Types, false, expires);

                        AddEntry(zoneName, entry, false, DnssecNSEC3HashAlgorithm.Unknown, 0, null, now);
                    }
                }
                catch (Exception)
                {
                    continue;
                }

                if (isSoaZone)
                    addedForSoaZone = true;
            }

            if (addedForSoaZone && (soaExpires > now))
            {
                NsecZone zone = GetZone(soaRecord.Name);
                zone.Soa = new SoaEntry(soaRecord, soaRRSIGRecords, soaExpires);
            }
        }

        public DnsDatagram Query(DnsDatagram request, bool dnssecOk, ushort udpPayloadSize)
        {
            if (_zones.IsEmpty)
                return null;

            DnsQuestionRecord question = request.Question[0];

            if (question.Class != DnsClass.IN)
                return null;

            switch (question.Type)
            {
                case DnsResourceRecordType.ANY:
                case DnsResourceRecordType.RRSIG:
                case DnsResourceRecordType.NSEC:
                case DnsResourceRecordType.NSEC3:
                    return null;
            }

            string qname = question.Name;
            ReadOnlySpan<char> zoneName = qname;

            if (question.Type == DnsResourceRecordType.DS)
            {
                if (qname.Length == 0)
                    return null;

                int i = qname.IndexOf('.');
                zoneName = i < 0 ? ReadOnlySpan<char>.Empty : zoneName.Slice(i + 1);
            }

            ConcurrentDictionary<string, NsecZone>.AlternateLookup<ReadOnlySpan<char>> lookup = _zones.GetAlternateLookup<ReadOnlySpan<char>>();
            NsecZone zone;

            while (true)
            {
                if (lookup.TryGetValue(zoneName, out zone))
                    break;

                if (zoneName.Length == 0)
                    return null;

                int i = zoneName.IndexOf('.');
                zoneName = i < 0 ? ReadOnlySpan<char>.Empty : zoneName.Slice(i + 1);
            }

            long now = GetUnixTime();

            SoaEntry soa = zone.Soa;
            if ((soa is null) || (soa.Expires <= now))
                return null;

            List<NsecEntry> proof = new List<NsecEntry>(3);

            DnsResponseCode rcode = SynthesizeFromNsec(zone.NsecEntries, qname, question.Type, now, proof);
            if (rcode == DnsResponseCode.Refused)
            {
                proof.Clear();

                rcode = SynthesizeFromNsec3(zone.Nsec3Chain, zone, qname, question.Type, now, proof);
                if (rcode == DnsResponseCode.Refused)
                    return null;
            }

            long expires = soa.Expires;

            foreach (NsecEntry entry in proof)
                expires = Math.Min(expires, entry.Expires);

            uint ttl = (uint)Math.Clamp(expires - now, 1, uint.MaxValue);

            List<DnsResourceRecord> authority = new List<DnsResourceRecord>(dnssecOk ? 2 + (proof.Count * 2) : 1);

            AddWithSignatures(authority, soa.Record, soa.RRSIGRecords, ttl, dnssecOk);

            if (dnssecOk)
            {
                foreach (NsecEntry entry in proof)
                    AddWithSignatures(authority, entry.Record, entry.RRSIGRecords, ttl, true);
            }

            Interlocked.Increment(ref _synthesizedResponses);

            IReadOnlyList<EDnsOption> options = null;

            if (request.EDNS is not null)
                options = [new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Synthesized, qname.ToLowerInvariant() + " " + question.Type.ToString() + " " + question.Class.ToString()))];

            if (dnssecOk)
                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, true, request.CheckingDisabled, rcode, request.Question, null, authority, null, udpPayloadSize, EDnsHeaderFlags.DNSSEC_OK, options);

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, true, false, request.CheckingDisabled, rcode, request.Question, null, authority, null, request.EDNS is null ? ushort.MinValue : udpPayloadSize, EDnsHeaderFlags.None, options);
        }

        public int RemoveExpired()
        {
            long now = GetUnixTime();
            int totalRemoved = 0;

            foreach (KeyValuePair<string, NsecZone> item in _zones)
            {
                NsecZone zone = item.Value;

                lock (zone.Lock)
                {
                    int removed = 0;

                    NsecEntry[] nsecEntries = zone.NsecEntries;
                    NsecEntry[] validNsecEntries = RemoveExpired(nsecEntries, now);
                    if (!ReferenceEquals(nsecEntries, validNsecEntries))
                    {
                        removed += nsecEntries.Length - validNsecEntries.Length;
                        zone.NsecEntries = validNsecEntries;
                    }

                    Nsec3Chain chain = zone.Nsec3Chain;
                    if (chain is not null)
                    {
                        NsecEntry[] validNsec3Entries = RemoveExpired(chain.Entries, now);
                        if (!ReferenceEquals(chain.Entries, validNsec3Entries))
                        {
                            removed += chain.Entries.Length - validNsec3Entries.Length;
                            zone.Nsec3Chain = validNsec3Entries.Length == 0 ? null : new Nsec3Chain(chain.HashAlgorithm, chain.Iterations, chain.Salt, validNsec3Entries);
                        }
                    }

                    SoaEntry soa = zone.Soa;
                    if ((soa is not null) && (soa.Expires <= now))
                        zone.Soa = null;

                    if ((zone.NsecEntries.Length == 0) && (zone.Nsec3Chain is null) && (zone.Soa is null))
                    {
                        zone.Removed = true;
                        _zones.TryRemove(item.Key, out _);
                    }

                    if (removed > 0)
                    {
                        Interlocked.Add(ref _totalEntries, -removed);
                        totalRemoved += removed;
                    }
                }
            }

            return totalRemoved;
        }

        public void RemoveTree(string domain)
        {
            foreach (KeyValuePair<string, NsecZone> item in _zones)
            {
                if (!IsSubDomainOrEqual(item.Key, domain))
                    continue;

                NsecZone zone = item.Value;

                lock (zone.Lock)
                {
                    int removed = zone.NsecEntries.Length + (zone.Nsec3Chain is null ? 0 : zone.Nsec3Chain.Entries.Length);

                    zone.NsecEntries = [];
                    zone.Nsec3Chain = null;
                    zone.Soa = null;
                    zone.Removed = true;

                    _zones.TryRemove(item.Key, out _);

                    if (removed > 0)
                        Interlocked.Add(ref _totalEntries, -removed);
                }
            }
        }

        public void Flush()
        {
            RemoveTree(string.Empty);
        }

        #endregion

        #region properties

        public long TotalEntries
        { get { return Math.Max(0, Volatile.Read(ref _totalEntries)); } }

        public long SynthesizedResponses
        { get { return Volatile.Read(ref _synthesizedResponses); } }

        #endregion

        sealed class NsecZone
        {
            public readonly string Name;
            public readonly int LabelCount;
            public readonly Lock Lock = new Lock();

            public volatile NsecEntry[] NsecEntries = [];
            public volatile Nsec3Chain Nsec3Chain;
            public volatile SoaEntry Soa;
            public bool Removed;

            public NsecZone(string name)
            {
                Name = name;
                LabelCount = GetLabelCount(name);
            }
        }

        sealed class Nsec3Chain
        {
            public readonly DnssecNSEC3HashAlgorithm HashAlgorithm;
            public readonly ushort Iterations;
            public readonly byte[] Salt;
            public readonly NsecEntry[] Entries;

            public Nsec3Chain(DnssecNSEC3HashAlgorithm hashAlgorithm, ushort iterations, byte[] salt, NsecEntry[] entries)
            {
                HashAlgorithm = hashAlgorithm;
                Iterations = iterations;
                Salt = salt;
                Entries = entries;
            }

            public string GetHashKey(string domain)
            {
                return Encoding.Latin1.GetString(DnsNSEC3RecordData.ComputeHashedOwnerName(domain, HashAlgorithm, Iterations, Salt));
            }
        }

        sealed class SoaEntry
        {
            public readonly DnsResourceRecord Record;
            public readonly DnsResourceRecord[] RRSIGRecords;
            public readonly long Expires;

            public SoaEntry(DnsResourceRecord record, DnsResourceRecord[] rrsigRecords, long expires)
            {
                Record = record;
                RRSIGRecords = rrsigRecords;
                Expires = expires;
            }
        }

        sealed class NsecEntry
        {
            public readonly string Key;
            public readonly string NextKey;
            public readonly string NextDomainName;
            public readonly DnsResourceRecord Record;
            public readonly DnsResourceRecord[] RRSIGRecords;
            public readonly IReadOnlyList<DnsResourceRecordType> Types;
            public readonly bool OptOut;
            public readonly long Expires;

            public NsecEntry(string key, string nextKey, string nextDomainName, DnsResourceRecord record, DnsResourceRecord[] rrsigRecords, IReadOnlyList<DnsResourceRecordType> types, bool optOut, long expires)
            {
                Key = key;
                NextKey = nextKey;
                NextDomainName = nextDomainName;
                Record = record;
                RRSIGRecords = rrsigRecords;
                Types = types;
                OptOut = optOut;
                Expires = expires;
            }

            public bool HasType(DnsResourceRecordType type)
            {
                for (int i = 0; i < Types.Count; i++)
                {
                    if (Types[i] == type)
                        return true;
                }

                return false;
            }
        }
    }
}
