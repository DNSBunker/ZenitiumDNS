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
using ZenitiumDns.ApplicationCommon;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns
{
    public sealed class LocalZone
    {
        #region variables

        readonly string _name;
        readonly uint _serial;
        readonly uint _expire;
        readonly bool _verified;
        readonly LocalizedText _verification;
        readonly DateTime _validUntil;

        readonly DnsResourceRecord _soa;
        readonly IReadOnlyList<DnsResourceRecord> _soaSignatures;
        readonly IReadOnlyList<DnsResourceRecord> _dnsKeys;
        readonly IReadOnlyList<DnsResourceRecord> _dnsKeySignatures;

        readonly Dictionary<string, Delegation> _delegations;
        readonly HashSet<string> _owners;
        readonly List<DnsResourceRecord> _nsecChain;
        readonly Dictionary<DnsResourceRecord, IReadOnlyList<DnsResourceRecord>> _nsecSignatures;
        readonly Dictionary<string, List<DnsResourceRecord>> _addresses;

        #endregion

        #region constructor

        private LocalZone(string name, IReadOnlyList<DnsResourceRecord> records, bool verified, LocalizedText verification, DateTime validUntil)
        {
            _name = name;
            _verified = verified;
            _verification = verification;
            _validUntil = validUntil;

            Dictionary<(string, DnsResourceRecordType), List<DnsResourceRecord>> rrsets = GroupRRsets(records);
            Dictionary<(string, DnsResourceRecordType), List<DnsResourceRecord>> signatures = GroupSignatures(records);

            _soa = rrsets[(name, DnsResourceRecordType.SOA)][0];
            DnsSOARecordData soa = _soa.RDATA as DnsSOARecordData;
            _serial = soa.Serial;
            _expire = soa.Expire;
            _soaSignatures = GetSignatures(signatures, name, DnsResourceRecordType.SOA);

            _dnsKeys = rrsets.TryGetValue((name, DnsResourceRecordType.DNSKEY), out List<DnsResourceRecord> dnsKeys) ? dnsKeys : [];
            _dnsKeySignatures = GetSignatures(signatures, name, DnsResourceRecordType.DNSKEY);

            _owners = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _addresses = new Dictionary<string, List<DnsResourceRecord>>(StringComparer.OrdinalIgnoreCase);
            _delegations = new Dictionary<string, Delegation>(StringComparer.OrdinalIgnoreCase);
            _nsecChain = new List<DnsResourceRecord>();
            _nsecSignatures = new Dictionary<DnsResourceRecord, IReadOnlyList<DnsResourceRecord>>();

            foreach (KeyValuePair<(string, DnsResourceRecordType), List<DnsResourceRecord>> rrset in rrsets)
            {
                (string owner, DnsResourceRecordType type) = rrset.Key;

                _owners.Add(owner);

                switch (type)
                {
                    case DnsResourceRecordType.A:
                    case DnsResourceRecordType.AAAA:
                        if (!_addresses.TryGetValue(owner, out List<DnsResourceRecord> addresses))
                        {
                            addresses = new List<DnsResourceRecord>(2);
                            _addresses.Add(owner, addresses);
                        }

                        addresses.AddRange(rrset.Value);
                        break;

                    case DnsResourceRecordType.NSEC:
                        foreach (DnsResourceRecord nsec in rrset.Value)
                        {
                            _nsecChain.Add(nsec);
                            _nsecSignatures[nsec] = GetSignatures(signatures, owner, DnsResourceRecordType.NSEC);
                        }

                        break;
                }
            }

            foreach (KeyValuePair<(string, DnsResourceRecordType), List<DnsResourceRecord>> rrset in rrsets)
            {
                (string owner, DnsResourceRecordType type) = rrset.Key;

                if ((type != DnsResourceRecordType.NS) || owner.Equals(name, StringComparison.OrdinalIgnoreCase))
                    continue;

                List<DnsResourceRecord> glue = new List<DnsResourceRecord>();

                foreach (DnsResourceRecord ns in rrset.Value)
                {
                    if (_addresses.TryGetValue((ns.RDATA as DnsNSRecordData).NameServer, out List<DnsResourceRecord> addresses))
                        glue.AddRange(addresses);
                }

                rrsets.TryGetValue((owner, DnsResourceRecordType.DS), out List<DnsResourceRecord> ds);
                rrsets.TryGetValue((owner, DnsResourceRecordType.NSEC), out List<DnsResourceRecord> nsec);

                _delegations[owner] = new Delegation(owner, rrset.Value, ds ?? [], GetSignatures(signatures, owner, DnsResourceRecordType.DS), nsec ?? [], GetSignatures(signatures, owner, DnsResourceRecordType.NSEC), glue);
            }

            _nsecChain.Sort(delegate (DnsResourceRecord x, DnsResourceRecord y) { return DnsNSECRecordData.CanonicalComparison(x.Name, y.Name); });
        }

        #endregion

        #region private

        private static Dictionary<(string, DnsResourceRecordType), List<DnsResourceRecord>> GroupRRsets(IReadOnlyList<DnsResourceRecord> records)
        {
            Dictionary<(string, DnsResourceRecordType), List<DnsResourceRecord>> rrsets = new Dictionary<(string, DnsResourceRecordType), List<DnsResourceRecord>>();

            foreach (DnsResourceRecord record in records)
            {
                if (record.Type == DnsResourceRecordType.RRSIG)
                    continue;

                (string, DnsResourceRecordType) key = (record.Name.ToLowerInvariant(), record.Type);

                if (!rrsets.TryGetValue(key, out List<DnsResourceRecord> rrset))
                {
                    rrset = new List<DnsResourceRecord>(1);
                    rrsets.Add(key, rrset);
                }

                rrset.Add(record);
            }

            return rrsets;
        }

        private static Dictionary<(string, DnsResourceRecordType), List<DnsResourceRecord>> GroupSignatures(IReadOnlyList<DnsResourceRecord> records)
        {
            Dictionary<(string, DnsResourceRecordType), List<DnsResourceRecord>> signatures = new Dictionary<(string, DnsResourceRecordType), List<DnsResourceRecord>>();

            foreach (DnsResourceRecord record in records)
            {
                if (record.Type != DnsResourceRecordType.RRSIG)
                    continue;

                (string, DnsResourceRecordType) key = (record.Name.ToLowerInvariant(), (record.RDATA as DnsRRSIGRecordData).TypeCovered);

                if (!signatures.TryGetValue(key, out List<DnsResourceRecord> list))
                {
                    list = new List<DnsResourceRecord>(1);
                    signatures.Add(key, list);
                }

                list.Add(record);
            }

            return signatures;
        }

        private static IReadOnlyList<DnsResourceRecord> GetSignatures(Dictionary<(string, DnsResourceRecordType), List<DnsResourceRecord>> signatures, string owner, DnsResourceRecordType type)
        {
            if (signatures.TryGetValue((owner.ToLowerInvariant(), type), out List<DnsResourceRecord> list))
                return list;

            return [];
        }

        private static bool VerifyRRset(IReadOnlyList<DnsResourceRecord> rrset, IReadOnlyList<DnsResourceRecord> rrsigs, IReadOnlyList<DnsResourceRecord> dnsKeys, ref DateTime validUntil)
        {
            DnsClient.ResolverContext context = new DnsClient.ResolverContext();

            foreach (DnsResourceRecord rrsig in rrsigs)
            {
                if ((rrsig.RDATA as DnsRRSIGRecordData).IsSignatureValid(rrset, dnsKeys, context, out _))
                {
                    DateTime expiration = DateTime.UnixEpoch.AddSeconds((rrsig.RDATA as DnsRRSIGRecordData).SignatureExpiration);
                    if (expiration < validUntil)
                        validUntil = expiration;

                    return true;
                }
            }

            return false;
        }

        private static bool IsBelow(string name, string zoneName)
        {
            if (zoneName.Length == 0)
                return name.Length > 0;

            return name.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase);
        }

        private DnsResourceRecord FindCoveringNsec(string name)
        {
            int low = 0;
            int high = _nsecChain.Count - 1;
            DnsResourceRecord candidate = null;

            while (low <= high)
            {
                int mid = (low + high) / 2;
                int value = DnsNSECRecordData.CanonicalComparison(_nsecChain[mid].Name, name);

                if (value == 0)
                    return _nsecChain[mid];

                if (value < 0)
                {
                    candidate = _nsecChain[mid];
                    low = mid + 1;
                }
                else
                {
                    high = mid - 1;
                }
            }

            return candidate ?? ((_nsecChain.Count > 0) ? _nsecChain[^1] : null);
        }

        private DnsResourceRecord Clone(DnsResourceRecord record, uint maxTtl = uint.MaxValue)
        {
            DnsResourceRecord clone = new DnsResourceRecord(record.Name, record.Type, record.Class, Math.Min(record.OriginalTtlValue, maxTtl), record.RDATA);

            if (_verified)
                clone.SetDnssecStatus(DnssecStatus.Secure, true);

            return clone;
        }

        private void AddClones(List<DnsResourceRecord> target, IReadOnlyList<DnsResourceRecord> records, uint maxTtl = uint.MaxValue)
        {
            foreach (DnsResourceRecord record in records)
                target.Add(Clone(record, maxTtl));
        }

        private void AddNsec(List<DnsResourceRecord> authority, List<DnsResourceRecord> added, DnsResourceRecord nsec, uint maxTtl)
        {
            if ((nsec is null) || added.Contains(nsec))
                return;

            added.Add(nsec);
            authority.Add(Clone(nsec, maxTtl));

            if (_nsecSignatures.TryGetValue(nsec, out IReadOnlyList<DnsResourceRecord> signatures))
                AddClones(authority, signatures, maxTtl);
        }

        #endregion

        #region public

        public static LocalZone Load(IReadOnlyList<DnsResourceRecord> records, string zoneName, IReadOnlyList<DnsResourceRecord> apexDS, bool requireVerification)
        {
            zoneName = zoneName.TrimEnd('.').ToLowerInvariant();

            List<DnsResourceRecord> zoneRecords = new List<DnsResourceRecord>(records.Count);

            foreach (DnsResourceRecord record in records)
            {
                if (record.Class != DnsClass.IN)
                    continue;

                if (!record.Name.Equals(zoneName, StringComparison.OrdinalIgnoreCase) && !IsBelow(record.Name, zoneName))
                    continue;

                zoneRecords.Add(record);
            }

            Dictionary<(string, DnsResourceRecordType), List<DnsResourceRecord>> rrsets = GroupRRsets(zoneRecords);
            Dictionary<(string, DnsResourceRecordType), List<DnsResourceRecord>> signatures = GroupSignatures(zoneRecords);

            if (!rrsets.TryGetValue((zoneName, DnsResourceRecordType.SOA), out List<DnsResourceRecord> soaRecords) || (soaRecords.Count != 1))
                throw new InvalidOperationException("The zone file has no SOA record for the zone apex.");

            if (!rrsets.ContainsKey((zoneName, DnsResourceRecordType.NS)))
                throw new InvalidOperationException("The zone file has no NS records for the zone apex.");

            bool verified = false;
            LocalizedText verification;
            DateTime validUntil = DateTime.MaxValue;

            if ((apexDS is null) || (apexDS.Count == 0))
            {
                verification = Lang.L("Keine DS-Einträge für die Zone vorhanden, die Signaturen wurden nicht geprüft.", "No DS records exist for the zone, the signatures were not verified.");
            }
            else if (!rrsets.TryGetValue((zoneName, DnsResourceRecordType.DNSKEY), out List<DnsResourceRecord> dnsKeys))
            {
                verification = Lang.L("Die Zone ist nicht signiert.", "The zone is not signed.");
            }
            else
            {
                List<DnsResourceRecord> keySigningKeys = new List<DnsResourceRecord>();

                foreach (DnsResourceRecord dnsKey in dnsKeys)
                {
                    foreach (DnsResourceRecord ds in apexDS)
                    {
                        if ((dnsKey.RDATA as DnsDNSKEYRecordData).IsDnsKeyValid(zoneName, ds.RDATA as DnsDSRecordData))
                        {
                            keySigningKeys.Add(dnsKey);
                            break;
                        }
                    }
                }

                if (keySigningKeys.Count == 0)
                {
                    verification = Lang.L("Kein DNSKEY der Zone passt zu den Trust Anchors bzw. DS-Einträgen.", "No DNSKEY of the zone matches the trust anchors or DS records.");
                }
                else if (!VerifyRRset(dnsKeys, GetSignatures(signatures, zoneName, DnsResourceRecordType.DNSKEY), keySigningKeys, ref validUntil))
                {
                    verification = Lang.L("Die Signatur der DNSKEY-Einträge ist ungültig oder abgelaufen.", "The signature of the DNSKEY records is invalid or expired.");
                }
                else if (rrsets.TryGetValue((zoneName, DnsResourceRecordType.ZONEMD), out List<DnsResourceRecord> zonemdRecords))
                {
                    DnsZONEMDRecordData zonemd = null;

                    foreach (DnsResourceRecord zonemdRecord in zonemdRecords)
                    {
                        DnsZONEMDRecordData candidate = zonemdRecord.RDATA as DnsZONEMDRecordData;

                        if ((candidate.Scheme == ZoneMdScheme.Simple) && ((candidate.HashAlgorithm == ZoneMdHashAlgorithm.SHA384) || (candidate.HashAlgorithm == ZoneMdHashAlgorithm.SHA512)))
                        {
                            zonemd = candidate;
                            break;
                        }
                    }

                    if (zonemd is null)
                        verification = Lang.L("Die Zone enthält keinen unterstützten ZONEMD-Eintrag.", "The zone contains no supported ZONEMD record.");
                    else if (zonemd.Serial != (soaRecords[0].RDATA as DnsSOARecordData).Serial)
                        verification = Lang.L("Die Seriennummer im ZONEMD-Eintrag passt nicht zum SOA.", "The serial in the ZONEMD record does not match the SOA.");
                    else if (!VerifyRRset(zonemdRecords, GetSignatures(signatures, zoneName, DnsResourceRecordType.ZONEMD), dnsKeys, ref validUntil))
                        verification = Lang.L("Die Signatur des ZONEMD-Eintrags ist ungültig oder abgelaufen.", "The signature of the ZONEMD record is invalid or expired.");
                    else if (!DnsZONEMDRecordData.ComputeDigest(zoneRecords, zoneName, zonemd.HashAlgorithm).AsSpan().SequenceEqual(zonemd.Digest))
                        verification = Lang.L("Die ZONEMD-Prüfsumme stimmt nicht, die Zonendatei ist verändert oder unvollständig.", "The ZONEMD digest does not match, the zone file is modified or incomplete.");
                    else
                    {
                        verified = true;
                        verification = Lang.L("ZONEMD-Prüfsumme und DNSSEC-Signaturen sind gültig.", "ZONEMD digest and DNSSEC signatures are valid.");
                    }
                }
                else
                {
                    int signedRRsets = 0;
                    string failed = null;

                    foreach (KeyValuePair<(string, DnsResourceRecordType), List<DnsResourceRecord>> signature in signatures)
                    {
                        if (signature.Key.Item2 == DnsResourceRecordType.DNSKEY)
                            continue;

                        if (!rrsets.TryGetValue(signature.Key, out List<DnsResourceRecord> rrset) || !VerifyRRset(rrset, signature.Value, dnsKeys, ref validUntil))
                        {
                            failed = signature.Key.Item1 + " " + signature.Key.Item2.ToString();
                            break;
                        }

                        signedRRsets++;
                    }

                    if (failed is not null)
                    {
                        verification = Lang.L("Die Signatur für " + failed + " ist ungültig oder abgelaufen.", "The signature for " + failed + " is invalid or expired.");
                    }
                    else
                    {
                        verified = true;
                        verification = Lang.L("Alle " + signedRRsets + " signierten Eintragsgruppen sind gültig signiert.", "All " + signedRRsets + " signed RRsets are validly signed.");
                    }
                }
            }

            if (requireVerification && !verified)
                throw new LocalizedException(verification);

            return new LocalZone(zoneName, zoneRecords, verified, verification, validUntil);
        }

        public DnsDatagram GetNameErrorResponse(DnsDatagram request, uint maxNegativeTtl = uint.MaxValue)
        {
            if (request.Question.Count != 1)
                return null;

            DnsQuestionRecord question = request.Question[0];
            string qname = question.Name.ToLowerInvariant();

            if (!IsBelow(qname, _name))
                return null;

            string closestEncloser = qname;

            while (true)
            {
                if (_delegations.ContainsKey(closestEncloser))
                    return null;

                if (_owners.Contains(closestEncloser))
                    break;

                int i = closestEncloser.IndexOf('.');
                closestEncloser = i < 0 ? string.Empty : closestEncloser.Substring(i + 1);

                if (closestEncloser.Equals(_name, StringComparison.OrdinalIgnoreCase))
                    break;
            }

            if (closestEncloser.Equals(qname, StringComparison.OrdinalIgnoreCase))
                return null;

            List<DnsResourceRecord> authority = new List<DnsResourceRecord>(8);
            List<DnsResourceRecord> added = new List<DnsResourceRecord>(2);

            uint maxTtl = Math.Min(maxNegativeTtl, Math.Min(_soa.OriginalTtlValue, (_soa.RDATA as DnsSOARecordData).Minimum));

            authority.Add(Clone(_soa, maxTtl));
            AddClones(authority, _soaSignatures, maxTtl);

            AddNsec(authority, added, FindCoveringNsec(qname), maxTtl);
            AddNsec(authority, added, FindCoveringNsec(closestEncloser.Length == 0 ? "*" : "*." + closestEncloser), maxTtl);

            return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, true, false, request.RecursionDesired, true, false, request.CheckingDisabled, DnsResponseCode.NxDomain, request.Question, null, authority, null, request.EDNS is null ? ushort.MinValue : request.EDNS.UdpPayloadSize, request.DnssecOk ? EDnsHeaderFlags.DNSSEC_OK : EDnsHeaderFlags.None);
        }

        public IEnumerable<DnsDatagram> GetSeedResponses()
        {
            if (_verified && (_dnsKeys.Count > 0))
            {
                List<DnsResourceRecord> answer = new List<DnsResourceRecord>(_dnsKeys.Count + _dnsKeySignatures.Count);
                AddClones(answer, _dnsKeys);
                AddClones(answer, _dnsKeySignatures);

                yield return new DnsDatagram(0, true, DnsOpcode.StandardQuery, true, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(_name, DnsResourceRecordType.DNSKEY, DnsClass.IN)], answer);
            }

            foreach (Delegation delegation in _delegations.Values)
            {
                List<DnsResourceRecord> authority = new List<DnsResourceRecord>(delegation.NS.Count + 4);

                foreach (DnsResourceRecord ns in delegation.NS)
                    authority.Add(new DnsResourceRecord(ns.Name, ns.Type, ns.Class, ns.OriginalTtlValue, new DnsNSRecordData((ns.RDATA as DnsNSRecordData).NameServer, false)));

                if (_verified)
                {
                    if (delegation.DS.Count > 0)
                    {
                        AddClones(authority, delegation.DS);
                        AddClones(authority, delegation.DSSignatures);
                    }
                    else if (delegation.NSEC.Count > 0)
                    {
                        AddClones(authority, delegation.NSEC);
                        AddClones(authority, delegation.NSECSignatures);
                    }
                }

                List<DnsResourceRecord> glue = new List<DnsResourceRecord>(delegation.Glue.Count);

                foreach (DnsResourceRecord record in delegation.Glue)
                    glue.Add(new DnsResourceRecord(record.Name, record.Type, record.Class, record.OriginalTtlValue, record.RDATA));

                yield return new DnsDatagram(0, true, DnsOpcode.StandardQuery, false, false, false, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord(delegation.Name, DnsResourceRecordType.NS, DnsClass.IN)], null, authority, glue);
            }
        }

        public IReadOnlyList<DnsResourceRecord> GetDS(string childName)
        {
            if (_verified && _delegations.TryGetValue(childName.TrimEnd('.'), out Delegation delegation))
                return delegation.DS;

            return null;
        }

        #endregion

        #region properties

        public string Name
        { get { return _name; } }

        public uint Serial
        { get { return _serial; } }

        public uint Expire
        { get { return _expire; } }

        public bool Verified
        { get { return _verified; } }

        public LocalizedText Verification
        { get { return _verification; } }

        public DateTime ValidUntil
        { get { return _validUntil; } }

        public int DelegationCount
        { get { return _delegations.Count; } }

        #endregion

        sealed record Delegation(string Name, IReadOnlyList<DnsResourceRecord> NS, IReadOnlyList<DnsResourceRecord> DS, IReadOnlyList<DnsResourceRecord> DSSignatures, IReadOnlyList<DnsResourceRecord> NSEC, IReadOnlyList<DnsResourceRecord> NSECSignatures, IReadOnlyList<DnsResourceRecord> Glue);
    }
}
