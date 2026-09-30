/*
Technitium DNS Server
Copyright (C) 2024  Shreyas Zare (shreyas@technitium.com)
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
using System.IO;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.ResourceRecords
{
    class CacheRecordInfo
    {
        #region variables

        public static readonly CacheRecordInfo Default = new CacheRecordInfo();

        const int MAX_POOLED_NAME_SERVERS = 65536;
        static readonly ConcurrentDictionary<NameServerAddress, NameServerAddress> _nameServerPool = new ConcurrentDictionary<NameServerAddress, NameServerAddress>();

        sealed class Extras
        {
            public IReadOnlyList<DnsResourceRecord> GlueRecords;
            public IReadOnlyList<DnsResourceRecord> RRSIGRecords;
            public IReadOnlyList<DnsResourceRecord> NSECRecords;
            public NetworkAddress EDnsClientSubnet;

            public bool IsEmpty
            { get { return (GlueRecords is null) && (RRSIGRecords is null) && (NSECRecords is null) && (EDnsClientSubnet is null); } }
        }

        Extras _extras;
        DnsDatagramMetadata _responseMetadata;

        DateTime _lastUsedOn;

        #endregion

        #region constructor

        public CacheRecordInfo()
        { }

        public CacheRecordInfo(BinaryReader bR)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                case 2:
                    GlueRecords = ReadRecordsFrom(bR, true);
                    RRSIGRecords = ReadRecordsFrom(bR, false);
                    NSECRecords = ReadRecordsFrom(bR, true);

                    if (bR.ReadBoolean())
                        EDnsClientSubnet = NetworkAddress.ReadFrom(bR);

                    if (version >= 2)
                    {
                        if (bR.ReadBoolean())
                            _responseMetadata = InternMetadata(new DnsDatagramMetadata(bR));
                    }

                    break;

                default:
                    throw new InvalidDataException("CacheRecordInfo format version not supported.");
            }
        }

        #endregion

        #region private

        private static DnsResourceRecord[] ReadRecordsFrom(BinaryReader bR, bool includeInnerRRSigRecords)
        {
            int count = bR.ReadByte();
            if (count == 0)
                return null;

            DnsResourceRecord[] records = new DnsResourceRecord[count];

            for (int i = 0; i < count; i++)
            {
                records[i] = DnsResourceRecord.ReadCacheRecordFrom(bR, delegate (DnsResourceRecord record)
                {
                    if (includeInnerRRSigRecords)
                    {
                        IReadOnlyList<DnsResourceRecord> rrsigRecords = ReadRecordsFrom(bR, false);
                        if (rrsigRecords is not null)
                            record.GetCacheRecordInfo().RRSIGRecords = rrsigRecords;
                    }
                });
            }

            return records;
        }

        private static void WriteRecordsTo(IReadOnlyList<DnsResourceRecord> records, BinaryWriter bW, bool includeInnerRRSigRecords)
        {
            if (records is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(records.Count));

                foreach (DnsResourceRecord record in records)
                {
                    record.WriteCacheRecordTo(bW, delegate ()
                    {
                        if (includeInnerRRSigRecords)
                        {
                            if (record.Tag is CacheRecordInfo cacheRecordInfo)
                                WriteRecordsTo(cacheRecordInfo.RRSIGRecords, bW, false);
                            else
                                bW.Write((byte)0);
                        }
                    });
                }
            }
        }

        private Extras GetExtras(bool create)
        {
            Extras extras = _extras;

            if ((extras is null) && create)
            {
                extras = new Extras();
                _extras = extras;
            }

            return extras;
        }

        private void TrimExtras()
        {
            Extras extras = _extras;

            if ((extras is not null) && extras.IsEmpty)
                _extras = null;
        }

        #endregion

        #region public

        public static DnsDatagramMetadata InternMetadata(DnsDatagramMetadata metadata)
        {
            NameServerAddress server = metadata?.NameServer;
            if (server is null)
                return metadata;

            if (_nameServerPool.TryGetValue(server, out NameServerAddress pooled))
            {
                if (ReferenceEquals(pooled, server))
                    return metadata;

                return new DnsDatagramMetadata(pooled, metadata.DatagramSize, metadata.RoundTripTime);
            }

            if (_nameServerPool.Count >= MAX_POOLED_NAME_SERVERS)
                _nameServerPool.Clear();

            _nameServerPool.TryAdd(server, server);
            return metadata;
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)2);

            WriteRecordsTo(GlueRecords, bW, true);
            WriteRecordsTo(RRSIGRecords, bW, false);
            WriteRecordsTo(NSECRecords, bW, true);

            NetworkAddress eDnsClientSubnet = EDnsClientSubnet;

            if (eDnsClientSubnet is null)
            {
                bW.Write(false);
            }
            else
            {
                bW.Write(true);
                eDnsClientSubnet.WriteTo(bW);
            }

            if (_responseMetadata is null)
            {
                bW.Write(false);
            }
            else
            {
                bW.Write(true);
                _responseMetadata.WriteTo(bW);
            }
        }

        #endregion

        #region properties

        public IReadOnlyList<DnsResourceRecord> GlueRecords
        {
            get { return _extras?.GlueRecords; }
            set
            {
                if ((value is null) || (value.Count == 0))
                {
                    Extras extras = GetExtras(false);
                    if (extras is not null)
                    {
                        extras.GlueRecords = null;
                        TrimExtras();
                    }
                }
                else
                {
                    GetExtras(true).GlueRecords = value;
                }
            }
        }

        public IReadOnlyList<DnsResourceRecord> RRSIGRecords
        {
            get { return _extras?.RRSIGRecords; }
            set
            {
                if ((value is null) || (value.Count == 0))
                {
                    Extras extras = GetExtras(false);
                    if (extras is not null)
                    {
                        extras.RRSIGRecords = null;
                        TrimExtras();
                    }
                }
                else
                {
                    GetExtras(true).RRSIGRecords = value;
                }
            }
        }

        public IReadOnlyList<DnsResourceRecord> NSECRecords
        {
            get { return _extras?.NSECRecords; }
            set
            {
                if ((value is null) || (value.Count == 0))
                {
                    Extras extras = GetExtras(false);
                    if (extras is not null)
                    {
                        extras.NSECRecords = null;
                        TrimExtras();
                    }
                }
                else
                {
                    GetExtras(true).NSECRecords = value;
                }
            }
        }

        public NetworkAddress EDnsClientSubnet
        {
            get { return _extras?.EDnsClientSubnet; }
            set
            {
                if (value is null)
                {
                    Extras extras = GetExtras(false);
                    if (extras is not null)
                    {
                        extras.EDnsClientSubnet = null;
                        TrimExtras();
                    }
                }
                else
                {
                    GetExtras(true).EDnsClientSubnet = value;
                }
            }
        }

        public DnsDatagramMetadata ResponseMetadata
        {
            get { return _responseMetadata; }
            set { _responseMetadata = value; }
        }

        public DateTime LastUsedOn
        {
            get { return _lastUsedOn; }
            set { _lastUsedOn = value; }
        }

        #endregion
    }
}
