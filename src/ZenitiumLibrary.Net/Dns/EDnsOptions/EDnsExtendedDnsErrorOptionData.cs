/*
Technitium Library
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

using System;
using System.IO;
using System.Text;
using System.Text.Json;
using ZenitiumLibrary.IO;

namespace ZenitiumLibrary.Net.Dns.EDnsOptions
{
    public enum EDnsExtendedDnsErrorCode : ushort
    {
        Other = 0,

        UnsupportedDnsKeyAlgorithm = 1,

        UnsupportedDsDigestType = 2,

        StaleAnswer = 3,

        ForgedAnswer = 4,

        DnssecIndeterminate = 5,

        DnssecBogus = 6,

        SignatureExpired = 7,

        SignatureNotYetValid = 8,

        DNSKEYMissing = 9,

        RRSIGsMissing = 10,

        NoZoneKeyBitSet = 11,

        NSECMissing = 12,

        CachedError = 13,

        NotReady = 14,

        Blocked = 15,

        Censored = 16,

        Filtered = 17,

        Prohibited = 18,

        StaleNxDomainAnswer = 19,

        NotAuthoritative = 20,

        NotSupported = 21,

        NoReachableAuthority = 22,

        NetworkError = 23,

        InvalidData = 24,

        SignatureExpiredBeforeValid = 25,

        TooEarly = 26,

        UnsupportedNSEC3IterationsValue = 27,

        UnableToConformToPolicy = 28,

        Synthesized = 29,

        InvalidQueryType = 30,

        RateLimited = 31,

        OverQuota = 32,

        NegativeTrustAnchor = 33,

        NewDelegationOnly = 34,

        BlockedByUpstreamDnsServer = 35,

        TooManyCryptoValidations = 49152,

        ResolverLimitReached = 49153,
    }

    public class EDnsExtendedDnsErrorOptionData : EDnsOptionData
    {
        #region variables

        EDnsExtendedDnsErrorCode _infoCode;
        string _extraText;

        #endregion

        #region constructor

        public EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode infoCode, string extraText)
        {
            _infoCode = infoCode;
            _extraText = extraText;
        }

        public EDnsExtendedDnsErrorOptionData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadOptionData(Stream s)
        {
            _infoCode = (EDnsExtendedDnsErrorCode)DnsDatagram.ReadUInt16NetworkOrder(s);

            int textLength = _length - 2;
            if (textLength > 0)
                _extraText = Encoding.UTF8.GetString(s.ReadExactly(textLength));
        }

        protected override void WriteOptionData(Stream s)
        {
            DnsDatagram.WriteUInt16NetworkOrder((ushort)_infoCode, s);

            if (!string.IsNullOrEmpty(_extraText))
                s.Write(Encoding.UTF8.GetBytes(_extraText));
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is EDnsExtendedDnsErrorOptionData other)
            {
                if (_infoCode != other._infoCode)
                    return false;

                if (!string.Equals(_extraText, other._extraText))
                    return false;

                return true;
            }

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_infoCode, _extraText);
        }

        public override string ToString()
        {
            return "[" + _infoCode.ToString() + (_extraText is null ? "" : ": " + _extraText) + "]";
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("InfoCode", _infoCode.ToString());
            jsonWriter.WriteString("ExtraText", _extraText);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public EDnsExtendedDnsErrorCode InfoCode
        { get { return _infoCode; } }

        public string ExtraText
        { get { return _extraText; } }

        public override int UncompressedLength
        { get { return 2 + (_extraText is null ? 0 : _extraText.Length); } }

        #endregion
    }
}
