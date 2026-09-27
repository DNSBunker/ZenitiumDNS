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
using System.IO;
using System.Text.Json;

namespace ZenitiumLibrary.Net.Dns.EDnsOptions
{
    public class EDnsPaddingOptionData : EDnsOptionData
    {
        #region variables

        static readonly byte[] ZEROS = new byte[512];

        int _paddingLength;

        #endregion

        #region constructor

        public EDnsPaddingOptionData(int paddingLength)
        {
            ArgumentOutOfRangeException.ThrowIfNegative(paddingLength);
            ArgumentOutOfRangeException.ThrowIfGreaterThan(paddingLength, ushort.MaxValue);

            _paddingLength = paddingLength;
        }

        public EDnsPaddingOptionData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadOptionData(Stream s)
        {
            _paddingLength = _length;

            Span<byte> buffer = stackalloc byte[256];
            int remaining = _length;

            while (remaining > 0)
            {
                int count = Math.Min(remaining, buffer.Length);
                s.ReadExactly(buffer.Slice(0, count));
                remaining -= count;
            }
        }

        protected override void WriteOptionData(Stream s)
        {
            int remaining = _paddingLength;

            while (remaining > 0)
            {
                int count = Math.Min(remaining, ZEROS.Length);
                s.Write(ZEROS, 0, count);
                remaining -= count;
            }
        }

        #endregion

        #region public

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is EDnsPaddingOptionData other)
                return _paddingLength == other._paddingLength;

            return false;
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_paddingLength);
        }

        public override string ToString()
        {
            return "[" + _paddingLength + " bytes]";
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteNumber("PaddingLength", _paddingLength);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public int PaddingLength
        { get { return _paddingLength; } }

        public override int UncompressedLength
        { get { return _paddingLength; } }

        #endregion
    }
}
