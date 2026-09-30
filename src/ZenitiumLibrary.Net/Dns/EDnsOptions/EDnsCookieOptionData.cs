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
    public class EDnsCookieOptionData : EDnsOptionData
    {
        #region variables

        public const int CLIENT_COOKIE_LENGTH = 8;
        public const int MIN_SERVER_COOKIE_LENGTH = 8;
        public const int MAX_SERVER_COOKIE_LENGTH = 32;

        byte[] _clientCookie;
        byte[] _serverCookie;
        bool _isMalformed;

        #endregion

        #region constructor

        public EDnsCookieOptionData(byte[] clientCookie, byte[] serverCookie = null)
        {
            ArgumentNullException.ThrowIfNull(clientCookie);

            if (clientCookie.Length != CLIENT_COOKIE_LENGTH)
                throw new ArgumentException("Client cookie must be " + CLIENT_COOKIE_LENGTH + " bytes long.", nameof(clientCookie));

            if ((serverCookie is not null) && (serverCookie.Length > 0) && ((serverCookie.Length < MIN_SERVER_COOKIE_LENGTH) || (serverCookie.Length > MAX_SERVER_COOKIE_LENGTH)))
                throw new ArgumentException("Server cookie must be " + MIN_SERVER_COOKIE_LENGTH + " to " + MAX_SERVER_COOKIE_LENGTH + " bytes long.", nameof(serverCookie));

            _clientCookie = clientCookie;
            _serverCookie = serverCookie ?? [];
        }

        public EDnsCookieOptionData(Stream s)
            : base(s)
        { }

        #endregion

        #region protected

        protected override void ReadOptionData(Stream s)
        {
            byte[] data = new byte[_length];
            s.ReadExactly(data);

            if (_length == CLIENT_COOKIE_LENGTH)
            {
                _clientCookie = data;
                _serverCookie = [];
            }
            else if ((_length >= CLIENT_COOKIE_LENGTH + MIN_SERVER_COOKIE_LENGTH) && (_length <= CLIENT_COOKIE_LENGTH + MAX_SERVER_COOKIE_LENGTH))
            {
                _clientCookie = data.AsSpan(0, CLIENT_COOKIE_LENGTH).ToArray();
                _serverCookie = data.AsSpan(CLIENT_COOKIE_LENGTH).ToArray();
            }
            else
            {
                _isMalformed = true;
                _clientCookie = data.AsSpan(0, Math.Min(data.Length, CLIENT_COOKIE_LENGTH)).ToArray();
                _serverCookie = data.Length > CLIENT_COOKIE_LENGTH ? data.AsSpan(CLIENT_COOKIE_LENGTH).ToArray() : [];
            }
        }

        protected override void WriteOptionData(Stream s)
        {
            s.Write(_clientCookie);
            s.Write(_serverCookie);
        }

        #endregion

        #region public

        public bool HasClientCookie(ReadOnlySpan<byte> clientCookie)
        {
            return !_isMalformed && _clientCookie.AsSpan().SequenceEqual(clientCookie);
        }

        public override bool Equals(object obj)
        {
            if (obj is null)
                return false;

            if (ReferenceEquals(this, obj))
                return true;

            if (obj is EDnsCookieOptionData other)
                return _clientCookie.AsSpan().SequenceEqual(other._clientCookie) && _serverCookie.AsSpan().SequenceEqual(other._serverCookie);

            return false;
        }

        public override int GetHashCode()
        {
            HashCode hash = new HashCode();
            hash.AddBytes(_clientCookie);
            hash.AddBytes(_serverCookie);

            return hash.ToHashCode();
        }

        public override string ToString()
        {
            return Convert.ToHexStringLower(_clientCookie) + (_serverCookie.Length > 0 ? " " + Convert.ToHexStringLower(_serverCookie) : "");
        }

        public override void SerializeTo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteStartObject();

            jsonWriter.WriteString("ClientCookie", Convert.ToHexStringLower(_clientCookie));

            if (_serverCookie.Length > 0)
                jsonWriter.WriteString("ServerCookie", Convert.ToHexStringLower(_serverCookie));

            if (_isMalformed)
                jsonWriter.WriteBoolean("Malformed", true);

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region properties

        public ReadOnlySpan<byte> ClientCookie
        { get { return _clientCookie; } }

        public ReadOnlySpan<byte> ServerCookie
        { get { return _serverCookie; } }

        public byte[] ServerCookieBytes
        { get { return _serverCookie; } }

        public bool IsMalformed
        { get { return _isMalformed; } }

        public override int UncompressedLength
        { get { return _clientCookie.Length + _serverCookie.Length; } }

        #endregion
    }
}
