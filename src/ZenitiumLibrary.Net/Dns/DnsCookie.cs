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
using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading;
using ZenitiumLibrary.Net.Dns.EDnsOptions;

namespace ZenitiumLibrary.Net.Dns
{
    public enum DnsCookieState : byte
    {
        None = 0,
        ClientOnly = 1,
        Valid = 2,
        Invalid = 3,
        Malformed = 4
    }

    public static class DnsCookie
    {
        #region variables

        public const int SECRET_LENGTH = 16;
        public const int SERVER_COOKIE_LENGTH = 16;

        const byte SERVER_COOKIE_VERSION = 1;
        const int SERVER_COOKIE_MAX_AGE = 3600;
        const int SERVER_COOKIE_MAX_FUTURE = 300;
        const int MAX_KNOWN_SERVERS = 65536;

        static volatile bool _clientEnabled;
        static readonly byte[] _clientSecret = RandomNumberGenerator.GetBytes(SECRET_LENGTH);
        static readonly ConcurrentDictionary<IPAddress, byte[]> _serverCookies = new ConcurrentDictionary<IPAddress, byte[]>();

        static long _clientCookiesSent;
        static long _clientCookieMismatches;

        #endregion

        #region private

        private static ulong RotateLeft(ulong value, int bits)
        {
            return (value << bits) | (value >> (64 - bits));
        }

        private static void SipRound(ref ulong v0, ref ulong v1, ref ulong v2, ref ulong v3)
        {
            v0 += v1;
            v1 = RotateLeft(v1, 13);
            v1 ^= v0;
            v0 = RotateLeft(v0, 32);
            v2 += v3;
            v3 = RotateLeft(v3, 16);
            v3 ^= v2;
            v0 += v3;
            v3 = RotateLeft(v3, 21);
            v3 ^= v0;
            v2 += v1;
            v1 = RotateLeft(v1, 17);
            v1 ^= v2;
            v2 = RotateLeft(v2, 32);
        }

        private static int WriteAddress(IPAddress address, Span<byte> destination)
        {
            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            address.TryWriteBytes(destination, out int bytesWritten);
            return bytesWritten;
        }

        private static IPAddress Normalize(IPAddress address)
        {
            return address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        }

        #endregion

        #region public

        public static ulong SipHash24(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
        {
            if (key.Length != 16)
                throw new ArgumentException("SipHash key must be 16 bytes long.", nameof(key));

            ulong k0 = BinaryPrimitives.ReadUInt64LittleEndian(key);
            ulong k1 = BinaryPrimitives.ReadUInt64LittleEndian(key.Slice(8));

            ulong v0 = 0x736f6d6570736575UL ^ k0;
            ulong v1 = 0x646f72616e646f6dUL ^ k1;
            ulong v2 = 0x6c7967656e657261UL ^ k0;
            ulong v3 = 0x7465646279746573UL ^ k1;

            int end = data.Length - (data.Length % 8);

            for (int i = 0; i < end; i += 8)
            {
                ulong m = BinaryPrimitives.ReadUInt64LittleEndian(data.Slice(i));

                v3 ^= m;
                SipRound(ref v0, ref v1, ref v2, ref v3);
                SipRound(ref v0, ref v1, ref v2, ref v3);
                v0 ^= m;
            }

            ulong b = ((ulong)data.Length) << 56;

            for (int i = 0; i < data.Length - end; i++)
                b |= ((ulong)data[end + i]) << (8 * i);

            v3 ^= b;
            SipRound(ref v0, ref v1, ref v2, ref v3);
            SipRound(ref v0, ref v1, ref v2, ref v3);
            v0 ^= b;

            v2 ^= 0xff;
            SipRound(ref v0, ref v1, ref v2, ref v3);
            SipRound(ref v0, ref v1, ref v2, ref v3);
            SipRound(ref v0, ref v1, ref v2, ref v3);
            SipRound(ref v0, ref v1, ref v2, ref v3);

            return v0 ^ v1 ^ v2 ^ v3;
        }

        public static uint GetTimestamp()
        {
            return unchecked((uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds());
        }

        public static EDnsCookieOptionData GetCookieOption(DnsDatagram datagram, out int count)
        {
            count = 0;

            if (datagram.EDNS is null)
                return null;

            EDnsCookieOptionData cookie = null;

            foreach (EDnsOption option in datagram.EDNS.Options)
            {
                if (option.Code == EDnsOptionCode.COOKIE)
                {
                    count++;
                    cookie ??= option.Data as EDnsCookieOptionData;
                }
            }

            return cookie;
        }

        public static EDnsCookieOptionData GetCookieOption(DnsDatagram datagram)
        {
            return GetCookieOption(datagram, out _);
        }

        public static bool IsMalformed(DnsDatagram request)
        {
            EDnsCookieOptionData cookie = GetCookieOption(request, out int count);
            if (count == 0)
                return false;

            return (count > 1) || (cookie is null) || cookie.IsMalformed;
        }

        public static void WriteServerCookie(ReadOnlySpan<byte> clientCookie, IPAddress clientAddress, uint timestamp, ReadOnlySpan<byte> secret, Span<byte> destination)
        {
            Span<byte> input = stackalloc byte[EDnsCookieOptionData.CLIENT_COOKIE_LENGTH + 8 + 16];

            clientCookie.CopyTo(input);
            input[8] = SERVER_COOKIE_VERSION;
            input[9] = 0;
            input[10] = 0;
            input[11] = 0;
            BinaryPrimitives.WriteUInt32BigEndian(input.Slice(12), timestamp);

            int addressLength = WriteAddress(clientAddress, input.Slice(16));

            ulong hash = SipHash24(secret, input.Slice(0, 16 + addressLength));

            input.Slice(8, 8).CopyTo(destination);
            BinaryPrimitives.WriteUInt64LittleEndian(destination.Slice(8), hash);
        }

        public static EDnsOption CreateServerCookieOption(ReadOnlySpan<byte> clientCookie, IPAddress clientAddress, ReadOnlySpan<byte> secret)
        {
            byte[] serverCookie = new byte[SERVER_COOKIE_LENGTH];
            WriteServerCookie(clientCookie, clientAddress, GetTimestamp(), secret, serverCookie);

            return new EDnsOption(EDnsOptionCode.COOKIE, new EDnsCookieOptionData(clientCookie.ToArray(), serverCookie));
        }

        public static bool IsServerCookieValid(ReadOnlySpan<byte> clientCookie, ReadOnlySpan<byte> serverCookie, IPAddress clientAddress, ReadOnlySpan<byte> secret, uint now)
        {
            if (serverCookie.Length != SERVER_COOKIE_LENGTH)
                return false;

            if ((serverCookie[0] != SERVER_COOKIE_VERSION) || (serverCookie[1] != 0) || (serverCookie[2] != 0) || (serverCookie[3] != 0))
                return false;

            uint timestamp = BinaryPrimitives.ReadUInt32BigEndian(serverCookie.Slice(4));
            int age = unchecked((int)(now - timestamp));

            if ((age > SERVER_COOKIE_MAX_AGE) || (age < -SERVER_COOKIE_MAX_FUTURE))
                return false;

            Span<byte> expected = stackalloc byte[SERVER_COOKIE_LENGTH];
            WriteServerCookie(clientCookie, clientAddress, timestamp, secret, expected);

            return CryptographicOperations.FixedTimeEquals(expected, serverCookie);
        }

        public static DnsCookieState GetState(DnsDatagram request, IPAddress clientAddress, ReadOnlySpan<byte> secret)
        {
            EDnsCookieOptionData cookie = GetCookieOption(request, out int count);
            if (count == 0)
                return DnsCookieState.None;

            if ((count > 1) || (cookie is null) || cookie.IsMalformed)
                return DnsCookieState.Malformed;

            if (cookie.ServerCookie.Length == 0)
                return DnsCookieState.ClientOnly;

            return IsServerCookieValid(cookie.ClientCookie, cookie.ServerCookie, clientAddress, secret, GetTimestamp()) ? DnsCookieState.Valid : DnsCookieState.Invalid;
        }

        public static IReadOnlyList<EDnsOption> ReplaceCookieOption(IReadOnlyList<EDnsOption> options, EDnsOption cookieOption)
        {
            List<EDnsOption> newOptions = new List<EDnsOption>(options.Count + 1);

            foreach (EDnsOption option in options)
            {
                if (option.Code != EDnsOptionCode.COOKIE)
                    newOptions.Add(option);
            }

            newOptions.Add(cookieOption);

            return newOptions;
        }

        #endregion

        #region internal

        internal static EDnsCookieOptionData GetClientCookieOption(IPAddress server)
        {
            server = Normalize(server);

            Span<byte> address = stackalloc byte[16];
            int addressLength = WriteAddress(server, address);

            byte[] clientCookie = new byte[EDnsCookieOptionData.CLIENT_COOKIE_LENGTH];
            BinaryPrimitives.WriteUInt64LittleEndian(clientCookie, SipHash24(_clientSecret, address.Slice(0, addressLength)));

            _serverCookies.TryGetValue(server, out byte[] serverCookie);

            Interlocked.Increment(ref _clientCookiesSent);

            return new EDnsCookieOptionData(clientCookie, serverCookie);
        }

        internal static bool ProcessResponse(IPAddress server, EDnsCookieOptionData sentCookie, DnsDatagram response, bool tcp)
        {
            server = Normalize(server);

            EDnsCookieOptionData responseCookie = GetCookieOption(response);

            if (responseCookie is null)
            {
                if (!_serverCookies.ContainsKey(server))
                    return true;

                if (tcp)
                {
                    _serverCookies.TryRemove(server, out _);
                    return true;
                }

                Interlocked.Increment(ref _clientCookieMismatches);
                return false;
            }

            if (!responseCookie.HasClientCookie(sentCookie.ClientCookie))
            {
                Interlocked.Increment(ref _clientCookieMismatches);
                return false;
            }

            if (responseCookie.ServerCookie.Length > 0)
            {
                if (_serverCookies.Count >= MAX_KNOWN_SERVERS)
                    _serverCookies.Clear();

                _serverCookies[server] = responseCookie.ServerCookieBytes;
            }

            return true;
        }

        #endregion

        #region properties

        public static bool ClientEnabled
        {
            get { return _clientEnabled; }
            set
            {
                if (!value)
                    _serverCookies.Clear();

                _clientEnabled = value;
            }
        }

        public static int KnownServers
        { get { return _serverCookies.Count; } }

        public static long ClientCookiesSent
        { get { return Interlocked.Read(ref _clientCookiesSent); } }

        public static long ClientCookieMismatches
        { get { return Interlocked.Read(ref _clientCookieMismatches); } }

        #endregion
    }
}
