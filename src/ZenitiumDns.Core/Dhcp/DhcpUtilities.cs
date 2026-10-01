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
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace ZenitiumDns.Core.Dhcp
{
    public static class DhcpUtilities
    {
        public const uint INFINITE_LEASE = uint.MaxValue;
        public const uint MIN_LEASE_TIME = 120;

        public static uint ToUInt32(IPAddress address)
        {
            Span<byte> bytes = stackalloc byte[4];
            if (!address.TryWriteBytes(bytes, out int written) || (written != 4))
                throw new ArgumentException("Not an IPv4 address: " + address);

            return BinaryPrimitives.ReadUInt32BigEndian(bytes);
        }

        public static IPAddress ToAddress(uint value)
        {
            Span<byte> bytes = stackalloc byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
            return new IPAddress(bytes);
        }

        public static uint GetMask(int prefixLength)
        {
            if (prefixLength <= 0)
                return 0;

            if (prefixLength >= 32)
                return uint.MaxValue;

            return uint.MaxValue << (32 - prefixLength);
        }

        public static bool TryGetPrefixLength(IPAddress mask, out int prefixLength)
        {
            prefixLength = 0;

            if ((mask is null) || (mask.AddressFamily != AddressFamily.InterNetwork))
                return false;

            uint value = ToUInt32(mask);
            uint inverted = ~value;

            if ((inverted & (inverted + 1)) != 0)
                return false;

            prefixLength = 32 - BitOperationsPopCount(inverted);
            return true;
        }

        private static int BitOperationsPopCount(uint value)
        {
            return System.Numerics.BitOperations.PopCount(value);
        }

        public static bool IsInNetwork(IPAddress address, IPAddress network, int prefixLength)
        {
            if ((address is null) || (address.AddressFamily != AddressFamily.InterNetwork))
                return false;

            uint mask = GetMask(prefixLength);
            return (ToUInt32(address) & mask) == (ToUInt32(network) & mask);
        }

        public static string FormatHardwareAddress(byte[] address)
        {
            if ((address is null) || (address.Length == 0))
                return "";

            StringBuilder sb = new StringBuilder(address.Length * 3);

            for (int i = 0; i < address.Length; i++)
            {
                if (i > 0)
                    sb.Append(':');

                sb.Append(address[i].ToString("x2", CultureInfo.InvariantCulture));
            }

            return sb.ToString();
        }

        public static string FormatHex(byte[] value)
        {
            return FormatHardwareAddress(value);
        }

        public static bool TryParseHex(string text, out byte[] bytes)
        {
            bytes = null;
            text = text.Trim();

            if (text.Length == 0)
                return false;

            if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            {
                string hex = text.Substring(2);
                if (((hex.Length % 2) != 0) || (hex.Length == 0))
                    return false;

                try
                {
                    bytes = Convert.FromHexString(hex);
                    return true;
                }
                catch (FormatException)
                {
                    return false;
                }
            }

            string[] parts = text.Split(':', '-');
            if (parts.Length < 2)
                return false;

            byte[] result = new byte[parts.Length];

            for (int i = 0; i < parts.Length; i++)
            {
                string part = parts[i];
                if ((part.Length < 1) || (part.Length > 2) || !byte.TryParse(part, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out result[i]))
                    return false;
            }

            bytes = result;
            return true;
        }

        public static bool IsPrintable(byte[] value)
        {
            if (value is null)
                return false;

            for (int i = 0; i < value.Length; i++)
            {
                byte b = value[i];

                if ((b == 0) && (i == value.Length - 1))
                    continue;

                if ((b < 0x20) || (b == 0x7F))
                    return false;
            }

            return true;
        }

        public static bool IsValidHostLabel(string label)
        {
            if (string.IsNullOrEmpty(label) || (label.Length > 63))
                return false;

            if ((label[0] == '-') || (label[^1] == '-'))
                return false;

            foreach (char c in label)
            {
                if (!(((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) || ((c >= '0') && (c <= '9')) || (c == '-')))
                    return false;
            }

            return true;
        }

        public static bool IsValidDomainName(string domain)
        {
            if (string.IsNullOrEmpty(domain) || (domain.Length > 253))
                return false;

            foreach (string label in domain.Split('.'))
            {
                if (!IsValidHostLabel(label) && !((label.Length > 0) && (label.Length <= 63) && IsValidUnderscoreLabel(label)))
                    return false;
            }

            return true;
        }

        private static bool IsValidUnderscoreLabel(string label)
        {
            if (label[0] != '_')
                return false;

            return IsValidHostLabel(label.Substring(1));
        }

        public static string SanitizeHostName(string name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return null;

            name = name.Trim().TrimEnd('.').ToLowerInvariant();

            int dot = name.IndexOf('.');
            if (dot >= 0)
                name = name.Substring(0, dot);

            StringBuilder sb = new StringBuilder(name.Length);

            foreach (char c in name)
            {
                if (((c >= 'a') && (c <= 'z')) || ((c >= '0') && (c <= '9')) || (c == '-'))
                    sb.Append(c);
                else if ((c == '_') || (c == ' '))
                    sb.Append('-');
            }

            string result = sb.ToString().Trim('-');

            if (result.Length > 63)
                result = result.Substring(0, 63).TrimEnd('-');

            if (!IsValidHostLabel(result))
                return null;

            return result;
        }

        public static bool TryParseLeaseTime(string text, out uint seconds)
        {
            seconds = 0;
            text = text.Trim().ToLowerInvariant();

            if (text.Length == 0)
                return false;

            if ((text == "infinite") || (text == "unlimited"))
            {
                seconds = INFINITE_LEASE;
                return true;
            }

            ulong multiplier = 1;
            char unit = text[^1];

            switch (unit)
            {
                case 's':
                    multiplier = 1;
                    text = text.Substring(0, text.Length - 1);
                    break;

                case 'm':
                    multiplier = 60;
                    text = text.Substring(0, text.Length - 1);
                    break;

                case 'h':
                    multiplier = 3600;
                    text = text.Substring(0, text.Length - 1);
                    break;

                case 'd':
                    multiplier = 86400;
                    text = text.Substring(0, text.Length - 1);
                    break;

                case 'w':
                    multiplier = 604800;
                    text = text.Substring(0, text.Length - 1);
                    break;
            }

            if ((text.Length == 0) || !ulong.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out ulong value))
                return false;

            ulong total = value * multiplier;
            if ((value != 0) && ((total / value) != multiplier))
                return false;

            if (total >= INFINITE_LEASE)
                return false;

            seconds = (uint)Math.Max(MIN_LEASE_TIME, total);
            return true;
        }

        public static bool LooksLikeLeaseTime(string text)
        {
            text = text.Trim().ToLowerInvariant();

            if ((text == "infinite") || (text == "unlimited"))
                return true;

            if (text.Length == 0)
                return false;

            int end = text.Length;
            if ("smhdw".Contains(text[^1]))
                end--;

            if (end == 0)
                return false;

            for (int i = 0; i < end; i++)
            {
                if ((text[i] < '0') || (text[i] > '9'))
                    return false;
            }

            return true;
        }

        public static string FormatLeaseTime(uint seconds)
        {
            if (seconds == INFINITE_LEASE)
                return "infinite";

            if ((seconds % 604800) == 0)
                return (seconds / 604800).ToString(CultureInfo.InvariantCulture) + "w";

            if ((seconds % 86400) == 0)
                return (seconds / 86400).ToString(CultureInfo.InvariantCulture) + "d";

            if ((seconds % 3600) == 0)
                return (seconds / 3600).ToString(CultureInfo.InvariantCulture) + "h";

            if ((seconds % 60) == 0)
                return (seconds / 60).ToString(CultureInfo.InvariantCulture) + "m";

            return seconds.ToString(CultureInfo.InvariantCulture) + "s";
        }

        public static string GetClientKey(byte hardwareType, byte[] hardwareAddress, byte[] clientId)
        {
            if ((clientId is not null) && (clientId.Length > 0))
                return "id:" + FormatHex(clientId);

            return "hw:" + hardwareType.ToString(CultureInfo.InvariantCulture) + "-" + FormatHardwareAddress(hardwareAddress);
        }

        public static uint GetStableHash(string value)
        {
            uint hash = 2166136261;

            foreach (char c in value)
            {
                hash ^= c;
                hash *= 16777619;
            }

            return hash;
        }
    }
}
