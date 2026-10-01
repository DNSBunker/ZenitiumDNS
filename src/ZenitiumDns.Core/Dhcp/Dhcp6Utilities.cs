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
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace ZenitiumDns.Core.Dhcp
{
    public sealed class Dhcp6InterfaceAddress
    {
        const byte IFA_F_TEMPORARY = 0x01;
        const byte IFA_F_DADFAILED = 0x08;
        const byte IFA_F_DEPRECATED = 0x20;
        const byte IFA_F_TENTATIVE = 0x40;
        const byte IFA_F_PERMANENT = 0x80;

        public Dhcp6InterfaceAddress(IPAddress address, int prefixLength, byte flags)
        {
            Address = address;
            PrefixLength = prefixLength;
            Flags = flags;
        }

        public IPAddress Address { get; }

        public int PrefixLength { get; }

        public byte Flags { get; }

        public bool IsLinkLocal
        { get { return Address.IsIPv6LinkLocal; } }

        public bool IsUniqueLocal
        { get { return (Address.GetAddressBytes()[0] & 0xFE) == 0xFC; } }

        public bool IsGlobal
        { get { return !IsLinkLocal && !IsUniqueLocal && !Address.IsIPv6Multicast && !Address.IsIPv6SiteLocal && !IPAddress.IsLoopback(Address); } }

        public bool IsTemporary
        { get { return (Flags & IFA_F_TEMPORARY) != 0; } }

        public bool IsDeprecated
        { get { return (Flags & IFA_F_DEPRECATED) != 0; } }

        public bool IsUsable
        { get { return (Flags & (IFA_F_TENTATIVE | IFA_F_DADFAILED)) == 0; } }

        public bool IsPermanent
        { get { return (Flags & IFA_F_PERMANENT) != 0; } }

        public UInt128 Prefix
        { get { return Dhcp6Utilities.GetPrefix(Dhcp6Utilities.ToUInt128(Address), PrefixLength); } }

        public bool Contains(IPAddress address)
        {
            return Dhcp6Utilities.IsInPrefix(Dhcp6Utilities.ToUInt128(address), Prefix, PrefixLength);
        }
    }

    public sealed class Dhcp6InterfaceInfo
    {
        public string Name { get; init; }

        public int Index { get; init; }

        public byte[] HardwareAddress { get; init; } = [];

        public int Mtu { get; init; }

        public bool Forwarding { get; init; }

        public IReadOnlyList<Dhcp6InterfaceAddress> Addresses { get; init; } = [];

        public IPAddress LinkLocal
        {
            get
            {
                foreach (Dhcp6InterfaceAddress address in Addresses)
                {
                    if (address.IsLinkLocal && address.IsUsable)
                        return address.Address;
                }

                return null;
            }
        }

        public List<Dhcp6InterfaceAddress> GetPrefixAddresses(int prefixLength)
        {
            List<Dhcp6InterfaceAddress> result = new List<Dhcp6InterfaceAddress>();
            HashSet<UInt128> seen = new HashSet<UInt128>();

            foreach (Dhcp6InterfaceAddress address in Addresses)
            {
                if (address.IsLinkLocal || address.IsTemporary || address.IsDeprecated || !address.IsUsable || (address.PrefixLength > prefixLength))
                    continue;

                if (address.Address.IsIPv6Multicast || IPAddress.IsLoopback(address.Address))
                    continue;

                UInt128 prefix = Dhcp6Utilities.GetPrefix(Dhcp6Utilities.ToUInt128(address.Address), prefixLength);

                if (seen.Add(prefix))
                    result.Add(address);
            }

            return result;
        }

        public IPAddress GetBestServerAddress(UInt128? prefixHint = null, int prefixLength = 64)
        {
            Dhcp6InterfaceAddress best = null;
            int bestScore = int.MinValue;

            foreach (Dhcp6InterfaceAddress address in Addresses)
            {
                if (address.IsLinkLocal || !address.IsUsable || address.Address.IsIPv6Multicast)
                    continue;

                int score = 0;

                if (address.IsUniqueLocal)
                    score += 40;
                else if (address.IsGlobal)
                    score += 30;

                if (!address.IsTemporary)
                    score += 20;

                if (address.IsPermanent)
                    score += 15;

                if (!address.IsDeprecated)
                    score += 10;

                if (prefixHint.HasValue && Dhcp6Utilities.IsInPrefix(Dhcp6Utilities.ToUInt128(address.Address), prefixHint.Value, prefixLength))
                    score += 5;

                if (score > bestScore)
                {
                    best = address;
                    bestScore = score;
                }
            }

            return best?.Address;
        }

        public bool IsOnLink(IPAddress address)
        {
            foreach (Dhcp6InterfaceAddress local in Addresses)
            {
                if (!local.IsLinkLocal && local.Contains(address))
                    return true;
            }

            return false;
        }
    }

    public static class Dhcp6Utilities
    {
        #region public

        public static UInt128 ToUInt128(IPAddress address)
        {
            Span<byte> bytes = stackalloc byte[16];

            if (!address.TryWriteBytes(bytes, out int written) || (written != 16))
                throw new ArgumentException("not an IPv6 address", nameof(address));

            return BinaryPrimitives.ReadUInt128BigEndian(bytes);
        }

        public static IPAddress ToAddress(UInt128 value)
        {
            Span<byte> bytes = stackalloc byte[16];
            BinaryPrimitives.WriteUInt128BigEndian(bytes, value);
            return new IPAddress(bytes);
        }

        public static UInt128 GetMask(int prefixLength)
        {
            if (prefixLength <= 0)
                return UInt128.Zero;

            if (prefixLength >= 128)
                return UInt128.MaxValue;

            return ~(UInt128.MaxValue >> prefixLength);
        }

        public static UInt128 GetPrefix(UInt128 value, int prefixLength)
        {
            return value & GetMask(prefixLength);
        }

        public static bool IsInPrefix(UInt128 value, UInt128 prefix, int prefixLength)
        {
            return GetPrefix(value, prefixLength) == GetPrefix(prefix, prefixLength);
        }

        public static string FormatPrefix(UInt128 prefix, int prefixLength)
        {
            return ToAddress(prefix) + "/" + prefixLength.ToString(CultureInfo.InvariantCulture);
        }

        public static List<Dhcp6InterfaceInfo> GetInterfaces()
        {
            if (OperatingSystem.IsLinux() && File.Exists("/proc/net/if_inet6"))
            {
                try
                {
                    return GetLinuxInterfaces();
                }
                catch
                { }
            }

            return GetGenericInterfaces();
        }

        public static Dhcp6InterfaceInfo GetInterface(string name)
        {
            foreach (Dhcp6InterfaceInfo info in GetInterfaces())
            {
                if (info.Name == name)
                    return info;
            }

            return null;
        }

        #endregion

        #region private

        private static Dictionary<string, NetworkInterface> GetNetworkInterfaces()
        {
            Dictionary<string, NetworkInterface> result = new Dictionary<string, NetworkInterface>(StringComparer.Ordinal);

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
                result[nic.Name] = nic;

            return result;
        }

        private static bool IsUp(NetworkInterface nic)
        {
            return (nic.OperationalStatus == OperationalStatus.Up) || (nic.OperationalStatus == OperationalStatus.Unknown);
        }

        private static List<Dhcp6InterfaceInfo> GetLinuxInterfaces()
        {
            Dictionary<string, NetworkInterface> nics = GetNetworkInterfaces();
            Dictionary<string, (int Index, List<Dhcp6InterfaceAddress> Addresses)> byName = new Dictionary<string, (int, List<Dhcp6InterfaceAddress>)>(StringComparer.Ordinal);

            foreach (string line in File.ReadAllLines("/proc/net/if_inet6"))
            {
                string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                if ((parts.Length < 6) || (parts[0].Length != 32))
                    continue;

                byte[] bytes = Convert.FromHexString(parts[0]);
                int index = int.Parse(parts[1], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                int prefixLength = int.Parse(parts[2], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                byte flags = byte.Parse(parts[4], NumberStyles.HexNumber, CultureInfo.InvariantCulture);
                string name = parts[5];

                if (name == "lo")
                    continue;

                IPAddress address = new IPAddress(bytes);

                if (IPAddress.IsLoopback(address))
                    continue;

                if (!byName.TryGetValue(name, out (int Index, List<Dhcp6InterfaceAddress> Addresses) entry))
                {
                    entry = (index, new List<Dhcp6InterfaceAddress>());
                    byName.Add(name, entry);
                }

                entry.Addresses.Add(new Dhcp6InterfaceAddress(address, prefixLength, flags));
            }

            List<Dhcp6InterfaceInfo> result = new List<Dhcp6InterfaceInfo>();

            foreach (KeyValuePair<string, (int Index, List<Dhcp6InterfaceAddress> Addresses)> entry in byName)
            {
                byte[] hardwareAddress = [];

                if (nics.TryGetValue(entry.Key, out NetworkInterface nic))
                {
                    if (!IsUp(nic))
                        continue;

                    try
                    {
                        hardwareAddress = nic.GetPhysicalAddress().GetAddressBytes();
                    }
                    catch
                    { }
                }

                result.Add(new Dhcp6InterfaceInfo()
                {
                    Name = entry.Key,
                    Index = entry.Value.Index,
                    HardwareAddress = hardwareAddress,
                    Mtu = ReadIntFile("/sys/class/net/" + entry.Key + "/mtu", 1500),
                    Forwarding = ReadIntFile("/proc/sys/net/ipv6/conf/" + entry.Key + "/forwarding", 0) == 1,
                    Addresses = entry.Value.Addresses
                });
            }

            result.Sort(delegate (Dhcp6InterfaceInfo x, Dhcp6InterfaceInfo y) { return x.Index.CompareTo(y.Index); });
            return result;
        }

        private static int ReadIntFile(string path, int defaultValue)
        {
            try
            {
                if (File.Exists(path) && int.TryParse(File.ReadAllText(path).Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out int value))
                    return value;
            }
            catch
            { }

            return defaultValue;
        }

        private static List<Dhcp6InterfaceInfo> GetGenericInterfaces()
        {
            List<Dhcp6InterfaceInfo> result = new List<Dhcp6InterfaceInfo>();

            foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                try
                {
                    if ((nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) || !IsUp(nic) || !nic.Supports(NetworkInterfaceComponent.IPv6))
                        continue;

                    IPInterfaceProperties properties = nic.GetIPProperties();
                    IPv6InterfaceProperties ipv6 = properties.GetIPv6Properties();
                    List<Dhcp6InterfaceAddress> addresses = new List<Dhcp6InterfaceAddress>();

                    foreach (UnicastIPAddressInformation unicast in properties.UnicastAddresses)
                    {
                        if (unicast.Address.AddressFamily != AddressFamily.InterNetworkV6)
                            continue;

                        IPAddress address = new IPAddress(unicast.Address.GetAddressBytes());
                        addresses.Add(new Dhcp6InterfaceAddress(address, unicast.PrefixLength, 0));
                    }

                    if (addresses.Count == 0)
                        continue;

                    result.Add(new Dhcp6InterfaceInfo()
                    {
                        Name = nic.Name,
                        Index = ipv6?.Index ?? 0,
                        HardwareAddress = nic.GetPhysicalAddress().GetAddressBytes(),
                        Mtu = ipv6?.Mtu ?? 1500,
                        Forwarding = false,
                        Addresses = addresses
                    });
                }
                catch
                { }
            }

            return result;
        }

        #endregion
    }
}
