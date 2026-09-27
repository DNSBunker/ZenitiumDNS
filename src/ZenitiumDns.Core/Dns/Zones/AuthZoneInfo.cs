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
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using ZenitiumLibrary.IO;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.Zones
{
    public enum AuthZoneType : byte
    {
        Unknown = 0,
        Primary = 1,
        Forwarder = 4
    }

    public sealed class AuthZoneInfo : IComparable<AuthZoneInfo>
    {
        #region variables

        readonly ApexZone _apexZone;

        readonly string _name;
        readonly AuthZoneType _type;
        readonly DateTime _lastModified;
        readonly bool _disabled;

        readonly AuthZoneQueryAccess _queryAccess;
        readonly IReadOnlyCollection<NetworkAccessControl> _queryAccessNetworkACL;

        #endregion

        #region constructor

        public AuthZoneInfo(BinaryReader bR, DateTime lastModified)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                case 8:
                case 9:
                case 10:
                case 11:
                    {
                        _name = bR.BaseStream.ReadShortString();
                        _type = (AuthZoneType)bR.ReadByte();
                        _disabled = bR.ReadBoolean();

                        EnsureSupportedType(_name, _type);

                        _queryAccess = AuthZoneQueryAccess.Allow;

                        if (version >= 2)
                        {
                            bR.ReadByte();
                            SkipLegacyNetworks(bR, version);

                            bR.ReadByte();
                            int count = bR.ReadByte();
                            for (int i = 0; i < count; i++)
                                IPAddressExtensions.ReadFrom(bR);

                            if (version >= 6)
                            {
                                bR.ReadByte();
                                SkipLegacyNetworks(bR, version);
                            }
                        }

                        if (version >= 8)
                            _lastModified = bR.BaseStream.ReadDateTime();
                        else
                            _lastModified = lastModified;

                        if (version >= 10)
                            SkipUpdateSecurityPolicies(bR, bR.ReadByte());
                    }
                    break;

                case 12:
                case 13:
                case 14:
                    {
                        _name = bR.BaseStream.ReadShortString();
                        _type = (AuthZoneType)bR.ReadByte();
                        _lastModified = bR.BaseStream.ReadDateTime();
                        _disabled = bR.ReadBoolean();

                        EnsureSupportedType(_name, _type);

                        bR.BaseStream.ReadShortString();
                        bR.ReadBoolean();
                        bR.ReadBoolean();
                        bR.ReadBoolean();

                        _queryAccess = (AuthZoneQueryAccess)bR.ReadByte();
                        _queryAccessNetworkACL = ReadNetworkACLFrom(bR);

                        bR.ReadByte();
                        ReadNetworkACLFrom(bR);
                        SkipShortStrings(bR);
                        SkipZoneHistory(bR);

                        bR.ReadByte();
                        ReadIPAddressesFrom(bR);

                        bR.ReadByte();
                        ReadNetworkACLFrom(bR);
                        SkipUpdateSecurityPolicies(bR, bR.ReadInt32());
                    }
                    break;

                case 15:
                    {
                        _name = bR.BaseStream.ReadShortString();
                        _type = (AuthZoneType)bR.ReadByte();
                        _lastModified = bR.BaseStream.ReadDateTime();
                        _disabled = bR.ReadBoolean();

                        EnsureSupportedType(_name, _type);

                        _queryAccess = (AuthZoneQueryAccess)bR.ReadByte();
                        _queryAccessNetworkACL = ReadNetworkACLFrom(bR);
                    }
                    break;

                default:
                    throw new InvalidDataException("AuthZoneInfo format version not supported.");
            }
        }

        internal AuthZoneInfo(ApexZone apexZone)
        {
            _apexZone = apexZone;
            _name = _apexZone.Name;
            _lastModified = _apexZone.LastModified;
            _disabled = _apexZone.Disabled;

            if (_apexZone is PrimaryZone)
                _type = AuthZoneType.Primary;
            else if (_apexZone is ForwarderZone)
                _type = AuthZoneType.Forwarder;
            else
                _type = AuthZoneType.Unknown;

            _queryAccess = _apexZone.QueryAccess;
            _queryAccessNetworkACL = _apexZone.QueryAccessNetworkACL;
        }

        #endregion

        #region private

        private static void EnsureSupportedType(string name, AuthZoneType type)
        {
            if (type != AuthZoneType.Forwarder)
                throw new NotSupportedException("Zone '" + (name.Length == 0 ? "<root>" : name) + "' was not loaded: authoritative zones of type " + ((byte)type).ToString() + " are not supported by ZenitiumDNS. Only Conditional Forwarder zones are supported.");
        }

        private static void SkipLegacyNetworks(BinaryReader bR, byte version)
        {
            int count = bR.ReadByte();

            for (int i = 0; i < count; i++)
            {
                if (version >= 9)
                    NetworkAddress.ReadFrom(bR);
                else
                    IPAddressExtensions.ReadFrom(bR);
            }
        }

        private static void SkipShortStrings(BinaryReader bR)
        {
            int count = bR.ReadByte();

            for (int i = 0; i < count; i++)
                bR.BaseStream.ReadShortString();
        }

        private static void SkipZoneHistory(BinaryReader bR)
        {
            int count = bR.ReadInt32();

            for (int i = 0; i < count; i++)
            {
                _ = new DnsResourceRecord(bR.BaseStream);

                if (bR.ReadBoolean())
                    _ = new HistoryRecordInfo(bR);
            }
        }

        private static void SkipUpdateSecurityPolicies(BinaryReader bR, int count)
        {
            for (int i = 0; i < count; i++)
            {
                bR.BaseStream.ReadShortString();

                int policyCount = bR.ReadByte();

                for (int j = 0; j < policyCount; j++)
                {
                    bR.BaseStream.ReadShortString();

                    int typeCount = bR.ReadByte();

                    for (int k = 0; k < typeCount; k++)
                        bR.ReadUInt16();
                }
            }
        }

        #endregion

        #region static

        public static string GetZoneTypeName(AuthZoneType type)
        {
            return type.ToString();
        }

        internal static NetworkAccessControl[] ReadNetworkACLFrom(BinaryReader bR)
        {
            int count = bR.ReadByte();
            if (count < 1)
                return null;

            NetworkAccessControl[] acl = new NetworkAccessControl[count];

            for (int i = 0; i < count; i++)
                acl[i] = NetworkAccessControl.ReadFrom(bR);

            return acl;
        }

        internal static void WriteNetworkACLTo(IReadOnlyCollection<NetworkAccessControl> acl, BinaryWriter bW)
        {
            if (acl is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(acl.Count));

                foreach (NetworkAccessControl nac in acl)
                    nac.WriteTo(bW);
            }
        }

        internal static NetworkAddress[] ReadNetworkAddressesFrom(BinaryReader bR)
        {
            int count = bR.ReadByte();
            if (count < 1)
                return null;

            NetworkAddress[] networks = new NetworkAddress[count];

            for (int i = 0; i < count; i++)
                networks[i] = NetworkAddress.ReadFrom(bR);

            return networks;
        }

        internal static void WriteNetworkAddressesTo(IReadOnlyCollection<NetworkAddress> networkAddresses, BinaryWriter bW)
        {
            if (networkAddresses is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(networkAddresses.Count));

                foreach (NetworkAddress network in networkAddresses)
                    network.WriteTo(bW);
            }
        }

        internal static IPAddress[] ReadIPAddressesFrom(BinaryReader bR)
        {
            int count = bR.ReadByte();
            if (count < 1)
                return null;

            IPAddress[] ipAddresses = new IPAddress[count];

            for (int i = 0; i < count; i++)
                ipAddresses[i] = IPAddressExtensions.ReadFrom(bR);

            return ipAddresses;
        }

        internal static List<NetworkAccessControl> ConvertDenyAllowToACL(NetworkAddress[] deniedNetworks, NetworkAddress[] allowedNetworks)
        {
            List<NetworkAccessControl> acl = new List<NetworkAccessControl>();

            if (deniedNetworks is not null)
            {
                foreach (NetworkAddress network in deniedNetworks)
                    acl.Add(new NetworkAccessControl(network, true));
            }

            if (allowedNetworks is not null)
            {
                foreach (NetworkAddress network in allowedNetworks)
                    acl.Add(new NetworkAccessControl(network));
            }

            if (acl.Count > 0)
                return acl;

            return null;
        }

        #endregion

        #region public

        public void WriteTo(BinaryWriter bW)
        {
            if (_apexZone is null)
                throw new InvalidOperationException();

            bW.Write((byte)15);

            bW.BaseStream.WriteShortString(_name);
            bW.Write((byte)_type);
            bW.BaseStream.WriteDateTime(LastModified);
            bW.Write(Disabled);

            bW.Write((byte)QueryAccess);
            WriteNetworkACLTo(QueryAccessNetworkACL, bW);
        }

        public int CompareTo(AuthZoneInfo other)
        {
            return _name.CompareTo(other._name);
        }

        public override bool Equals(object obj)
        {
            if (ReferenceEquals(this, obj))
                return true;

            if (obj is not AuthZoneInfo other)
                return false;

            return _name.Equals(other._name, StringComparison.OrdinalIgnoreCase);
        }

        public override int GetHashCode()
        {
            return HashCode.Combine(_name);
        }

        public override string ToString()
        {
            return _name.Length == 0 ? "<root>" : _name;
        }

        #endregion

        #region properties

        internal ApexZone ApexZone
        { get { return _apexZone; } }

        public string Name
        { get { return _name; } }

        public string DisplayName
        { get { return _name.Length == 0 ? "<root>" : _name; } }

        public AuthZoneType Type
        { get { return _type; } }

        public string TypeName
        { get { return GetZoneTypeName(_type); } }

        public DateTime LastModified
        {
            get
            {
                if (_apexZone is null)
                    return _lastModified;

                return _apexZone.LastModified;
            }
        }

        public bool Disabled
        {
            get
            {
                if (_apexZone is null)
                    return _disabled;

                return _apexZone.Disabled;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.Disabled = value;
            }
        }

        public AuthZoneQueryAccess QueryAccess
        {
            get
            {
                if (_apexZone is null)
                    return _queryAccess;

                return _apexZone.QueryAccess;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.QueryAccess = value;
            }
        }

        public IReadOnlyCollection<NetworkAccessControl> QueryAccessNetworkACL
        {
            get
            {
                if (_apexZone is null)
                    return _queryAccessNetworkACL;

                return _apexZone.QueryAccessNetworkACL;
            }
            set
            {
                if (_apexZone is null)
                    throw new InvalidOperationException();

                _apexZone.QueryAccessNetworkACL = value;
            }
        }

        #endregion
    }
}
