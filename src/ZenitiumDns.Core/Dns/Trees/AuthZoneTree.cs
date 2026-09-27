/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)
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

using ZenitiumDns.Core.Dns.Zones;
using System;
using System.Collections.Generic;
using System.Threading;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core.Dns.Trees
{
    class AuthZoneTree : ZoneTree<AuthZoneNode, SubDomainZone, ApexZone>
    {
        #region private

        private static Node GetNextSubDomainZoneNode(byte[] key, Node currentNode, int baseDepth)
        {
            int k;

            NodeValue currentValue = currentNode.Value;
            if (currentValue is null)
            {
                if (currentNode.Children is null)
                {
                    k = currentNode.K + 1;
                    currentNode = currentNode.Parent;
                }
                else
                {
                    if (key.Length == currentNode.Depth)
                    {
                        k = 0;
                    }
                    else
                    {
                        k = key[currentNode.Depth];
                    }
                }
            }
            else
            {
                bool foundApexZone = false;

                if (currentNode.Depth > baseDepth)
                {
                    AuthZoneNode authZoneNode = currentValue.Value;
                    if (authZoneNode is not null)
                    {
                        ApexZone apexZone = authZoneNode.ApexZone;
                        if (apexZone is not null)
                            foundApexZone = true;
                    }
                }

                if (foundApexZone)
                {
                    k = currentNode.K + 1;
                    currentNode = currentNode.Parent;
                }
                else
                {
                    int x = DnsNSECRecordData.CanonicalComparison(currentValue.Key, key);
                    if (x == 0)
                    {
                        k = 0;
                    }
                    else if (x > 0)
                    {
                        return currentNode;
                    }
                    else
                    {
                        k = key[currentNode.Depth];
                    }
                }
            }

            while ((currentNode is not null) && (currentNode.Depth >= baseDepth))
            {
                Node[] children = currentNode.Children;
                if (children is not null)
                {
                    Node child = null;

                    for (int i = k; i < children.Length; i++)
                    {
                        child = Volatile.Read(ref children[i]);
                        if (child is not null)
                        {
                            NodeValue childValue = child.Value;
                            if (childValue is not null)
                            {
                                AuthZoneNode authZoneNode = childValue.Value;
                                if (authZoneNode is not null)
                                {
                                    if (authZoneNode.ParentSideZone is not null)
                                    {
                                        return child;
                                    }

                                    if (authZoneNode.ApexZone is not null)
                                    {
                                        child = null;
                                        continue;
                                    }
                                }
                            }

                            if (child.Children is not null)
                                break;
                        }
                    }

                    if (child is not null)
                    {
                        k = 0;
                        currentNode = child;
                        continue;
                    }
                }

                k = currentNode.K + 1;
                currentNode = currentNode.Parent;
            }

            return null;
        }

        private static bool SubDomainExists(byte[] key, Node currentNode)
        {
            Node[] children = currentNode.Children;
            if (children is not null)
            {
                Node child = Volatile.Read(ref children[1]);
                if (child is not null)
                    return true;
            }

            Node nextSubDomain = GetNextSubDomainZoneNode(key, currentNode, currentNode.Depth);
            if (nextSubDomain is null)
                return false;

            NodeValue value = nextSubDomain.Value;
            if (value is null)
                return false;

            return IsKeySubDomain(key, value.Key, false);
        }

        private void RemoveAllSubDomains(string domain, Node currentNode)
        {
            Node current = currentNode;
            byte[] currentKey = ConvertToByteKey(domain);

            do
            {
                current = GetNextSubDomainZoneNode(currentKey, current, currentNode.Depth);
                if (current is null)
                    break;

                NodeValue v = current.Value;
                if (v is not null)
                {
                    AuthZoneNode z = v.Value;
                    if (z is not null)
                    {
                        if (z.ApexZone is null)
                        {
                            current.RemoveNodeValue(v.Key, out _);
                            current.CleanThisBranch();
                        }
                        else
                        {
                            z.TryRemove(out SubDomainZone _);
                        }
                    }

                    currentKey = v.Key;
                }
            }
            while (true);
        }

        #endregion

        #region protected

        protected override void GetClosestValuesForZone(AuthZoneNode zoneValue, out SubDomainZone closestSubDomain, out SubDomainZone closestDelegation, out ApexZone closestAuthority)
        {
            ApexZone apexZone = zoneValue.ApexZone;
            if (apexZone is not null)
            {
                closestSubDomain = null;
                closestDelegation = zoneValue.ParentSideZone;
                closestAuthority = apexZone;
            }
            else
            {
                SubDomainZone subDomainZone = zoneValue.ParentSideZone;

                if (subDomainZone.ContainsNameServerRecords())
                {
                    closestSubDomain = null;
                    closestDelegation = subDomainZone;
                }
                else
                {
                    closestSubDomain = subDomainZone;
                    closestDelegation = null;
                }

                closestAuthority = null;
            }
        }

        #endregion

        #region public

        public bool TryAdd(ApexZone zone)
        {
            AuthZoneNode zoneNode = GetOrAdd(zone.Name, delegate (string key)
            {
                return new AuthZoneNode(null, zone);
            });

            if (ReferenceEquals(zoneNode.ApexZone, zone))
                return true;

            return zoneNode.TryAdd(zone);
        }

        public bool TryGet(string zoneName, string domain, out AuthZone authZone)
        {
            if (TryGet(domain, out AuthZoneNode authZoneNode))
            {
                authZone = authZoneNode.GetAuthZone(zoneName);
                return authZone is not null;
            }

            authZone = null;
            return false;
        }

        public bool TryGet(string zoneName, out ApexZone apexZone)
        {
            if (TryGet(zoneName, out AuthZoneNode authZoneNode) && (authZoneNode.ApexZone is not null))
            {
                apexZone = authZoneNode.ApexZone;
                return true;
            }

            apexZone = null;
            return false;
        }

        public bool TryRemove(string domain, out ApexZone apexZone)
        {
            if (!TryGet(domain, out AuthZoneNode authZoneNode, out Node currentNode) || (authZoneNode.ApexZone is null))
            {
                apexZone = null;
                return false;
            }

            apexZone = authZoneNode.ApexZone;

            if (authZoneNode.ParentSideZone is null)
            {
                if (!base.TryRemove(domain, out AuthZoneNode _))
                {
                    apexZone = null;
                    return false;
                }
            }
            else
            {
                if (!authZoneNode.TryRemove(out ApexZone _))
                {
                    apexZone = null;
                    return false;
                }
            }

            RemoveAllSubDomains(domain, currentNode);

            currentNode.CleanThisBranch();
            return true;
        }

        public bool TryRemove(string domain, out SubDomainZone subDomainZone, bool removeAllSubDomains = false)
        {
            if (!TryGet(domain, out AuthZoneNode zoneNode, out Node currentNode) || (zoneNode.ParentSideZone is null))
            {
                subDomainZone = null;
                return false;
            }

            subDomainZone = zoneNode.ParentSideZone;

            if (zoneNode.ApexZone is null)
            {
                if (!base.TryRemove(domain, out AuthZoneNode _))
                {
                    subDomainZone = null;
                    return false;
                }
            }
            else
            {
                if (!zoneNode.TryRemove(out SubDomainZone _))
                {
                    subDomainZone = null;
                    return false;
                }
            }

            if (removeAllSubDomains)
                RemoveAllSubDomains(domain, currentNode);

            currentNode.CleanThisBranch();
            return true;
        }

        public override bool TryRemove(string key, out AuthZoneNode authZoneNode)
        {
            throw new InvalidOperationException();
        }

        public IReadOnlyList<AuthZone> GetApexZoneWithSubDomainZones(string zoneName)
        {
            List<AuthZone> zones = new List<AuthZone>();

            byte[] key = ConvertToByteKey(zoneName);

            NodeValue nodeValue = _root.FindNodeValue(key, out Node currentNode);
            if (nodeValue is not null)
            {
                AuthZoneNode authZoneNode = nodeValue.Value;
                if (authZoneNode is not null)
                {
                    ApexZone apexZone = authZoneNode.ApexZone;
                    if (apexZone is not null)
                    {
                        zones.Add(apexZone);

                        Node current = currentNode;
                        byte[] currentKey = key;

                        do
                        {
                            current = GetNextSubDomainZoneNode(currentKey, current, currentNode.Depth);
                            if (current is null)
                                break;

                            NodeValue value = current.Value;
                            if (value is not null)
                            {
                                authZoneNode = value.Value;
                                if (authZoneNode is not null)
                                    zones.Add(authZoneNode.ParentSideZone);

                                currentKey = value.Key;
                            }
                        }
                        while (true);
                    }
                }
            }

            return zones;
        }

        public AuthZone GetOrAddSubDomainZone(string zoneName, string domain, Func<SubDomainZone> valueFactory)
        {
            bool isApex = zoneName.Equals(domain, StringComparison.OrdinalIgnoreCase);

            AuthZoneNode authZoneNode = GetOrAdd(domain, delegate (string key)
            {
                if (isApex)
                    throw new DnsServerException("Zone was not found for domain: " + key);

                return new AuthZoneNode(valueFactory(), null);
            });

            if (isApex)
            {
                if (authZoneNode.ApexZone is null)
                    throw new DnsServerException("Zone was not found: " + zoneName);

                return authZoneNode.ApexZone;
            }
            else
            {
                return authZoneNode.GetOrAddParentSideZone(valueFactory);
            }
        }

        public AuthZone GetAuthZone(string zoneName, string domain)
        {
            if (TryGet(domain, out AuthZoneNode authZoneNode))
                return authZoneNode.GetAuthZone(zoneName);

            return null;
        }

        public AuthZone FindZone(string domain, out SubDomainZone closest, out SubDomainZone delegation, out ApexZone authority, out bool hasSubDomains)
        {
            byte[] key = ConvertToByteKey(domain);

            AuthZoneNode authZoneNode = FindZoneNode(key, true, out Node currentNode, out Node closestSubDomainNode, out _, out SubDomainZone closestSubDomain, out SubDomainZone closestDelegation, out ApexZone closestAuthority);
            if (authZoneNode is null)
            {
                closest = closestSubDomain;
                delegation = closestDelegation;
                authority = closestAuthority;

                if (authority is null)
                {
                    hasSubDomains = false;
                }
                else if ((closestSubDomainNode is not null) && !closestSubDomainNode.HasChildren)
                {
                    hasSubDomains = false;
                }
                else
                {
                    hasSubDomains = SubDomainExists(key, currentNode);
                }

                return null;
            }
            else
            {
                AuthZone zone;

                ApexZone apexZone = authZoneNode.ApexZone;
                if (apexZone is not null)
                {
                    zone = apexZone;
                    closest = null;
                    delegation = authZoneNode.ParentSideZone;
                    authority = apexZone;
                }
                else
                {
                    SubDomainZone subDomainZone = authZoneNode.ParentSideZone;

                    zone = subDomainZone;

                    if (zone == closestSubDomain)
                        closest = null;
                    else
                        closest = closestSubDomain;

                    if (closestDelegation is not null)
                        delegation = closestDelegation;
                    else if (subDomainZone.ContainsNameServerRecords())
                        delegation = subDomainZone;
                    else
                        delegation = null;

                    authority = closestAuthority;
                }

                if (zone.Disabled)
                {
                    if ((closestSubDomainNode is not null) && !closestSubDomainNode.HasChildren)
                    {
                        hasSubDomains = false;
                    }
                    else
                    {
                        hasSubDomains = SubDomainExists(key, currentNode);
                    }
                }
                else
                {
                    hasSubDomains = false;
                }

                return zone;
            }
        }

        #endregion
    }
}
