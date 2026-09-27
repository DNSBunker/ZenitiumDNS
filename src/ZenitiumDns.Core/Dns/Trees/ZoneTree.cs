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

using ZenitiumDns.Core.Dns.Zones;
using System.Collections.Generic;
using System.Threading;

namespace ZenitiumDns.Core.Dns.Trees
{
    abstract class ZoneTree<TNode, TSubDomainZone, TApexZone> : DomainTree<TNode> where TNode : class where TSubDomainZone : Zone where TApexZone : Zone
    {
        #region private

        private static Node GetNextChildZoneNode(Node current, int baseDepth)
        {
            int k = 0;

            while ((current is not null) && (current.Depth >= baseDepth))
            {
                if ((current.K != 0) || (current.Depth == baseDepth))
                {
                    Node[] children = current.Children;
                    if (children is not null)
                    {
                        Node child = null;

                        for (int i = k; i < children.Length; i++)
                        {
                            child = Volatile.Read(ref children[i]);
                            if (child is not null)
                            {
                                if (child.Value is not null)
                                    return child;

                                if (child.K == 0)
                                    return child;

                                if (child.Children is not null)
                                    break;
                            }
                        }

                        if (child is not null)
                        {
                            k = 0;
                            current = child;
                            continue;
                        }
                    }
                }

                k = current.K + 1;
                current = current.Parent;
            }

            return null;
        }

        private static byte[] GetNodeKey(Node node)
        {
            byte[] key = new byte[node.Depth];
            int i = node.Depth - 1;

            while (i > -1)
            {
                key[i--] = node.K;
                node = node.Parent;
            }

            return key;
        }

        private static bool KeysMatch(byte[] mainKey, byte[] testKey, bool matchWildcard)
        {
            if (matchWildcard)
            {
                int i = 0;
                int j = 0;

                while ((i < mainKey.Length) && (j < testKey.Length))
                {
                    if ((mainKey[i] == 1) && (testKey[j] != 1))
                    {
                        if (i == mainKey.Length - 2)
                            return true;
                    }

                    if (mainKey[i] != testKey[j])
                        return false;

                    i++;
                    j++;
                }

                return (i == mainKey.Length) && (j == testKey.Length);
            }
            else
            {
                if (mainKey.Length != testKey.Length)
                    return false;

                for (int i = 0; i < mainKey.Length; i++)
                {
                    if (mainKey[i] != testKey[i])
                        return false;
                }

                return true;
            }
        }

        private void FindClosestValuesForZone(TNode zoneNode, Node currentNode, ref Node closestSubDomainNode, ref Node closestAuthorityNode, ref TSubDomainZone closestSubDomain, ref TSubDomainZone closestDelegation, ref TApexZone closestAuthority)
        {
            GetClosestValuesForZone(zoneNode, out TSubDomainZone subDomain, out TSubDomainZone delegation, out TApexZone authority);

            if (subDomain is not null)
            {
                if ((closestSubDomain is null) || !closestSubDomain.ContainsDNAMERecord())
                {
                    closestSubDomain = subDomain;
                    closestSubDomainNode = currentNode;
                }
            }

            if (delegation is not null)
                closestDelegation = delegation;

            if (authority is not null)
            {
                closestAuthority = authority;
                closestAuthorityNode = currentNode;

                closestSubDomain = null;
                closestSubDomainNode = null;
            }
        }

        #endregion

        #region protected

        protected static bool IsKeySubDomain(byte[] mainKey, byte[] testKey, bool matchWildcard)
        {
            if (matchWildcard)
            {
                int i = 0;
                int j = 0;

                while ((i < mainKey.Length) && (j < testKey.Length))
                {
                    if ((mainKey[i] == 1) && (testKey[j] != 1))
                    {
                        while (j < testKey.Length)
                        {
                            if (testKey[j] == 0)
                                break;

                            j++;
                        }

                        i++;
                        continue;
                    }

                    if (mainKey[i] != testKey[j])
                        return false;

                    i++;
                    j++;
                }

                return (i == mainKey.Length) && (j < testKey.Length);
            }
            else
            {
                if (mainKey.Length > testKey.Length)
                    return false;

                for (int i = 0; i < mainKey.Length; i++)
                {
                    if (mainKey[i] != testKey[i])
                        return false;
                }

                return mainKey.Length < testKey.Length;
            }
        }

        protected TNode FindZoneNode(byte[] key, bool matchWildcard, out Node currentNode, out Node closestSubDomainNode, out Node closestAuthorityNode, out TSubDomainZone closestSubDomain, out TSubDomainZone closestDelegation, out TApexZone closestAuthority)
        {
            currentNode = _root;
            closestSubDomainNode = null;
            closestAuthorityNode = null;
            closestSubDomain = null;
            closestDelegation = null;
            closestAuthority = null;
            Node wildcardNode = null;
            int i = 0;

            while (i <= key.Length)
            {
                NodeValue value = currentNode.Value;
                if ((value is not null) && (value.Key.Length <= key.Length))
                {
                    TNode zoneNode = value.Value;
                    if ((zoneNode is not null) && IsKeySubDomain(value.Key, key, matchWildcard))
                    {
                        FindClosestValuesForZone(zoneNode, currentNode, ref closestSubDomainNode, ref closestAuthorityNode, ref closestSubDomain, ref closestDelegation, ref closestAuthority);

                        wildcardNode = null;
                    }
                }

                if (i == key.Length)
                    break;

                Node[] children = currentNode.Children;
                if (children is null)
                    break;

                Node childNode;

                if (matchWildcard && (key[i] != 1))
                {
                    childNode = Volatile.Read(ref children[1]);
                    if (childNode is not null)
                    {
                        NodeValue wValue = childNode.Value;
                        if (wValue is null)
                        {
                            Node[] wChildren = childNode.Children;
                            if (wChildren is not null)
                            {
                                Node wChildNode = Volatile.Read(ref wChildren[0]);
                                if (wChildNode is not null)
                                {
                                    wValue = wChildNode.Value;
                                    if ((wValue is not null) && (wValue.Key.Length == wChildNode.Depth))
                                        wildcardNode = wChildNode;
                                }
                            }
                        }
                        else if (wValue.Key.Length == childNode.Depth + 1)
                        {
                            wildcardNode = childNode;
                        }
                    }
                }

                childNode = Volatile.Read(ref children[key[i]]);
                if (childNode is null)
                {
                    if (wildcardNode is null)
                        return null;

                    break;
                }

                currentNode = childNode;
                i++;
            }

            {
                NodeValue value = currentNode.Value;
                if (value is not null)
                {
                    if (KeysMatch(value.Key, key, matchWildcard))
                    {
                        TNode zoneNode = value.Value;
                        if (zoneNode is not null)
                            FindClosestValuesForZone(zoneNode, currentNode, ref closestSubDomainNode, ref closestAuthorityNode, ref closestSubDomain, ref closestDelegation, ref closestAuthority);

                        return value.Value;
                    }

                    if (wildcardNode is not null)
                    {
                        NodeValue wildcardValue = wildcardNode.Value;
                        if (wildcardValue is not null)
                        {
                            if (IsKeySubDomain(key, value.Key, false) && IsKeySubDomain(wildcardValue.Key, value.Key, matchWildcard))
                            {
                                wildcardNode = null;
                            }
                        }
                    }
                }
                else if ((wildcardNode is not null) && (currentNode.K == 0) && currentNode.HasChildren && (currentNode != wildcardNode.Parent))
                {
                    wildcardNode = null;
                }
            }

            if (wildcardNode is not null)
            {
                NodeValue value = wildcardNode.Value;
                if (value is not null)
                {
                    if (KeysMatch(value.Key, key, true))
                    {
                        TNode zoneNode = value.Value;
                        if (zoneNode is not null)
                            FindClosestValuesForZone(zoneNode, currentNode, ref closestSubDomainNode, ref closestAuthorityNode, ref closestSubDomain, ref closestDelegation, ref closestAuthority);

                        return value.Value;
                    }
                }
            }

            return null;
        }

        protected abstract void GetClosestValuesForZone(TNode zoneValue, out TSubDomainZone closestSubDomain, out TSubDomainZone closestDelegation, out TApexZone closestAuthority);

        #endregion

        #region public

        public void ListSubDomains(string domain, List<string> subDomains)
        {
            byte[] bKey = ConvertToByteKey(domain);

            _ = _root.FindNodeValue(bKey, out Node currentNode);
            Node current = currentNode;
            NodeValue value;

            do
            {
                value = current.Value;
                if (value is not null)
                {
                    if (IsKeySubDomain(bKey, value.Key, false))
                    {
                        string label = ConvertKeyToLabel(value.Key, bKey.Length);
                        if (label is not null)
                            subDomains.Add(label);
                    }
                }
                else if ((current.K == 0) && (current.Depth > currentNode.Depth))
                {
                    byte[] nodeKey = GetNodeKey(current);
                    if (IsKeySubDomain(bKey, nodeKey, false))
                    {
                        string label = ConvertKeyToLabel(nodeKey, bKey.Length);
                        if (label is not null)
                            subDomains.Add(label);
                    }
                }

                current = GetNextChildZoneNode(current, currentNode.Depth);
            }
            while (current is not null);
        }

        #endregion
    }
}
