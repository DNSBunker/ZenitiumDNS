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

using ZenitiumDns.ApplicationCommon;

namespace ZenitiumDns.Core.Dns
{
    static class ResponseTypeTags
    {
        public static readonly object Authoritative = DnsServerResponseType.Authoritative;
        public static readonly object Recursive = DnsServerResponseType.Recursive;
        public static readonly object Cached = DnsServerResponseType.Cached;
        public static readonly object Blocked = DnsServerResponseType.Blocked;
        public static readonly object UpstreamBlocked = DnsServerResponseType.UpstreamBlocked;
        public static readonly object UpstreamBlockedCached = DnsServerResponseType.UpstreamBlockedCached;
        public static readonly object Dropped = DnsServerResponseType.Dropped;
    }
}
