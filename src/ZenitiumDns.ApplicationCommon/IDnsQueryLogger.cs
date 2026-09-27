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

using System;
using System.Net;
using System.Threading.Tasks;
using ZenitiumLibrary.Net.Dns;

namespace ZenitiumDns.ApplicationCommon
{
    public enum DnsServerResponseType : byte
    {
        Authoritative = 1,
        Recursive = 2,
        Cached = 3,
        Blocked = 4,
        UpstreamBlocked = 5,
        UpstreamBlockedCached = 6,
        Dropped = 7
    }

    public interface IDnsQueryLogger
    {
        Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response);
    }
}
