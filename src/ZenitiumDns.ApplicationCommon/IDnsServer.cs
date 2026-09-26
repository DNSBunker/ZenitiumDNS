/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using System.Net.Mail;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Proxy;

namespace ZenitiumDns.ApplicationCommon
{
    public interface IDnsServer : IDnsClient
    {
        Task<DnsDatagram> DirectQueryAsync(DnsQuestionRecord question, int timeout = 4000, CancellationToken cancellationToken = default);

        Task<DnsDatagram> DirectQueryAsync(DnsDatagram request, int timeout = 4000, CancellationToken cancellationToken = default);

        Task<DnsDatagram> DirectQueryAsync(DnsDatagram request, IPEndPoint remoteEP, int timeout = 4000, CancellationToken cancellationToken = default);

        bool IsLocallyServedZone(string domain);

        void WriteLog(string message);

        void WriteLog(Exception ex);

        void WriteLog(string message, Exception ex);

        string ApplicationName { get; }

        string ApplicationFolder { get; }

        string ServerDomain { get; }

        MailAddress ResponsiblePerson { get; }

        IDnsCache DnsCache { get; }

        NetProxy? Proxy { get; }

        IPv6Mode IPv6Mode { get; }

        public ushort UdpPayloadSize { get; }
    }
}
