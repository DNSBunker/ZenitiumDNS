/*
Technitium DNS Server
Copyright (C) 2021  Shreyas Zare (shreyas@technitium.com)

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

using System.Net;
using System.Threading.Tasks;
using ZenitiumLibrary.Net.Dns;

namespace ZenitiumDns.ApplicationCommon
{
    public enum DnsRequestControllerAction
    {
        Allow = 0,

        DropSilently = 1,

        DropWithRefused = 2
    }

    public interface IDnsRequestController
    {
        Task<DnsRequestControllerAction> GetRequestActionAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol);
    }
}
