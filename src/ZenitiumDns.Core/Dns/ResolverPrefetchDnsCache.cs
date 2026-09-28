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

using System.Threading.Tasks;
using ZenitiumLibrary.Net.Dns;

namespace ZenitiumDns.Core.Dns
{
    class ResolverPrefetchDnsCache : ResolverDnsCache
    {
        #region variables

        readonly DnsQuestionRecord _prefetchQuestion;

        #endregion

        #region constructor

        public ResolverPrefetchDnsCache(DnsServer dnsServer, bool skipDnsAppAuthoritativeRequestHandlers, DnsQuestionRecord prefetchQuestion, bool aggressiveNsec = true)
            : base(dnsServer, skipDnsAppAuthoritativeRequestHandlers, false, aggressiveNsec)
        {
            _prefetchQuestion = prefetchQuestion;
        }

        #endregion

        #region public

        public override Task<DnsDatagram> QueryAsync(DnsDatagram request, bool serveStale = false, bool findClosestNameServers = false, bool resetExpiry = false)
        {
            if (_prefetchQuestion.Equals(request.Question[0]))
            {
                if (!findClosestNameServers)
                    return Task.FromResult<DnsDatagram>(null);

                return QueryClosestDelegationAsync(request);
            }

            return base.QueryAsync(request, serveStale, findClosestNameServers, resetExpiry);
        }

        #endregion
    }
}
