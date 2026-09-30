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

using ZenitiumLibrary.Net.Dns;

namespace ZenitiumDns.Core.Dns
{
    sealed class ResolutionScratchCache : DnsCache
    {
        #region variables

        const uint FAILURE_RECORD_TTL = 10u;
        const uint NEGATIVE_RECORD_TTL = 300u;
        const uint MINIMUM_RECORD_TTL = 0u;
        const uint MAXIMUM_RECORD_TTL = 7 * 24 * 60 * 60;
        const uint SERVE_STALE_TTL = 0u;
        const uint SERVE_STALE_ANSWER_TTL = 30u;

        #endregion

        #region constructor

        public ResolutionScratchCache()
            : base(FAILURE_RECORD_TTL, NEGATIVE_RECORD_TTL, MINIMUM_RECORD_TTL, MAXIMUM_RECORD_TTL, SERVE_STALE_TTL, SERVE_STALE_ANSWER_TTL)
        { }

        #endregion
    }
}
