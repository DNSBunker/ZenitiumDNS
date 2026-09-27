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

namespace ZenitiumDns.Core.Dns
{
    public enum RequestFilterRule : byte
    {
        Malformed = 0,
        Size = 1,
        Opcode = 2,
        Class = 3,
        Any = 4,
        ZoneTransfer = 5,
        NoRecursion = 6,
        EdnsVersion = 7
    }

    public static class RequestFilterRuleExtensions
    {
        public static string GetApiName(this RequestFilterRule rule)
        {
            switch (rule)
            {
                case RequestFilterRule.Malformed:
                    return "malformed";

                case RequestFilterRule.Size:
                    return "size";

                case RequestFilterRule.Opcode:
                    return "opcode";

                case RequestFilterRule.Class:
                    return "class";

                case RequestFilterRule.Any:
                    return "any";

                case RequestFilterRule.ZoneTransfer:
                    return "zoneTransfer";

                case RequestFilterRule.NoRecursion:
                    return "noRecursion";

                case RequestFilterRule.EdnsVersion:
                    return "ednsVersion";

                default:
                    return rule.ToString();
            }
        }
    }
}
