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
