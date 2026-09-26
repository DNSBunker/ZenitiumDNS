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
