using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

namespace Zenitium.Dns.Security
{
    public class ZenitiumFortressPreProcessor : IDisposable
    {
        public enum PreProcessorAction { Allow, SilentDrop }

        private class ClientProfile
        {
            public long TotalQueries = 0;
            public long NxDomainResponses = 0;
            public long TxtQueries = 0;
            public long AnyQueries = 0;
            public long RareTypeQueries = 0;

            public long BanUntilTicks = 0;

            public long ExpirationTicks;
            public long LastSeenTicks;

            public ClientProfile()
            {
                long now = DateTime.UtcNow.Ticks;
                LastSeenTicks = now;
                ExpirationTicks = now + TimeSpan.FromHours(6).Ticks;
            }
        }

        private readonly ConcurrentDictionary<IPAddress, ClientProfile> _profiles = new();
        private readonly CancellationTokenSource _cts = new();

        private const double SOFT_TXT_RATIO       = 0.60;
        private const double SOFT_ANY_RATIO       = 0.20;
        private const double SOFT_RARE_TYPE_RATIO = 0.15;
        private const double SOFT_NX_RATIO        = 0.92;

        private const double HARD_TXT_RATIO       = 0.90;
        private const double HARD_ANY_RATIO       = 0.50;
        private const double HARD_RARE_TYPE_RATIO = 0.40;
        private const double HARD_NX_RATIO        = 0.99;

        private const int MIN_QUERIES_FOR_SOFT    = 200;
        private const int MIN_QUERIES_FOR_HARD    = 500;
        private const int HARD_BAN_MINUTES        = 15;

        private const int MAX_TRACKED_PROFILES    = 150000;

        public ZenitiumFortressPreProcessor()
        {
            _ = Task.Run(async () =>
            {
                while (!_cts.Token.IsCancellationRequested)
                {
                    try
                    {
                        await Task.Delay(TimeSpan.FromMinutes(2), _cts.Token);
                        CleanUp();
                    }
                    catch (OperationCanceledException) { break; }
                    catch (Exception) { }
                }
            });
        }

        public PreProcessorAction EvaluateRequest(
            IPAddress clientIp,
            string domain,
            string recordType)
        {
            IPAddress effectiveIp = GetEffectiveIp(clientIp);

            if (_profiles.Count >= MAX_TRACKED_PROFILES && !_profiles.ContainsKey(effectiveIp))
                return PreProcessorAction.SilentDrop;

            var profile = _profiles.GetOrAdd(effectiveIp, _ => new ClientProfile());
            long now = DateTime.UtcNow.Ticks;

            Interlocked.Exchange(ref profile.LastSeenTicks, now);
            Interlocked.Exchange(ref profile.ExpirationTicks, now + TimeSpan.FromHours(6).Ticks);

            long banUntil = Interlocked.Read(ref profile.BanUntilTicks);
            if (banUntil > now) return PreProcessorAction.SilentDrop;
            if (banUntil > 0 && banUntil <= now)
                Interlocked.Exchange(ref profile.BanUntilTicks, 0);

            Interlocked.Increment(ref profile.TotalQueries);

            if (recordType == "TXT")
                Interlocked.Increment(ref profile.TxtQueries);

            if (recordType == "ANY")
                Interlocked.Increment(ref profile.AnyQueries);

            if (IsRareType(recordType))
                Interlocked.Increment(ref profile.RareTypeQueries);

            long total = Interlocked.Read(ref profile.TotalQueries);

            if (total >= MIN_QUERIES_FOR_SOFT)
            {
                double txtRatio  = (double)Interlocked.Read(ref profile.TxtQueries)        / total;
                double anyRatio  = (double)Interlocked.Read(ref profile.AnyQueries)        / total;
                double rareRatio = (double)Interlocked.Read(ref profile.RareTypeQueries)   / total;
                double nxRatio   = (double)Interlocked.Read(ref profile.NxDomainResponses) / total;

                if (total >= MIN_QUERIES_FOR_HARD)
                {
                    if (txtRatio  > HARD_TXT_RATIO  ||
                        anyRatio  > HARD_ANY_RATIO  ||
                        rareRatio > HARD_RARE_TYPE_RATIO ||
                        nxRatio   > HARD_NX_RATIO)
                    {
                        ApplyHardBan(profile, now);
                        return PreProcessorAction.SilentDrop;
                    }
                }

                if (txtRatio  > SOFT_TXT_RATIO  ||
                    anyRatio  > SOFT_ANY_RATIO  ||
                    rareRatio > SOFT_RARE_TYPE_RATIO ||
                    nxRatio   > SOFT_NX_RATIO)
                {
                    return PreProcessorAction.SilentDrop;
                }
            }

            return PreProcessorAction.Allow;
        }

        public void ReportNxDomain(IPAddress clientIp, string fullDomain)
        {
            IPAddress effectiveIp = GetEffectiveIp(clientIp);
            if (!_profiles.TryGetValue(effectiveIp, out var profile)) return;

            Interlocked.Increment(ref profile.NxDomainResponses);
        }

        public void ReportBadConnection(IPAddress clientIp, int penaltySeconds = 30)
        {
            //no suppression
        }

        public void ResetReputation(IPAddress clientIp)
        {
            IPAddress effectiveIp = GetEffectiveIp(clientIp);
            if (_profiles.TryGetValue(effectiveIp, out var profile))
                ResetProfile(profile);
        }

        private static void ApplyHardBan(ClientProfile p, long now)
        {
            long newEnd = now + TimeSpan.FromMinutes(HARD_BAN_MINUTES).Ticks;
            long current;
            do
            {
                current = Interlocked.Read(ref p.BanUntilTicks);
                if (newEnd <= current) return;
            } while (Interlocked.CompareExchange(ref p.BanUntilTicks, newEnd, current) != current);

            Interlocked.Exchange(ref p.ExpirationTicks, newEnd + TimeSpan.FromHours(1).Ticks);
        }

        private static bool IsRareType(string recordType)
        {
            return recordType is
                "NULL" or "HINFO" or "WKS"  or "AFSDB" or "X25"  or
                "ISDN" or "RT"   or "NSAP"  or "PX"    or "GPOS" or
                "KX"   or "A6"   or "SINK"  or "APL"   or "CHAOS";
        }

        private void ResetProfile(ClientProfile p)
        {
            Interlocked.Exchange(ref p.BanUntilTicks, 0);
            Interlocked.Exchange(ref p.TotalQueries, 0);
            Interlocked.Exchange(ref p.NxDomainResponses, 0);
            Interlocked.Exchange(ref p.TxtQueries, 0);
            Interlocked.Exchange(ref p.AnyQueries, 0);
            Interlocked.Exchange(ref p.RareTypeQueries, 0);
        }

        private IPAddress GetEffectiveIp(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetworkV6) return ip;
            byte[] bytes = ip.GetAddressBytes();
            for (int i = 8; i < 16; i++) bytes[i] = 0;
            return new IPAddress(bytes);
        }

        private void CleanUp()
        {
            long now = DateTime.UtcNow.Ticks;

            foreach (var key in _profiles.Keys)
            {
                if (!_profiles.TryGetValue(key, out var p)) continue;

                if (now > Interlocked.Read(ref p.ExpirationTicks))
                    _profiles.TryRemove(key, out _);
            }

            if (_profiles.Count > MAX_TRACKED_PROFILES)
            {
                var toRemove = _profiles
                    .OrderBy(kv => Interlocked.Read(ref kv.Value.LastSeenTicks))
                    .Take(_profiles.Count / 5)
                    .Select(kv => kv.Key);

                foreach (var key in toRemove)
                    _profiles.TryRemove(key, out _);
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _cts.Dispose();
        }
    }
}