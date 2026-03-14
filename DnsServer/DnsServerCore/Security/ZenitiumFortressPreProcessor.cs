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
        public enum PreProcessorAction { Allow, TruncateToTcp, SilentDrop }
        public enum TransportProtocol { Udp, Tcp }

        private class ClientProfile
        {
            public long IsVerified = 0; 
            public long IsBanned = 0;   
            public long TotalQueries = 0;
            public long TxtQueries = 0;
            public long NxDomainResponses = 0;
            public readonly ConcurrentDictionary<string, int> DomainNxStrikes = new();
            
            public long Tokens = 100; 
            public long LastRefillTicks = DateTime.UtcNow.Ticks;

            public long ExpirationTicks;
            public long LastSeenTicks;

            public ClientProfile() {
                ExpirationTicks = DateTime.UtcNow.AddHours(6).Ticks;
                LastSeenTicks = DateTime.UtcNow.Ticks;
            }
        }

        private readonly ConcurrentDictionary<IPAddress, ClientProfile> _profiles = new();
        private readonly CancellationTokenSource _cts = new();
        
        private const double MAX_TXT_RATIO = 0.25;
        private const double MAX_NX_RATIO = 0.45;
        private const int MAX_DOMAIN_NX_STRIKES = 15;
        private const int MAX_TRACKED_PROFILES = 150000;
        private const int TOKENS_MAX = 100;
        private const int TOKENS_PER_SEC = 10;

        public ZenitiumFortressPreProcessor()
        {
            _ = Task.Run(async () => {
                while (!_cts.Token.IsCancellationRequested) {
                    await Task.Delay(TimeSpan.FromMinutes(5), _cts.Token);
                    CleanUp();
                }
            });
        }

        public PreProcessorAction EvaluateRequest(IPAddress clientIp, TransportProtocol protocol, string domain, string recordType)
        {
            IPAddress effectiveIp = GetEffectiveIp(clientIp);
            var profile = _profiles.GetOrAdd(effectiveIp, _ => new ClientProfile());
            long now = DateTime.UtcNow.Ticks;
            
            Interlocked.Exchange(ref profile.LastSeenTicks, now);
            
            long currentExpiry = Interlocked.Read(ref profile.ExpirationTicks);
            if (now > currentExpiry) {
                long newExpiry = now + TimeSpan.FromHours(6).Ticks;
                if (Interlocked.CompareExchange(ref profile.ExpirationTicks, newExpiry, currentExpiry) == currentExpiry) {
                    ResetProfile(profile);
                }
            }

            if (Interlocked.Read(ref profile.IsBanned) == 1) return PreProcessorAction.SilentDrop;
            
            if (!ConsumeToken(profile, now)) return PreProcessorAction.SilentDrop;
            
            if (protocol == TransportProtocol.Udp) {
                if (Interlocked.Read(ref profile.IsVerified) == 0) return PreProcessorAction.TruncateToTcp;
                if (recordType == "ANY") return PreProcessorAction.TruncateToTcp;
            } else {
                Interlocked.Exchange(ref profile.IsVerified, 1);
            }
            
            if (recordType != "ANY") {
                Interlocked.Increment(ref profile.TotalQueries);
                if (recordType == "TXT") Interlocked.Increment(ref profile.TxtQueries);
            }

            long total = Interlocked.Read(ref profile.TotalQueries);
            if (total > 30) {
                if ((double)Interlocked.Read(ref profile.TxtQueries) / total > MAX_TXT_RATIO) 
                    return PreProcessorAction.TruncateToTcp;

                if ((double)Interlocked.Read(ref profile.NxDomainResponses) / total > MAX_NX_RATIO) {
                    Interlocked.Exchange(ref profile.IsBanned, 1);
                    return PreProcessorAction.SilentDrop;
                }
            }

            return PreProcessorAction.Allow;
        }

        private bool ConsumeToken(ClientProfile p, long now)
        {
            long lastRefill = Interlocked.Read(ref p.LastRefillTicks);
            double secondsPassed = TimeSpan.FromTicks(now - lastRefill).TotalSeconds;
            
            if (secondsPassed >= 1.0) {
                long currentTokens = Interlocked.Read(ref p.Tokens);
                long added = (long)(secondsPassed * TOKENS_PER_SEC);
                long newTotal = Math.Min(TOKENS_MAX, currentTokens + added);
                
                if (Interlocked.CompareExchange(ref p.Tokens, newTotal, currentTokens) == currentTokens) {
                    Interlocked.Exchange(ref p.LastRefillTicks, now);
                }
            }
            
            long current;
            do {
                current = Interlocked.Read(ref p.Tokens);
                if (current <= 0) return false;
            } while (Interlocked.CompareExchange(ref p.Tokens, current - 1, current) != current);
            
            return true;
        }

        public void ReportNxDomain(IPAddress clientIp, string fullDomain)
        {
            IPAddress effectiveIp = GetEffectiveIp(clientIp);
            if (!_profiles.TryGetValue(effectiveIp, out var profile)) return;

            Interlocked.Increment(ref profile.NxDomainResponses);
            
            string root = GetRootDomain(fullDomain);
            int strikes = profile.DomainNxStrikes.AddOrUpdate(root, 1, (key, val) => val + 1);

            if (strikes > MAX_DOMAIN_NX_STRIKES) {
                Interlocked.Exchange(ref profile.IsBanned, 1);
            }
        }

        private void ResetProfile(ClientProfile p)
        {
            Interlocked.Exchange(ref p.IsVerified, 0);
            Interlocked.Exchange(ref p.IsBanned, 0);
            Interlocked.Exchange(ref p.TotalQueries, 0);
            Interlocked.Exchange(ref p.TxtQueries, 0);
            Interlocked.Exchange(ref p.NxDomainResponses, 0);
            Interlocked.Exchange(ref p.Tokens, TOKENS_MAX);
            Interlocked.Exchange(ref p.LastRefillTicks, DateTime.UtcNow.Ticks);
            p.DomainNxStrikes.Clear();
        }

        private IPAddress GetEffectiveIp(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetworkV6) return ip;
            byte[] bytes = ip.GetAddressBytes();
            for (int i = 8; i < 16; i++) bytes[i] = 0; // /64 masking
            return new IPAddress(bytes);
        }

        private string GetRootDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain)) return "unknown";
            var parts = domain.TrimEnd('.').Split('.');
            if (parts.Length <= 2) return domain;
            return $"{parts[parts.Length - 2]}.{parts[parts.Length - 1]}";
        }

        private void CleanUp()
        {
            long now = DateTime.UtcNow.Ticks;
            
            foreach (var key in _profiles.Keys) {
                if (_profiles.TryGetValue(key, out var p) && now > Interlocked.Read(ref p.ExpirationTicks))
                    _profiles.TryRemove(key, out _);
            }
            
            if (_profiles.Count > MAX_TRACKED_PROFILES) {
                var toRemove = _profiles
                    .OrderBy(kv => Interlocked.Read(ref kv.Value.LastSeenTicks))
                    .Take(_profiles.Count / 5)
                    .Select(kv => kv.Key);

                foreach (var key in toRemove) _profiles.TryRemove(key, out _);
            }
        }

        public void Dispose() { _cts.Cancel(); _cts.Dispose(); }
    }
}