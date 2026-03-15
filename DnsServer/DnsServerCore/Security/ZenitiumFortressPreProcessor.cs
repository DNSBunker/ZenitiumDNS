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
        private enum ClientTier { Trusted, Normal, Suspicious, Restricted }

        private class ClientProfile
        {
            public long IsVerified = 0;
            public long BanUntilTicks = 0;
            public long BanCount = 0;

            public long TotalQueries = 0;
            public long TxtQueries = 0;
            public long NxDomainResponses = 0;

            public long Karma = 100;

            public readonly ConcurrentDictionary<string, (int Strikes, long LastStrikeTicks)> DomainNxStrikes = new();

            public double Tokens = 100.0;
            public long LastRefillTicks;

            public long ExpirationTicks;
            public long LastSeenTicks;
            
            public long LastBurstWindowStart;
            public long BurstWindowQueries;
            
            public readonly double[] EntropyBuffer;
            public int EntropyIndex;
            public int EntropyCount;
            public readonly object EntropyLock;

            public ClientProfile()
            {
                long now = DateTime.UtcNow.Ticks;
                LastSeenTicks = now;
                ExpirationTicks = now + TimeSpan.FromHours(6).Ticks;
                LastRefillTicks = now;

                LastBurstWindowStart = now;
                BurstWindowQueries = 0;

                EntropyBuffer = new double[ENTROPY_BUFFER_SIZE];
                EntropyIndex = 0;
                EntropyCount = 0;
                EntropyLock = new object();
            }
        }

        private readonly ConcurrentDictionary<IPAddress, ClientProfile> _profiles = new();
        private readonly CancellationTokenSource _cts = new();
        
        private const double MAX_TXT_RATIO = 0.35;
        private const double MAX_TXT_RATIO_SUSPICIOUS = 0.20;
        private const double MAX_NX_RATIO = 0.60;
        private const double MAX_NX_RATIO_SUSPICIOUS = 0.40;
        private const int MIN_QUERIES_FOR_RATIO_CHECK = 100;

        private const int MAX_DOMAIN_NX_STRIKES = 20;
        private const int MAX_TRACKED_PROFILES = 150000;

        private const double BASE_TOKENS_MAX = 100.0;
        private const double BASE_TOKENS_PER_SEC = 10.0;

        private const int BURST_WINDOW_TICKS = 5 * 10000000;
        private const int BURST_MAX_QUERIES = 40;

        private const int ENTROPY_BUFFER_SIZE = 50;
        private const double ENTROPY_THRESHOLD_NORMAL = 4.2;
        private const double ENTROPY_THRESHOLD_SUSPICIOUS = 3.9;
        private const double ENTROPY_THRESHOLD_TCP = 4.8;

        private const int BAN_MAX_MINUTES = 40;

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
                    catch (OperationCanceledException)
                    {
                        break;
                    }
                    catch (Exception)
                    {
                    }
                }
            });
        }

        public PreProcessorAction EvaluateRequest(IPAddress clientIp, TransportProtocol protocol, string domain, string recordType)
        {
            IPAddress effectiveIp = GetEffectiveIp(clientIp);

            if (_profiles.Count >= MAX_TRACKED_PROFILES && !_profiles.ContainsKey(effectiveIp))
            {
                return PreProcessorAction.SilentDrop;
            }

            var profile = _profiles.GetOrAdd(effectiveIp, _ => new ClientProfile());
            long now = DateTime.UtcNow.Ticks;

            Interlocked.Exchange(ref profile.LastSeenTicks, now);
            Interlocked.Exchange(ref profile.ExpirationTicks, now + TimeSpan.FromHours(6).Ticks);

            ClientTier tier = GetTier(Interlocked.Read(ref profile.Karma));

            long banUntil = Interlocked.Read(ref profile.BanUntilTicks);
            if (banUntil > now) return PreProcessorAction.SilentDrop;

            if (banUntil > 0 && banUntil <= now)
            {
                Interlocked.Exchange(ref profile.BanUntilTicks, 0);
                Interlocked.Exchange(ref profile.Karma, 50);
                profile.DomainNxStrikes.Clear();
            }

            if (tier == ClientTier.Restricted && protocol == TransportProtocol.Udp)
            {
                return PreProcessorAction.TruncateToTcp;
            }

            if (!ConsumeToken(profile, now, tier)) return PreProcessorAction.SilentDrop;

            if (protocol == TransportProtocol.Udp)
            {
                if (Interlocked.Read(ref profile.IsVerified) == 0) return PreProcessorAction.TruncateToTcp;
                if (recordType == "ANY")
                {
                    PenalizeKarma(profile, 5);
                    return PreProcessorAction.TruncateToTcp;
                }
            }
            else
            {
                Interlocked.Exchange(ref profile.IsVerified, 1);
            }

            if (IsInBurst(profile, now))
            {
                PenalizeKarma(profile, 2);
                return PreProcessorAction.TruncateToTcp;
            }

            if (recordType != "ANY")
            {
                Interlocked.Increment(ref profile.TotalQueries);
                if (recordType == "TXT") Interlocked.Increment(ref profile.TxtQueries);
            }

            long total = Interlocked.Read(ref profile.TotalQueries);
            if (total > MIN_QUERIES_FOR_RATIO_CHECK && tier != ClientTier.Trusted)
            {
                double activeTxtRatio = tier == ClientTier.Suspicious ? MAX_TXT_RATIO_SUSPICIOUS : MAX_TXT_RATIO;
                double txtRatio = (double)Interlocked.Read(ref profile.TxtQueries) / total;
                
                if (txtRatio > activeTxtRatio)
                {
                    PenalizeKarma(profile, 2);
                    return PreProcessorAction.TruncateToTcp;
                }

                double activeNxRatio = tier == ClientTier.Suspicious ? MAX_NX_RATIO_SUSPICIOUS : MAX_NX_RATIO;
                double nxRatio = (double)Interlocked.Read(ref profile.NxDomainResponses) / total;
                
                if (nxRatio > activeNxRatio)
                {
                    PenalizeKarma(profile, 5);
                }
            }

            if (tier != ClientTier.Trusted && recordType != "ANY")
            {
                string root = GetRootDomain(domain);
                string host = domain.EndsWith(root, StringComparison.OrdinalIgnoreCase)
                    ? domain.Substring(0, domain.Length - root.Length).TrimEnd('.')
                    : domain;

                double entropy = CalculateEntropy(host);
                double avgEntropy = 0;

                lock (profile.EntropyLock)
                {
                    profile.EntropyBuffer[profile.EntropyIndex] = entropy;
                    profile.EntropyIndex = (profile.EntropyIndex + 1) % ENTROPY_BUFFER_SIZE;
                    if (profile.EntropyCount < ENTROPY_BUFFER_SIZE) profile.EntropyCount++;

                    double sum = 0;
                    for (int i = 0; i < profile.EntropyCount; i++) sum += profile.EntropyBuffer[i];
                    avgEntropy = sum / profile.EntropyCount;
                }

                if (profile.EntropyCount >= 10)
                {
                    double activeEntropyThreshold = tier == ClientTier.Suspicious ? ENTROPY_THRESHOLD_SUSPICIOUS : ENTROPY_THRESHOLD_NORMAL;
                    
                    if (avgEntropy > ENTROPY_THRESHOLD_TCP) return PreProcessorAction.TruncateToTcp;
                    if (avgEntropy > activeEntropyThreshold) PenalizeKarma(profile, 3);
                }
            }

            return PreProcessorAction.Allow;
        }

        private ClientTier GetTier(long karma)
        {
            if (karma >= 800) return ClientTier.Trusted;
            if (karma >= 400) return ClientTier.Normal;
            if (karma >= 100) return ClientTier.Suspicious;
            return ClientTier.Restricted;
        }

        private bool IsInBurst(ClientProfile p, long now)
        {
            long start = Interlocked.Read(ref p.LastBurstWindowStart);

            if (now - start > BURST_WINDOW_TICKS)
            {
                if (Interlocked.CompareExchange(ref p.LastBurstWindowStart, now, start) == start)
                {
                    Interlocked.Exchange(ref p.BurstWindowQueries, 1);
                    return false;
                }
            }

            long queries = Interlocked.Increment(ref p.BurstWindowQueries);
            return queries > BURST_MAX_QUERIES;
        }

        private double CalculateEntropy(string hostname)
        {
            if (string.IsNullOrEmpty(hostname)) return 0.0;

            Span<int> counts = stackalloc int[256];
            int validChars = 0;

            for (int i = 0; i < hostname.Length; i++)
            {
                char c = hostname[i];
                if (c < 256)
                {
                    counts[c]++;
                    validChars++;
                }
            }

            if (validChars == 0) return 0.0;

            double entropy = 0.0;
            for (int i = 0; i < 256; i++)
            {
                if (counts[i] > 0)
                {
                    double p = (double)counts[i] / validChars;
                    entropy -= p * Math.Log2(p);
                }
            }

            return entropy;
        }

        private bool ConsumeToken(ClientProfile p, long now, ClientTier tier)
        {
            lock (p)
            {
                long lastRefill = p.LastRefillTicks;
                double secondsPassed = TimeSpan.FromTicks(now - lastRefill).TotalSeconds;

                long currentKarma = Interlocked.Read(ref p.Karma);
                
                double multiplier = tier == ClientTier.Trusted ? 2.0 : (tier == ClientTier.Restricted ? 0.5 : 1.0);
                double maxTokens = (BASE_TOKENS_MAX + currentKarma) * multiplier;
                double refillRate = (BASE_TOKENS_PER_SEC + (currentKarma / 10.0)) * multiplier;

                if (secondsPassed >= 0.1)
                {
                    double added = secondsPassed * refillRate;
                    p.Tokens = Math.Min(maxTokens, p.Tokens + added);
                    p.LastRefillTicks = now;
                }

                if (p.Tokens < 1.0) return false;

                p.Tokens -= 1.0;
                return true;
            }
        }

        public void ReportSuccessfulQuery(IPAddress clientIp)
        {
            IPAddress effectiveIp = GetEffectiveIp(clientIp);
            if (!_profiles.TryGetValue(effectiveIp, out var profile)) return;

            long k = Interlocked.Read(ref profile.Karma);
            if (k < 1000)
            {
                Interlocked.Increment(ref profile.Karma);
            }
        }

        public void ReportNxDomain(IPAddress clientIp, string fullDomain)
        {
            IPAddress effectiveIp = GetEffectiveIp(clientIp);
            if (!_profiles.TryGetValue(effectiveIp, out var profile)) return;

            Interlocked.Increment(ref profile.NxDomainResponses);
            PenalizeKarma(profile, 2);

            string root = GetRootDomain(fullDomain);
            long now = DateTime.UtcNow.Ticks;

            profile.DomainNxStrikes.AddOrUpdate(root,
                _ => (1, now),
                (_, val) => (val.Strikes + 1, now)
            );

            if (profile.DomainNxStrikes.TryGetValue(root, out var data) && data.Strikes > MAX_DOMAIN_NX_STRIKES)
            {
                ApplyBan(profile, 10);
            }
        }

        public void ReportBadConnection(IPAddress clientIp, int penalty = 20)
        {
            IPAddress effectiveIp = GetEffectiveIp(clientIp);
            if (!_profiles.TryGetValue(effectiveIp, out var profile)) return;
            PenalizeKarma(profile, penalty);
        }

        private void PenalizeKarma(ClientProfile p, long penalty)
        {
            long currentKarma;
            long newKarma;
            do
            {
                currentKarma = Interlocked.Read(ref p.Karma);
                newKarma = Math.Max(0, currentKarma - penalty);

                if (newKarma == 0)
                {
                    ApplyBan(p, 5);
                    break;
                }
            } while (Interlocked.CompareExchange(ref p.Karma, newKarma, currentKarma) != currentKarma);
        }

        private void ApplyBan(ClientProfile p, int baseDurationMinutes)
        {
            long count = Interlocked.Increment(ref p.BanCount);
            
            double multiplier = Math.Pow(2, count - 1);
            int duration = (int)(baseDurationMinutes * multiplier);

            if (duration > BAN_MAX_MINUTES) duration = BAN_MAX_MINUTES;

            long newBanEndTicks = DateTime.UtcNow.AddMinutes(duration).Ticks;
            long currentBan;
            do
            {
                currentBan = Interlocked.Read(ref p.BanUntilTicks);
                if (newBanEndTicks <= currentBan) return; 
            } while (Interlocked.CompareExchange(ref p.BanUntilTicks, newBanEndTicks, currentBan) != currentBan);
            
            Interlocked.Exchange(ref p.ExpirationTicks, newBanEndTicks + TimeSpan.FromHours(1).Ticks);
        }

        public void ResetReputation(IPAddress clientIp)
        {
            IPAddress effectiveIp = GetEffectiveIp(clientIp);
            if (_profiles.TryGetValue(effectiveIp, out var profile))
            {
                ResetProfile(profile);
                Interlocked.Exchange(ref profile.BanCount, 0);
            }
        }

        private void ResetProfile(ClientProfile p)
        {
            Interlocked.Exchange(ref p.IsVerified, 0);
            Interlocked.Exchange(ref p.BanUntilTicks, 0);
            Interlocked.Exchange(ref p.TotalQueries, 0);
            Interlocked.Exchange(ref p.TxtQueries, 0);
            Interlocked.Exchange(ref p.NxDomainResponses, 0);
            Interlocked.Exchange(ref p.Karma, 100);
            p.DomainNxStrikes.Clear();

            lock (p)
            {
                p.Tokens = BASE_TOKENS_MAX + 100;
                p.LastRefillTicks = DateTime.UtcNow.Ticks;
            }
        }

        private IPAddress GetEffectiveIp(IPAddress ip)
        {
            if (ip.AddressFamily != AddressFamily.InterNetworkV6) return ip;
            byte[] bytes = ip.GetAddressBytes();
            for (int i = 8; i < 16; i++) bytes[i] = 0; 
            return new IPAddress(bytes);
        }

        private string GetRootDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain)) return "unknown";
            var parts = domain.TrimEnd('.').Split('.');
            if (parts.Length <= 2) return domain;

            string tld = parts[parts.Length - 1];
            string sld = parts[parts.Length - 2];

            if (tld.Length == 2 && (sld == "co" || sld == "com" || sld == "net" || sld == "org" || sld == "gov" || sld == "edu"))
            {
                if (parts.Length >= 3) return $"{parts[parts.Length - 3]}.{sld}.{tld}";
            }

            return $"{sld}.{tld}";
        }

        private void CleanUp()
        {
            long now = DateTime.UtcNow.Ticks;
            long strikeDecayTime = DateTime.UtcNow.AddHours(-1).Ticks;

            foreach (var key in _profiles.Keys)
            {
                if (_profiles.TryGetValue(key, out var p))
                {
                    if (now > Interlocked.Read(ref p.ExpirationTicks))
                    {
                        _profiles.TryRemove(key, out _);
                        continue;
                    }

                    var oldStrikes = p.DomainNxStrikes.Where(kv => kv.Value.LastStrikeTicks < strikeDecayTime).Select(kv => kv.Key).ToList();
                    foreach (var strikeKey in oldStrikes)
                    {
                        p.DomainNxStrikes.TryRemove(strikeKey, out _);
                    }
                }
            }

            if (_profiles.Count > MAX_TRACKED_PROFILES)
            {
                var toRemove = _profiles
                    .OrderBy(kv => Interlocked.Read(ref kv.Value.LastSeenTicks))
                    .Take(_profiles.Count / 5)
                    .Select(kv => kv.Key);

                foreach (var key in toRemove) _profiles.TryRemove(key, out _);
            }
        }

        public void Dispose()
        {
            _cts.Cancel();
            _cts.Dispose();
        }
    }
}