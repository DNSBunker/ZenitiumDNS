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

using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumDns.ApplicationCommon;
using ZenitiumDns.Core.Auth;
using ZenitiumDns.Core.Dhcp;
using ZenitiumDns.Core.Dns;
using ZenitiumDns.Core.Dns.Applications;
using ZenitiumDns.Core.Dns.ZoneManagers;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core
{
    public partial class DnsWebService
    {
        sealed class WebServiceSelfTestApi
        {
            #region variables

            const int CACHE_SECONDS = 60;
            const int CERTIFICATE_WARNING_DAYS = 14;

            readonly DnsWebService _dnsWebService;
            readonly SemaphoreSlim _runLock = new SemaphoreSlim(1, 1);

            IReadOnlyList<SelfTestResult> _lastResults;
            DateTime _lastRunOn;
            double _lastDuration;
            string _lastLanguage;

            #endregion

            #region constructor

            public WebServiceSelfTestApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

            [DllImport("libc", EntryPoint = "adjtimex", SetLastError = true)]
            static extern int Adjtimex(byte[] timex);

            private static string FormatSize(long bytes)
            {
                if (bytes >= 1024L * 1024 * 1024)
                    return (bytes / (1024.0 * 1024 * 1024)).ToString("0.0", Lang.Culture) + " GB";

                return (bytes / (1024.0 * 1024)).ToString("0", Lang.Culture) + " MB";
            }

            private static string FormatDate(DateTime date)
            {
                return date.ToLocalTime().ToString(Lang.T("dd.MM.yyyy HH:mm", "yyyy-MM-dd HH:mm"), CultureInfo.InvariantCulture);
            }

            private static long ReadProcLong(string path)
            {
                string value = File.ReadAllText(path).Trim();
                return long.Parse(value, CultureInfo.InvariantCulture);
            }

            private static DriveInfo FindDrive(string path)
            {
                string fullPath = Path.GetFullPath(path);
                DriveInfo bestDrive = null;

                foreach (DriveInfo drive in DriveInfo.GetDrives())
                {
                    string root = drive.RootDirectory.FullName;

                    if (!fullPath.StartsWith(root, StringComparison.Ordinal))
                        continue;

                    if ((root.Length > 1) && (fullPath.Length > root.Length) && (fullPath[root.Length] != Path.DirectorySeparatorChar) && !root.EndsWith(Path.DirectorySeparatorChar))
                        continue;

                    if ((bestDrive is null) || (root.Length > bestDrive.RootDirectory.FullName.Length))
                        bestDrive = drive;
                }

                return bestDrive;
            }

            private static bool IsWritable(string folder)
            {
                string testFile = Path.Combine(folder, ".selftest-" + Guid.NewGuid().ToString("N"));

                try
                {
                    File.WriteAllBytes(testFile, []);
                    File.Delete(testFile);
                    return true;
                }
                catch
                {
                    return false;
                }
            }

            private static string FormatNumber(long value)
            {
                return value.ToString("N0", Lang.Culture);
            }

            private static string FormatRemainingDays(TimeSpan remaining)
            {
                int days = (int)Math.Floor(remaining.TotalDays);

                if (days < 1)
                    return Lang.T("in weniger als einem Tag", "in less than a day");

                if (days == 1)
                    return Lang.T("in einem Tag", "in one day");

                return Lang.T("in " + days + " Tagen", "in " + days + " days");
            }

            private static void CheckCertificate(List<SelfTestResult> results, string group, string name, X509Certificate2 certificate, string expectedHostname, string section)
            {
                DateTime now = DateTime.UtcNow;
                string validity = name + Lang.T(": Gültigkeit", ": validity");
                DateTime notAfter = certificate.NotAfter.ToUniversalTime();

                if (notAfter <= now)
                    results.Add(new SelfTestResult(group, validity, SelfTestStatus.Error, Lang.T("Das Zertifikat ist am " + FormatDate(notAfter) + " abgelaufen. Clients bauen keine verschlüsselten Verbindungen mehr auf.", "The certificate expired on " + FormatDate(notAfter) + ". Clients no longer establish encrypted connections."), section));
                else if (certificate.NotBefore.ToUniversalTime() > now)
                    results.Add(new SelfTestResult(group, validity, SelfTestStatus.Error, Lang.T("Das Zertifikat gilt erst ab " + FormatDate(certificate.NotBefore) + ". Systemzeit prüfen.", "The certificate is only valid from " + FormatDate(certificate.NotBefore) + ". Check the system time."), section));
                else if ((notAfter - now).TotalDays < CERTIFICATE_WARNING_DAYS)
                    results.Add(new SelfTestResult(group, validity, SelfTestStatus.Warning, Lang.T("Das Zertifikat läuft am " + FormatDate(notAfter) + " ab, " + FormatRemainingDays(notAfter - now) + ". Die automatische Erneuerung prüfen.", "The certificate expires on " + FormatDate(notAfter) + ", " + FormatRemainingDays(notAfter - now) + ". Check the automatic renewal."), section));
                else
                    results.Add(new SelfTestResult(group, validity, SelfTestStatus.Ok, Lang.T("Gültig bis " + FormatDate(notAfter) + ".", "Valid until " + FormatDate(notAfter) + "."), section));

                if (!string.IsNullOrEmpty(expectedHostname))
                {
                    bool matches;

                    try
                    {
                        matches = certificate.MatchesHostname(expectedHostname);
                    }
                    catch
                    {
                        matches = false;
                    }

                    if (matches)
                        results.Add(new SelfTestResult(group, name + Lang.T(": Name", ": name"), SelfTestStatus.Ok, Lang.T("Das Zertifikat gilt für " + expectedHostname + ".", "The certificate is valid for " + expectedHostname + "."), section));
                    else
                        results.Add(new SelfTestResult(group, name + Lang.T(": Name", ": name"), SelfTestStatus.Warning, Lang.T("Das Zertifikat gilt nicht für den Serverdomainnamen " + expectedHostname + ". Clients, die diesen Namen verwenden, lehnen die Verbindung ab.", "The certificate is not valid for the server domain name " + expectedHostname + ". Clients using this name reject the connection."), section));
                }
            }

            private static void AddStrictLimit(List<string> strictLimits, string prefix, int minimum, (int, int) limit)
            {
                (int udpLimit, int tcpLimit) = limit;

                if ((udpLimit > 0) && (udpLimit < minimum))
                    strictLimits.Add(prefix + " UDP " + udpLimit + " QPS");

                if ((tcpLimit > 0) && (tcpLimit < minimum))
                    strictLimits.Add(prefix + " TCP " + tcpLimit + " QPS");
            }

            private void CheckServices(List<SelfTestResult> results)
            {
                string group = Lang.T("Dienste", "Services");
                DnsServer dnsServer = _dnsWebService._dnsServer;

                List<string> inactive = new List<string>();
                int active = 0;

                foreach ((string name, bool isActive) in dnsServer.GetListenerStatus())
                {
                    if (isActive)
                        active++;
                    else
                        inactive.Add(name);
                }

                if (inactive.Count > 0)
                    results.Add(new SelfTestResult(group, Lang.T("Lauschende Sockets", "Listening sockets"), SelfTestStatus.Error, Lang.T("Nicht aktiv: " + string.Join(", ", inactive) + ". Meist belegt ein anderer Dienst den Port, etwa systemd-resolved, dnsmasq oder unbound. Das Log nennt die genaue Ursache.", "Not active: " + string.Join(", ", inactive) + ". Usually another service occupies the port, such as systemd-resolved, dnsmasq or unbound. The log names the exact cause."), "settings:Network"));
                else
                    results.Add(new SelfTestResult(group, Lang.T("Lauschende Sockets", "Listening sockets"), SelfTestStatus.Ok, Lang.T(active + " Dienste lauschen wie konfiguriert.", active + " services are listening as configured."), "settings:Network"));

                if ((dnsServer.EnableDnsOverTls || dnsServer.EnableDnsOverHttps || dnsServer.EnableDnsOverQuic) && (dnsServer.DnsTlsCertificate is null))
                    results.Add(new SelfTestResult(group, Lang.T("Verschlüsselte Protokolle", "Encrypted protocols"), SelfTestStatus.Error, Lang.T("DoT, DoH oder DoQ ist aktiviert, aber es ist kein TLS-Zertifikat geladen. Diese Dienste bleiben deshalb aus.", "DoT, DoH or DoQ is enabled, but no TLS certificate is loaded. These services therefore stay off."), "settings:OptionalProtocols"));

                bool hasEncryptedService = (dnsServer.DnsTlsCertificate is not null) && (dnsServer.EnableDnsOverTls || dnsServer.EnableDnsOverHttps || dnsServer.EnableDnsOverQuic);

                switch (dnsServer.Do53Mode)
                {
                    case DnsServerDo53Mode.DdrOnlyDrop:
                    case DnsServerDo53Mode.DdrOnlyRefused:
                        if (dnsServer.GetDdrRecords().Count == 0)
                            results.Add(new SelfTestResult(group, "Do53", SelfTestStatus.Error, Lang.T("Do53 beantwortet nur DDR, es gibt aber keine DDR-Einträge, weil kein TLS-Zertifikat geladen oder kein verschlüsselter Dienst aktiv ist. Clients erhalten über Port 53 damit gar keine Antworten.", "Do53 only answers DDR, but there are no DDR records because no TLS certificate is loaded or no encrypted service is active. Clients therefore get no answers at all over port 53."), "settings:OptionalProtocols"));
                        else
                            results.Add(new SelfTestResult(group, "Do53", SelfTestStatus.Info, Lang.T("Do53 beantwortet nur DDR, andere Anfragen werden " + (dnsServer.Do53Mode == DnsServerDo53Mode.DdrOnlyDrop ? "verworfen" : "mit REFUSED abgelehnt") + ". Clients ohne DDR-Unterstützung können den Resolver nur verschlüsselt nutzen.", "Do53 only answers DDR, other queries are " + (dnsServer.Do53Mode == DnsServerDo53Mode.DdrOnlyDrop ? "dropped" : "rejected with REFUSED") + ". Clients without DDR support can only use the resolver encrypted."), "settings:OptionalProtocols"));

                        break;

                    case DnsServerDo53Mode.Disabled:
                        if (!hasEncryptedService && !dnsServer.EnableDnsOverHttp && !dnsServer.EnableDnsOverUdpProxy && !dnsServer.EnableDnsOverTcpProxy)
                            results.Add(new SelfTestResult(group, "Do53", SelfTestStatus.Error, Lang.T("Do53 ist deaktiviert und kein anderer Dienst ist aktiv. Der Resolver ist von außen nicht erreichbar.", "Do53 is disabled and no other service is active. The resolver cannot be reached from outside."), "settings:OptionalProtocols"));
                        else
                            results.Add(new SelfTestResult(group, "Do53", SelfTestStatus.Info, Lang.T("Do53 ist deaktiviert, Port 53 wird nicht geöffnet.", "Do53 is disabled, port 53 is not opened."), "settings:OptionalProtocols"));

                        break;
                }

                if (hasEncryptedService || dnsServer.EnableDnsOverHttp)
                {
                    switch (dnsServer.EDnsPaddingMode)
                    {
                        case DnsServerEDnsPaddingMode.Disabled:
                            results.Add(new SelfTestResult(group, Lang.T("EDNS-Padding", "EDNS padding"), SelfTestStatus.Warning, Lang.T("Padding ist ausgeschaltet. Aus der Größe verschlüsselter Antworten lässt sich dann teilweise ablesen, welche Domain abgefragt wurde.", "Padding is turned off. The size of encrypted responses can then partly reveal which domain was queried."), "settings:OptionalProtocols"));
                            break;

                        case DnsServerEDnsPaddingMode.Always:
                            results.Add(new SelfTestResult(group, Lang.T("EDNS-Padding", "EDNS padding"), SelfTestStatus.Ok, Lang.T("Verschlüsselte Antworten werden immer auf 468 Byte aufgefüllt.", "Encrypted responses are always padded to 468 bytes."), "settings:OptionalProtocols"));
                            break;

                        default:
                            results.Add(new SelfTestResult(group, Lang.T("EDNS-Padding", "EDNS padding"), SelfTestStatus.Ok, Lang.T("Verschlüsselte Antworten werden auf 468 Byte aufgefüllt, wenn der Client Padding sendet.", "Encrypted responses are padded to 468 bytes when the client sends padding."), "settings:OptionalProtocols"));
                            break;
                    }
                }

                if (dnsServer.EnableDnsOverQuic && !System.Net.Quic.QuicListener.IsSupported)
                    results.Add(new SelfTestResult(group, "DNS-over-QUIC", SelfTestStatus.Warning, Lang.T("DoQ ist aktiviert, aber libmsquic ist nicht installiert.", "DoQ is enabled, but libmsquic is not installed."), "settings:OptionalProtocols"));

                if (dnsServer.EnableDnsOverHttp && ((dnsServer.DnsReverseProxyNetworkACL is null) || (dnsServer.DnsReverseProxyNetworkACL.Count == 0)))
                    results.Add(new SelfTestResult(group, "DNS-over-HTTP", SelfTestStatus.Warning, Lang.T("DNS-over-HTTP ohne TLS ist aktiv, aber es sind keine erlaubten Reverse Proxys eingetragen.", "DNS-over-HTTP without TLS is active, but no allowed reverse proxies are configured."), "settings:OptionalProtocols"));
            }

            private async Task CheckResolutionAsync(List<SelfTestResult> results)
            {
                string group = Lang.T("Auflösung", "Resolution");
                DnsServer dnsServer = _dnsWebService._dnsServer;

                DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("", DnsResourceRecordType.NS, DnsClass.IN)], null, null, null, DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, EDnsHeaderFlags.DNSSEC_OK);

                Stopwatch stopwatch = Stopwatch.StartNew();
                DnsDatagram response = null;
                string error = null;

                try
                {
                    response = await dnsServer.DirectQueryAsync(request, 8000);
                }
                catch (Exception ex)
                {
                    error = ex.Message;
                }

                stopwatch.Stop();

                string via = ((dnsServer.Forwarders is not null) && (dnsServer.Forwarders.Count > 0)) ? Lang.T("über die Forwarder", "via the forwarders") : (dnsServer.IanaDataManager.GetZoneState(IanaDataItem.RootZone).Active ? Lang.T("mit der lokalen Kopie der Root-Zone", "with the local copy of the root zone") : Lang.T("über die Root-Server", "via the root servers"));

                if ((response is null) || (response.RCODE != DnsResponseCode.NoError) || (response.Answer.Count == 0))
                {
                    string detail = error ?? ((response is null) ? Lang.T("keine Antwort", "no response") : response.RCODE.ToString());
                    results.Add(new SelfTestResult(group, Lang.T("Rekursive Auflösung", "Recursive resolution"), SelfTestStatus.Error, Lang.T("Die Root-Zone lässt sich " + via + " nicht auflösen (" + detail + "). Ausgehende Verbindungen auf Port 53 und die Forwarder prüfen.", "The root zone cannot be resolved " + via + " (" + detail + "). Check outgoing connections on port 53 and the forwarders."), "settings:ProxyForwarders"));
                    return;
                }

                results.Add(new SelfTestResult(group, Lang.T("Rekursive Auflösung", "Recursive resolution"), SelfTestStatus.Ok, Lang.T("Die Root-Zone wurde " + via + " in " + stopwatch.ElapsedMilliseconds + " ms aufgelöst.", "The root zone was resolved " + via + " in " + stopwatch.ElapsedMilliseconds + " ms."), "settings:ProxyForwarders"));

                if (!dnsServer.DnssecValidation)
                    results.Add(new SelfTestResult(group, Lang.T("DNSSEC-Validierung", "DNSSEC validation"), SelfTestStatus.Warning, Lang.T("Die DNSSEC-Validierung ist ausgeschaltet. Clients erhalten keine geprüften Antworten und keine Signaturen.", "DNSSEC validation is turned off. Clients receive no validated answers and no signatures."), "settings:Recursion"));
                else if (response.AuthenticData)
                    results.Add(new SelfTestResult(group, Lang.T("DNSSEC-Validierung", "DNSSEC validation"), SelfTestStatus.Ok, Lang.T("Die signierte Root-Zone wurde erfolgreich validiert.", "The signed root zone was validated successfully."), "settings:Recursion"));
                else
                    results.Add(new SelfTestResult(group, Lang.T("DNSSEC-Validierung", "DNSSEC validation"), SelfTestStatus.Error, Lang.T("Die DNSSEC-Validierung ist eingeschaltet, die Antwort für die Root-Zone ist aber nicht als validiert markiert. Systemzeit und Trust Anchor prüfen.", "DNSSEC validation is turned on, but the answer for the root zone is not marked as validated. Check the system time and the trust anchor."), "settings:Recursion"));

                if (dnsServer.IPv6Mode != IPv6Mode.Disabled)
                {
                    if (IPv6Reachability.IsUnavailable && (dnsServer.IPv6Mode == IPv6Mode.Preferred))
                        results.Add(new SelfTestResult(group, "IPv6", SelfTestStatus.Warning, Lang.T("IPv6 ist auf „Bevorzugen“ gestellt, IPv6-Nameserver sind aber nicht erreichbar. Nach jedem Neustart laufen die ersten Anfragen deshalb in Zeitüberschreitungen, bis der automatische Rückfall greift. Unter Einstellungen > Netzwerk auf „Aktivieren“ oder „Deaktivieren“ stellen.", "IPv6 is set to \"Prefer\", but IPv6 name servers are unreachable. After every restart the first queries therefore run into timeouts until the automatic fallback kicks in. Set it to \"Enable\" or \"Disable\" under Settings > Network."), "settings:Network"));
                    else if (IPv6Reachability.IsUnavailable)
                        results.Add(new SelfTestResult(group, "IPv6", SelfTestStatus.Info, Lang.T("IPv6 ist aktiviert, ausgehende IPv6-Anfragen sind aber gerade ausgesetzt, weil IPv6-Nameserver nicht erreichbar waren.", "IPv6 is enabled, but outgoing IPv6 queries are currently suspended because IPv6 name servers were unreachable."), "settings:Network"));
                    else
                        results.Add(new SelfTestResult(group, "IPv6", SelfTestStatus.Ok, Lang.T("Ausgehende Anfragen über IPv6 sind aktiv.", "Outgoing queries over IPv6 are active."), "settings:Network"));
                }

                List<string> protections = new List<string>();

                if (!dnsServer.EnableDnsCookies)
                    protections.Add(Lang.T("DNS-Cookies", "DNS cookies"));

                if (!dnsServer.RandomizeName)
                    protections.Add(Lang.T("zufällige Groß-/Kleinschreibung (0x20)", "random letter case (0x20)"));

                if (protections.Count > 0)
                    results.Add(new SelfTestResult(group, Lang.T("Schutz vor gefälschten Antworten", "Protection against forged answers"), SelfTestStatus.Info, Lang.T("Ausgeschaltet: " + string.Join(", ", protections) + ". Beide erschweren es Angreifern, gefälschte Antworten in den Cache zu bringen.", "Turned off: " + string.Join(", ", protections) + ". Both make it harder for attackers to inject forged answers into the cache."), "settings:Recursion"));
                else
                    results.Add(new SelfTestResult(group, Lang.T("Schutz vor gefälschten Antworten", "Protection against forged answers"), SelfTestStatus.Ok, Lang.T("DNS-Cookies und zufällige Groß-/Kleinschreibung (0x20) sind aktiv.", "DNS cookies and random letter case (0x20) are active."), "settings:Recursion"));

                if (!dnsServer.QnameMinimization && ((dnsServer.Forwarders is null) || (dnsServer.Forwarders.Count == 0)))
                    results.Add(new SelfTestResult(group, Lang.T("QNAME-Minimierung", "QNAME minimization"), SelfTestStatus.Info, Lang.T("Die QNAME-Minimierung ist ausgeschaltet. Root- und TLD-Server sehen dann den vollständigen abgefragten Namen.", "QNAME minimization is turned off. Root and TLD servers then see the full queried name."), "settings:Recursion"));
            }

            private void CheckCache(List<SelfTestResult> results)
            {
                const string group = "Cache";
                DnsServer dnsServer = _dnsWebService._dnsServer;
                CacheZoneManager cache = dnsServer.CacheZoneManager;

                if (!dnsServer.EnableCache)
                {
                    if ((dnsServer.Forwarders is not null) && (dnsServer.Forwarders.Count > 0))
                        results.Add(new SelfTestResult(group, Lang.T("Status", "Status"), SelfTestStatus.Info, Lang.T("Der Cache ist ausgeschaltet. Jede Anfrage geht an die Forwarder, die dann selbst cachen sollten (etwa Unbound)." + (dnsServer.DnssecValidation ? " Die DNSSEC-Validierung fragt ohne Cache bei jeder Auflösung die Schlüssel der Zonen erneut ab." : ""), "The cache is turned off. Every query goes to the forwarders, which should cache themselves (for example Unbound)." + (dnsServer.DnssecValidation ? " Without a cache, DNSSEC validation fetches the keys of the zones again for every resolution." : "")), "settings:Cache"));
                    else
                        results.Add(new SelfTestResult(group, Lang.T("Status", "Status"), SelfTestStatus.Warning, Lang.T("Der Cache ist ausgeschaltet, aber es sind keine Forwarder eingetragen. Jede Anfrage wird ab den Root-Servern aufgelöst, das ist langsam und belastet die Nameserver. Forwarder mit eigenem Cache eintragen (etwa Unbound) oder den Cache einschalten.", "The cache is turned off, but no forwarders are configured. Every query is resolved starting at the root servers, which is slow and loads the name servers. Configure forwarders with their own cache (for example Unbound) or turn the cache on."), "settings:Cache"));

                    return;
                }

                long entries = cache.TotalEntries;
                long maximumEntries = cache.MaximumEntries;
                int maximumMemory = cache.MaximumMemoryMegabytes;

                if ((maximumEntries == 0) && (maximumMemory == 0))
                {
                    results.Add(new SelfTestResult(group, Lang.T("Größe", "Size"), SelfTestStatus.Info, Lang.T(FormatNumber(entries) + " Einträge, weder Höchstzahl noch Speichergrenze gesetzt. Der Cache wächst, bis der Arbeitsspeicher zu 85 % belegt ist, und wird dann angehalten und bei Bedarf gekürzt; eine Speichergrenze lässt anderen Programmen mehr Platz.", FormatNumber(entries) + " entries, neither a maximum number of entries nor a memory limit is set. The cache grows until memory is 85 % full and is then held and cut when needed; a memory limit leaves more room for other programs."), "settings:Cache"));
                }
                else
                {
                    string limits = (maximumEntries > 0 ? Lang.T(" von höchstens " + FormatNumber(maximumEntries), " of at most " + FormatNumber(maximumEntries)) : "") + (maximumMemory > 0 ? Lang.T(", Speichergrenze " + FormatNumber(maximumMemory) + " MB", ", memory limit " + FormatNumber(maximumMemory) + " MB") : "");

                    results.Add(new SelfTestResult(group, Lang.T("Größe", "Size"), SelfTestStatus.Ok, Lang.T(FormatNumber(entries) + " Einträge" + limits + ".", FormatNumber(entries) + " entries" + limits + "."), "settings:Cache"));
                }

                MemoryPressureReading pressure = cache.LastMemoryPressure;
                string pressureScope = pressure.Source switch
                {
                    "cgroup" => Lang.T("Speichergrenze des Dienstes oder Containers", "memory limit of the service or container"),
                    "heap" => Lang.T("Heap-Grenze von .NET", ".NET heap limit"),
                    _ => Lang.T("Arbeitsspeicher des Systems", "system memory")
                };

                if (cache.PressureCapEntries > 0)
                    results.Add(new SelfTestResult(group, Lang.T("Speicherschutz", "Memory protection"), SelfTestStatus.Warning, Lang.T("Der Speicher ist fast voll (" + (int)(pressure.Ratio * 100) + " % der " + pressureScope + "). Der Cache wächst derzeit nicht über " + FormatNumber(cache.PressureCapEntries) + " Einträge hinaus, um einen Absturz durch Speichermangel zu verhindern. Die Grenze fällt weg, wenn der Speicher fünf Minuten lang unter 75 % liegt.", "Memory is almost full (" + (int)(pressure.Ratio * 100) + " % of the " + pressureScope + "). The cache currently does not grow beyond " + FormatNumber(cache.PressureCapEntries) + " entries to prevent an out-of-memory crash. The cap is lifted once memory stays below 75 % for five minutes."), "settings:Cache"));
                else if (pressure.Limit > 0)
                    results.Add(new SelfTestResult(group, Lang.T("Speicherschutz", "Memory protection"), SelfTestStatus.Ok, Lang.T("Aktiv, der Speicher ist zu " + (int)(pressure.Ratio * 100) + " % belegt (" + pressureScope + "). Ab 85 % hält der Server den Cache an, ab 90 % kürzt er ihn.", "Active, memory is " + (int)(pressure.Ratio * 100) + " % full (" + pressureScope + "). From 85 % the server holds the cache, from 90 % it cuts it."), "settings:Cache"));

                if (cache.PressureTrims > 0)
                    results.Add(new SelfTestResult(group, Lang.T("Speicherschutz", "Memory protection"), SelfTestStatus.Info, Lang.T("Seit dem Start wurde der Cache " + FormatNumber(cache.PressureTrims) + "-mal wegen fast vollen Speichers gekürzt, " + FormatNumber(cache.PressureTrimmedEntries) + " Einträge wurden entfernt.", "Since start, the cache was cut " + FormatNumber(cache.PressureTrims) + " times because memory was almost full, " + FormatNumber(cache.PressureTrimmedEntries) + " entries were removed."), "settings:Cache"));

                if ((maximumMemory > 0) && (cache.MemoryTrimmedEntries > cache.PressureTrimmedEntries))
                    results.Add(new SelfTestResult(group, Lang.T("Speichergrenze", "Memory limit"), SelfTestStatus.Info, Lang.T("Seit dem Start wurden wegen der Speichergrenze " + FormatNumber(cache.MemoryTrimmedEntries - cache.PressureTrimmedEntries) + " Einträge entfernt.", FormatNumber(cache.MemoryTrimmedEntries - cache.PressureTrimmedEntries) + " entries were removed because of the memory limit since start."), "settings:Cache"));
            }

            private void CheckCertificates(List<SelfTestResult> results)
            {
                string group = Lang.T("Zertifikate", "Certificates");
                DnsServer dnsServer = _dnsWebService._dnsServer;

                X509Certificate2 dnsCertificate = dnsServer.DnsTlsCertificate;

                if (dnsServer.ClientProfileManager.HasClientIds && (dnsServer.EnableDnsOverTls || dnsServer.EnableDnsOverQuic))
                {
                    IReadOnlyList<string> wildcardDomains = dnsServer.GetTlsWildcardDomains();

                    if (dnsCertificate is null)
                        results.Add(new SelfTestResult(group, "ClientID", SelfTestStatus.Warning, Lang.T("Clientprofile nutzen ClientIDs, für DNS-over-TLS und DNS-over-QUIC ist aber kein Zertifikat eingerichtet.", "Client profiles use ClientIDs, but no certificate is configured for DNS-over-TLS and DNS-over-QUIC."), "clients"));
                    else if (wildcardDomains.Count == 0)
                        results.Add(new SelfTestResult(group, "ClientID", SelfTestStatus.Warning, Lang.T("Clientprofile nutzen ClientIDs, das Zertifikat hat aber keinen Wildcard-Eintrag (*.name). DNS-over-TLS und DNS-over-QUIC erkennen die ClientID am Servernamen <id>.name, den Clients nur mit einem Wildcard-Zertifikat akzeptieren. Über DNS-over-HTTPS funktioniert die ClientID im Pfad auch ohne.", "Client profiles use ClientIDs, but the certificate has no wildcard entry (*.name). DNS-over-TLS and DNS-over-QUIC recognize the ClientID by the server name <id>.name, which clients only accept with a wildcard certificate. Over DNS-over-HTTPS the ClientID in the path works without one."), "clients"));
                    else
                        results.Add(new SelfTestResult(group, "ClientID", SelfTestStatus.Ok, Lang.T("ClientIDs über DNS-over-TLS und DNS-over-QUIC: <id>." + wildcardDomains[0] + ".", "ClientIDs over DNS-over-TLS and DNS-over-QUIC: <id>." + wildcardDomains[0] + "."), "clients"));
                }

                if (dnsCertificate is not null)
                {
                    CheckCertificate(results, group, "DoT/DoH/DoQ", dnsCertificate, dnsServer.ServerDomain, "settings:OptionalProtocols");

                    if (dnsServer.EnableDdr)
                    {
                        bool hasIpAddress = false;

                        foreach (X509Extension extension in dnsCertificate.Extensions)
                        {
                            if (extension.Oid?.Value != "2.5.29.17")
                                continue;

                            foreach (IPAddress address in new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical).EnumerateIPAddresses())
                            {
                                hasIpAddress = true;
                                break;
                            }
                        }

                        if (hasIpAddress)
                            results.Add(new SelfTestResult(group, "DDR", SelfTestStatus.Ok, Lang.T("Das Zertifikat enthält IP-Adressen, Clients können die DDR-Ankündigung prüfen.", "The certificate contains IP addresses, clients can verify the DDR announcement."), "settings:OptionalProtocols"));
                        else
                            results.Add(new SelfTestResult(group, "DDR", SelfTestStatus.Info, Lang.T("Das Zertifikat enthält keine IP-Adresse. Windows und Apple-Geräte nutzen die DDR-Ankündigung dann nicht automatisch.", "The certificate contains no IP address. Windows and Apple devices then do not use the DDR announcement automatically."), "settings:OptionalProtocols"));
                    }
                }

                X509Certificate2 webCertificate = _dnsWebService._webServiceSslServerAuthenticationOptions?.ServerCertificateContext?.TargetCertificate;
                if (_dnsWebService._webServiceEnableTls && (webCertificate is not null) && !_dnsWebService._webServiceUseSelfSignedTlsCertificate)
                    CheckCertificate(results, group, Lang.T("Weboberfläche", "Web interface"), webCertificate, null, "settings:WebService");
            }

            private void CheckSecurity(List<SelfTestResult> results)
            {
                string group = Lang.T("Sicherheit", "Security");
                DnsServer dnsServer = _dnsWebService._dnsServer;

                if (_dnsWebService._authManager.HasDefaultCredentials())
                    results.Add(new SelfTestResult(group, Lang.T("Admin-Passwort", "Admin password"), SelfTestStatus.Error, Lang.T("Der Benutzer admin hat noch das Standardpasswort admin. Sofort unter Konto ändern.", "The user admin still has the default password admin. Change it immediately under the account menu."), "password"));
                else
                    results.Add(new SelfTestResult(group, Lang.T("Admin-Passwort", "Admin password"), SelfTestStatus.Ok, Lang.T("Das Standardpasswort ist geändert.", "The default password has been changed."), "password"));

                string adminPasswordFile = _dnsWebService._authManager.GetAdminPasswordFilePath();

                if ((adminPasswordFile is not null) && File.Exists(adminPasswordFile))
                    results.Add(new SelfTestResult(group, Lang.T("Passwortdatei", "Password file"), SelfTestStatus.Warning, Lang.T("Die Datei admin.password aus der Installation enthält noch das gültige Passwort von admin. Sobald das Passwort geändert oder der Benutzer admin gelöscht oder umbenannt ist, wird sie automatisch gelöscht.", "The file admin.password from the installation still contains the valid password of admin. It is deleted automatically as soon as the password is changed or the user admin is deleted or renamed."), "password"));

                bool publicHttp = false;

                foreach (IPAddress address in _dnsWebService._webServiceLocalAddresses)
                {
                    if (!IPAddress.IsLoopback(address))
                    {
                        publicHttp = true;
                        break;
                    }
                }

                if (publicHttp && !_dnsWebService._webServiceEnableTls)
                    results.Add(new SelfTestResult(group, Lang.T("Weboberfläche", "Web interface"), SelfTestStatus.Warning, Lang.T("Die Weboberfläche ist ohne HTTPS über das Netz erreichbar. Anmeldedaten und Tokens gehen unverschlüsselt über die Leitung.", "The web interface is reachable over the network without HTTPS. Credentials and tokens travel unencrypted."), "settings:WebService"));
                else if (publicHttp && !_dnsWebService._webServiceHttpToTlsRedirect)
                    results.Add(new SelfTestResult(group, Lang.T("Weboberfläche", "Web interface"), SelfTestStatus.Info, Lang.T("HTTPS ist aktiv, HTTP auf Port " + _dnsWebService._webServiceHttpPort + " ist aber weiter ohne Umleitung erreichbar.", "HTTPS is active, but HTTP on port " + _dnsWebService._webServiceHttpPort + " is still reachable without redirect."), "settings:WebService"));
                else
                    results.Add(new SelfTestResult(group, Lang.T("Weboberfläche", "Web interface"), SelfTestStatus.Ok, publicHttp ? Lang.T("Die Weboberfläche ist nur verschlüsselt erreichbar.", "The web interface is only reachable encrypted.") : Lang.T("Die Weboberfläche lauscht nur auf Loopback.", "The web interface only listens on loopback."), "settings:WebService"));

                bool rateLimited = (dnsServer.QpsPrefixLimitsIPv4.Count > 0) || (dnsServer.QpsPrefixLimitsIPv6.Count > 0);

                switch (dnsServer.Recursion)
                {
                    case DnsServerRecursion.Allow:
                        if (rateLimited)
                            results.Add(new SelfTestResult(group, Lang.T("Rekursion", "Recursion"), SelfTestStatus.Ok, Lang.T("Öffentlicher Resolver mit Ratenbegrenzung.", "Public resolver with rate limiting."), "settings:Recursion"));
                        else
                            results.Add(new SelfTestResult(group, Lang.T("Rekursion", "Recursion"), SelfTestStatus.Error, Lang.T("Der Resolver ist für alle offen, aber die Ratenbegrenzung ist ausgeschaltet. Er kann so für Amplification-Angriffe missbraucht werden.", "The resolver is open to everyone, but rate limiting is turned off. It can thus be abused for amplification attacks."), "settings:Recursion"));

                        break;

                    case DnsServerRecursion.AllowOnlyForPrivateNetworks:
                        results.Add(new SelfTestResult(group, Lang.T("Rekursion", "Recursion"), SelfTestStatus.Info, Lang.T("Die Rekursion ist nur für private Netze erlaubt. Für den öffentlichen Betrieb unter Einstellungen > Resolver auf „Für alle erlauben“ stellen.", "Recursion is only allowed for private networks. For public operation, set it to \"Allow for everyone\" under Settings > Resolver."), "settings:Recursion"));
                        break;

                    case DnsServerRecursion.Deny:
                        results.Add(new SelfTestResult(group, Lang.T("Rekursion", "Recursion"), SelfTestStatus.Warning, Lang.T("Die Rekursion ist ausgeschaltet. Der Server beantwortet nur lokale Zonen.", "Recursion is turned off. The server only answers local zones."), "settings:Recursion"));
                        break;

                    default:
                        results.Add(new SelfTestResult(group, Lang.T("Rekursion", "Recursion"), rateLimited ? SelfTestStatus.Ok : SelfTestStatus.Warning, rateLimited ? Lang.T("Die Rekursion ist per ACL eingeschränkt.", "Recursion is restricted by ACL.") : Lang.T("Die Rekursion ist per ACL eingeschränkt, die Ratenbegrenzung ist aber ausgeschaltet.", "Recursion is restricted by ACL, but rate limiting is turned off."), "settings:Recursion"));
                        break;
                }

                if (dnsServer.Recursion != DnsServerRecursion.Allow)
                {
                    if (!rateLimited)
                        results.Add(new SelfTestResult(group, Lang.T("Ratenbegrenzung", "Rate limiting"), SelfTestStatus.Info, Lang.T("Die Ratenbegrenzung ist ausgeschaltet.", "Rate limiting is turned off."), "settings:RateLimiting"));
                    else
                        results.Add(new SelfTestResult(group, Lang.T("Ratenbegrenzung", "Rate limiting"), SelfTestStatus.Ok, Lang.T("Aktiv.", "Active."), "settings:RateLimiting"));
                }

                List<string> strictLimits = new List<string>();

                foreach (KeyValuePair<int, (int, int)> limit in dnsServer.QpsPrefixLimitsIPv4)
                    AddStrictLimit(strictLimits, "/" + limit.Key, limit.Key >= 32 ? 200 : 5000, limit.Value);

                foreach (KeyValuePair<int, (int, int)> limit in dnsServer.QpsPrefixLimitsIPv6)
                    AddStrictLimit(strictLimits, "/" + limit.Key, limit.Key >= 64 ? 200 : 2000, limit.Value);

                if (strictLimits.Count > 0)
                    results.Add(new SelfTestResult(group, Lang.T("Ratenbegrenzung", "Rate limiting"), SelfTestStatus.Warning, Lang.T("Sehr niedrige Limits: " + string.Join(", ", strictLimits) + ". Hinter einer IPv4-Adresse mit CGNAT oder einem Firmen-NAT stehen oft Hunderte Nutzer, die dann gebremst werden. Empfohlen sind 1000 UDP und 5000 TCP je /32 und /64.", "Very low limits: " + string.Join(", ", strictLimits) + ". Behind an IPv4 address with CGNAT or corporate NAT there are often hundreds of users who then get throttled. 1000 UDP and 5000 TCP per /32 and /64 are recommended."), "settings:RateLimiting"));

                if (dnsServer.RateLimitUdpTruncationPercentage < 100)
                    results.Add(new SelfTestResult(group, Lang.T("TC-Antworten", "TC responses"), SelfTestStatus.Info, Lang.T("Nur " + dnsServer.RateLimitUdpTruncationPercentage + " % der gebremsten UDP-Anfragen erhalten eine TC-Antwort. Die übrigen Clients laufen in Zeitüberschreitungen, statt auf TCP auszuweichen. 100 % ist für Clients hinter NAT am verträglichsten.", "Only " + dnsServer.RateLimitUdpTruncationPercentage + " % of throttled UDP queries receive a TC response. The remaining clients run into timeouts instead of switching to TCP. 100 % works best for clients behind NAT."), "settings:RateLimiting"));

                int disabledRules = 0;

                if (!dnsServer.RequestFilterMalformed)
                    disabledRules++;

                if (dnsServer.RequestFilterMaxSize < 1)
                    disabledRules++;

                if (!dnsServer.RequestFilterOpcode)
                    disabledRules++;

                if (!dnsServer.RequestFilterClass)
                    disabledRules++;

                if (!dnsServer.RequestFilterAny)
                    disabledRules++;

                if (!dnsServer.RequestFilterZoneTransfer)
                    disabledRules++;

                if (!dnsServer.RequestFilterNoRecursion)
                    disabledRules++;

                if (!dnsServer.RequestFilterEdnsVersion)
                    disabledRules++;

                if (disabledRules == 0)
                    results.Add(new SelfTestResult(group, Lang.T("Anfragefilter", "Request filter"), SelfTestStatus.Ok, Lang.T("Alle Regeln sind aktiv.", "All rules are active."), "settings:RequestFilter"));
                else
                    results.Add(new SelfTestResult(group, Lang.T("Anfragefilter", "Request filter"), dnsServer.Recursion == DnsServerRecursion.Allow ? SelfTestStatus.Warning : SelfTestStatus.Info, Lang.T(disabledRules + " von 8 Regeln sind ausgeschaltet.", disabledRules + " of 8 rules are turned off."), "settings:RequestFilter"));
            }

            private void CheckFilters(List<SelfTestResult> results)
            {
                const string group = "Filter";
                DnsServer dnsServer = _dnsWebService._dnsServer;
                BlockListZoneManager blockListZoneManager = dnsServer.BlockListZoneManager;
                ClientBlockListManager clientBlockListManager = dnsServer.ClientBlockListManager;

                if (clientBlockListManager.ListUrls.Count > 0)
                {
                    if (clientBlockListManager.AddressRanges == 0)
                        results.Add(new SelfTestResult(group, Lang.T("Client-Sperrlisten", "Client block lists"), SelfTestStatus.Error, Lang.T("Es sind Client-Sperrlisten eingetragen, aber keine Adresse ist geladen. Download-Fehler stehen im Log.", "Client block lists are configured, but no address is loaded. Download errors are in the log."), "settings:RequestFilter"));
                    else if ((clientBlockListManager.UpdateIntervalHours > 0) && (clientBlockListManager.LastUpdatedOn != DateTime.MinValue) && ((DateTime.UtcNow - clientBlockListManager.LastUpdatedOn).TotalHours > (clientBlockListManager.UpdateIntervalHours * 3)))
                        results.Add(new SelfTestResult(group, Lang.T("Client-Sperrlisten", "Client block lists"), SelfTestStatus.Warning, Lang.T(FormatNumber(clientBlockListManager.AddressRanges) + " Adressbereiche geladen, die letzte erfolgreiche Aktualisierung war aber am " + FormatDate(clientBlockListManager.LastUpdatedOn) + ".", FormatNumber(clientBlockListManager.AddressRanges) + " address ranges loaded, but the last successful update was on " + FormatDate(clientBlockListManager.LastUpdatedOn) + "."), "settings:RequestFilter"));
                    else
                        results.Add(new SelfTestResult(group, Lang.T("Client-Sperrlisten", "Client block lists"), SelfTestStatus.Ok, Lang.T(FormatNumber(clientBlockListManager.AddressRanges) + " Adressbereiche geladen, " + FormatNumber(clientBlockListManager.Drops) + " Anfragen oder Verbindungen seit dem Start verworfen.", FormatNumber(clientBlockListManager.AddressRanges) + " address ranges loaded, " + FormatNumber(clientBlockListManager.Drops) + " queries or connections dropped since start."), "settings:RequestFilter"));
                }

                int enabledLists = 0;
                long rules = 0;
                List<string> failedLists = new List<string>();
                List<string> staleLists = new List<string>();
                int intervalHours = blockListZoneManager.BlockListUpdateIntervalHours;
                DateTime utcNow = DateTime.UtcNow;

                foreach (BlockListZoneManager.ListInfo info in blockListZoneManager.GetListInfos())
                {
                    if (!info.Enabled)
                        continue;

                    enabledLists++;

                    BlockListZoneManager.ListStatus status = info.Status;
                    if (status is null)
                        continue;

                    string label = string.IsNullOrEmpty(info.Name) ? info.Url : info.Name;

                    rules += status.Domains + status.Exceptions + status.Regexes + status.Ips;

                    if ((status.LoadError is not null) || (status.LastResult == "failed") || (status.LastResult == "notFound"))
                        failedLists.Add(label);
                    else if ((intervalHours > 0) && (status.LastCheckedOn != default) && ((utcNow - status.LastCheckedOn).TotalHours > (intervalHours * 3)))
                        staleLists.Add(label);
                }

                static string Names(List<string> names)
                {
                    if (names.Count <= 3)
                        return string.Join(", ", names);

                    return string.Join(", ", names.GetRange(0, 3)) + Lang.T(" und " + (names.Count - 3) + " weitere", " and " + (names.Count - 3) + " more");
                }

                if (enabledLists > 0)
                {
                    if (!dnsServer.EnableBlocking)
                        results.Add(new SelfTestResult(group, Lang.T("Blocklisten", "Block lists"), SelfTestStatus.Info, Lang.T("Die Blockierung ist ausgeschaltet. " + enabledLists + " Listen sind eingetragen, werden aber nicht angewendet.", "Blocking is turned off. " + enabledLists + " lists are configured but not applied."), "filter-lists"));
                    else if ((rules == 0) && (failedLists.Count > 0))
                        results.Add(new SelfTestResult(group, Lang.T("Blocklisten", "Block lists"), SelfTestStatus.Error, Lang.T("Keine Regel geladen. Nicht verfügbar: " + Names(failedLists) + ". Die Tabelle unter Filter > Blocklisten nennt die Fehler.", "No rule loaded. Not available: " + Names(failedLists) + ". The table under Filter > Block lists shows the errors."), "filter-lists"));
                    else if (failedLists.Count > 0)
                        results.Add(new SelfTestResult(group, Lang.T("Blocklisten", "Block lists"), SelfTestStatus.Warning, Lang.T(failedLists.Count + " von " + enabledLists + " Listen ließen sich nicht abrufen oder laden: " + Names(failedLists) + ". Für sie gilt der zuletzt geladene Stand oder gar keiner.", failedLists.Count + " of " + enabledLists + " lists could not be downloaded or loaded: " + Names(failedLists) + ". For them the last loaded version applies, or none."), "filter-lists"));
                    else if (staleLists.Count > 0)
                        results.Add(new SelfTestResult(group, Lang.T("Blocklisten", "Block lists"), SelfTestStatus.Warning, Lang.T("Seit mehr als " + (intervalHours * 3) + " Stunden nicht geprüft: " + Names(staleLists) + ".", "Not checked for more than " + (intervalHours * 3) + " hours: " + Names(staleLists) + "."), "filter-lists"));
                    else
                        results.Add(new SelfTestResult(group, Lang.T("Blocklisten", "Block lists"), SelfTestStatus.Ok, Lang.T(enabledLists + " Listen mit " + FormatNumber(rules) + " Regeln geladen" + (blockListZoneManager.BlockListLastUpdatedOn == DateTime.MinValue ? "." : ", zuletzt aktualisiert am " + FormatDate(blockListZoneManager.BlockListLastUpdatedOn) + "."), enabledLists + " lists with " + FormatNumber(rules) + " rules loaded" + (blockListZoneManager.BlockListLastUpdatedOn == DateTime.MinValue ? "." : ", last updated on " + FormatDate(blockListZoneManager.BlockListLastUpdatedOn) + ".")), "filter-lists"));
                }

                int profiles = dnsServer.ClientProfileManager.Count;

                if (profiles > 0)
                    results.Add(new SelfTestResult(group, Lang.T("Clientprofile", "Client profiles"), SelfTestStatus.Ok, Lang.T(profiles + " Profile eingerichtet" + (dnsServer.EnableBlocking ? "." : ", die Blockierung ist aber ausgeschaltet."), profiles + " profiles configured" + (dnsServer.EnableBlocking ? "." : ", but blocking is turned off.")), "clients"));
            }

            private void CheckApps(List<SelfTestResult> results)
            {
                const string group = "Apps";
                DnsApplicationManager appManager = _dnsWebService._dnsServer.DnsApplicationManager;

                foreach (KeyValuePair<string, string> loadError in appManager.LoadErrors)
                    results.Add(new SelfTestResult(group, loadError.Key, SelfTestStatus.Error, Lang.T("Die App konnte nicht geladen werden: ", "The app could not be loaded: ") + loadError.Value, "apps"));

                int enabled = 0;

                foreach (KeyValuePair<string, DnsApplication> application in appManager.Applications)
                {
                    if (!application.Value.Enabled)
                        continue;

                    enabled++;

                    if (application.Value.InitializationError is not null)
                        results.Add(new SelfTestResult(group, application.Key, SelfTestStatus.Error, Lang.T("Die App meldet einen Fehler bei der Initialisierung: ", "The app reports an initialization error: ") + application.Value.InitializationError, "apps"));
                }

                if (appManager.LoadErrors.Count == 0)
                    results.Add(new SelfTestResult(group, Lang.T("Geladene Apps", "Loaded apps"), SelfTestStatus.Ok, Lang.T(appManager.Applications.Count + " installiert, " + enabled + " aktiviert.", appManager.Applications.Count + " installed, " + enabled + " enabled."), "apps"));
            }

            private void CheckIanaData(List<SelfTestResult> results)
            {
                string group = Lang.T("Root-Zone", "Root zone");
                IanaDataManager manager = _dnsWebService._dnsServer.IanaDataManager;

                foreach ((IanaDataItem item, string title) in new[] { (IanaDataItem.RootZone, Lang.T("Root-Zone", "Root zone")), (IanaDataItem.ArpaZone, Lang.T("arpa-Zone", "arpa zone")) })
                {
                    var state = manager.GetZoneState(item);

                    if (!_dnsWebService._dnsServer.EnableCache)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Info, Lang.T("Nicht genutzt, weil der Cache ausgeschaltet ist.", "Not used because the cache is turned off."), "settings:Recursion"));
                    else if (state.Mode == IanaDataMode.Disabled)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Info, Lang.T("Ausgeschaltet, der Resolver fragt die zuständigen Nameserver.", "Turned off, the resolver queries the responsible name servers."), "settings:Recursion"));
                    else if (state.Error is not null)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Warning, state.Error + (state.Active ? Lang.T(" Die zuletzt geprüfte Version ist weiter aktiv.", " The last verified version remains active.") : Lang.T(" Der Resolver fragt so lange die zuständigen Nameserver.", " Meanwhile the resolver queries the responsible name servers.")), "settings:Recursion"));
                    else if (state.Active)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Ok, Lang.T("Seriennummer " + state.Serial + ", " + FormatNumber(state.Delegations) + " Delegationen. ", "Serial " + state.Serial + ", " + FormatNumber(state.Delegations) + " delegations. ") + state.Message, "settings:Recursion"));
                    else if (state.Mode == IanaDataMode.Custom)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Warning, Lang.T("Die eigene Version wird nicht verwendet: ", "The custom version is not used: ") + state.Message, "settings:Recursion"));
                    else
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Info, Lang.T("Wird kurz nach dem Start geladen und geprüft.", "Loaded and verified shortly after start."), "settings:Recursion"));
                }

                var anchors = manager.GetTrustAnchorState();

                if (anchors.Error is not null)
                    results.Add(new SelfTestResult(group, "Root-KSK", SelfTestStatus.Warning, anchors.Error, "settings:Recursion"));
                else if (anchors.Source is not null)
                    results.Add(new SelfTestResult(group, "Root-KSK", SelfTestStatus.Ok, Lang.T("Quelle ", "Source ") + anchors.Source + ". " + anchors.Message, "settings:Recursion"));
            }

            private void CheckDhcp(List<SelfTestResult> results)
            {
                DhcpServer dhcpServer = _dnsWebService._dhcpServer;

                if (dhcpServer is null)
                    return;

                DhcpSettings settings = dhcpServer.Settings;

                if (!settings.Enabled)
                    return;

                string group = "DHCP";

                IReadOnlyList<DhcpConfigError> configErrors = dhcpServer.ConfigErrors;
                if (configErrors.Count > 0)
                {
                    DhcpConfigError first = configErrors[0];
                    string where = first.Line > 0 ? Lang.T("Zeile " + first.Line + ": ", "line " + first.Line + ": ") : "";
                    results.Add(new SelfTestResult(group, Lang.T("Konfiguration", "Configuration"), SelfTestStatus.Error, Lang.T("Die Konfiguration enthält " + configErrors.Count + " Fehler, der DHCP-Server vergibt deshalb keine Adressen. Erster Fehler, " + where + first.Message, "The configuration contains " + configErrors.Count + " error(s), so the DHCP server hands out no addresses. First error, " + where + first.Message), "dhcp"));
                }

                if (settings.Enabled)
                {
                    List<DhcpListenerStatus> listeners = dhcpServer.GetListenerStatus();
                    List<string> failed = new List<string>();
                    List<string> listening = new List<string>();

                    foreach (DhcpListenerStatus listener in listeners)
                    {
                        if (!string.IsNullOrEmpty(listener.Error))
                            failed.Add(listener.Interface + " (" + listener.Error + ")");
                        else if (listener.Listening)
                            listening.Add(listener.Interface + ((listener.Addresses is not null) && (listener.Addresses.Count > 0) ? " " + string.Join(", ", listener.Addresses) : ""));
                    }

                    if (failed.Count > 0)
                        results.Add(new SelfTestResult(group, Lang.T("Schnittstellen", "Interfaces"), SelfTestStatus.Error, Lang.T("Kein Empfang auf: " + string.Join("; ", failed) + ". Meist belegt ein anderer DHCP-Server Port 67 oder die Schnittstelle hat keine IPv4-Adresse.", "Not receiving on: " + string.Join("; ", failed) + ". Usually another DHCP server occupies port 67 or the interface has no IPv4 address."), "dhcp"));
                    else if (listening.Count == 0)
                        results.Add(new SelfTestResult(group, Lang.T("Schnittstellen", "Interfaces"), SelfTestStatus.Error, Lang.T("Der DHCP-Server lauscht auf keiner Schnittstelle. Eine Schnittstelle mit IPv4-Adresse auswählen, die zu einem Adressbereich passt.", "The DHCP server is not listening on any interface. Select an interface with an IPv4 address that matches an address range."), "dhcp"));
                    else
                        results.Add(new SelfTestResult(group, Lang.T("Schnittstellen", "Interfaces"), SelfTestStatus.Ok, Lang.T("Empfang auf " + string.Join("; ", listening) + ".", "Receiving on " + string.Join("; ", listening) + "."), "dhcp"));

                    if (!string.IsNullOrEmpty(dhcpServer.RawSenderError))
                        results.Add(new SelfTestResult(group, Lang.T("Direkte Antworten", "Direct replies"), SelfTestStatus.Info, Lang.T("Antworten an Clients, die noch keine Adresse haben, gehen per Broadcast, weil kein Raw-Socket geöffnet werden kann (" + dhcpServer.RawSenderError + "). Das funktioniert, belastet aber alle Geräte im Netz. Dafür braucht der Dienst CAP_NET_RAW.", "Replies to clients without an address are broadcast because no raw socket can be opened (" + dhcpServer.RawSenderError + "). This works but reaches every device in the network. The service needs CAP_NET_RAW for direct replies."), "dhcp"));

                    int foreignWindowSeconds = Math.Max(900, settings.RogueProbeIntervalSeconds * 3);
                    DateTime recent = DateTime.UtcNow.AddSeconds(-foreignWindowSeconds);
                    int foreignWindowMinutes = (foreignWindowSeconds + 59) / 60;
                    List<string> foreign = new List<string>();

                    foreach (DhcpForeignServer server in dhcpServer.GetForeignServers())
                    {
                        if (server.LastSeen >= recent)
                            foreign.Add(server.Address + (string.IsNullOrEmpty(server.Interface) ? "" : " (" + server.Interface + ")"));
                    }

                    if (foreign.Count > 0)
                    {
                        string list = string.Join(", ", foreign);

                        switch (settings.Priority)
                        {
                            case DhcpPriorityMode.Standby:
                                results.Add(new SelfTestResult(group, Lang.T("Andere DHCP-Server", "Other DHCP servers"), SelfTestStatus.Info, Lang.T("Im Netz antwortet ein anderer DHCP-Server: " + list + ". Wie eingestellt (Reserve) bietet ZenitiumDNS keine neuen Adressen an, bis er " + foreignWindowMinutes + " Minuten lang nicht mehr zu sehen ist.", "Another DHCP server answers in the network: " + list + ". As configured (standby), ZenitiumDNS offers no new addresses until it has not been seen for " + foreignWindowMinutes + " minutes."), "dhcp"));
                                break;

                            case DhcpPriorityMode.Delayed:
                                results.Add(new SelfTestResult(group, Lang.T("Andere DHCP-Server", "Other DHCP servers"), SelfTestStatus.Info, Lang.T("Im Netz antwortet ein anderer DHCP-Server: " + list + ". ZenitiumDNS antwortet wie eingestellt (Nachrangig) verzögert, Clients nehmen meist das schnellere Angebot des anderen Servers.", "Another DHCP server answers in the network: " + list + ". As configured (secondary), ZenitiumDNS answers with a delay, so clients usually take the faster offer of the other server."), "dhcp"));
                                break;

                            default:
                                results.Add(new SelfTestResult(group, Lang.T("Andere DHCP-Server", "Other DHCP servers"), SelfTestStatus.Warning, Lang.T("Im Netz antwortet ein anderer DHCP-Server: " + list + ". Clients nehmen das erste Angebot, Adressen und Einstellungen hängen dann vom Zufall ab. Den anderen Server abschalten oder hier die Priorität auf „Nachrangig“ oder „Reserve“ stellen.", "Another DHCP server answers in the network: " + list + ". Clients take the first offer, so addresses and settings depend on chance. Turn the other server off or set the priority here to \"Secondary\" or \"Standby\"."), "dhcp"));
                                break;
                        }
                    }
                    else if (settings.RogueDetection && string.IsNullOrEmpty(dhcpServer.LastProbeError) && (dhcpServer.LastProbe > DateTime.MinValue))
                    {
                        results.Add(new SelfTestResult(group, Lang.T("Andere DHCP-Server", "Other DHCP servers"), SelfTestStatus.Ok, Lang.T("Bei der letzten Suche um " + FormatDate(dhcpServer.LastProbe) + " hat kein anderer DHCP-Server geantwortet.", "No other DHCP server answered the last search at " + FormatDate(dhcpServer.LastProbe) + "."), "dhcp"));
                    }

                    if (settings.RogueDetection && !string.IsNullOrEmpty(dhcpServer.LastProbeError))
                        results.Add(new SelfTestResult(group, Lang.T("Suche nach anderen Servern", "Search for other servers"), SelfTestStatus.Warning, Lang.T("Die Suche nach anderen DHCP-Servern ist fehlgeschlagen: " + dhcpServer.LastProbeError, "The search for other DHCP servers failed: " + dhcpServer.LastProbeError), "dhcp"));

                    (int total, int used) = dhcpServer.GetPoolUsage();
                    if (total > 0)
                    {
                        int percent = (int)Math.Round(used * 100.0 / total);
                        string usage = Lang.T(FormatNumber(used) + " von " + FormatNumber(total) + " Adressen vergeben (" + percent + " %).", FormatNumber(used) + " of " + FormatNumber(total) + " addresses in use (" + percent + " %).");

                        if (used >= total)
                            results.Add(new SelfTestResult(group, Lang.T("Adressbereich", "Address pool"), SelfTestStatus.Error, usage + Lang.T(" Neue Geräte erhalten keine Adresse. Den Bereich vergrößern oder die Lease-Zeit verkürzen.", " New devices get no address. Enlarge the range or shorten the lease time."), "dhcp"));
                        else if (percent >= 90)
                            results.Add(new SelfTestResult(group, Lang.T("Adressbereich", "Address pool"), SelfTestStatus.Warning, usage + Lang.T(" Der Bereich ist bald erschöpft.", " The pool will soon be exhausted."), "dhcp"));
                        else
                            results.Add(new SelfTestResult(group, Lang.T("Adressbereich", "Address pool"), SelfTestStatus.Ok, usage, "dhcp"));
                    }

                    CheckDhcp6(results, dhcpServer, settings, group);
                }
            }

            private void CheckDhcp6(List<SelfTestResult> results, DhcpServer dhcpServer, DhcpSettings settings, string group)
            {
                DhcpConfiguration config = dhcpServer.Configuration;
                bool configured = config.Ranges6.Count > 0;
                List<RaInterfaceStatus> raStatus = dhcpServer.GetRaStatus();
                HashSet<string> ownDns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                bool stateful = false;

                foreach (Dhcp6RangeRule rule in config.Ranges6)
                {
                    if (rule.AssignsAddresses)
                        stateful = true;
                }

                if (configured)
                {
                    List<string> failed = new List<string>();
                    List<string> advertising = new List<string>();
                    List<string> listening = new List<string>();

                    foreach (DhcpListenerStatus listener in dhcpServer.GetListener6Status())
                    {
                        if (!string.IsNullOrEmpty(listener.Error))
                            failed.Add(listener.Interface + " (" + listener.Error + ")");
                        else if (listener.Listening)
                            listening.Add(listener.Interface);
                    }

                    foreach (RaInterfaceStatus status in raStatus)
                    {
                        if (!status.Active)
                        {
                            failed.Add(status.Interface + " (" + status.Error + ")");
                            continue;
                        }

                        List<string> prefixes = new List<string>();
                        foreach (RaPrefix prefix in status.Plan.Prefixes)
                            prefixes.Add(prefix.ToString());

                        List<string> dns = new List<string>();
                        foreach (IPAddress address in status.Plan.DnsServers)
                        {
                            dns.Add(address.ToString());
                            ownDns.Add(address.ToString());
                        }

                        advertising.Add(Lang.T(status.Interface + " mit " + string.Join(", ", prefixes) + ", DNS " + string.Join(", ", dns), status.Interface + " with " + string.Join(", ", prefixes) + ", DNS " + string.Join(", ", dns)));
                    }

                    if (failed.Count > 0)
                        results.Add(new SelfTestResult(group, "IPv6", SelfTestStatus.Warning, Lang.T("Router Advertisements oder DHCPv6 laufen nicht auf: " + string.Join("; ", failed) + ". Ohne globale oder ULA-Adresse auf der Schnittstelle gibt es keinen Präfix; ohne CAP_NET_RAW keine Router Advertisements.", "Router advertisements or DHCPv6 do not run on: " + string.Join("; ", failed) + ". Without a global or ULA address on the interface there is no prefix; without CAP_NET_RAW there are no router advertisements."), "dhcp"));
                    else if (advertising.Count > 0)
                        results.Add(new SelfTestResult(group, "IPv6", SelfTestStatus.Ok, Lang.T("Router Advertisements auf " + string.Join("; ", advertising) + ".", "Router advertisements on " + string.Join("; ", advertising) + "."), "dhcp"));
                    else if (listening.Count > 0)
                        results.Add(new SelfTestResult(group, "IPv6", SelfTestStatus.Info, Lang.T("DHCPv6 empfängt auf " + string.Join(", ", listening) + ", es werden aber keine Router Advertisements gesendet. Geräte fragen DHCPv6 nur, wenn ein Router das M- oder O-Flag setzt; dafür enable-ra eintragen oder einen SLAAC-Modus wählen.", "DHCPv6 receives on " + string.Join(", ", listening) + ", but no router advertisements are sent. Devices only ask DHCPv6 when a router sets the M or O flag; add enable-ra or choose a SLAAC mode."), "dhcp"));
                }

                DateTime recent = DateTime.UtcNow.AddHours(-1);
                List<string> foreignDns = new List<string>();
                List<string> foreignManaged = new List<string>();

                foreach (RaForeignRouter router in dhcpServer.GetForeignRouters())
                {
                    if (router.LastSeen < recent)
                        continue;

                    List<string> other = new List<string>();
                    foreach (string server in router.DnsServers)
                    {
                        if (!ownDns.Contains(server))
                            other.Add(server);
                    }

                    if (other.Count > 0)
                        foreignDns.Add(router.Address + " (" + router.Interface + "): " + string.Join(", ", other));

                    if (router.Managed)
                        foreignManaged.Add(router.Address + " (" + router.Interface + ")");
                }

                if (foreignDns.Count > 0)
                {
                    if (configured)
                        results.Add(new SelfTestResult(group, Lang.T("IPv6-DNS anderer Router", "IPv6 DNS of other routers"), SelfTestStatus.Warning, Lang.T("Andere Router kündigen per IPv6 eigene DNS-Server an: " + string.Join("; ", foreignDns) + ". Geräte können diese statt ZenitiumDNS fragen, dann greifen Filter und Gerätenamen nicht. Im Router die DNS-Ankündigung (RDNSS) abschalten oder auf diesen Server setzen.", "Other routers announce their own DNS servers over IPv6: " + string.Join("; ", foreignDns) + ". Devices may ask them instead of ZenitiumDNS, and then filters and device names do not apply. Disable the DNS announcement (RDNSS) in the router or point it to this server."), "dhcp"));
                    else
                        results.Add(new SelfTestResult(group, Lang.T("IPv6-DNS anderer Router", "IPv6 DNS of other routers"), SelfTestStatus.Warning, Lang.T("Router kündigen per IPv6 eigene DNS-Server an: " + string.Join("; ", foreignDns) + ". Geräte mit IPv6 fragen diese womöglich statt ZenitiumDNS. Im Router die DNS-Ankündigung (RDNSS) abschalten oder auf diesen Server setzen, oder hier unter DHCP > IPv6 SLAAC einschalten, damit auch ZenitiumDNS angekündigt wird.", "Routers announce their own DNS servers over IPv6: " + string.Join("; ", foreignDns) + ". Devices with IPv6 may ask them instead of ZenitiumDNS. Disable the DNS announcement (RDNSS) in the router or point it to this server, or turn on SLAAC under DHCP > IPv6 so that ZenitiumDNS is announced as well."), "dhcp"));
                }

                if (configured && stateful && (foreignManaged.Count > 0))
                    results.Add(new SelfTestResult(group, Lang.T("Andere DHCPv6-Server", "Other DHCPv6 servers"), SelfTestStatus.Info, Lang.T("Diese Router setzen das M-Flag und verteilen vermutlich selbst DHCPv6-Adressen: " + string.Join("; ", foreignManaged) + ". Geräte können dann Adressen von beiden Servern bekommen.", "These routers set the M flag and probably hand out DHCPv6 addresses themselves: " + string.Join("; ", foreignManaged) + ". Devices may then get addresses from both servers."), "dhcp"));

                List<string> foreignServers = new List<string>();
                DateTime serverWindow = DateTime.UtcNow.AddSeconds(-Math.Max(900, settings.RogueProbeIntervalSeconds * 3));

                foreach (DhcpForeignServer server in dhcpServer.GetForeignServers6())
                {
                    if (server.LastSeen >= serverWindow)
                        foreignServers.Add(server.ServerId + " (" + server.Interface + ")");
                }

                if (configured && (foreignServers.Count > 0))
                    results.Add(new SelfTestResult(group, Lang.T("Andere DHCPv6-Server", "Other DHCPv6 servers"), settings.Priority == DhcpPriorityMode.Primary ? SelfTestStatus.Warning : SelfTestStatus.Info, Lang.T("Geräte haben einen anderen DHCPv6-Server angesprochen (DUID " + string.Join(", ", foreignServers) + ")." + (settings.Priority == DhcpPriorityMode.Standby ? " Wie eingestellt (Reserve) vergibt ZenitiumDNS solange keine neuen IPv6-Adressen." : " Den anderen Server abschalten oder die Priorität anpassen."), "Devices addressed another DHCPv6 server (DUID " + string.Join(", ", foreignServers) + ")." + (settings.Priority == DhcpPriorityMode.Standby ? " As configured (standby), ZenitiumDNS hands out no new IPv6 addresses meanwhile." : " Turn the other server off or adjust the priority.")), "dhcp"));
            }

            private void CheckWatchdog(List<SelfTestResult> results)
            {
                string group = Lang.T("Wächter", "Watchdog");
                Watchdog watchdog = _dnsWebService._dnsServer.Watchdog;

                if (!watchdog.Enabled)
                {
                    results.Add(new SelfTestResult(group, "Status", SelfTestStatus.Info, Lang.T("Der Wächter ist ausgeschaltet. Bei vollem Datenträger, Speichermangel oder ausgefallenen Diensten greift niemand automatisch ein.", "The watchdog is turned off. Nothing intervenes automatically when the disk is full, memory runs low or services fail."), "settings:General"));
                    return;
                }

                DateTime cutoff = DateTime.UtcNow.AddHours(-24);
                int shown = 0;

                foreach (WatchdogEvent watchdogEvent in watchdog.GetEvents())
                {
                    if (watchdogEvent.Time < cutoff)
                        break;

                    if (shown++ >= 5)
                        break;

                    results.Add(new SelfTestResult(group, watchdogEvent.Title.ToString(), SelfTestStatus.Warning, FormatDate(watchdogEvent.Time) + ": " + watchdogEvent.Message.ToString(), "settings:General"));
                }

                if (shown == 0)
                    results.Add(new SelfTestResult(group, "Status", SelfTestStatus.Ok, Lang.T("Aktiv, in den letzten 24 Stunden war kein Eingriff nötig.", "Active, no intervention was needed in the last 24 hours."), "settings:General"));
            }

            private async Task CheckClockOffsetAsync(List<SelfTestResult> results, string group)
            {
                IanaDataManager ianaDataManager = _dnsWebService._dnsServer.IanaDataManager;

                if (!ianaDataManager.TryGetClockSample(out _, out _, out DateTime checkedOn, out _) || ((DateTime.UtcNow - checkedOn).TotalHours > 2))
                {
                    try
                    {
                        await ianaDataManager.MeasureClockAsync();
                    }
                    catch
                    { }
                }

                if (!ianaDataManager.TryGetClockSample(out double offset, out double uncertainty, out checkedOn, out string source))
                {
                    results.Add(new SelfTestResult(group, Lang.T("Systemzeit", "System time"), SelfTestStatus.Info, Lang.T("Die Abweichung der Systemzeit ließ sich nicht messen, weil kein HTTPS-Server erreichbar war. Aktuell: ", "The system time offset could not be measured because no HTTPS server was reachable. Current: ") + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC."));
                    return;
                }

                double absOffset = Math.Abs(offset);
                string measured = Lang.T("gemessen gegen " + source + " am " + FormatDate(checkedOn) + ", Genauigkeit etwa ±" + Math.Ceiling(uncertainty).ToString(CultureInfo.InvariantCulture) + " s", "measured against " + source + " on " + FormatDate(checkedOn) + ", accuracy about ±" + Math.Ceiling(uncertainty).ToString(CultureInfo.InvariantCulture) + " s");
                string amount = Lang.T((offset > 0 ? "nach" : "vor") + " um etwa " + Math.Round(absOffset).ToString(CultureInfo.InvariantCulture) + " s", (offset > 0 ? "behind" : "ahead") + " by about " + Math.Round(absOffset).ToString(CultureInfo.InvariantCulture) + " s");

                if (absOffset <= Math.Max(5, uncertainty))
                    results.Add(new SelfTestResult(group, Lang.T("Systemzeit", "System time"), SelfTestStatus.Ok, Lang.T("Die Systemzeit stimmt (" + measured + ").", "The system time is correct (" + measured + ").")));
                else if (absOffset <= 60)
                    results.Add(new SelfTestResult(group, Lang.T("Systemzeit", "System time"), SelfTestStatus.Warning, Lang.T("Die Systemzeit geht " + amount + " (" + measured + "). NTP-Synchronisierung prüfen, etwa mit chrony oder systemd-timesyncd.", "The system time is " + amount + " (" + measured + "). Check NTP synchronization, for example with chrony or systemd-timesyncd.")));
                else
                    results.Add(new SelfTestResult(group, Lang.T("Systemzeit", "System time"), SelfTestStatus.Error, Lang.T("Die Systemzeit geht " + amount + " (" + measured + "). DNSSEC-Validierung, TLS-Zertifikate und die Prüfung der Root-Zone können scheitern. NTP einrichten, etwa mit chrony oder systemd-timesyncd.", "The system time is " + amount + " (" + measured + "). DNSSEC validation, TLS certificates and root zone verification may fail. Set up NTP, for example with chrony or systemd-timesyncd.")));
            }

            private void CheckSystem(List<SelfTestResult> results)
            {
                string group = Lang.T("System", "System");
                DnsServer dnsServer = _dnsWebService._dnsServer;

                if (OperatingSystem.IsLinux())
                {
                    string clockStatus = null;

                    try
                    {
                        byte[] timex = new byte[512];
                        int state = Adjtimex(timex);

                        if (state == 5)
                            clockStatus = "unsynchronized";
                        else if (state >= 0)
                            clockStatus = "synchronized";
                    }
                    catch
                    { }

                    if ((clockStatus is null) && File.Exists("/run/systemd/timesync/synchronized"))
                        clockStatus = "synchronized";

                    if (clockStatus == "synchronized")
                        results.Add(new SelfTestResult(group, Lang.T("Zeitsynchronisierung", "Time synchronization"), SelfTestStatus.Ok, Lang.T("Die Systemzeit wird per NTP synchronisiert.", "The system time is synchronized via NTP.")));
                    else if (clockStatus == "unsynchronized")
                        results.Add(new SelfTestResult(group, Lang.T("Zeitsynchronisierung", "Time synchronization"), SelfTestStatus.Error, Lang.T("Die Systemzeit wird nicht synchronisiert. Weicht sie ab, scheitern DNSSEC-Validierung, TLS-Zertifikate und die Prüfung der Root-Zone. NTP einrichten, etwa mit chrony oder systemd-timesyncd.", "The system time is not synchronized. If it drifts, DNSSEC validation, TLS certificates and root zone verification fail. Set up NTP, for example with chrony or systemd-timesyncd.")));
                    else
                        results.Add(new SelfTestResult(group, Lang.T("Zeitsynchronisierung", "Time synchronization"), SelfTestStatus.Info, Lang.T("Ob die Systemzeit synchronisiert wird, lässt sich aus dem Dienst heraus nicht prüfen.", "Whether the system time is synchronized cannot be checked from within the service.")));

                    try
                    {
                        long memTotal = 0;
                        long memAvailable = 0;

                        foreach (string line in File.ReadAllLines("/proc/meminfo"))
                        {
                            string[] parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                            if (parts.Length < 2)
                                continue;

                            if (parts[0] == "MemTotal:")
                                memTotal = long.Parse(parts[1], CultureInfo.InvariantCulture) * 1024;
                            else if (parts[0] == "MemAvailable:")
                                memAvailable = long.Parse(parts[1], CultureInfo.InvariantCulture) * 1024;
                        }

                        long workingSet = Environment.WorkingSet;

                        if ((memTotal > 0) && (memAvailable < memTotal / 10))
                            results.Add(new SelfTestResult(group, Lang.T("Arbeitsspeicher", "Memory"), SelfTestStatus.Warning, Lang.T("Nur noch " + FormatSize(memAvailable) + " von " + FormatSize(memTotal) + " frei. ZenitiumDNS belegt " + FormatSize(workingSet) + ". Cache-Größe oder Blocklisten verkleinern.", "Only " + FormatSize(memAvailable) + " of " + FormatSize(memTotal) + " free. ZenitiumDNS uses " + FormatSize(workingSet) + ". Reduce the cache size or the block lists."), "settings:Cache"));
                        else if (memTotal > 0)
                            results.Add(new SelfTestResult(group, Lang.T("Arbeitsspeicher", "Memory"), SelfTestStatus.Ok, Lang.T(FormatSize(memAvailable) + " von " + FormatSize(memTotal) + " frei, ZenitiumDNS belegt " + FormatSize(workingSet) + ".", FormatSize(memAvailable) + " of " + FormatSize(memTotal) + " free, ZenitiumDNS uses " + FormatSize(workingSet) + "."), "settings:Cache"));
                    }
                    catch
                    { }

                    try
                    {
                        long rmemMax = ReadProcLong("/proc/sys/net/core/rmem_max");
                        long wmemMax = ReadProcLong("/proc/sys/net/core/wmem_max");
                        long receiveBuffer = dnsServer.UdpReceiveBufferSizeKB * 1024L;
                        long sendBuffer = dnsServer.UdpSendBufferSizeKB * 1024L;

                        if ((rmemMax < receiveBuffer) || (wmemMax < sendBuffer))
                            results.Add(new SelfTestResult(group, Lang.T("UDP-Puffer", "UDP buffers"), SelfTestStatus.Warning, Lang.T("Der Kernel begrenzt die UDP-Puffer auf " + FormatSize(Math.Min(rmemMax, wmemMax)) + ", eingestellt sind " + FormatSize(Math.Max(receiveBuffer, sendBuffer)) + ". Bei Lastspitzen gehen Pakete verloren. Abhilfe: ", "The kernel limits the UDP buffers to " + FormatSize(Math.Min(rmemMax, wmemMax)) + ", configured are " + FormatSize(Math.Max(receiveBuffer, sendBuffer)) + ". Packets get lost during load peaks. Fix: ") + "sysctl -w net.core.rmem_max=" + receiveBuffer + " net.core.wmem_max=" + sendBuffer, "settings:Network"));
                        else
                            results.Add(new SelfTestResult(group, Lang.T("UDP-Puffer", "UDP buffers"), SelfTestStatus.Ok, Lang.T("Die Kernel-Grenzen erlauben die eingestellten Puffergrößen.", "The kernel limits allow the configured buffer sizes."), "settings:Network"));
                    }
                    catch
                    { }

                    try
                    {
                        foreach (string line in File.ReadAllLines("/proc/self/limits"))
                        {
                            if (!line.StartsWith("Max open files", StringComparison.Ordinal))
                                continue;

                            string[] parts = line.Substring("Max open files".Length).Split(' ', StringSplitOptions.RemoveEmptyEntries);
                            if ((parts.Length > 0) && long.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out long softLimit))
                            {
                                if (softLimit < 65536)
                                    results.Add(new SelfTestResult(group, Lang.T("Offene Dateien", "Open files"), SelfTestStatus.Warning, Lang.T("Das Limit für offene Dateien und Verbindungen liegt bei " + softLimit + ". Für viele gleichzeitige TCP-, DoT- und DoH-Verbindungen LimitNOFILE im Dienst erhöhen.", "The limit for open files and connections is " + softLimit + ". For many concurrent TCP, DoT and DoH connections, raise LimitNOFILE in the service.")));
                                else
                                    results.Add(new SelfTestResult(group, Lang.T("Offene Dateien", "Open files"), SelfTestStatus.Ok, "Limit " + softLimit + "."));
                            }

                            break;
                        }
                    }
                    catch
                    { }
                }

                void CheckFolder(string title, string folder)
                {
                    if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
                        return;

                    if (!IsWritable(folder))
                    {
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Error, Lang.T("Der Ordner " + folder + " ist nicht beschreibbar.", "The folder " + folder + " is not writable.")));
                        return;
                    }

                    DriveInfo drive = null;

                    try
                    {
                        drive = FindDrive(folder);
                    }
                    catch
                    { }

                    if (drive is null)
                    {
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Ok, Lang.T("Beschreibbar.", "Writable.")));
                        return;
                    }

                    long free = drive.AvailableFreeSpace;

                    if (free < 200L * 1024 * 1024)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Error, Lang.T("Nur noch " + FormatSize(free) + " frei in " + folder + ". Einstellungen, Cache und Statistik lassen sich bald nicht mehr speichern.", "Only " + FormatSize(free) + " free in " + folder + ". Settings, cache and statistics will soon no longer be saved.")));
                    else if (free < 1024L * 1024 * 1024)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Warning, Lang.T("Nur noch " + FormatSize(free) + " frei in " + folder + ".", "Only " + FormatSize(free) + " free in " + folder + ".")));
                    else
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Ok, Lang.T(FormatSize(free) + " frei in " + folder + ".", FormatSize(free) + " free in " + folder + ".")));
                }

                CheckFolder(Lang.T("Konfigurationsordner", "Configuration folder"), _dnsWebService._configFolder);

                string logFolder = null;

                try
                {
                    logFolder = _dnsWebService._log.LogFolderAbsolutePath;
                }
                catch
                { }

                CheckFolder(Lang.T("Log-Ordner", "Log folder"), logFolder);
            }

            private async Task<IReadOnlyList<SelfTestResult>> RunChecksAsync()
            {
                List<SelfTestResult> results = new List<SelfTestResult>();

                void Run(string group, Action<List<SelfTestResult>> check)
                {
                    try
                    {
                        check(results);
                    }
                    catch (Exception ex)
                    {
                        results.Add(new SelfTestResult(group, Lang.T("Prüfung", "Check"), SelfTestStatus.Warning, Lang.T("Die Prüfung ist fehlgeschlagen: ", "The check failed: ") + ex.Message));
                    }
                }

                async Task<List<SelfTestResult>> RunAsync(string group, string title, Func<List<SelfTestResult>, Task> check)
                {
                    List<SelfTestResult> asyncResults = new List<SelfTestResult>();

                    try
                    {
                        await check(asyncResults);
                    }
                    catch (Exception ex)
                    {
                        asyncResults.Add(new SelfTestResult(group, title, SelfTestStatus.Warning, Lang.T("Die Prüfung ist fehlgeschlagen: ", "The check failed: ") + ex.Message));
                    }

                    return asyncResults;
                }

                Task<List<SelfTestResult>> resolution = RunAsync(Lang.T("Auflösung", "Resolution"), Lang.T("Prüfung", "Check"), CheckResolutionAsync);
                Task<List<SelfTestResult>> clock = RunAsync("System", Lang.T("Systemzeit", "System time"), delegate (List<SelfTestResult> list) { return CheckClockOffsetAsync(list, "System"); });

                Run(Lang.T("Dienste", "Services"), CheckServices);
                results.AddRange(await resolution);
                Run("Cache", CheckCache);
                Run(Lang.T("Zertifikate", "Certificates"), CheckCertificates);
                Run(Lang.T("Root-Zone", "Root zone"), CheckIanaData);
                Run(Lang.T("Sicherheit", "Security"), CheckSecurity);
                Run("Filter", CheckFilters);
                Run("Apps", CheckApps);
                Run("DHCP", CheckDhcp);
                Run(Lang.T("Wächter", "Watchdog"), CheckWatchdog);
                results.AddRange(await clock);
                Run("System", CheckSystem);

                return results;
            }

            #endregion

            #region public

            public async Task RunAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                bool refresh = context.Request.GetQueryOrForm("refresh", bool.Parse, false);

                IReadOnlyList<SelfTestResult> results;
                DateTime runOn;
                double duration;

                await _runLock.WaitAsync();
                try
                {
                    if (refresh || (_lastResults is null) || (_lastLanguage != Lang.Code) || (DateTime.UtcNow > _lastRunOn.AddSeconds(CACHE_SECONDS)))
                    {
                        _lastLanguage = Lang.Code;

                        long start = Stopwatch.GetTimestamp();
                        _lastResults = await RunChecksAsync();
                        _lastDuration = Stopwatch.GetElapsedTime(start).TotalMilliseconds;
                        _lastRunOn = DateTime.UtcNow;
                    }

                    results = _lastResults;
                    runOn = _lastRunOn;
                    duration = _lastDuration;
                }
                finally
                {
                    _runLock.Release();
                }

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WriteString("runOn", runOn);
                jsonWriter.WriteNumber("durationMs", Math.Round(duration));

                int errors = 0;
                int warnings = 0;
                int infos = 0;
                int oks = 0;

                jsonWriter.WriteStartArray("results");

                foreach (SelfTestResult result in results)
                {
                    switch (result.Status)
                    {
                        case SelfTestStatus.Error:
                            errors++;
                            break;

                        case SelfTestStatus.Warning:
                            warnings++;
                            break;

                        case SelfTestStatus.Info:
                            infos++;
                            break;

                        default:
                            oks++;
                            break;
                    }

                    jsonWriter.WriteStartObject();
                    jsonWriter.WriteString("group", result.Group);
                    jsonWriter.WriteString("title", result.Title);
                    jsonWriter.WriteString("status", result.Status.ToString().ToLowerInvariant());
                    jsonWriter.WriteString("message", result.Message);

                    if (result.Section is not null)
                        jsonWriter.WriteString("section", result.Section);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("errors", errors);
                jsonWriter.WriteNumber("warnings", warnings);
                jsonWriter.WriteNumber("infos", infos);
                jsonWriter.WriteNumber("oks", oks);
            }

            #endregion

            enum SelfTestStatus
            {
                Ok,
                Info,
                Warning,
                Error
            }

            sealed record SelfTestResult(string Group, string Title, SelfTestStatus Status, string Message, string Section = null);
        }
    }
}
