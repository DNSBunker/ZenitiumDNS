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

            private static void CheckCertificate(List<SelfTestResult> results, string group, string name, X509Certificate2 certificate, string expectedHostname)
            {
                DateTime now = DateTime.UtcNow;
                string validity = name + Lang.T(": Gültigkeit", ": validity");
                DateTime notAfter = certificate.NotAfter.ToUniversalTime();

                if (notAfter <= now)
                    results.Add(new SelfTestResult(group, validity, SelfTestStatus.Error, Lang.T("Das Zertifikat ist am " + FormatDate(notAfter) + " abgelaufen. Clients bauen keine verschlüsselten Verbindungen mehr auf.", "The certificate expired on " + FormatDate(notAfter) + ". Clients no longer establish encrypted connections.")));
                else if (certificate.NotBefore.ToUniversalTime() > now)
                    results.Add(new SelfTestResult(group, validity, SelfTestStatus.Error, Lang.T("Das Zertifikat gilt erst ab " + FormatDate(certificate.NotBefore) + ". Systemzeit prüfen.", "The certificate is only valid from " + FormatDate(certificate.NotBefore) + ". Check the system time.")));
                else if ((notAfter - now).TotalDays < CERTIFICATE_WARNING_DAYS)
                    results.Add(new SelfTestResult(group, validity, SelfTestStatus.Warning, Lang.T("Das Zertifikat läuft am " + FormatDate(notAfter) + " ab, in " + Math.Floor((notAfter - now).TotalDays) + " Tagen. Die automatische Erneuerung prüfen.", "The certificate expires on " + FormatDate(notAfter) + ", in " + Math.Floor((notAfter - now).TotalDays) + " days. Check the automatic renewal.")));
                else
                    results.Add(new SelfTestResult(group, validity, SelfTestStatus.Ok, Lang.T("Gültig bis " + FormatDate(notAfter) + ".", "Valid until " + FormatDate(notAfter) + ".")));

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
                        results.Add(new SelfTestResult(group, name + Lang.T(": Name", ": name"), SelfTestStatus.Ok, Lang.T("Das Zertifikat gilt für " + expectedHostname + ".", "The certificate is valid for " + expectedHostname + ".")));
                    else
                        results.Add(new SelfTestResult(group, name + Lang.T(": Name", ": name"), SelfTestStatus.Warning, Lang.T("Das Zertifikat gilt nicht für den Serverdomainnamen " + expectedHostname + ". Clients, die diesen Namen verwenden, lehnen die Verbindung ab.", "The certificate is not valid for the server domain name " + expectedHostname + ". Clients using this name reject the connection.")));
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
                    results.Add(new SelfTestResult(group, Lang.T("Lauschende Sockets", "Listening sockets"), SelfTestStatus.Error, Lang.T("Nicht aktiv: " + string.Join(", ", inactive) + ". Meist belegt ein anderer Dienst den Port, etwa systemd-resolved, dnsmasq oder unbound. Das Log nennt die genaue Ursache.", "Not active: " + string.Join(", ", inactive) + ". Usually another service occupies the port, such as systemd-resolved, dnsmasq or unbound. The log names the exact cause.")));
                else
                    results.Add(new SelfTestResult(group, Lang.T("Lauschende Sockets", "Listening sockets"), SelfTestStatus.Ok, Lang.T(active + " Dienste lauschen wie konfiguriert.", active + " services are listening as configured.")));

                if ((dnsServer.EnableDnsOverTls || dnsServer.EnableDnsOverHttps || dnsServer.EnableDnsOverQuic) && (dnsServer.DnsTlsCertificate is null))
                    results.Add(new SelfTestResult(group, Lang.T("Verschlüsselte Protokolle", "Encrypted protocols"), SelfTestStatus.Error, Lang.T("DoT, DoH oder DoQ ist aktiviert, aber es ist kein TLS-Zertifikat geladen. Diese Dienste bleiben deshalb aus.", "DoT, DoH or DoQ is enabled, but no TLS certificate is loaded. These services therefore stay off.")));

                bool hasEncryptedService = (dnsServer.DnsTlsCertificate is not null) && (dnsServer.EnableDnsOverTls || dnsServer.EnableDnsOverHttps || dnsServer.EnableDnsOverQuic);

                switch (dnsServer.Do53Mode)
                {
                    case DnsServerDo53Mode.DdrOnlyDrop:
                    case DnsServerDo53Mode.DdrOnlyRefused:
                        if (dnsServer.GetDdrRecords().Count == 0)
                            results.Add(new SelfTestResult(group, "Do53", SelfTestStatus.Error, Lang.T("Do53 beantwortet nur DDR, es gibt aber keine DDR-Einträge, weil kein TLS-Zertifikat geladen oder kein verschlüsselter Dienst aktiv ist. Clients erhalten über Port 53 damit gar keine Antworten.", "Do53 only answers DDR, but there are no DDR records because no TLS certificate is loaded or no encrypted service is active. Clients therefore get no answers at all over port 53.")));
                        else
                            results.Add(new SelfTestResult(group, "Do53", SelfTestStatus.Info, Lang.T("Do53 beantwortet nur DDR, andere Anfragen werden " + (dnsServer.Do53Mode == DnsServerDo53Mode.DdrOnlyDrop ? "verworfen" : "mit REFUSED abgelehnt") + ". Clients ohne DDR-Unterstützung können den Resolver nur verschlüsselt nutzen.", "Do53 only answers DDR, other queries are " + (dnsServer.Do53Mode == DnsServerDo53Mode.DdrOnlyDrop ? "dropped" : "rejected with REFUSED") + ". Clients without DDR support can only use the resolver encrypted.")));

                        break;

                    case DnsServerDo53Mode.Disabled:
                        if (!hasEncryptedService && !dnsServer.EnableDnsOverHttp && !dnsServer.EnableDnsOverUdpProxy && !dnsServer.EnableDnsOverTcpProxy)
                            results.Add(new SelfTestResult(group, "Do53", SelfTestStatus.Error, Lang.T("Do53 ist deaktiviert und kein anderer Dienst ist aktiv. Der Resolver ist von außen nicht erreichbar.", "Do53 is disabled and no other service is active. The resolver cannot be reached from outside.")));
                        else
                            results.Add(new SelfTestResult(group, "Do53", SelfTestStatus.Info, Lang.T("Do53 ist deaktiviert, Port 53 wird nicht geöffnet.", "Do53 is disabled, port 53 is not opened.")));

                        break;
                }

                if (hasEncryptedService || dnsServer.EnableDnsOverHttp)
                {
                    switch (dnsServer.EDnsPaddingMode)
                    {
                        case DnsServerEDnsPaddingMode.Disabled:
                            results.Add(new SelfTestResult(group, Lang.T("EDNS-Padding", "EDNS padding"), SelfTestStatus.Warning, Lang.T("Padding ist ausgeschaltet. Aus der Größe verschlüsselter Antworten lässt sich dann teilweise ablesen, welche Domain abgefragt wurde.", "Padding is turned off. The size of encrypted responses can then partly reveal which domain was queried.")));
                            break;

                        case DnsServerEDnsPaddingMode.Always:
                            results.Add(new SelfTestResult(group, Lang.T("EDNS-Padding", "EDNS padding"), SelfTestStatus.Ok, Lang.T("Verschlüsselte Antworten werden immer auf 468 Byte aufgefüllt.", "Encrypted responses are always padded to 468 bytes.")));
                            break;

                        default:
                            results.Add(new SelfTestResult(group, Lang.T("EDNS-Padding", "EDNS padding"), SelfTestStatus.Ok, Lang.T("Verschlüsselte Antworten werden auf 468 Byte aufgefüllt, wenn der Client Padding sendet.", "Encrypted responses are padded to 468 bytes when the client sends padding.")));
                            break;
                    }
                }

                if (dnsServer.EnableDnsOverQuic && !System.Net.Quic.QuicListener.IsSupported)
                    results.Add(new SelfTestResult(group, "DNS-over-QUIC", SelfTestStatus.Warning, Lang.T("DoQ ist aktiviert, aber libmsquic ist nicht installiert.", "DoQ is enabled, but libmsquic is not installed.")));

                if (dnsServer.EnableDnsOverHttp && ((dnsServer.DnsReverseProxyNetworkACL is null) || (dnsServer.DnsReverseProxyNetworkACL.Count == 0)))
                    results.Add(new SelfTestResult(group, "DNS-over-HTTP", SelfTestStatus.Warning, Lang.T("DNS-over-HTTP ohne TLS ist aktiv, aber es sind keine erlaubten Reverse Proxys eingetragen.", "DNS-over-HTTP without TLS is active, but no allowed reverse proxies are configured.")));
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
                    results.Add(new SelfTestResult(group, Lang.T("Rekursive Auflösung", "Recursive resolution"), SelfTestStatus.Error, Lang.T("Die Root-Zone lässt sich " + via + " nicht auflösen (" + detail + "). Ausgehende Verbindungen auf Port 53 und die Forwarder prüfen.", "The root zone cannot be resolved " + via + " (" + detail + "). Check outgoing connections on port 53 and the forwarders.")));
                    return;
                }

                results.Add(new SelfTestResult(group, Lang.T("Rekursive Auflösung", "Recursive resolution"), SelfTestStatus.Ok, Lang.T("Die Root-Zone wurde " + via + " in " + stopwatch.ElapsedMilliseconds + " ms aufgelöst.", "The root zone was resolved " + via + " in " + stopwatch.ElapsedMilliseconds + " ms.")));

                if (!dnsServer.DnssecValidation)
                    results.Add(new SelfTestResult(group, Lang.T("DNSSEC-Validierung", "DNSSEC validation"), SelfTestStatus.Warning, Lang.T("Die DNSSEC-Validierung ist ausgeschaltet. Clients erhalten keine geprüften Antworten und keine Signaturen.", "DNSSEC validation is turned off. Clients receive no validated answers and no signatures.")));
                else if (response.AuthenticData)
                    results.Add(new SelfTestResult(group, Lang.T("DNSSEC-Validierung", "DNSSEC validation"), SelfTestStatus.Ok, Lang.T("Die signierte Root-Zone wurde erfolgreich validiert.", "The signed root zone was validated successfully.")));
                else
                    results.Add(new SelfTestResult(group, Lang.T("DNSSEC-Validierung", "DNSSEC validation"), SelfTestStatus.Error, Lang.T("Die DNSSEC-Validierung ist eingeschaltet, die Antwort für die Root-Zone ist aber nicht als validiert markiert. Systemzeit und Trust Anchor prüfen.", "DNSSEC validation is turned on, but the answer for the root zone is not marked as validated. Check the system time and the trust anchor.")));

                if (dnsServer.IPv6Mode != IPv6Mode.Disabled)
                {
                    if (IPv6Reachability.IsUnavailable && (dnsServer.IPv6Mode == IPv6Mode.Preferred))
                        results.Add(new SelfTestResult(group, "IPv6", SelfTestStatus.Warning, Lang.T("IPv6 ist auf „Bevorzugen“ gestellt, IPv6-Nameserver sind aber nicht erreichbar. Nach jedem Neustart laufen die ersten Anfragen deshalb in Zeitüberschreitungen, bis der automatische Rückfall greift. Unter Einstellungen > Netzwerk auf „Aktivieren“ oder „Deaktivieren“ stellen.", "IPv6 is set to \"Prefer\", but IPv6 name servers are unreachable. After every restart the first queries therefore run into timeouts until the automatic fallback kicks in. Set it to \"Enable\" or \"Disable\" under Settings > Network.")));
                    else if (IPv6Reachability.IsUnavailable)
                        results.Add(new SelfTestResult(group, "IPv6", SelfTestStatus.Info, Lang.T("IPv6 ist aktiviert, ausgehende IPv6-Anfragen sind aber gerade ausgesetzt, weil IPv6-Nameserver nicht erreichbar waren.", "IPv6 is enabled, but outgoing IPv6 queries are currently suspended because IPv6 name servers were unreachable.")));
                    else
                        results.Add(new SelfTestResult(group, "IPv6", SelfTestStatus.Ok, Lang.T("Ausgehende Anfragen über IPv6 sind aktiv.", "Outgoing queries over IPv6 are active.")));
                }
            }

            private void CheckCertificates(List<SelfTestResult> results)
            {
                string group = Lang.T("Zertifikate", "Certificates");
                DnsServer dnsServer = _dnsWebService._dnsServer;

                X509Certificate2 dnsCertificate = dnsServer.DnsTlsCertificate;
                if (dnsCertificate is not null)
                {
                    CheckCertificate(results, group, "DoT/DoH/DoQ", dnsCertificate, dnsServer.ServerDomain);

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
                            results.Add(new SelfTestResult(group, "DDR", SelfTestStatus.Ok, Lang.T("Das Zertifikat enthält IP-Adressen, Clients können die DDR-Ankündigung prüfen.", "The certificate contains IP addresses, clients can verify the DDR announcement.")));
                        else
                            results.Add(new SelfTestResult(group, "DDR", SelfTestStatus.Info, Lang.T("Das Zertifikat enthält keine IP-Adresse. Windows und Apple-Geräte nutzen die DDR-Ankündigung dann nicht automatisch.", "The certificate contains no IP address. Windows and Apple devices then do not use the DDR announcement automatically.")));
                    }
                }

                X509Certificate2 webCertificate = _dnsWebService._webServiceSslServerAuthenticationOptions?.ServerCertificateContext?.TargetCertificate;
                if (_dnsWebService._webServiceEnableTls && (webCertificate is not null) && !_dnsWebService._webServiceUseSelfSignedTlsCertificate)
                    CheckCertificate(results, group, Lang.T("Weboberfläche", "Web interface"), webCertificate, null);
            }

            private void CheckSecurity(List<SelfTestResult> results)
            {
                string group = Lang.T("Sicherheit", "Security");
                DnsServer dnsServer = _dnsWebService._dnsServer;

                if (_dnsWebService._authManager.HasDefaultCredentials())
                    results.Add(new SelfTestResult(group, Lang.T("Admin-Passwort", "Admin password"), SelfTestStatus.Error, Lang.T("Der Benutzer admin hat noch das Standardpasswort admin. Sofort unter Konto ändern.", "The user admin still has the default password admin. Change it immediately under the account menu.")));
                else
                    results.Add(new SelfTestResult(group, Lang.T("Admin-Passwort", "Admin password"), SelfTestStatus.Ok, Lang.T("Das Standardpasswort ist geändert.", "The default password has been changed.")));

                if (File.Exists(Path.Combine(_dnsWebService._configFolder, "admin.password")))
                    results.Add(new SelfTestResult(group, Lang.T("Passwortdatei", "Password file"), SelfTestStatus.Warning, Lang.T("Die Datei admin.password aus der Installation liegt noch im Konfigurationsordner. Nach der ersten Anmeldung löschen.", "The file admin.password from the installation is still in the configuration folder. Delete it after the first sign-in.")));

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
                    results.Add(new SelfTestResult(group, Lang.T("Weboberfläche", "Web interface"), SelfTestStatus.Warning, Lang.T("Die Weboberfläche ist ohne HTTPS über das Netz erreichbar. Anmeldedaten und Tokens gehen unverschlüsselt über die Leitung.", "The web interface is reachable over the network without HTTPS. Credentials and tokens travel unencrypted.")));
                else if (publicHttp && !_dnsWebService._webServiceHttpToTlsRedirect)
                    results.Add(new SelfTestResult(group, Lang.T("Weboberfläche", "Web interface"), SelfTestStatus.Info, Lang.T("HTTPS ist aktiv, HTTP auf Port " + _dnsWebService._webServiceHttpPort + " ist aber weiter ohne Umleitung erreichbar.", "HTTPS is active, but HTTP on port " + _dnsWebService._webServiceHttpPort + " is still reachable without redirect.")));
                else
                    results.Add(new SelfTestResult(group, Lang.T("Weboberfläche", "Web interface"), SelfTestStatus.Ok, publicHttp ? Lang.T("Die Weboberfläche ist nur verschlüsselt erreichbar.", "The web interface is only reachable encrypted.") : Lang.T("Die Weboberfläche lauscht nur auf Loopback.", "The web interface only listens on loopback.")));

                bool rateLimited = (dnsServer.QpsPrefixLimitsIPv4.Count > 0) || (dnsServer.QpsPrefixLimitsIPv6.Count > 0);

                switch (dnsServer.Recursion)
                {
                    case DnsServerRecursion.Allow:
                        if (rateLimited)
                            results.Add(new SelfTestResult(group, Lang.T("Rekursion", "Recursion"), SelfTestStatus.Ok, Lang.T("Öffentlicher Resolver mit Ratenbegrenzung.", "Public resolver with rate limiting.")));
                        else
                            results.Add(new SelfTestResult(group, Lang.T("Rekursion", "Recursion"), SelfTestStatus.Error, Lang.T("Der Resolver ist für alle offen, aber die Ratenbegrenzung ist ausgeschaltet. Er kann so für Amplification-Angriffe missbraucht werden.", "The resolver is open to everyone, but rate limiting is turned off. It can thus be abused for amplification attacks.")));

                        break;

                    case DnsServerRecursion.AllowOnlyForPrivateNetworks:
                        results.Add(new SelfTestResult(group, Lang.T("Rekursion", "Recursion"), SelfTestStatus.Info, Lang.T("Die Rekursion ist nur für private Netze erlaubt. Für den öffentlichen Betrieb unter Einstellungen > Resolver auf „Für alle erlauben“ stellen.", "Recursion is only allowed for private networks. For public operation, set it to \"Allow for everyone\" under Settings > Resolver.")));
                        break;

                    case DnsServerRecursion.Deny:
                        results.Add(new SelfTestResult(group, Lang.T("Rekursion", "Recursion"), SelfTestStatus.Warning, Lang.T("Die Rekursion ist ausgeschaltet. Der Server beantwortet nur lokale Zonen.", "Recursion is turned off. The server only answers local zones.")));
                        break;

                    default:
                        results.Add(new SelfTestResult(group, Lang.T("Rekursion", "Recursion"), rateLimited ? SelfTestStatus.Ok : SelfTestStatus.Warning, rateLimited ? Lang.T("Die Rekursion ist per ACL eingeschränkt.", "Recursion is restricted by ACL.") : Lang.T("Die Rekursion ist per ACL eingeschränkt, die Ratenbegrenzung ist aber ausgeschaltet.", "Recursion is restricted by ACL, but rate limiting is turned off.")));
                        break;
                }

                if (dnsServer.Recursion != DnsServerRecursion.Allow)
                {
                    if (!rateLimited)
                        results.Add(new SelfTestResult(group, Lang.T("Ratenbegrenzung", "Rate limiting"), SelfTestStatus.Info, Lang.T("Die Ratenbegrenzung ist ausgeschaltet.", "Rate limiting is turned off.")));
                    else
                        results.Add(new SelfTestResult(group, Lang.T("Ratenbegrenzung", "Rate limiting"), SelfTestStatus.Ok, Lang.T("Aktiv.", "Active.")));
                }

                List<string> strictLimits = new List<string>();

                foreach (KeyValuePair<int, (int, int)> limit in dnsServer.QpsPrefixLimitsIPv4)
                    AddStrictLimit(strictLimits, "/" + limit.Key, limit.Key >= 32 ? 200 : 5000, limit.Value);

                foreach (KeyValuePair<int, (int, int)> limit in dnsServer.QpsPrefixLimitsIPv6)
                    AddStrictLimit(strictLimits, "/" + limit.Key, limit.Key >= 64 ? 200 : 2000, limit.Value);

                if (strictLimits.Count > 0)
                    results.Add(new SelfTestResult(group, Lang.T("Ratenbegrenzung", "Rate limiting"), SelfTestStatus.Warning, Lang.T("Sehr niedrige Limits: " + string.Join(", ", strictLimits) + ". Hinter einer IPv4-Adresse mit CGNAT oder einem Firmen-NAT stehen oft Hunderte Nutzer, die dann gebremst werden. Empfohlen sind 1000 UDP und 5000 TCP je /32 und /64.", "Very low limits: " + string.Join(", ", strictLimits) + ". Behind an IPv4 address with CGNAT or corporate NAT there are often hundreds of users who then get throttled. 1000 UDP and 5000 TCP per /32 and /64 are recommended.")));

                if (dnsServer.RateLimitUdpTruncationPercentage < 100)
                    results.Add(new SelfTestResult(group, Lang.T("TC-Antworten", "TC responses"), SelfTestStatus.Info, Lang.T("Nur " + dnsServer.RateLimitUdpTruncationPercentage + " % der gebremsten UDP-Anfragen erhalten eine TC-Antwort. Die übrigen Clients laufen in Zeitüberschreitungen, statt auf TCP auszuweichen. 100 % ist für Clients hinter NAT am verträglichsten.", "Only " + dnsServer.RateLimitUdpTruncationPercentage + " % of throttled UDP queries receive a TC response. The remaining clients run into timeouts instead of switching to TCP. 100 % works best for clients behind NAT.")));

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
                    results.Add(new SelfTestResult(group, Lang.T("Anfragefilter", "Request filter"), SelfTestStatus.Ok, Lang.T("Alle Regeln sind aktiv.", "All rules are active.")));
                else
                    results.Add(new SelfTestResult(group, Lang.T("Anfragefilter", "Request filter"), dnsServer.Recursion == DnsServerRecursion.Allow ? SelfTestStatus.Warning : SelfTestStatus.Info, Lang.T(disabledRules + " von 8 Regeln sind ausgeschaltet.", disabledRules + " of 8 rules are turned off.")));
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
                        results.Add(new SelfTestResult(group, Lang.T("Client-Sperrlisten", "Client block lists"), SelfTestStatus.Error, Lang.T("Es sind Client-Sperrlisten eingetragen, aber keine Adresse ist geladen. Download-Fehler stehen im Log.", "Client block lists are configured, but no address is loaded. Download errors are in the log.")));
                    else if ((clientBlockListManager.UpdateIntervalHours > 0) && (clientBlockListManager.LastUpdatedOn != DateTime.MinValue) && ((DateTime.UtcNow - clientBlockListManager.LastUpdatedOn).TotalHours > (clientBlockListManager.UpdateIntervalHours * 3)))
                        results.Add(new SelfTestResult(group, Lang.T("Client-Sperrlisten", "Client block lists"), SelfTestStatus.Warning, Lang.T(FormatNumber(clientBlockListManager.AddressRanges) + " Adressbereiche geladen, die letzte erfolgreiche Aktualisierung war aber am " + FormatDate(clientBlockListManager.LastUpdatedOn) + ".", FormatNumber(clientBlockListManager.AddressRanges) + " address ranges loaded, but the last successful update was on " + FormatDate(clientBlockListManager.LastUpdatedOn) + ".")));
                    else
                        results.Add(new SelfTestResult(group, Lang.T("Client-Sperrlisten", "Client block lists"), SelfTestStatus.Ok, Lang.T(FormatNumber(clientBlockListManager.AddressRanges) + " Adressbereiche geladen, " + FormatNumber(clientBlockListManager.Drops) + " Anfragen oder Verbindungen seit dem Start verworfen.", FormatNumber(clientBlockListManager.AddressRanges) + " address ranges loaded, " + FormatNumber(clientBlockListManager.Drops) + " queries or connections dropped since start.")));
                }

                if (!dnsServer.EnableBlocking || (blockListZoneManager.BlockListUrls.Count == 0))
                    return;

                if (blockListZoneManager.TotalZonesBlocked == 0)
                {
                    results.Add(new SelfTestResult(group, Lang.T("Blocklisten", "Block lists"), SelfTestStatus.Error, Lang.T("Es sind Blocklisten eingetragen, aber keine Domain ist geladen. Download-Fehler stehen im Log.", "Block lists are configured, but no domain is loaded. Download errors are in the log.")));
                    return;
                }

                DateTime lastUpdatedOn = blockListZoneManager.BlockListLastUpdatedOn;
                int intervalHours = blockListZoneManager.BlockListUpdateIntervalHours;

                if ((intervalHours > 0) && (lastUpdatedOn != DateTime.MinValue) && ((DateTime.UtcNow - lastUpdatedOn).TotalHours > (intervalHours * 3)))
                    results.Add(new SelfTestResult(group, Lang.T("Blocklisten", "Block lists"), SelfTestStatus.Warning, Lang.T(FormatNumber(blockListZoneManager.TotalZonesBlocked) + " Domains geladen, die letzte erfolgreiche Aktualisierung war aber am " + FormatDate(lastUpdatedOn) + ".", FormatNumber(blockListZoneManager.TotalZonesBlocked) + " domains loaded, but the last successful update was on " + FormatDate(lastUpdatedOn) + ".")));
                else
                    results.Add(new SelfTestResult(group, Lang.T("Blocklisten", "Block lists"), SelfTestStatus.Ok, Lang.T(FormatNumber(blockListZoneManager.TotalZonesBlocked) + " Domains geladen" + (lastUpdatedOn == DateTime.MinValue ? "." : ", zuletzt aktualisiert am " + FormatDate(lastUpdatedOn) + "."), FormatNumber(blockListZoneManager.TotalZonesBlocked) + " domains loaded" + (lastUpdatedOn == DateTime.MinValue ? "." : ", last updated on " + FormatDate(lastUpdatedOn) + "."))));
            }

            private void CheckApps(List<SelfTestResult> results)
            {
                const string group = "Apps";
                DnsApplicationManager appManager = _dnsWebService._dnsServer.DnsApplicationManager;

                foreach (KeyValuePair<string, string> loadError in appManager.LoadErrors)
                    results.Add(new SelfTestResult(group, loadError.Key, SelfTestStatus.Error, Lang.T("Die App konnte nicht geladen werden: ", "The app could not be loaded: ") + loadError.Value));

                int enabled = 0;

                foreach (KeyValuePair<string, DnsApplication> application in appManager.Applications)
                {
                    if (!application.Value.Enabled)
                        continue;

                    enabled++;

                    if (application.Value.InitializationError is not null)
                        results.Add(new SelfTestResult(group, application.Key, SelfTestStatus.Error, Lang.T("Die App meldet einen Fehler bei der Initialisierung: ", "The app reports an initialization error: ") + application.Value.InitializationError));
                }

                if (appManager.LoadErrors.Count == 0)
                    results.Add(new SelfTestResult(group, Lang.T("Geladene Apps", "Loaded apps"), SelfTestStatus.Ok, Lang.T(appManager.Applications.Count + " installiert, " + enabled + " aktiviert.", appManager.Applications.Count + " installed, " + enabled + " enabled.")));
            }

            private void CheckIanaData(List<SelfTestResult> results)
            {
                string group = Lang.T("Root-Zone", "Root zone");
                IanaDataManager manager = _dnsWebService._dnsServer.IanaDataManager;

                foreach ((IanaDataItem item, string title) in new[] { (IanaDataItem.RootZone, Lang.T("Root-Zone", "Root zone")), (IanaDataItem.ArpaZone, Lang.T("arpa-Zone", "arpa zone")) })
                {
                    var state = manager.GetZoneState(item);

                    if (state.Mode == IanaDataMode.Disabled)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Info, Lang.T("Ausgeschaltet, der Resolver fragt die zuständigen Nameserver.", "Turned off, the resolver queries the responsible name servers.")));
                    else if (state.Error is not null)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Warning, state.Error + (state.Active ? Lang.T(" Die zuletzt geprüfte Version ist weiter aktiv.", " The last verified version remains active.") : Lang.T(" Der Resolver fragt so lange die zuständigen Nameserver.", " Meanwhile the resolver queries the responsible name servers."))));
                    else if (state.Active)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Ok, Lang.T("Seriennummer " + state.Serial + ", " + FormatNumber(state.Delegations) + " Delegationen. ", "Serial " + state.Serial + ", " + FormatNumber(state.Delegations) + " delegations. ") + state.Message));
                    else if (state.Mode == IanaDataMode.Custom)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Warning, Lang.T("Die eigene Version wird nicht verwendet: ", "The custom version is not used: ") + state.Message));
                    else
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Info, Lang.T("Wird kurz nach dem Start geladen und geprüft.", "Loaded and verified shortly after start.")));
                }

                var anchors = manager.GetTrustAnchorState();

                if (anchors.Error is not null)
                    results.Add(new SelfTestResult(group, "Root-KSK", SelfTestStatus.Warning, anchors.Error));
                else if (anchors.Source is not null)
                    results.Add(new SelfTestResult(group, "Root-KSK", SelfTestStatus.Ok, Lang.T("Quelle ", "Source ") + anchors.Source + ". " + anchors.Message));
            }

            private void CheckWatchdog(List<SelfTestResult> results)
            {
                string group = Lang.T("Wächter", "Watchdog");
                Watchdog watchdog = _dnsWebService._dnsServer.Watchdog;

                if (!watchdog.Enabled)
                {
                    results.Add(new SelfTestResult(group, "Status", SelfTestStatus.Info, Lang.T("Der Wächter ist ausgeschaltet. Bei vollem Datenträger, Speichermangel oder ausgefallenen Diensten greift niemand automatisch ein.", "The watchdog is turned off. Nothing intervenes automatically when the disk is full, memory runs low or services fail.")));
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

                    results.Add(new SelfTestResult(group, watchdogEvent.Title.ToString(), SelfTestStatus.Warning, FormatDate(watchdogEvent.Time) + ": " + watchdogEvent.Message.ToString()));
                }

                if (shown == 0)
                    results.Add(new SelfTestResult(group, "Status", SelfTestStatus.Ok, Lang.T("Aktiv, in den letzten 24 Stunden war kein Eingriff nötig.", "Active, no intervention was needed in the last 24 hours.")));
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
                            results.Add(new SelfTestResult(group, Lang.T("Arbeitsspeicher", "Memory"), SelfTestStatus.Warning, Lang.T("Nur noch " + FormatSize(memAvailable) + " von " + FormatSize(memTotal) + " frei. ZenitiumDNS belegt " + FormatSize(workingSet) + ". Cache-Größe oder Blocklisten verkleinern.", "Only " + FormatSize(memAvailable) + " of " + FormatSize(memTotal) + " free. ZenitiumDNS uses " + FormatSize(workingSet) + ". Reduce the cache size or the block lists.")));
                        else if (memTotal > 0)
                            results.Add(new SelfTestResult(group, Lang.T("Arbeitsspeicher", "Memory"), SelfTestStatus.Ok, Lang.T(FormatSize(memAvailable) + " von " + FormatSize(memTotal) + " frei, ZenitiumDNS belegt " + FormatSize(workingSet) + ".", FormatSize(memAvailable) + " of " + FormatSize(memTotal) + " free, ZenitiumDNS uses " + FormatSize(workingSet) + ".")));
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
                            results.Add(new SelfTestResult(group, Lang.T("UDP-Puffer", "UDP buffers"), SelfTestStatus.Warning, Lang.T("Der Kernel begrenzt die UDP-Puffer auf " + FormatSize(Math.Min(rmemMax, wmemMax)) + ", eingestellt sind " + FormatSize(Math.Max(receiveBuffer, sendBuffer)) + ". Bei Lastspitzen gehen Pakete verloren. Abhilfe: ", "The kernel limits the UDP buffers to " + FormatSize(Math.Min(rmemMax, wmemMax)) + ", configured are " + FormatSize(Math.Max(receiveBuffer, sendBuffer)) + ". Packets get lost during load peaks. Fix: ") + "sysctl -w net.core.rmem_max=" + receiveBuffer + " net.core.wmem_max=" + sendBuffer));
                        else
                            results.Add(new SelfTestResult(group, Lang.T("UDP-Puffer", "UDP buffers"), SelfTestStatus.Ok, Lang.T("Die Kernel-Grenzen erlauben die eingestellten Puffergrößen.", "The kernel limits allow the configured buffer sizes.")));
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

                Run(Lang.T("Dienste", "Services"), CheckServices);

                try
                {
                    await CheckResolutionAsync(results);
                }
                catch (Exception ex)
                {
                    results.Add(new SelfTestResult(Lang.T("Auflösung", "Resolution"), Lang.T("Prüfung", "Check"), SelfTestStatus.Warning, Lang.T("Die Prüfung ist fehlgeschlagen: ", "The check failed: ") + ex.Message));
                }

                Run(Lang.T("Zertifikate", "Certificates"), CheckCertificates);
                Run(Lang.T("Root-Zone", "Root zone"), CheckIanaData);
                Run(Lang.T("Sicherheit", "Security"), CheckSecurity);
                Run("Filter", CheckFilters);
                Run("Apps", CheckApps);
                Run(Lang.T("Wächter", "Watchdog"), CheckWatchdog);

                try
                {
                    await CheckClockOffsetAsync(results, "System");
                }
                catch (Exception ex)
                {
                    results.Add(new SelfTestResult("System", Lang.T("Systemzeit", "System time"), SelfTestStatus.Warning, Lang.T("Die Prüfung ist fehlgeschlagen: ", "The check failed: ") + ex.Message));
                }

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

                await _runLock.WaitAsync();
                try
                {
                    if (refresh || (_lastResults is null) || (_lastLanguage != Lang.Code) || (DateTime.UtcNow > _lastRunOn.AddSeconds(CACHE_SECONDS)))
                    {
                        _lastLanguage = Lang.Code;
                        _lastResults = await RunChecksAsync();
                        _lastRunOn = DateTime.UtcNow;
                    }

                    results = _lastResults;
                    runOn = _lastRunOn;
                }
                finally
                {
                    _runLock.Release();
                }

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WriteString("runOn", runOn);

                int errors = 0;
                int warnings = 0;

                jsonWriter.WriteStartArray("results");

                foreach (SelfTestResult result in results)
                {
                    if (result.Status == SelfTestStatus.Error)
                        errors++;
                    else if (result.Status == SelfTestStatus.Warning)
                        warnings++;

                    jsonWriter.WriteStartObject();
                    jsonWriter.WriteString("group", result.Group);
                    jsonWriter.WriteString("title", result.Title);
                    jsonWriter.WriteString("status", result.Status.ToString().ToLowerInvariant());
                    jsonWriter.WriteString("message", result.Message);
                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("errors", errors);
                jsonWriter.WriteNumber("warnings", warnings);
            }

            #endregion

            enum SelfTestStatus
            {
                Ok,
                Info,
                Warning,
                Error
            }

            sealed record SelfTestResult(string Group, string Title, SelfTestStatus Status, string Message);
        }
    }
}
