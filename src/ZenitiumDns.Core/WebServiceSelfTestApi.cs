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
                    return (bytes / (1024.0 * 1024 * 1024)).ToString("0.0", CultureInfo.GetCultureInfo("de-DE")) + " GB";

                return (bytes / (1024.0 * 1024)).ToString("0", CultureInfo.GetCultureInfo("de-DE")) + " MB";
            }

            private static string FormatDate(DateTime date)
            {
                return date.ToLocalTime().ToString("dd.MM.yyyy HH:mm", CultureInfo.GetCultureInfo("de-DE"));
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

            private static void CheckCertificate(List<SelfTestResult> results, string group, string name, X509Certificate2 certificate, string expectedHostname)
            {
                DateTime now = DateTime.UtcNow;
                DateTime notAfter = certificate.NotAfter.ToUniversalTime();

                if (notAfter <= now)
                    results.Add(new SelfTestResult(group, name + ": Gültigkeit", SelfTestStatus.Error, "Das Zertifikat ist am " + FormatDate(notAfter) + " abgelaufen. Clients bauen keine verschlüsselten Verbindungen mehr auf."));
                else if (certificate.NotBefore.ToUniversalTime() > now)
                    results.Add(new SelfTestResult(group, name + ": Gültigkeit", SelfTestStatus.Error, "Das Zertifikat gilt erst ab " + FormatDate(certificate.NotBefore) + ". Systemzeit prüfen."));
                else if ((notAfter - now).TotalDays < CERTIFICATE_WARNING_DAYS)
                    results.Add(new SelfTestResult(group, name + ": Gültigkeit", SelfTestStatus.Warning, "Das Zertifikat läuft am " + FormatDate(notAfter) + " ab, in " + Math.Floor((notAfter - now).TotalDays) + " Tagen. Die automatische Erneuerung prüfen."));
                else
                    results.Add(new SelfTestResult(group, name + ": Gültigkeit", SelfTestStatus.Ok, "Gültig bis " + FormatDate(notAfter) + "."));

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
                        results.Add(new SelfTestResult(group, name + ": Name", SelfTestStatus.Ok, "Das Zertifikat gilt für " + expectedHostname + "."));
                    else
                        results.Add(new SelfTestResult(group, name + ": Name", SelfTestStatus.Warning, "Das Zertifikat gilt nicht für den Serverdomainnamen " + expectedHostname + ". Clients, die diesen Namen verwenden, lehnen die Verbindung ab."));
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
                const string group = "Dienste";
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
                    results.Add(new SelfTestResult(group, "Lauschende Sockets", SelfTestStatus.Error, "Nicht aktiv: " + string.Join(", ", inactive) + ". Meist belegt ein anderer Dienst den Port, etwa systemd-resolved, dnsmasq oder unbound. Das Log nennt die genaue Ursache."));
                else
                    results.Add(new SelfTestResult(group, "Lauschende Sockets", SelfTestStatus.Ok, active + " Dienste lauschen wie konfiguriert."));

                if ((dnsServer.EnableDnsOverTls || dnsServer.EnableDnsOverHttps || dnsServer.EnableDnsOverQuic) && (dnsServer.DnsTlsCertificate is null))
                    results.Add(new SelfTestResult(group, "Verschlüsselte Protokolle", SelfTestStatus.Error, "DoT, DoH oder DoQ ist aktiviert, aber es ist kein TLS-Zertifikat geladen. Diese Dienste bleiben deshalb aus."));

                bool hasEncryptedService = (dnsServer.DnsTlsCertificate is not null) && (dnsServer.EnableDnsOverTls || dnsServer.EnableDnsOverHttps || dnsServer.EnableDnsOverQuic);

                switch (dnsServer.Do53Mode)
                {
                    case DnsServerDo53Mode.DdrOnlyDrop:
                    case DnsServerDo53Mode.DdrOnlyRefused:
                        if (dnsServer.GetDdrRecords().Count == 0)
                            results.Add(new SelfTestResult(group, "Do53", SelfTestStatus.Error, "Do53 beantwortet nur DDR, es gibt aber keine DDR-Einträge, weil kein TLS-Zertifikat geladen oder kein verschlüsselter Dienst aktiv ist. Clients erhalten über Port 53 damit gar keine Antworten."));
                        else
                            results.Add(new SelfTestResult(group, "Do53", SelfTestStatus.Info, "Do53 beantwortet nur DDR, andere Anfragen werden " + (dnsServer.Do53Mode == DnsServerDo53Mode.DdrOnlyDrop ? "verworfen" : "mit REFUSED abgelehnt") + ". Clients ohne DDR-Unterstützung können den Resolver nur verschlüsselt nutzen."));

                        break;

                    case DnsServerDo53Mode.Disabled:
                        if (!hasEncryptedService && !dnsServer.EnableDnsOverHttp && !dnsServer.EnableDnsOverUdpProxy && !dnsServer.EnableDnsOverTcpProxy)
                            results.Add(new SelfTestResult(group, "Do53", SelfTestStatus.Error, "Do53 ist deaktiviert und kein anderer Dienst ist aktiv. Der Resolver ist von außen nicht erreichbar."));
                        else
                            results.Add(new SelfTestResult(group, "Do53", SelfTestStatus.Info, "Do53 ist deaktiviert, Port 53 wird nicht geöffnet."));

                        break;
                }

                if (hasEncryptedService || dnsServer.EnableDnsOverHttp)
                {
                    switch (dnsServer.EDnsPaddingMode)
                    {
                        case DnsServerEDnsPaddingMode.Disabled:
                            results.Add(new SelfTestResult(group, "EDNS-Padding", SelfTestStatus.Warning, "Padding ist ausgeschaltet. Aus der Größe verschlüsselter Antworten lässt sich dann teilweise ablesen, welche Domain abgefragt wurde."));
                            break;

                        case DnsServerEDnsPaddingMode.Always:
                            results.Add(new SelfTestResult(group, "EDNS-Padding", SelfTestStatus.Ok, "Verschlüsselte Antworten werden immer auf 468 Byte aufgefüllt."));
                            break;

                        default:
                            results.Add(new SelfTestResult(group, "EDNS-Padding", SelfTestStatus.Ok, "Verschlüsselte Antworten werden auf 468 Byte aufgefüllt, wenn der Client Padding sendet."));
                            break;
                    }
                }

                if (dnsServer.EnableDnsOverQuic && !System.Net.Quic.QuicListener.IsSupported)
                    results.Add(new SelfTestResult(group, "DNS-over-QUIC", SelfTestStatus.Warning, "DoQ ist aktiviert, aber libmsquic ist nicht installiert."));

                if (dnsServer.EnableDnsOverHttp && ((dnsServer.DnsReverseProxyNetworkACL is null) || (dnsServer.DnsReverseProxyNetworkACL.Count == 0)))
                    results.Add(new SelfTestResult(group, "DNS-over-HTTP", SelfTestStatus.Warning, "DNS-over-HTTP ohne TLS ist aktiv, aber es sind keine erlaubten Reverse Proxys eingetragen."));
            }

            private async Task CheckResolutionAsync(List<SelfTestResult> results)
            {
                const string group = "Auflösung";
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

                string via = ((dnsServer.Forwarders is not null) && (dnsServer.Forwarders.Count > 0)) ? "über die Forwarder" : (dnsServer.IanaDataManager.GetZoneState(IanaDataItem.RootZone).Active ? "mit der lokalen Kopie der Root-Zone" : "über die Root-Server");

                if ((response is null) || (response.RCODE != DnsResponseCode.NoError) || (response.Answer.Count == 0))
                {
                    string detail = error ?? ((response is null) ? "keine Antwort" : response.RCODE.ToString());
                    results.Add(new SelfTestResult(group, "Rekursive Auflösung", SelfTestStatus.Error, "Die Root-Zone lässt sich " + via + " nicht auflösen (" + detail + "). Ausgehende Verbindungen auf Port 53 und die Forwarder prüfen."));
                    return;
                }

                results.Add(new SelfTestResult(group, "Rekursive Auflösung", SelfTestStatus.Ok, "Die Root-Zone wurde " + via + " in " + stopwatch.ElapsedMilliseconds + " ms aufgelöst."));

                if (!dnsServer.DnssecValidation)
                    results.Add(new SelfTestResult(group, "DNSSEC-Validierung", SelfTestStatus.Warning, "Die DNSSEC-Validierung ist ausgeschaltet. Clients erhalten keine geprüften Antworten und keine Signaturen."));
                else if (response.AuthenticData)
                    results.Add(new SelfTestResult(group, "DNSSEC-Validierung", SelfTestStatus.Ok, "Die signierte Root-Zone wurde erfolgreich validiert."));
                else
                    results.Add(new SelfTestResult(group, "DNSSEC-Validierung", SelfTestStatus.Error, "Die DNSSEC-Validierung ist eingeschaltet, die Antwort für die Root-Zone ist aber nicht als validiert markiert. Systemzeit und Trust Anchor prüfen."));

                if (dnsServer.IPv6Mode != IPv6Mode.Disabled)
                {
                    if (IPv6Reachability.IsUnavailable && (dnsServer.IPv6Mode == IPv6Mode.Preferred))
                        results.Add(new SelfTestResult(group, "IPv6", SelfTestStatus.Warning, "IPv6 ist auf „Bevorzugen“ gestellt, IPv6-Nameserver sind aber nicht erreichbar. Nach jedem Neustart laufen die ersten Anfragen deshalb in Zeitüberschreitungen, bis der automatische Rückfall greift. Unter Einstellungen > Netzwerk auf „Aktiviert“ oder „Deaktiviert“ stellen."));
                    else if (IPv6Reachability.IsUnavailable)
                        results.Add(new SelfTestResult(group, "IPv6", SelfTestStatus.Info, "IPv6 ist aktiviert, ausgehende IPv6-Anfragen sind aber gerade ausgesetzt, weil IPv6-Nameserver nicht erreichbar waren."));
                    else
                        results.Add(new SelfTestResult(group, "IPv6", SelfTestStatus.Ok, "Ausgehende Anfragen über IPv6 sind aktiv."));
                }
            }

            private void CheckCertificates(List<SelfTestResult> results)
            {
                const string group = "Zertifikate";
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
                            results.Add(new SelfTestResult(group, "DDR", SelfTestStatus.Ok, "Das Zertifikat enthält IP-Adressen, Clients können die DDR-Ankündigung prüfen."));
                        else
                            results.Add(new SelfTestResult(group, "DDR", SelfTestStatus.Info, "Das Zertifikat enthält keine IP-Adresse. Windows und Apple-Geräte nutzen die DDR-Ankündigung dann nicht automatisch."));
                    }
                }

                X509Certificate2 webCertificate = _dnsWebService._webServiceSslServerAuthenticationOptions?.ServerCertificateContext?.TargetCertificate;
                if (_dnsWebService._webServiceEnableTls && (webCertificate is not null) && !_dnsWebService._webServiceUseSelfSignedTlsCertificate)
                    CheckCertificate(results, group, "Weboberfläche", webCertificate, null);
            }

            private void CheckSecurity(List<SelfTestResult> results)
            {
                const string group = "Sicherheit";
                DnsServer dnsServer = _dnsWebService._dnsServer;

                if (_dnsWebService._authManager.HasDefaultCredentials())
                    results.Add(new SelfTestResult(group, "Admin-Passwort", SelfTestStatus.Error, "Der Benutzer admin hat noch das Standardpasswort admin. Sofort unter Konto ändern."));
                else
                    results.Add(new SelfTestResult(group, "Admin-Passwort", SelfTestStatus.Ok, "Das Standardpasswort ist geändert."));

                if (File.Exists(Path.Combine(_dnsWebService._configFolder, "admin.password")))
                    results.Add(new SelfTestResult(group, "Passwortdatei", SelfTestStatus.Warning, "Die Datei admin.password aus der Installation liegt noch im Konfigurationsordner. Nach der ersten Anmeldung löschen."));

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
                    results.Add(new SelfTestResult(group, "Weboberfläche", SelfTestStatus.Warning, "Die Weboberfläche ist ohne HTTPS über das Netz erreichbar. Anmeldedaten und Tokens gehen unverschlüsselt über die Leitung."));
                else if (publicHttp && !_dnsWebService._webServiceHttpToTlsRedirect)
                    results.Add(new SelfTestResult(group, "Weboberfläche", SelfTestStatus.Info, "HTTPS ist aktiv, HTTP auf Port " + _dnsWebService._webServiceHttpPort + " ist aber weiter ohne Umleitung erreichbar."));
                else
                    results.Add(new SelfTestResult(group, "Weboberfläche", SelfTestStatus.Ok, publicHttp ? "Die Weboberfläche ist nur verschlüsselt erreichbar." : "Die Weboberfläche lauscht nur auf Loopback."));

                bool rateLimited = (dnsServer.QpsPrefixLimitsIPv4.Count > 0) || (dnsServer.QpsPrefixLimitsIPv6.Count > 0);

                switch (dnsServer.Recursion)
                {
                    case DnsServerRecursion.Allow:
                        if (rateLimited)
                            results.Add(new SelfTestResult(group, "Rekursion", SelfTestStatus.Ok, "Öffentlicher Resolver mit Ratenbegrenzung."));
                        else
                            results.Add(new SelfTestResult(group, "Rekursion", SelfTestStatus.Error, "Der Resolver ist für alle offen, aber die Ratenbegrenzung ist ausgeschaltet. Er kann so für Amplification-Angriffe missbraucht werden."));

                        break;

                    case DnsServerRecursion.AllowOnlyForPrivateNetworks:
                        results.Add(new SelfTestResult(group, "Rekursion", SelfTestStatus.Info, "Die Rekursion ist nur für private Netze erlaubt. Für den öffentlichen Betrieb unter Einstellungen > Resolver auf „Erlauben“ stellen."));
                        break;

                    case DnsServerRecursion.Deny:
                        results.Add(new SelfTestResult(group, "Rekursion", SelfTestStatus.Warning, "Die Rekursion ist ausgeschaltet. Der Server beantwortet nur lokale Zonen."));
                        break;

                    default:
                        results.Add(new SelfTestResult(group, "Rekursion", rateLimited ? SelfTestStatus.Ok : SelfTestStatus.Warning, rateLimited ? "Die Rekursion ist per ACL eingeschränkt." : "Die Rekursion ist per ACL eingeschränkt, die Ratenbegrenzung ist aber ausgeschaltet."));
                        break;
                }

                if (dnsServer.Recursion != DnsServerRecursion.Allow)
                {
                    if (!rateLimited)
                        results.Add(new SelfTestResult(group, "Ratenbegrenzung", SelfTestStatus.Info, "Die Ratenbegrenzung ist ausgeschaltet."));
                    else
                        results.Add(new SelfTestResult(group, "Ratenbegrenzung", SelfTestStatus.Ok, "Aktiv."));
                }

                List<string> strictLimits = new List<string>();

                foreach (KeyValuePair<int, (int, int)> limit in dnsServer.QpsPrefixLimitsIPv4)
                    AddStrictLimit(strictLimits, "/" + limit.Key, limit.Key >= 32 ? 200 : 5000, limit.Value);

                foreach (KeyValuePair<int, (int, int)> limit in dnsServer.QpsPrefixLimitsIPv6)
                    AddStrictLimit(strictLimits, "/" + limit.Key, limit.Key >= 64 ? 200 : 2000, limit.Value);

                if (strictLimits.Count > 0)
                    results.Add(new SelfTestResult(group, "Ratenbegrenzung", SelfTestStatus.Warning, "Sehr niedrige Limits: " + string.Join(", ", strictLimits) + ". Hinter einer IPv4-Adresse mit CGNAT oder einem Firmen-NAT stehen oft Hunderte Nutzer, die dann gebremst werden. Empfohlen sind 1000 UDP und 5000 TCP je /32 und /64."));

                if (dnsServer.RateLimitUdpTruncationPercentage < 100)
                    results.Add(new SelfTestResult(group, "TC-Antworten", SelfTestStatus.Info, "Nur " + dnsServer.RateLimitUdpTruncationPercentage + " % der gebremsten UDP-Anfragen erhalten eine TC-Antwort. Die übrigen Clients laufen in Zeitüberschreitungen, statt auf TCP auszuweichen. 100 % ist für Clients hinter NAT am verträglichsten."));

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
                    results.Add(new SelfTestResult(group, "Anfragefilter", SelfTestStatus.Ok, "Alle Regeln sind aktiv."));
                else
                    results.Add(new SelfTestResult(group, "Anfragefilter", dnsServer.Recursion == DnsServerRecursion.Allow ? SelfTestStatus.Warning : SelfTestStatus.Info, disabledRules + " von 8 Regeln sind ausgeschaltet."));
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
                        results.Add(new SelfTestResult(group, "Client-Sperrlisten", SelfTestStatus.Error, "Es sind Client-Sperrlisten eingetragen, aber keine Adresse ist geladen. Download-Fehler stehen im Log."));
                    else if ((clientBlockListManager.UpdateIntervalHours > 0) && (clientBlockListManager.LastUpdatedOn != DateTime.MinValue) && ((DateTime.UtcNow - clientBlockListManager.LastUpdatedOn).TotalHours > (clientBlockListManager.UpdateIntervalHours * 3)))
                        results.Add(new SelfTestResult(group, "Client-Sperrlisten", SelfTestStatus.Warning, clientBlockListManager.AddressRanges.ToString("N0", CultureInfo.GetCultureInfo("de-DE")) + " Adressbereiche geladen, die letzte erfolgreiche Aktualisierung war aber am " + FormatDate(clientBlockListManager.LastUpdatedOn) + "."));
                    else
                        results.Add(new SelfTestResult(group, "Client-Sperrlisten", SelfTestStatus.Ok, clientBlockListManager.AddressRanges.ToString("N0", CultureInfo.GetCultureInfo("de-DE")) + " Adressbereiche geladen, " + clientBlockListManager.Drops.ToString("N0", CultureInfo.GetCultureInfo("de-DE")) + " Anfragen oder Verbindungen seit dem Start verworfen."));
                }

                if (!dnsServer.EnableBlocking || (blockListZoneManager.BlockListUrls.Count == 0))
                    return;

                if (blockListZoneManager.TotalZonesBlocked == 0)
                {
                    results.Add(new SelfTestResult(group, "Blocklisten", SelfTestStatus.Error, "Es sind Blocklisten eingetragen, aber keine Domain ist geladen. Download-Fehler stehen im Log."));
                    return;
                }

                DateTime lastUpdatedOn = blockListZoneManager.BlockListLastUpdatedOn;
                int intervalHours = blockListZoneManager.BlockListUpdateIntervalHours;

                if ((intervalHours > 0) && (lastUpdatedOn != DateTime.MinValue) && ((DateTime.UtcNow - lastUpdatedOn).TotalHours > (intervalHours * 3)))
                    results.Add(new SelfTestResult(group, "Blocklisten", SelfTestStatus.Warning, blockListZoneManager.TotalZonesBlocked.ToString("N0", CultureInfo.GetCultureInfo("de-DE")) + " Domains geladen, die letzte erfolgreiche Aktualisierung war aber am " + FormatDate(lastUpdatedOn) + "."));
                else
                    results.Add(new SelfTestResult(group, "Blocklisten", SelfTestStatus.Ok, blockListZoneManager.TotalZonesBlocked.ToString("N0", CultureInfo.GetCultureInfo("de-DE")) + " Domains geladen" + (lastUpdatedOn == DateTime.MinValue ? "." : ", zuletzt aktualisiert am " + FormatDate(lastUpdatedOn) + ".")));
            }

            private void CheckApps(List<SelfTestResult> results)
            {
                const string group = "Apps";
                DnsApplicationManager appManager = _dnsWebService._dnsServer.DnsApplicationManager;

                foreach (KeyValuePair<string, string> loadError in appManager.LoadErrors)
                    results.Add(new SelfTestResult(group, loadError.Key, SelfTestStatus.Error, "Die App konnte nicht geladen werden: " + loadError.Value));

                int enabled = 0;

                foreach (KeyValuePair<string, DnsApplication> application in appManager.Applications)
                {
                    if (!application.Value.Enabled)
                        continue;

                    enabled++;

                    if (application.Value.InitializationError is not null)
                        results.Add(new SelfTestResult(group, application.Key, SelfTestStatus.Error, "Die App meldet einen Fehler bei der Initialisierung: " + application.Value.InitializationError));
                }

                if (appManager.LoadErrors.Count == 0)
                    results.Add(new SelfTestResult(group, "Geladene Apps", SelfTestStatus.Ok, appManager.Applications.Count + " installiert, " + enabled + " aktiviert."));
            }

            private void CheckIanaData(List<SelfTestResult> results)
            {
                const string group = "Root-Zone";
                IanaDataManager manager = _dnsWebService._dnsServer.IanaDataManager;

                foreach ((IanaDataItem item, string title) in new[] { (IanaDataItem.RootZone, "Root-Zone"), (IanaDataItem.ArpaZone, "arpa-Zone") })
                {
                    var state = manager.GetZoneState(item);

                    if (state.Mode == IanaDataMode.Disabled)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Info, "Ausgeschaltet, der Resolver fragt die zuständigen Nameserver."));
                    else if (state.Error is not null)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Warning, state.Error + (state.Active ? " Die zuletzt geprüfte Version ist weiter aktiv." : " Der Resolver fragt so lange die zuständigen Nameserver.")));
                    else if (state.Active)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Ok, "Seriennummer " + state.Serial + ", " + state.Delegations.ToString("N0", CultureInfo.GetCultureInfo("de-DE")) + " Delegationen. " + state.Message));
                    else if (state.Mode == IanaDataMode.Custom)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Warning, "Die eigene Version wird nicht verwendet: " + state.Message));
                    else
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Info, "Wird kurz nach dem Start geladen und geprüft."));
                }

                var anchors = manager.GetTrustAnchorState();

                if (anchors.Error is not null)
                    results.Add(new SelfTestResult(group, "Root-KSK", SelfTestStatus.Warning, anchors.Error));
                else if (anchors.Source is not null)
                    results.Add(new SelfTestResult(group, "Root-KSK", SelfTestStatus.Ok, "Quelle " + anchors.Source + ". " + anchors.Message));
            }

            private void CheckWatchdog(List<SelfTestResult> results)
            {
                const string group = "Wächter";
                Watchdog watchdog = _dnsWebService._dnsServer.Watchdog;

                if (!watchdog.Enabled)
                {
                    results.Add(new SelfTestResult(group, "Status", SelfTestStatus.Info, "Der Wächter ist ausgeschaltet. Bei vollem Datenträger, Speichermangel oder ausgefallenen Diensten greift niemand automatisch ein."));
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

                    results.Add(new SelfTestResult(group, watchdogEvent.Title, SelfTestStatus.Warning, FormatDate(watchdogEvent.Time) + ": " + watchdogEvent.Message));
                }

                if (shown == 0)
                    results.Add(new SelfTestResult(group, "Status", SelfTestStatus.Ok, "Aktiv, in den letzten 24 Stunden war kein Eingriff nötig."));
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
                    results.Add(new SelfTestResult(group, "Systemzeit", SelfTestStatus.Info, "Die Abweichung der Systemzeit ließ sich nicht messen, weil kein HTTPS-Server erreichbar war. Aktuell: " + DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture) + " UTC."));
                    return;
                }

                double absOffset = Math.Abs(offset);
                string measured = "gemessen gegen " + source + " am " + checkedOn.ToLocalTime().ToString("dd.MM.yyyy HH:mm", CultureInfo.InvariantCulture) + ", Genauigkeit etwa ±" + Math.Ceiling(uncertainty).ToString(CultureInfo.InvariantCulture) + " s";
                string amount = (offset > 0 ? "nach" : "vor") + " um etwa " + Math.Round(absOffset).ToString(CultureInfo.InvariantCulture) + " s";

                if (absOffset <= Math.Max(5, uncertainty))
                    results.Add(new SelfTestResult(group, "Systemzeit", SelfTestStatus.Ok, "Die Systemzeit stimmt (" + measured + ")."));
                else if (absOffset <= 60)
                    results.Add(new SelfTestResult(group, "Systemzeit", SelfTestStatus.Warning, "Die Systemzeit geht " + amount + " (" + measured + "). NTP-Synchronisierung prüfen, etwa mit chrony oder systemd-timesyncd."));
                else
                    results.Add(new SelfTestResult(group, "Systemzeit", SelfTestStatus.Error, "Die Systemzeit geht " + amount + " (" + measured + "). DNSSEC-Validierung, TLS-Zertifikate und die Prüfung der Root-Zone können scheitern. NTP einrichten, etwa mit chrony oder systemd-timesyncd."));
            }

            private void CheckSystem(List<SelfTestResult> results)
            {
                const string group = "System";
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
                        results.Add(new SelfTestResult(group, "Zeitsynchronisierung", SelfTestStatus.Ok, "Die Systemzeit wird per NTP synchronisiert."));
                    else if (clockStatus == "unsynchronized")
                        results.Add(new SelfTestResult(group, "Zeitsynchronisierung", SelfTestStatus.Error, "Die Systemzeit wird nicht synchronisiert. Weicht sie ab, scheitern DNSSEC-Validierung, TLS-Zertifikate und die Prüfung der Root-Zone. NTP einrichten, etwa mit chrony oder systemd-timesyncd."));
                    else
                        results.Add(new SelfTestResult(group, "Zeitsynchronisierung", SelfTestStatus.Info, "Ob die Systemzeit synchronisiert wird, lässt sich aus dem Dienst heraus nicht prüfen."));

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
                            results.Add(new SelfTestResult(group, "Arbeitsspeicher", SelfTestStatus.Warning, "Nur noch " + FormatSize(memAvailable) + " von " + FormatSize(memTotal) + " frei. ZenitiumDNS belegt " + FormatSize(workingSet) + ". Cache-Größe oder Blocklisten verkleinern."));
                        else if (memTotal > 0)
                            results.Add(new SelfTestResult(group, "Arbeitsspeicher", SelfTestStatus.Ok, FormatSize(memAvailable) + " von " + FormatSize(memTotal) + " frei, ZenitiumDNS belegt " + FormatSize(workingSet) + "."));
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
                            results.Add(new SelfTestResult(group, "UDP-Puffer", SelfTestStatus.Warning, "Der Kernel begrenzt die UDP-Puffer auf " + FormatSize(Math.Min(rmemMax, wmemMax)) + ", eingestellt sind " + FormatSize(Math.Max(receiveBuffer, sendBuffer)) + ". Bei Lastspitzen gehen Pakete verloren. Abhilfe: sysctl -w net.core.rmem_max=" + receiveBuffer + " net.core.wmem_max=" + sendBuffer));
                        else
                            results.Add(new SelfTestResult(group, "UDP-Puffer", SelfTestStatus.Ok, "Die Kernel-Grenzen erlauben die eingestellten Puffergrößen."));
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
                                    results.Add(new SelfTestResult(group, "Offene Dateien", SelfTestStatus.Warning, "Das Limit für offene Dateien und Verbindungen liegt bei " + softLimit + ". Für viele gleichzeitige TCP-, DoT- und DoH-Verbindungen LimitNOFILE im Dienst erhöhen."));
                                else
                                    results.Add(new SelfTestResult(group, "Offene Dateien", SelfTestStatus.Ok, "Limit " + softLimit + "."));
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
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Error, "Der Ordner " + folder + " ist nicht beschreibbar."));
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
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Ok, "Beschreibbar."));
                        return;
                    }

                    long free = drive.AvailableFreeSpace;

                    if (free < 200L * 1024 * 1024)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Error, "Nur noch " + FormatSize(free) + " frei in " + folder + ". Einstellungen, Cache und Statistik lassen sich bald nicht mehr speichern."));
                    else if (free < 1024L * 1024 * 1024)
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Warning, "Nur noch " + FormatSize(free) + " frei in " + folder + "."));
                    else
                        results.Add(new SelfTestResult(group, title, SelfTestStatus.Ok, FormatSize(free) + " frei in " + folder + "."));
                }

                CheckFolder("Konfigurationsordner", _dnsWebService._configFolder);

                string logFolder = null;

                try
                {
                    logFolder = _dnsWebService._log.LogFolderAbsolutePath;
                }
                catch
                { }

                CheckFolder("Log-Ordner", logFolder);
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
                        results.Add(new SelfTestResult(group, "Prüfung", SelfTestStatus.Warning, "Die Prüfung ist fehlgeschlagen: " + ex.Message));
                    }
                }

                Run("Dienste", CheckServices);

                try
                {
                    await CheckResolutionAsync(results);
                }
                catch (Exception ex)
                {
                    results.Add(new SelfTestResult("Auflösung", "Prüfung", SelfTestStatus.Warning, "Die Prüfung ist fehlgeschlagen: " + ex.Message));
                }

                Run("Zertifikate", CheckCertificates);
                Run("Root-Zone", CheckIanaData);
                Run("Sicherheit", CheckSecurity);
                Run("Filter", CheckFilters);
                Run("Apps", CheckApps);
                Run("Wächter", CheckWatchdog);

                try
                {
                    await CheckClockOffsetAsync(results, "System");
                }
                catch (Exception ex)
                {
                    results.Add(new SelfTestResult("System", "Systemzeit", SelfTestStatus.Warning, "Die Prüfung ist fehlgeschlagen: " + ex.Message));
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
                    if (refresh || (_lastResults is null) || (DateTime.UtcNow > _lastRunOn.AddSeconds(CACHE_SECONDS)))
                    {
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
