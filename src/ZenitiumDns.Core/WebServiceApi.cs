/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)
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

using ZenitiumDns.ApplicationCommon;
using ZenitiumDns.Core.Auth;
using ZenitiumDns.Core.Dns;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumLibrary;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;
using ZenitiumLibrary.Net.Http.Client;
using ZenitiumLibrary.Net.Proxy;

namespace ZenitiumDns.Core
{
    public partial class DnsWebService
    {
        class WebServiceApi
        {
            #region variables

            static readonly char[] _domainTrimChars = new char[] { '\t', ' ', '.' };

            readonly DnsWebService _dnsWebService;
            readonly Uri _updateCheckUri;

            ReleaseInfo _latestRelease;
            DateTime _latestReleaseCheckedOn;
            string _loggedUpdateVersion;
            readonly SemaphoreSlim _updateCheckLock = new SemaphoreSlim(1, 1);
            const int UPDATE_CHECK_CACHE_SECONDS = 3600;
            const int UPDATE_CHECK_FAILURE_CACHE_SECONDS = 600;
            const int MAX_RELEASE_NOTES_LENGTH = 20000;

            #endregion

            #region constructor

            public WebServiceApi(DnsWebService dnsWebService, Uri updateCheckUri)
            {
                _dnsWebService = dnsWebService;
                _updateCheckUri = updateCheckUri;
            }

            #endregion

            #region private

            private static bool TryParsePackageVersion(string value, out Version version, out int revision)
            {
                version = null;
                revision = 0;

                if (string.IsNullOrEmpty(value))
                    return false;

                value = value.Trim();

                if (value.StartsWith('v') || value.StartsWith('V'))
                    value = value.Substring(1);

                int dash = value.IndexOf('-');
                string versionPart = dash < 0 ? value : value.Substring(0, dash);

                if (!Version.TryParse(versionPart, out version))
                    return false;

                if ((dash >= 0) && !int.TryParse(value.AsSpan(dash + 1), out revision))
                    return false;

                return true;
            }

            private static int ComparePackageVersions(string x, string y)
            {
                if (!TryParsePackageVersion(x, out Version xVersion, out int xRevision) || !TryParsePackageVersion(y, out Version yVersion, out int yRevision))
                    return 0;

                int result = xVersion.CompareTo(yVersion);
                if (result != 0)
                    return result;

                return xRevision.CompareTo(yRevision);
            }

            private async Task<ReleaseInfo> GetLatestReleaseAsync(bool force)
            {
                await _updateCheckLock.WaitAsync();
                try
                {
                    ReleaseInfo cached = _latestRelease;
                    int cacheSeconds = (cached is null) || (cached.Error is not null) ? UPDATE_CHECK_FAILURE_CACHE_SECONDS : UPDATE_CHECK_CACHE_SECONDS;

                    if ((cached is not null) && (DateTime.UtcNow < _latestReleaseCheckedOn.AddSeconds(force ? 60 : cacheSeconds)))
                        return cached;

                    ReleaseInfo release;

                    try
                    {
                        HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                        handler.Proxy = _dnsWebService._dnsServer.Proxy;
                        handler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsWebService._dnsServer.IPv6Mode);
                        handler.DnsClient = _dnsWebService._dnsServer;

                        using (HttpClient http = new HttpClient(handler))
                        {
                            http.Timeout = TimeSpan.FromSeconds(20);
                            http.DefaultRequestHeaders.UserAgent.ParseAdd("ZenitiumDNS/" + _dnsWebService.GetServerVersion());
                            http.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");

                            string jsonData = await http.GetStringAsync(_updateCheckUri);

                            using JsonDocument jsonDocument = JsonDocument.Parse(jsonData);
                            release = ReleaseInfo.Parse(jsonDocument.RootElement);
                        }
                    }
                    catch (Exception ex)
                    {
                        release = new ReleaseInfo() { Error = ex.Message };

                        if ((cached is null) || (cached.Error is null))
                            _dnsWebService._log.Write("DNS Server failed to check for updates: " + _updateCheckUri.AbsoluteUri, ex);
                    }

                    _latestRelease = release;
                    _latestReleaseCheckedOn = DateTime.UtcNow;

                    return release;
                }
                finally
                {
                    _updateCheckLock.Release();
                }
            }

            private static string GetHttpUrlOrNull(string url)
            {
                if (Uri.TryCreate(url, UriKind.Absolute, out Uri uri) && ((uri.Scheme == Uri.UriSchemeHttps) || (uri.Scheme == Uri.UriSchemeHttp)))
                    return uri.AbsoluteUri;

                return null;
            }

            #endregion

            #region public

            public async Task CheckForUpdateAsync(HttpContext context)
            {
                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                string currentVersion = _dnsWebService.GetServerVersion();

                jsonWriter.WriteString("currentVersion", currentVersion);

                if (!_dnsWebService._dnsServer.EnableCheckForUpdate || (_updateCheckUri is null))
                {
                    jsonWriter.WriteBoolean("dnsServerEnableCheckForUpdate", false);
                    jsonWriter.WriteBoolean("updateAvailable", false);
                    return;
                }

                ReleaseInfo release = await GetLatestReleaseAsync(context.Request.GetQueryOrForm("force", bool.Parse, false));

                jsonWriter.WriteBoolean("dnsServerEnableCheckForUpdate", true);

                if (release.Error is not null)
                {
                    jsonWriter.WriteBoolean("updateAvailable", false);
                    jsonWriter.WriteString("updateCheckError", release.Error);
                    return;
                }

                bool updateAvailable = ComparePackageVersions(release.Version, currentVersion) > 0;

                jsonWriter.WriteBoolean("updateAvailable", updateAvailable);
                jsonWriter.WriteString("updateVersion", release.Version);
                jsonWriter.WriteString("updateTitle", release.Title);
                jsonWriter.WriteString("releaseUrl", release.HtmlUrl);
                jsonWriter.WriteString("publishedAt", release.PublishedAt);

                if (updateAvailable)
                {
                    string architecture = RuntimeInformation.OSArchitecture switch
                    {
                        Architecture.X64 => "amd64",
                        Architecture.Arm64 => "arm64",
                        _ => RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant()
                    };

                    ReleaseAsset debAsset = null;
                    ReleaseAsset checksumsAsset = null;

                    foreach (ReleaseAsset asset in release.Assets)
                    {
                        if (asset.Name.EndsWith("_" + architecture + ".deb", StringComparison.OrdinalIgnoreCase))
                            debAsset = asset;
                        else if (asset.Name.Equals("SHA256SUMS", StringComparison.OrdinalIgnoreCase))
                            checksumsAsset = asset;
                    }

                    jsonWriter.WriteString("releaseNotes", release.Body);

                    if (debAsset is not null)
                    {
                        jsonWriter.WriteString("downloadName", debAsset.Name);
                        jsonWriter.WriteString("downloadLink", debAsset.Url);
                        jsonWriter.WriteNumber("downloadSize", debAsset.Size);
                    }

                    if (checksumsAsset is not null)
                        jsonWriter.WriteString("checksumsLink", checksumsAsset.Url);

                    if (!release.Version.Equals(_loggedUpdateVersion, StringComparison.Ordinal))
                    {
                        _loggedUpdateVersion = release.Version;
                        _dnsWebService._log.Write("ZenitiumDNS " + release.Version + " is available (installed: " + currentVersion + "): " + release.HtmlUrl);
                    }
                }
            }

            public async Task ResolveQueryAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DnsClient, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                string server = request.GetQueryOrForm("server");
                string domain = request.GetQueryOrForm("domain").Trim(_domainTrimChars);
                DnsResourceRecordType type = request.GetQueryOrFormEnum<DnsResourceRecordType>("type");
                DnsTransportProtocol protocol = request.GetQueryOrFormEnum("protocol", DnsTransportProtocol.Udp);
                bool dnssecValidation = request.GetQueryOrForm("dnssec", bool.Parse, false);
                NetworkAddress eDnsClientSubnet = request.GetQueryOrForm("eDnsClientSubnet", NetworkAddress.Parse, null);

                NetProxy proxy = _dnsWebService._dnsServer.Proxy;
                IPv6Mode ipv6Mode = _dnsWebService._dnsServer.IPv6Mode;
                ushort udpPayloadSize = _dnsWebService._dnsServer.UdpPayloadSize;
                bool randomizeName = false;
                bool qnameMinimization = _dnsWebService._dnsServer.QnameMinimization;
                const int RETRIES = 1;
                const int TIMEOUT = 10000;

                DnsDatagram dnsResponse;
                List<DnsDatagram> rawResponses = new List<DnsDatagram>();
                string dnssecErrorMessage = null;
                bool thisServerWithoutDnssec = false;

                if (server.Equals("recursive-resolver", StringComparison.OrdinalIgnoreCase))
                {
                    if (type == DnsResourceRecordType.AXFR)
                        throw new DnsServerException("Cannot do zone transfer (AXFR) for 'recursive-resolver'.");

                    DnsQuestionRecord question;

                    if ((type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress address))
                        question = new DnsQuestionRecord(address, DnsClass.IN);
                    else
                        question = new DnsQuestionRecord(domain, type, DnsClass.IN);

                    DnsCache dnsCache = new DnsCache();
                    dnsCache.MinimumRecordTtl = 0;
                    dnsCache.MaximumRecordTtl = 7 * 24 * 60 * 60;

                    try
                    {
                        dnsResponse = await ZenitiumLibrary.TaskExtensions.TimeoutAsync(async delegate (CancellationToken cancellationToken1)
                        {
                            return await DnsClient.RecursiveResolveAsync(question, dnsCache, proxy, ipv6Mode, udpPayloadSize, randomizeName, qnameMinimization, dnssecValidation, eDnsClientSubnet, RETRIES, TIMEOUT, rawResponses: rawResponses, cancellationToken: cancellationToken1);
                        }, DnsServer.RECURSIVE_RESOLUTION_TIMEOUT);
                    }
                    catch (DnsClientResponseDnssecValidationException ex)
                    {
                        if (ex.InnerException is DnsClientResponseDnssecValidationException ex1)
                            ex = ex1;

                        dnsResponse = ex.Response;
                        dnssecErrorMessage = ex.Message;
                    }
                }
                else if (server.Equals("system-dns", StringComparison.OrdinalIgnoreCase))
                {
                    DnsClient dnsClient = new DnsClient();

                    dnsClient.Proxy = proxy;
                    dnsClient.IPv6Mode = ipv6Mode;
                    dnsClient.RandomizeName = randomizeName;
                    dnsClient.Retries = RETRIES;
                    dnsClient.Timeout = TIMEOUT;
                    dnsClient.UdpPayloadSize = udpPayloadSize;
                    dnsClient.DnssecValidation = dnssecValidation;
                    dnsClient.EDnsClientSubnet = eDnsClientSubnet;

                    try
                    {
                        dnsResponse = await dnsClient.ResolveAsync(domain, type);
                    }
                    catch (DnsClientResponseDnssecValidationException ex)
                    {
                        if (ex.InnerException is DnsClientResponseDnssecValidationException ex1)
                            ex = ex1;

                        dnsResponse = ex.Response;
                        dnssecErrorMessage = ex.Message;
                    }
                }
                else
                {
                    if ((type == DnsResourceRecordType.AXFR) && (protocol == DnsTransportProtocol.Udp))
                        protocol = DnsTransportProtocol.Tcp;

                    NameServerAddress nameServer;

                    if (server.Equals("this-server", StringComparison.OrdinalIgnoreCase))
                    {
                        switch (protocol)
                        {
                            case DnsTransportProtocol.Udp:
                                nameServer = _dnsWebService._dnsServer.ThisServer;
                                break;

                            case DnsTransportProtocol.Tcp:
                                nameServer = _dnsWebService._dnsServer.ThisServer.Clone(DnsTransportProtocol.Tcp);
                                break;

                            case DnsTransportProtocol.Tls:
                                throw new DnsServerException("Cannot use DNS-over-TLS protocol for 'this-server'. Please use the TLS certificate domain name as the server.");

                            case DnsTransportProtocol.Https:
                                throw new DnsServerException("Cannot use DNS-over-HTTPS protocol for 'this-server'. Please use the TLS certificate domain name with a url as the server.");

                            case DnsTransportProtocol.Quic:
                                throw new DnsServerException("Cannot use DNS-over-QUIC protocol for 'this-server'. Please use the TLS certificate domain name as the server.");

                            default:
                                throw new NotSupportedException("DNS transport protocol is not supported: " + protocol.ToString());
                        }

                        proxy = null;
                        thisServerWithoutDnssec = dnssecValidation && !_dnsWebService._dnsServer.DnssecValidation;
                    }
                    else
                    {
                        nameServer = NameServerAddress.Parse(server);

                        if (nameServer.Protocol != protocol)
                            nameServer = nameServer.Clone(protocol);

                        if (nameServer.IsIPEndPointStale)
                            await nameServer.ResolveIPAddressAsync(_dnsWebService._dnsServer, _dnsWebService._dnsServer.IPv6Mode);

                        if ((nameServer.DomainEndPoint is null) && ((protocol == DnsTransportProtocol.Udp) || (protocol == DnsTransportProtocol.Tcp)))
                        {
                            try
                            {
                                await nameServer.ResolveDomainNameAsync(_dnsWebService._dnsServer);
                            }
                            catch
                            { }
                        }
                    }

                    DnsClient dnsClient = new DnsClient(nameServer);

                    dnsClient.Proxy = proxy;
                    dnsClient.IPv6Mode = ipv6Mode;
                    dnsClient.RandomizeName = randomizeName;
                    dnsClient.Retries = RETRIES;
                    dnsClient.Timeout = TIMEOUT;
                    dnsClient.UdpPayloadSize = udpPayloadSize;
                    dnsClient.DnssecValidation = dnssecValidation;
                    dnsClient.EDnsClientSubnet = eDnsClientSubnet;

                    if (dnssecValidation && (type == DnsResourceRecordType.PTR) && IPAddress.TryParse(domain, out IPAddress ptrIp))
                        domain = ptrIp.GetReverseDomain();

                    try
                    {
                        dnsResponse = await dnsClient.ResolveAsync(domain, type);
                    }
                    catch (DnsClientResponseDnssecValidationException ex)
                    {
                        if (ex.InnerException is DnsClientResponseDnssecValidationException ex1)
                            ex = ex1;

                        dnsResponse = ex.Response;
                        dnssecErrorMessage = ex.Message;
                    }

                    if (type == DnsResourceRecordType.AXFR)
                        dnsResponse = dnsResponse.Join();
                }

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                if (dnssecErrorMessage is not null)
                {
                    if (thisServerWithoutDnssec)
                        dnssecErrorMessage = Lang.T("Die DNSSEC-Validierung ist in den Einstellungen dieses Servers deaktiviert. Er fragt dann ohne DNSSEC an und liefert keine Signaturen (RRSIG) mit, deshalb kann der DNS-Client die Antwort nicht prüfen. Validierung unter Einstellungen > Resolver > DNSSEC aktivieren oder ohne DNSSEC-Prüfung abfragen. Meldung des DNS-Clients: ", "DNSSEC validation is disabled in the settings of this server. It then queries without DNSSEC and returns no signatures (RRSIG), so the DNS client cannot verify the answer. Enable validation under Settings > Resolver > DNSSEC or query without DNSSEC validation. Message from the DNS client: ") + dnssecErrorMessage;

                    jsonWriter.WriteString("warningMessage", dnssecErrorMessage);
                }

                jsonWriter.WritePropertyName("result");
                dnsResponse.SerializeTo(jsonWriter);

                jsonWriter.WritePropertyName("rawResponses");
                jsonWriter.WriteStartArray();

                for (int i = 0; i < rawResponses.Count; i++)
                    rawResponses[i].SerializeTo(jsonWriter);

                jsonWriter.WriteEndArray();
            }

            public async Task HealthCheckAsync(HttpContext context)
            {
                if (context.Items["session"] is UserSession)
                {
                    User sessionUser = _dnsWebService.GetSessionUser(context);

                    if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DnsClient, sessionUser, PermissionFlag.View))
                        throw new DnsWebServiceException("Access was denied.");
                }

                HttpRequest request = context.Request;

                string domain = request.GetQueryOrForm("domain", "localhost");
                DnsResourceRecordType type = request.GetQueryOrFormEnum("type", DnsResourceRecordType.A);

                _ = DnsClient.ParseResponseA(await _dnsWebService._dnsServer.DirectQueryAsync(new DnsQuestionRecord(domain, type, DnsClass.IN)));
            }

            #endregion

            sealed class ReleaseAsset
            {
                public string Name;
                public string Url;
                public long Size;
            }

            sealed class ReleaseInfo
            {
                public string Version;
                public string Title;
                public string Body;
                public string HtmlUrl;
                public string PublishedAt;
                public List<ReleaseAsset> Assets = new List<ReleaseAsset>();
                public string Error;

                public static ReleaseInfo Parse(JsonElement jsonRelease)
                {
                    ReleaseInfo release = new ReleaseInfo();

                    string tagName = jsonRelease.GetProperty("tag_name").GetString();

                    if (!TryParsePackageVersion(tagName, out _, out _))
                        throw new InvalidDataException("The latest release has an invalid version tag: " + tagName);

                    release.Version = tagName.TrimStart('v', 'V');
                    release.Title = jsonRelease.GetPropertyValue("name", null) ?? ("ZenitiumDNS " + release.Version);
                    release.Body = jsonRelease.GetPropertyValue("body", null);
                    release.HtmlUrl = GetHttpUrlOrNull(jsonRelease.GetPropertyValue("html_url", null));
                    release.PublishedAt = jsonRelease.GetPropertyValue("published_at", null);

                    if ((release.Body is not null) && (release.Body.Length > MAX_RELEASE_NOTES_LENGTH))
                        release.Body = release.Body.Substring(0, MAX_RELEASE_NOTES_LENGTH);

                    if (jsonRelease.TryGetProperty("assets", out JsonElement jsonAssets) && (jsonAssets.ValueKind == JsonValueKind.Array))
                    {
                        foreach (JsonElement jsonAsset in jsonAssets.EnumerateArray())
                        {
                            string name = jsonAsset.GetPropertyValue("name", null);
                            string url = GetHttpUrlOrNull(jsonAsset.GetPropertyValue("browser_download_url", null));

                            if ((name is null) || (url is null) || !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                                continue;

                            release.Assets.Add(new ReleaseAsset() { Name = name, Url = url, Size = jsonAsset.TryGetProperty("size", out JsonElement jsonSize) && jsonSize.TryGetInt64(out long size) ? size : 0 });
                        }
                    }

                    return release;
                }
            }
        }
    }
}
