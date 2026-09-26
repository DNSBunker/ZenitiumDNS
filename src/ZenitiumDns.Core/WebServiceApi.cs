/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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

using ZenitiumDns.Core.Auth;
using ZenitiumDns.Core.Dns;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
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

            string _checkForUpdateJsonData;
            DateTime _checkForUpdateJsonDataUpdatedOn;
            const int CHECK_FOR_UPDATE_JSON_DATA_CACHE_TIME_SECONDS = 3600;

            #endregion

            #region constructor

            public WebServiceApi(DnsWebService dnsWebService, Uri updateCheckUri)
            {
                _dnsWebService = dnsWebService;
                _updateCheckUri = updateCheckUri;
            }

            #endregion

            #region private

            private async Task<string> GetCheckForUpdateJsonData()
            {
                if ((_checkForUpdateJsonData is null) || (DateTime.UtcNow > _checkForUpdateJsonDataUpdatedOn.AddSeconds(CHECK_FOR_UPDATE_JSON_DATA_CACHE_TIME_SECONDS)))
                {
                    HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                    handler.Proxy = _dnsWebService._dnsServer.Proxy;
                    handler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsWebService._dnsServer.IPv6Mode);
                    handler.DnsClient = _dnsWebService._dnsServer;

                    using (HttpClient http = new HttpClient(handler))
                    {
                        _checkForUpdateJsonData = await http.GetStringAsync(_updateCheckUri);
                        _checkForUpdateJsonDataUpdatedOn = DateTime.UtcNow;
                    }
                }

                return _checkForUpdateJsonData;
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

                if (!_dnsWebService._dnsServer.EnableCheckForUpdate || (_updateCheckUri is null))
                {
                    jsonWriter.WriteBoolean("dnsServerEnableCheckForUpdate", false);
                    jsonWriter.WriteBoolean("updateAvailable", false);

                    _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "Check for update was done {dnsServerEnableCheckForUpdate: False; updateAvailable: False;}");
                    return;
                }

                try
                {
                    string jsonData = await GetCheckForUpdateJsonData();
                    using JsonDocument jsonDocument = JsonDocument.Parse(jsonData);
                    JsonElement jsonResponse = jsonDocument.RootElement;

                    string updateVersion = jsonResponse.GetProperty("updateVersion").GetString();
                    string updateTitle = jsonResponse.GetPropertyValue("updateTitle", null);
                    string updateMessage = jsonResponse.GetPropertyValue("updateMessage", null);
                    string downloadLink = GetHttpUrlOrNull(jsonResponse.GetPropertyValue("downloadLink", null));
                    string instructionsLink = GetHttpUrlOrNull(jsonResponse.GetPropertyValue("instructionsLink", null));
                    string changeLogLink = GetHttpUrlOrNull(jsonResponse.GetPropertyValue("changeLogLink", null));

                    bool updateAvailable = new Version(updateVersion) > _dnsWebService._currentVersion;

                    jsonWriter.WriteBoolean("dnsServerEnableCheckForUpdate", true);
                    jsonWriter.WriteBoolean("updateAvailable", updateAvailable);
                    jsonWriter.WriteString("updateVersion", updateVersion);
                    jsonWriter.WriteString("currentVersion", _dnsWebService.GetServerVersion());

                    if (updateAvailable)
                    {
                        jsonWriter.WriteString("updateTitle", updateTitle);
                        jsonWriter.WriteString("updateMessage", updateMessage);
                        jsonWriter.WriteString("downloadLink", downloadLink);
                        jsonWriter.WriteString("instructionsLink", instructionsLink);
                        jsonWriter.WriteString("changeLogLink", changeLogLink);
                    }

                    _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "Check for update was done {dnsServerEnableCheckForUpdate: True; updateAvailable: " + updateAvailable + "; updateVersion: " + updateVersion + ";}");
                }
                catch (Exception ex)
                {
                    _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "Check for update was done {dnsServerEnableCheckForUpdate: True; updateAvailable: False;}", ex);

                    jsonWriter.WriteBoolean("dnsServerEnableCheckForUpdate", true);
                    jsonWriter.WriteBoolean("updateAvailable", false);
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
                        dnssecErrorMessage = "Die DNSSEC-Validierung ist in den Einstellungen dieses Servers deaktiviert. Er fragt dann ohne DNSSEC an und liefert keine Signaturen (RRSIG) mit, deshalb kann der DNS-Client die Antwort nicht prüfen. Validierung unter Einstellungen > Resolver > DNSSEC aktivieren oder ohne DNSSEC-Prüfung abfragen. Meldung des DNS-Clients: " + dnssecErrorMessage;

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
        }
    }
}
