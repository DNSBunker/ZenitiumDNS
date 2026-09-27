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

using ZenitiumDns.Core.Auth;
using ZenitiumDns.Core.Dns;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.Sockets;
using System.Text.Json;
using System.Threading.Tasks;
using ZenitiumLibrary;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ClientConnection;
using ZenitiumLibrary.Net.Dns.ResourceRecords;
using ZenitiumLibrary.Net.Http.Client;
using ZenitiumLibrary.Net.Proxy;

namespace ZenitiumDns.Core
{
    public partial class DnsWebService
    {
        sealed class WebServiceSettingsApi
        {
            #region variables

            readonly DnsWebService _dnsWebService;

            #endregion

            #region constructor

            public WebServiceSettingsApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

            private static void WritePrefixLimits(Utf8JsonWriter jsonWriter, string propertyName, IReadOnlyDictionary<int, (int, int)> prefixLimits)
            {
                jsonWriter.WriteStartArray(propertyName);

                foreach (KeyValuePair<int, (int, int)> prefixLimit in prefixLimits)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteNumber("prefix", prefixLimit.Key);
                    jsonWriter.WriteNumber("udpLimit", prefixLimit.Value.Item1);
                    jsonWriter.WriteNumber("tcpLimit", prefixLimit.Value.Item2);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();
            }

            private static bool TryReadPrefixLimits(HttpRequest request, string name, out Dictionary<int, (int, int)> prefixLimits)
            {
                if (!request.TryQueryOrFormArray(name, delegate (JsonElement jsonObject)
                {
                    int prefix = jsonObject.GetProperty("prefix").GetInt32();
                    int udpLimit = jsonObject.GetProperty("udpLimit").GetInt32();
                    int tcpLimit = jsonObject.GetProperty("tcpLimit").GetInt32();

                    return new KeyValuePair<int, (int, int)>(prefix, (udpLimit, tcpLimit));
                }, delegate (ArraySegment<string> tableRow)
                {
                    int prefix = int.Parse(tableRow[0]);
                    int udpLimit = int.Parse(tableRow[1]);
                    int tcpLimit = int.Parse(tableRow[2]);

                    return new KeyValuePair<int, (int, int)>(prefix, (udpLimit, tcpLimit));
                },
                    3, out KeyValuePair<int, (int, int)>[] entries, '|'))
                {
                    prefixLimits = null;
                    return false;
                }

                prefixLimits = new Dictionary<int, (int, int)>(entries.Length);

                foreach (KeyValuePair<int, (int, int)> entry in entries)
                    prefixLimits[entry.Key] = entry.Value;

                return true;
            }

            private void WriteDnsSettings(Utf8JsonWriter jsonWriter)
            {
                jsonWriter.WriteString("version", _dnsWebService.GetServerVersion());
                _dnsWebService.WriteVersionInfo(jsonWriter);
                jsonWriter.WriteString("uptimestamp", _dnsWebService._uptimestamp);

                jsonWriter.WriteString("dnsServerDomain", _dnsWebService._dnsServer.ServerDomain);

                jsonWriter.WriteStringArray("dnsServerLocalEndPoints", _dnsWebService._dnsServer.LocalEndPoints);

                jsonWriter.WriteStringArray("dnsServerIPv4SourceAddresses", DnsClientConnection.IPv4SourceAddresses);
                jsonWriter.WriteStringArray("dnsServerIPv6SourceAddresses", DnsClientConnection.IPv6SourceAddresses);

                jsonWriter.WriteNumber("defaultRecordTtl", _dnsWebService._dnsServer.AuthZoneManager.DefaultRecordTtl);
                jsonWriter.WriteNumber("defaultNsRecordTtl", _dnsWebService._dnsServer.AuthZoneManager.DefaultNsRecordTtl);
                jsonWriter.WriteNumber("defaultSoaRecordTtl", _dnsWebService._dnsServer.AuthZoneManager.DefaultSoaRecordTtl);
                jsonWriter.WriteString("defaultResponsiblePerson", _dnsWebService._dnsServer.DefaultResponsiblePerson?.Address);

                jsonWriter.WriteBoolean("dnsServerEnableCheckForUpdate", _dnsWebService._dnsServer.EnableCheckForUpdate);

                jsonWriter.WriteString("ipv6Mode", _dnsWebService._dnsServer.IPv6Mode.ToString());
                jsonWriter.WriteBoolean("preferIPv6", _dnsWebService._dnsServer.IPv6Mode == IPv6Mode.Preferred);
                jsonWriter.WriteBoolean("ipv6AutoFallback", _dnsWebService._dnsServer.IPv6AutoFallback);
                jsonWriter.WriteBoolean("enableUdpSocketPool", _dnsWebService._dnsServer.EnableUdpSocketPool);
                jsonWriter.WriteNumber("udpListenerThreads", _dnsWebService._dnsServer.UdpListenerThreads);
                jsonWriter.WriteNumber("maxPendingStreamRequests", _dnsWebService._dnsServer.MaxPendingStreamRequests);

                jsonWriter.WriteBoolean("requestFilterMalformed", _dnsWebService._dnsServer.RequestFilterMalformed);
                jsonWriter.WriteNumber("requestFilterMaxSize", _dnsWebService._dnsServer.RequestFilterMaxSize);
                jsonWriter.WriteBoolean("requestFilterOpcode", _dnsWebService._dnsServer.RequestFilterOpcode);
                jsonWriter.WriteBoolean("requestFilterClass", _dnsWebService._dnsServer.RequestFilterClass);
                jsonWriter.WriteBoolean("requestFilterAny", _dnsWebService._dnsServer.RequestFilterAny);
                jsonWriter.WriteBoolean("requestFilterZoneTransfer", _dnsWebService._dnsServer.RequestFilterZoneTransfer);
                jsonWriter.WriteBoolean("requestFilterNoRecursion", _dnsWebService._dnsServer.RequestFilterNoRecursion);
                jsonWriter.WriteBoolean("requestFilterEdnsVersion", _dnsWebService._dnsServer.RequestFilterEdnsVersion);
                jsonWriter.WriteBoolean("requestFilterRefuseOnly", _dnsWebService._dnsServer.RequestFilterRefuseOnly);

                jsonWriter.WriteStartObject("requestFilterMatches");

                foreach (RequestFilterRule rule in Enum.GetValues<RequestFilterRule>())
                    jsonWriter.WriteNumber(rule.GetApiName(), _dnsWebService._dnsServer.GetRequestFilterMatches(rule));

                jsonWriter.WriteEndObject();

                ClientBlockListManager clientBlockListManager = _dnsWebService._dnsServer.ClientBlockListManager;

                jsonWriter.WriteStartArray("clientBlockListUrls");

                foreach (Uri listUrl in clientBlockListManager.ListUrls)
                    jsonWriter.WriteStringValue(listUrl.AbsoluteUri);

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("clientBlockListUpdateIntervalHours", clientBlockListManager.UpdateIntervalHours);
                jsonWriter.WriteNumber("clientBlockListAddressRanges", clientBlockListManager.AddressRanges);
                jsonWriter.WriteNumber("clientBlockListDrops", clientBlockListManager.Drops);

                if (clientBlockListManager.LastUpdatedOn == DateTime.MinValue)
                    jsonWriter.WriteNull("clientBlockListLastUpdatedOn");
                else
                    jsonWriter.WriteString("clientBlockListLastUpdatedOn", clientBlockListManager.LastUpdatedOn);

                jsonWriter.WriteStartArray("socketPoolExcludedPorts");

                ushort[] socketPoolExcludedPorts = UdpClientConnection.SocketPoolExcludedPorts;
                if (socketPoolExcludedPorts is not null)
                {
                    foreach (ushort excludedPort in socketPoolExcludedPorts)
                        jsonWriter.WriteNumberValue(excludedPort);
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("udpPayloadSize", _dnsWebService._dnsServer.UdpPayloadSize);

                jsonWriter.WriteBoolean("dnssecValidation", _dnsWebService._dnsServer.DnssecValidation);
                jsonWriter.WriteBoolean("dnssecPostQuantumDowngradeProtection", _dnsWebService._dnsServer.DnssecPostQuantumDowngradeProtection);

                jsonWriter.WriteBoolean("eDnsClientSubnet", _dnsWebService._dnsServer.EDnsClientSubnet);
                jsonWriter.WriteNumber("eDnsClientSubnetIPv4PrefixLength", _dnsWebService._dnsServer.EDnsClientSubnetIPv4PrefixLength);
                jsonWriter.WriteNumber("eDnsClientSubnetIPv6PrefixLength", _dnsWebService._dnsServer.EDnsClientSubnetIPv6PrefixLength);
                jsonWriter.WriteString("eDnsClientSubnetIpv4Override", _dnsWebService._dnsServer.EDnsClientSubnetIpv4Override?.ToString());
                jsonWriter.WriteString("eDnsClientSubnetIpv6Override", _dnsWebService._dnsServer.EDnsClientSubnetIpv6Override?.ToString());

                WritePrefixLimits(jsonWriter, "qpsPrefixLimitsIPv4", _dnsWebService._dnsServer.QpsPrefixLimitsIPv4);
                WritePrefixLimits(jsonWriter, "qpsPrefixLimitsIPv6", _dnsWebService._dnsServer.QpsPrefixLimitsIPv6);

                jsonWriter.WriteNumber("rateLimitBurstSeconds", _dnsWebService._dnsServer.RateLimitBurstSeconds);
                jsonWriter.WriteNumber("rateLimitUdpTruncationPercentage", _dnsWebService._dnsServer.RateLimitUdpTruncationPercentage);

                jsonWriter.WritePropertyName("rateLimitBypassList");
                jsonWriter.WriteStartArray();

                if (_dnsWebService._dnsServer.RateLimitBypassList is not null)
                {
                    foreach (NetworkAddress network in _dnsWebService._dnsServer.RateLimitBypassList)
                        jsonWriter.WriteStringValue(network.ToString());
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("clientTimeout", _dnsWebService._dnsServer.ClientTimeout);
                jsonWriter.WriteNumber("tcpSendTimeout", _dnsWebService._dnsServer.TcpSendTimeout);
                jsonWriter.WriteNumber("tcpReceiveTimeout", _dnsWebService._dnsServer.TcpReceiveTimeout);
                jsonWriter.WriteNumber("quicIdleTimeout", _dnsWebService._dnsServer.QuicIdleTimeout);
                jsonWriter.WriteNumber("quicMaxInboundStreams", _dnsWebService._dnsServer.QuicMaxInboundStreams);
                jsonWriter.WriteNumber("listenBacklog", _dnsWebService._dnsServer.ListenBacklog);
                jsonWriter.WriteNumber("udpSendBufferSizeKB", _dnsWebService._dnsServer.UdpSendBufferSizeKB);
                jsonWriter.WriteNumber("udpReceiveBufferSizeKB", _dnsWebService._dnsServer.UdpReceiveBufferSizeKB);
                jsonWriter.WriteNumber("maxConcurrentResolutionsPerCore", _dnsWebService._dnsServer.MaxConcurrentResolutionsPerCore);

                jsonWriter.WritePropertyName("webServiceLocalAddresses");
                jsonWriter.WriteStartArray();

                foreach (IPAddress localAddress in _dnsWebService._webServiceLocalAddresses)
                {
                    if (localAddress.AddressFamily == AddressFamily.InterNetworkV6)
                        jsonWriter.WriteStringValue("[" + localAddress.ToString() + "]");
                    else
                        jsonWriter.WriteStringValue(localAddress.ToString());
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("webServiceHttpPort", _dnsWebService._webServiceHttpPort);

                jsonWriter.WriteBoolean("webServiceEnableHttpUnixSocket", _dnsWebService._webServiceEnableHttpUnixSocket);
                jsonWriter.WriteString("webServiceHttpUnixSocket", _dnsWebService._webServiceHttpUnixSocket);

                jsonWriter.WriteBoolean("webServiceEnableTlsUnixSocket", _dnsWebService._webServiceEnableTlsUnixSocket);
                jsonWriter.WriteString("webServiceTlsUnixSocket", _dnsWebService._webServiceTlsUnixSocket);

                jsonWriter.WriteBoolean("webServiceEnableTls", _dnsWebService._webServiceEnableTls);
                jsonWriter.WriteBoolean("webServiceEnableHttp3", _dnsWebService._webServiceEnableHttp3);
                jsonWriter.WriteBoolean("webServiceHttpToTlsRedirect", _dnsWebService._webServiceHttpToTlsRedirect);
                jsonWriter.WriteBoolean("webServiceUseSelfSignedTlsCertificate", _dnsWebService._webServiceUseSelfSignedTlsCertificate);

                jsonWriter.WriteNumber("webServiceTlsPort", _dnsWebService._webServiceTlsPort);

                jsonWriter.WritePropertyName("webServiceReverseProxyAddresses");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._webServiceReverseProxyAddresses is not null)
                    {
                        foreach (NetworkAccessControl nac in _dnsWebService._webServiceReverseProxyAddresses)
                            jsonWriter.WriteStringValue(nac.ToString());
                    }

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteString("webServiceRealIpHeader", _dnsWebService._webServiceRealIpHeader);
                jsonWriter.WriteString("webServiceCspFrameAncestorsHeader", _dnsWebService._webServiceCspFrameAncestorsHeader);
                jsonWriter.WriteString("webServiceTlsCertificatePath", _dnsWebService._webServiceTlsCertificatePath);
                jsonWriter.WriteString("webServiceTlsCertificatePassword", string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath) ? null : "************");
                jsonWriter.WriteString("webServiceTlsCertificateKeyPath", _dnsWebService._webServiceTlsCertificateKeyPath);

                jsonWriter.WriteBoolean("enableEDnsClientSubnetSourceAddress", _dnsWebService._dnsServer.EnableEDnsClientSubnetSourceAddress);
                jsonWriter.WriteBoolean("enableDnsOverUdpProxy", _dnsWebService._dnsServer.EnableDnsOverUdpProxy);
                jsonWriter.WriteBoolean("enableDnsOverTcpProxy", _dnsWebService._dnsServer.EnableDnsOverTcpProxy);
                jsonWriter.WriteBoolean("enableDnsOverHttp", _dnsWebService._dnsServer.EnableDnsOverHttp);
                jsonWriter.WriteBoolean("enableDnsOverHttpUnixSocket", _dnsWebService._dnsServer.EnableDnsOverHttpUnixSocket);
                jsonWriter.WriteBoolean("enableDnsOverHttpsUnixSocket", _dnsWebService._dnsServer.EnableDnsOverHttpsUnixSocket);
                jsonWriter.WriteBoolean("enableDnsOverTls", _dnsWebService._dnsServer.EnableDnsOverTls);
                jsonWriter.WriteBoolean("enableDnsOverHttps", _dnsWebService._dnsServer.EnableDnsOverHttps);
                jsonWriter.WriteBoolean("enableDnsOverHttp3", _dnsWebService._dnsServer.EnableDnsOverHttp3);
                jsonWriter.WriteBoolean("enableDnsOverQuic", _dnsWebService._dnsServer.EnableDnsOverQuic);

                jsonWriter.WriteBoolean("enableDnsOverHttpHelpRedirect", _dnsWebService._dnsServer.EnableDnsOverHttpHelpRedirect);

                jsonWriter.WriteNumber("dnsOverUdpProxyPort", _dnsWebService._dnsServer.DnsOverUdpProxyPort);
                jsonWriter.WriteNumber("dnsOverTcpProxyPort", _dnsWebService._dnsServer.DnsOverTcpProxyPort);
                jsonWriter.WriteNumber("dnsOverHttpPort", _dnsWebService._dnsServer.DnsOverHttpPort);
                jsonWriter.WriteString("dnsOverHttpUnixSocket", _dnsWebService._dnsServer.DnsOverHttpUnixSocket);
                jsonWriter.WriteString("dnsOverHttpsUnixSocket", _dnsWebService._dnsServer.DnsOverHttpsUnixSocket);
                jsonWriter.WriteNumber("dnsOverTlsPort", _dnsWebService._dnsServer.DnsOverTlsPort);
                jsonWriter.WriteNumber("dnsOverHttpsPort", _dnsWebService._dnsServer.DnsOverHttpsPort);
                jsonWriter.WriteNumber("dnsOverQuicPort", _dnsWebService._dnsServer.DnsOverQuicPort);

                jsonWriter.WritePropertyName("dnsReverseProxyNetworkACL");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._dnsServer.DnsReverseProxyNetworkACL is not null)
                    {
                        foreach (NetworkAccessControl nac in _dnsWebService._dnsServer.DnsReverseProxyNetworkACL)
                            jsonWriter.WriteStringValue(nac.ToString());
                    }

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteString("dnsOverHttpRealIpHeader", _dnsWebService._dnsServer.DnsOverHttpRealIpHeader);
                jsonWriter.WriteString("dnsTlsCertificatePath", _dnsWebService._dnsServer.DnsTlsCertificatePath);
                jsonWriter.WriteString("dnsTlsCertificatePassword", string.IsNullOrEmpty(_dnsWebService._dnsServer.DnsTlsCertificatePath) ? null : "************");
                jsonWriter.WriteString("dnsTlsCertificateKeyPath", _dnsWebService._dnsServer.DnsTlsCertificateKeyPath);

                jsonWriter.WriteBoolean("enableDdr", _dnsWebService._dnsServer.EnableDdr);
                jsonWriter.WriteBoolean("ddrOnlyUnencrypted", _dnsWebService._dnsServer.DdrOnlyUnencrypted);
                jsonWriter.WriteBoolean("ddrProxyDoh", _dnsWebService._dnsServer.DdrProxyDoh);
                jsonWriter.WriteNumber("ddrProxyDohPort", _dnsWebService._dnsServer.DdrProxyDohPort);
                jsonWriter.WriteBoolean("ddrProxyDohHttp3", _dnsWebService._dnsServer.DdrProxyDohHttp3);
                jsonWriter.WriteString("do53Mode", _dnsWebService._dnsServer.Do53Mode.ToString());
                jsonWriter.WriteString("eDnsPaddingMode", _dnsWebService._dnsServer.EDnsPaddingMode.ToString());
                jsonWriter.WriteStartArray("ddrRecords");

                foreach (DnsResourceRecord ddrRecord in _dnsWebService._dnsServer.GetDdrRecords())
                    jsonWriter.WriteStringValue(ddrRecord.ToZoneFileEntry());

                jsonWriter.WriteEndArray();

                jsonWriter.WriteString("recursion", _dnsWebService._dnsServer.Recursion.ToString());

                jsonWriter.WritePropertyName("recursionNetworkACL");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._dnsServer.RecursionNetworkACL is not null)
                    {
                        foreach (NetworkAccessControl nac in _dnsWebService._dnsServer.RecursionNetworkACL)
                            jsonWriter.WriteStringValue(nac.ToString());
                    }

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteBoolean("randomizeName", _dnsWebService._dnsServer.RandomizeName);
                jsonWriter.WriteBoolean("qnameMinimization", _dnsWebService._dnsServer.QnameMinimization);
                jsonWriter.WriteBoolean("locallyServedDnsZones", _dnsWebService._dnsServer.LocallyServedDnsZones);

                jsonWriter.WriteNumber("resolverRetries", _dnsWebService._dnsServer.ResolverRetries);
                jsonWriter.WriteNumber("resolverTimeout", _dnsWebService._dnsServer.ResolverTimeout);
                jsonWriter.WriteNumber("resolverConcurrency", _dnsWebService._dnsServer.ResolverConcurrency);
                jsonWriter.WriteNumber("resolverMaxStackCount", _dnsWebService._dnsServer.ResolverMaxStackCount);

                jsonWriter.WriteBoolean("saveCache", _dnsWebService._dnsServer.SaveCacheToDisk);
                jsonWriter.WriteBoolean("serveStale", _dnsWebService._dnsServer.ServeStale);
                jsonWriter.WriteNumber("serveStaleTtl", _dnsWebService._dnsServer.CacheZoneManager.ServeStaleTtl);
                jsonWriter.WriteNumber("serveStaleAnswerTtl", _dnsWebService._dnsServer.CacheZoneManager.ServeStaleAnswerTtl);
                jsonWriter.WriteNumber("serveStaleResetTtl", _dnsWebService._dnsServer.CacheZoneManager.ServeStaleResetTtl);
                jsonWriter.WriteNumber("serveStaleMaxWaitTime", _dnsWebService._dnsServer.ServeStaleMaxWaitTime);

                jsonWriter.WriteNumber("cacheMaximumEntries", _dnsWebService._dnsServer.CacheZoneManager.MaximumEntries);
                jsonWriter.WriteNumber("cacheMinimumRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.MinimumRecordTtl);
                jsonWriter.WriteNumber("cacheMaximumRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.MaximumRecordTtl);
                jsonWriter.WriteNumber("cacheNegativeRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.NegativeRecordTtl);
                jsonWriter.WriteNumber("cacheMaximumNegativeRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.MaximumNegativeRecordTtl);
                jsonWriter.WriteNumber("cacheFailureRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.FailureRecordTtl);

                jsonWriter.WriteNumber("cachePrefetchEligibility", _dnsWebService._dnsServer.CachePrefetchEligibility);
                jsonWriter.WriteNumber("cachePrefetchTrigger", _dnsWebService._dnsServer.CachePrefetchTrigger);

                jsonWriter.WriteBoolean("enableBlocking", _dnsWebService._dnsServer.EnableBlocking);
                jsonWriter.WriteBoolean("allowTxtBlockingReport", _dnsWebService._dnsServer.AllowTxtBlockingReport);

                jsonWriter.WritePropertyName("blockingBypassList");
                jsonWriter.WriteStartArray();

                if (_dnsWebService._dnsServer.BlockingBypassList is not null)
                {
                    foreach (NetworkAddress network in _dnsWebService._dnsServer.BlockingBypassList)
                        jsonWriter.WriteStringValue(network.ToString());
                }

                jsonWriter.WriteEndArray();

                if (!_dnsWebService._dnsServer.EnableBlocking && (DateTime.UtcNow < _dnsWebService._dnsServer.BlockListZoneManager.TemporaryDisableBlockingTill))
                    jsonWriter.WriteString("temporaryDisableBlockingTill", _dnsWebService._dnsServer.BlockListZoneManager.TemporaryDisableBlockingTill);

                jsonWriter.WriteString("blockingType", _dnsWebService._dnsServer.BlockingType.ToString());
                jsonWriter.WriteNumber("blockingAnswerTtl", _dnsWebService._dnsServer.BlockingAnswerTtl);
                jsonWriter.WriteNumber("blockingNegativeTtl", _dnsWebService._dnsServer.BlockingNegativeTtl);
                jsonWriter.WriteString("blockingReportText", _dnsWebService._dnsServer.BlockingReportText);
                jsonWriter.WriteBoolean("blockFirefoxCanaryDomain", _dnsWebService._dnsServer.BlockFirefoxCanaryDomain);
                jsonWriter.WriteBoolean("forceChromePreflight", _dnsWebService._dnsServer.ForceChromePreflight);
                jsonWriter.WriteBoolean("enableLiveMonitoring", _dnsWebService._dnsServer.SystemMonitor.Enabled);
                jsonWriter.WriteBoolean("enableWatchdog", _dnsWebService._dnsServer.Watchdog.Enabled);

                jsonWriter.WriteStartObject("ianaData");
                _dnsWebService._dnsServer.IanaDataManager.WriteStatus(jsonWriter);
                jsonWriter.WriteEndObject();
                jsonWriter.WriteStringArray("autoAllowedNames", _dnsWebService._dnsServer.AutoAllowedNames);

                jsonWriter.WritePropertyName("customBlockingAddresses");
                jsonWriter.WriteStartArray();

                foreach (DnsARecordData record in _dnsWebService._dnsServer.CustomBlockingARecords)
                    jsonWriter.WriteStringValue(record.Address.ToString());

                foreach (DnsAAAARecordData record in _dnsWebService._dnsServer.CustomBlockingAAAARecords)
                    jsonWriter.WriteStringValue(record.Address.ToString());

                jsonWriter.WriteEndArray();

                jsonWriter.WritePropertyName("blockListUrls");

                if (_dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Count == 0)
                {
                    jsonWriter.WriteNullValue();
                }
                else
                {
                    jsonWriter.WriteStartArray();

                    foreach (string blockListUrl in _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls)
                        jsonWriter.WriteStringValue(blockListUrl);

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteNumber("blockListUpdateIntervalHours", _dnsWebService._dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours);

                if (_dnsWebService._dnsServer.BlockListZoneManager.BlockListUpdateEnabled)
                {
                    DateTime blockListNextUpdatedOn = _dnsWebService._dnsServer.BlockListZoneManager.BlockListLastUpdatedOn.AddHours(_dnsWebService._dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours);

                    jsonWriter.WriteString("blockListNextUpdatedOn", blockListNextUpdatedOn);
                }

                jsonWriter.WritePropertyName("proxy");
                if (_dnsWebService._dnsServer.Proxy == null)
                {
                    jsonWriter.WriteNullValue();
                }
                else
                {
                    jsonWriter.WriteStartObject();

                    NetProxy proxy = _dnsWebService._dnsServer.Proxy;

                    jsonWriter.WriteString("type", proxy.Type.ToString());
                    jsonWriter.WriteString("address", proxy.Address);
                    jsonWriter.WriteNumber("port", proxy.Port);

                    NetworkCredential credential = proxy.Credential;
                    if (credential != null)
                    {
                        jsonWriter.WriteString("username", credential.UserName);
                        jsonWriter.WriteString("password", credential.Password);
                    }

                    jsonWriter.WritePropertyName("bypass");
                    jsonWriter.WriteStartArray();

                    foreach (NetProxyBypassItem item in proxy.BypassList)
                        jsonWriter.WriteStringValue(item.Value);

                    jsonWriter.WriteEndArray();

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WritePropertyName("forwarders");

                DnsTransportProtocol forwarderProtocol = DnsTransportProtocol.Udp;

                if (_dnsWebService._dnsServer.Forwarders == null)
                {
                    jsonWriter.WriteNullValue();
                }
                else
                {
                    forwarderProtocol = _dnsWebService._dnsServer.Forwarders[0].Protocol;

                    jsonWriter.WriteStartArray();

                    foreach (NameServerAddress forwarder in _dnsWebService._dnsServer.Forwarders)
                        jsonWriter.WriteStringValue(forwarder.OriginalAddress);

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteString("forwarderProtocol", forwarderProtocol.ToString());
                jsonWriter.WriteBoolean("concurrentForwarding", _dnsWebService._dnsServer.ConcurrentForwarding);

                jsonWriter.WriteNumber("forwarderRetries", _dnsWebService._dnsServer.ForwarderRetries);
                jsonWriter.WriteNumber("forwarderTimeout", _dnsWebService._dnsServer.ForwarderTimeout);
                jsonWriter.WriteNumber("forwarderConcurrency", _dnsWebService._dnsServer.ForwarderConcurrency);

                jsonWriter.WriteBoolean("enableLogging", _dnsWebService._log.LoggingType != LoggingType.None);
                jsonWriter.WriteString("loggingType", _dnsWebService._log.LoggingType.ToString());
                jsonWriter.WriteBoolean("ignoreResolverLogs", _dnsWebService._dnsServer.ResolverLogManager == null);
                jsonWriter.WriteBoolean("logQueries", _dnsWebService._dnsServer.QueryLogManager != null);
                jsonWriter.WriteBoolean("noStackTrace", _dnsWebService._log.NoStackTrace);
                jsonWriter.WriteBoolean("hideClientAddresses", _dnsWebService._log.HideClientAddresses);
                jsonWriter.WriteBoolean("useLocalTime", _dnsWebService._log.UseLocalTime);
                jsonWriter.WriteString("logFolder", _dnsWebService._log.LogFolder);
                jsonWriter.WriteNumber("maxLogFileDays", _dnsWebService._log.MaxLogFileDays);

                jsonWriter.WriteBoolean("enableInMemoryStats", _dnsWebService._dnsServer.StatsManager.EnableInMemoryStats);
                jsonWriter.WriteNumber("maxStatFileDays", _dnsWebService._dnsServer.StatsManager.MaxStatFileDays);
            }

            #endregion

            #region public

            public void GetDnsSettings(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteDnsSettings(jsonWriter);
            }

            public async Task SetDnsSettingsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                bool serverDomainChanged = false;
                bool webServiceLocalAddressesChanged = false;
                bool restartDnsService = false;
                bool restartWebService = false;
                IReadOnlyList<IPAddress> oldWebServiceLocalAddresses = _dnsWebService._webServiceLocalAddresses;
                int oldWebServiceHttpPort = _dnsWebService._webServiceHttpPort;
                int oldWebServiceTlsPort = _dnsWebService._webServiceTlsPort;
                bool _webServiceEnablingTls = false;

                HttpRequest request = context.Request;
                JsonDocument jsonDocument = null;

                if (request.HasJsonContentType())
                {
                    jsonDocument = await JsonDocument.ParseAsync(request.Body);
                    context.Items["jsonContent"] = jsonDocument;
                }

                {
                    bool effectiveEnableDdr = request.TryGetQueryOrForm("enableDdr", bool.Parse, out bool newEnableDdr) ? newEnableDdr : _dnsWebService._dnsServer.EnableDdr;
                    DnsServerDo53Mode effectiveDo53Mode = request.TryGetQueryOrFormEnum("do53Mode", out DnsServerDo53Mode newDo53Mode) ? newDo53Mode : _dnsWebService._dnsServer.Do53Mode;

                    if (!effectiveEnableDdr && ((effectiveDo53Mode == DnsServerDo53Mode.DdrOnlyDrop) || (effectiveDo53Mode == DnsServerDo53Mode.DdrOnlyRefused)))
                        throw new DnsWebServiceException("Do53 can be restricted to DDR only when DDR is enabled.");

                    string ddrProxyDohPortValue = request.QueryOrForm("ddrProxyDohPort");
                    if ((ddrProxyDohPortValue is not null) && (!ushort.TryParse(ddrProxyDohPortValue, out ushort ddrProxyDohPortCheck) || (ddrProxyDohPortCheck == 0)))
                        throw new DnsWebServiceException("DoH port for DDR must be between 1 and 65535.");
                }

                try
                {
                    try
                    {
                        #region general

                        if (request.TryGetQueryOrForm("dnsServerDomain", out string dnsServerDomain))
                        {
                            dnsServerDomain = dnsServerDomain.TrimEnd('.');

                            if (!_dnsWebService._dnsServer.ServerDomain.Equals(dnsServerDomain, StringComparison.OrdinalIgnoreCase))
                            {
                                _dnsWebService._dnsServer.ServerDomain = dnsServerDomain;
                                serverDomainChanged = true;
                            }
                        }

                        if (request.TryQueryOrFormArray("dnsServerLocalEndPoints", InterfaceEndPoint.Parse, out IPEndPoint[] dnsServerLocalEndPoints))
                        {
                            if (dnsServerLocalEndPoints.Length == 0)
                            {
                                dnsServerLocalEndPoints = [new IPEndPoint(IPAddress.Any, 53), new IPEndPoint(IPAddress.IPv6Any, 53)];
                            }
                            else
                            {
                                foreach (IPEndPoint localEndPoint in dnsServerLocalEndPoints)
                                {
                                    if (localEndPoint.Port == 0)
                                        localEndPoint.Port = 53;
                                }
                            }

                            if (!_dnsWebService._dnsServer.LocalEndPoints.HasSameItems(dnsServerLocalEndPoints))
                                restartDnsService = true;

                            _dnsWebService._dnsServer.LocalEndPoints = dnsServerLocalEndPoints;
                        }

                        if (request.TryQueryOrFormArray("dnsServerIPv4SourceAddresses", NetworkAddress.Parse, out NetworkAddress[] dnsServerIPv4SourceAddresses))
                            DnsClientConnection.IPv4SourceAddresses = dnsServerIPv4SourceAddresses;

                        if (request.TryQueryOrFormArray("dnsServerIPv6SourceAddresses", NetworkAddress.Parse, out NetworkAddress[] dnsServerIPv6SourceAddresses))
                            DnsClientConnection.IPv6SourceAddresses = dnsServerIPv6SourceAddresses;

                        if (request.TryGetQueryOrForm("defaultRecordTtl", ZoneFile.ParseTtl, out uint defaultRecordTtl))
                        {
                            _dnsWebService._dnsServer.AuthZoneManager.DefaultRecordTtl = defaultRecordTtl;
                        }

                        if (request.TryGetQueryOrForm("defaultNsRecordTtl", ZoneFile.ParseTtl, out uint defaultNsRecordTtl))
                        {
                            _dnsWebService._dnsServer.AuthZoneManager.DefaultNsRecordTtl = defaultNsRecordTtl;
                        }

                        if (request.TryGetQueryOrForm("defaultSoaRecordTtl", ZoneFile.ParseTtl, out uint defaultSoaRecordTtl))
                        {
                            _dnsWebService._dnsServer.AuthZoneManager.DefaultSoaRecordTtl = defaultSoaRecordTtl;
                        }

                        string defaultResponsiblePerson = request.QueryOrForm("defaultResponsiblePerson");
                        if (defaultResponsiblePerson is not null)
                        {
                            if (defaultResponsiblePerson.Length == 0)
                                _dnsWebService._dnsServer.DefaultResponsiblePerson = null;
                            else if (defaultResponsiblePerson.Length > 255)
                                throw new ArgumentException("Default responsible person email address length cannot exceed 255 characters.", nameof(defaultResponsiblePerson));
                            else
                                _dnsWebService._dnsServer.DefaultResponsiblePerson = new MailAddress(defaultResponsiblePerson);
                        }

                        if (request.TryGetQueryOrForm("dnsServerEnableCheckForUpdate", bool.Parse, out bool dnsServerEnableCheckForUpdate))
                        {
                            _dnsWebService._dnsServer.EnableCheckForUpdate = dnsServerEnableCheckForUpdate;
                        }

                        if (request.TryGetQueryOrFormEnum("ipv6Mode", out IPv6Mode ipv6Mode))
                            _dnsWebService._dnsServer.IPv6Mode = ipv6Mode;
                        else if (request.TryGetQueryOrForm("preferIPv6", bool.Parse, out bool preferIPv6))
                            _dnsWebService._dnsServer.IPv6Mode = preferIPv6 ? IPv6Mode.Preferred : IPv6Mode.Disabled;

                        if (request.TryGetQueryOrForm("ipv6AutoFallback", bool.Parse, out bool ipv6AutoFallback))
                            _dnsWebService._dnsServer.IPv6AutoFallback = ipv6AutoFallback;

                        if (request.TryGetQueryOrForm("udpListenerThreads", int.Parse, out int udpListenerThreads) && (udpListenerThreads != _dnsWebService._dnsServer.UdpListenerThreads))
                        {
                            _dnsWebService._dnsServer.UdpListenerThreads = udpListenerThreads;
                            restartDnsService = true;
                        }

                        if (request.TryGetQueryOrForm("maxPendingStreamRequests", int.Parse, out int maxPendingStreamRequests))
                            _dnsWebService._dnsServer.MaxPendingStreamRequests = maxPendingStreamRequests;

                        if (request.TryGetQueryOrForm("requestFilterMalformed", bool.Parse, out bool requestFilterMalformed))
                            _dnsWebService._dnsServer.RequestFilterMalformed = requestFilterMalformed;

                        if (request.TryGetQueryOrForm("requestFilterMaxSize", int.Parse, out int requestFilterMaxSize))
                            _dnsWebService._dnsServer.RequestFilterMaxSize = requestFilterMaxSize;

                        if (request.TryGetQueryOrForm("requestFilterOpcode", bool.Parse, out bool requestFilterOpcode))
                            _dnsWebService._dnsServer.RequestFilterOpcode = requestFilterOpcode;

                        if (request.TryGetQueryOrForm("requestFilterClass", bool.Parse, out bool requestFilterClass))
                            _dnsWebService._dnsServer.RequestFilterClass = requestFilterClass;

                        if (request.TryGetQueryOrForm("requestFilterAny", bool.Parse, out bool requestFilterAny))
                            _dnsWebService._dnsServer.RequestFilterAny = requestFilterAny;

                        if (request.TryGetQueryOrForm("requestFilterZoneTransfer", bool.Parse, out bool requestFilterZoneTransfer))
                            _dnsWebService._dnsServer.RequestFilterZoneTransfer = requestFilterZoneTransfer;

                        if (request.TryGetQueryOrForm("requestFilterNoRecursion", bool.Parse, out bool requestFilterNoRecursion))
                            _dnsWebService._dnsServer.RequestFilterNoRecursion = requestFilterNoRecursion;

                        if (request.TryGetQueryOrForm("requestFilterEdnsVersion", bool.Parse, out bool requestFilterEdnsVersion))
                            _dnsWebService._dnsServer.RequestFilterEdnsVersion = requestFilterEdnsVersion;

                        if (request.TryGetQueryOrForm("requestFilterRefuseOnly", bool.Parse, out bool requestFilterRefuseOnly))
                            _dnsWebService._dnsServer.RequestFilterRefuseOnly = requestFilterRefuseOnly;

                        if (request.TryGetQueryOrForm("clientBlockListUpdateIntervalHours", int.Parse, out int clientBlockListUpdateIntervalHours))
                            _dnsWebService._dnsServer.ClientBlockListManager.UpdateIntervalHours = clientBlockListUpdateIntervalHours;

                        if (request.TryQueryOrFormArray("clientBlockListUrls", out string[] clientBlockListUrls))
                        {
                            List<Uri> listUrls = new List<Uri>(clientBlockListUrls.Length);

                            foreach (string clientBlockListUrl in clientBlockListUrls)
                            {
                                string url = clientBlockListUrl.Trim();
                                if (url.Length == 0)
                                    continue;

                                if (!Uri.TryCreate(url, UriKind.Absolute, out Uri listUrl) || ((listUrl.Scheme != Uri.UriSchemeHttps) && (listUrl.Scheme != Uri.UriSchemeHttp) && (listUrl.Scheme != Uri.UriSchemeFile)))
                                    throw new DnsWebServiceException("Invalid client block list URL: " + url);

                                if (!listUrls.Contains(listUrl))
                                    listUrls.Add(listUrl);
                            }

                            _dnsWebService._dnsServer.ClientBlockListManager.ListUrls = listUrls;
                        }

                        if (request.TryGetQueryOrForm("enableUdpSocketPool", bool.Parse, out bool enableUdpSocketPool))
                            _dnsWebService._dnsServer.EnableUdpSocketPool = enableUdpSocketPool;

                        if (request.TryQueryOrFormArray("socketPoolExcludedPorts", ushort.Parse, out ushort[] socketPoolExcludedPorts))
                            UdpClientConnection.SocketPoolExcludedPorts = socketPoolExcludedPorts;

                        if (request.TryGetQueryOrForm("udpPayloadSize", ushort.Parse, out ushort udpPayloadSize))
                        {
                            _dnsWebService._dnsServer.UdpPayloadSize = udpPayloadSize;
                        }

                        if (request.TryGetQueryOrForm("dnssecPostQuantumDowngradeProtection", bool.Parse, out bool dnssecPostQuantumDowngradeProtection))
                            _dnsWebService._dnsServer.DnssecPostQuantumDowngradeProtection = dnssecPostQuantumDowngradeProtection;

                        if (request.TryGetQueryOrForm("dnssecValidation", bool.Parse, out bool dnssecValidation))
                        {
                            _dnsWebService._dnsServer.DnssecValidation = dnssecValidation;
                        }

                        if (request.TryGetQueryOrForm("eDnsClientSubnet", bool.Parse, out bool eDnsClientSubnet))
                        {
                            _dnsWebService._dnsServer.EDnsClientSubnet = eDnsClientSubnet;
                        }

                        if (request.TryGetQueryOrForm("eDnsClientSubnetIPv4PrefixLength", byte.Parse, out byte eDnsClientSubnetIPv4PrefixLength))
                        {
                            _dnsWebService._dnsServer.EDnsClientSubnetIPv4PrefixLength = eDnsClientSubnetIPv4PrefixLength;
                        }

                        if (request.TryGetQueryOrForm("eDnsClientSubnetIPv6PrefixLength", byte.Parse, out byte eDnsClientSubnetIPv6PrefixLength))
                        {
                            _dnsWebService._dnsServer.EDnsClientSubnetIPv6PrefixLength = eDnsClientSubnetIPv6PrefixLength;
                        }

                        string eDnsClientSubnetIpv4Override = request.QueryOrForm("eDnsClientSubnetIpv4Override");
                        if (eDnsClientSubnetIpv4Override is not null)
                        {
                            if (eDnsClientSubnetIpv4Override.Length == 0)
                                _dnsWebService._dnsServer.EDnsClientSubnetIpv4Override = null;
                            else
                                _dnsWebService._dnsServer.EDnsClientSubnetIpv4Override = NetworkAddress.Parse(eDnsClientSubnetIpv4Override);
                        }

                        string eDnsClientSubnetIpv6Override = request.QueryOrForm("eDnsClientSubnetIpv6Override");
                        if (eDnsClientSubnetIpv6Override is not null)
                        {
                            if (eDnsClientSubnetIpv6Override.Length == 0)
                                _dnsWebService._dnsServer.EDnsClientSubnetIpv6Override = null;
                            else
                                _dnsWebService._dnsServer.EDnsClientSubnetIpv6Override = NetworkAddress.Parse(eDnsClientSubnetIpv6Override);
                        }

                        if (TryReadPrefixLimits(request, "qpsPrefixLimitsIPv4", out Dictionary<int, (int, int)> qpsPrefixLimitsIPv4))
                            _dnsWebService._dnsServer.QpsPrefixLimitsIPv4 = qpsPrefixLimitsIPv4;
                        else if (TryReadPrefixLimits(request, "qpmPrefixLimitsIPv4", out Dictionary<int, (int, int)> qpmPrefixLimitsIPv4))
                            _dnsWebService._dnsServer.QpsPrefixLimitsIPv4 = DnsServer.ConvertLegacyQpmPrefixLimits(qpmPrefixLimitsIPv4, false);

                        if (TryReadPrefixLimits(request, "qpsPrefixLimitsIPv6", out Dictionary<int, (int, int)> qpsPrefixLimitsIPv6))
                            _dnsWebService._dnsServer.QpsPrefixLimitsIPv6 = qpsPrefixLimitsIPv6;
                        else if (TryReadPrefixLimits(request, "qpmPrefixLimitsIPv6", out Dictionary<int, (int, int)> qpmPrefixLimitsIPv6))
                            _dnsWebService._dnsServer.QpsPrefixLimitsIPv6 = DnsServer.ConvertLegacyQpmPrefixLimits(qpmPrefixLimitsIPv6, true);

                        if (request.TryGetQueryOrForm("rateLimitBurstSeconds", int.Parse, out int rateLimitBurstSeconds))
                            _dnsWebService._dnsServer.RateLimitBurstSeconds = rateLimitBurstSeconds;

                        if (request.TryGetQueryOrForm("rateLimitUdpTruncationPercentage", int.Parse, out int rateLimitUdpTruncationPercentage) || request.TryGetQueryOrForm("qpmLimitUdpTruncationPercentage", int.Parse, out rateLimitUdpTruncationPercentage))
                            _dnsWebService._dnsServer.RateLimitUdpTruncationPercentage = rateLimitUdpTruncationPercentage;

                        if (request.TryQueryOrFormArray("rateLimitBypassList", NetworkAddress.Parse, out NetworkAddress[] rateLimitBypassList) || request.TryQueryOrFormArray("qpmLimitBypassList", NetworkAddress.Parse, out rateLimitBypassList))
                            _dnsWebService._dnsServer.RateLimitBypassList = rateLimitBypassList;

                        if (request.TryGetQueryOrForm("clientTimeout", int.Parse, out int clientTimeout))
                        {
                            _dnsWebService._dnsServer.ClientTimeout = clientTimeout;
                        }

                        if (request.TryGetQueryOrForm("tcpSendTimeout", int.Parse, out int tcpSendTimeout))
                        {
                            if (_dnsWebService._dnsServer.TcpSendTimeout != tcpSendTimeout)
                            {
                                _dnsWebService._dnsServer.TcpSendTimeout = tcpSendTimeout;
                                restartDnsService = true;
                            }

                        }

                        if (request.TryGetQueryOrForm("tcpReceiveTimeout", int.Parse, out int tcpReceiveTimeout))
                        {
                            if (_dnsWebService._dnsServer.TcpReceiveTimeout != tcpReceiveTimeout)
                            {
                                _dnsWebService._dnsServer.TcpReceiveTimeout = tcpReceiveTimeout;
                                restartDnsService = true;
                            }

                        }

                        if (request.TryGetQueryOrForm("quicIdleTimeout", int.Parse, out int quicIdleTimeout))
                        {
                            _dnsWebService._dnsServer.QuicIdleTimeout = quicIdleTimeout;
                        }

                        if (request.TryGetQueryOrForm("quicMaxInboundStreams", int.Parse, out int quicMaxInboundStreams))
                        {
                            _dnsWebService._dnsServer.QuicMaxInboundStreams = quicMaxInboundStreams;
                        }

                        if (request.TryGetQueryOrForm("listenBacklog", int.Parse, out int listenBacklog))
                        {
                            if (_dnsWebService._dnsServer.ListenBacklog != listenBacklog)
                            {
                                _dnsWebService._dnsServer.ListenBacklog = listenBacklog;
                                restartDnsService = true;
                            }

                        }

                        if (request.TryGetQueryOrForm("udpSendBufferSizeKB", int.Parse, out int udpSendBufferSizeKB))
                        {
                            if (_dnsWebService._dnsServer.UdpSendBufferSizeKB != udpSendBufferSizeKB)
                            {
                                _dnsWebService._dnsServer.UdpSendBufferSizeKB = udpSendBufferSizeKB;
                                restartDnsService = true;
                            }

                        }

                        if (request.TryGetQueryOrForm("udpReceiveBufferSizeKB", int.Parse, out int udpReceiveBufferSizeKB))
                        {
                            if (_dnsWebService._dnsServer.UdpReceiveBufferSizeKB != udpReceiveBufferSizeKB)
                            {
                                _dnsWebService._dnsServer.UdpReceiveBufferSizeKB = udpReceiveBufferSizeKB;
                                restartDnsService = true;
                            }

                        }

                        if (request.TryGetQueryOrForm("maxConcurrentResolutionsPerCore", ushort.Parse, out ushort maxConcurrentResolutionsPerCore))
                        {
                            _dnsWebService._dnsServer.MaxConcurrentResolutionsPerCore = maxConcurrentResolutionsPerCore;
                        }

                        #endregion

                        #region web service

                        if (request.TryQueryOrFormArray("webServiceLocalAddresses", IPAddress.Parse, out IPAddress[] webServiceLocalAddresses))
                        {
                            if (webServiceLocalAddresses.Length == 0)
                                webServiceLocalAddresses = [IPAddress.Any, IPAddress.IPv6Any];

                            if (!_dnsWebService._webServiceLocalAddresses.HasSameItems(webServiceLocalAddresses))
                            {
                                webServiceLocalAddressesChanged = true;
                                restartWebService = true;
                            }

                            _dnsWebService._webServiceLocalAddresses = WebUtilities.GetValidKestrelLocalAddresses(webServiceLocalAddresses);
                        }

                        if (request.TryGetQueryOrForm("webServiceHttpPort", int.Parse, out int webServiceHttpPort))
                        {
                            if (_dnsWebService._webServiceHttpPort != webServiceHttpPort)
                            {
                                _dnsWebService._webServiceHttpPort = webServiceHttpPort;
                                restartWebService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("webServiceEnableHttpUnixSocket", bool.Parse, out bool webServiceEnableHttpUnixSocket))
                        {
                            if (_dnsWebService._webServiceEnableHttpUnixSocket != webServiceEnableHttpUnixSocket)
                            {
                                if (webServiceEnableHttpUnixSocket)
                                {
                                    if (!DnsServer.IsUnixDomainSocketSupported())
                                        throw new ArgumentException("Unix Domain Sockets (UDS) are supported only on Linux, Windows 10 (build 17063 and later), and Windows Server 2019 (update 1809 and later).", "webServiceEnableHttpUnixSocket");
                                }

                                _dnsWebService._webServiceEnableHttpUnixSocket = webServiceEnableHttpUnixSocket;
                                restartWebService = true;
                            }
                        }

                        if (request.TryQueryOrForm("webServiceHttpUnixSocket", out string webServiceHttpUnixSocket))
                        {
                            if (string.IsNullOrWhiteSpace(webServiceHttpUnixSocket))
                                webServiceHttpUnixSocket = null;

                            if (_dnsWebService._webServiceHttpUnixSocket != webServiceHttpUnixSocket)
                            {
                                _dnsWebService._webServiceHttpUnixSocket = webServiceHttpUnixSocket;
                                restartWebService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("webServiceEnableTlsUnixSocket", bool.Parse, out bool webServiceEnableTlsUnixSocket))
                        {
                            if (_dnsWebService._webServiceEnableTlsUnixSocket != webServiceEnableTlsUnixSocket)
                            {
                                if (webServiceEnableTlsUnixSocket)
                                {
                                    if (!DnsServer.IsUnixDomainSocketSupported())
                                        throw new ArgumentException("Unix Domain Sockets (UDS) are supported only on Linux, Windows 10 (build 17063 and later), and Windows Server 2019 (update 1809 and later).", "webServiceEnableTlsUnixSocket");
                                }

                                _dnsWebService._webServiceEnableTlsUnixSocket = webServiceEnableTlsUnixSocket;
                                restartWebService = true;
                            }
                        }

                        if (request.TryQueryOrForm("webServiceTlsUnixSocket", out string webServiceTlsUnixSocket))
                        {
                            if (string.IsNullOrWhiteSpace(webServiceTlsUnixSocket))
                                webServiceTlsUnixSocket = null;

                            if (_dnsWebService._webServiceTlsUnixSocket != webServiceTlsUnixSocket)
                            {
                                _dnsWebService._webServiceTlsUnixSocket = webServiceTlsUnixSocket;
                                restartWebService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("webServiceEnableTls", bool.Parse, out bool webServiceEnableTls))
                        {
                            if (_dnsWebService._webServiceEnableTls != webServiceEnableTls)
                            {
                                _dnsWebService._webServiceEnableTls = webServiceEnableTls;
                                _webServiceEnablingTls = webServiceEnableTls;
                                restartWebService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("webServiceEnableHttp3", bool.Parse, out bool webServiceEnableHttp3))
                        {
                            if (_dnsWebService._webServiceEnableHttp3 != webServiceEnableHttp3)
                            {
                                if (webServiceEnableHttp3)
                                    DnsServer.ValidateQuicSupport("HTTP/3");

                                _dnsWebService._webServiceEnableHttp3 = webServiceEnableHttp3;
                                restartWebService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("webServiceHttpToTlsRedirect", bool.Parse, out bool webServiceHttpToTlsRedirect))
                        {
                            if (_dnsWebService._webServiceHttpToTlsRedirect != webServiceHttpToTlsRedirect)
                            {
                                _dnsWebService._webServiceHttpToTlsRedirect = webServiceHttpToTlsRedirect;
                                restartWebService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("webServiceUseSelfSignedTlsCertificate", bool.Parse, out bool webServiceUseSelfSignedTlsCertificate))
                            _dnsWebService._webServiceUseSelfSignedTlsCertificate = webServiceUseSelfSignedTlsCertificate;

                        if (request.TryGetQueryOrForm("webServiceTlsPort", int.Parse, out int webServiceTlsPort))
                        {
                            if (_dnsWebService._webServiceTlsPort != webServiceTlsPort)
                            {
                                _dnsWebService._webServiceTlsPort = webServiceTlsPort;
                                restartWebService = true;
                            }
                        }

                        if (request.TryQueryOrFormArray("webServiceReverseProxyAddresses", NetworkAccessControl.Parse, out NetworkAccessControl[] webServiceReverseProxyAddresses))
                        {
                            if ((webServiceReverseProxyAddresses is null) || (webServiceReverseProxyAddresses.Length == 0))
                                _dnsWebService._webServiceReverseProxyAddresses = null;
                            else if (webServiceReverseProxyAddresses.Length > byte.MaxValue)
                                throw new ArgumentOutOfRangeException("WebServiceReverseProxyAddresses", "Web Service Reverse Proxy Addresses list cannot have more than 255 entries.");
                            else
                                _dnsWebService._webServiceReverseProxyAddresses = webServiceReverseProxyAddresses;
                        }

                        if (request.TryQueryOrForm("webServiceRealIpHeader", out string webServiceRealIpHeader))
                        {
                            if (string.IsNullOrWhiteSpace(webServiceRealIpHeader))
                                webServiceRealIpHeader = "X-Real-IP";
                            else if (webServiceRealIpHeader.Length > 255)
                                throw new ArgumentException("Web Service Real IP header name cannot exceed 255 characters.", nameof(webServiceRealIpHeader));
                            else if (webServiceRealIpHeader.Contains(' '))
                                throw new ArgumentException("Web Service Real IP header name cannot contain invalid characters.", nameof(webServiceRealIpHeader));

                            _dnsWebService._webServiceRealIpHeader = webServiceRealIpHeader;
                        }

                        if (request.TryQueryOrForm("webServiceCspFrameAncestorsHeader", out string webServiceCspFrameAncestorsHeader))
                        {
                            if (string.IsNullOrWhiteSpace(webServiceCspFrameAncestorsHeader))
                                webServiceCspFrameAncestorsHeader = "'none'";
                            else if (webServiceCspFrameAncestorsHeader.Length > 255)
                                throw new ArgumentException("Web Service Content Security Policy (CSP) Frame Ancestors header value cannot exceed 255 characters.", nameof(webServiceCspFrameAncestorsHeader));

                            _dnsWebService._webServiceCspFrameAncestorsHeader = webServiceCspFrameAncestorsHeader;
                        }

                        string webServiceTlsCertificatePath = request.QueryOrForm("webServiceTlsCertificatePath");
                        if (webServiceTlsCertificatePath is not null)
                        {
                            if (webServiceTlsCertificatePath.Length == 0)
                            {
                                if (!string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath))
                                    _dnsWebService.RemoveWebServiceTlsCertificate();
                            }
                            else
                            {
                                string webServiceTlsCertificatePassword = request.QueryOrForm("webServiceTlsCertificatePassword");

                                if ((webServiceTlsCertificatePassword is null) || (webServiceTlsCertificatePassword == "************"))
                                    webServiceTlsCertificatePassword = _dnsWebService._webServiceTlsCertificatePassword;

                                string webServiceTlsCertificateKeyPath = request.QueryOrForm("webServiceTlsCertificateKeyPath");

                                if (webServiceTlsCertificateKeyPath is null)
                                    webServiceTlsCertificateKeyPath = _dnsWebService._webServiceTlsCertificateKeyPath;
                                else if (webServiceTlsCertificateKeyPath.Length == 0)
                                    webServiceTlsCertificateKeyPath = null;

                                if ((webServiceTlsCertificatePath != _dnsWebService._webServiceTlsCertificatePath) || (webServiceTlsCertificatePassword != _dnsWebService._webServiceTlsCertificatePassword) || (webServiceTlsCertificateKeyPath != _dnsWebService._webServiceTlsCertificateKeyPath))
                                    _dnsWebService.SetWebServiceTlsCertificate(webServiceTlsCertificatePath, webServiceTlsCertificatePassword, webServiceTlsCertificateKeyPath);
                            }
                        }

                        #endregion

                        #region optional protocols

                        if (request.TryGetQueryOrForm("enableEDnsClientSubnetSourceAddress", bool.Parse, out bool enableEDnsClientSubnetSourceAddress))
                            _dnsWebService._dnsServer.EnableEDnsClientSubnetSourceAddress = enableEDnsClientSubnetSourceAddress;

                        if (request.TryGetQueryOrForm("enableDnsOverUdpProxy", bool.Parse, out bool enableDnsOverUdpProxy))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverUdpProxy != enableDnsOverUdpProxy)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverUdpProxy = enableDnsOverUdpProxy;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverTcpProxy", bool.Parse, out bool enableDnsOverTcpProxy))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverTcpProxy != enableDnsOverTcpProxy)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverTcpProxy = enableDnsOverTcpProxy;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverHttp", bool.Parse, out bool enableDnsOverHttp))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverHttp != enableDnsOverHttp)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverHttp = enableDnsOverHttp;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverHttpUnixSocket", bool.Parse, out bool enableDnsOverHttpUnixSocket))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverHttpUnixSocket != enableDnsOverHttpUnixSocket)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverHttpUnixSocket = enableDnsOverHttpUnixSocket;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverHttpsUnixSocket", bool.Parse, out bool enableDnsOverHttpsUnixSocket))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverHttpsUnixSocket != enableDnsOverHttpsUnixSocket)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverHttpsUnixSocket = enableDnsOverHttpsUnixSocket;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverTls", bool.Parse, out bool enableDnsOverTls))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverTls != enableDnsOverTls)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverTls = enableDnsOverTls;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverHttps", bool.Parse, out bool enableDnsOverHttps))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverHttps != enableDnsOverHttps)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverHttps = enableDnsOverHttps;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverHttp3", bool.Parse, out bool enableDnsOverHttp3))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverHttp3 != enableDnsOverHttp3)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverHttp3 = enableDnsOverHttp3;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverQuic", bool.Parse, out bool enableDnsOverQuic))
                        {
                            if (_dnsWebService._dnsServer.EnableDnsOverQuic != enableDnsOverQuic)
                            {
                                _dnsWebService._dnsServer.EnableDnsOverQuic = enableDnsOverQuic;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("enableDnsOverHttpHelpRedirect", bool.Parse, out bool enableDnsOverHttpHelpRedirect))
                            _dnsWebService._dnsServer.EnableDnsOverHttpHelpRedirect = enableDnsOverHttpHelpRedirect;

                        if (request.TryGetQueryOrForm("dnsOverUdpProxyPort", int.Parse, out int dnsOverUdpProxyPort))
                        {
                            if (_dnsWebService._dnsServer.DnsOverUdpProxyPort != dnsOverUdpProxyPort)
                            {
                                _dnsWebService._dnsServer.DnsOverUdpProxyPort = dnsOverUdpProxyPort;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("dnsOverTcpProxyPort", int.Parse, out int dnsOverTcpProxyPort))
                        {
                            if (_dnsWebService._dnsServer.DnsOverTcpProxyPort != dnsOverTcpProxyPort)
                            {
                                _dnsWebService._dnsServer.DnsOverTcpProxyPort = dnsOverTcpProxyPort;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("dnsOverHttpPort", int.Parse, out int dnsOverHttpPort))
                        {
                            if (_dnsWebService._dnsServer.DnsOverHttpPort != dnsOverHttpPort)
                            {
                                _dnsWebService._dnsServer.DnsOverHttpPort = dnsOverHttpPort;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryQueryOrForm("dnsOverHttpUnixSocket", out string dnsOverHttpUnixSocket))
                        {
                            if (string.IsNullOrWhiteSpace(dnsOverHttpUnixSocket))
                                dnsOverHttpUnixSocket = null;

                            if (_dnsWebService._dnsServer.DnsOverHttpUnixSocket != dnsOverHttpUnixSocket)
                            {
                                _dnsWebService._dnsServer.DnsOverHttpUnixSocket = dnsOverHttpUnixSocket;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryQueryOrForm("dnsOverHttpsUnixSocket", out string dnsOverHttpsUnixSocket))
                        {
                            if (string.IsNullOrWhiteSpace(dnsOverHttpsUnixSocket))
                                dnsOverHttpsUnixSocket = null;

                            if (_dnsWebService._dnsServer.DnsOverHttpsUnixSocket != dnsOverHttpsUnixSocket)
                            {
                                _dnsWebService._dnsServer.DnsOverHttpsUnixSocket = dnsOverHttpsUnixSocket;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("dnsOverTlsPort", int.Parse, out int dnsOverTlsPort))
                        {
                            if (_dnsWebService._dnsServer.DnsOverTlsPort != dnsOverTlsPort)
                            {
                                _dnsWebService._dnsServer.DnsOverTlsPort = dnsOverTlsPort;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("dnsOverHttpsPort", int.Parse, out int dnsOverHttpsPort))
                        {
                            if (_dnsWebService._dnsServer.DnsOverHttpsPort != dnsOverHttpsPort)
                            {
                                _dnsWebService._dnsServer.DnsOverHttpsPort = dnsOverHttpsPort;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("dnsOverQuicPort", int.Parse, out int dnsOverQuicPort))
                        {
                            if (_dnsWebService._dnsServer.DnsOverQuicPort != dnsOverQuicPort)
                            {
                                _dnsWebService._dnsServer.DnsOverQuicPort = dnsOverQuicPort;
                                restartDnsService = true;
                            }
                        }

                        if (request.TryQueryOrFormArray("dnsReverseProxyNetworkACL", NetworkAccessControl.Parse, out NetworkAccessControl[] dnsReverseProxyNetworkACL))
                            _dnsWebService._dnsServer.DnsReverseProxyNetworkACL = dnsReverseProxyNetworkACL;
                        else if (request.TryQueryOrFormArray("reverseProxyNetworkACL", NetworkAccessControl.Parse, out dnsReverseProxyNetworkACL))
                            _dnsWebService._dnsServer.DnsReverseProxyNetworkACL = dnsReverseProxyNetworkACL;

                        if (request.TryQueryOrForm("dnsOverHttpRealIpHeader", out string dnsOverHttpRealIpHeader))
                            _dnsWebService._dnsServer.DnsOverHttpRealIpHeader = dnsOverHttpRealIpHeader;

                        if (request.TryGetQueryOrForm("enableDdr", bool.Parse, out bool enableDdr))
                            _dnsWebService._dnsServer.EnableDdr = enableDdr;

                        if (request.TryGetQueryOrForm("ddrOnlyUnencrypted", bool.Parse, out bool ddrOnlyUnencrypted))
                            _dnsWebService._dnsServer.DdrOnlyUnencrypted = ddrOnlyUnencrypted;

                        if (request.TryGetQueryOrForm("ddrProxyDoh", bool.Parse, out bool ddrProxyDoh))
                            _dnsWebService._dnsServer.DdrProxyDoh = ddrProxyDoh;

                        if (request.TryGetQueryOrForm("ddrProxyDohPort", ushort.Parse, out ushort ddrProxyDohPort))
                            _dnsWebService._dnsServer.DdrProxyDohPort = ddrProxyDohPort;

                        if (request.TryGetQueryOrForm("ddrProxyDohHttp3", bool.Parse, out bool ddrProxyDohHttp3))
                            _dnsWebService._dnsServer.DdrProxyDohHttp3 = ddrProxyDohHttp3;

                        if (request.TryGetQueryOrFormEnum("do53Mode", out DnsServerDo53Mode do53Mode))
                        {
                            if ((do53Mode == DnsServerDo53Mode.Disabled) != (_dnsWebService._dnsServer.Do53Mode == DnsServerDo53Mode.Disabled))
                                restartDnsService = true;

                            _dnsWebService._dnsServer.Do53Mode = do53Mode;
                        }

                        if (request.TryGetQueryOrFormEnum("eDnsPaddingMode", out DnsServerEDnsPaddingMode eDnsPaddingMode))
                            _dnsWebService._dnsServer.EDnsPaddingMode = eDnsPaddingMode;

                        string dnsTlsCertificatePath = request.QueryOrForm("dnsTlsCertificatePath");
                        if (dnsTlsCertificatePath is not null)
                        {
                            if (dnsTlsCertificatePath.Length == 0)
                            {
                                if (!string.IsNullOrEmpty(_dnsWebService._dnsServer.DnsTlsCertificatePath) && (_dnsWebService._dnsServer.EnableDnsOverTls || _dnsWebService._dnsServer.EnableDnsOverHttps || _dnsWebService._dnsServer.EnableDnsOverQuic))
                                    restartDnsService = true;

                                _dnsWebService._dnsServer.RemoveDnsTlsCertificate();
                            }
                            else
                            {
                                string dnsTlsCertificatePassword = request.QueryOrForm("dnsTlsCertificatePassword");

                                if ((dnsTlsCertificatePassword is null) || (dnsTlsCertificatePassword == "************"))
                                    dnsTlsCertificatePassword = _dnsWebService._dnsServer.DnsTlsCertificatePassword;

                                string dnsTlsCertificateKeyPath = request.QueryOrForm("dnsTlsCertificateKeyPath");

                                if (dnsTlsCertificateKeyPath is null)
                                    dnsTlsCertificateKeyPath = _dnsWebService._dnsServer.DnsTlsCertificateKeyPath;
                                else if (dnsTlsCertificateKeyPath.Length == 0)
                                    dnsTlsCertificateKeyPath = null;

                                if ((dnsTlsCertificatePath != _dnsWebService._dnsServer.DnsTlsCertificatePath) || (dnsTlsCertificatePassword != _dnsWebService._dnsServer.DnsTlsCertificatePassword) || (dnsTlsCertificateKeyPath != _dnsWebService._dnsServer.DnsTlsCertificateKeyPath))
                                {
                                    _dnsWebService._dnsServer.SetDnsTlsCertificate(dnsTlsCertificatePath, dnsTlsCertificatePassword, true, dnsTlsCertificateKeyPath);

                                    if (string.IsNullOrEmpty(_dnsWebService._dnsServer.DnsTlsCertificatePath) && (_dnsWebService._dnsServer.EnableDnsOverTls || _dnsWebService._dnsServer.EnableDnsOverHttps || _dnsWebService._dnsServer.EnableDnsOverQuic))
                                        restartDnsService = true;
                                }
                            }
                        }

                        #endregion

                        #region recursion

                        if (request.TryGetQueryOrFormEnum("recursion", out DnsServerRecursion recursion))
                        {
                            _dnsWebService._dnsServer.Recursion = recursion;
                        }

                        if (request.TryQueryOrFormArray("recursionNetworkACL", NetworkAccessControl.Parse, out NetworkAccessControl[] recursionNetworkACL))
                        {
                            _dnsWebService._dnsServer.RecursionNetworkACL = recursionNetworkACL;
                        }

                        if (request.TryGetQueryOrForm("randomizeName", bool.Parse, out bool randomizeName))
                        {
                            _dnsWebService._dnsServer.RandomizeName = randomizeName;
                        }

                        if (request.TryGetQueryOrForm("qnameMinimization", bool.Parse, out bool qnameMinimization))
                        {
                            _dnsWebService._dnsServer.QnameMinimization = qnameMinimization;
                        }

                        if (request.TryGetQueryOrForm("locallyServedDnsZones", bool.Parse, out bool locallyServedDnsZones))
                        {
                            _dnsWebService._dnsServer.LocallyServedDnsZones = locallyServedDnsZones;
                        }

                        if (request.TryGetQueryOrForm("resolverRetries", int.Parse, out int resolverRetries))
                        {
                            _dnsWebService._dnsServer.ResolverRetries = resolverRetries;
                        }

                        if (request.TryGetQueryOrForm("resolverTimeout", int.Parse, out int resolverTimeout))
                        {
                            _dnsWebService._dnsServer.ResolverTimeout = resolverTimeout;
                        }

                        if (request.TryGetQueryOrForm("resolverConcurrency", int.Parse, out int resolverConcurrency))
                        {
                            _dnsWebService._dnsServer.ResolverConcurrency = resolverConcurrency;
                        }

                        if (request.TryGetQueryOrForm("resolverMaxStackCount", int.Parse, out int resolverMaxStackCount))
                        {
                            _dnsWebService._dnsServer.ResolverMaxStackCount = resolverMaxStackCount;
                        }

                        #endregion

                        #region cache

                        if (request.TryGetQueryOrForm("saveCache", bool.Parse, out bool saveCache))
                            _dnsWebService._dnsServer.SaveCacheToDisk = saveCache;

                        if (request.TryGetQueryOrForm("serveStale", bool.Parse, out bool serveStale))
                            _dnsWebService._dnsServer.ServeStale = serveStale;

                        if (request.TryGetQueryOrForm("serveStaleTtl", ZoneFile.ParseTtl, out uint serveStaleTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.ServeStaleTtl = serveStaleTtl;

                        if (request.TryGetQueryOrForm("serveStaleAnswerTtl", ZoneFile.ParseTtl, out uint serveStaleAnswerTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.ServeStaleAnswerTtl = serveStaleAnswerTtl;

                        if (request.TryGetQueryOrForm("serveStaleResetTtl", ZoneFile.ParseTtl, out uint serveStaleResetTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.ServeStaleResetTtl = serveStaleResetTtl;

                        if (request.TryGetQueryOrForm("serveStaleMaxWaitTime", int.Parse, out int serveStaleMaxWaitTime))
                            _dnsWebService._dnsServer.ServeStaleMaxWaitTime = serveStaleMaxWaitTime;

                        if (request.TryGetQueryOrForm("cacheMaximumEntries", long.Parse, out long cacheMaximumEntries))
                            _dnsWebService._dnsServer.CacheZoneManager.MaximumEntries = cacheMaximumEntries;

                        if (request.TryGetQueryOrForm("cacheMinimumRecordTtl", ZoneFile.ParseTtl, out uint cacheMinimumRecordTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.MinimumRecordTtl = cacheMinimumRecordTtl;

                        if (request.TryGetQueryOrForm("cacheMaximumRecordTtl", ZoneFile.ParseTtl, out uint cacheMaximumRecordTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.MaximumRecordTtl = cacheMaximumRecordTtl;

                        if (request.TryGetQueryOrForm("cacheNegativeRecordTtl", ZoneFile.ParseTtl, out uint cacheNegativeRecordTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.NegativeRecordTtl = cacheNegativeRecordTtl;

                        if (request.TryGetQueryOrForm("cacheMaximumNegativeRecordTtl", ZoneFile.ParseTtl, out uint cacheMaximumNegativeRecordTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.MaximumNegativeRecordTtl = cacheMaximumNegativeRecordTtl;

                        if (request.TryGetQueryOrForm("cacheFailureRecordTtl", ZoneFile.ParseTtl, out uint cacheFailureRecordTtl))
                            _dnsWebService._dnsServer.CacheZoneManager.FailureRecordTtl = cacheFailureRecordTtl;

                        if (request.TryGetQueryOrForm("cachePrefetchEligibility", int.Parse, out int cachePrefetchEligibility))
                            _dnsWebService._dnsServer.CachePrefetchEligibility = cachePrefetchEligibility;

                        if (request.TryGetQueryOrForm("cachePrefetchTrigger", int.Parse, out int cachePrefetchTrigger))
                            _dnsWebService._dnsServer.CachePrefetchTrigger = cachePrefetchTrigger;

                        #endregion

                        #region blocking

                        if (request.TryGetQueryOrForm("enableBlocking", bool.Parse, out bool enableBlocking))
                        {
                            _dnsWebService._dnsServer.EnableBlocking = enableBlocking;
                        }

                        if (request.TryGetQueryOrForm("allowTxtBlockingReport", bool.Parse, out bool allowTxtBlockingReport))
                        {
                            _dnsWebService._dnsServer.AllowTxtBlockingReport = allowTxtBlockingReport;
                        }

                        if (request.TryQueryOrFormArray("blockingBypassList", NetworkAddress.Parse, out NetworkAddress[] blockingBypassList))
                        {
                            _dnsWebService._dnsServer.BlockingBypassList = blockingBypassList;
                        }

                        if (request.TryGetQueryOrFormEnum("blockingType", out DnsServerBlockingType blockingType))
                        {
                            _dnsWebService._dnsServer.BlockingType = blockingType;
                        }

                        if (request.TryGetQueryOrForm("blockingAnswerTtl", ZoneFile.ParseTtl, out uint blockingAnswerTtl))
                        {
                            _dnsWebService._dnsServer.BlockingAnswerTtl = blockingAnswerTtl;
                        }

                        if (request.TryGetQueryOrForm("blockingNegativeTtl", ZoneFile.ParseTtl, out uint blockingNegativeTtl))
                            _dnsWebService._dnsServer.BlockingNegativeTtl = blockingNegativeTtl;

                        string blockingReportText = request.QueryOrForm("blockingReportText");
                        if (blockingReportText is not null)
                            _dnsWebService._dnsServer.BlockingReportText = blockingReportText;

                        if (request.TryGetQueryOrForm("blockFirefoxCanaryDomain", bool.Parse, out bool blockFirefoxCanaryDomain))
                            _dnsWebService._dnsServer.BlockFirefoxCanaryDomain = blockFirefoxCanaryDomain;

                        if (request.TryGetQueryOrForm("forceChromePreflight", bool.Parse, out bool forceChromePreflight))
                            _dnsWebService._dnsServer.ForceChromePreflight = forceChromePreflight;

                        if (request.TryGetQueryOrForm("enableLiveMonitoring", bool.Parse, out bool enableLiveMonitoring))
                            _dnsWebService._dnsServer.SystemMonitor.Enabled = enableLiveMonitoring;

                        if (request.TryGetQueryOrForm("enableWatchdog", bool.Parse, out bool enableWatchdog))
                            _dnsWebService._dnsServer.Watchdog.Enabled = enableWatchdog;

                        if (request.TryGetQueryOrFormEnum("rootZoneMode", out IanaDataMode rootZoneMode))
                            await _dnsWebService._dnsServer.IanaDataManager.SetModeAsync(IanaDataItem.RootZone, rootZoneMode);

                        if (request.TryGetQueryOrFormEnum("arpaZoneMode", out IanaDataMode arpaZoneMode))
                            await _dnsWebService._dnsServer.IanaDataManager.SetModeAsync(IanaDataItem.ArpaZone, arpaZoneMode);

                        if (request.TryGetQueryOrFormEnum("trustAnchorMode", out IanaDataMode trustAnchorMode))
                            await _dnsWebService._dnsServer.IanaDataManager.SetModeAsync(IanaDataItem.TrustAnchors, trustAnchorMode);

                        if (request.TryQueryOrFormArray("customBlockingAddresses", out string[] customBlockingAddresses))
                        {
                            if (customBlockingAddresses.Length == 0)
                            {
                                _dnsWebService._dnsServer.CustomBlockingARecords = null;
                                _dnsWebService._dnsServer.CustomBlockingAAAARecords = null;
                            }
                            else
                            {
                                List<DnsARecordData> dnsARecords = new List<DnsARecordData>();
                                List<DnsAAAARecordData> dnsAAAARecords = new List<DnsAAAARecordData>();

                                foreach (string strAddress in customBlockingAddresses)
                                {
                                    if (IPAddress.TryParse(strAddress, out IPAddress customAddress))
                                    {
                                        switch (customAddress.AddressFamily)
                                        {
                                            case AddressFamily.InterNetwork:
                                                dnsARecords.Add(new DnsARecordData(customAddress));
                                                break;

                                            case AddressFamily.InterNetworkV6:
                                                dnsAAAARecords.Add(new DnsAAAARecordData(customAddress));
                                                break;
                                        }
                                    }
                                }

                                _dnsWebService._dnsServer.CustomBlockingARecords = dnsARecords;
                                _dnsWebService._dnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                            }

                        }

                        if (request.TryQueryOrFormArray("blockListUrls", out string[] blockListUrls))
                        {
                            _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls = blockListUrls;
                            _dnsWebService._dnsServer.BlockListZoneManager.SaveConfigFile();
                        }

                        if (request.TryGetQueryOrForm("blockListUpdateIntervalHours", int.Parse, out int blockListUpdateIntervalHours))
                        {
                            _dnsWebService._dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours = blockListUpdateIntervalHours;
                            _dnsWebService._dnsServer.BlockListZoneManager.SaveConfigFile();
                        }

                        #endregion

                        #region proxy & forwarders

                        if (request.TryGetQueryOrFormEnum("proxyType", out NetProxyType proxyType))
                        {
                            if (proxyType == NetProxyType.None)
                            {
                                _dnsWebService._dnsServer.Proxy = null;
                            }
                            else
                            {
                                NetworkCredential credential = null;

                                if (request.TryGetQueryOrForm("proxyUsername", out string proxyUsername))
                                {
                                    if (proxyUsername.Length > 255)
                                        throw new ArgumentException("Proxy username length cannot exceed 255 characters.", nameof(proxyUsername));

                                    string proxyPassword = request.QueryOrForm("proxyPassword");
                                    if (proxyPassword?.Length > 255)
                                        throw new ArgumentException("Proxy password length cannot exceed 255 characters.", nameof(proxyPassword));

                                    credential = new NetworkCredential(proxyUsername, proxyPassword);
                                }

                                string proxyAddress = request.QueryOrForm("proxyAddress");
                                string proxyPort = request.QueryOrForm("proxyPort");

                                _dnsWebService._dnsServer.Proxy = NetProxy.CreateProxy(proxyType, proxyAddress, int.Parse(proxyPort), credential);

                                if (request.TryQueryOrFormArray("proxyBypass", delegate (string value) { return new NetProxyBypassItem(value); }, out NetProxyBypassItem[] proxyBypass))
                                {
                                    _dnsWebService._dnsServer.Proxy.BypassList = proxyBypass;
                                }
                            }

                        }

                        if (request.TryQueryOrFormArray("forwarders", NameServerAddress.Parse, out NameServerAddress[] forwarders))
                        {
                            if (forwarders.Length == 0)
                            {
                                _dnsWebService._dnsServer.Forwarders = null;
                            }
                            else
                            {
                                DnsTransportProtocol forwarderProtocol = request.GetQueryOrFormEnum("forwarderProtocol", DnsTransportProtocol.Udp);

                                switch (forwarderProtocol)
                                {
                                    case DnsTransportProtocol.Udp:
                                        if (proxyType == NetProxyType.Http)
                                            throw new DnsWebServiceException("HTTP proxy server can transport only DNS-over-TCP, DNS-over-TLS, or DNS-over-HTTPS forwarder protocols. Use SOCKS5 proxy server for DNS-over-UDP or DNS-over-QUIC forwarder protocols.");

                                        break;

                                    case DnsTransportProtocol.HttpsJson:
                                        forwarderProtocol = DnsTransportProtocol.Https;
                                        break;

                                    case DnsTransportProtocol.Quic:
                                        DnsServer.ValidateQuicSupport();

                                        if (proxyType == NetProxyType.Http)
                                            throw new DnsWebServiceException("HTTP proxy server can transport only DNS-over-TCP, DNS-over-TLS, or DNS-over-HTTPS forwarder protocols. Use SOCKS5 proxy server for DNS-over-UDP or DNS-over-QUIC forwarder protocols.");

                                        break;
                                }

                                for (int i = 0; i < forwarders.Length; i++)
                                {
                                    if (forwarders[i].Protocol != forwarderProtocol)
                                        forwarders[i] = forwarders[i].Clone(forwarderProtocol);
                                }

                                if (!_dnsWebService._dnsServer.Forwarders.ListEquals(forwarders))
                                    _dnsWebService._dnsServer.Forwarders = forwarders;
                            }

                        }

                        if (request.TryGetQueryOrForm("concurrentForwarding", bool.Parse, out bool concurrentForwarding))
                        {
                            _dnsWebService._dnsServer.ConcurrentForwarding = concurrentForwarding;
                        }

                        if (request.TryGetQueryOrForm("forwarderRetries", int.Parse, out int forwarderRetries))
                        {
                            _dnsWebService._dnsServer.ForwarderRetries = forwarderRetries;
                        }

                        if (request.TryGetQueryOrForm("forwarderTimeout", int.Parse, out int forwarderTimeout))
                        {
                            _dnsWebService._dnsServer.ForwarderTimeout = forwarderTimeout;
                        }

                        if (request.TryGetQueryOrForm("forwarderConcurrency", int.Parse, out int forwarderConcurrency))
                        {
                            _dnsWebService._dnsServer.ForwarderConcurrency = forwarderConcurrency;
                        }

                        #endregion

                        #region logging

                        if (request.TryGetQueryOrFormEnum("loggingType", out LoggingType loggingType))
                            _dnsWebService._log.LoggingType = loggingType;
                        else if (request.TryGetQueryOrForm("enableLogging", bool.Parse, out bool enableLogging))
                            _dnsWebService._log.LoggingType = enableLogging ? LoggingType.File : LoggingType.None;

                        if (request.TryGetQueryOrForm("ignoreResolverLogs", bool.Parse, out bool ignoreResolverLogs))
                            _dnsWebService._dnsServer.ResolverLogManager = ignoreResolverLogs ? null : _dnsWebService._log;

                        if (request.TryGetQueryOrForm("logQueries", bool.Parse, out bool logQueries))
                            _dnsWebService._dnsServer.QueryLogManager = logQueries ? _dnsWebService._log : null;

                        if (request.TryGetQueryOrForm("noStackTrace", bool.Parse, out bool noStackTrace))
                            _dnsWebService._log.NoStackTrace = noStackTrace;

                        if (request.TryGetQueryOrForm("hideClientAddresses", bool.Parse, out bool hideClientAddresses))
                            _dnsWebService._log.HideClientAddresses = hideClientAddresses;

                        if (request.TryGetQueryOrForm("useLocalTime", bool.Parse, out bool useLocalTime))
                            _dnsWebService._log.UseLocalTime = useLocalTime;

                        if (request.TryGetQueryOrForm("logFolder", out string logFolder))
                            _dnsWebService._log.LogFolder = logFolder;

                        if (request.TryGetQueryOrForm("maxLogFileDays", int.Parse, out int maxLogFileDays))
                            _dnsWebService._log.MaxLogFileDays = maxLogFileDays;

                        if (request.TryGetQueryOrForm("enableInMemoryStats", bool.Parse, out bool enableInMemoryStats))
                            _dnsWebService._dnsServer.StatsManager.EnableInMemoryStats = enableInMemoryStats;

                        if (request.TryGetQueryOrForm("maxStatFileDays", int.Parse, out int maxStatFileDays))
                            _dnsWebService._dnsServer.StatsManager.MaxStatFileDays = maxStatFileDays;

                        #endregion
                    }
                    finally
                    {
                        jsonDocument?.Dispose();

                        _dnsWebService.CheckAndLoadSelfSignedCertificate(serverDomainChanged || webServiceLocalAddressesChanged, true);

                        if (_dnsWebService._webServiceEnableTls && string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath) && !_dnsWebService._webServiceUseSelfSignedTlsCertificate)
                        {
                            _dnsWebService._webServiceEnableTls = false;
                            restartWebService = true;
                        }

                        if (_dnsWebService._ssoHttpHandler is not null)
                        {
                            _dnsWebService._ssoHttpHandler.Proxy = _dnsWebService._dnsServer.Proxy;
                            _dnsWebService._ssoHttpHandler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsWebService._dnsServer.IPv6Mode);
                        }

                        _dnsWebService.SaveConfigFile();
                        _dnsWebService._dnsServer.SaveConfigFile();
                        _dnsWebService._dnsServer.BlockListZoneManager.SaveConfigFile();
                        _dnsWebService._log.SaveConfigFile();
                    }

                    _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] DNS Settings were updated successfully.");

                    Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                    WriteDnsSettings(jsonWriter);
                }
                finally
                {
                    if (restartDnsService || restartWebService)
                        _dnsWebService.RestartService(restartDnsService, restartWebService, oldWebServiceLocalAddresses, oldWebServiceHttpPort, oldWebServiceTlsPort);
                }
            }

            public async Task BackupSettingsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                bool authConfig = request.GetQueryOrForm("authConfig", bool.Parse, false);
                bool webServiceSettings = request.GetQueryOrForm("webServiceSettings", bool.Parse, false);
                bool dnsSettings = request.GetQueryOrForm("dnsSettings", bool.Parse, false);
                bool logSettings = request.GetQueryOrForm("logSettings", bool.Parse, false);
                bool zones = request.GetQueryOrForm("zones", bool.Parse, false);
                bool allowedZones = request.GetQueryOrForm("allowedZones", bool.Parse, false);
                bool blockedZones = request.GetQueryOrForm("blockedZones", bool.Parse, false);
                bool blockLists = request.GetQueryOrForm("blockLists", bool.Parse, false);
                bool apps = request.GetQueryOrForm("apps", bool.Parse, false);
                bool stats = request.GetQueryOrForm("stats", bool.Parse, false);
                bool logs = request.GetQueryOrForm("logs", bool.Parse, false);

                string tmpFile = Path.GetTempFileName();
                try
                {
                    await using (FileStream backupZipStream = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        await _dnsWebService.BackupConfigAsync(backupZipStream, authConfig, webServiceSettings, dnsSettings, logSettings, zones, allowedZones, blockedZones, blockLists, apps, stats, logs);

                        backupZipStream.Position = 0;

                        HttpResponse response = context.Response;

                        response.ContentType = "application/zip";
                        response.ContentLength = backupZipStream.Length;
                        response.Headers.ContentDisposition = "attachment;filename=" + _dnsWebService._dnsServer.ServerDomain + DateTime.UtcNow.ToString("_yyyy-MM-dd_HH-mm-ss", CultureInfo.InvariantCulture) + "_backup.zip";

                        await using (Stream output = response.Body)
                        {
                            await backupZipStream.CopyToAsync(output);
                        }
                    }
                }
                finally
                {
                    try
                    {
                        File.Delete(tmpFile);
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService._log.Write(ex);
                    }
                }

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Settings backup zip file was exported.");
            }

            public async Task RestoreSettingsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                bool authConfig = request.GetQueryOrForm("authConfig", bool.Parse, false);
                bool webServiceSettings = request.GetQueryOrForm("webServiceSettings", bool.Parse, false);
                bool dnsSettings = request.GetQueryOrForm("dnsSettings", bool.Parse, false);
                bool logSettings = request.GetQueryOrForm("logSettings", bool.Parse, false);
                bool zones = request.GetQueryOrForm("zones", bool.Parse, false);
                bool allowedZones = request.GetQueryOrForm("allowedZones", bool.Parse, false);
                bool blockedZones = request.GetQueryOrForm("blockedZones", bool.Parse, false);
                bool blockLists = request.GetQueryOrForm("blockLists", bool.Parse, false);
                bool apps = request.GetQueryOrForm("apps", bool.Parse, false);
                bool stats = request.GetQueryOrForm("stats", bool.Parse, false);
                bool logs = request.GetQueryOrForm("logs", bool.Parse, false);
                bool deleteExistingFiles = request.GetQueryOrForm("deleteExistingFiles", bool.Parse, false);

                if (!request.HasFormContentType || (request.Form.Files.Count == 0))
                    throw new DnsWebServiceException("DNS backup zip file is missing.");

                IReadOnlyList<IPAddress> oldWebServiceLocalAddresses = _dnsWebService._webServiceLocalAddresses;
                int oldWebServiceHttpPort = _dnsWebService._webServiceHttpPort;
                int oldWebServiceTlsPort = _dnsWebService._webServiceTlsPort;

                try
                {
                    string tmpFile = Path.GetTempFileName();
                    try
                    {
                        await using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                        {
                            await request.Form.Files[0].CopyToAsync(fS);

                            fS.Position = 0;

                            await _dnsWebService.RestoreConfigAsync(fS, authConfig, webServiceSettings, dnsSettings, logSettings, zones, allowedZones, blockedZones, blockLists, apps, stats, logs, deleteExistingFiles, context.GetCurrentSession());

                            _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Settings backup zip file was restored.");
                        }
                    }
                    finally
                    {
                        try
                        {
                            File.Delete(tmpFile);
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write(ex);
                        }
                    }

                    Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                    WriteDnsSettings(jsonWriter);
                }
                finally
                {
                    if (dnsSettings || webServiceSettings)
                        _dnsWebService.RestartService(dnsSettings, webServiceSettings, oldWebServiceLocalAddresses, oldWebServiceHttpPort, oldWebServiceTlsPort);
                }
            }

            public void ForceUpdateBlockLists(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                _dnsWebService._dnsServer.BlockListZoneManager.ForceUpdateBlockLists();

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Block list update was triggered.");
            }

            public async Task UpdateIanaDataAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                await _dnsWebService._dnsServer.IanaDataManager.UpdateNowAsync();

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Root zone, arpa zone and trust anchors were updated.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                jsonWriter.WriteStartObject("ianaData");
                _dnsWebService._dnsServer.IanaDataManager.WriteStatus(jsonWriter);
                jsonWriter.WriteEndObject();
            }

            public async Task GetIanaDataAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                IanaDataItem item = context.Request.GetQueryOrFormEnum<IanaDataItem>("item");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                jsonWriter.WriteString("content", await _dnsWebService._dnsServer.IanaDataManager.GetContentAsync(item));
            }

            public async Task SetIanaDataAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;
                IanaDataItem item = request.GetQueryOrFormEnum<IanaDataItem>("item");

                string content = request.QueryOrForm("content");
                if (string.IsNullOrWhiteSpace(content))
                    throw new DnsWebServiceException("Parameter 'content' is missing.");

                await _dnsWebService._dnsServer.IanaDataManager.SetCustomContentAsync(item, content);
                _dnsWebService._dnsServer.SaveConfigFile();

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] A custom version of " + item.ToString() + " was saved and activated.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                jsonWriter.WriteStartObject("ianaData");
                _dnsWebService._dnsServer.IanaDataManager.WriteStatus(jsonWriter);
                jsonWriter.WriteEndObject();
            }

            public void ForceUpdateClientBlockLists(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                _ = _dnsWebService._dnsServer.ClientBlockListManager.UpdateAsync();

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Client block list update was triggered.");
            }

            public void TemporaryDisableBlocking(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                int minutes = context.Request.GetQueryOrForm("minutes", int.Parse);

                _dnsWebService._dnsServer.BlockListZoneManager.TemporaryDisableBlocking(minutes, _dnsWebService.GetRemoteEndPoint(context), sessionUser.Username);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                jsonWriter.WriteString("temporaryDisableBlockingTill", _dnsWebService._dnsServer.BlockListZoneManager.TemporaryDisableBlockingTill);
            }

            #endregion
        }
    }
}
