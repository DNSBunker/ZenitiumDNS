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
using System.Globalization;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;
using ZenitiumDns.ApplicationCommon;
using ZenitiumDns.Core.Auth;
using ZenitiumDns.Core.Dhcp;
using ZenitiumDns.Core.Dns;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;

namespace ZenitiumDns.Core
{
    public partial class DnsWebService
    {
        sealed class WebServiceDhcpApi
        {
            #region variables

            readonly DnsWebService _dnsWebService;

            #endregion

            #region constructor

            public WebServiceDhcpApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

            private User CheckPermission(HttpContext context, PermissionFlag flag)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, flag))
                    throw new DnsWebServiceException("Access was denied.");

                return sessionUser;
            }

            private DhcpServer GetDhcpServer()
            {
                DhcpServer dhcpServer = _dnsWebService._dhcpServer;

                if (dhcpServer is null)
                    throw new DnsWebServiceException(Lang.T("Der DHCP-Server ist nicht gestartet, Details stehen im Protokoll.", "The DHCP server is not running, see the log for details."));

                return dhcpServer;
            }

            private static void WriteErrors(Utf8JsonWriter writer, IReadOnlyList<DhcpConfigError> errors)
            {
                writer.WriteStartArray("errors");

                foreach (DhcpConfigError error in errors)
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("line", error.Line);
                    writer.WriteString("message", error.Message);
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
            }

            private static void WriteTime(Utf8JsonWriter writer, string name, DateTime value)
            {
                if ((value == DateTime.MinValue) || (value == DateTime.MaxValue))
                    writer.WriteNull(name);
                else
                    writer.WriteString(name, DateTime.SpecifyKind(value, DateTimeKind.Utc));
            }

            private static void ValidateSimpleValue(string name, string value)
            {
                if (string.IsNullOrEmpty(value))
                    return;

                foreach (char c in value)
                {
                    if ((c == '\n') || (c == '\r') || (c == ',') || (c == '#') || (c == '"') || (c == '='))
                        throw new DnsWebServiceException(Lang.T("Ungültiges Zeichen im Feld ", "Invalid character in field ") + name + ".");
                }
            }

            private static DhcpSettings ParseSettings(string json)
            {
                if (string.IsNullOrWhiteSpace(json))
                    throw new DnsWebServiceException("Parameter 'settings' is missing.");

                DhcpSettings settings;

                try
                {
                    using (JsonDocument document = JsonDocument.Parse(json))
                    {
                        settings = DhcpSettings.ReadFrom(document.RootElement);
                    }
                }
                catch (JsonException ex)
                {
                    throw new DnsWebServiceException("Invalid settings JSON: " + ex.Message);
                }

                ValidateSimpleValue("interface", settings.Interface);
                ValidateSimpleValue("rangeStart", settings.RangeStart);
                ValidateSimpleValue("rangeEnd", settings.RangeEnd);
                ValidateSimpleValue("netmask", settings.Netmask);
                ValidateSimpleValue("gateway", settings.Gateway);
                ValidateSimpleValue("domain", settings.Domain);
                ValidateSimpleValue("leaseTime", settings.LeaseTime);
                ValidateSimpleValue("ipv6RangeStart", settings.Ipv6RangeStart);
                ValidateSimpleValue("ipv6RangeEnd", settings.Ipv6RangeEnd);

                foreach (string server in settings.DnsServers)
                    ValidateSimpleValue("dnsServers", server);

                foreach (DhcpReservation reservation in settings.Reservations)
                {
                    ValidateSimpleValue("mac", reservation.HardwareAddress);
                    ValidateSimpleValue("address", reservation.Address);
                    ValidateSimpleValue("address6", reservation.Address6);
                    ValidateSimpleValue("hostName", reservation.HostName);
                }

                return settings;
            }

            private bool CanAssignProfiles(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);
                return _dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify);
            }

            private void WriteProfileNames(Utf8JsonWriter writer, HttpContext context, bool withIdentifiers)
            {
                writer.WriteBoolean("canAssignProfiles", CanAssignProfiles(context));
                writer.WriteStartArray("profiles");

                foreach (ClientProfile profile in _dnsWebService._dnsServer.ClientProfileManager.Profiles)
                {
                    writer.WriteStartObject();
                    writer.WriteString("name", profile.Name);

                    if (withIdentifiers)
                        WriteStringArray(writer, "identifiers", profile.Identifiers);

                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
            }

            private void WriteResolvedProfile(Utf8JsonWriter writer, IPAddress address, byte[] hardwareAddress)
            {
                string mac = hardwareAddress is null ? null : ClientProfileManager.FormatHardwareAddress(hardwareAddress);
                ClientProfile profile = _dnsWebService._dnsServer.ClientProfileManager.ResolveDevice(address, mac, out string matchedBy);

                if (profile is not null)
                {
                    writer.WriteString("profile", profile.Name);
                    writer.WriteString("profileBy", matchedBy);
                }
            }

            private static void WriteStringArray(Utf8JsonWriter writer, string name, IEnumerable<string> values)
            {
                writer.WriteStartArray(name);

                foreach (string value in values)
                    writer.WriteStringValue(value);

                writer.WriteEndArray();
            }

            private static void WriteListeners(Utf8JsonWriter writer, string name, List<DhcpListenerStatus> listeners)
            {
                writer.WriteStartArray(name);
                foreach (DhcpListenerStatus listener in listeners)
                {
                    writer.WriteStartObject();
                    writer.WriteString("interface", listener.Interface);
                    writer.WriteBoolean("listening", listener.Listening);

                    if (listener.Error is not null)
                        writer.WriteString("error", listener.Error);

                    WriteStringArray(writer, "addresses", listener.Addresses);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();
            }

            private static void WriteIpv6Status(Utf8JsonWriter writer, DhcpServer dhcp)
            {
                writer.WriteStartObject("ipv6");
                writer.WriteString("serverDuid", DhcpUtilities.FormatHex(dhcp.ServerDuid));
                WriteListeners(writer, "listeners", dhcp.GetListener6Status());

                writer.WriteStartArray("routerAdvertisements");
                foreach (RaInterfaceStatus status in dhcp.GetRaStatus())
                {
                    writer.WriteStartObject();
                    writer.WriteString("interface", status.Interface);
                    writer.WriteBoolean("active", status.Active);

                    if (status.Error is not null)
                        writer.WriteString("error", status.Error);

                    if (status.Plan is not null)
                    {
                        RaPlan plan = status.Plan;
                        writer.WriteBoolean("managed", plan.Managed);
                        writer.WriteBoolean("other", plan.Other);
                        writer.WriteNumber("routerLifetime", plan.RouterLifetime);
                        writer.WriteNumber("interval", plan.Interval);

                        if (plan.Mtu > 0)
                            writer.WriteNumber("mtu", plan.Mtu);

                        writer.WriteStartArray("prefixes");
                        foreach (RaPrefix prefix in plan.Prefixes)
                        {
                            writer.WriteStartObject();
                            writer.WriteString("prefix", prefix.ToString());
                            writer.WriteBoolean("slaac", prefix.Autonomous);
                            writer.WriteBoolean("onLink", prefix.OnLink);
                            writer.WriteNumber("validLifetime", prefix.ValidLifetime);
                            writer.WriteEndObject();
                        }
                        writer.WriteEndArray();

                        List<string> dnsServers = new List<string>();
                        foreach (IPAddress address in plan.DnsServers)
                            dnsServers.Add(address.ToString());

                        WriteStringArray(writer, "dnsServers", dnsServers);
                        WriteStringArray(writer, "searchDomains", plan.SearchDomains);
                        WriteTime(writer, "lastSent", status.LastSent);
                        writer.WriteNumber("sent", status.Sent);
                        writer.WriteNumber("solicitations", status.Solicitations);
                    }

                    writer.WriteEndObject();
                }
                writer.WriteEndArray();

                writer.WriteStartArray("foreignRouters");
                foreach (RaForeignRouter router in dhcp.GetForeignRouters())
                {
                    writer.WriteStartObject();
                    writer.WriteString("address", router.Address.ToString());
                    writer.WriteString("interface", router.Interface);
                    writer.WriteBoolean("managed", router.Managed);
                    writer.WriteBoolean("other", router.Other);
                    writer.WriteNumber("routerLifetime", router.RouterLifetime);
                    WriteStringArray(writer, "prefixes", router.Prefixes);
                    WriteStringArray(writer, "dnsServers", router.DnsServers);
                    WriteStringArray(writer, "searchDomains", router.SearchDomains);
                    WriteTime(writer, "firstSeen", router.FirstSeen);
                    WriteTime(writer, "lastSeen", router.LastSeen);
                    writer.WriteNumber("count", router.Count);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();

                writer.WriteStartArray("foreignServers");
                foreach (DhcpForeignServer server in dhcp.GetForeignServers6())
                {
                    writer.WriteStartObject();
                    writer.WriteString("serverId", server.ServerId);
                    writer.WriteString("interface", server.Interface);
                    WriteTime(writer, "firstSeen", server.FirstSeen);
                    WriteTime(writer, "lastSeen", server.LastSeen);
                    writer.WriteNumber("count", server.Count);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();

                (UInt128 total, int used) = dhcp.GetPoolUsage6();
                writer.WriteString("poolSize", total.ToString(CultureInfo.InvariantCulture));
                writer.WriteNumber("poolUsed", used);
                writer.WriteNumber("activeLeases", dhcp.LeaseStore6.CountActive(DateTime.UtcNow));

                writer.WriteStartObject("counters");
                foreach (KeyValuePair<string, long> counter in dhcp.GetCounters6())
                    writer.WriteNumber(counter.Key, counter.Value);
                writer.WriteEndObject();

                writer.WriteEndObject();
            }

            #endregion

            #region public

            public void GetStatus(HttpContext context)
            {
                CheckPermission(context, PermissionFlag.View);

                DhcpServer dhcp = GetDhcpServer();
                DhcpSettings settings = dhcp.Settings;
                Utf8JsonWriter writer = context.GetCurrentJsonWriter();

                writer.WriteBoolean("enabled", settings.Enabled);
                writer.WriteBoolean("serving", dhcp.IsServing);
                writer.WriteBoolean("offersPaused", dhcp.OffersPaused);
                writer.WriteString("priority", settings.Priority.ToString().ToLowerInvariant());
                writer.WriteBoolean("unicastAvailable", dhcp.RawSenderError is null);

                if (dhcp.RawSenderError is not null)
                    writer.WriteString("unicastError", dhcp.RawSenderError);

                WriteErrors(writer, dhcp.ConfigErrors);

                WriteListeners(writer, "listeners", dhcp.GetListenerStatus());

                (int total, int used) = dhcp.GetPoolUsage();
                writer.WriteNumber("poolSize", total);
                writer.WriteNumber("poolUsed", used);
                writer.WriteNumber("activeLeases", dhcp.LeaseStore.CountActive(DateTime.UtcNow));

                writer.WriteStartObject("counters");
                foreach (KeyValuePair<string, long> counter in dhcp.GetCounters())
                    writer.WriteNumber(counter.Key, counter.Value);
                writer.WriteEndObject();

                writer.WriteBoolean("rogueDetection", settings.RogueDetection);
                WriteTime(writer, "lastProbe", dhcp.LastProbe);

                if (dhcp.LastProbeError is not null)
                    writer.WriteString("lastProbeError", dhcp.LastProbeError);

                writer.WriteStartArray("foreignServers");
                foreach (DhcpForeignServer server in dhcp.GetForeignServers())
                {
                    writer.WriteStartObject();
                    writer.WriteString("address", server.Address.ToString());
                    writer.WriteString("interface", server.Interface);
                    writer.WriteString("source", server.Source);
                    WriteTime(writer, "firstSeen", server.FirstSeen);
                    WriteTime(writer, "lastSeen", server.LastSeen);
                    writer.WriteNumber("count", server.Count);

                    if (server.OfferedAddress is not null)
                        writer.WriteString("offeredAddress", server.OfferedAddress.ToString());

                    writer.WriteEndObject();
                }
                writer.WriteEndArray();

                WriteIpv6Status(writer, dhcp);
            }

            public void GetSettings(HttpContext context)
            {
                CheckPermission(context, PermissionFlag.View);

                DhcpServer dhcp = GetDhcpServer();
                DhcpSettings settings = dhcp.Settings;
                Utf8JsonWriter writer = context.GetCurrentJsonWriter();

                writer.WritePropertyName("settings");
                settings.WriteTo(writer, false);

                writer.WriteString("generated", settings.GenerateSimpleConfig(out _));
                WriteErrors(writer, dhcp.ConfigErrors);

                writer.WriteStartArray("interfaces");
                foreach (DhcpInterfaceInfo info in DhcpServer.GetInterfaces())
                {
                    writer.WriteStartObject();
                    writer.WriteString("name", info.Name);

                    writer.WriteStartArray("addresses");
                    foreach (DhcpInterfaceAddress address in info.Addresses)
                        writer.WriteStringValue(address.Address + "/" + address.PrefixLength);
                    writer.WriteEndArray();

                    if (info.Gateway is not null)
                        writer.WriteString("gateway", info.Gateway.ToString());

                    writer.WriteEndObject();
                }

                List<DhcpInterfaceInfo> interfaces4 = DhcpServer.GetInterfaces();

                foreach (Dhcp6InterfaceInfo info in Dhcp6Utilities.GetInterfaces())
                {
                    bool known = false;

                    foreach (DhcpInterfaceInfo info4 in interfaces4)
                    {
                        if (info4.Name == info.Name)
                        {
                            known = true;
                            break;
                        }
                    }

                    if (known || (info.LinkLocal is null))
                        continue;

                    writer.WriteStartObject();
                    writer.WriteString("name", info.Name);
                    writer.WriteStartArray("addresses");
                    writer.WriteEndArray();
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();

                writer.WriteStartArray("interfaces6");
                foreach (Dhcp6InterfaceInfo info in Dhcp6Utilities.GetInterfaces())
                {
                    writer.WriteStartObject();
                    writer.WriteString("name", info.Name);
                    writer.WriteBoolean("forwarding", info.Forwarding);

                    if (info.LinkLocal is not null)
                        writer.WriteString("linkLocal", info.LinkLocal.ToString());

                    writer.WriteStartArray("prefixes");
                    foreach (Dhcp6InterfaceAddress address in info.GetPrefixAddresses(64))
                        writer.WriteStringValue(Dhcp6Utilities.FormatPrefix(Dhcp6Utilities.GetPrefix(Dhcp6Utilities.ToUInt128(address.Address), 64), 64));
                    writer.WriteEndArray();

                    writer.WriteStartArray("addresses");
                    foreach (Dhcp6InterfaceAddress address in info.Addresses)
                    {
                        if (!address.IsLinkLocal && !address.IsTemporary)
                            writer.WriteStringValue(address.Address + "/" + address.PrefixLength);
                    }
                    writer.WriteEndArray();

                    writer.WriteEndObject();
                }
                writer.WriteEndArray();

                writer.WriteStartArray("options");
                List<DhcpOptionDefinition> definitions = new List<DhcpOptionDefinition>(DhcpOptionCatalog.Definitions);
                definitions.Sort(delegate (DhcpOptionDefinition x, DhcpOptionDefinition y) { return x.Code.CompareTo(y.Code); });

                foreach (DhcpOptionDefinition definition in definitions)
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("code", definition.Code);
                    writer.WriteString("name", definition.Name);
                    writer.WriteString("type", definition.Type.ToString());
                    writer.WriteBoolean("managed", definition.Protected);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();

                WriteProfileNames(writer, context, true);

                writer.WriteStartArray("options6");
                List<Dhcp6OptionDefinition> definitions6 = new List<Dhcp6OptionDefinition>(Dhcp6OptionCatalog.Definitions);
                definitions6.Sort(delegate (Dhcp6OptionDefinition x, Dhcp6OptionDefinition y) { return x.Code.CompareTo(y.Code); });

                foreach (Dhcp6OptionDefinition definition in definitions6)
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("code", definition.Code);
                    writer.WriteString("name", definition.Name);
                    writer.WriteString("type", definition.Type.ToString());
                    writer.WriteBoolean("managed", definition.Protected);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();

            }

            public void ValidateSettings(HttpContext context)
            {
                CheckPermission(context, PermissionFlag.View);

                DhcpSettings settings = ParseSettings(context.Request.GetQueryOrForm("settings"));
                List<DhcpConfigError> errors = settings.Validate(out DhcpConfiguration config);
                Utf8JsonWriter writer = context.GetCurrentJsonWriter();

                WriteErrors(writer, errors);
                writer.WriteString("generated", settings.GenerateSimpleConfig(out _));
                writer.WriteNumber("ranges", config.Ranges.Count);
                writer.WriteNumber("ranges6", config.Ranges6.Count);
                writer.WriteNumber("hosts", config.Hosts.Count);
                writer.WriteNumber("options", config.Options.Count);
            }

            public void SetSettings(HttpContext context)
            {
                User sessionUser = CheckPermission(context, PermissionFlag.Modify);

                DhcpServer dhcp = GetDhcpServer();
                DhcpSettings settings = ParseSettings(context.Request.GetQueryOrForm("settings"));

                List<DhcpConfigError> errors = dhcp.Apply(settings, true);
                Utf8JsonWriter writer = context.GetCurrentJsonWriter();

                WriteErrors(writer, errors);
                writer.WriteBoolean("saved", errors.Count == 0);

                if (errors.Count == 0)
                {
                    _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] DHCP settings were saved.");
                }
            }

            public void ListLeases(HttpContext context)
            {
                CheckPermission(context, PermissionFlag.View);

                DhcpServer dhcp = GetDhcpServer();
                DateTime now = DateTime.UtcNow;
                List<DhcpLease> leases = dhcp.LeaseStore.GetAll();

                leases.Sort(delegate (DhcpLease x, DhcpLease y) { return DhcpUtilities.ToUInt32(x.Address).CompareTo(DhcpUtilities.ToUInt32(y.Address)); });

                Utf8JsonWriter writer = context.GetCurrentJsonWriter();
                writer.WriteStartArray("leases");

                foreach (DhcpLease lease in leases)
                {
                    if ((lease.State == DhcpLeaseState.Free) || (lease.State == DhcpLeaseState.Offered))
                        continue;

                    string state = lease.State.ToString().ToLowerInvariant();

                    if ((lease.State == DhcpLeaseState.Bound) && !lease.IsActive(now))
                        state = "expired";
                    else if ((lease.State == DhcpLeaseState.Declined) && (lease.Expires <= now))
                        continue;

                    writer.WriteStartObject();
                    writer.WriteString("address", lease.Address.ToString());
                    writer.WriteString("hardwareAddress", DhcpUtilities.FormatHardwareAddress(lease.HardwareAddress));

                    if ((lease.ClientId is not null) && (lease.ClientId.Length > 0))
                        writer.WriteString("clientId", DhcpUtilities.FormatHex(lease.ClientId));

                    writer.WriteString("hostName", lease.HostName ?? "");
                    writer.WriteString("clientHostName", lease.ClientHostName ?? "");
                    writer.WriteString("vendorClass", lease.VendorClass ?? "");
                    writer.WriteString("state", state);
                    writer.WriteBoolean("reserved", lease.Reserved);

                    if ((lease.ClientId is not null) && (lease.ClientId.Length > 6) && (lease.ClientId[0] == 0xFF))
                        writer.WriteString("duid", DhcpUtilities.FormatHex(lease.ClientId.AsSpan(5).ToArray()));

                    WriteResolvedProfile(writer, lease.Address, lease.HardwareAddress.Length == 6 ? lease.HardwareAddress : null);
                    WriteTime(writer, "start", lease.Start);

                    if (lease.IsInfinite)
                        writer.WriteString("expires", "infinite");
                    else
                        WriteTime(writer, "expires", lease.Expires);

                    writer.WriteEndObject();
                }

                writer.WriteEndArray();

                WriteProfileNames(writer, context, false);

                List<Dhcp6Lease> leases6 = dhcp.LeaseStore6.GetAll();
                leases6.Sort(delegate (Dhcp6Lease x, Dhcp6Lease y) { return Dhcp6Utilities.ToUInt128(x.Address).CompareTo(Dhcp6Utilities.ToUInt128(y.Address)); });

                writer.WriteStartArray("leases6");

                foreach (Dhcp6Lease lease in leases6)
                {
                    if ((lease.State == DhcpLeaseState.Free) || (lease.State == DhcpLeaseState.Offered))
                        continue;

                    string state = lease.State.ToString().ToLowerInvariant();

                    if ((lease.State == DhcpLeaseState.Bound) && !lease.IsActive(now))
                        state = "expired";
                    else if ((lease.State == DhcpLeaseState.Declined) && (lease.Expires <= now))
                        continue;

                    writer.WriteStartObject();
                    writer.WriteString("address", lease.Address.ToString());
                    writer.WriteString("duid", DhcpUtilities.FormatHex(lease.Duid));
                    writer.WriteNumber("iaid", lease.Iaid);
                    writer.WriteString("hardwareAddress", DhcpUtilities.FormatHardwareAddress(lease.HardwareAddress));
                    writer.WriteString("hostName", lease.HostName ?? "");
                    writer.WriteString("clientHostName", lease.ClientHostName ?? "");
                    writer.WriteString("interface", lease.Interface ?? "");
                    writer.WriteString("state", state);
                    writer.WriteBoolean("reserved", lease.Reserved);
                    WriteResolvedProfile(writer, lease.Address, lease.HardwareAddress.Length == 6 ? lease.HardwareAddress : null);
                    WriteTime(writer, "start", lease.Start);

                    if (lease.IsInfinite)
                        writer.WriteString("expires", "infinite");
                    else
                        WriteTime(writer, "expires", lease.Expires);

                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
            }

            public void DeleteLease(HttpContext context)
            {
                User sessionUser = CheckPermission(context, PermissionFlag.Delete);

                if (!IPAddress.TryParse(context.Request.GetQueryOrForm("address"), out IPAddress address) || ((address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) && (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)))
                    throw new DnsWebServiceException(Lang.T("Ungültige Adresse.", "Invalid address."));

                if (!GetDhcpServer().DeleteLease(address))
                    throw new DnsWebServiceException(Lang.T("Für diese Adresse gibt es kein Lease.", "There is no lease for this address."));

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] DHCP lease was deleted: " + address);
            }

            public void ReserveLease(HttpContext context)
            {
                User sessionUser = CheckPermission(context, PermissionFlag.Modify);

                DhcpServer dhcp = GetDhcpServer();

                if (!IPAddress.TryParse(context.Request.GetQueryOrForm("address"), out IPAddress address) || ((address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) && (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)))
                    throw new DnsWebServiceException(Lang.T("Ungültige Adresse.", "Invalid address."));

                bool ipv6 = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6;
                byte[] hardwareAddress;
                string hostName;
                string reservedText;

                if (ipv6)
                {
                    Dhcp6Lease lease = dhcp.LeaseStore6.Get(address);

                    if (lease is null)
                        throw new DnsWebServiceException(Lang.T("Für diese Adresse gibt es kein Lease.", "There is no lease for this address."));

                    if (lease.HardwareAddress.Length == 0)
                        throw new DnsWebServiceException(Lang.T("Das Gerät nennt in seiner DUID keine MAC-Adresse. Die Reservierung lässt sich im Reiter Experte mit id:" + DhcpUtilities.FormatHex(lease.Duid) + " anlegen.", "The device does not include a MAC address in its DUID. Create the reservation in the Expert tab with id:" + DhcpUtilities.FormatHex(lease.Duid) + "."));

                    hardwareAddress = lease.HardwareAddress;
                    hostName = lease.HostName;
                    reservedText = Dhcp6Utilities.ToAddress(Dhcp6Utilities.ToUInt128(address) & (UInt128.MaxValue >> 64)).ToString();
                }
                else
                {
                    DhcpLease lease = dhcp.LeaseStore.Get(address);

                    if ((lease is null) || (lease.HardwareAddress.Length == 0) || string.IsNullOrEmpty(lease.ClientKey))
                        throw new DnsWebServiceException(Lang.T("Für diese Adresse gibt es kein Lease.", "There is no lease for this address."));

                    hardwareAddress = lease.HardwareAddress;
                    hostName = lease.HostName;
                    reservedText = address.ToString();
                }

                DhcpSettings settings = dhcp.Settings;
                string mac = DhcpUtilities.FormatHardwareAddress(hardwareAddress);
                List<DhcpReservation> reservations = new List<DhcpReservation>(settings.Reservations);
                int merge = -1;

                for (int i = 0; i < reservations.Count; i++)
                {
                    DhcpReservation existing = reservations[i];
                    bool sameMac = string.Equals(existing.HardwareAddress, mac, StringComparison.OrdinalIgnoreCase);
                    string existingAddress = ipv6 ? existing.Address6 : existing.Address;

                    if (sameMac && string.IsNullOrWhiteSpace(existingAddress))
                    {
                        merge = i;
                        continue;
                    }

                    if (sameMac || string.Equals(existingAddress, reservedText, StringComparison.OrdinalIgnoreCase))
                        throw new DnsWebServiceException(Lang.T("Für diese MAC- oder IP-Adresse gibt es schon eine Reservierung.", "A reservation for this MAC or IP address already exists."));
                }

                if ((hostName is not null) && !DhcpUtilities.IsValidHostLabel(hostName))
                    hostName = null;

                if (merge >= 0)
                {
                    DhcpReservation existing = reservations[merge];

                    reservations[merge] = new DhcpReservation()
                    {
                        HardwareAddress = existing.HardwareAddress,
                        Address = ipv6 ? existing.Address : reservedText,
                        Address6 = ipv6 ? reservedText : existing.Address6,
                        HostName = string.IsNullOrWhiteSpace(existing.HostName) ? hostName ?? "" : existing.HostName
                    };
                }
                else
                {
                    reservations.Add(new DhcpReservation() { HardwareAddress = mac, Address = ipv6 ? "" : reservedText, Address6 = ipv6 ? reservedText : "", HostName = hostName ?? "" });
                }

                List<DhcpConfigError> errors = dhcp.Apply(settings.WithReservations(reservations), true);

                if (errors.Count > 0)
                    throw new DnsWebServiceException(Lang.T("Die Reservierung passt nicht zur Konfiguration: ", "The reservation does not fit the configuration: ") + errors[0].Message);

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] DHCP lease was converted into a reservation: " + reservedText + " " + mac);
            }

            public async Task ListDevicesAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.View) && !_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                DhcpServer dhcp = GetDhcpServer();
                List<DhcpDevice> devices = dhcp.GetDevices();
                List<Task> lookups = new List<Task>();

                foreach (DhcpDevice device in devices)
                {
                    if ((device.HostName is not null) || (device.Addresses4.Count == 0) || (lookups.Count >= 64))
                        continue;

                    DhcpDevice target = device;
                    IPAddress address = IPAddress.Parse(device.Addresses4.Min);

                    lookups.Add(Task.Run(async delegate ()
                    {
                        try
                        {
                            DnsDatagram response = await _dnsWebService._dnsServer.DirectQueryAsync(new DnsQuestionRecord(address, DnsClass.IN), 500);
                            IReadOnlyList<string> names = DnsClient.ParseResponsePTR(response);

                            if (names.Count > 0)
                                target.HostName = names[0].TrimEnd('.');
                        }
                        catch
                        { }
                    }));
                }

                await Task.WhenAll(lookups);

                devices.Sort(delegate (DhcpDevice x, DhcpDevice y)
                {
                    int c = string.Compare(x.HostName ?? "\uffff", y.HostName ?? "\uffff", StringComparison.OrdinalIgnoreCase);
                    return c != 0 ? c : string.CompareOrdinal(x.HardwareAddress ?? "", y.HardwareAddress ?? "");
                });

                Utf8JsonWriter writer = context.GetCurrentJsonWriter();
                writer.WriteStartArray("devices");

                foreach (DhcpDevice device in devices)
                {
                    writer.WriteStartObject();

                    if (device.HardwareAddress is not null)
                        writer.WriteString("mac", device.HardwareAddress);

                    writer.WriteString("hostName", device.HostName ?? "");
                    WriteStringArray(writer, "ipv4", device.Addresses4);
                    WriteStringArray(writer, "ipv6", device.Addresses6);

                    if (device.ClientId is not null)
                        writer.WriteString("clientId", device.ClientId);

                    WriteStringArray(writer, "duids", device.Duids);
                    writer.WriteBoolean("reserved", device.Reserved);
                    WriteStringArray(writer, "sources", device.Sources);
                    WriteTime(writer, "lastSeen", device.LastSeen);

                    IPAddress first = device.Addresses4.Count > 0 ? IPAddress.Parse(device.Addresses4.Min) : (device.Addresses6.Count > 0 ? IPAddress.Parse(device.Addresses6.Min) : null);
                    byte[] mac = device.HardwareAddress is null ? null : Convert.FromHexString(device.HardwareAddress.Replace(":", ""));
                    WriteResolvedProfile(writer, first, mac);

                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                WriteProfileNames(writer, context, false);
            }

            public async Task ProbeAsync(HttpContext context)
            {
                CheckPermission(context, PermissionFlag.Modify);

                DhcpServer dhcp = GetDhcpServer();
                await dhcp.ProbeAsync();

                GetStatus(context);
            }

            public void ClearForeignServers(HttpContext context)
            {
                CheckPermission(context, PermissionFlag.Modify);
                GetDhcpServer().ClearForeignServers();
            }

            #endregion
        }
    }
}
