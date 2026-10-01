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

                foreach (string server in settings.DnsServers)
                    ValidateSimpleValue("dnsServers", server);

                foreach (DhcpReservation reservation in settings.Reservations)
                {
                    ValidateSimpleValue("mac", reservation.HardwareAddress);
                    ValidateSimpleValue("address", reservation.Address);
                    ValidateSimpleValue("hostName", reservation.HostName);
                }

                return settings;
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

                writer.WriteStartArray("listeners");
                foreach (DhcpListenerStatus listener in dhcp.GetListenerStatus())
                {
                    writer.WriteStartObject();
                    writer.WriteString("interface", listener.Interface);
                    writer.WriteBoolean("listening", listener.Listening);

                    if (listener.Error is not null)
                        writer.WriteString("error", listener.Error);

                    writer.WriteStartArray("addresses");
                    foreach (string address in listener.Addresses)
                        writer.WriteStringValue(address);
                    writer.WriteEndArray();
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();

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

                if (!IPAddress.TryParse(context.Request.GetQueryOrForm("address"), out IPAddress address) || (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork))
                    throw new DnsWebServiceException(Lang.T("Ungültige Adresse.", "Invalid address."));

                if (!GetDhcpServer().DeleteLease(address))
                    throw new DnsWebServiceException(Lang.T("Für diese Adresse gibt es kein Lease.", "There is no lease for this address."));

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] DHCP lease was deleted: " + address);
            }

            public void ReserveLease(HttpContext context)
            {
                User sessionUser = CheckPermission(context, PermissionFlag.Modify);

                DhcpServer dhcp = GetDhcpServer();

                if (!IPAddress.TryParse(context.Request.GetQueryOrForm("address"), out IPAddress address) || (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork))
                    throw new DnsWebServiceException(Lang.T("Ungültige Adresse.", "Invalid address."));

                DhcpLease lease = dhcp.LeaseStore.Get(address);

                if ((lease is null) || (lease.HardwareAddress.Length == 0) || string.IsNullOrEmpty(lease.ClientKey))
                    throw new DnsWebServiceException(Lang.T("Für diese Adresse gibt es kein Lease.", "There is no lease for this address."));

                DhcpSettings settings = dhcp.Settings;
                string mac = DhcpUtilities.FormatHardwareAddress(lease.HardwareAddress);
                List<DhcpReservation> reservations = new List<DhcpReservation>(settings.Reservations);

                foreach (DhcpReservation existing in reservations)
                {
                    if (string.Equals(existing.HardwareAddress, mac, StringComparison.OrdinalIgnoreCase) || string.Equals(existing.Address, address.ToString(), StringComparison.Ordinal))
                        throw new DnsWebServiceException(Lang.T("Für diese MAC- oder IP-Adresse gibt es schon eine Reservierung.", "A reservation for this MAC or IP address already exists."));
                }

                string hostName = lease.HostName;
                if ((hostName is not null) && !DhcpUtilities.IsValidHostLabel(hostName))
                    hostName = null;

                reservations.Add(new DhcpReservation() { HardwareAddress = mac, Address = address.ToString(), HostName = hostName ?? "" });

                List<DhcpConfigError> errors = dhcp.Apply(settings.WithReservations(reservations), true);

                if (errors.Count > 0)
                    throw new DnsWebServiceException(Lang.T("Die Reservierung passt nicht zur Konfiguration: ", "The reservation does not fit the configuration: ") + errors[0].Message);

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] DHCP lease was converted into a reservation: " + address + " " + mac);
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
