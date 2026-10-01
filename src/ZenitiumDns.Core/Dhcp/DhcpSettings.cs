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

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;

namespace ZenitiumDns.Core.Dhcp
{
    public enum DhcpPriorityMode : byte
    {
        Primary = 0,
        Delayed = 1,
        Standby = 2
    }

    public sealed class DhcpReservation
    {
        public string HardwareAddress { get; init; }

        public string Address { get; init; }

        public string HostName { get; init; }
    }

    public sealed class DhcpSettings
    {
        #region variables

        public const int FILE_VERSION = 1;
        public const int MAX_EXPERT_LENGTH = 1024 * 1024;
        public const int MAX_RESERVATIONS = 5000;

        #endregion

        #region properties

        public bool Enabled { get; init; }

        public bool SimpleEnabled { get; init; } = true;

        public string Interface { get; init; } = "";

        public string RangeStart { get; init; } = "";

        public string RangeEnd { get; init; } = "";

        public string Netmask { get; init; } = "";

        public string Gateway { get; init; } = "";

        public IReadOnlyList<string> DnsServers { get; init; } = [];

        public string Domain { get; init; } = "";

        public string LeaseTime { get; init; } = "24h";

        public bool Authoritative { get; init; } = true;

        public IReadOnlyList<DhcpReservation> Reservations { get; init; } = [];

        public string Expert { get; init; } = "";

        public DhcpPriorityMode Priority { get; init; } = DhcpPriorityMode.Primary;

        public int ResponseDelayMs { get; init; } = 2000;

        public int MinSecs { get; init; }

        public bool PingCheck { get; init; } = true;

        public int PingTimeoutMs { get; init; } = 500;

        public bool RogueDetection { get; init; } = true;

        public int RogueProbeIntervalSeconds { get; init; } = 300;

        public bool RegisterDns { get; init; } = true;

        public uint DnsTtl { get; init; } = 60;

        #endregion

        #region public

        public string GenerateSimpleConfig(out List<string> errors)
        {
            errors = new List<string>();
            StringBuilder sb = new StringBuilder();

            if (!SimpleEnabled)
                return "";

            if (!string.IsNullOrWhiteSpace(Interface))
                sb.Append("interface=").Append(Interface.Trim()).Append('\n');

            bool hasRange = !string.IsNullOrWhiteSpace(RangeStart) || !string.IsNullOrWhiteSpace(RangeEnd);

            if (hasRange)
            {
                sb.Append("dhcp-range=set:simple,").Append(RangeStart.Trim()).Append(',').Append(RangeEnd.Trim());

                if (!string.IsNullOrWhiteSpace(Netmask))
                    sb.Append(',').Append(Netmask.Trim());

                sb.Append(',').Append(string.IsNullOrWhiteSpace(LeaseTime) ? "24h" : LeaseTime.Trim()).Append('\n');

                if (!string.IsNullOrWhiteSpace(Gateway))
                    sb.Append("dhcp-option=tag:simple,option:router,").Append(Gateway.Trim()).Append('\n');

                List<string> dns = new List<string>();
                foreach (string server in DnsServers)
                {
                    if (!string.IsNullOrWhiteSpace(server))
                        dns.Add(server.Trim());
                }

                if (dns.Count > 0)
                    sb.Append("dhcp-option=tag:simple,option:dns-server,").Append(string.Join(',', dns)).Append('\n');

                if (!string.IsNullOrWhiteSpace(Domain))
                    sb.Append("dhcp-option=tag:simple,option:domain-search,").Append(Domain.Trim().TrimEnd('.')).Append('\n');
            }

            if (!string.IsNullOrWhiteSpace(Domain))
                sb.Append("domain=").Append(Domain.Trim().TrimEnd('.')).Append(",local\n");

            foreach (DhcpReservation reservation in Reservations)
            {
                if (string.IsNullOrWhiteSpace(reservation.HardwareAddress))
                {
                    errors.Add("a reservation has no MAC address");
                    continue;
                }

                sb.Append("dhcp-host=").Append(reservation.HardwareAddress.Trim());

                if (!string.IsNullOrWhiteSpace(reservation.Address))
                    sb.Append(',').Append(reservation.Address.Trim());

                if (!string.IsNullOrWhiteSpace(reservation.HostName))
                    sb.Append(',').Append(reservation.HostName.Trim());

                sb.Append('\n');
            }

            if (Authoritative)
                sb.Append("dhcp-authoritative\n");

            return sb.ToString();
        }

        public string GetEffectiveConfigText(out int simpleLineCount)
        {
            string simple = GenerateSimpleConfig(out _);
            simpleLineCount = 0;

            foreach (char c in simple)
            {
                if (c == '\n')
                    simpleLineCount++;
            }

            return simple + (Expert ?? "");
        }

        public void WriteTo(Utf8JsonWriter writer, bool includeVersion = true)
        {
            writer.WriteStartObject();

            if (includeVersion)
                writer.WriteNumber("version", FILE_VERSION);

            writer.WriteBoolean("enabled", Enabled);
            writer.WriteBoolean("simpleEnabled", SimpleEnabled);
            writer.WriteString("interface", Interface);
            writer.WriteString("rangeStart", RangeStart);
            writer.WriteString("rangeEnd", RangeEnd);
            writer.WriteString("netmask", Netmask);
            writer.WriteString("gateway", Gateway);

            writer.WriteStartArray("dnsServers");
            foreach (string server in DnsServers)
                writer.WriteStringValue(server);
            writer.WriteEndArray();

            writer.WriteString("domain", Domain);
            writer.WriteString("leaseTime", LeaseTime);
            writer.WriteBoolean("authoritative", Authoritative);

            writer.WriteStartArray("reservations");
            foreach (DhcpReservation reservation in Reservations)
            {
                writer.WriteStartObject();
                writer.WriteString("mac", reservation.HardwareAddress ?? "");
                writer.WriteString("address", reservation.Address ?? "");
                writer.WriteString("hostName", reservation.HostName ?? "");
                writer.WriteEndObject();
            }
            writer.WriteEndArray();

            writer.WriteString("expert", Expert ?? "");
            writer.WriteString("priority", Priority.ToString().ToLowerInvariant());
            writer.WriteNumber("responseDelayMs", ResponseDelayMs);
            writer.WriteNumber("minSecs", MinSecs);
            writer.WriteBoolean("pingCheck", PingCheck);
            writer.WriteNumber("pingTimeoutMs", PingTimeoutMs);
            writer.WriteBoolean("rogueDetection", RogueDetection);
            writer.WriteNumber("rogueProbeIntervalSeconds", RogueProbeIntervalSeconds);
            writer.WriteBoolean("registerDns", RegisterDns);
            writer.WriteNumber("dnsTtl", DnsTtl);
            writer.WriteEndObject();
        }

        public byte[] ToJson()
        {
            using (MemoryStream mS = new MemoryStream())
            {
                using (Utf8JsonWriter writer = new Utf8JsonWriter(mS, new JsonWriterOptions() { Indented = true }))
                {
                    WriteTo(writer);
                }

                return mS.ToArray();
            }
        }

        public static DhcpSettings ReadFrom(JsonElement root)
        {
            List<string> dns = new List<string>();
            if (root.TryGetProperty("dnsServers", out JsonElement jsonDns) && (jsonDns.ValueKind == JsonValueKind.Array))
            {
                foreach (JsonElement item in jsonDns.EnumerateArray())
                    dns.Add(item.GetString() ?? "");
            }

            List<DhcpReservation> reservations = new List<DhcpReservation>();
            if (root.TryGetProperty("reservations", out JsonElement jsonReservations) && (jsonReservations.ValueKind == JsonValueKind.Array))
            {
                foreach (JsonElement item in jsonReservations.EnumerateArray())
                {
                    reservations.Add(new DhcpReservation()
                    {
                        HardwareAddress = GetString(item, "mac"),
                        Address = GetString(item, "address"),
                        HostName = GetString(item, "hostName")
                    });
                }
            }

            DhcpPriorityMode priority = DhcpPriorityMode.Primary;
            if (root.TryGetProperty("priority", out JsonElement jsonPriority) && !Enum.TryParse(jsonPriority.GetString(), true, out priority))
                priority = DhcpPriorityMode.Primary;

            return new DhcpSettings()
            {
                Enabled = GetBool(root, "enabled", false),
                SimpleEnabled = GetBool(root, "simpleEnabled", true),
                Interface = GetString(root, "interface"),
                RangeStart = GetString(root, "rangeStart"),
                RangeEnd = GetString(root, "rangeEnd"),
                Netmask = GetString(root, "netmask"),
                Gateway = GetString(root, "gateway"),
                DnsServers = dns,
                Domain = GetString(root, "domain"),
                LeaseTime = GetString(root, "leaseTime", "24h"),
                Authoritative = GetBool(root, "authoritative", true),
                Reservations = reservations,
                Expert = GetString(root, "expert"),
                Priority = priority,
                ResponseDelayMs = Math.Clamp(GetInt(root, "responseDelayMs", 2000), 0, 10000),
                MinSecs = Math.Clamp(GetInt(root, "minSecs", 0), 0, 60),
                PingCheck = GetBool(root, "pingCheck", true),
                PingTimeoutMs = Math.Clamp(GetInt(root, "pingTimeoutMs", 500), 100, 3000),
                RogueDetection = GetBool(root, "rogueDetection", true),
                RogueProbeIntervalSeconds = Math.Clamp(GetInt(root, "rogueProbeIntervalSeconds", 300), 30, 86400),
                RegisterDns = GetBool(root, "registerDns", true),
                DnsTtl = (uint)Math.Clamp(GetInt(root, "dnsTtl", 60), 0, 86400)
            };
        }

        public DhcpSettings WithReservations(IReadOnlyList<DhcpReservation> reservations)
        {
            return new DhcpSettings()
            {
                Enabled = Enabled,
                SimpleEnabled = true,
                Interface = Interface,
                RangeStart = RangeStart,
                RangeEnd = RangeEnd,
                Netmask = Netmask,
                Gateway = Gateway,
                DnsServers = DnsServers,
                Domain = Domain,
                LeaseTime = LeaseTime,
                Authoritative = Authoritative,
                Reservations = reservations,
                Expert = Expert,
                Priority = Priority,
                ResponseDelayMs = ResponseDelayMs,
                MinSecs = MinSecs,
                PingCheck = PingCheck,
                PingTimeoutMs = PingTimeoutMs,
                RogueDetection = RogueDetection,
                RogueProbeIntervalSeconds = RogueProbeIntervalSeconds,
                RegisterDns = RegisterDns,
                DnsTtl = DnsTtl
            };
        }

        public List<DhcpConfigError> Validate(out DhcpConfiguration configuration)
        {
            List<DhcpConfigError> errors = new List<DhcpConfigError>();

            if ((Expert is not null) && (Expert.Length > MAX_EXPERT_LENGTH))
                errors.Add(new DhcpConfigError(0, "the expert configuration is larger than 1 MB"));

            if (Reservations.Count > MAX_RESERVATIONS)
                errors.Add(new DhcpConfigError(0, "more than " + MAX_RESERVATIONS + " reservations"));

            string simple = GenerateSimpleConfig(out List<string> simpleErrors);

            foreach (string error in simpleErrors)
                errors.Add(new DhcpConfigError(0, error));

            if (SimpleEnabled && (string.IsNullOrWhiteSpace(RangeStart) != string.IsNullOrWhiteSpace(RangeEnd)))
                errors.Add(new DhcpConfigError(0, "the simple range needs a start and an end address"));

            string text = GetEffectiveConfigText(out int simpleLines);
            configuration = DhcpConfigParser.Parse(text, simpleLines);

            foreach (DhcpConfigError error in configuration.Errors)
            {
                if (error.Line <= simpleLines)
                    errors.Add(new DhcpConfigError(0, "simple settings: " + error.Message));
                else
                    errors.Add(new DhcpConfigError(error.Line - simpleLines, error.Message));
            }

            if (Enabled && (configuration.Ranges.Count == 0))
                errors.Add(new DhcpConfigError(0, "no address range is configured"));

            return errors;
        }

        #endregion

        #region private

        private static string GetString(JsonElement element, string name, string defaultValue = "")
        {
            if (element.TryGetProperty(name, out JsonElement value) && (value.ValueKind == JsonValueKind.String))
                return value.GetString();

            return defaultValue;
        }

        private static bool GetBool(JsonElement element, string name, bool defaultValue)
        {
            if (element.TryGetProperty(name, out JsonElement value) && ((value.ValueKind == JsonValueKind.True) || (value.ValueKind == JsonValueKind.False)))
                return value.GetBoolean();

            return defaultValue;
        }

        private static int GetInt(JsonElement element, string name, int defaultValue)
        {
            if (element.TryGetProperty(name, out JsonElement value) && (value.ValueKind == JsonValueKind.Number) && value.TryGetInt32(out int number))
                return number;

            return defaultValue;
        }

        #endregion
    }
}
