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
using System.Text.Json;
using System.Threading;
using ZenitiumDns.Core.Dns.ZoneManagers;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;

namespace ZenitiumDns.Core.Dns
{
    public sealed class ClientProfile
    {
        #region variables

        internal sealed class FilterCache
        {
            public ListRuleSet RuleSet;
            public IReadOnlyList<string> GlobalLines;
            public ListRuleFilter Filter;
        }

        internal FilterCache _filterCache;

        #endregion

        #region constructor

        public ClientProfile(string name, IReadOnlyList<string> identifiers, bool blockingEnabled, bool useDefaultLists, IReadOnlyList<string> blockListUrls)
        {
            Name = name;
            Identifiers = identifiers ?? [];
            BlockingEnabled = blockingEnabled;
            UseDefaultLists = useDefaultLists;
            BlockListUrls = blockListUrls ?? [];
        }

        #endregion

        #region properties

        public string Name { get; }

        public IReadOnlyList<string> Identifiers { get; }

        public bool BlockingEnabled { get; }

        public bool UseDefaultLists { get; }

        public IReadOnlyList<string> BlockListUrls { get; }

        public bool UsesOnlyDefaultLists
        { get { return UseDefaultLists && (BlockListUrls.Count == 0); } }

        #endregion
    }

    public readonly struct DnsClientIdentity
    {
        public readonly IPAddress Address;
        public readonly string ClientId;
        public readonly ClientProfile Profile;

        public DnsClientIdentity(IPAddress address, string clientId, ClientProfile profile)
        {
            Address = address;
            ClientId = clientId;
            Profile = profile;
        }
    }

    public delegate bool HardwareAddressResolver(IPAddress address, out byte[] hardwareAddress);

    public sealed class ClientProfileManager
    {
        #region variables

        public const string FILE_NAME = "clients.json";
        public const int MAX_PROFILES = 1000;
        public const int MAX_IDENTIFIERS = 100;
        public const int MAX_LISTS = 64;
        public const int MAX_NAME_LENGTH = 60;
        public const int MAX_CLIENT_ID_LENGTH = 63;
        const string DOH_PATH = "/dns-query/";

        readonly DnsServer _dnsServer;
        readonly string _configFolder;
        readonly Lock _lock = new Lock();

        ProfileIndex _index = ProfileIndex.Empty;

        #endregion

        #region constructor

        public ClientProfileManager(DnsServer dnsServer, string configFolder)
        {
            _dnsServer = dnsServer;
            _configFolder = configFolder;
        }

        #endregion

        #region private

        private string FilePath
        { get { return Path.Combine(_configFolder, FILE_NAME); } }

        private static ClientProfile ReadProfile(JsonElement element)
        {
            string name = element.GetProperty("name").GetString();
            List<string> identifiers = new List<string>();
            List<string> lists = new List<string>();
            bool blockingEnabled = true;
            bool useDefaultLists = true;

            if (element.TryGetProperty("identifiers", out JsonElement jsonIdentifiers))
            {
                foreach (JsonElement item in jsonIdentifiers.EnumerateArray())
                    identifiers.Add(item.GetString());
            }

            if (element.TryGetProperty("blockListUrls", out JsonElement jsonLists))
            {
                foreach (JsonElement item in jsonLists.EnumerateArray())
                    lists.Add(item.GetString());
            }

            if (element.TryGetProperty("blockingEnabled", out JsonElement jsonBlockingEnabled))
                blockingEnabled = jsonBlockingEnabled.GetBoolean();

            if (element.TryGetProperty("useDefaultLists", out JsonElement jsonUseDefaultLists))
                useDefaultLists = jsonUseDefaultLists.GetBoolean();

            return new ClientProfile(name, identifiers, blockingEnabled, useDefaultLists, lists);
        }

        private void SaveInternal(IReadOnlyList<ClientProfile> profiles)
        {
            string tmpFile = FilePath + ".tmp";

            using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.Write))
            {
                using (Utf8JsonWriter jsonWriter = new Utf8JsonWriter(fS, new JsonWriterOptions() { Indented = true }))
                {
                    jsonWriter.WriteStartObject();
                    jsonWriter.WriteNumber("version", 1);
                    jsonWriter.WriteStartArray("profiles");

                    foreach (ClientProfile profile in profiles)
                        WriteProfile(jsonWriter, profile);

                    jsonWriter.WriteEndArray();
                    jsonWriter.WriteEndObject();
                }
            }

            File.Move(tmpFile, FilePath, true);
        }

        private void Apply(ProfileIndex index, bool initial = false)
        {
            _index = index;

            if (initial)
                _dnsServer.BlockListZoneManager.InitializeProfileListUrls(index.ListLines);
            else
                _dnsServer.BlockListZoneManager.SetProfileListUrls(index.ListLines);
        }

        private static bool TryGetClientIdFromHost(string host, out string clientId)
        {
            clientId = null;

            if (string.IsNullOrEmpty(host))
                return false;

            int i = host.IndexOf('.');
            if ((i < 1) || (host.IndexOf('.', i + 1) < 0))
                return false;

            clientId = host.Substring(0, i).ToLowerInvariant();
            return true;
        }

        private void BackupInvalidFile(string file)
        {
            try
            {
                string backupFile = file + ".invalid";
                File.Copy(file, backupFile, true);
                _dnsServer.LogManager.Write("DNS Server saved a copy of the client profiles file as: " + backupFile);
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }
        }

        #endregion

        #region public

        public static void WriteProfile(Utf8JsonWriter jsonWriter, ClientProfile profile)
        {
            jsonWriter.WriteStartObject();
            jsonWriter.WriteString("name", profile.Name);

            jsonWriter.WriteStartArray("identifiers");
            foreach (string identifier in profile.Identifiers)
                jsonWriter.WriteStringValue(identifier);
            jsonWriter.WriteEndArray();

            jsonWriter.WriteBoolean("blockingEnabled", profile.BlockingEnabled);
            jsonWriter.WriteBoolean("useDefaultLists", profile.UseDefaultLists);

            jsonWriter.WriteStartArray("blockListUrls");
            foreach (string url in profile.BlockListUrls)
                jsonWriter.WriteStringValue(url);
            jsonWriter.WriteEndArray();

            jsonWriter.WriteEndObject();
        }

        public static bool IsValidClientId(string value)
        {
            if (string.IsNullOrEmpty(value) || (value.Length > MAX_CLIENT_ID_LENGTH))
                return false;

            if ((value[0] == '-') || (value[^1] == '-'))
                return false;

            foreach (char c in value)
            {
                if (!(((c >= 'a') && (c <= 'z')) || ((c >= '0') && (c <= '9')) || (c == '-')))
                    return false;
            }

            return true;
        }

        public static bool TryNormalizeHardwareAddress(string text, out string normalized)
        {
            normalized = null;

            if ((text is null) || (text.Length != 17))
                return false;

            char separator = text[2];
            if ((separator != ':') && (separator != '-'))
                return false;

            char[] chars = new char[17];

            for (int i = 0; i < 17; i++)
            {
                char c = text[i];

                if ((i % 3) == 2)
                {
                    if (c != separator)
                        return false;

                    chars[i] = ':';
                    continue;
                }

                if (!char.IsAsciiHexDigit(c))
                    return false;

                chars[i] = char.ToLowerInvariant(c);
            }

            normalized = new string(chars);
            return true;
        }

        public static string FormatHardwareAddress(byte[] address)
        {
            if ((address is null) || (address.Length != 6))
                return null;

            return string.Join(':', Array.ConvertAll(address, delegate (byte b) { return b.ToString("x2"); }));
        }

        public static string NormalizeIdentifier(string identifier)
        {
            ClientProfile profile = Normalize("x", [identifier], true, true, []);

            if (profile.Identifiers.Count != 1)
                throw new ArgumentException("The identifier is empty.");

            return profile.Identifiers[0];
        }

        public static ClientProfile Normalize(string name, IEnumerable<string> identifiers, bool blockingEnabled, bool useDefaultLists, IEnumerable<string> blockListUrls)
        {
            name = name?.Trim();

            if (string.IsNullOrEmpty(name))
                throw new ArgumentException("Profile name is required.");

            if (name.Length > MAX_NAME_LENGTH)
                throw new ArgumentException("Profile name cannot exceed " + MAX_NAME_LENGTH + " characters.");

            List<string> normalizedIdentifiers = new List<string>();
            HashSet<string> seenIdentifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (string rawIdentifier in identifiers ?? [])
            {
                string identifier = rawIdentifier?.Trim();
                if (string.IsNullOrEmpty(identifier))
                    continue;

                string normalized;

                if (!identifier.Contains('/') && IPAddressExtensions.TryParseStrict(identifier, out IPAddress address))
                {
                    if (address.IsIPv4MappedToIPv6)
                        address = address.MapToIPv4();

                    normalized = address.ToString();
                }
                else if (identifier.Contains('/'))
                {
                    if (!IPAddressExtensions.TryParseStrictNetwork(identifier, out NetworkAddress network))
                        throw new ArgumentException("Invalid network address: " + identifier);

                    normalized = network.ToString();
                }
                else if (TryNormalizeHardwareAddress(identifier, out string mac))
                {
                    normalized = mac;
                }
                else
                {
                    normalized = identifier.ToLowerInvariant();

                    if (!IsValidClientId(normalized))
                        throw new ArgumentException("Invalid client identifier '" + identifier + "'. Use an IP address, a network in CIDR notation, a MAC address or a ClientID made of lowercase letters, digits and hyphens (max. " + MAX_CLIENT_ID_LENGTH + " characters).");
                }

                if (seenIdentifiers.Add(normalized))
                    normalizedIdentifiers.Add(normalized);
            }

            if (normalizedIdentifiers.Count > MAX_IDENTIFIERS)
                throw new ArgumentException("A profile cannot have more than " + MAX_IDENTIFIERS + " identifiers.");

            List<string> normalizedLists = new List<string>();
            HashSet<string> seenLists = new HashSet<string>(StringComparer.Ordinal);

            foreach (string rawUrl in blockListUrls ?? [])
            {
                string line = rawUrl?.Trim();
                if (string.IsNullOrEmpty(line))
                    continue;

                if (line.Length > 255)
                    throw new ArgumentException("Block list URL length cannot exceed 255 characters.");

                if (line.StartsWith('#'))
                    continue;

                bool isAllowList = line.StartsWith('!');
                string url = isAllowList ? line.Substring(1).Trim() : line;

                if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri) || !(uri.IsFile || (uri.Scheme == Uri.UriSchemeHttp) || (uri.Scheme == Uri.UriSchemeHttps)))
                    throw new ArgumentException("Invalid block list URL: " + line);

                string normalized = (isAllowList ? "!" : "") + uri.AbsoluteUri;

                if (seenLists.Add(normalized))
                    normalizedLists.Add(normalized);
            }

            if (normalizedLists.Count > MAX_LISTS)
                throw new ArgumentException("A profile cannot have more than " + MAX_LISTS + " block lists.");

            return new ClientProfile(name, normalizedIdentifiers, blockingEnabled, useDefaultLists, normalizedLists);
        }

        public void LoadConfigFile(bool initial = false)
        {
            string file = FilePath;

            if (!File.Exists(file))
            {
                lock (_lock)
                {
                    Apply(ProfileIndex.Empty, initial);
                }

                return;
            }

            try
            {
                List<ClientProfile> profiles = new List<ClientProfile>();
                int skipped = 0;

                using (JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(file)))
                {
                    if (document.RootElement.TryGetProperty("profiles", out JsonElement jsonProfiles) && (jsonProfiles.ValueKind == JsonValueKind.Array))
                    {
                        HashSet<string> names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        HashSet<string> usedIdentifiers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        int position = 0;

                        foreach (JsonElement jsonProfile in jsonProfiles.EnumerateArray())
                        {
                            position++;

                            try
                            {
                                ClientProfile read = ReadProfile(jsonProfile);
                                ClientProfile profile = Normalize(read.Name, read.Identifiers, read.BlockingEnabled, read.UseDefaultLists, read.BlockListUrls);

                                if (profiles.Count >= MAX_PROFILES)
                                    throw new ArgumentException("Cannot load more than " + MAX_PROFILES + " client profiles.");

                                if (!names.Add(profile.Name))
                                    throw new ArgumentException("A client profile with the same name already exists: " + profile.Name);

                                List<string> identifiers = new List<string>(profile.Identifiers.Count);

                                foreach (string identifier in profile.Identifiers)
                                {
                                    if (usedIdentifiers.Add(identifier))
                                        identifiers.Add(identifier);
                                    else
                                        _dnsServer.LogManager.Write("DNS Server ignored the client identifier '" + identifier + "' of the client profile '" + profile.Name + "' since it is already used by another profile.");
                                }

                                if (identifiers.Count != profile.Identifiers.Count)
                                    profile = new ClientProfile(profile.Name, identifiers, profile.BlockingEnabled, profile.UseDefaultLists, profile.BlockListUrls);

                                profiles.Add(profile);
                            }
                            catch (Exception ex)
                            {
                                skipped++;
                                _dnsServer.LogManager.Write("DNS Server skipped the client profile at position " + position + " in " + file + ": " + ex.Message);
                            }
                        }
                    }
                }

                if (skipped > 0)
                    BackupInvalidFile(file);

                lock (_lock)
                {
                    Apply(ProfileIndex.Create(profiles), initial);
                }

                _dnsServer.LogManager.Write("DNS Server client profiles file was loaded: " + file + (skipped > 0 ? " (" + skipped + " invalid profiles skipped)" : ""));
            }
            catch (Exception ex)
            {
                BackupInvalidFile(file);
                _dnsServer.LogManager.Write("DNS Server encountered an error while loading client profiles file: " + file, ex);
            }
        }

        public void SetProfile(string originalName, ClientProfile profile)
        {
            lock (_lock)
            {
                List<ClientProfile> profiles = new List<ClientProfile>(_index.Profiles);
                int index = -1;

                if (!string.IsNullOrEmpty(originalName))
                {
                    index = profiles.FindIndex(delegate (ClientProfile p) { return p.Name.Equals(originalName, StringComparison.OrdinalIgnoreCase); });
                    if (index < 0)
                        throw new ArgumentException("Client profile was not found: " + originalName);
                }

                for (int i = 0; i < profiles.Count; i++)
                {
                    if ((i != index) && profiles[i].Name.Equals(profile.Name, StringComparison.OrdinalIgnoreCase))
                        throw new ArgumentException("A client profile with the same name already exists: " + profile.Name);
                }

                if (index < 0)
                {
                    if (profiles.Count >= MAX_PROFILES)
                        throw new ArgumentException("Cannot create more than " + MAX_PROFILES + " client profiles.");

                    profiles.Add(profile);
                }
                else
                {
                    profiles[index] = profile;
                }

                ProfileIndex newIndex = ProfileIndex.Create(profiles);

                SaveInternal(newIndex.Profiles);
                Apply(newIndex);
            }
        }

        public bool DeleteProfile(string name)
        {
            lock (_lock)
            {
                List<ClientProfile> profiles = new List<ClientProfile>(_index.Profiles);

                int index = profiles.FindIndex(delegate (ClientProfile p) { return p.Name.Equals(name, StringComparison.OrdinalIgnoreCase); });
                if (index < 0)
                    return false;

                profiles.RemoveAt(index);

                ProfileIndex newIndex = ProfileIndex.Create(profiles);

                SaveInternal(newIndex.Profiles);
                Apply(newIndex);
                return true;
            }
        }

        public DnsClientIdentity Resolve(IPAddress address, DnsDatagram request)
        {
            ProfileIndex index = _index;

            if (index.Profiles.Length == 0)
                return new DnsClientIdentity(address, null, null);

            string clientId = null;
            ClientProfile profile = null;

            NameServerAddress server = request.Metadata?.NameServer;

            if (server is not null)
            {
                Uri dohEndPoint = server.DoHEndPoint;

                if (dohEndPoint is not null)
                {
                    string path = dohEndPoint.AbsolutePath;

                    if (path.StartsWith(DOH_PATH, StringComparison.OrdinalIgnoreCase))
                    {
                        string id = path.Substring(DOH_PATH.Length).TrimEnd('/').ToLowerInvariant();

                        if (IsValidClientId(id))
                            clientId = id;
                    }

                    if ((clientId is null) && TryGetClientIdFromHost(dohEndPoint.Host, out string hostId) && index.ByClientId.ContainsKey(hostId))
                        clientId = hostId;
                }
                else if (((server.Protocol == DnsTransportProtocol.Tls) || (server.Protocol == DnsTransportProtocol.Quic)) && (server.DomainEndPoint is not null))
                {
                    if (TryGetClientIdFromHost(server.DomainEndPoint.Address, out string hostId) && index.ByClientId.ContainsKey(hostId))
                        clientId = hostId;
                }
            }

            if (clientId is not null)
                index.ByClientId.TryGetValue(clientId, out profile);

            if ((profile is null) && (address is not null) && (index.ByMac.Count > 0))
            {
                HardwareAddressResolver resolver = HardwareAddressResolver;

                if ((resolver is not null) && resolver(address, out byte[] hardwareAddress))
                {
                    string mac = FormatHardwareAddress(hardwareAddress);

                    if (mac is not null)
                        index.ByMac.TryGetValue(mac, out profile);
                }
            }

            if ((profile is null) && (address is not null))
            {
                if (address.IsIPv4MappedToIPv6)
                    address = address.MapToIPv4();

                if (!index.ByAddress.TryGetValue(address, out profile))
                {
                    foreach ((NetworkAddress network, ClientProfile networkProfile) in index.ByNetwork)
                    {
                        if (network.Contains(address))
                        {
                            profile = networkProfile;
                            break;
                        }
                    }
                }
            }

            return new DnsClientIdentity(address, clientId, profile);
        }

        public ClientProfile ResolveDevice(IPAddress address, string mac, out string matchedBy)
        {
            ProfileIndex index = _index;
            matchedBy = null;

            if ((mac is not null) && index.ByMac.TryGetValue(mac, out ClientProfile byMac))
            {
                matchedBy = mac;
                return byMac;
            }

            if (address is null)
                return null;

            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            if (index.ByAddress.TryGetValue(address, out ClientProfile byAddress))
            {
                matchedBy = address.ToString();
                return byAddress;
            }

            foreach ((NetworkAddress network, ClientProfile networkProfile) in index.ByNetwork)
            {
                if (network.Contains(address))
                {
                    matchedBy = network.ToString();
                    return networkProfile;
                }
            }

            return null;
        }

        public string AssignIdentifier(string identifier, string profileName)
        {
            string normalized = NormalizeIdentifier(identifier);

            lock (_lock)
            {
                List<ClientProfile> profiles = new List<ClientProfile>(_index.Profiles);
                string previous = null;
                int target = -1;

                if (!string.IsNullOrEmpty(profileName))
                {
                    target = profiles.FindIndex(delegate (ClientProfile p) { return p.Name.Equals(profileName, StringComparison.OrdinalIgnoreCase); });

                    if (target < 0)
                        throw new ArgumentException("Client profile was not found: " + profileName);
                }

                for (int i = 0; i < profiles.Count; i++)
                {
                    ClientProfile profile = profiles[i];
                    List<string> identifiers = new List<string>(profile.Identifiers);

                    if (identifiers.RemoveAll(delegate (string x) { return x.Equals(normalized, StringComparison.OrdinalIgnoreCase); }) > 0)
                    {
                        previous = profile.Name;
                        profiles[i] = new ClientProfile(profile.Name, identifiers, profile.BlockingEnabled, profile.UseDefaultLists, profile.BlockListUrls);
                    }
                }

                if (target >= 0)
                {
                    ClientProfile profile = profiles[target];
                    List<string> identifiers = new List<string>(profile.Identifiers) { normalized };

                    if (identifiers.Count > MAX_IDENTIFIERS)
                        throw new ArgumentException("A profile cannot have more than " + MAX_IDENTIFIERS + " identifiers.");

                    profiles[target] = new ClientProfile(profile.Name, identifiers, profile.BlockingEnabled, profile.UseDefaultLists, profile.BlockListUrls);
                }

                ProfileIndex newIndex = ProfileIndex.Create(profiles);

                SaveInternal(newIndex.Profiles);
                Apply(newIndex);

                return previous;
            }
        }

        public ClientProfile GetProfile(string name)
        {
            foreach (ClientProfile profile in _index.Profiles)
            {
                if (profile.Name.Equals(name, StringComparison.OrdinalIgnoreCase))
                    return profile;
            }

            return null;
        }

        public IReadOnlyList<string> GetProfilesUsingList(string listLine)
        {
            List<string> names = new List<string>();

            foreach (ClientProfile profile in _index.Profiles)
            {
                foreach (string line in profile.BlockListUrls)
                {
                    if (line.Equals(listLine, StringComparison.Ordinal))
                    {
                        names.Add(profile.Name);
                        break;
                    }
                }
            }

            return names;
        }

        #endregion

        #region properties

        public IReadOnlyList<ClientProfile> Profiles
        { get { return _index.Profiles; } }

        public int Count
        { get { return _index.Profiles.Length; } }

        public bool HasClientIds
        { get { return _index.ByClientId.Count > 0; } }

        public bool HasHardwareAddresses
        { get { return _index.ByMac.Count > 0; } }

        public HardwareAddressResolver HardwareAddressResolver { get; set; }

        #endregion

        sealed class ProfileIndex
        {
            public static readonly ProfileIndex Empty = new ProfileIndex([], new Dictionary<string, ClientProfile>(), new Dictionary<string, ClientProfile>(), new Dictionary<IPAddress, ClientProfile>(), [], []);

            public readonly ClientProfile[] Profiles;
            public readonly Dictionary<string, ClientProfile> ByClientId;
            public readonly Dictionary<string, ClientProfile> ByMac;
            public readonly Dictionary<IPAddress, ClientProfile> ByAddress;
            public readonly (NetworkAddress, ClientProfile)[] ByNetwork;
            public readonly IReadOnlyList<string> ListLines;

            private ProfileIndex(ClientProfile[] profiles, Dictionary<string, ClientProfile> byClientId, Dictionary<string, ClientProfile> byMac, Dictionary<IPAddress, ClientProfile> byAddress, (NetworkAddress, ClientProfile)[] byNetwork, IReadOnlyList<string> listLines)
            {
                Profiles = profiles;
                ByClientId = byClientId;
                ByMac = byMac;
                ByAddress = byAddress;
                ByNetwork = byNetwork;
                ListLines = listLines;
            }

            public static ProfileIndex Create(IReadOnlyList<ClientProfile> profiles)
            {
                Dictionary<string, ClientProfile> byClientId = new Dictionary<string, ClientProfile>(StringComparer.Ordinal);
                Dictionary<string, ClientProfile> byMac = new Dictionary<string, ClientProfile>(StringComparer.Ordinal);
                Dictionary<IPAddress, ClientProfile> byAddress = new Dictionary<IPAddress, ClientProfile>();
                List<(NetworkAddress, ClientProfile)> byNetwork = new List<(NetworkAddress, ClientProfile)>();
                Dictionary<string, string> owners = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                List<string> listLines = new List<string>();
                HashSet<string> seenLines = new HashSet<string>(StringComparer.Ordinal);

                foreach (ClientProfile profile in profiles)
                {
                    foreach (string identifier in profile.Identifiers)
                    {
                        if (owners.TryGetValue(identifier, out string owner))
                            throw new ArgumentException("The client identifier '" + identifier + "' is already used by the profile: " + owner);

                        owners.Add(identifier, profile.Name);

                        if (identifier.Contains('/'))
                            byNetwork.Add((NetworkAddress.Parse(identifier), profile));
                        else if (IPAddressExtensions.TryParseStrict(identifier, out IPAddress address))
                            byAddress.Add(address, profile);
                        else if (TryNormalizeHardwareAddress(identifier, out string mac))
                            byMac.Add(mac, profile);
                        else
                            byClientId.Add(identifier, profile);
                    }

                    foreach (string line in profile.BlockListUrls)
                    {
                        if (seenLines.Add(line))
                            listLines.Add(line);
                    }
                }

                byNetwork.Sort(delegate ((NetworkAddress, ClientProfile) x, (NetworkAddress, ClientProfile) y) { return y.Item1.PrefixLength.CompareTo(x.Item1.PrefixLength); });

                return new ProfileIndex([.. profiles], byClientId, byMac, byAddress, byNetwork.ToArray(), listLines);
            }
        }
    }
}
