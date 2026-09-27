using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Utilities.Collections;
using ZenitiumLibrary;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ResourceRecords;
using ZenitiumLibrary.Net.Http.Client;

namespace ZenitiumDns.Core.Dns
{
    public enum IanaDataMode : byte
    {
        Automatic = 0,
        Custom = 1,
        Disabled = 2
    }

    public enum IanaDataItem
    {
        RootZone,
        ArpaZone,
        TrustAnchors
    }

    sealed class IanaDataManager : IDisposable
    {
        #region variables

        const string ROOT_ZONE_URL = "https://www.internic.net/domain/root.zone";
        const string ARPA_ZONE_URL = "https://www.internic.net/domain/arpa.zone";
        const string TRUST_ANCHORS_URL = "https://data.iana.org/root-anchors/root-anchors.xml";
        const string TRUST_ANCHORS_SIGNATURE_URL = "https://data.iana.org/root-anchors/root-anchors.p7s";

        const long MAX_DOWNLOAD_SIZE = 16L * 1024 * 1024;
        static readonly string USER_AGENT = "ZenitiumDNS/" + (typeof(IanaDataManager).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0");
        const int TIMER_INTERVAL = 60000;
        const int TIMER_INITIAL_DELAY = 30000;

        static readonly TimeSpan ZONE_CHECK_INTERVAL = TimeSpan.FromHours(1);
        static readonly TimeSpan ZONE_RETRY_INTERVAL = TimeSpan.FromMinutes(10);
        static readonly TimeSpan TRUST_ANCHOR_CHECK_INTERVAL = TimeSpan.FromHours(24);
        static readonly TimeSpan TRUST_ANCHOR_RETRY_INTERVAL = TimeSpan.FromHours(1);
        static readonly TimeSpan SEED_INTERVAL = TimeSpan.FromMinutes(15);
        static readonly TimeSpan SIGNATURE_REFRESH_MARGIN = TimeSpan.FromDays(2);

        readonly DnsServer _dnsServer;
        readonly string _folder;
        readonly SemaphoreSlim _lock = new SemaphoreSlim(1, 1);

        IanaDataMode _rootZoneMode = IanaDataMode.Automatic;
        IanaDataMode _arpaZoneMode = IanaDataMode.Automatic;
        IanaDataMode _trustAnchorMode = IanaDataMode.Automatic;

        volatile LocalZone _rootZone;
        volatile LocalZone _arpaZone;

        readonly ItemStatus _rootStatus = new ItemStatus();
        readonly ItemStatus _arpaStatus = new ItemStatus();
        readonly ItemStatus _trustAnchorStatus = new ItemStatus();

        Timer _timer;
        int _timerRunning;
        bool _initialized;
        DateTime _lastSeed;

        #endregion

        #region constructor

        public IanaDataManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;
            _folder = Path.Combine(dnsServer.ConfigFolder, "iana");
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _timer?.Dispose();
            _timer = null;

            _disposed = true;
        }

        #endregion

        #region private

        private string GetFile(string name)
        {
            return Path.Combine(_folder, name);
        }

        private static string GetZoneFileName(IanaDataItem item, bool custom)
        {
            string name = item == IanaDataItem.RootZone ? "root" : "arpa";
            return custom ? name + ".custom.zone" : name + ".zone";
        }

        private ItemStatus GetStatus(IanaDataItem item)
        {
            switch (item)
            {
                case IanaDataItem.RootZone:
                    return _rootStatus;

                case IanaDataItem.ArpaZone:
                    return _arpaStatus;

                default:
                    return _trustAnchorStatus;
            }
        }

        private IanaDataMode GetMode(IanaDataItem item)
        {
            switch (item)
            {
                case IanaDataItem.RootZone:
                    return _rootZoneMode;

                case IanaDataItem.ArpaZone:
                    return _arpaZoneMode;

                default:
                    return _trustAnchorMode;
            }
        }

        private async Task<byte[]> DownloadAsync(string url, DateTime ifModifiedSince)
        {
            HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
            handler.Proxy = _dnsServer.Proxy;
            handler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsServer.IPv6Mode);
            handler.DnsClient = _dnsServer;

            using (HttpClient http = new HttpClient(handler))
            {
                http.Timeout = TimeSpan.FromMinutes(2);
                http.DefaultRequestHeaders.UserAgent.ParseAdd(USER_AGENT);

                using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, url))
                {
                    if (ifModifiedSince != DateTime.MinValue)
                        request.Headers.IfModifiedSince = ifModifiedSince;

                    using (HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead))
                    {
                        if (response.StatusCode == HttpStatusCode.NotModified)
                            return null;

                        response.EnsureSuccessStatusCode();

                        if (response.Content.Headers.ContentLength > MAX_DOWNLOAD_SIZE)
                            throw new InvalidDataException("The file is larger than " + (MAX_DOWNLOAD_SIZE / 1024 / 1024) + " MB.");

                        await using (Stream stream = await response.Content.ReadAsStreamAsync())
                        using (MemoryStream buffer = new MemoryStream())
                        {
                            byte[] chunk = new byte[65536];
                            int read;

                            while ((read = await stream.ReadAsync(chunk)) > 0)
                            {
                                if (buffer.Length + read > MAX_DOWNLOAD_SIZE)
                                    throw new InvalidDataException("The file is larger than " + (MAX_DOWNLOAD_SIZE / 1024 / 1024) + " MB.");

                                buffer.Write(chunk, 0, read);
                            }

                            return buffer.ToArray();
                        }
                    }
                }
            }
        }

        private static async Task WriteFileAtomicAsync(string file, byte[] data)
        {
            string tmpFile = file + ".tmp";
            await File.WriteAllBytesAsync(tmpFile, data);
            File.Move(tmpFile, file, true);
        }

        private static IReadOnlyList<DnsResourceRecord> VerifyTrustAnchors(byte[] xml, byte[] signature)
        {
            X509Certificate2Collection roots = new X509Certificate2Collection();
            roots.ImportFromPemFile(Path.Combine(Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location), "icannbundle.pem"));

            CmsSignedData signedData = new CmsSignedData(new CmsProcessableByteArray(xml), signature);
            IStore<Org.BouncyCastle.X509.X509Certificate> certificates = signedData.GetCertificates();

            X509Certificate2Collection extraStore = new X509Certificate2Collection();

            foreach (Org.BouncyCastle.X509.X509Certificate certificate in certificates.EnumerateMatches(null))
                extraStore.Add(X509CertificateLoader.LoadCertificate(certificate.GetEncoded()));

            bool trusted = false;

            foreach (SignerInformation signer in signedData.GetSignerInfos().GetSigners())
            {
                foreach (Org.BouncyCastle.X509.X509Certificate certificate in certificates.EnumerateMatches(signer.SignerID))
                {
                    if (!signer.Verify(certificate))
                        continue;

                    using (X509Certificate2 signerCertificate = X509CertificateLoader.LoadCertificate(certificate.GetEncoded()))
                    using (X509Chain chain = new X509Chain())
                    {
                        chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                        chain.ChainPolicy.CustomTrustStore.AddRange(roots);
                        chain.ChainPolicy.ExtraStore.AddRange(extraStore);
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreWrongUsage | X509VerificationFlags.IgnoreInvalidPolicy;

                        if (chain.Build(signerCertificate))
                        {
                            trusted = true;
                            break;
                        }
                    }
                }

                if (trusted)
                    break;
            }

            if (!trusted)
                throw new InvalidDataException("The signature of root-anchors.xml is invalid or does not chain to the ICANN Root CA.");

            IReadOnlyList<DnsResourceRecord> anchors = DnsClient.ParseRootTrustAnchors(Encoding.UTF8.GetString(xml));
            if (anchors.Count == 0)
                throw new InvalidDataException("root-anchors.xml contains no currently valid trust anchor.");

            return anchors;
        }

        private static IReadOnlyList<DnsResourceRecord> ParseCustomTrustAnchors(string text)
        {
            List<DnsResourceRecord> records = ZoneFile.ReadZoneFileFromAsync(new StringReader(text), "").Sync();
            List<DnsResourceRecord> anchors = new List<DnsResourceRecord>();

            foreach (DnsResourceRecord record in records)
            {
                if ((record.Type != DnsResourceRecordType.DS) || (record.Name.Length != 0))
                    throw new InvalidDataException("Only DS records for the root zone \".\" are allowed as trust anchors.");

                anchors.Add(new DnsResourceRecord("", DnsResourceRecordType.DS, DnsClass.IN, 0, record.RDATA));
            }

            if (anchors.Count == 0)
                throw new InvalidDataException("At least one DS record for the root zone \".\" is required.");

            return anchors;
        }

        private static string FormatTrustAnchors(IReadOnlyList<DnsResourceRecord> anchors)
        {
            StringBuilder sb = new StringBuilder();

            foreach (DnsResourceRecord anchor in anchors)
            {
                DnsDSRecordData ds = anchor.RDATA as DnsDSRecordData;
                sb.Append(". IN DS ").Append(ds.KeyTag).Append(' ').Append((byte)ds.Algorithm).Append(' ').Append((byte)ds.DigestType).Append(' ').Append(Convert.ToHexString(ds.Digest)).Append('\n');
            }

            return sb.ToString();
        }

        private async Task ApplyTrustAnchorsAsync(bool download)
        {
            ItemStatus status = _trustAnchorStatus;
            status.LastCheck = DateTime.UtcNow;

            try
            {
                switch (_trustAnchorMode)
                {
                    case IanaDataMode.Automatic:
                        {
                            string xmlFile = GetFile("root-anchors.xml");
                            string signatureFile = GetFile("root-anchors.p7s");
                            byte[] xml = null;
                            byte[] signature = null;

                            if (download || !File.Exists(xmlFile) || !File.Exists(signatureFile))
                            {
                                xml = await DownloadAsync(TRUST_ANCHORS_URL, DateTime.MinValue);
                                signature = await DownloadAsync(TRUST_ANCHORS_SIGNATURE_URL, DateTime.MinValue);
                            }
                            else
                            {
                                xml = await File.ReadAllBytesAsync(xmlFile);
                                signature = await File.ReadAllBytesAsync(signatureFile);
                            }

                            IReadOnlyList<DnsResourceRecord> anchors = VerifyTrustAnchors(xml, signature);

                            await WriteFileAtomicAsync(xmlFile, xml);
                            await WriteFileAtomicAsync(signatureFile, signature);

                            DnsClient.RootTrustAnchors = anchors;
                            status.SetSuccess("IANA", "Signatur von ICANN geprüft, " + anchors.Count + " gültige Schlüssel.");
                        }
                        break;

                    case IanaDataMode.Custom:
                        {
                            IReadOnlyList<DnsResourceRecord> anchors = ParseCustomTrustAnchors(await File.ReadAllTextAsync(GetFile("root-anchors.custom.txt")));

                            DnsClient.RootTrustAnchors = anchors;
                            status.SetSuccess("Eigene Version", anchors.Count + " selbst eingetragene Schlüssel.");
                        }
                        break;

                    default:
                        DnsClient.ReloadRootTrustAnchors();
                        status.SetSuccess("Mitgeliefert", "Die mit dem Paket ausgelieferte root-anchors.xml wird verwendet.");
                        break;
                }
            }
            catch (Exception ex)
            {
                if (_trustAnchorMode == IanaDataMode.Automatic)
                {
                    bool keepCurrent = status.LoadedOn != DateTime.MinValue;

                    if (!keepCurrent)
                        DnsClient.ReloadRootTrustAnchors();

                    status.SetError(ex.Message + (keepCurrent ? " Die zuletzt geprüften Schlüssel bleiben aktiv." : " Die mitgelieferten Schlüssel werden verwendet."));
                }
                else
                {
                    DnsClient.ReloadRootTrustAnchors();
                    status.SetError(ex.Message + " Die mitgelieferten Schlüssel werden verwendet.");
                }

                _dnsServer.LogManager?.Write("DNS Server failed to update the root trust anchors: " + ex.Message);
            }

            status.NextCheck = DateTime.UtcNow + (status.Error is null ? TRUST_ANCHOR_CHECK_INTERVAL : TRUST_ANCHOR_RETRY_INTERVAL);
        }

        private async Task<IReadOnlyList<DnsResourceRecord>> GetApexDSAsync(IanaDataItem item)
        {
            if (item == IanaDataItem.RootZone)
                return DnsClient.RootTrustAnchors;

            LocalZone rootZone = _rootZone;
            IReadOnlyList<DnsResourceRecord> ds = rootZone?.GetDS("arpa");
            if (ds is not null)
                return ds;

            try
            {
                DnsDatagram request = new DnsDatagram(0, false, DnsOpcode.StandardQuery, false, false, true, false, false, false, DnsResponseCode.NoError, [new DnsQuestionRecord("arpa", DnsResourceRecordType.DS, DnsClass.IN)], null, null, null, DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE, EDnsHeaderFlags.DNSSEC_OK);
                DnsDatagram response = await _dnsServer.DirectQueryAsync(request, 10000);

                if ((response is not null) && response.AuthenticData)
                {
                    List<DnsResourceRecord> records = new List<DnsResourceRecord>();

                    foreach (DnsResourceRecord answer in response.Answer)
                    {
                        if (answer.Type == DnsResourceRecordType.DS)
                            records.Add(answer);
                    }

                    if (records.Count > 0)
                        return records;
                }
            }
            catch
            { }

            return null;
        }

        private async Task ApplyZoneAsync(IanaDataItem item, bool download)
        {
            ItemStatus status = GetStatus(item);
            IanaDataMode mode = GetMode(item);
            string zoneName = item == IanaDataItem.RootZone ? "" : "arpa";

            status.LastCheck = DateTime.UtcNow;

            try
            {
                switch (mode)
                {
                    case IanaDataMode.Automatic:
                        {
                            string file = GetFile(GetZoneFileName(item, false));
                            LocalZone current = item == IanaDataItem.RootZone ? _rootZone : _arpaZone;
                            bool fileExists = File.Exists(file);
                            byte[] data = null;

                            if (download || !fileExists)
                            {
                                data = await DownloadAsync(item == IanaDataItem.RootZone ? ROOT_ZONE_URL : ARPA_ZONE_URL, (fileExists && (current is not null)) ? File.GetLastWriteTimeUtc(file) : DateTime.MinValue);

                                if ((data is null) && (current is not null))
                                {
                                    File.SetLastWriteTimeUtc(file, DateTime.UtcNow);
                                    status.LoadedOn = DateTime.UtcNow;
                                    status.Error = null;
                                    break;
                                }
                            }

                            data ??= await File.ReadAllBytesAsync(file);

                            List<DnsResourceRecord> records = await ZoneFile.ReadZoneFileFromAsync(new StringReader(Encoding.UTF8.GetString(data)), zoneName);
                            LocalZone zone = LocalZone.Load(records, zoneName, await GetApexDSAsync(item), true);

                            if ((current is not null) && current.Verified && (zone.Serial < current.Serial))
                                throw new InvalidDataException("The downloaded zone has an older serial " + zone.Serial + " than the active zone " + current.Serial + ".");

                            await WriteFileAtomicAsync(file, data);

                            Activate(item, zone);
                            status.SetSuccess("IANA", zone.Verification);
                        }
                        break;

                    case IanaDataMode.Custom:
                        {
                            string text = await File.ReadAllTextAsync(GetFile(GetZoneFileName(item, true)));
                            List<DnsResourceRecord> records = await ZoneFile.ReadZoneFileFromAsync(new StringReader(text), zoneName);
                            LocalZone zone = LocalZone.Load(records, zoneName, await GetApexDSAsync(item), false);

                            Activate(item, zone);
                            status.SetSuccess("Eigene Version", zone.Verified ? zone.Verification : "Nicht signaturgeprüft: " + zone.Verification);
                        }
                        break;

                    default:
                        Activate(item, null);
                        status.SetDisabled();
                        break;
                }
            }
            catch (Exception ex)
            {
                status.SetError(ex.Message);
                _dnsServer.LogManager?.Write("DNS Server failed to load the " + (item == IanaDataItem.RootZone ? "root" : "arpa") + " zone: " + ex.Message);
            }

            status.NextCheck = DateTime.UtcNow + (status.Error is null ? ZONE_CHECK_INTERVAL : ZONE_RETRY_INTERVAL);
        }

        private void Activate(IanaDataItem item, LocalZone zone)
        {
            if (item == IanaDataItem.RootZone)
                _rootZone = zone;
            else
                _arpaZone = zone;

            if (zone is not null)
                Seed(zone);
        }

        private void Seed(LocalZone zone)
        {
            if (zone is null)
                return;

            int failed = 0;
            Exception lastError = null;

            foreach (DnsDatagram response in zone.GetSeedResponses())
            {
                try
                {
                    _dnsServer.CacheZoneManager.CacheResponse(response, false, zone.Name);
                }
                catch (Exception ex)
                {
                    failed++;
                    lastError = ex;
                }
            }

            if (lastError is not null)
                _dnsServer.LogManager?.Write("Local " + (zone.Name.Length == 0 ? "root" : zone.Name) + " zone could not be fully loaded into the cache (" + failed + " delegations failed): " + lastError.GetType().Name + ": " + lastError.Message);
        }

        private bool IsUsable(LocalZone zone, ItemStatus status)
        {
            if (zone is null)
                return false;

            DateTime utcNow = DateTime.UtcNow;

            if (zone.ValidUntil <= utcNow)
                return false;

            if ((status.LoadedOn != DateTime.MinValue) && (status.LoadedOn.AddSeconds(zone.Expire) <= utcNow))
                return false;

            return zone.Verified || !_dnsServer.DnssecValidation;
        }

        private async void TimerCallback(object state)
        {
            if (Interlocked.Exchange(ref _timerRunning, 1) == 1)
                return;

            try
            {
                await _lock.WaitAsync();
                try
                {
                    DateTime utcNow = DateTime.UtcNow;

                    if (!_initialized)
                    {
                        await ApplyTrustAnchorsAsync(false);
                        await ApplyZoneAsync(IanaDataItem.RootZone, false);
                        await ApplyZoneAsync(IanaDataItem.ArpaZone, false);

                        _initialized = true;
                        _lastSeed = utcNow;
                        return;
                    }

                    if ((_trustAnchorMode == IanaDataMode.Automatic) && (utcNow >= _trustAnchorStatus.NextCheck))
                        await ApplyTrustAnchorsAsync(true);

                    foreach (IanaDataItem item in new[] { IanaDataItem.RootZone, IanaDataItem.ArpaZone })
                    {
                        if (GetMode(item) != IanaDataMode.Automatic)
                            continue;

                        LocalZone zone = item == IanaDataItem.RootZone ? _rootZone : _arpaZone;
                        bool signaturesExpiring = (zone is not null) && (zone.ValidUntil - utcNow < SIGNATURE_REFRESH_MARGIN);

                        if ((utcNow >= GetStatus(item).NextCheck) || signaturesExpiring)
                            await ApplyZoneAsync(item, true);
                    }

                    if ((utcNow - _lastSeed) >= SEED_INTERVAL)
                    {
                        _lastSeed = utcNow;

                        if (IsUsable(_rootZone, _rootStatus))
                            Seed(_rootZone);

                        if (IsUsable(_arpaZone, _arpaStatus))
                            Seed(_arpaZone);
                    }
                }
                finally
                {
                    _lock.Release();
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager?.Write(ex);
            }
            finally
            {
                Volatile.Write(ref _timerRunning, 0);
            }
        }

        private void WriteItemStatus(Utf8JsonWriter jsonWriter, string propertyName, IanaDataItem item, LocalZone zone)
        {
            ItemStatus status = GetStatus(item);

            jsonWriter.WriteStartObject(propertyName);

            jsonWriter.WriteString("mode", GetMode(item).ToString());
            jsonWriter.WriteBoolean("hasCustom", File.Exists(item == IanaDataItem.TrustAnchors ? GetFile("root-anchors.custom.txt") : GetFile(GetZoneFileName(item, true))));
            jsonWriter.WriteString("source", status.Source);
            jsonWriter.WriteString("message", status.Message);
            jsonWriter.WriteString("error", status.Error);

            if (status.LoadedOn != DateTime.MinValue)
                jsonWriter.WriteString("loadedOn", status.LoadedOn);
            else
                jsonWriter.WriteNull("loadedOn");

            if (status.LastCheck != DateTime.MinValue)
                jsonWriter.WriteString("lastCheck", status.LastCheck);
            else
                jsonWriter.WriteNull("lastCheck");

            if (item == IanaDataItem.TrustAnchors)
            {
                jsonWriter.WriteStartArray("keyTags");

                foreach (DnsResourceRecord anchor in DnsClient.RootTrustAnchors)
                    jsonWriter.WriteNumberValue((anchor.RDATA as DnsDSRecordData).KeyTag);

                jsonWriter.WriteEndArray();
            }
            else
            {
                jsonWriter.WriteBoolean("active", IsUsable(zone, status));

                if (zone is not null)
                {
                    jsonWriter.WriteNumber("serial", zone.Serial);
                    jsonWriter.WriteBoolean("verified", zone.Verified);
                    jsonWriter.WriteNumber("delegations", zone.DelegationCount);

                    if (zone.ValidUntil != DateTime.MaxValue)
                        jsonWriter.WriteString("validUntil", zone.ValidUntil);
                }
            }

            jsonWriter.WriteEndObject();
        }

        #endregion

        #region public

        public void Start()
        {
            if (_timer is not null)
                return;

            Directory.CreateDirectory(_folder);
            _timer = new Timer(TimerCallback, null, TIMER_INITIAL_DELAY, TIMER_INTERVAL);
        }

        public DnsDatagram GetNameErrorResponse(DnsDatagram request)
        {
            if (request.Question.Count != 1)
                return null;

            string name = request.Question[0].Name;

            LocalZone arpaZone = _arpaZone;
            if ((name.Length > 5) && name.EndsWith(".arpa", StringComparison.OrdinalIgnoreCase) && IsUsable(arpaZone, _arpaStatus))
                return arpaZone.GetNameErrorResponse(request, _dnsServer.CacheZoneManager.MaximumNegativeRecordTtl);

            LocalZone rootZone = _rootZone;
            if (IsUsable(rootZone, _rootStatus))
                return rootZone.GetNameErrorResponse(request, _dnsServer.CacheZoneManager.MaximumNegativeRecordTtl);

            return null;
        }

        public void Reseed()
        {
            LocalZone rootZone = _rootZone;
            if (IsUsable(rootZone, _rootStatus))
                Seed(rootZone);

            LocalZone arpaZone = _arpaZone;
            if (IsUsable(arpaZone, _arpaStatus))
                Seed(arpaZone);
        }

        public async Task UpdateNowAsync()
        {
            await _lock.WaitAsync();
            try
            {
                await ApplyTrustAnchorsAsync(_trustAnchorMode == IanaDataMode.Automatic);
                await ApplyZoneAsync(IanaDataItem.RootZone, _rootZoneMode == IanaDataMode.Automatic);
                await ApplyZoneAsync(IanaDataItem.ArpaZone, _arpaZoneMode == IanaDataMode.Automatic);

                _initialized = true;
            }
            finally
            {
                _lock.Release();
            }
        }

        public async Task SetModeAsync(IanaDataItem item, IanaDataMode mode)
        {
            if (GetMode(item) == mode)
                return;

            if (mode == IanaDataMode.Custom)
            {
                string file = item == IanaDataItem.TrustAnchors ? GetFile("root-anchors.custom.txt") : GetFile(GetZoneFileName(item, true));
                if (!File.Exists(file))
                    throw new InvalidOperationException("There is no custom version yet. Edit and save a custom version first.");
            }

            switch (item)
            {
                case IanaDataItem.RootZone:
                    _rootZoneMode = mode;
                    break;

                case IanaDataItem.ArpaZone:
                    _arpaZoneMode = mode;
                    break;

                default:
                    _trustAnchorMode = mode;
                    break;
            }

            if (!_initialized)
                return;

            await _lock.WaitAsync();
            try
            {
                if (item == IanaDataItem.TrustAnchors)
                    await ApplyTrustAnchorsAsync(false);
                else
                    await ApplyZoneAsync(item, false);
            }
            finally
            {
                _lock.Release();
            }
        }

        public void LoadModes(IanaDataMode rootZoneMode, IanaDataMode arpaZoneMode, IanaDataMode trustAnchorMode)
        {
            _rootZoneMode = rootZoneMode;
            _arpaZoneMode = arpaZoneMode;
            _trustAnchorMode = trustAnchorMode;
        }

        public async Task<string> GetContentAsync(IanaDataItem item)
        {
            if (item == IanaDataItem.TrustAnchors)
            {
                string customFile = GetFile("root-anchors.custom.txt");

                if ((_trustAnchorMode == IanaDataMode.Custom) && File.Exists(customFile))
                    return await File.ReadAllTextAsync(customFile);

                return FormatTrustAnchors(DnsClient.RootTrustAnchors);
            }

            string custom = GetFile(GetZoneFileName(item, true));
            string automatic = GetFile(GetZoneFileName(item, false));

            if ((GetMode(item) == IanaDataMode.Custom) && File.Exists(custom))
                return await File.ReadAllTextAsync(custom);

            if (File.Exists(automatic))
                return await File.ReadAllTextAsync(automatic);

            if (File.Exists(custom))
                return await File.ReadAllTextAsync(custom);

            return string.Empty;
        }

        public async Task SetCustomContentAsync(IanaDataItem item, string content)
        {
            Directory.CreateDirectory(_folder);

            if (item == IanaDataItem.TrustAnchors)
            {
                ParseCustomTrustAnchors(content);
                await WriteFileAtomicAsync(GetFile("root-anchors.custom.txt"), Encoding.UTF8.GetBytes(content));
            }
            else
            {
                string zoneName = item == IanaDataItem.RootZone ? "" : "arpa";
                List<DnsResourceRecord> records = await ZoneFile.ReadZoneFileFromAsync(new StringReader(content), zoneName);
                LocalZone.Load(records, zoneName, null, false);

                await WriteFileAtomicAsync(GetFile(GetZoneFileName(item, true)), Encoding.UTF8.GetBytes(content));
            }

            switch (item)
            {
                case IanaDataItem.RootZone:
                    _rootZoneMode = IanaDataMode.Custom;
                    break;

                case IanaDataItem.ArpaZone:
                    _arpaZoneMode = IanaDataMode.Custom;
                    break;

                default:
                    _trustAnchorMode = IanaDataMode.Custom;
                    break;
            }

            await _lock.WaitAsync();
            try
            {
                if (item == IanaDataItem.TrustAnchors)
                    await ApplyTrustAnchorsAsync(false);
                else
                    await ApplyZoneAsync(item, false);

                _initialized = true;
            }
            finally
            {
                _lock.Release();
            }
        }

        public void WriteStatus(Utf8JsonWriter jsonWriter)
        {
            WriteItemStatus(jsonWriter, "rootZone", IanaDataItem.RootZone, _rootZone);
            WriteItemStatus(jsonWriter, "arpaZone", IanaDataItem.ArpaZone, _arpaZone);
            WriteItemStatus(jsonWriter, "trustAnchors", IanaDataItem.TrustAnchors, null);
        }

        public (bool Active, bool Verified, uint Serial, int Delegations, string Error, string Message, IanaDataMode Mode) GetZoneState(IanaDataItem item)
        {
            LocalZone zone = item == IanaDataItem.RootZone ? _rootZone : _arpaZone;
            ItemStatus status = GetStatus(item);

            return (IsUsable(zone, status), zone?.Verified ?? false, zone?.Serial ?? 0, zone?.DelegationCount ?? 0, status.Error, status.Message, GetMode(item));
        }

        public (string Source, string Error, string Message, IanaDataMode Mode) GetTrustAnchorState()
        {
            return (_trustAnchorStatus.Source, _trustAnchorStatus.Error, _trustAnchorStatus.Message, _trustAnchorMode);
        }

        #endregion

        #region properties

        public IanaDataMode RootZoneMode
        { get { return _rootZoneMode; } }

        public IanaDataMode ArpaZoneMode
        { get { return _arpaZoneMode; } }

        public IanaDataMode TrustAnchorMode
        { get { return _trustAnchorMode; } }

        #endregion

        sealed class ItemStatus
        {
            public string Source;
            public string Message;
            public string Error;
            public DateTime LoadedOn;
            public DateTime LastCheck;
            public DateTime NextCheck;

            public void SetSuccess(string source, string message)
            {
                Source = source;
                Message = message;
                Error = null;
                LoadedOn = DateTime.UtcNow;
            }

            public void SetError(string error)
            {
                Error = error;
            }

            public void SetDisabled()
            {
                Source = null;
                Message = "Ausgeschaltet.";
                Error = null;
                LoadedOn = DateTime.MinValue;
            }
        }
    }
}
