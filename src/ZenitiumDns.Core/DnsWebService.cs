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
using ZenitiumDns.Core.Dns.Zones;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumLibrary;
using ZenitiumLibrary.IO;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.ClientConnection;
using ZenitiumLibrary.Net.Dns.ResourceRecords;
using ZenitiumLibrary.Net.Http.Client;

namespace ZenitiumDns.Core
{
    public sealed partial class DnsWebService : IAsyncDisposable, IDisposable
    {
        #region variables

        readonly static char[] commaSeparator = new char[] { ',' };
        static readonly IPEndPoint IPENDPOINT_ANY_0 = new IPEndPoint(IPAddress.Any, 0);
        const string DEFAULT_UPDATE_CHECK_URL = "https://api.github.com/repos/DNSBunker/ZenitiumDNS-DE/releases/latest";

        readonly Version _currentVersion;
        readonly string _packageVersion;
        readonly string _technitiumVersion;
        readonly DateTime _uptimestamp = DateTime.UtcNow;
        readonly string _appFolder;
        readonly string _configFolder;

        readonly LogManager _log;
        readonly AuthManager _authManager;

        readonly WebServiceApi _api;
        readonly WebServiceDashboardApi _dashboardApi;
        readonly WebServiceSelfTestApi _selfTestApi;
        readonly WebServiceZonesApi _zonesApi;
        readonly WebServiceOtherZonesApi _otherZonesApi;
        readonly WebServiceAppsApi _appsApi;
        readonly WebServiceSettingsApi _settingsApi;
        readonly WebServiceAuthApi _authApi;
        readonly WebServiceLogsApi _logsApi;

        WebApplication _webService;
        HttpClientNetworkHandler _ssoHttpHandler;
        HttpClient _ssoHttpClient;

        DnsServer _dnsServer;

        int _webServiceHttpPort = 5380;
        int _webServiceTlsPort = 53443;

        IReadOnlyList<IPAddress> _webServiceLocalAddresses = [IPAddress.Any, IPAddress.IPv6Any];

        bool _webServiceEnableHttpUnixSocket;
        string _webServiceHttpUnixSocket;

        bool _webServiceEnableTlsUnixSocket;
        string _webServiceTlsUnixSocket;

        bool _webServiceEnableTls;
        bool _webServiceEnableHttp3;
        bool _webServiceHttpToTlsRedirect;
        bool _webServiceUseSelfSignedTlsCertificate;

        IReadOnlyCollection<NetworkAccessControl> _webServiceReverseProxyAddresses =
            [
                new NetworkAccessControl(IPAddress.Parse("127.0.0.0"), 8),
                new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8),
                new NetworkAccessControl(IPAddress.Parse("100.64.0.0"), 10),
                new NetworkAccessControl(IPAddress.Parse("169.254.0.0"), 16),
                new NetworkAccessControl(IPAddress.Parse("172.16.0.0"), 12),
                new NetworkAccessControl(IPAddress.Parse("192.168.0.0"), 16),
                new NetworkAccessControl(IPAddress.Parse("2000::"), 3, true),
                new NetworkAccessControl(IPAddress.IPv6Any, 0)
            ];

        string _webServiceTlsCertificatePath;
        string _webServiceTlsCertificatePassword;
        string _webServiceTlsCertificateKeyPath;
        string _webServiceRealIpHeader = "X-Real-IP";
        string _webServiceCspFrameAncestorsHeader = "'none'";

        Timer _tlsCertificateUpdateTimer;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL = 60000;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL = 60000;

        DateTime _webServiceCertificateLastModifiedOn;
        SslServerAuthenticationOptions _webServiceSslServerAuthenticationOptions;

        bool _ssoEnabled;

        List<string> _configDisabledZones;

        readonly Lock _saveLock = new Lock();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        bool _isRunning;

        #endregion

        #region constructor

        public DnsWebService(bool isPortableApp, string configFolder = null)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();

            _currentVersion = assembly.GetName().Version;
            _packageVersion = assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? GetCleanVersion(_currentVersion);
            _technitiumVersion = null;

            foreach (AssemblyMetadataAttribute metadata in assembly.GetCustomAttributes<AssemblyMetadataAttribute>())
            {
                if (metadata.Key == "TechnitiumVersion")
                    _technitiumVersion = metadata.Value;
            }

            _appFolder = Path.GetDirectoryName(assembly.Location);

            if (configFolder is null)
                _configFolder = Path.Combine(_appFolder, "config");
            else
                _configFolder = Path.GetFullPath(configFolder);

            Directory.CreateDirectory(_configFolder);
            Directory.CreateDirectory(Path.Combine(_configFolder, "blocklists"));
            Directory.CreateDirectory(Path.Combine(_configFolder, "zones"));

            _log = new LogManager(isPortableApp, _configFolder);
            _authManager = new AuthManager(this, _configFolder, _log);

            string updateCheckUrl = Environment.GetEnvironmentVariable("DNS_SERVER_UPDATE_CHECK_URL") ?? DEFAULT_UPDATE_CHECK_URL;
            Uri.TryCreate(updateCheckUrl, UriKind.Absolute, out Uri updateCheckUri);

            _api = new WebServiceApi(this, updateCheckUri);
            _dashboardApi = new WebServiceDashboardApi(this);
            _selfTestApi = new WebServiceSelfTestApi(this);
            _zonesApi = new WebServiceZonesApi(this);
            _otherZonesApi = new WebServiceOtherZonesApi(this);
            _appsApi = new WebServiceAppsApi(this);
            _settingsApi = new WebServiceSettingsApi(this);
            _authApi = new WebServiceAuthApi(this);
            _logsApi = new WebServiceLogsApi(this);

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave)
                    {
                        try
                        {
                            SaveConfigFileInternal();
                            _pendingSave = false;
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);

                            _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                        }
                    }
                }
            });
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
                return;

            StopTlsCertificateUpdateTimer();

            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave)
                {
                    try
                    {
                        SaveConfigFileInternal();
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            await StopAsync();

            _authManager?.Dispose();

            if (_log is not null)
                await _log.DisposeAsync();

            _disposed = true;
        }

        public void Dispose()
        {
            DisposeAsync().Sync();
        }

        #endregion

        #region config

        private void LoadConfigFile()
        {
            string webServiceConfigFile = Path.Combine(_configFolder, "webservice.config");

            try
            {
                using (FileStream fS = new FileStream(webServiceConfigFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS);
                }

                _log.Write("Web Service config file was loaded: " + webServiceConfigFile);
            }
            catch (FileNotFoundException)
            {
                if (!TryLoadOldConfigFile())
                {
                    CreateForwarderZoneToDisableDnssecForNTP();

                    UdpClientConnection.SocketPoolExcludedPorts = [(ushort)_webServiceTlsPort];
                }

                lock (_saveLock)
                {
                    SaveConfigFileInternal();
                }
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading Web Service config file: " + webServiceConfigFile, ex);
                _log.Write("Note: You may try deleting the Web Service config file to fix this issue. However, you will lose Web Service settings but, other data wont be affected.");
                throw;
            }
        }

        public void LoadConfig(Stream s)
        {
            lock (_saveLock)
            {
                ReadConfigFrom(s);

                SaveConfigFileInternal();

                if (_pendingSave)
                {
                    _pendingSave = false;
                    _saveTimer.Change(Timeout.Infinite, Timeout.Infinite);
                }
            }
        }

        private void CreateForwarderZoneToDisableDnssecForNTP()
        {
            if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                string ntpDomain = "ntp.org";
                string fwdRecordComments = "Negative Trust Anchor for ntp.org to allow systems with no real-time clock to sync time.";

                if (_dnsServer.AuthZoneManager.CreateForwarderZone(ntpDomain, DnsTransportProtocol.Udp, "this-server", false, DnsForwarderRecordProxyType.DefaultProxy, null, 0, null, null, fwdRecordComments) is not null)
                {
                    _authManager.SetPermission(PermissionSection.Zones, ntpDomain, _authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _authManager.SetPermission(PermissionSection.Zones, ntpDomain, _authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _authManager.SaveConfigFile();
                }
            }
        }

        private void SaveConfigFileInternal()
        {
            string tmpConfigFile = Path.Combine(_configFolder, "webservice.tmp");
            string configFile = Path.Combine(_configFolder, "webservice.config");

            using (FileStream fS = new FileStream(tmpConfigFile, FileMode.Create, FileAccess.Write))
            {
                WriteConfigTo(fS);
            }

            File.Move(tmpConfigFile, configFile, true);

            _log.Write("Web Service config file was saved: " + configFile);
        }

        public void SavePendingConfigFile()
        {
            lock (_saveLock)
            {
                if (!_pendingSave)
                    return;

                SaveConfigFileInternal();
                _pendingSave = false;
            }
        }

        public void SaveConfigFile()
        {
            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void InspectAndFixZonePermissions()
        {
            Permission permission = _authManager.GetPermission(PermissionSection.Zones);
            if (permission is null)
                throw new DnsWebServiceException("Failed to read 'Zones' permissions: auth.config file is probably corrupt.");

            IReadOnlyDictionary<string, Permission> subItemPermissions = permission.SubItemPermissions;

            foreach (KeyValuePair<string, Permission> subItemPermission in subItemPermissions)
            {
                string zoneName = subItemPermission.Key;

                if (_dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName) is null)
                    permission.RemoveAllSubItemPermissions(zoneName);
            }

            IReadOnlyList<AuthZoneInfo> zones = _dnsServer.AuthZoneManager.GetAllZones();
            Group admins = _authManager.GetGroup(Group.ADMINISTRATORS);
            if (admins is null)
                throw new DnsWebServiceException("Failed to find 'Administrators' group: auth.config file is probably corrupt.");

            Group dnsAdmins = _authManager.GetGroup(Group.DNS_ADMINISTRATORS);
            if (dnsAdmins is null)
                throw new DnsWebServiceException("Failed to find 'DNS Administrators' group: auth.config file is probably corrupt.");

            foreach (AuthZoneInfo zone in zones)
            {
                _authManager.SetPermission(PermissionSection.Zones, zone.Name, admins, PermissionFlag.ViewModifyDelete);
                _authManager.SetPermission(PermissionSection.Zones, zone.Name, dnsAdmins, PermissionFlag.ViewModifyDelete);
            }

            _authManager.SaveConfigFile();
        }

        private void ReadConfigFrom(Stream s)
        {
            if (Encoding.ASCII.GetString(s.ReadExactly(2)) != "WC")
                throw new InvalidDataException("Web Service config file format is invalid.");

            BinaryReader bR = new BinaryReader(s);

            int version = bR.ReadByte();
            if (version > 5)
                throw new InvalidDataException("Web Service config version not supported.");

            _webServiceHttpPort = bR.ReadInt32();
            _webServiceTlsPort = bR.ReadInt32();

            {
                IPAddress[] webServiceLocalAddresses;

                int count = bR.ReadByte();
                if (count > 0)
                {
                    IPAddress[] localAddresses = new IPAddress[count];

                    for (int i = 0; i < count; i++)
                        localAddresses[i] = IPAddressExtensions.ReadFrom(bR);

                    webServiceLocalAddresses = localAddresses;
                }
                else
                {
                    webServiceLocalAddresses = [IPAddress.Any, IPAddress.IPv6Any];
                }

                _webServiceLocalAddresses = webServiceLocalAddresses;
            }

            if (version >= 3)
            {
                _webServiceEnableHttpUnixSocket = bR.ReadBoolean();

                _webServiceHttpUnixSocket = s.ReadShortString();
                if (_webServiceHttpUnixSocket.Length == 0)
                    _webServiceHttpUnixSocket = null;
            }
            else
            {
                _webServiceEnableHttpUnixSocket = false;
                _webServiceHttpUnixSocket = null;
            }

            if (version >= 4)
            {
                _webServiceEnableTlsUnixSocket = bR.ReadBoolean();

                _webServiceTlsUnixSocket = s.ReadShortString();
                if (_webServiceTlsUnixSocket.Length == 0)
                    _webServiceTlsUnixSocket = null;
            }
            else
            {
                _webServiceEnableTlsUnixSocket = false;
                _webServiceTlsUnixSocket = null;
            }

            _webServiceEnableTls = bR.ReadBoolean();
            _webServiceEnableHttp3 = bR.ReadBoolean();
            _webServiceHttpToTlsRedirect = bR.ReadBoolean();
            _webServiceUseSelfSignedTlsCertificate = bR.ReadBoolean();

            if (version >= 2)
            {
                _webServiceReverseProxyAddresses = AuthZoneInfo.ReadNetworkACLFrom(bR);
            }
            else
            {
                _webServiceReverseProxyAddresses =
                    [
                        new NetworkAccessControl(IPAddress.Parse("127.0.0.0"), 8),
                        new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8),
                        new NetworkAccessControl(IPAddress.Parse("100.64.0.0"), 10),
                        new NetworkAccessControl(IPAddress.Parse("169.254.0.0"), 16),
                        new NetworkAccessControl(IPAddress.Parse("172.16.0.0"), 12),
                        new NetworkAccessControl(IPAddress.Parse("192.168.0.0"), 16),
                        new NetworkAccessControl(IPAddress.Parse("2000::"), 3, true),
                        new NetworkAccessControl(IPAddress.IPv6Any, 0)
                    ];
            }

            _webServiceTlsCertificatePath = s.ReadShortString();
            _webServiceTlsCertificatePassword = s.ReadShortString();

            if (_webServiceTlsCertificatePath.Length == 0)
                _webServiceTlsCertificatePath = null;

            _webServiceRealIpHeader = s.ReadShortString();

            if (version >= 3)
                _webServiceCspFrameAncestorsHeader = s.ReadShortString();
            else
                _webServiceCspFrameAncestorsHeader = "'none'";

            if (version >= 5)
            {
                string webServiceTlsCertificateKeyPath = s.ReadShortString();
                _webServiceTlsCertificateKeyPath = webServiceTlsCertificateKeyPath.Length == 0 ? null : webServiceTlsCertificateKeyPath;
            }
            else
            {
                _webServiceTlsCertificateKeyPath = null;
            }

            if (_webServiceTlsCertificatePath is null)
            {
                StopTlsCertificateUpdateTimer();
            }
            else
            {
                string webServiceTlsCertificateAbsolutePath = ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                try
                {
                    LoadWebServiceTlsCertificate(webServiceTlsCertificateAbsolutePath, _webServiceTlsCertificatePassword, ConvertToAbsolutePath(_webServiceTlsCertificateKeyPath));
                }
                catch (Exception ex)
                {
                    _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + webServiceTlsCertificateAbsolutePath, ex);
                }

                StartTlsCertificateUpdateTimer();
            }

            CheckAndLoadSelfSignedCertificate(false, false);
        }

        private void WriteConfigTo(Stream s)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("WC"));
            bW.Write((byte)5);

            bW.Write(_webServiceHttpPort);
            bW.Write(_webServiceTlsPort);

            {
                bW.Write(Convert.ToByte(_webServiceLocalAddresses.Count));

                foreach (IPAddress localAddress in _webServiceLocalAddresses)
                    localAddress.WriteTo(bW);
            }

            bW.Write(_webServiceEnableHttpUnixSocket);
            s.WriteShortString(_webServiceHttpUnixSocket ?? "");

            bW.Write(_webServiceEnableTlsUnixSocket);
            s.WriteShortString(_webServiceTlsUnixSocket ?? "");

            bW.Write(_webServiceEnableTls);
            bW.Write(_webServiceEnableHttp3);
            bW.Write(_webServiceHttpToTlsRedirect);
            bW.Write(_webServiceUseSelfSignedTlsCertificate);

            AuthZoneInfo.WriteNetworkACLTo(_webServiceReverseProxyAddresses, bW);

            if (_webServiceTlsCertificatePath is null)
                s.WriteShortString(string.Empty);
            else
                s.WriteShortString(_webServiceTlsCertificatePath);

            if (_webServiceTlsCertificatePassword is null)
                s.WriteShortString(string.Empty);
            else
                s.WriteShortString(_webServiceTlsCertificatePassword);

            s.WriteShortString(_webServiceRealIpHeader);
            s.WriteShortString(_webServiceCspFrameAncestorsHeader);
            s.WriteShortString(_webServiceTlsCertificateKeyPath ?? string.Empty);
        }

        #endregion

        #region backup and restore config

        internal async Task BackupConfigAsync(Stream zipStream, bool authConfig, bool webServiceSettings, bool dnsSettings, bool logSettings, bool zones, bool allowedZones, bool blockedZones, bool blockLists, bool apps, bool stats, bool logs)
        {
            await using (ZipArchive backupZip = new ZipArchive(zipStream, ZipArchiveMode.Create, true, Encoding.UTF8))
            {
                if (authConfig)
                {
                    _authManager.SavePendingConfigFile();

                    string authConfigFile = Path.Combine(_configFolder, "auth.config");

                    if (File.Exists(authConfigFile))
                        backupZip.CreateEntryFromFile(authConfigFile, "auth.config");
                }

                if (webServiceSettings)
                {
                    SavePendingConfigFile();

                    string webServiceConfigFile = Path.Combine(_configFolder, "webservice.config");

                    if (File.Exists(webServiceConfigFile))
                        backupZip.CreateEntryFromFile(webServiceConfigFile, "webservice.config");

                    if (!string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                    {
                        string webServiceTlsCertificatePath = ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                        if (File.Exists(webServiceTlsCertificatePath) && !Path.IsPathRooted(ConvertToRelativePath(webServiceTlsCertificatePath)))
                        {
                            string entryName = ConvertToRelativePath(webServiceTlsCertificatePath).Replace('\\', '/');
                            backupZip.CreateEntryFromFile(webServiceTlsCertificatePath, entryName);
                        }
                    }
                }

                if (dnsSettings)
                {
                    _dnsServer.SavePendingConfigFile();

                    string dnsConfigFile = Path.Combine(_configFolder, "dns.config");

                    if (File.Exists(dnsConfigFile))
                        backupZip.CreateEntryFromFile(dnsConfigFile, "dns.config");

                    if (!string.IsNullOrEmpty(_dnsServer.DnsTlsCertificatePath))
                    {
                        string dnsTlsCertificatePath = ConvertToAbsolutePath(_dnsServer.DnsTlsCertificatePath);

                        if (File.Exists(dnsTlsCertificatePath) && !Path.IsPathRooted(ConvertToRelativePath(dnsTlsCertificatePath)))
                        {
                            string entryName = ConvertToRelativePath(dnsTlsCertificatePath).Replace('\\', '/');
                            backupZip.CreateEntryFromFile(dnsTlsCertificatePath, entryName);
                        }
                    }
                }

                if (logSettings)
                {
                    _log.SavePendingConfigFile();

                    string logConfigFile = Path.Combine(_configFolder, "log.config");

                    if (File.Exists(logConfigFile))
                        backupZip.CreateEntryFromFile(logConfigFile, "log.config");
                }

                if (zones)
                {
                    _dnsServer.AuthZoneManager.SavePendingZoneFiles();

                    string[] zoneFiles = Directory.GetFiles(Path.Combine(_configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);
                    foreach (string zoneFile in zoneFiles)
                    {
                        string entryName = "zones/" + Path.GetFileName(zoneFile);
                        backupZip.CreateEntryFromFile(zoneFile, entryName);
                    }
                }

                if (allowedZones)
                {
                    _dnsServer.AllowedZoneManager.SavePendingZoneFile();

                    string allowedZonesFile = Path.Combine(_configFolder, "allowed.config");

                    if (File.Exists(allowedZonesFile))
                        backupZip.CreateEntryFromFile(allowedZonesFile, "allowed.config");
                }

                if (blockedZones)
                {
                    _dnsServer.BlockedZoneManager.SavePendingZoneFile();

                    string blockedZonesFile = Path.Combine(_configFolder, "blocked.config");

                    if (File.Exists(blockedZonesFile))
                        backupZip.CreateEntryFromFile(blockedZonesFile, "blocked.config");
                }

                if (blockLists)
                {
                    _dnsServer.BlockListZoneManager.SavePendingConfigFile();

                    string blockListConfigFile = Path.Combine(_configFolder, "blocklist.config");

                    if (File.Exists(blockListConfigFile))
                        backupZip.CreateEntryFromFile(blockListConfigFile, "blocklist.config");

                    string[] blockListFiles = Directory.GetFiles(Path.Combine(_configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);
                    foreach (string blockListFile in blockListFiles)
                    {
                        string entryName = "blocklists/" + Path.GetFileName(blockListFile);
                        backupZip.CreateEntryFromFile(blockListFile, entryName);
                    }
                }

                if (apps)
                {
                    string[] appFiles = Directory.GetFiles(Path.Combine(_configFolder, "apps"), "*", SearchOption.AllDirectories);
                    foreach (string appFile in appFiles)
                    {
                        string entryName = appFile.Substring(_configFolder.Length);

                        if (Path.DirectorySeparatorChar != '/')
                            entryName = entryName.Replace(Path.DirectorySeparatorChar, '/');

                        entryName = entryName.TrimStart('/');

                        await CreateBackupEntryFromSharedFileAsync(backupZip, appFile, entryName);
                    }
                }

                if (stats)
                {
                    string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly);
                    foreach (string hourlyStatsFile in hourlyStatsFiles)
                    {
                        string entryName = "stats/" + Path.GetFileName(hourlyStatsFile);
                        backupZip.CreateEntryFromFile(hourlyStatsFile, entryName);
                    }

                    string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly);
                    foreach (string dailyStatsFile in dailyStatsFiles)
                    {
                        string entryName = "stats/" + Path.GetFileName(dailyStatsFile);
                        backupZip.CreateEntryFromFile(dailyStatsFile, entryName);
                    }
                }

                if (logs)
                {
                    string[] logFiles = Directory.GetFiles(_log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);
                    foreach (string logFile in logFiles)
                    {
                        string entryName = "logs/" + Path.GetFileName(logFile);

                        if (logFile.Equals(_log.CurrentLogFile, StringComparison.OrdinalIgnoreCase))
                        {
                            await CreateBackupEntryFromSharedFileAsync(backupZip, logFile, entryName);
                        }
                        else
                        {
                            backupZip.CreateEntryFromFile(logFile, entryName);
                        }
                    }
                }
            }
        }

        internal async Task RestoreConfigAsync(Stream zipStream, bool authConfig, bool webServiceSettings, bool dnsSettings, bool logSettings, bool zones, bool allowedZones, bool blockedZones, bool blockLists, bool apps, bool stats, bool logs, bool deleteExistingFiles, UserSession implantSession = null)
        {
            await using (ZipArchive backupZip = new ZipArchive(zipStream, ZipArchiveMode.Read, false, Encoding.UTF8))
            {
                if (logSettings)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("log.config");
                    if (entry is not null)
                    {
                        await using (Stream stream = entry.Open())
                        {
                            _log.LoadConfig(stream);
                        }
                    }
                }

                if (logs)
                {
                    _log.BulkManipulateLogFiles(async delegate ()
                    {
                        if (deleteExistingFiles)
                        {
                            string[] logFiles = Directory.GetFiles(_log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);

                            foreach (string logFile in logFiles)
                            {
                                try
                                {
                                    File.Delete(logFile);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }

                        foreach (ZipArchiveEntry entry in backupZip.Entries)
                        {
                            if (entry.FullName.StartsWith("logs/", StringComparison.Ordinal))
                            {
                                try
                                {
                                    await ExtractBackupEntryToFolderAsync(entry, _log.LogFolderAbsolutePath);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }
                    });
                }

                if (authConfig)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("auth.config");
                    if (entry is not null)
                    {
                        await using (Stream stream = entry.Open())
                        {
                            _authManager.LoadConfig(stream, out _, implantSession);
                        }
                    }
                }

                if ((webServiceSettings || dnsSettings))
                {
                    foreach (ZipArchiveEntry certEntry in backupZip.Entries)
                    {
                        if (certEntry.FullName.StartsWith("apps/", StringComparison.Ordinal))
                            continue;

                        if (certEntry.FullName.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase) || certEntry.FullName.EndsWith(".p12", StringComparison.OrdinalIgnoreCase))
                        {
                            try
                            {
                                string certFile = Path.GetFullPath(Path.Combine(_configFolder, certEntry.FullName));
                                if (!certFile.StartsWith(_configFolder.TrimEnd(['/', '\\']) + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                                    throw new IOException("Extracting Zip entry would have resulted in a file outside the specified destination directory.");

                                Directory.CreateDirectory(Path.GetDirectoryName(certFile));

                                await certEntry.ExtractToFileAsync(certFile, true);
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }
                }

                if (webServiceSettings)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("webservice.config");
                    if (entry is not null)
                    {
                        await using (Stream stream = entry.Open())
                        {
                            LoadConfig(stream);
                        }
                    }
                }

                if (dnsSettings)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("dns.config");
                    if (entry is not null)
                    {
                        try
                        {
                            await using (Stream stream = entry.Open())
                            {
                                _dnsServer.LoadConfig(stream);
                            }
                        }
                        catch (InvalidDataException)
                        {
                            await using (Stream stream = entry.Open())
                            {
                                if (!TryLoadOldConfigFrom(stream))
                                    throw;

                                _log.Write("Old DNS config file was restored successfully.");

                                lock (_saveLock)
                                {
                                    SaveConfigFileInternal();
                                }
                            }
                        }
                    }
                }

                if (zones)
                {
                    _dnsServer.AuthZoneManager.SavePendingZoneFiles();

                    if (deleteExistingFiles)
                    {
                        string[] zoneFiles = Directory.GetFiles(Path.Combine(_configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);

                        foreach (string zoneFile in zoneFiles)
                        {
                            try
                            {
                                File.Delete(zoneFile);
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }

                    foreach (ZipArchiveEntry entry in backupZip.Entries)
                    {
                        if (entry.FullName.StartsWith("zones/", StringComparison.Ordinal))
                        {
                            try
                            {
                                await ExtractBackupEntryToFolderAsync(entry, Path.Combine(_configFolder, "zones"));
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }

                    _dnsServer.AuthZoneManager.LoadAllZoneFiles();
                    InspectAndFixZonePermissions();
                }

                if (allowedZones)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("allowed.config");
                    if (entry is not null)
                    {
                        await using (Stream stream = entry.Open())
                        {
                            _dnsServer.AllowedZoneManager.LoadAllowedZone(stream);
                        }
                    }
                }

                if (blockedZones)
                {
                    ZipArchiveEntry entry = backupZip.GetEntry("blocked.config");
                    if (entry is not null)
                    {
                        await using (Stream stream = entry.Open())
                        {
                            _dnsServer.BlockedZoneManager.LoadBlockedZone(stream);
                        }
                    }
                }

                if (blockLists)
                {
                    if (deleteExistingFiles)
                    {
                        string[] blockListFiles = Directory.GetFiles(Path.Combine(_configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);

                        foreach (string blockListFile in blockListFiles)
                        {
                            try
                            {
                                File.Delete(blockListFile);
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }

                    foreach (ZipArchiveEntry entry in backupZip.Entries)
                    {
                        if (entry.FullName.StartsWith("blocklists/", StringComparison.Ordinal))
                        {
                            try
                            {
                                await ExtractBackupEntryToFolderAsync(entry, Path.Combine(_configFolder, "blocklists"));
                            }
                            catch (IOException)
                            {
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }

                    ZipArchiveEntry blockListConfigEntry = backupZip.GetEntry("blocklist.config");
                    if (blockListConfigEntry is not null)
                    {
                        await using (Stream stream = blockListConfigEntry.Open())
                        {
                            _dnsServer.BlockListZoneManager.LoadConfig(stream);
                        }
                    }
                }

                if (apps)
                {
                    await _dnsServer.DnsApplicationManager.UnloadAllApplicationsAsync();

                    if (deleteExistingFiles)
                    {
                        string appFolder = Path.Combine(_configFolder, "apps");
                        if (Directory.Exists(appFolder))
                        {
                            try
                            {
                                Directory.Delete(appFolder, true);
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }

                        Directory.CreateDirectory(appFolder);
                    }

                    string appsFolder = Path.Combine(_configFolder, "apps");

                    foreach (ZipArchiveEntry entry in backupZip.Entries)
                    {
                        if (entry.FullName.StartsWith("apps/", StringComparison.Ordinal))
                        {
                            string filePath = Path.GetFullPath(Path.Combine(_configFolder, entry.FullName));
                            if (!filePath.StartsWith(appsFolder + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                                throw new IOException("Extracting Zip entry would have resulted in a file outside the specified destination directory.");

                            if ((entry.Length == 0) && (entry.Name.Length == 0) && entry.FullName.EndsWith('/'))
                            {
                                Directory.CreateDirectory(filePath);
                            }
                            else
                            {
                                Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                                try
                                {
                                    await entry.ExtractToFileAsync(filePath, true);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }
                    }

                    await _dnsServer.DnsApplicationManager.LoadAllApplicationsAsync();
                }

                if (stats)
                {
                    if (deleteExistingFiles)
                    {
                        string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly);

                        foreach (string hourlyStatsFile in hourlyStatsFiles)
                        {
                            try
                            {
                                File.Delete(hourlyStatsFile);
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }

                        string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly);

                        foreach (string dailyStatsFile in dailyStatsFiles)
                        {
                            try
                            {
                                File.Delete(dailyStatsFile);
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }

                    foreach (ZipArchiveEntry entry in backupZip.Entries)
                    {
                        if (entry.FullName.StartsWith("stats/", StringComparison.Ordinal))
                        {
                            try
                            {
                                await ExtractBackupEntryToFolderAsync(entry, Path.Combine(_configFolder, "stats"));
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }

                    _dnsServer.StatsManager.ReloadStats();
                }
            }
        }

        private static async Task ExtractBackupEntryToFolderAsync(ZipArchiveEntry entry, string folder)
        {
            if (entry.Name.Length == 0)
                return;

            string folderPath = Path.GetFullPath(folder).TrimEnd(['/', '\\']) + Path.DirectorySeparatorChar;
            string filePath = Path.GetFullPath(Path.Combine(folderPath, entry.Name));

            if (!filePath.StartsWith(folderPath, StringComparison.Ordinal))
                throw new IOException("Extracting Zip entry would have resulted in a file outside the specified destination directory.");

            await entry.ExtractToFileAsync(filePath, true);
        }

        private static async Task CreateBackupEntryFromSharedFileAsync(ZipArchive backupZip, string sourceFileName, string entryName)
        {
            await using (FileStream fS = new FileStream(sourceFileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                ZipArchiveEntry entry = backupZip.CreateEntry(entryName);

                DateTime lastWrite = File.GetLastWriteTime(sourceFileName);

                if (lastWrite.Year < 1980 || lastWrite.Year > 2107)
                    lastWrite = new DateTime(1980, 1, 1, 0, 0, 0);

                entry.LastWriteTime = lastWrite;

                await using (Stream sE = entry.Open())
                {
                    await fS.CopyToAsync(sE);
                }
            }
        }

        #endregion

        #region private

        private string ConvertToRelativePath(string path)
        {
            string configFolder = _configFolder.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;

            if (path.StartsWith(configFolder, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                path = path.Substring(configFolder.Length).TrimStart(Path.DirectorySeparatorChar);

            return path;
        }

        private string ConvertToAbsolutePath(string path)
        {
            if (path is null)
                return null;

            if (Path.IsPathRooted(path))
                return path;

            return Path.GetFullPath(Path.Combine(_configFolder, path));
        }

        private void RestartService(bool restartDnsService, bool restartWebService)
        {
            RestartService(restartDnsService, restartWebService, _webServiceLocalAddresses, _webServiceHttpPort, _webServiceTlsPort);
        }

        private void RestartService(bool restartDnsService, bool restartWebService, IReadOnlyList<IPAddress> oldWebServiceLocalAddresses, int oldWebServiceHttpPort, int oldWebServiceTlsPort)
        {
            ThreadPool.QueueUserWorkItem(async delegate (object state)
            {
                if (restartWebService)
                {
                    try
                    {
                        await Task.Delay(2000);

                        _log.Write("Attempting to restart web service.");

                        try
                        {
                            await StopWebServiceAsync();
                            await TryStartWebServiceAsync(oldWebServiceLocalAddresses, oldWebServiceHttpPort, oldWebServiceTlsPort);

                            _log.Write("Web service was restarted successfully.");
                        }
                        catch (Exception ex)
                        {
                            _log.Write("Failed to restart web service.", ex);
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                }

                if (restartDnsService)
                {
                    try
                    {
                        _log.Write("Attempting to restart DNS service.");

                        await _dnsServer.StopAsync();
                        await _dnsServer.StartAsync();

                        _log.Write("DNS service was restarted successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write("Failed to restart DNS service.", ex);
                    }
                }
            });
        }

        #endregion

        #region server version

        private string GetServerVersion()
        {
            return _packageVersion;
        }

        private void WriteVersionInfo(Utf8JsonWriter jsonWriter)
        {
            jsonWriter.WriteString("technitiumVersion", _technitiumVersion);
            jsonWriter.WriteString("runtimeVersion", RuntimeInformation.FrameworkDescription);
            jsonWriter.WriteString("osDescription", RuntimeInformation.OSDescription);
            jsonWriter.WriteString("osArchitecture", RuntimeInformation.OSArchitecture.ToString().ToLowerInvariant());
        }

        private static string GetCleanVersion(Version version)
        {
            string strVersion = version.Major + "." + version.Minor;

            if (version.Build > 0)
                strVersion += "." + version.Build;

            if (version.Revision > 0)
                strVersion += "." + version.Revision;

            return strVersion;
        }

        #endregion

        #region web service

        private async Task TryStartWebServiceAsync(IReadOnlyList<IPAddress> oldWebServiceLocalAddresses, int oldWebServiceHttpPort, int oldWebServiceTlsPort)
        {
            try
            {
                _webServiceLocalAddresses = WebUtilities.GetValidKestrelLocalAddresses(_webServiceLocalAddresses);

                await StartWebServiceAsync(false);
                return;
            }
            catch (Exception ex)
            {
                _log.Write("Web Service failed to start.", ex);
            }

            _log.Write("Attempting to revert Web Service end point changes ...");

            try
            {
                _webServiceLocalAddresses = WebUtilities.GetValidKestrelLocalAddresses(oldWebServiceLocalAddresses);
                _webServiceHttpPort = oldWebServiceHttpPort;
                _webServiceTlsPort = oldWebServiceTlsPort;

                await StartWebServiceAsync(false);

                lock (_saveLock)
                {
                    SaveConfigFileInternal();
                }

                return;
            }
            catch (Exception ex2)
            {
                _log.Write("Web Service failed to start.", ex2);
            }

            _log.Write("Attempting to start Web Service on ANY (0.0.0.0) fallback address...");

            try
            {
                _webServiceLocalAddresses = [IPAddress.Any];

                await StartWebServiceAsync(true);
                return;
            }
            catch (Exception ex3)
            {
                _log.Write("Web Service failed to start.", ex3);
            }

            _log.Write("Attempting to start Web Service on loopback (127.0.0.1) fallback address...");

            _webServiceLocalAddresses = [IPAddress.Loopback];

            await StartWebServiceAsync(true);
        }

        private async Task StartWebServiceAsync(bool httpOnlyMode)
        {
            WebApplicationBuilder builder = WebApplication.CreateBuilder();

            bool ssoEnabled = _authManager.SsoEnabled && (_authManager.SsoAuthority is not null) && (_authManager.SsoClientId is not null) && (_authManager.SsoClientSecret is not null);
            if (ssoEnabled)
            {
                builder.Services.AddAuthentication(delegate (AuthenticationOptions options)
                {
                    options.DefaultScheme = BearerTokenDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                })
                .AddBearerToken()
                .AddOpenIdConnect(delegate (OpenIdConnectOptions options)
                {
                    options.Authority = _authManager.SsoAuthority.AbsoluteUri;
                    options.ClientId = _authManager.SsoClientId;
                    options.ClientSecret = _authManager.SsoClientSecret;
                    options.RequireHttpsMetadata = false;
                    options.ResponseType = OpenIdConnectResponseType.Code;
                    options.ResponseMode = OpenIdConnectResponseMode.FormPost;

                    _ssoHttpHandler?.Dispose();
                    _ssoHttpClient?.Dispose();

                    _ssoHttpHandler = new HttpClientNetworkHandler
                    {
                        Proxy = _dnsServer.Proxy,
                        NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsServer.IPv6Mode),
                        DnsClient = _dnsServer
                    };

                    _ssoHttpClient = new HttpClient(_ssoHttpHandler);

                    options.BackchannelHttpHandler = _ssoHttpHandler;
                    options.Backchannel = _ssoHttpClient;

                    options.Scope.Clear();

                    foreach (string scope in _authManager.SsoScopes)
                        options.Scope.Add(scope);

                    options.ClaimActions.MapUniqueJsonKey("sub", "sub");
                    options.ClaimActions.MapUniqueJsonKey("email", "email");
                    options.ClaimActions.MapUniqueJsonKey("preferred_username", "preferred_username");
                    options.ClaimActions.MapUniqueJsonKey("upn", "upn");
                    options.ClaimActions.MapUniqueJsonKey("nickname", "nickname");
                    options.ClaimActions.MapUniqueJsonKey("name", "name");
                    options.ClaimActions.MapUniqueJsonKey("given_name", "given_name");
                    options.ClaimActions.MapJsonKey("groups", "groups");
                    options.ClaimActions.MapJsonKey("roles", "roles");

                    options.CallbackPath = new PathString("/sso/callback");

                    if (_authManager.SsoMetadataAddress is not null)
                        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(_authManager.SsoMetadataAddress.AbsoluteUri, new OpenIdConnectConfigurationRetriever(), new HttpDocumentRetriever(_ssoHttpClient) { RequireHttps = false });

                    options.Events = new OpenIdConnectEvents
                    {
                        OnRedirectToIdentityProvider = async delegate (RedirectContext context)
                        {
                            OpenIdConnectConfiguration configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(context.HttpContext.RequestAborted);

                            context.Options.GetClaimsFromUserInfoEndpoint = !string.IsNullOrEmpty(configuration.UserInfoEndpoint);
                        },
                        OnTicketReceived = async delegate (TicketReceivedContext context)
                        {
                            context.HandleResponse();

                            if ((context.Principal is null) || (context.Principal.Identity is null) || !context.Principal.Identity.IsAuthenticated)
                                context.Response.Redirect("/#error=" + Uri.EscapeDataString("SSO authentication failed. Please try again."));
                            else
                                await _authApi.SsoLoginFinalizeAsync(context.HttpContext, context.Principal);
                        },
                        OnAuthenticationFailed = delegate (AuthenticationFailedContext context)
                        {
                            _log.Write(GetRemoteEndPoint(context.HttpContext), context.Exception);

                            context.HandleResponse();
                            context.Response.Redirect("/#error=" + Uri.EscapeDataString("SSO authentication failed. Please try again."));

                            return Task.CompletedTask;
                        },
                        OnRemoteFailure = delegate (RemoteFailureContext context)
                        {
                            if (context.Failure is not null)
                                _log.Write(GetRemoteEndPoint(context.HttpContext), context.Failure);

                            context.HandleResponse();
                            context.Response.Redirect("/#error=" + Uri.EscapeDataString("SSO remote failure. Please contact your administrator."));

                            return Task.CompletedTask;
                        }
                    };
                });

                builder.Services.AddAuthorization();
            }

            builder.Environment.ContentRootFileProvider = new PhysicalFileProvider(_appFolder)
            {
                UseActivePolling = true,
                UsePollingFileWatcher = true
            };

            string wwwFolderPath = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH");
            if (string.IsNullOrEmpty(wwwFolderPath))
            {
                wwwFolderPath = Path.Combine(_appFolder, "www");
            }
            else if (!Directory.Exists(wwwFolderPath))
            {
                _log.Write("Web Service is falling back to the default web root folder since the folder configured by the DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH environment variable does not exist: " + wwwFolderPath);
                wwwFolderPath = Path.Combine(_appFolder, "www");
            }

            builder.Environment.WebRootFileProvider = new PhysicalFileProvider(wwwFolderPath)
            {
                UseActivePolling = true,
                UsePollingFileWatcher = true
            };

            builder.Services.AddResponseCompression(delegate (ResponseCompressionOptions options)
            {
                options.EnableForHttps = true;
            });

            builder.WebHost.ConfigureKestrel(delegate (WebHostBuilderContext context, KestrelServerOptions serverOptions)
            {
                foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                    serverOptions.Listen(webServiceLocalAddress, _webServiceHttpPort);

                if (!httpOnlyMode && _webServiceEnableHttpUnixSocket && (_webServiceHttpUnixSocket is not null))
                {
                    try
                    {
                        if (File.Exists(_webServiceHttpUnixSocket))
                            File.Delete(_webServiceHttpUnixSocket);
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }

                    serverOptions.ListenUnixSocket(_webServiceHttpUnixSocket);
                }

                if (!httpOnlyMode && _webServiceEnableTlsUnixSocket && (_webServiceTlsUnixSocket is not null) && (_webServiceSslServerAuthenticationOptions is not null))
                {
                    try
                    {
                        if (File.Exists(_webServiceTlsUnixSocket))
                            File.Delete(_webServiceTlsUnixSocket);
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }

                    serverOptions.ListenUnixSocket(_webServiceTlsUnixSocket, delegate (ListenOptions listenOptions)
                    {
                        if (IsHttp2Supported())
                            listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
                        else
                            listenOptions.Protocols = HttpProtocols.Http1;

                        listenOptions.UseHttps(delegate (SslStream stream, SslClientHelloInfo clientHelloInfo, object state, CancellationToken cancellationToken)
                        {
                            return ValueTask.FromResult(_webServiceSslServerAuthenticationOptions);
                        }, null);
                    });
                }

                if (!httpOnlyMode && _webServiceEnableTls && (_webServiceSslServerAuthenticationOptions is not null))
                {
                    foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                    {
                        serverOptions.Listen(webServiceLocalAddress, _webServiceTlsPort, delegate (ListenOptions listenOptions)
                        {
                            if (_webServiceEnableHttp3)
                                listenOptions.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
                            else if (IsHttp2Supported())
                                listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
                            else
                                listenOptions.Protocols = HttpProtocols.Http1;

                            listenOptions.UseHttps(delegate (SslStream stream, SslClientHelloInfo clientHelloInfo, object state, CancellationToken cancellationToken)
                            {
                                return ValueTask.FromResult(_webServiceSslServerAuthenticationOptions);
                            }, null);
                        });
                    }
                }

                serverOptions.AddServerHeader = false;
                serverOptions.Limits.MaxRequestBodySize = int.MaxValue;
            });

            builder.Services.Configure(delegate (FormOptions options)
            {
                options.MultipartBodyLengthLimit = int.MaxValue;
            });

            builder.Logging.ClearProviders();

            _webService = builder.Build();

            if (ssoEnabled)
            {
                _webService.Use(delegate (HttpContext context, Func<Task> next)
                {
                    IPAddress remoteIP = context.Connection.RemoteIpAddress;
                    if ((remoteIP is not null) && NetworkAccessControl.IsAddressAllowed(remoteIP, _webServiceReverseProxyAddresses))
                    {
                        string strScheme = context.Request.Headers["X-Forwarded-Proto"];
                        if (!string.IsNullOrEmpty(strScheme))
                            context.Request.Scheme = strScheme;

                        string strHost = context.Request.Headers["X-Forwarded-Host"];
                        if (!string.IsNullOrEmpty(strHost))
                            context.Request.Host = new HostString(strHost);

                        string strPathBase = context.Request.Headers["X-Forwarded-Prefix"];
                        if (!string.IsNullOrEmpty(strPathBase))
                            context.Request.PathBase = new PathString(strPathBase);
                    }

                    return next();
                });

                _webService.UseAuthentication();
                _webService.UseAuthorization();
            }

            _webService.UseResponseCompression();

            if (!httpOnlyMode && _webServiceHttpToTlsRedirect && _webServiceEnableTls && (_webServiceSslServerAuthenticationOptions is not null))
                _webService.Use(WebServiceHttpsRedirectionMiddleware);

            _webService.UseDefaultFiles();
            _webService.UseStaticFiles(new StaticFileOptions()
            {
                OnPrepareResponse = delegate (StaticFileResponseContext ctx)
                {
                    ctx.Context.Response.Headers["X-Robots-Tag"] = "noindex, nofollow";
                    ctx.Context.Response.Headers.CacheControl = "no-cache";
                    ctx.Context.Response.Headers.XContentTypeOptions = "nosniff";
                    ctx.Context.Response.Headers["Referrer-Policy"] = "same-origin";
                    ctx.Context.Response.Headers.ContentSecurityPolicy =
                        "default-src 'self'; " +
                        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data:; " +
                        $"frame-ancestors {_webServiceCspFrameAncestorsHeader};";

                    if (_webServiceCspFrameAncestorsHeader.Equals("'none'", StringComparison.OrdinalIgnoreCase))
                        ctx.Context.Response.Headers.XFrameOptions = "DENY";
                },
                ServeUnknownFileTypes = true
            });

            ConfigureWebServiceRoutes();

            try
            {
                await _webService.StartAsync();

                foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                {
                    _log.Write(new IPEndPoint(webServiceLocalAddress, _webServiceHttpPort), "Http", "Web Service was bound successfully.");

                    if (!httpOnlyMode && _webServiceEnableTls && (_webServiceSslServerAuthenticationOptions is not null))
                        _log.Write(new IPEndPoint(webServiceLocalAddress, _webServiceTlsPort), "Https", "Web Service was bound successfully.");
                }

                if (!httpOnlyMode && _webServiceEnableHttpUnixSocket && (_webServiceHttpUnixSocket is not null))
                    _log.Write(new UnixDomainSocketEndPoint(_webServiceHttpUnixSocket), "HttpUnix", "Web Service was bound successfully.");

                if (!httpOnlyMode && _webServiceEnableTlsUnixSocket && (_webServiceTlsUnixSocket is not null) && (_webServiceSslServerAuthenticationOptions is not null))
                    _log.Write(new UnixDomainSocketEndPoint(_webServiceTlsUnixSocket), "HttpsUnix", "Web Service was bound successfully.");
            }
            catch
            {
                await StopWebServiceAsync();

                foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                {
                    _log.Write(new IPEndPoint(webServiceLocalAddress, _webServiceHttpPort), "Http", "Web Service failed to bind.");

                    if (!httpOnlyMode && _webServiceEnableTls && (_webServiceSslServerAuthenticationOptions is not null))
                        _log.Write(new IPEndPoint(webServiceLocalAddress, _webServiceTlsPort), "Https", "Web Service failed to bind.");
                }

                if (!httpOnlyMode && _webServiceEnableHttpUnixSocket && (_webServiceHttpUnixSocket is not null))
                    _log.Write(new UnixDomainSocketEndPoint(_webServiceHttpUnixSocket), "HttpUnix", "Web Service failed to bind.");

                if (!httpOnlyMode && _webServiceEnableTlsUnixSocket && (_webServiceTlsUnixSocket is not null) && (_webServiceSslServerAuthenticationOptions is not null))
                    _log.Write(new UnixDomainSocketEndPoint(_webServiceTlsUnixSocket), "HttpsUnix", "Web Service failed to bind.");

                throw;
            }

            _ssoEnabled = ssoEnabled;
        }

        private async Task StopWebServiceAsync()
        {
            if (_webService is not null)
            {
                await _webService.DisposeAsync();
                _webService = null;
            }

            _ssoHttpHandler?.Dispose();
            _ssoHttpClient?.Dispose();
        }

        private bool IsHttp2Supported()
        {
            if (_webServiceEnableHttp3)
                return true;

            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT:
                    return Environment.OSVersion.Version.Major >= 10;

                case PlatformID.Unix:
                    return true;

                default:
                    return false;
            }
        }

        private IPEndPoint GetRemoteEndPoint(HttpContext context)
        {
            try
            {
                IPAddress remoteIP = context.Connection.RemoteIpAddress;
                if ((remoteIP is not null) && remoteIP.IsIPv4MappedToIPv6)
                    remoteIP = remoteIP.MapToIPv4();

                if (!string.IsNullOrEmpty(_webServiceRealIpHeader) && ((remoteIP is null) || NetworkAccessControl.IsAddressAllowed(remoteIP, _webServiceReverseProxyAddresses)))
                {
                    string xRealIp = context.Request.Headers[_webServiceRealIpHeader];
                    if (IPAddress.TryParse(xRealIp, out IPAddress address))
                        return new IPEndPoint(address, 0);
                }

                if (remoteIP is not null)
                    return new IPEndPoint(remoteIP, context.Connection.RemotePort);
            }
            catch
            { }

            return IPENDPOINT_ANY_0;
        }

        private void ConfigureWebServiceRoutes()
        {
            _webService.UseExceptionHandler(WebServiceExceptionHandler);

            _webService.Use(WebServiceApiMiddleware);

            _webService.UseRouting();

            _webService.MapGetAndPost("/api/status", _authApi.StatusAsync);

            _webService.MapGetAndPost("/sso/login", _authApi.SsoLoginAsync);
            _webService.MapGetAndPost("/api/sso/status", _authApi.StatusAsync);

            _webService.MapGetAndPost("/api/user/login", delegate (HttpContext context) { return _authApi.LoginAsync(context, UserSessionType.Standard); });
            _webService.MapGetAndPost("/api/user/logout", _authApi.Logout);

            _webService.MapGetAndPost("/api/user/createSingleUseToken", _authApi.CreateSingleUseToken);
            _webService.MapGetAndPost("/api/user/session/get", _authApi.GetCurrentSessionDetails);
            _webService.MapGetAndPost("/api/user/session/delete", delegate (HttpContext context) { _authApi.DeleteSession(context, false); });
            _webService.MapGetAndPost("/api/user/changePassword", _authApi.ChangePasswordAsync);
            _webService.MapGetAndPost("/api/user/2fa/init", _authApi.Initialize2FA);
            _webService.MapGetAndPost("/api/user/2fa/enable", _authApi.Enable2FA);
            _webService.MapGetAndPost("/api/user/2fa/disable", _authApi.Disable2FA);
            _webService.MapGetAndPost("/api/user/profile/get", _authApi.GetProfile);
            _webService.MapGetAndPost("/api/user/profile/set", _authApi.SetProfile);
            _webService.MapGetAndPost("/api/user/checkForUpdate", _api.CheckForUpdateAsync);

            _webService.MapGetAndPost("/api/dashboard/metrics/json", _dashboardApi.GetMetricsJson);
            _webService.MapGetAndPost("/api/dashboard/stats/get", _dashboardApi.GetStatsAsync);
            _webService.MapGetAndPost("/api/dashboard/stats/getTop", _dashboardApi.GetTopStatsAsync);
            _webService.MapGetAndPost("/api/dashboard/stats/deleteAll", _logsApi.DeleteAllStats);
            _webService.MapGetAndPost("/api/dashboard/ipv6/probe", _dashboardApi.ProbeIPv6UpstreamAsync);
            _webService.MapGetAndPost("/api/dashboard/system/live", _dashboardApi.GetLiveSystemStats);

            _webService.MapGetAndPost("/api/zones/list", _zonesApi.ListZones);
            _webService.MapGetAndPost("/api/zones/create", _zonesApi.CreateZoneAsync);
            _webService.MapGetAndPost("/api/zones/import", _zonesApi.ImportZoneAsync);
            _webService.MapGetAndPost("/api/zones/export", _zonesApi.ExportZoneAsync);
            _webService.MapGetAndPost("/api/zones/clone", _zonesApi.CloneZone);
            _webService.MapGetAndPost("/api/zones/enable", _zonesApi.EnableZone);
            _webService.MapGetAndPost("/api/zones/disable", _zonesApi.DisableZone);
            _webService.MapGetAndPost("/api/zones/delete", _zonesApi.DeleteZone);
            _webService.MapGetAndPost("/api/zones/options/get", _zonesApi.GetZoneOptions);
            _webService.MapGetAndPost("/api/zones/options/set", _zonesApi.SetZoneOptions);
            _webService.MapGetAndPost("/api/zones/permissions/get", delegate (HttpContext context) { _authApi.GetPermissionDetails(context, PermissionSection.Zones); });
            _webService.MapGetAndPost("/api/zones/permissions/set", delegate (HttpContext context) { _authApi.SetPermissionsDetails(context, PermissionSection.Zones); });
            _webService.MapGetAndPost("/api/zones/records/add", _zonesApi.AddRecord);
            _webService.MapGetAndPost("/api/zones/records/get", _zonesApi.GetRecords);
            _webService.MapGetAndPost("/api/zones/records/update", _zonesApi.UpdateRecord);
            _webService.MapGetAndPost("/api/zones/records/delete", _zonesApi.DeleteRecord);

            _webService.MapGetAndPost("/api/cache/list", _otherZonesApi.ListCachedZones);
            _webService.MapGetAndPost("/api/cache/delete", _otherZonesApi.DeleteCachedZone);
            _webService.MapGetAndPost("/api/cache/flush", _otherZonesApi.FlushCache);

            _webService.MapGetAndPost("/api/allowed/list", _otherZonesApi.ListAllowedZones);
            _webService.MapGetAndPost("/api/allowed/add", _otherZonesApi.AllowZone);
            _webService.MapGetAndPost("/api/allowed/delete", _otherZonesApi.DeleteAllowedZone);
            _webService.MapGetAndPost("/api/allowed/flush", _otherZonesApi.FlushAllowedZone);
            _webService.MapGetAndPost("/api/allowed/import", _otherZonesApi.ImportAllowedZones);
            _webService.MapGetAndPost("/api/allowed/export", _otherZonesApi.ExportAllowedZonesAsync);

            _webService.MapGetAndPost("/api/blocked/list", _otherZonesApi.ListBlockedZones);
            _webService.MapGetAndPost("/api/blocked/add", _otherZonesApi.BlockZone);
            _webService.MapGetAndPost("/api/blocked/delete", _otherZonesApi.DeleteBlockedZone);
            _webService.MapGetAndPost("/api/blocked/flush", _otherZonesApi.FlushBlockedZone);
            _webService.MapGetAndPost("/api/blocked/import", _otherZonesApi.ImportBlockedZones);
            _webService.MapGetAndPost("/api/blocked/export", _otherZonesApi.ExportBlockedZonesAsync);

            _webService.MapGetAndPost("/api/selftest/run", _selfTestApi.RunAsync);

            _webService.MapGetAndPost("/api/apps/list", _appsApi.ListInstalledApps);
            _webService.MapGetAndPost("/api/apps/enable", delegate (HttpContext context) { return _appsApi.SetAppEnabledAsync(context, true); });
            _webService.MapGetAndPost("/api/apps/disable", delegate (HttpContext context) { return _appsApi.SetAppEnabledAsync(context, false); });
            _webService.MapGetAndPost("/api/apps/config/get", _appsApi.GetAppConfigAsync);
            _webService.MapGetAndPost("/api/apps/config/set", _appsApi.SetAppConfigAsync);

            _webService.MapGetAndPost("/api/dnsClient/resolve", _api.ResolveQueryAsync);
            _webService.MapGetAndPost("/api/dnsClient/healthCheck", _api.HealthCheckAsync);

            _webService.MapGetAndPost("/api/settings/get", _settingsApi.GetDnsSettings);
            _webService.MapGetAndPost("/api/settings/set", _settingsApi.SetDnsSettingsAsync);
            _webService.MapGetAndPost("/api/settings/forceUpdateBlockLists", _settingsApi.ForceUpdateBlockLists);
            _webService.MapGetAndPost("/api/settings/forceUpdateClientBlockLists", _settingsApi.ForceUpdateClientBlockLists);
            _webService.MapGetAndPost("/api/settings/iana/update", _settingsApi.UpdateIanaDataAsync);
            _webService.MapGetAndPost("/api/settings/iana/get", _settingsApi.GetIanaDataAsync);
            _webService.MapPost("/api/settings/iana/set", _settingsApi.SetIanaDataAsync);
            _webService.MapGetAndPost("/api/settings/temporaryDisableBlocking", _settingsApi.TemporaryDisableBlocking);
            _webService.MapGetAndPost("/api/settings/backup", _settingsApi.BackupSettingsAsync);
            _webService.MapPost("/api/settings/restore", _settingsApi.RestoreSettingsAsync);

            _webService.MapGetAndPost("/api/admin/sessions/list", _authApi.ListSessions);
            _webService.MapGetAndPost("/api/admin/sessions/delete", delegate (HttpContext context) { _authApi.DeleteSession(context, true); });
            _webService.MapGetAndPost("/api/admin/users/list", _authApi.ListUsers);
            _webService.MapGetAndPost("/api/admin/users/create", _authApi.CreateUser);
            _webService.MapGetAndPost("/api/admin/users/get", _authApi.GetUserDetails);
            _webService.MapGetAndPost("/api/admin/users/set", _authApi.SetUserDetails);
            _webService.MapGetAndPost("/api/admin/users/delete", _authApi.DeleteUser);
            _webService.MapGetAndPost("/api/admin/groups/list", _authApi.ListGroups);
            _webService.MapGetAndPost("/api/admin/groups/create", _authApi.CreateGroup);
            _webService.MapGetAndPost("/api/admin/groups/get", _authApi.GetGroupDetails);
            _webService.MapGetAndPost("/api/admin/groups/set", _authApi.SetGroupDetails);
            _webService.MapGetAndPost("/api/admin/groups/delete", _authApi.DeleteGroup);
            _webService.MapGetAndPost("/api/admin/permissions/list", _authApi.ListPermissions);
            _webService.MapGetAndPost("/api/admin/permissions/get", delegate (HttpContext context) { _authApi.GetPermissionDetails(context, PermissionSection.Unknown); });
            _webService.MapGetAndPost("/api/admin/permissions/set", delegate (HttpContext context) { _authApi.SetPermissionsDetails(context, PermissionSection.Unknown); });
            _webService.MapGetAndPost("/api/admin/sso/get", _authApi.GetSsoConfig);
            _webService.MapGetAndPost("/api/admin/sso/set", _authApi.SetSsoConfig);
            _webService.MapGetAndPost("/api/admin/ldap/get", _authApi.GetLdapConfig);
            _webService.MapGetAndPost("/api/admin/ldap/set", _authApi.SetLdapConfig);
            _webService.MapGetAndPost("/api/admin/ldap/test", _authApi.TestLdapConnectionAsync);

            _webService.MapGetAndPost("/api/logs/list", _logsApi.ListLogs);
            _webService.MapGetAndPost("/api/logs/download", _logsApi.DownloadLogAsync);
            _webService.MapGetAndPost("/api/logs/delete", _logsApi.DeleteLog);
            _webService.MapGetAndPost("/api/logs/deleteAll", _logsApi.DeleteAllLogs);
            _webService.MapGetAndPost("/api/logs/query", _logsApi.QueryLogsAsync);
            _webService.MapGetAndPost("/api/logs/export", _logsApi.ExportLogsAsync);

            _webService.MapFallback("/api/{*path}", delegate (HttpContext context)
            {
                context.Items["apiFallback"] = string.Empty;
            });
        }

        private Task WebServiceHttpsRedirectionMiddleware(HttpContext context, RequestDelegate next)
        {
            if (context.Request.IsHttps || (context.Connection.RemoteIpAddress is null))
                return next(context);

            context.Response.Redirect("https://" + (context.Request.Host.HasValue ? context.Request.Host.Host : _dnsServer.ServerDomain) + (_webServiceTlsPort == 443 ? "" : ":" + _webServiceTlsPort) + context.Request.Path + (context.Request.QueryString.HasValue ? context.Request.QueryString.Value : ""), false, true);
            return Task.CompletedTask;
        }

        private async Task WebServiceApiMiddleware(HttpContext context, RequestDelegate next)
        {
            HttpRequest request = context.Request;

            bool needsJsonResponseObject;

            switch (request.Path)
            {
                case "/api/status":
                case "/api/sso/status":
                case "/api/user/login":
                case "/api/user/logout":
                    needsJsonResponseObject = false;
                    break;

                case "/api/user/session/get":
                    {
                        if (!TryValidateSession(context, out UserSession _))
                            throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                        needsJsonResponseObject = false;
                    }
                    break;

                case "/api/zones/export":
                case "/api/allowed/export":
                case "/api/blocked/export":
                case "/api/settings/backup":
                case "/api/logs/download":
                case "/api/logs/export":
                    {
                        if (!TryValidateSession(context, out UserSession _))
                            throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                        await next(context);
                    }
                    return;

                case "/api/dnsClient/healthCheck":
                    {
                        if (!TryValidateSession(context, out UserSession _))
                        {
                            IPAddress remoteAddress = GetRemoteEndPoint(context).Address;

                            if (!remoteAddress.Equals(IPAddress.Loopback) && !remoteAddress.Equals(IPAddress.IPv6Loopback))
                                throw new InvalidTokenWebServiceException("Invalid token or session expired.");
                        }

                        needsJsonResponseObject = false;
                    }
                    break;

                default:
                    if (request.Path.Value.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!TryValidateSession(context, out UserSession _))
                            throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                        needsJsonResponseObject = true;
                    }
                    else if (request.Path.Value.StartsWith("/sso/", StringComparison.OrdinalIgnoreCase))
                    {
                        await next(context);
                        return;
                    }
                    else
                    {
                        HttpResponse response = context.Response;
                        response.StatusCode = StatusCodes.Status404NotFound;
                        response.ContentLength = 0;
                        response.Headers.CacheControl = "no-cache, no-store, must-revalidate";
                        response.Headers.Pragma = "no-cache";
                        response.Headers.Expires = "0";
                        return;
                    }

                    break;
            }

            using (MemoryStream mS = new MemoryStream(4096))
            {
                Utf8JsonWriter jsonWriter = new Utf8JsonWriter(mS);
                context.Items["jsonWriter"] = jsonWriter;

                jsonWriter.WriteStartObject();

                if (needsJsonResponseObject)
                {
                    jsonWriter.WritePropertyName("response");
                    jsonWriter.WriteStartObject();

                    await next(context);

                    jsonWriter.WriteEndObject();
                }
                else
                {
                    await next(context);
                }

                jsonWriter.WriteString("server", _dnsServer.ServerDomain);
                jsonWriter.WriteString("status", "ok");

                jsonWriter.WriteEndObject();
                jsonWriter.Flush();

                mS.Position = 0;

                HttpResponse response = context.Response;

                response.Headers.CacheControl = "no-cache, no-store, must-revalidate";
                response.Headers.Pragma = "no-cache";
                response.Headers.Expires = "0";

                object apiFallback = context.Items["apiFallback"];
                if (apiFallback is null)
                {
                    response.StatusCode = StatusCodes.Status200OK;
                    response.ContentType = "application/json; charset=utf-8";
                    response.ContentLength = mS.Length;

                    await mS.CopyToAsync(response.Body);
                }
                else
                {
                    response.StatusCode = StatusCodes.Status404NotFound;
                    response.ContentLength = 0;
                }
            }
        }

        private void WebServiceExceptionHandler(IApplicationBuilder exceptionHandlerApp)
        {
            exceptionHandlerApp.Run(async delegate (HttpContext context)
            {
                IExceptionHandlerPathFeature exceptionHandlerPathFeature = context.Features.Get<IExceptionHandlerPathFeature>();
                if (exceptionHandlerPathFeature.Path.StartsWith("/api/", StringComparison.Ordinal))
                {
                    Exception ex = exceptionHandlerPathFeature.Error;

                    HttpResponse response = context.Response;

                    response.StatusCode = StatusCodes.Status200OK;
                    response.Headers.CacheControl = "no-cache, no-store, must-revalidate";
                    response.Headers.Pragma = "no-cache";
                    response.Headers.Expires = "0";
                    response.ContentType = "application/json; charset=utf-8";

                    await using (Utf8JsonWriter jsonWriter = new Utf8JsonWriter(response.Body))
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("server", _dnsServer.ServerDomain);

                        if (ex is TwoFactorAuthRequiredWebServiceException)
                        {
                            jsonWriter.WriteString("status", "2fa-required");
                            jsonWriter.WriteString("errorMessage", ex.Message);
                        }
                        else if (ex is InvalidTokenWebServiceException)
                        {
                            jsonWriter.WriteString("status", "invalid-token");
                            jsonWriter.WriteString("errorMessage", ex.Message);
                        }
                        else
                        {
                            _log.Write(GetRemoteEndPoint(context), ex);

                            jsonWriter.WriteString("status", "error");
                            jsonWriter.WriteString("errorMessage", ex.Message);

                            if (ex.InnerException is not null)
                                jsonWriter.WriteString("innerErrorMessage", ex.InnerException.Message);
                        }

                        jsonWriter.WriteEndObject();
                    }
                }
            });
        }

        private static string GetAuthorizationToken(HttpRequest request)
        {
            StringValues authorization = request.Headers.Authorization;
            string token = null;

            foreach (string entry in authorization)
            {
                if (entry.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    token = entry.Substring(7).Trim();
                    break;
                }
            }

            if (token is null)
                token = request.QueryOrForm("token");

            if (string.IsNullOrEmpty(token))
                return null;

            return token;
        }

        private bool TryValidateSession(HttpContext context, out UserSession session)
        {
            HttpRequest request = context.Request;

            session = _authManager.GetSession(GetAuthorizationToken(request));
            if ((session is null) || session.User.Disabled)
                return false;

            if (session.Type == UserSessionType.SingleUse)
            {
                _authManager.DeleteSession(session.Token);
            }
            else
            {
                if (session.HasExpired())
                {
                    _authManager.DeleteSession(session.Token);
                    _authManager.SaveConfigFile();
                    return false;
                }

                IPEndPoint remoteEP = GetRemoteEndPoint(context);

                session.UpdateLastSeen(remoteEP.Address, request.Headers.UserAgent);
            }

            context.Items["session"] = session;

            return true;
        }

        private User GetSessionUser(HttpContext context, bool standardOnly = false)
        {
            UserSession session = context.GetCurrentSession();

            if (standardOnly && (session.Type != UserSessionType.Standard))
                throw new DnsWebServiceException("Access was denied.");

            return session.User;
        }

        #endregion

        #region tls

        private void StartTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer is null)
            {
                _tlsCertificateUpdateTimer = new Timer(delegate (object state)
                {
                    if (!string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                    {
                        string webServiceTlsCertificatePath = ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                        try
                        {
                            string webServiceTlsCertificateKeyPath = ConvertToAbsolutePath(_webServiceTlsCertificateKeyPath);
                            DateTime lastModifiedOn = TlsCertificateFile.GetLastWriteTimeUtc(webServiceTlsCertificatePath, webServiceTlsCertificateKeyPath);

                            if ((lastModifiedOn != DateTime.MinValue) && (lastModifiedOn != _webServiceCertificateLastModifiedOn))
                                LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, _webServiceTlsCertificatePassword, webServiceTlsCertificateKeyPath);
                        }
                        catch (Exception ex)
                        {
                            _log.Write("DNS Server encountered an error while updating Web Service TLS Certificate: " + webServiceTlsCertificatePath, ex);
                        }
                    }
                }, null, TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL, TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL);
            }
        }

        private void StopTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer is not null)
            {
                _tlsCertificateUpdateTimer.Dispose();
                _tlsCertificateUpdateTimer = null;
            }
        }

        private void LoadWebServiceTlsCertificate(string tlsCertificatePath, string tlsCertificatePassword, string tlsCertificateKeyPath = null)
        {
            SslStreamCertificateContext certificateContext = TlsCertificateFile.Load(tlsCertificatePath, tlsCertificateKeyPath, tlsCertificatePassword, out _);

            List<SslApplicationProtocol> applicationProtocols = new List<SslApplicationProtocol>();

            if (_webServiceEnableHttp3)
                applicationProtocols.Add(new SslApplicationProtocol("h3"));

            if (IsHttp2Supported())
                applicationProtocols.Add(new SslApplicationProtocol("h2"));

            applicationProtocols.Add(new SslApplicationProtocol("http/1.1"));

            _webServiceSslServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = applicationProtocols,
                ServerCertificateContext = certificateContext
            };

            _webServiceCertificateLastModifiedOn = TlsCertificateFile.GetLastWriteTimeUtc(tlsCertificatePath, tlsCertificateKeyPath);

            _log.Write("Web Service TLS certificate was loaded: " + tlsCertificatePath);
        }

        private void RemoveWebServiceTlsCertificate()
        {
            _webServiceSslServerAuthenticationOptions = null;

            _webServiceTlsCertificatePath = null;
            _webServiceTlsCertificatePassword = null;
            _webServiceTlsCertificateKeyPath = null;

            StopTlsCertificateUpdateTimer();
        }

        public void SetWebServiceTlsCertificate(string webServiceTlsCertificatePath, string webServiceTlsCertificatePassword, string webServiceTlsCertificateKeyPath = null)
        {
            if (string.IsNullOrWhiteSpace(webServiceTlsCertificatePath))
                throw new ArgumentException("Web service TLS certificate path cannot be null or empty.", nameof(webServiceTlsCertificatePath));

            if (webServiceTlsCertificatePath.Length > 255)
                throw new ArgumentException("Web service TLS certificate path length cannot exceed 255 characters.", nameof(webServiceTlsCertificatePath));

            if (webServiceTlsCertificatePassword?.Length > 255)
                throw new ArgumentException("Web service TLS certificate password length cannot exceed 255 characters.", nameof(webServiceTlsCertificatePassword));

            if (webServiceTlsCertificateKeyPath?.Length > 255)
                throw new ArgumentException("Web service TLS private key path length cannot exceed 255 characters.", nameof(webServiceTlsCertificateKeyPath));

            if (string.IsNullOrEmpty(webServiceTlsCertificateKeyPath))
                webServiceTlsCertificateKeyPath = null;

            webServiceTlsCertificatePath = ConvertToAbsolutePath(webServiceTlsCertificatePath);
            string webServiceTlsCertificateKeyAbsolutePath = ConvertToAbsolutePath(webServiceTlsCertificateKeyPath);

            LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, webServiceTlsCertificatePassword, webServiceTlsCertificateKeyAbsolutePath);

            _webServiceTlsCertificatePath = ConvertToRelativePath(webServiceTlsCertificatePath);
            _webServiceTlsCertificatePassword = webServiceTlsCertificatePassword;
            _webServiceTlsCertificateKeyPath = webServiceTlsCertificateKeyAbsolutePath is null ? null : ConvertToRelativePath(webServiceTlsCertificateKeyAbsolutePath);

            StartTlsCertificateUpdateTimer();
        }

        private void CheckAndLoadSelfSignedCertificate(bool forceGenerateNew, bool throwException)
        {
            string selfSignedCertificateFilePath = Path.Combine(_configFolder, "self-signed-cert.pfx");

            if (_webServiceUseSelfSignedTlsCertificate)
            {
                string oldSelfSignedCertificateFilePath = Path.Combine(_configFolder, "cert.pfx");

                if (!oldSelfSignedCertificateFilePath.Equals(ConvertToAbsolutePath(_webServiceTlsCertificatePath), Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) && File.Exists(oldSelfSignedCertificateFilePath) && !File.Exists(selfSignedCertificateFilePath))
                    File.Move(oldSelfSignedCertificateFilePath, selfSignedCertificateFilePath);

                if (forceGenerateNew || !File.Exists(selfSignedCertificateFilePath))
                {
                    RSA rsa = RSA.Create(2048);
                    CertificateRequest req = new CertificateRequest("cn=" + _dnsServer.ServerDomain, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                    SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
                    bool sanAdded = false;

                    foreach (IPAddress localAddress in _webServiceLocalAddresses)
                    {
                        if (localAddress.Equals(IPAddress.IPv6Any) || localAddress.Equals(IPAddress.Any))
                            continue;

                        san.AddIpAddress(localAddress);
                        sanAdded = true;
                    }

                    if (sanAdded)
                        req.CertificateExtensions.Add(san.Build());

                    X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(5));

                    File.WriteAllBytes(selfSignedCertificateFilePath, cert.Export(X509ContentType.Pkcs12, null as string));
                }

                if ((_webServiceSslServerAuthenticationOptions is null) || string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                {
                    try
                    {
                        LoadWebServiceTlsCertificate(selfSignedCertificateFilePath, null);

                        if (!forceGenerateNew)
                        {
                            if (_webServiceSslServerAuthenticationOptions.ServerCertificateContext.TargetCertificate.NotAfter < DateTime.UtcNow.AddYears(1))
                            {
                                _log.Write("Web Service TLS self signed certificate is nearing expiration and will be regenerated.");
                                CheckAndLoadSelfSignedCertificate(true, throwException);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading self signed Web Service TLS certificate: " + selfSignedCertificateFilePath, ex);

                        if (throwException)
                            throw;
                    }
                }
            }
            else
            {
                File.Delete(selfSignedCertificateFilePath);
            }
        }

        #endregion

        #region public

        public async Task StartAsync(bool throwIfBindFails = false)
        {
            if (_disposed)
                ObjectDisposedException.ThrowIf(_disposed, this);

            if (_isRunning)
                throw new DnsWebServiceException("The DNS web service is already running.");

            try
            {
                _dnsServer = new DnsServer(_configFolder, Path.Combine(_appFolder, "dohwww"), _log);

                LoadConfigFile();

                _dnsServer.LoadConfigFile();

                await _dnsServer.DnsApplicationManager.LoadAllApplicationsAsync();

                _dnsServer.AuthZoneManager.LoadAllZoneFiles();
                InspectAndFixZonePermissions();

                if (_configDisabledZones != null)
                {
                    foreach (string domain in _configDisabledZones)
                    {
                        AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
                        if (zoneInfo is not null)
                        {
                            zoneInfo.Disabled = true;
                            _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                        }
                    }
                }

                _dnsServer.AllowedZoneManager.LoadAllowedZoneFile();
                _dnsServer.BlockedZoneManager.LoadBlockedZoneFile();
                _dnsServer.BlockListZoneManager.LoadConfigFile();

                if (throwIfBindFails)
                    await StartWebServiceAsync(false);
                else
                    await TryStartWebServiceAsync([IPAddress.Any, IPAddress.IPv6Any], 5380, 53443);

                await _dnsServer.StartAsync(throwIfBindFails);

                _log.Write("DNS Server (v" + _currentVersion.ToString() + ") was started successfully.");
                _isRunning = true;
            }
            catch (Exception ex)
            {
                _log.Write("Failed to start DNS Server (v" + _currentVersion.ToString() + ").", ex);
                throw;
            }
        }

        public async Task StopAsync()
        {
            if (!_isRunning || _disposed)
                return;

            try
            {
                await StopWebServiceAsync();

                if (_dnsServer is not null)
                    await _dnsServer.DisposeAsync();

                _log.Write("DNS Server (v" + _currentVersion.ToString() + ") was stopped successfully.");
                _isRunning = false;
            }
            catch (Exception ex)
            {
                _log.Write("Failed to stop DNS Server (v" + _currentVersion.ToString() + ").", ex);
                throw;
            }
        }

        #endregion

        #region properties

        public DnsServer DnsServer
        { get { return _dnsServer; } }

        public string ConfigFolder
        { get { return _configFolder; } }

        public int WebServiceHttpPort
        { get { return _webServiceHttpPort; } }

        #endregion
    }
}
