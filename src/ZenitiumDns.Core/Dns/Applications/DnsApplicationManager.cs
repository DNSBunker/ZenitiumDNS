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
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumLibrary;
using ZenitiumLibrary.IO;

namespace ZenitiumDns.Core.Dns.Applications
{
    public sealed class DnsApplicationManager : IDisposable
    {
        #region variables

        readonly static string BUNDLED_APPS_PATH = Environment.GetEnvironmentVariable("DNS_SERVER_BUNDLED_APPS_PATH") is string bundledAppsPath && (bundledAppsPath.Length > 0) ? bundledAppsPath : "/usr/share/zenitiumdns/apps";
        const string BUNDLED_APPS_STATE_FILE = "bundled.lst";
        const string DISABLED_MARKER_FILE = "dnsApp.disabled";

        readonly DnsServer _dnsServer;

        readonly string _appsPath;

        readonly ConcurrentDictionary<string, DnsApplication> _applications = new ConcurrentDictionary<string, DnsApplication>();
        readonly ConcurrentDictionary<string, string> _loadErrors = new ConcurrentDictionary<string, string>();

        IReadOnlyList<IDnsRequestController> _dnsRequestControllers = [];
        IReadOnlyList<IDnsAuthoritativeRequestHandler> _dnsAuthoritativeRequestHandlers = [];
        IReadOnlyList<IDnsRequestBlockingHandler> _dnsRequestBlockingHandlers = [];
        IReadOnlyList<IDnsQueryLogger> _dnsQueryLoggers = [];
        IReadOnlyList<IDnsPostProcessor> _dnsPostProcessors = [];

        SemaphoreSlim _opsLock = new SemaphoreSlim(1, 1);

        #endregion

        #region constructor

        public DnsApplicationManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _appsPath = Path.Combine(_dnsServer.ConfigFolder, "apps");

            if (!Directory.Exists(_appsPath))
                Directory.CreateDirectory(_appsPath);
        }

        #endregion

        #region IDisposable

        bool _disposed;

        private void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                if (_applications != null)
                    UnloadAllApplicationsAsync().Sync();

                if (_opsLock is not null)
                {
                    _opsLock.Dispose();
                    _opsLock = null;
                }
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region private

        private async Task<DnsApplication> LoadApplicationAsync(string applicationFolder, bool refreshAppObjectList)
        {
            string applicationName = Path.GetFileName(applicationFolder);
            bool enabled = !File.Exists(Path.Combine(applicationFolder, DISABLED_MARKER_FILE));

            DnsApplication application = new DnsApplication(new InternalDnsServer(_dnsServer, applicationName, applicationFolder), applicationName, enabled);

            await application.InitializeAsync();

            if (!_applications.TryAdd(application.Name, application))
            {
                application.Dispose();
                throw new DnsServerException("DNS application already exists: " + application.Name);
            }

            application.ConfigUpdated += Application_ConfigUpdated;

            if (refreshAppObjectList)
                RefreshAppObjectLists();

            return application;
        }

        private void UnloadApplication(string applicationName)
        {
            if (!_applications.TryRemove(applicationName, out DnsApplication removedApp))
                throw new DnsServerException("DNS application does not exists: " + applicationName);

            RefreshAppObjectLists();

            removedApp.ConfigUpdated -= Application_ConfigUpdated;
            removedApp.Dispose();
        }

        private void Application_ConfigUpdated(object sender, EventArgs e)
        {
            RefreshAppObjectLists();
        }

        private void RefreshAppObjectLists()
        {
            List<IDnsRequestController> dnsRequestControllers = new List<IDnsRequestController>(1);
            List<IDnsAuthoritativeRequestHandler> dnsAuthoritativeRequestHandlers = new List<IDnsAuthoritativeRequestHandler>(1);
            List<IDnsRequestBlockingHandler> dnsRequestBlockingHandlers = new List<IDnsRequestBlockingHandler>(1);
            List<IDnsQueryLogger> dnsQueryLoggers = new List<IDnsQueryLogger>(1);
            List<IDnsPostProcessor> dnsPostProcessors = new List<IDnsPostProcessor>(1);

            foreach (KeyValuePair<string, DnsApplication> application in _applications)
            {
                if (!application.Value.Enabled)
                    continue;

                foreach (KeyValuePair<string, IDnsRequestController> controller in application.Value.DnsRequestControllers)
                    dnsRequestControllers.Add(controller.Value);

                foreach (KeyValuePair<string, IDnsAuthoritativeRequestHandler> handler in application.Value.DnsAuthoritativeRequestHandlers)
                    dnsAuthoritativeRequestHandlers.Add(handler.Value);

                foreach (KeyValuePair<string, IDnsRequestBlockingHandler> blocker in application.Value.DnsRequestBlockingHandler)
                    dnsRequestBlockingHandlers.Add(blocker.Value);

                foreach (KeyValuePair<string, IDnsQueryLogger> logger in application.Value.DnsQueryLoggers)
                    dnsQueryLoggers.Add(logger.Value);

                foreach (KeyValuePair<string, IDnsPostProcessor> processor in application.Value.DnsPostProcessors)
                    dnsPostProcessors.Add(processor.Value);
            }

            dnsRequestControllers.Sort(CompareApps);
            dnsAuthoritativeRequestHandlers.Sort(CompareApps);
            dnsRequestBlockingHandlers.Sort(CompareApps);
            dnsQueryLoggers.Sort(CompareApps);
            dnsPostProcessors.Sort(CompareApps);

            _dnsRequestControllers = dnsRequestControllers;
            _dnsAuthoritativeRequestHandlers = dnsAuthoritativeRequestHandlers;
            _dnsRequestBlockingHandlers = dnsRequestBlockingHandlers;
            _dnsQueryLoggers = dnsQueryLoggers;
            _dnsPostProcessors = dnsPostProcessors;
        }

        private static async Task ExtractApplicationAsync(ZipArchive appZip, string applicationFolder)
        {
            foreach (ZipArchiveEntry entry in appZip.Entries)
            {
                string filePath = Path.GetFullPath(Path.Combine(applicationFolder, entry.FullName));
                if (!filePath.StartsWith(applicationFolder + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                    throw new IOException("Extracting Zip entry would have resulted in a file outside the specified destination directory.");

                if ((entry.Name == "dnsApp.config") && File.Exists(filePath))
                    continue;

                if ((entry.Length == 0) && (entry.Name.Length == 0) && entry.FullName.EndsWith('/'))
                {
                    Directory.CreateDirectory(filePath);
                }
                else
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                    await entry.ExtractToFileAsync(filePath, true);
                }
            }
        }

        private string GetApplicationFolder(string applicationName)
        {
            foreach (char invalidChar in Path.GetInvalidFileNameChars())
            {
                if (applicationName.Contains(invalidChar))
                    throw new DnsServerException("The application name contains an invalid character: " + invalidChar);
            }

            string applicationFolder = Path.GetFullPath(Path.Combine(_appsPath, applicationName));
            if (!applicationFolder.StartsWith(_appsPath + Path.DirectorySeparatorChar, StringComparison.Ordinal))
                throw new DnsServerException("The application name is invalid: " + applicationName);

            return applicationFolder;
        }

        private async Task ProvisionBundledApplicationsAsync()
        {
            if (!Directory.Exists(BUNDLED_APPS_PATH))
                return;

            string stateFile = Path.Combine(_appsPath, BUNDLED_APPS_STATE_FILE);
            Dictionary<string, string> state = new Dictionary<string, string>(StringComparer.Ordinal);

            if (File.Exists(stateFile))
            {
                foreach (string line in await File.ReadAllLinesAsync(stateFile))
                {
                    string[] parts = line.Split(' ', 2, StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    if (parts.Length == 2)
                        state[parts[0]] = parts[1];
                }
            }

            bool stateChanged = false;

            foreach (string zipFile in Directory.GetFiles(BUNDLED_APPS_PATH, "*.zip"))
            {
                string applicationName = Path.GetFileNameWithoutExtension(zipFile);

                try
                {
                    string applicationFolder = GetApplicationFolder(applicationName);
                    string hash;

                    await using (FileStream fS = new FileStream(zipFile, FileMode.Open, FileAccess.Read))
                    {
                        hash = Convert.ToHexString(await SHA256.HashDataAsync(fS));

                        if (Directory.Exists(applicationFolder))
                        {
                            if (state.TryGetValue(applicationName, out string knownHash) && knownHash.Equals(hash, StringComparison.OrdinalIgnoreCase))
                                continue;

                            fS.Position = 0;

                            await using (ZipArchive appZip = new ZipArchive(fS, ZipArchiveMode.Read, true, Encoding.UTF8))
                            {
                                await ExtractApplicationAsync(appZip, applicationFolder);
                            }

                            _dnsServer.LogManager.Write("DNS Server updated the bundled DNS application: " + applicationName);
                        }
                        else
                        {
                            Directory.CreateDirectory(applicationFolder);

                            try
                            {
                                await File.WriteAllBytesAsync(Path.Combine(applicationFolder, DISABLED_MARKER_FILE), []);

                                fS.Position = 0;

                                await using (ZipArchive appZip = new ZipArchive(fS, ZipArchiveMode.Read, true, Encoding.UTF8))
                                {
                                    await ExtractApplicationAsync(appZip, applicationFolder);
                                }
                            }
                            catch
                            {
                                Directory.Delete(applicationFolder, true);
                                throw;
                            }

                            _dnsServer.LogManager.Write("DNS Server installed the bundled DNS application in disabled state: " + applicationName);
                        }
                    }

                    state[applicationName] = hash;
                    stateChanged = true;
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write("DNS Server failed to provision the bundled DNS application: " + applicationName, ex);
                }
            }

            if (stateChanged)
            {
                List<string> lines = new List<string>(state.Count);

                foreach (KeyValuePair<string, string> entry in state)
                    lines.Add(entry.Key + " " + entry.Value);

                string tmpStateFile = stateFile + ".tmp";
                await File.WriteAllLinesAsync(tmpStateFile, lines);
                File.Move(tmpStateFile, stateFile, true);
            }
        }

        private static int CompareApps<T>(T x, T y)
        {
            int xp;
            int yp;

            if (x is IDnsApplicationPreference xpref)
                xp = xpref.Preference;
            else
                xp = 100;

            if (y is IDnsApplicationPreference ypref)
                yp = ypref.Preference;
            else
                yp = 100;

            return xp.CompareTo(yp);
        }

        #endregion

        #region public

        public async Task UnloadAllApplicationsAsync()
        {
            await _opsLock.WaitAsync();
            try
            {
                foreach (KeyValuePair<string, DnsApplication> application in _applications)
                {
                    try
                    {
                        application.Value.Dispose();
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                }

                _applications.Clear();
                _dnsRequestControllers = Array.Empty<IDnsRequestController>();
                _dnsAuthoritativeRequestHandlers = Array.Empty<IDnsAuthoritativeRequestHandler>();
                _dnsRequestBlockingHandlers = Array.Empty<IDnsRequestBlockingHandler>();
                _dnsQueryLoggers = Array.Empty<IDnsQueryLogger>();
                _dnsPostProcessors = Array.Empty<IDnsPostProcessor>();
            }
            finally
            {
                _opsLock.Release();
            }
        }

        public async Task LoadAllApplicationsAsync()
        {
            await UnloadAllApplicationsAsync();

            _loadErrors.Clear();

            await _opsLock.WaitAsync();
            try
            {
                try
                {
                    await ProvisionBundledApplicationsAsync();
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }

                List<Task> tasks = new List<Task>();

                foreach (string applicationFolder in Directory.GetDirectories(_appsPath))
                {
                    tasks.Add(Task.Run(async delegate ()
                    {
                        try
                        {
                            _dnsServer.LogManager.Write("DNS Server is loading DNS application: " + Path.GetFileName(applicationFolder));

                            _ = await LoadApplicationAsync(applicationFolder, false);

                            _dnsServer.LogManager.Write("DNS Server successfully loaded DNS application: " + Path.GetFileName(applicationFolder));
                        }
                        catch (Exception ex)
                        {
                            _loadErrors[Path.GetFileName(applicationFolder)] = ex.Message;
                            _dnsServer.LogManager.Write("DNS Server failed to load DNS application: " + Path.GetFileName(applicationFolder), ex);
                        }
                    }));
                }

                await Task.WhenAll(tasks);

                RefreshAppObjectLists();
            }
            finally
            {
                _opsLock.Release();
            }
        }

        public async Task<DnsApplication> SetApplicationEnabledAsync(string applicationName, bool enabled)
        {
            await _opsLock.WaitAsync();
            try
            {
                if (!_applications.TryGetValue(applicationName, out DnsApplication application))
                    throw new DnsServerException("DNS application does not exists: " + applicationName);

                if (application.Enabled == enabled)
                    return application;

                string applicationFolder = application.DnsServer.ApplicationFolder;
                string markerFile = Path.Combine(applicationFolder, DISABLED_MARKER_FILE);

                UnloadApplication(applicationName);

                if (enabled)
                    File.Delete(markerFile);
                else
                    await File.WriteAllBytesAsync(markerFile, []);

                return await LoadApplicationAsync(applicationFolder, true);
            }
            finally
            {
                _opsLock.Release();
            }
        }

        #endregion

        #region properties

        public IReadOnlyDictionary<string, DnsApplication> Applications
        { get { return _applications; } }

        public IReadOnlyDictionary<string, string> LoadErrors
        { get { return _loadErrors; } }

        public IReadOnlyList<IDnsRequestController> DnsRequestControllers
        { get { return _dnsRequestControllers; } }

        public IReadOnlyList<IDnsAuthoritativeRequestHandler> DnsAuthoritativeRequestHandlers
        { get { return _dnsAuthoritativeRequestHandlers; } }

        public IReadOnlyList<IDnsRequestBlockingHandler> DnsRequestBlockingHandlers
        { get { return _dnsRequestBlockingHandlers; } }

        public IReadOnlyList<IDnsQueryLogger> DnsQueryLoggers
        { get { return _dnsQueryLoggers; } }

        public IReadOnlyList<IDnsPostProcessor> DnsPostProcessors
        { get { return _dnsPostProcessors; } }

        #endregion
    }
}
