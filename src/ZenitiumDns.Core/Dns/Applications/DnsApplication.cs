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
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Threading.Tasks;

namespace ZenitiumDns.Core.Dns.Applications
{
    public sealed class DnsApplication : IDisposable
    {
        #region events

        public event EventHandler ConfigUpdated;

        #endregion

        #region variables

        readonly static Type _dnsApplicationInterface = typeof(IDnsApplication);

        readonly IDnsServer _dnsServer;
        readonly string _name;
        readonly bool _enabled;
        string _initializationError;

        readonly DnsApplicationAssemblyLoadContext _appContext;

        readonly string _description;
        readonly string _descriptionEnglish;
        readonly Version _version;
        readonly IReadOnlyDictionary<string, IDnsApplication> _dnsApplications;
        readonly IReadOnlyDictionary<string, IDnsAppRecordRequestHandler> _dnsAppRecordRequestHandlers;
        readonly IReadOnlyDictionary<string, IDnsRequestController> _dnsRequestControllers;
        readonly IReadOnlyDictionary<string, IDnsAuthoritativeRequestHandler> _dnsAuthoritativeRequestHandlers;
        readonly IReadOnlyDictionary<string, IDnsRequestBlockingHandler> _dnsRequestBlockingHandlers;
        readonly IReadOnlyDictionary<string, IDnsQueryLogger> _dnsQueryLoggers;
        readonly IReadOnlyDictionary<string, IDnsQueryLogs> _dnsQueryLogs;
        readonly IReadOnlyDictionary<string, IDnsPostProcessor> _dnsPostProcessors;

        #endregion

        #region constructor

        public DnsApplication(IDnsServer dnsServer, string name, bool enabled = true)
        {
            _dnsServer = dnsServer;
            _name = name;
            _enabled = enabled;

            _appContext = new DnsApplicationAssemblyLoadContext(_dnsServer);

            Dictionary<string, IDnsApplication> dnsApplications = new Dictionary<string, IDnsApplication>();
            Dictionary<string, IDnsAppRecordRequestHandler> dnsAppRecordRequestHandlers = new Dictionary<string, IDnsAppRecordRequestHandler>(2);
            Dictionary<string, IDnsRequestController> dnsRequestControllers = new Dictionary<string, IDnsRequestController>(1);
            Dictionary<string, IDnsAuthoritativeRequestHandler> dnsAuthoritativeRequestHandlers = new Dictionary<string, IDnsAuthoritativeRequestHandler>(1);
            Dictionary<string, IDnsRequestBlockingHandler> dnsRequestBlockingHandlers = new Dictionary<string, IDnsRequestBlockingHandler>(1);
            Dictionary<string, IDnsQueryLogger> dnsQueryLoggers = new Dictionary<string, IDnsQueryLogger>(1);
            Dictionary<string, IDnsQueryLogs> dnsQueryLogs = new Dictionary<string, IDnsQueryLogs>(1);
            Dictionary<string, IDnsPostProcessor> dnsPostProcessors = new Dictionary<string, IDnsPostProcessor>(1);

            foreach (Assembly appAssembly in _appContext.AppAssemblies)
            {
                try
                {
                    foreach (Type classType in appAssembly.ExportedTypes)
                    {
                        bool isDnsApp = false;

                        foreach (Type interfaceType in classType.GetInterfaces())
                        {
                            if (interfaceType == _dnsApplicationInterface)
                            {
                                isDnsApp = true;
                                break;
                            }
                        }

                        if (isDnsApp)
                        {
                            try
                            {
                                IDnsApplication app = Activator.CreateInstance(classType) as IDnsApplication;

                                dnsApplications.Add(classType.FullName, app);

                                if (app is IDnsAppRecordRequestHandler appRecordHandler)
                                    dnsAppRecordRequestHandlers.Add(classType.FullName, appRecordHandler);

                                if (app is IDnsRequestController requestController)
                                    dnsRequestControllers.Add(classType.FullName, requestController);

                                if (app is IDnsAuthoritativeRequestHandler requestHandler)
                                    dnsAuthoritativeRequestHandlers.Add(classType.FullName, requestHandler);

                                if (app is IDnsRequestBlockingHandler blockingHandler)
                                    dnsRequestBlockingHandlers.Add(classType.FullName, blockingHandler);

                                if (app is IDnsQueryLogger logger)
                                    dnsQueryLoggers.Add(classType.FullName, logger);

                                if (app is IDnsQueryLogs queryLogs)
                                    dnsQueryLogs.Add(classType.FullName, queryLogs);

                                if (app is IDnsPostProcessor postProcessor)
                                    dnsPostProcessors.Add(classType.FullName, postProcessor);

                                if (_description is null)
                                {
                                    AssemblyDescriptionAttribute attribute = appAssembly.GetCustomAttribute<AssemblyDescriptionAttribute>();
                                    if (attribute is not null)
                                        _description = attribute.Description.Replace("\\n", "\n");

                                    foreach (AssemblyMetadataAttribute metadata in appAssembly.GetCustomAttributes<AssemblyMetadataAttribute>())
                                    {
                                        if ((metadata.Key == "DescriptionEn") && (metadata.Value is not null))
                                            _descriptionEnglish = metadata.Value.Replace("\\n", "\n");
                                    }
                                }

                                if (_version is null)
                                    _version = appAssembly.GetName().Version;
                            }
                            catch (Exception ex)
                            {
                                _dnsServer.WriteLog(ex);
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.WriteLog(ex);
                }
            }

            if (_version is null)
            {
                if (dnsApplications.Count > 0)
                    _version = new Version(1, 0);
                else
                    _version = new Version(0, 0);
            }

            _dnsApplications = dnsApplications;

            if (_enabled)
            {
                _dnsAppRecordRequestHandlers = dnsAppRecordRequestHandlers;
                _dnsRequestControllers = dnsRequestControllers;
                _dnsAuthoritativeRequestHandlers = dnsAuthoritativeRequestHandlers;
                _dnsRequestBlockingHandlers = dnsRequestBlockingHandlers;
                _dnsQueryLoggers = dnsQueryLoggers;
                _dnsQueryLogs = dnsQueryLogs;
                _dnsPostProcessors = dnsPostProcessors;
            }
            else
            {
                _dnsAppRecordRequestHandlers = new Dictionary<string, IDnsAppRecordRequestHandler>();
                _dnsRequestControllers = new Dictionary<string, IDnsRequestController>();
                _dnsAuthoritativeRequestHandlers = new Dictionary<string, IDnsAuthoritativeRequestHandler>();
                _dnsRequestBlockingHandlers = new Dictionary<string, IDnsRequestBlockingHandler>();
                _dnsQueryLoggers = new Dictionary<string, IDnsQueryLogger>();
                _dnsQueryLogs = new Dictionary<string, IDnsQueryLogs>();
                _dnsPostProcessors = new Dictionary<string, IDnsPostProcessor>();
            }
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
                if (_dnsApplications is not null)
                {
                    foreach (KeyValuePair<string, IDnsApplication> app in _dnsApplications)
                        app.Value.Dispose();
                }

                if (_appContext != null)
                    _appContext.Unload();
            }

            _disposed = true;
        }

        public void Dispose()
        {
            Dispose(true);
        }

        #endregion

        #region internal

        internal async Task InitializeAsync()
        {
            if (!_enabled)
                return;

            string config = await GetConfigAsync();

            foreach (KeyValuePair<string, IDnsApplication> app in _dnsApplications)
            {
                try
                {
                    await app.Value.InitializeAsync(_dnsServer, config);
                }
                catch (Exception ex)
                {
                    _initializationError = ex.Message;
                    _dnsServer.WriteLog(ex);
                }
            }
        }

        #endregion

        #region public

        public Task<string> GetConfigAsync()
        {
            string configFile = Path.Combine(_dnsServer.ApplicationFolder, "dnsApp.config");

            if (File.Exists(configFile))
                return File.ReadAllTextAsync(configFile);

            return Task.FromResult<string>(null);
        }

        public async Task SetConfigAsync(string config)
        {
            string configFile = Path.Combine(_dnsServer.ApplicationFolder, "dnsApp.config");

            if (_enabled)
            {
                foreach (KeyValuePair<string, IDnsApplication> app in _dnsApplications)
                    await app.Value.InitializeAsync(_dnsServer, config);

                _initializationError = null;
            }

            if (string.IsNullOrEmpty(config))
            {
                File.Delete(configFile);
            }
            else
            {
                string tmpConfigFile = Path.Combine(_dnsServer.ApplicationFolder, "dnsApp.tmp");

                await File.WriteAllTextAsync(tmpConfigFile, config);

                File.Move(tmpConfigFile, configFile, true);
            }

            ConfigUpdated?.Invoke(this, EventArgs.Empty);
        }

        #endregion

        #region properties

        public IDnsServer DnsServer
        { get { return _dnsServer; } }

        public string Name
        { get { return _name; } }

        public string Description
        { get { return Lang.T(_description, _descriptionEnglish ?? _description); } }

        public Version Version
        { get { return _version; } }

        public bool Enabled
        { get { return _enabled; } }

        public string InitializationError
        { get { return _initializationError; } }

        public IReadOnlyDictionary<string, IDnsApplication> DnsApplications
        { get { return _dnsApplications; } }

        public IReadOnlyDictionary<string, IDnsAppRecordRequestHandler> DnsAppRecordRequestHandlers
        { get { return _dnsAppRecordRequestHandlers; } }

        public IReadOnlyDictionary<string, IDnsRequestController> DnsRequestControllers
        { get { return _dnsRequestControllers; } }

        public IReadOnlyDictionary<string, IDnsAuthoritativeRequestHandler> DnsAuthoritativeRequestHandlers
        { get { return _dnsAuthoritativeRequestHandlers; } }

        public IReadOnlyDictionary<string, IDnsRequestBlockingHandler> DnsRequestBlockingHandler
        { get { return _dnsRequestBlockingHandlers; } }

        public IReadOnlyDictionary<string, IDnsQueryLogger> DnsQueryLoggers
        { get { return _dnsQueryLoggers; } }

        public IReadOnlyDictionary<string, IDnsQueryLogs> DnsQueryLogs
        { get { return _dnsQueryLogs; } }

        public IReadOnlyDictionary<string, IDnsPostProcessor> DnsPostProcessors
        { get { return _dnsPostProcessors; } }

        #endregion
    }
}
