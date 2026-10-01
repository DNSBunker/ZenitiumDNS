/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)
Copyright (C) 2025  Zafer Balkan (zafer@zaferbalkan.com)
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
using LogExporter.Strategy;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumLibrary;
using ZenitiumLibrary.Net.Dns;

namespace LogExporter
{
    public sealed class App : IDnsApplication, IDnsQueryLogger
    {
        #region variables

        IDnsServer? _dnsServer;
        AppConfig? _config;

        readonly ExportManager _exportManager = new ExportManager();

        bool _enableLogging;

        readonly ConcurrentQueue<LogEntry> _queuedLogs = new ConcurrentQueue<LogEntry>();
        readonly Timer _queueTimer;
        const int QUEUE_TIMER_INTERVAL = 10000;
        const int BULK_INSERT_COUNT = 1000;
        const int DEFAULT_MAX_QUEUE_SIZE = 1000000;

        bool _disposed;

        #endregion

        #region constructor

        public App()
        {
            _queueTimer = new Timer(HandleExportLogCallback);
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        private void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _queueTimer?.Dispose();

                    ExportLogsAsync().Sync();

                    _exportManager.Dispose();
                }

                _disposed = true;
            }
        }

        #endregion

        #region public

        public Task InitializeAsync(IDnsServer dnsServer, string? config)
        {
            _dnsServer = dnsServer;

            if (config is null)
                throw new InvalidOperationException();

            _config = AppConfig.Deserialize(config);

            if (_config is null)
                throw new DnsClientException(Lang.T("Ungültige App-Konfiguration.", "Invalid app configuration."));

            if (_config.MaxQueueSize <= 0)
                _config.MaxQueueSize = DEFAULT_MAX_QUEUE_SIZE;

            _exportManager.RemoveStrategy(typeof(FileExportStrategy));

            if ((_config.FileTarget is not null) && _config.FileTarget.Enabled)
            {
                if (string.IsNullOrWhiteSpace(_config.FileTarget.Path))
                    throw new DnsClientException(Lang.T("Für den Dateiexport fehlt der Pfad (file.path).", "The file export has no path (file.path)."));

                string path = _config.FileTarget.Path;
                if (!Path.IsPathRooted(path))
                    path = Path.Combine(_dnsServer.ApplicationFolder, path);

                _exportManager.AddStrategy(new FileExportStrategy(Path.GetFullPath(path)));
            }

            _exportManager.RemoveStrategy(typeof(HttpExportStrategy));

            if ((_config.HttpTarget is not null) && _config.HttpTarget.Enabled)
            {
                if (!Uri.TryCreate(_config.HttpTarget.Endpoint, UriKind.Absolute, out Uri? endpoint) || ((endpoint.Scheme != Uri.UriSchemeHttp) && (endpoint.Scheme != Uri.UriSchemeHttps)))
                    throw new DnsClientException(Lang.T("Der HTTP-Export braucht eine absolute http- oder https-Adresse (http.endpoint).", "The HTTP export needs an absolute http or https address (http.endpoint)."));

                _exportManager.AddStrategy(new HttpExportStrategy(_dnsServer, endpoint.AbsoluteUri, _config.HttpTarget.Headers));
            }

            _exportManager.RemoveStrategy(typeof(SyslogExportStrategy));

            if ((_config.SyslogTarget is not null) && _config.SyslogTarget.Enabled)
            {
                bool local = string.Equals(_config.SyslogTarget.Protocol, "local", StringComparison.OrdinalIgnoreCase);

                if (!local && string.IsNullOrWhiteSpace(_config.SyslogTarget.Address))
                    throw new DnsClientException(Lang.T("Für den Syslog-Export fehlt die Adresse (syslog.address).", "The syslog export has no address (syslog.address)."));

                if ((_config.SyslogTarget.Port is not null) && ((_config.SyslogTarget.Port < 1) || (_config.SyslogTarget.Port > 65535)))
                    throw new DnsClientException(Lang.T("Der Syslog-Port muss zwischen 1 und 65535 liegen.", "The syslog port must be between 1 and 65535."));

                _exportManager.AddStrategy(new SyslogExportStrategy(_config.SyslogTarget.Address ?? "", _config.SyslogTarget.Port, _config.SyslogTarget.Protocol));
            }

            _enableLogging = _exportManager.HasStrategy();

            if (_enableLogging)
                _queueTimer.Change(QUEUE_TIMER_INTERVAL, Timeout.Infinite);
            else
                _queueTimer.Change(Timeout.Infinite, Timeout.Infinite);

            return Task.CompletedTask;
        }

        public Task InsertLogAsync(DateTime timestamp, DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, DnsDatagram response)
        {
            if (_enableLogging)
            {
                if (_queuedLogs.Count < _config!.MaxQueueSize)
                    _queuedLogs.Enqueue(new LogEntry(timestamp, remoteEP, protocol, request, response, _config.EnableEdnsLogging));
            }

            return Task.CompletedTask;
        }

        #endregion

        #region private

        private async Task ExportLogsAsync()
        {
            try
            {
                List<LogEntry> logs = new List<LogEntry>(BULK_INSERT_COUNT);

                while (true)
                {
                    while (logs.Count < BULK_INSERT_COUNT && _queuedLogs.TryDequeue(out LogEntry? log))
                    {
                        logs.Add(log);
                    }

                    if (logs.Count < 1)
                        break;

                    await _exportManager.ImplementStrategyAsync(logs);

                    logs.Clear();
                }
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
        }

        private async void HandleExportLogCallback(object? state)
        {
            try
            {
                await ExportLogsAsync();
            }
            catch (Exception ex)
            {
                _dnsServer?.WriteLog(ex);
            }
            finally
            {
                try
                {
                    _queueTimer?.Change(QUEUE_TIMER_INTERVAL, Timeout.Infinite);
                }
                catch (ObjectDisposedException)
                { }
            }
        }

        #endregion

        #region properties

        public string Description
        {
            get { return Lang.T("Exportiert das Anfrageprotokoll an externe Ziele: Datei, HTTP-Endpunkt oder Syslog (UDP, TCP, TLS oder lokal).", "Exports the query log to external targets: file, HTTP endpoint or syslog (UDP, TCP, TLS or local)."); }
        }

        #endregion
    }
}
