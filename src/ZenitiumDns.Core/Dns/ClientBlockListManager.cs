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
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumLibrary.Net.Http.Client;

namespace ZenitiumDns.Core.Dns
{
    sealed class ClientBlockListManager : IDisposable
    {
        #region variables

        const int UPDATE_CHECK_INTERVAL = 600000;
        const int INITIAL_UPDATE_DELAY = 30000;
        const long MAX_LIST_SIZE = 64L * 1024 * 1024;

        readonly DnsServer _dnsServer;
        readonly string _cacheFolder;
        readonly SemaphoreSlim _updateLock = new SemaphoreSlim(1, 1);

        IReadOnlyList<Uri> _listUrls = [];
        int _updateIntervalHours = 24;
        DateTime _lastUpdatedOn;
        long _drops;

        volatile ClientBlockList _list = ClientBlockList.Empty;
        Timer _updateTimer;

        #endregion

        #region constructor

        public ClientBlockListManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;
            _cacheFolder = Path.Combine(dnsServer.ConfigFolder, "clientblocklists");
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _updateTimer?.Dispose();
            _updateLock.Dispose();

            _disposed = true;
        }

        #endregion

        #region private

        private string GetCacheFilePath(Uri listUrl)
        {
            if (listUrl.IsFile)
                return listUrl.LocalPath;

            return Path.Combine(_cacheFolder, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(listUrl.AbsoluteUri))).ToLowerInvariant());
        }

        private void LoadFromCache()
        {
            List<(IPAddress, int)> entries = new List<(IPAddress, int)>();
            int loadedLists = 0;

            foreach (Uri listUrl in _listUrls)
            {
                string filePath = GetCacheFilePath(listUrl);

                if (!File.Exists(filePath))
                    continue;

                try
                {
                    using (StreamReader reader = new StreamReader(filePath))
                    {
                        string line;

                        while ((line = reader.ReadLine()) is not null)
                        {
                            if (ClientBlockList.TryParseEntry(line, out IPAddress address, out int prefixLength))
                                entries.Add((address, prefixLength));
                        }
                    }

                    loadedLists++;
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write("DNS Server failed to read client block list: " + listUrl.AbsoluteUri, ex);
                }
            }

            ClientBlockList list = ClientBlockList.Build(entries);
            _list = list;

            if (_listUrls.Count > 0)
                _dnsServer.LogManager.Write("DNS Server loaded " + loadedLists + " client block list(s) with " + list.Count + " address ranges.");
        }

        private async Task<bool> DownloadAsync(Uri listUrl)
        {
            if (listUrl.IsFile)
                return File.Exists(listUrl.LocalPath);

            string filePath = GetCacheFilePath(listUrl);
            string tmpFilePath = filePath + ".tmp";

            try
            {
                Directory.CreateDirectory(_cacheFolder);

                HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                handler.Proxy = _dnsServer.Proxy;
                handler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsServer.IPv6Mode);
                handler.DnsClient = _dnsServer;

                using (HttpClient http = new HttpClient(handler))
                {
                    http.Timeout = TimeSpan.FromMinutes(2);

                    using (HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, listUrl))
                    {
                        if (File.Exists(filePath))
                            request.Headers.IfModifiedSince = File.GetLastWriteTimeUtc(filePath);

                        using (HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead))
                        {
                            if (response.StatusCode == HttpStatusCode.NotModified)
                            {
                                File.SetLastWriteTimeUtc(filePath, DateTime.UtcNow);
                                return true;
                            }

                            response.EnsureSuccessStatusCode();

                            if (response.Content.Headers.ContentLength > MAX_LIST_SIZE)
                                throw new InvalidDataException("Client block list is larger than " + (MAX_LIST_SIZE / 1024 / 1024) + " MB.");

                            await using (Stream httpStream = await response.Content.ReadAsStreamAsync())
                            await using (FileStream fileStream = new FileStream(tmpFilePath, FileMode.Create, FileAccess.Write))
                            {
                                byte[] buffer = new byte[65536];
                                long total = 0;
                                int read;

                                while ((read = await httpStream.ReadAsync(buffer)) > 0)
                                {
                                    total += read;
                                    if (total > MAX_LIST_SIZE)
                                        throw new InvalidDataException("Client block list is larger than " + (MAX_LIST_SIZE / 1024 / 1024) + " MB.");

                                    await fileStream.WriteAsync(buffer.AsMemory(0, read));
                                }
                            }

                            File.Move(tmpFilePath, filePath, true);
                        }
                    }
                }

                _dnsServer.LogManager.Write("DNS Server downloaded client block list: " + listUrl.AbsoluteUri);
                return true;
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server failed to download client block list and will use the previously downloaded file (if available): " + listUrl.AbsoluteUri, ex);

                try
                {
                    File.Delete(tmpFilePath);
                }
                catch
                { }

                return false;
            }
        }

        private void ResetTimer(int dueTime)
        {
            if (_listUrls.Count == 0)
            {
                _updateTimer?.Dispose();
                _updateTimer = null;
                return;
            }

            if (_updateTimer is null)
                _updateTimer = new Timer(UpdateTimerCallback, null, dueTime, UPDATE_CHECK_INTERVAL);
            else
                _updateTimer.Change(dueTime, UPDATE_CHECK_INTERVAL);
        }

        private async void UpdateTimerCallback(object state)
        {
            try
            {
                if ((_updateIntervalHours > 0) && (DateTime.UtcNow >= _lastUpdatedOn.AddHours(_updateIntervalHours)))
                    await UpdateAsync();
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write(ex);
            }
        }

        #endregion

        #region public

        public async Task UpdateAsync()
        {
            if (!await _updateLock.WaitAsync(0))
                return;

            try
            {
                IReadOnlyList<Uri> listUrls = _listUrls;
                bool success = false;

                foreach (Uri listUrl in listUrls)
                {
                    if (await DownloadAsync(listUrl))
                        success = true;
                }

                if (success)
                    _lastUpdatedOn = DateTime.UtcNow;

                LoadFromCache();
            }
            finally
            {
                _updateLock.Release();
            }
        }

        public bool Contains(IPAddress address)
        {
            ClientBlockList list = _list;

            return (list.Count > 0) && list.Contains(address);
        }

        public void CountDrop()
        {
            Interlocked.Increment(ref _drops);
        }

        #endregion

        #region properties

        public IReadOnlyList<Uri> ListUrls
        {
            get { return _listUrls; }
            set
            {
                value ??= [];

                if (value.Count > byte.MaxValue)
                    throw new ArgumentOutOfRangeException(nameof(ListUrls), "Client block lists cannot have more than 255 entries.");

                bool changed = value.Count != _listUrls.Count;

                for (int i = 0; !changed && (i < value.Count); i++)
                    changed = !value[i].Equals(_listUrls[i]);

                _listUrls = value;

                if (!changed)
                    return;

                LoadFromCache();

                if (value.Count == 0)
                {
                    ResetTimer(0);
                    return;
                }

                _lastUpdatedOn = DateTime.MinValue;
                ResetTimer(INITIAL_UPDATE_DELAY);
            }
        }

        public int UpdateIntervalHours
        {
            get { return _updateIntervalHours; }
            set
            {
                if ((value < 0) || (value > 168))
                    throw new ArgumentOutOfRangeException(nameof(UpdateIntervalHours), "Valid range is from 0 to 168 hours.");

                _updateIntervalHours = value;
            }
        }

        public bool IsEnabled
        { get { return _list.Count > 0; } }

        public int AddressRanges
        { get { return _list.Count; } }

        public DateTime LastUpdatedOn
        { get { return _lastUpdatedOn; } }

        public long Drops
        { get { return Interlocked.Read(ref _drops); } }

        #endregion
    }
}
