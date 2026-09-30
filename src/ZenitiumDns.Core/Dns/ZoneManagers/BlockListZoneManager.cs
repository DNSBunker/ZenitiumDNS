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

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using ZenitiumLibrary;
using ZenitiumLibrary.IO;
using ZenitiumLibrary.Net;
using ZenitiumLibrary.Net.Dns;
using ZenitiumLibrary.Net.Dns.EDnsOptions;
using ZenitiumLibrary.Net.Dns.ResourceRecords;
using ZenitiumLibrary.Net.Http.Client;

namespace ZenitiumDns.Core.Dns.ZoneManagers
{
    public sealed class BlockListZoneManager : IDisposable
    {
        #region variables

        readonly static char[] _popWordSeperator = new char[] { ' ', '\t' };
        readonly static char[] _trimSeperator = new char[] { ' ', '\t', '*', '.' };

        readonly DnsServer _dnsServer;
        readonly string _localCacheFolder;

        IReadOnlyList<string> _blockListUrls = [];
        IReadOnlyList<string> _profileListUrls = [];
        ClientProfile.FilterCache _defaultFilterCache;

        const string STATUS_FILE_NAME = "status.json";
        const int MAX_LIST_NAME_LENGTH = 60;
        readonly ConcurrentDictionary<string, ListStatus> _listStatus = new ConcurrentDictionary<string, ListStatus>(StringComparer.Ordinal);
        readonly Lock _statusLock = new Lock();

        ListRuleSet _ruleSet = ListRuleSet.Empty;
        readonly SemaphoreSlim _updateSemaphore = new SemaphoreSlim(1, 1);
        readonly Lock _loadLock = new Lock();

        DnsSOARecordData _soaRecord;
        DnsNSRecordData _nsRecord;

        readonly IReadOnlyCollection<DnsARecordData> _aRecords = [new DnsARecordData(IPAddress.Any)];
        readonly IReadOnlyCollection<DnsAAAARecordData> _aaaaRecords = [new DnsAAAARecordData(IPAddress.IPv6Any)];

        Timer _blockListUpdateTimer;
        DateTime _blockListLastUpdatedOn;
        int _blockListUpdateIntervalHours = 8;
        const int BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL = 5000;
        const int BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL = 900000;

        Timer _temporaryDisableBlockingTimer;
        DateTime _temporaryDisableBlockingTill;

        readonly Lock _saveLock = new Lock();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        #endregion

        #region constructor

        public BlockListZoneManager(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;

            _localCacheFolder = Path.Combine(_dnsServer.ConfigFolder, "blocklists");

            if (!Directory.Exists(_localCacheFolder))
                Directory.CreateDirectory(_localCacheFolder);

            LoadListStatus();

            UpdateServerDomain();

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
                            _dnsServer.LogManager.Write(ex);

                            _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                        }
                    }
                }
            });
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _blockListUpdateTimer?.Dispose();
            _temporaryDisableBlockingTimer?.Dispose();

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
                        _dnsServer.LogManager.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            _disposed = true;
        }

        #endregion

        #region config

        public void LoadConfigFile()
        {
            string blockListConfigFile = Path.Combine(_dnsServer.ConfigFolder, "blocklist.config");

            try
            {
                using (FileStream fS = new FileStream(blockListConfigFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS);
                }

                _dnsServer.LogManager.Write("DNS Server block list config file was loaded: " + blockListConfigFile);
            }
            catch (FileNotFoundException)
            {
                lock (_saveLock)
                {
                    SaveConfigFileInternal();
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server encountered an error while loading block list config file: " + blockListConfigFile, ex);
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

        private void SaveConfigFileInternal()
        {
            string tmpBlockListConfigFile = Path.Combine(_dnsServer.ConfigFolder, "blocklist.tmp");
            string blockListConfigFile = Path.Combine(_dnsServer.ConfigFolder, "blocklist.config");

            using (FileStream fS = new FileStream(tmpBlockListConfigFile, FileMode.Create, FileAccess.Write))
            {
                WriteConfigTo(fS);
            }

            File.Move(tmpBlockListConfigFile, blockListConfigFile, true);

            _dnsServer.LogManager.Write("DNS Server block list config file was saved: " + blockListConfigFile);
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

        private void ReadConfigFrom(Stream s)
        {
            if (Encoding.ASCII.GetString(s.ReadExactly(2)) != "BL")
                throw new InvalidDataException("DnsServer block list zone file format is invalid.");

            BinaryReader bR = new BinaryReader(s);

            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    int count = bR.ReadByte();
                    string[] blockListUrls = new string[count];

                    for (int i = 0; i < count; i++)
                        blockListUrls[i] = s.ReadShortString();

                    _blockListUpdateIntervalHours = bR.ReadInt32();

                    DateTime blockListLastUpdatedOn = s.ReadDateTime();
                    _blockListLastUpdatedOn = blockListLastUpdatedOn;

                    if ((blockListUrls.Length > 0) || (_profileListUrls.Count > 0))
                    {
                        ThreadPool.QueueUserWorkItem(delegate (object state)
                        {
                            try
                            {
                                LoadBlockLists();
                            }
                            catch (Exception ex)
                            {
                                _dnsServer.LogManager.Write(ex);
                            }
                        });
                    }

                    ApplyBlockListUrls(blockListUrls);
                    ApplyBlockListUpdateInterval();
                    break;

                default:
                    throw new InvalidDataException("DnsServer block list zone file version not supported.");
            }
        }

        private void WriteConfigTo(Stream s)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("BL"));
            bW.Write((byte)1);

            bW.Write(Convert.ToByte(_blockListUrls.Count));

            foreach (string blockListUrl in _blockListUrls)
                s.WriteShortString(blockListUrl);

            bW.Write(_blockListUpdateIntervalHours);
            s.WriteDateTime(_blockListLastUpdatedOn);
        }

        #endregion

        #region private

        internal void UpdateServerDomain()
        {
            _soaRecord = new DnsSOARecordData(_dnsServer.ServerDomain, _dnsServer.ResponsiblePerson.Address, 1, 14400, 3600, 604800, _dnsServer.BlockingNegativeTtl);
            _nsRecord = new DnsNSRecordData(_dnsServer.ServerDomain);
        }

        private string GetBlockListFilePath(Uri blockListUrl)
        {
            return Path.Combine(_localCacheFolder, Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(blockListUrl.AbsoluteUri))).ToLowerInvariant());
        }

        private static string PopWord(ref string line)
        {
            if (line.Length == 0)
                return line;

            line = line.TrimStart(_popWordSeperator);

            int i = line.IndexOfAny(_popWordSeperator);
            string word;

            if (i < 0)
            {
                word = line;
                line = "";
            }
            else
            {
                word = line.Substring(0, i);
                line = line.Substring(i + 1);
            }

            return word;
        }

        private string GetListFilePath(Uri listUrl)
        {
            if (listUrl.IsFile)
                return listUrl.LocalPath;

            return GetBlockListFilePath(listUrl);
        }

        private void ReadListFile(Uri listUrl, bool isAllowList, ListRuleSetBuilder builder)
        {
            if (!File.Exists(GetListFilePath(listUrl)))
            {
                _dnsServer.LogManager.Write("DNS Server has no local copy of the " + (isAllowList ? "allow" : "block") + " list yet: " + listUrl.AbsoluteUri);

                ListStatus missingStatus = GetListStatus(listUrl);
                missingStatus.Domains = 0;
                missingStatus.Exceptions = 0;
                missingStatus.Regexes = 0;
                missingStatus.Ips = 0;
                missingStatus.LoadError = "File not found";
                return;
            }

            try
            {
                _dnsServer.LogManager.Write("DNS Server is reading " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri);

                ListRuleCounts counts;

                using (FileStream fS = new FileStream(GetListFilePath(listUrl), FileMode.Open, FileAccess.Read, FileShare.Read, 65536))
                {
                    using (StreamReader sR = new StreamReader(fS, true))
                    {
                        counts = builder.ParseList(listUrl, isAllowList, sR);
                    }
                }

                _dnsServer.LogManager.Write("DNS Server read " + (isAllowList ? "allow" : "block") + " list file (" + counts.Domains + " domain(s) " + (isAllowList ? "allowed" : "blocked") + (counts.Exceptions > 0 ? ", " + counts.Exceptions + " exception(s)" : "") + (counts.Regexes > 0 ? ", " + counts.Regexes + " regex rule(s)" : "") + (counts.Ips > 0 ? ", " + counts.Ips + " IP rule(s)" : "") + (counts.Skipped > 0 ? ", " + counts.Skipped + " unsupported line(s) skipped" : "") + ") from: " + listUrl.AbsoluteUri);

                ListStatus status = GetListStatus(listUrl);
                status.Domains = counts.Domains;
                status.Exceptions = counts.Exceptions;
                status.Regexes = counts.Regexes;
                status.Ips = counts.Ips;
                status.Skipped = counts.Skipped;
                status.LastLoadedOn = DateTime.UtcNow;
                status.LoadError = null;
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server failed to read " + (isAllowList ? "allow" : "block") + " list from: " + listUrl.AbsoluteUri, ex);

                ListStatus status = GetListStatus(listUrl);
                status.Domains = 0;
                status.Exceptions = 0;
                status.Regexes = 0;
                status.Ips = 0;
                status.LoadError = ex is FileNotFoundException ? "File not found" : ex.Message;
            }
        }

        private void ApplyBlockListUrls(IReadOnlyList<string> blockListUrls)
        {
            bool blockListUrlsUpdated = !blockListUrls.HasSameItems(_blockListUrls);

            _blockListUrls = blockListUrls;

            ApplyListChanges(blockListUrlsUpdated);
        }

        private void ApplyListChanges(bool listsUpdated)
        {
            bool hasLists = (_blockListUrls.Count > 0) || (_profileListUrls.Count > 0);

            if ((_blockListUpdateIntervalHours > 0) && hasLists)
            {
                if (_blockListUpdateTimer is null)
                    StartBlockListUpdateTimer(listsUpdated);
                else if (listsUpdated)
                    ForceUpdateBlockLists(true);
            }
            else
            {
                StopBlockListUpdateTimer();
            }

            if (!hasLists)
                Flush();
        }

        private List<(Uri Url, bool IsAllowList)> GetEnabledLists()
        {
            List<(Uri Url, bool IsAllowList)> lists = new List<(Uri Url, bool IsAllowList)>();
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);

            void Add(IReadOnlyList<string> lines)
            {
                foreach (string line in lines)
                {
                    if (!TryParseListLine(line, out Uri listUrl, out bool isAllowList, out bool enabled) || !enabled)
                        continue;

                    if (seen.Add(GetListKey(listUrl, isAllowList)))
                        lists.Add((listUrl, isAllowList));
                }
            }

            Add(_blockListUrls);
            Add(_profileListUrls);

            return lists;
        }

        private static string GetListKey(Uri listUrl, bool isAllowList)
        {
            return (isAllowList ? "!" : "") + listUrl.AbsoluteUri;
        }

        private HashSet<string> GetGlobalListKeys()
        {
            HashSet<string> keys = new HashSet<string>(StringComparer.Ordinal);

            foreach (string line in _blockListUrls)
            {
                if (TryParseListLine(line, out Uri listUrl, out bool isAllowList, out bool enabled) && enabled)
                    keys.Add(GetListKey(listUrl, isAllowList));
            }

            return keys;
        }

        private ListRuleFilter GetFilter(ListRuleSet ruleSet, ClientProfile profile)
        {
            IReadOnlyList<string> globalLines = _blockListUrls;

            if ((profile is null) || profile.UsesOnlyDefaultLists)
            {
                if (_profileListUrls.Count == 0)
                    return null;

                ClientProfile.FilterCache defaultCache = _defaultFilterCache;
                if ((defaultCache is not null) && ReferenceEquals(defaultCache.RuleSet, ruleSet) && ReferenceEquals(defaultCache.GlobalLines, globalLines))
                    return defaultCache.Filter;

                HashSet<string> globalKeys = GetGlobalListKeys();
                ListRuleFilter defaultFilter = ruleSet.CreateFilter(delegate (Uri listUrl, bool isAllowList) { return globalKeys.Contains(GetListKey(listUrl, isAllowList)); });

                _defaultFilterCache = new ClientProfile.FilterCache() { RuleSet = ruleSet, GlobalLines = globalLines, Filter = defaultFilter };
                return defaultFilter;
            }

            ClientProfile.FilterCache cache = profile._filterCache;
            if ((cache is not null) && ReferenceEquals(cache.RuleSet, ruleSet) && ReferenceEquals(cache.GlobalLines, globalLines))
                return cache.Filter;

            HashSet<string> keys = profile.UseDefaultLists ? GetGlobalListKeys() : new HashSet<string>(StringComparer.Ordinal);

            foreach (string line in profile.BlockListUrls)
            {
                if (TryParseListLine(line, out Uri listUrl, out bool isAllowList, out bool enabled) && enabled)
                    keys.Add(GetListKey(listUrl, isAllowList));
            }

            ListRuleFilter filter = ruleSet.CreateFilter(delegate (Uri listUrl, bool isAllowList) { return keys.Contains(GetListKey(listUrl, isAllowList)); });

            profile._filterCache = new ClientProfile.FilterCache() { RuleSet = ruleSet, GlobalLines = globalLines, Filter = filter };
            return filter;
        }

        private void ApplyBlockListUpdateInterval()
        {
            if ((_blockListUpdateIntervalHours > 0) && ((_blockListUrls.Count > 0) || (_profileListUrls.Count > 0)))
            {
                if (_blockListUpdateTimer is null)
                    StartBlockListUpdateTimer(false);
            }
            else
            {
                StopBlockListUpdateTimer();
            }
        }

        private void Flush()
        {
            _ruleSet = ListRuleSet.Empty;
        }

        private async Task<ListDownloadResult> DownloadListAsync(Uri listUrl, bool isAllowList)
        {
            ListStatus status = GetListStatus(listUrl);
            status.LastCheckedOn = DateTime.UtcNow;

            try
            {
                _dnsServer.LogManager.Write("DNS Server is downloading " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);

                string listFilePath = GetBlockListFilePath(listUrl);

                if (listUrl.IsFile)
                {
                    if (!File.Exists(listUrl.LocalPath))
                    {
                        _dnsServer.LogManager.Write("DNS Server did not find the " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);

                        status.LastResult = "notFound";
                        status.LastError = "File not found: " + listUrl.LocalPath;
                        return ListDownloadResult.Failed;
                    }

                    if (File.Exists(listFilePath))
                    {
                        if (File.GetLastWriteTimeUtc(listUrl.LocalPath) <= File.GetLastWriteTimeUtc(listFilePath))
                        {
                            _dnsServer.LogManager.Write("DNS Server successfully checked for a new update of the " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);

                            status.LastResult = "notModified";
                            status.LastError = null;
                            return ListDownloadResult.NotModified;
                        }
                    }

                    await File.Create(listFilePath).DisposeAsync();

                    _dnsServer.LogManager.Write("DNS Server found new update for the " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);

                    status.LastResult = "updated";
                    status.LastError = null;
                    status.LastUpdatedOn = DateTime.UtcNow;
                    return ListDownloadResult.Downloaded;
                }

                HttpClientNetworkHandler handler = new HttpClientNetworkHandler();
                handler.Proxy = _dnsServer.Proxy;
                handler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsServer.IPv6Mode);
                handler.DnsClient = _dnsServer;

                using (HttpClient http = new HttpClient(handler))
                {
                    if (File.Exists(listFilePath))
                        http.DefaultRequestHeaders.IfModifiedSince = File.GetLastWriteTimeUtc(listFilePath);

                    HttpResponseMessage httpResponse = await http.GetAsync(listUrl, HttpCompletionOption.ResponseHeadersRead);
                    switch (httpResponse.StatusCode)
                    {
                        case HttpStatusCode.OK:
                            {
                                string listDownloadFilePath = listFilePath + ".downloading";

                                await using (FileStream fS = new FileStream(listDownloadFilePath, FileMode.Create, FileAccess.Write))
                                {
                                    await using (Stream httpStream = await httpResponse.Content.ReadAsStreamAsync())
                                    {
                                        await httpStream.CopyToAsync(fS, TimeSpan.FromSeconds(60));
                                    }
                                }

                                File.Move(listDownloadFilePath, listFilePath, true);

                                if (httpResponse.Content.Headers.LastModified != null)
                                    File.SetLastWriteTimeUtc(listFilePath, httpResponse.Content.Headers.LastModified.Value.UtcDateTime);

                                _dnsServer.LogManager.Write("DNS Server successfully downloaded " + (isAllowList ? "allow" : "block") + " list (" + WebUtilities.GetFormattedSize(new FileInfo(listFilePath).Length) + "): " + listUrl.AbsoluteUri);

                                status.LastResult = "updated";
                                status.LastError = null;
                                status.LastUpdatedOn = DateTime.UtcNow;
                                return ListDownloadResult.Downloaded;
                            }

                        case HttpStatusCode.NotModified:
                            {
                                _dnsServer.LogManager.Write("DNS Server successfully checked for a new update of the " + (isAllowList ? "allow" : "block") + " list: " + listUrl.AbsoluteUri);

                                status.LastResult = "notModified";
                                status.LastError = null;
                                return ListDownloadResult.NotModified;
                            }

                        default:
                            throw new HttpRequestException((int)httpResponse.StatusCode + " " + httpResponse.ReasonPhrase);
                    }
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server failed to download " + (isAllowList ? "allow" : "block") + " list and will use previously downloaded file (if available): " + listUrl.AbsoluteUri, ex);

                status.LastResult = "failed";
                status.LastError = ex.Message;
                return ListDownloadResult.Failed;
            }
        }

        private async Task<bool> UpdateBlockListsAsync(bool forceReload)
        {
            await _updateSemaphore.WaitAsync();

            try
            {
                return await UpdateBlockListsInternalAsync(forceReload);
            }
            finally
            {
                _updateSemaphore.Release();
            }
        }

        private async Task<bool> UpdateBlockListsInternalAsync(bool forceReload)
        {
            List<Task<ListDownloadResult>> tasks = new List<Task<ListDownloadResult>>();
            HashSet<string> downloading = new HashSet<string>(StringComparer.Ordinal);

            foreach ((Uri listUrl, bool isAllowList) in GetEnabledLists())
            {
                if (downloading.Add(listUrl.AbsoluteUri))
                    tasks.Add(DownloadListAsync(listUrl, isAllowList));
            }

            ListDownloadResult[] results = await Task.WhenAll(tasks);

            bool downloaded = false;
            bool notModified = false;

            foreach (ListDownloadResult result in results)
            {
                if (result == ListDownloadResult.Downloaded)
                    downloaded = true;
                else if (result == ListDownloadResult.NotModified)
                    notModified = true;
            }

            if (downloaded || forceReload)
            {
                LoadBlockLists();

                GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, false);
            }

            SaveListStatus();

            return downloaded || notModified;
        }

        private void ForceUpdateBlockLists(bool forceReload)
        {
            ThreadPool.QueueUserWorkItem(async delegate (object state)
            {
                try
                {
                    if (await UpdateBlockListsAsync(forceReload))
                    {
                        _blockListLastUpdatedOn = DateTime.UtcNow;
                        SaveConfigFile();
                    }
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            });
        }

        private void StartBlockListUpdateTimer(bool forceUpdateAndReload)
        {
            if (_blockListUpdateTimer is null)
            {
                if (forceUpdateAndReload)
                    _blockListLastUpdatedOn = default;

                _blockListUpdateTimer = new Timer(async delegate (object state)
                {
                    try
                    {
                        if (DateTime.UtcNow > _blockListLastUpdatedOn.AddHours(_blockListUpdateIntervalHours))
                        {
                            if (await UpdateBlockListsAsync(_blockListLastUpdatedOn == default))
                            {
                                _blockListLastUpdatedOn = DateTime.UtcNow;
                                SaveConfigFile();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write("DNS Server encountered an error while updating block lists.", ex);
                    }
                    finally
                    {
                        try
                        {
                            _blockListUpdateTimer?.Change(BLOCK_LIST_UPDATE_TIMER_PERIODIC_INTERVAL, Timeout.Infinite);
                        }
                        catch (ObjectDisposedException)
                        { }
                    }
                }, null, BLOCK_LIST_UPDATE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void StopBlockListUpdateTimer()
        {
            if (_blockListUpdateTimer is not null)
            {
                _blockListUpdateTimer.Dispose();
                _blockListUpdateTimer = null;
            }
        }

        private void LoadBlockLists()
        {
            lock (_loadLock)
            {
                LoadBlockListsInternal();
            }
        }

        private void LoadBlockListsInternal()
        {
            _dnsServer.LogManager.Write("DNS Server is loading block list zone...");

            List<Uri> allowListUrls = new List<Uri>();
            List<Uri> blockListUrls = new List<Uri>();

            foreach ((Uri listUrl, bool isAllowList) in GetEnabledLists())
            {
                if (isAllowList)
                    allowListUrls.Add(listUrl);
                else
                    blockListUrls.Add(listUrl);
            }

            long totalFileSize = 0;

            foreach (Uri listUrl in blockListUrls)
            {
                try
                {
                    FileInfo fileInfo = new FileInfo(GetListFilePath(listUrl));
                    if (fileInfo.Exists)
                        totalFileSize += fileInfo.Length;
                }
                catch
                { }
            }

            ListRuleSet currentRuleSet = _ruleSet;
            ListRuleSetBuilder builder = new ListRuleSetBuilder(Math.Max(currentRuleSet.Block.Tree.Count, totalFileSize / 24));
            foreach (Uri allowListUrl in allowListUrls)
                ReadListFile(allowListUrl, true, builder);

            foreach (Uri blockListUrl in blockListUrls)
                ReadListFile(blockListUrl, false, builder);

            ListRuleSet ruleSet = builder.Build();
            _ruleSet = ruleSet;

            _dnsServer.LogManager.Write("DNS Server block list zone uses " + WebUtilities.GetFormattedSize(ruleSet.MemoryUsage) + " of memory for " + ruleSet.BlockedDomainCount + " blocked and " + ruleSet.AllowedDomainCount + " allowed domain(s), " + ruleSet.RegexCount + " regex and " + ruleSet.AdvancedCount + " advanced rule(s), " + ruleSet.IpBlock.Count + " IP rule(s).");
            _dnsServer.LogManager.Write("DNS Server block list zone was loaded successfully.");

            SaveListStatus();
        }

        private ListStatus GetListStatus(Uri listUrl)
        {
            return _listStatus.GetOrAdd(listUrl.AbsoluteUri, delegate (string key) { return new ListStatus(); });
        }

        private void LoadListStatus()
        {
            string file = Path.Combine(_localCacheFolder, STATUS_FILE_NAME);

            if (!File.Exists(file))
                return;

            try
            {
                Dictionary<string, ListStatus> stored = JsonSerializer.Deserialize<Dictionary<string, ListStatus>>(File.ReadAllBytes(file));

                if (stored is not null)
                {
                    foreach (KeyValuePair<string, ListStatus> entry in stored)
                    {
                        if (entry.Value is not null)
                            _listStatus[entry.Key] = entry.Value;
                    }
                }
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager.Write("DNS Server failed to load the block list status file: " + file, ex);
            }
        }

        private void SaveListStatus()
        {
            string file = Path.Combine(_localCacheFolder, STATUS_FILE_NAME);

            lock (_statusLock)
            {
                try
                {
                    Dictionary<string, ListStatus> snapshot = new Dictionary<string, ListStatus>(_listStatus, StringComparer.Ordinal);
                    string tmpFile = file + ".tmp";

                    File.WriteAllBytes(tmpFile, JsonSerializer.SerializeToUtf8Bytes(snapshot));
                    File.Move(tmpFile, file, true);
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write("DNS Server failed to save the block list status file: " + file, ex);
                }
            }
        }

        private static bool TryParseListLine(string line, out Uri listUrl, out bool isAllowList, out bool enabled)
        {
            listUrl = null;
            isAllowList = false;
            enabled = true;

            string value = line.Trim();

            if (value.StartsWith('#'))
            {
                enabled = false;
                value = value.TrimStart('#').Trim();
            }

            if (value.StartsWith('!'))
            {
                isAllowList = true;
                value = value.Substring(1).Trim();
            }

            return Uri.TryCreate(value, UriKind.Absolute, out listUrl) && (listUrl.IsFile || (listUrl.Scheme == Uri.UriSchemeHttp) || (listUrl.Scheme == Uri.UriSchemeHttps));
        }

        private int FindListLine(IReadOnlyList<string> lines, string url)
        {
            for (int i = 0; i < lines.Count; i++)
            {
                if (TryParseListLine(lines[i], out Uri listUrl, out _, out _) && listUrl.AbsoluteUri.Equals(url, StringComparison.Ordinal))
                    return i;
            }

            return -1;
        }

        #endregion

        #region public

        internal void SetProfileListUrls(IReadOnlyList<string> profileListUrls)
        {
            bool updated = !profileListUrls.HasSameItems(_profileListUrls);

            _profileListUrls = profileListUrls;

            if (!updated)
                return;

            if (_blockListUpdateIntervalHours > 0)
                ApplyListChanges(true);
            else if ((_blockListUrls.Count > 0) || (_profileListUrls.Count > 0))
                ForceUpdateBlockLists(true);
            else
                Flush();
        }

        internal void InitializeProfileListUrls(IReadOnlyList<string> profileListUrls)
        {
            _profileListUrls = profileListUrls;
        }

        public bool IsAllowed(DnsDatagram request)
        {
            return IsAllowed(request, default);
        }

        public bool IsAllowed(DnsDatagram request, in DnsClientIdentity client)
        {
            ListRuleSet ruleSet = _ruleSet;
            if (!ruleSet.HasAllowRules)
                return false;

            DnsQuestionRecord question = request.Question[0];

            return ruleSet.Evaluate(question.Name, question.Type, GetFilter(ruleSet, client.Profile), new ListClientInfo(client.Address, client.Profile?.Name, client.ClientId)).Action == ListRuleAction.Allow;
        }

        public DnsDatagram Query(DnsDatagram request)
        {
            return Query(request, default);
        }

        public DnsDatagram Query(DnsDatagram request, in DnsClientIdentity client)
        {
            ListRuleSet ruleSet = _ruleSet;
            if (!ruleSet.HasBlockRules)
                return null;

            DnsQuestionRecord question = request.Question[0];

            ListRuleMatch match = ruleSet.Evaluate(question.Name, question.Type, GetFilter(ruleSet, client.Profile), new ListClientInfo(client.Address, client.Profile?.Name, client.ClientId));
            if (match.Action != ListRuleAction.Block)
                return null;

            return GetBlockedResponse(request, match.Domain, match.Lists, "block-list-zone");
        }

        public DnsDatagram QueryAnswerAddresses(DnsDatagram request, DnsDatagram response)
        {
            return QueryAnswerAddresses(request, response, default);
        }

        public DnsDatagram QueryAnswerAddresses(DnsDatagram request, DnsDatagram response, in DnsClientIdentity client)
        {
            ListRuleSet ruleSet = _ruleSet;
            if (!ruleSet.HasIpRules)
                return null;

            ListRuleFilter filter = GetFilter(ruleSet, client.Profile);
            if ((filter is not null) && filter.IsEmpty)
                return null;

            foreach (DnsResourceRecord record in response.Answer)
            {
                IPAddress address;

                switch (record.Type)
                {
                    case DnsResourceRecordType.A:
                        address = (record.RDATA as DnsARecordData).Address;
                        break;

                    case DnsResourceRecordType.AAAA:
                        address = (record.RDATA as DnsAAAARecordData).Address;
                        break;

                    default:
                        continue;
                }

                if (ruleSet.TryMatchAnswerAddress(address, filter, out Uri list))
                    return GetBlockedResponse(request, request.Question[0].Name.ToLowerInvariant(), [list], "block-list-ip " + address.ToString());
            }

            return null;
        }

        private DnsDatagram GetBlockedResponse(DnsDatagram request, string blockedDomain, IReadOnlyList<Uri> blockLists, string source)
        {
            DnsQuestionRecord question = request.Question[0];

            if (_dnsServer.AllowTxtBlockingReport && (question.Type == DnsResourceRecordType.TXT))
            {
                DnsResourceRecord[] answer = new DnsResourceRecord[_dnsServer.IsBlockingReportTextPerList ? blockLists.Count : 1];

                for (int i = 0; i < answer.Length; i++)
                    answer[i] = new DnsResourceRecord(question.Name, DnsResourceRecordType.TXT, question.Class, _dnsServer.BlockingAnswerTtl, new DnsTXTRecordData(_dnsServer.GetBlockingReportText(source, blockedDomain, blockLists[i].AbsoluteUri)));

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, false, false, false, DnsResponseCode.NoError, request.Question, answer);
            }
            else
            {
                EDnsOption[] options = null;

                if (_dnsServer.AllowTxtBlockingReport && (request.EDNS is not null))
                {
                    options = new EDnsOption[_dnsServer.IsBlockingReportTextPerList ? blockLists.Count : 1];

                    for (int i = 0; i < options.Length; i++)
                        options[i] = new EDnsOption(EDnsOptionCode.EXTENDED_DNS_ERROR, new EDnsExtendedDnsErrorOptionData(EDnsExtendedDnsErrorCode.Blocked, _dnsServer.GetBlockingReportText(source, blockedDomain, blockLists[i].AbsoluteUri)));
                }

                IReadOnlyCollection<DnsARecordData> aRecords;
                IReadOnlyCollection<DnsAAAARecordData> aaaaRecords;

                switch (_dnsServer.BlockingType)
                {
                    case DnsServerBlockingType.AnyAddress:
                        aRecords = _aRecords;
                        aaaaRecords = _aaaaRecords;
                        break;

                    case DnsServerBlockingType.CustomAddress:
                        aRecords = _dnsServer.CustomBlockingARecords;
                        aaaaRecords = _dnsServer.CustomBlockingAAAARecords;
                        break;

                    case DnsServerBlockingType.NxDomain:
                        string parentDomain = AuthZoneManager.GetParentZone(blockedDomain);
                        if (parentDomain is null)
                            parentDomain = string.Empty;

                        return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, !_dnsServer.AllowTxtBlockingReport, false, false, DnsResponseCode.NxDomain, request.Question, null, [new DnsResourceRecord(parentDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingNegativeTtl, _soaRecord)], null, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options);

                    default:
                        throw new InvalidOperationException();
                }

                IReadOnlyList<DnsResourceRecord> answer = null;
                IReadOnlyList<DnsResourceRecord> authority = null;

                switch (question.Type)
                {
                    case DnsResourceRecordType.A:
                        {
                            if (aRecords.Count > 0)
                            {
                                DnsResourceRecord[] rrList = new DnsResourceRecord[aRecords.Count];
                                int i = 0;

                                foreach (DnsARecordData record in aRecords)
                                    rrList[i++] = new DnsResourceRecord(question.Name, DnsResourceRecordType.A, question.Class, _dnsServer.BlockingAnswerTtl, record);

                                answer = rrList;
                            }
                            else
                            {
                                authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingNegativeTtl, _soaRecord)];
                            }
                        }
                        break;

                    case DnsResourceRecordType.AAAA:
                        {
                            if (aaaaRecords.Count > 0)
                            {
                                DnsResourceRecord[] rrList = new DnsResourceRecord[aaaaRecords.Count];
                                int i = 0;

                                foreach (DnsAAAARecordData record in aaaaRecords)
                                    rrList[i++] = new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, question.Class, _dnsServer.BlockingAnswerTtl, record);

                                answer = rrList;
                            }
                            else
                            {
                                authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingNegativeTtl, _soaRecord)];
                            }
                        }
                        break;

                    case DnsResourceRecordType.NS:
                        if (question.Name.Equals(blockedDomain, StringComparison.OrdinalIgnoreCase))
                            answer = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.NS, question.Class, _dnsServer.BlockingAnswerTtl, _nsRecord)];
                        else
                            authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingNegativeTtl, _soaRecord)];

                        break;

                    case DnsResourceRecordType.SOA:
                        answer = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingNegativeTtl, _soaRecord)];
                        break;

                    default:
                        authority = [new DnsResourceRecord(blockedDomain, DnsResourceRecordType.SOA, question.Class, _dnsServer.BlockingNegativeTtl, _soaRecord)];
                        break;
                }

                return new DnsDatagram(request.Identifier, true, DnsOpcode.StandardQuery, false, false, request.RecursionDesired, !_dnsServer.AllowTxtBlockingReport, false, false, DnsResponseCode.NoError, request.Question, answer, authority, null, request.EDNS is null ? ushort.MinValue : _dnsServer.UdpPayloadSize, EDnsHeaderFlags.None, options);
            }
        }

        public void ForceUpdateBlockLists()
        {
            ForceUpdateBlockLists(false);
        }

        public IReadOnlyList<ListInfo> GetListInfos()
        {
            List<ListInfo> infos = new List<ListInfo>();
            HashSet<string> seen = new HashSet<string>(StringComparer.Ordinal);

            ClientProfileManager profileManager = _dnsServer.ClientProfileManager;
            List<(string Line, bool Global)> allLines = new List<(string Line, bool Global)>();

            foreach (string line in _blockListUrls)
                allLines.Add((line, true));

            foreach (string line in _profileListUrls)
                allLines.Add((line, false));

            foreach ((string line, bool global) in allLines)
            {
                if (!TryParseListLine(line, out Uri listUrl, out bool isAllowList, out bool enabled))
                    continue;

                if (!seen.Add(listUrl.AbsoluteUri))
                    continue;

                IReadOnlyList<string> profiles = profileManager is null ? [] : profileManager.GetProfilesUsingList(GetListKey(listUrl, isAllowList));

                _listStatus.TryGetValue(listUrl.AbsoluteUri, out ListStatus status);

                string localPath = GetListFilePath(listUrl);
                long fileSize = -1;
                DateTime fileModifiedOn = default;

                try
                {
                    FileInfo fileInfo = new FileInfo(localPath);
                    if (fileInfo.Exists)
                    {
                        fileSize = fileInfo.Length;
                        fileModifiedOn = fileInfo.LastWriteTimeUtc;
                    }
                }
                catch
                { }

                infos.Add(new ListInfo(listUrl.AbsoluteUri, isAllowList, enabled, status?.Name, localPath, fileSize, fileModifiedOn, status, global, profiles));
            }

            return infos;
        }

        public async Task<bool> UpdateListAsync(string url)
        {
            List<string> lines = new List<string>(_blockListUrls);
            lines.AddRange(_profileListUrls);
            int index = FindListLine(lines, url);

            if ((index < 0) || !TryParseListLine(lines[index], out Uri listUrl, out bool isAllowList, out bool enabled) || !enabled)
                return false;

            await _updateSemaphore.WaitAsync();

            try
            {
                ListDownloadResult result = await DownloadListAsync(listUrl, isAllowList);

                if (result == ListDownloadResult.Downloaded)
                {
                    LoadBlockLists();
                    GC.Collect(GC.MaxGeneration, GCCollectionMode.Forced, false);
                }

                SaveListStatus();

                return result != ListDownloadResult.Failed;
            }
            finally
            {
                _updateSemaphore.Release();
            }
        }

        public bool SetListEnabled(string url, bool enabled)
        {
            List<string> lines = new List<string>(_blockListUrls);
            int index = FindListLine(lines, url);

            if ((index < 0) || !TryParseListLine(lines[index], out Uri listUrl, out bool isAllowList, out bool currentlyEnabled))
                return false;

            if (currentlyEnabled == enabled)
                return true;

            lines[index] = (enabled ? "" : "#") + (isAllowList ? "!" : "") + listUrl.AbsoluteUri;

            ApplyBlockListUrls(lines);
            SaveConfigFile();

            if (!enabled || (_blockListUpdateTimer is null))
            {
                ThreadPool.QueueUserWorkItem(delegate (object state)
                {
                    try
                    {
                        LoadBlockLists();
                    }
                    catch (Exception ex)
                    {
                        _dnsServer.LogManager.Write(ex);
                    }
                });
            }

            return true;
        }

        public bool RemoveList(string url)
        {
            List<string> lines = new List<string>(_blockListUrls);
            int index = FindListLine(lines, url);

            if (index < 0)
                return false;

            lines.RemoveAt(index);

            bool onlyComments = true;

            foreach (string line in lines)
            {
                if (!line.TrimStart().StartsWith('#'))
                {
                    onlyComments = false;
                    break;
                }
            }

            ApplyBlockListUrls(lines.Count == 0 ? [] : lines);
            SaveConfigFile();

            _listStatus.TryRemove(url, out _);
            SaveListStatus();

            if (onlyComments)
                Flush();
            else if (_blockListUpdateTimer is null)
                LoadBlockLists();

            return true;
        }

        public bool SetListName(string url, string name)
        {
            if ((FindListLine(_blockListUrls, url) < 0) && (FindListLine(_profileListUrls, url) < 0))
                return false;

            name = name?.Trim();

            if (!string.IsNullOrEmpty(name) && (name.Length > MAX_LIST_NAME_LENGTH))
                name = name.Substring(0, MAX_LIST_NAME_LENGTH);

            ListStatus status = _listStatus.GetOrAdd(url, delegate (string key) { return new ListStatus(); });
            status.Name = string.IsNullOrEmpty(name) ? null : name;

            SaveListStatus();
            return true;
        }

        public void TemporaryDisableBlocking(int minutes, IPEndPoint userEP, string username)
        {
            Timer temporaryDisableBlockingTimer = _temporaryDisableBlockingTimer;
            if (temporaryDisableBlockingTimer is not null)
                temporaryDisableBlockingTimer.Dispose();

            Timer newTemporaryDisableBlockingTimer = new Timer(delegate (object state)
            {
                try
                {
                    _dnsServer.EnableBlocking = true;
                    _dnsServer.LogManager.Write(userEP, "[" + username + "] Blocking was enabled after " + minutes + " minute(s) being temporarily disabled.");
                }
                catch (Exception ex)
                {
                    _dnsServer.LogManager.Write(ex);
                }
            });

            Timer originalTimer = Interlocked.CompareExchange(ref _temporaryDisableBlockingTimer, newTemporaryDisableBlockingTimer, temporaryDisableBlockingTimer);
            if (ReferenceEquals(originalTimer, temporaryDisableBlockingTimer))
            {
                newTemporaryDisableBlockingTimer.Change(minutes * 60 * 1000, Timeout.Infinite);
                _dnsServer.EnableBlocking = false;
                _temporaryDisableBlockingTill = DateTime.UtcNow.AddMinutes(minutes);

                _dnsServer.LogManager.Write(userEP, "[" + username + "] Blocking was temporarily disabled for " + minutes + " minute(s).");
            }
            else
            {
                newTemporaryDisableBlockingTimer.Dispose();
            }
        }

        public void StopTemporaryDisableBlockingTimer()
        {
            Timer temporaryDisableBlockingTimer = _temporaryDisableBlockingTimer;
            if (temporaryDisableBlockingTimer is not null)
                temporaryDisableBlockingTimer.Dispose();
        }

        #endregion

        #region properties

        public IReadOnlyList<string> BlockListUrls
        {
            get { return _blockListUrls; }
            set
            {
                if (value is null)
                {
                    value = [];
                }
                else if (value.Count > 255)
                {
                    throw new ArgumentException("Cannot configure more than 255 block list URLs.", nameof(BlockListUrls));
                }
                else
                {
                    List<string> uniqueList = new List<string>(value.Count);
                    int commentCount = 0;

                    foreach (string url in value)
                    {
                        if (url.Length > 255)
                            throw new ArgumentException("Block list URL (or comment line) length cannot exceed 255 characters.", nameof(BlockListUrls));

                        if (url.TrimStart().StartsWith('#'))
                        {
                            uniqueList.Add(url);
                            commentCount++;
                            continue;
                        }

                        try
                        {
                            if (url.StartsWith('!'))
                                _ = new Uri(url.Substring(1));
                            else
                                _ = new Uri(url);
                        }
                        catch (Exception ex)
                        {
                            throw new ArgumentException(ex.Message, nameof(BlockListUrls));
                        }

                        if (!uniqueList.Contains(url))
                            uniqueList.Add(url);
                    }

                    if (uniqueList.Count == commentCount)
                        uniqueList = [];

                    value = uniqueList;
                }

                ApplyBlockListUrls(value);
            }
        }

        public int BlockListUpdateIntervalHours
        {
            get { return _blockListUpdateIntervalHours; }
            set
            {
                if ((value < 0) || (value > 168))
                    throw new ArgumentOutOfRangeException(nameof(BlockListUpdateIntervalHours), "Value must be between 1 hour and 168 hours (7 days) or 0 to disable automatic update.");

                _blockListUpdateIntervalHours = value;

                ApplyBlockListUpdateInterval();
            }
        }

        public bool BlockListUpdateEnabled
        { get { return _blockListUpdateTimer is not null; } }

        public DateTime BlockListLastUpdatedOn
        {
            get { return _blockListLastUpdatedOn; }
            internal set
            {
                _blockListLastUpdatedOn = value;
            }
        }

        public DateTime TemporaryDisableBlockingTill
        { get { return _temporaryDisableBlockingTill; } }

        public int TotalZonesAllowed
        { get { return _ruleSet.AllowedDomainCount; } }

        public int TotalZonesBlocked
        { get { return _ruleSet.BlockedDomainCount; } }

        #endregion

        enum ListDownloadResult : byte
        {
            Failed = 0,
            NotModified = 1,
            Downloaded = 2
        }

        public sealed class ListStatus
        {
            public string Name { get; set; }
            public DateTime LastCheckedOn { get; set; }
            public DateTime LastUpdatedOn { get; set; }
            public string LastResult { get; set; }
            public string LastError { get; set; }
            public DateTime LastLoadedOn { get; set; }
            public string LoadError { get; set; }
            public int Domains { get; set; }
            public int Exceptions { get; set; }
            public int Regexes { get; set; }
            public int Ips { get; set; }
            public int Skipped { get; set; }
        }

        public sealed record ListInfo(string Url, bool IsAllowList, bool Enabled, string Name, string LocalPath, long FileSize, DateTime FileModifiedOn, ListStatus Status, bool Global, IReadOnlyList<string> Profiles);
    }
}
