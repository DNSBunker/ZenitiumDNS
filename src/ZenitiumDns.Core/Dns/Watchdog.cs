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
using System.Threading;
using System.Threading.Tasks;
using ZenitiumDns.ApplicationCommon;

namespace ZenitiumDns.Core.Dns
{
    sealed class Watchdog : IDisposable
    {
        #region variables

        const int CHECK_INTERVAL = 10000;
        const int MAX_EVENTS = 50;

        const long DISK_CRITICAL_BYTES = 256L * 1024 * 1024;
        const long LOG_FILE_MAX_BYTES = 512L * 1024 * 1024;
        const double MEMORY_LOAD_CRITICAL = 0.92;
        const double CACHE_TRIM_RATIO = 0.3;
        const int STATS_QUEUE_MAX = StatsManager.MAX_QUEUE_LENGTH;
        const long THREAD_POOL_QUEUE_HIGH = 2000;
        const int THREAD_POOL_STREAK = 3;
        const int MAX_MIN_WORKER_THREADS = 1024;
        const int LISTENER_STREAK = 3;
        const int MAX_LISTENER_RESTARTS = 3;

        static readonly TimeSpan DISK_COOLDOWN = TimeSpan.FromMinutes(10);
        static readonly TimeSpan MEMORY_COOLDOWN = TimeSpan.FromMinutes(5);
        static readonly TimeSpan STATS_QUEUE_COOLDOWN = TimeSpan.FromMinutes(1);
        static readonly TimeSpan THREAD_POOL_COOLDOWN = TimeSpan.FromMinutes(5);
        static readonly TimeSpan LISTENER_COOLDOWN = TimeSpan.FromMinutes(10);

        readonly DnsServer _dnsServer;
        readonly Lock _lock = new Lock();
        readonly LinkedList<WatchdogEvent> _events = new LinkedList<WatchdogEvent>();

        Timer _timer;
        int _checking;

        DateTime _lastDiskAction;
        DateTime _lastMemoryAction;
        DateTime _lastStatsQueueAction;
        DateTime _lastThreadPoolAction;
        DateTime _lastListenerRestart;

        int _threadPoolStreak;
        int _listenerStreak;
        int _listenerRestarts;

        #endregion

        #region constructor

        public Watchdog(DnsServer dnsServer)
        {
            _dnsServer = dnsServer;
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            lock (_lock)
            {
                _timer?.Dispose();
                _timer = null;
            }

            _disposed = true;
        }

        #endregion

        #region private

        private void AddEvent(WatchdogSeverity severity, LocalizedText title, LocalizedText message, string logMessage)
        {
            lock (_lock)
            {
                _events.AddFirst(new WatchdogEvent(DateTime.UtcNow, severity, title, message));

                while (_events.Count > MAX_EVENTS)
                    _events.RemoveLast();
            }

            _dnsServer.LogManager?.Write("Watchdog: " + logMessage);
        }

        private static DriveInfo FindDrive(string path)
        {
            string fullPath = Path.GetFullPath(path);
            DriveInfo bestDrive = null;

            foreach (DriveInfo drive in DriveInfo.GetDrives())
            {
                string root = drive.RootDirectory.FullName;

                if (!fullPath.StartsWith(root, StringComparison.Ordinal))
                    continue;

                if ((root.Length > 1) && (fullPath.Length > root.Length) && (fullPath[root.Length] != Path.DirectorySeparatorChar) && !root.EndsWith(Path.DirectorySeparatorChar))
                    continue;

                if ((bestDrive is null) || (root.Length > bestDrive.RootDirectory.FullName.Length))
                    bestDrive = drive;
            }

            return bestDrive;
        }

        private static long GetFreeSpace(string folder)
        {
            if (string.IsNullOrEmpty(folder) || !Directory.Exists(folder))
                return long.MaxValue;

            try
            {
                DriveInfo drive = FindDrive(folder);
                if (drive is null)
                    return long.MaxValue;

                return drive.AvailableFreeSpace;
            }
            catch
            {
                return long.MaxValue;
            }
        }

        private static string FormatMegabytes(long bytes)
        {
            return (bytes / (1024 * 1024)).ToString("N0", System.Globalization.CultureInfo.InvariantCulture) + " MB";
        }

        private static string FormatMegabytes(long bytes, string language)
        {
            return (bytes / (1024 * 1024)).ToString("N0", System.Globalization.CultureInfo.GetCultureInfo(language == Lang.German ? "de-DE" : "en-US")) + " MB";
        }

        private static string FormatCount(long value, string language)
        {
            return value.ToString("N0", System.Globalization.CultureInfo.GetCultureInfo(language == Lang.German ? "de-DE" : "en-US"));
        }

        private void CheckDiskSpace(DateTime utcNow)
        {
            LogManager log = _dnsServer.LogManager;
            if (log is null)
                return;

            string logFolder = null;

            try
            {
                logFolder = log.LogFolderAbsolutePath;
            }
            catch
            { }

            long configFree = GetFreeSpace(_dnsServer.ConfigFolder);
            long logFree = GetFreeSpace(logFolder);
            long free = Math.Min(configFree, logFree);

            if ((free >= DISK_CRITICAL_BYTES) || ((utcNow - _lastDiskAction) < DISK_COOLDOWN))
                return;

            _lastDiskAction = utcNow;

            int deletedLogFiles = log.DeleteLogFilesBefore(DateTime.Now.AddDays(-1));
            log.SuspendFileLoggingForToday("only " + FormatMegabytes(free) + " of disk space left");

            AddEvent(WatchdogSeverity.Critical, Lang.L("Speicherplatz", "Disk space"), Lang.L("Nur noch " + FormatMegabytes(free, Lang.German) + " frei. Das Datei-Protokoll ist bis Mitternacht pausiert, " + deletedLogFiles + " ältere Protokolldateien wurden gelöscht, damit Einstellungen und Cache weiter gespeichert werden können.", "Only " + FormatMegabytes(free, Lang.English) + " free. File logging is paused until midnight, " + deletedLogFiles + " older log files were deleted so that settings and cache can still be saved."), "only " + FormatMegabytes(free) + " of disk space left; file logging suspended until midnight and " + deletedLogFiles + " old log files deleted.");
        }

        private void CheckLogFileSize()
        {
            LogManager log = _dnsServer.LogManager;
            if ((log is null) || log.IsFileLoggingSuspended)
                return;

            long size = log.CurrentLogFileSize;
            if (size < LOG_FILE_MAX_BYTES)
                return;

            log.SuspendFileLoggingForToday("today's log file reached " + FormatMegabytes(size));

            AddEvent(WatchdogSeverity.Warning, Lang.L("Protokoll", "Log"), Lang.L("Die heutige Protokolldatei hat " + FormatMegabytes(size, Lang.German) + " erreicht. Das Datei-Protokoll ist bis Mitternacht pausiert, damit die Platte nicht vollläuft. Häufig ist das Protokollieren aller Anfragen eingeschaltet.", "Today's log file reached " + FormatMegabytes(size, Lang.English) + ". File logging is paused until midnight so that the disk does not fill up. Often logging of all queries is turned on."), "today's log file reached " + FormatMegabytes(size) + "; file logging suspended until midnight.");
        }

        private void CheckMemory(DateTime utcNow)
        {
            if ((utcNow - _lastMemoryAction) < MEMORY_COOLDOWN)
                return;

            GCMemoryInfo memoryInfo = GC.GetGCMemoryInfo();
            long total = memoryInfo.TotalAvailableMemoryBytes;
            long load = memoryInfo.MemoryLoadBytes;

            if ((total <= 0) || (load < (total * MEMORY_LOAD_CRITICAL)))
                return;

            long cacheEntries = _dnsServer.CacheZoneManager.TotalEntries;
            if (cacheEntries < 10000)
                return;

            _lastMemoryAction = utcNow;

            long workingSetBefore = Environment.WorkingSet;
            int removed = _dnsServer.CacheZoneManager.TrimEntries((long)(cacheEntries * CACHE_TRIM_RATIO));

            GC.Collect(2, GCCollectionMode.Aggressive, true, true);

            long workingSetAfter = Environment.WorkingSet;

            AddEvent(WatchdogSeverity.Critical, Lang.L("Arbeitsspeicher", "Memory"), Lang.L("Der Arbeitsspeicher war zu " + (load * 100 / total) + " % belegt. " + FormatCount(removed, Lang.German) + " selten genutzte Cache-Einträge wurden entfernt, der Prozess belegt jetzt " + FormatMegabytes(workingSetAfter, Lang.German) + " statt " + FormatMegabytes(workingSetBefore, Lang.German) + ". Dauerhaft hilft ein kleinerer Höchstwert für Cache-Einträge.", "Memory was " + (load * 100 / total) + " % full. " + FormatCount(removed, Lang.English) + " rarely used cache entries were removed, the process now uses " + FormatMegabytes(workingSetAfter, Lang.English) + " instead of " + FormatMegabytes(workingSetBefore, Lang.English) + ". A lower maximum for cache entries helps permanently."), "memory load at " + (load * 100 / total) + "%; removed " + removed + " cache entries, working set " + FormatMegabytes(workingSetBefore) + " -> " + FormatMegabytes(workingSetAfter) + ".");
        }

        private void CheckStatsQueue(DateTime utcNow)
        {
            StatsManager statsManager = _dnsServer.StatsManager;
            if ((statsManager is null) || ((utcNow - _lastStatsQueueAction) < STATS_QUEUE_COOLDOWN))
                return;

            int length = statsManager.QueueLength;
            if (length < STATS_QUEUE_MAX)
                return;

            _lastStatsQueueAction = utcNow;

            int dropped = statsManager.DropQueuedItems();

            AddEvent(WatchdogSeverity.Warning, Lang.L("Statistik", "Statistics"), Lang.L(FormatCount(dropped, Lang.German) + " noch nicht ausgewertete Einträge der Statistik wurden verworfen, weil die Warteschlange nicht mehr abgearbeitet wurde. Meist schreibt eine Query-Logs-App zu langsam in ihre Datenbank.", FormatCount(dropped, Lang.English) + " unprocessed statistics entries were dropped because the queue was no longer being processed. Usually a query logs app writes to its database too slowly."), "stats queue reached " + length + " items; dropped " + dropped + " items.");
        }

        private void CheckThreadPool(DateTime utcNow)
        {
            if (ThreadPool.PendingWorkItemCount < THREAD_POOL_QUEUE_HIGH)
            {
                _threadPoolStreak = 0;
                return;
            }

            if (++_threadPoolStreak < THREAD_POOL_STREAK)
                return;

            if ((utcNow - _lastThreadPoolAction) < THREAD_POOL_COOLDOWN)
                return;

            ThreadPool.GetMinThreads(out int workerThreads, out int completionPortThreads);

            if (workerThreads >= MAX_MIN_WORKER_THREADS)
                return;

            int newWorkerThreads = Math.Min(MAX_MIN_WORKER_THREADS, workerThreads + (Environment.ProcessorCount * 4));

            if (!ThreadPool.SetMinThreads(newWorkerThreads, completionPortThreads))
                return;

            _lastThreadPoolAction = utcNow;
            _threadPoolStreak = 0;

            AddEvent(WatchdogSeverity.Warning, Lang.L("Threadpool", "Thread pool"), Lang.L("Im Threadpool warteten über 30 Sekunden mehr als " + THREAD_POOL_QUEUE_HIGH + " Aufgaben. Die Mindestzahl der Threads wurde von " + workerThreads + " auf " + newWorkerThreads + " erhöht, damit Anfragen nicht liegen bleiben.", "More than " + THREAD_POOL_QUEUE_HIGH + " tasks waited in the thread pool for over 30 seconds. The minimum number of threads was raised from " + workerThreads + " to " + newWorkerThreads + " so that queries do not get stuck."), "thread pool queue stayed above " + THREAD_POOL_QUEUE_HIGH + "; minimum worker threads raised from " + workerThreads + " to " + newWorkerThreads + ".");
        }

        private async Task CheckListenersAsync(DateTime utcNow)
        {
            if (!_dnsServer.IsRunning)
            {
                _listenerStreak = 0;
                return;
            }

            List<string> inactive = new List<string>();

            foreach ((string name, bool isActive) in _dnsServer.GetListenerStatus())
            {
                if (!isActive)
                    inactive.Add(name);
            }

            if (inactive.Count == 0)
            {
                _listenerStreak = 0;
                return;
            }

            if (++_listenerStreak < LISTENER_STREAK)
                return;

            if ((_listenerRestarts >= MAX_LISTENER_RESTARTS) || ((utcNow - _lastListenerRestart) < LISTENER_COOLDOWN))
                return;

            _listenerRestarts++;
            _lastListenerRestart = utcNow;
            _listenerStreak = 0;

            string names = string.Join(", ", inactive);

            AddEvent(WatchdogSeverity.Critical, Lang.L("Dienste", "Services"), Lang.L("Nicht aktiv: " + names + ". Die DNS-Dienste werden neu gestartet (Versuch " + _listenerRestarts + " von " + MAX_LISTENER_RESTARTS + "), etwa weil ein anderer Dienst den Port beim Start belegt hatte.", "Not active: " + names + ". The DNS services are being restarted (attempt " + _listenerRestarts + " of " + MAX_LISTENER_RESTARTS + "), for example because another service occupied the port at startup."), "listeners not active (" + names + "); restarting DNS service, attempt " + _listenerRestarts + " of " + MAX_LISTENER_RESTARTS + ".");

            await _dnsServer.StopAsync();
            await _dnsServer.StartAsync();
        }

        private async void TimerCallback(object state)
        {
            if (Interlocked.Exchange(ref _checking, 1) == 1)
                return;

            try
            {
                DateTime utcNow = DateTime.UtcNow;

                CheckDiskSpace(utcNow);
                CheckLogFileSize();
                CheckMemory(utcNow);
                CheckStatsQueue(utcNow);
                CheckThreadPool(utcNow);
                await CheckListenersAsync(utcNow);
            }
            catch (Exception ex)
            {
                _dnsServer.LogManager?.Write(ex);
            }
            finally
            {
                Volatile.Write(ref _checking, 0);
            }
        }

        #endregion

        #region public

        public IReadOnlyList<WatchdogEvent> GetEvents()
        {
            lock (_lock)
            {
                return new List<WatchdogEvent>(_events);
            }
        }

        #endregion

        #region properties

        public bool Enabled
        {
            get
            {
                lock (_lock)
                {
                    return _timer is not null;
                }
            }
            set
            {
                lock (_lock)
                {
                    if (_disposed)
                        return;

                    if (value)
                    {
                        if (_timer is null)
                            _timer = new Timer(TimerCallback, null, CHECK_INTERVAL * 3, CHECK_INTERVAL);
                    }
                    else
                    {
                        _timer?.Dispose();
                        _timer = null;
                    }
                }
            }
        }

        #endregion
    }

    enum WatchdogSeverity
    {
        Warning,
        Critical
    }

    sealed record WatchdogEvent(DateTime Time, WatchdogSeverity Severity, LocalizedText Title, LocalizedText Message);
}
