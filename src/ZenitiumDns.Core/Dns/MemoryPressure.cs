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
using System.Globalization;
using System.IO;

namespace ZenitiumDns.Core.Dns
{
    readonly struct MemoryPressureReading
    {
        public MemoryPressureReading(double ratio, long used, long limit, string source)
        {
            Ratio = ratio;
            Used = used;
            Limit = limit;
            Source = source;
        }

        public double Ratio { get; }

        public long Used { get; }

        public long Limit { get; }

        public string Source { get; }
    }

    static class MemoryPressure
    {
        #region variables

        const long UNLIMITED = long.MaxValue / 2;
        const double HEAP_USABLE_FRACTION = 0.85;

        static readonly object _lock = new object();
        static List<string> _cgroupV2Directories;
        static string _cgroupV1Directory;
        static bool _initialized;

        #endregion

        #region private

        private static void Initialize()
        {
            lock (_lock)
            {
                if (_initialized)
                    return;

                _initialized = true;

                if (!OperatingSystem.IsLinux())
                    return;

                try
                {
                    foreach (string line in File.ReadAllLines("/proc/self/cgroup"))
                    {
                        string[] parts = line.Split(':', 3);
                        if (parts.Length != 3)
                            continue;

                        if ((parts[0] == "0") && (parts[1].Length == 0))
                        {
                            List<string> directories = new List<string>();
                            string path = parts[2].Trim();

                            while (true)
                            {
                                string directory = "/sys/fs/cgroup" + (path == "/" ? "" : path);

                                if (Directory.Exists(directory))
                                    directories.Add(directory);

                                if ((path == "/") || (path.Length == 0))
                                    break;

                                int slash = path.LastIndexOf('/');
                                path = slash <= 0 ? "/" : path.Substring(0, slash);
                            }

                            if (directories.Count > 0)
                                _cgroupV2Directories = directories;
                        }
                        else if (parts[1].Split(',').AsSpan().Contains("memory"))
                        {
                            string directory = "/sys/fs/cgroup/memory" + (parts[2] == "/" ? "" : parts[2]);

                            if (!File.Exists(Path.Combine(directory, "memory.limit_in_bytes")))
                                directory = "/sys/fs/cgroup/memory";

                            if (File.Exists(Path.Combine(directory, "memory.limit_in_bytes")))
                                _cgroupV1Directory = directory;
                        }
                    }
                }
                catch
                { }
            }
        }

        private static long ReadLong(string file)
        {
            try
            {
                string text = File.ReadAllText(file).Trim();

                if (text == "max")
                    return UNLIMITED;

                if (long.TryParse(text, NumberStyles.None, CultureInfo.InvariantCulture, out long value))
                    return value;
            }
            catch
            { }

            return -1;
        }

        private static long ReadStat(string file, string key)
        {
            try
            {
                foreach (string line in File.ReadLines(file))
                {
                    if (line.StartsWith(key, StringComparison.Ordinal) && (line.Length > key.Length) && (line[key.Length] == ' '))
                    {
                        if (long.TryParse(line.AsSpan(key.Length + 1).Trim(), NumberStyles.None, CultureInfo.InvariantCulture, out long value))
                            return value;
                    }
                }
            }
            catch
            { }

            return 0;
        }

        private static void Consider(ref MemoryPressureReading worst, ref long smallestLimit, long used, long limit, string source)
        {
            if ((limit <= 0) || (limit >= UNLIMITED) || (used < 0))
                return;

            if (limit < smallestLimit)
                smallestLimit = limit;

            double ratio = (double)used / limit;

            if (ratio > worst.Ratio)
                worst = new MemoryPressureReading(ratio, used, limit, source);
        }

        #endregion

        #region public

        public static MemoryPressureReading Read()
        {
            Initialize();

            MemoryPressureReading worst = new MemoryPressureReading(0, 0, 0, "none");
            long smallestLimit = long.MaxValue;

            if (OperatingSystem.IsLinux())
            {
                long total = 0;
                long available = -1;

                try
                {
                    foreach (string line in File.ReadLines("/proc/meminfo"))
                    {
                        if (line.StartsWith("MemTotal:", StringComparison.Ordinal))
                            total = ParseMeminfo(line);
                        else if (line.StartsWith("MemAvailable:", StringComparison.Ordinal))
                            available = ParseMeminfo(line);

                        if ((total > 0) && (available >= 0))
                            break;
                    }
                }
                catch
                { }

                if ((total > 0) && (available >= 0))
                    Consider(ref worst, ref smallestLimit, total - available, total, "system");

                List<string> directories = _cgroupV2Directories;

                if (directories is not null)
                {
                    foreach (string directory in directories)
                    {
                        long max = ReadLong(Path.Combine(directory, "memory.max"));
                        if ((max <= 0) || (max >= UNLIMITED))
                            continue;

                        long current = ReadLong(Path.Combine(directory, "memory.current"));
                        if (current < 0)
                            continue;

                        long inactiveFile = ReadStat(Path.Combine(directory, "memory.stat"), "inactive_file");
                        Consider(ref worst, ref smallestLimit, Math.Max(0, current - inactiveFile), max, "cgroup");
                    }
                }
                else if (_cgroupV1Directory is not null)
                {
                    long limit = ReadLong(Path.Combine(_cgroupV1Directory, "memory.limit_in_bytes"));
                    long usage = ReadLong(Path.Combine(_cgroupV1Directory, "memory.usage_in_bytes"));
                    long inactiveFile = ReadStat(Path.Combine(_cgroupV1Directory, "memory.stat"), "total_inactive_file");

                    if ((limit > 0) && (limit < (1L << 60)) && (usage >= 0))
                        Consider(ref worst, ref smallestLimit, Math.Max(0, usage - inactiveFile), limit, "cgroup");
                }
            }
            else
            {
                GCMemoryInfo info = GC.GetGCMemoryInfo();
                Consider(ref worst, ref smallestLimit, info.MemoryLoadBytes, info.TotalAvailableMemoryBytes, "system");
            }

            GCMemoryInfo gcInfo = GC.GetGCMemoryInfo();
            long heapLimit = gcInfo.TotalAvailableMemoryBytes;

            if ((heapLimit > 0) && (heapLimit < smallestLimit * 0.95))
                Consider(ref worst, ref smallestLimit, gcInfo.HeapSizeBytes, (long)(heapLimit * HEAP_USABLE_FRACTION), "heap");

            return worst;
        }

        private static long ParseMeminfo(string line)
        {
            int colon = line.IndexOf(':');
            string value = line.Substring(colon + 1).Trim();

            if (value.EndsWith(" kB", StringComparison.Ordinal))
                value = value.Substring(0, value.Length - 3);

            if (long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out long kb))
                return kb * 1024;

            return -1;
        }

        #endregion
    }
}
