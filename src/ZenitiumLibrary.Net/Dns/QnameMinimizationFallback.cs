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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Threading;

namespace ZenitiumLibrary.Net.Dns
{
    public static class QnameMinimizationFallback
    {
        #region variables

        const int MAX_ZONES = 10000;
        static readonly long REMEMBER_TICKS = Stopwatch.Frequency * 3600;

        static volatile bool _enabled = true;
        static readonly ConcurrentDictionary<string, long> _zones = new ConcurrentDictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        static long _fallbacks;
        static long _skipped;

        #endregion

        #region internal

        internal static bool IsFallbackZone(string zoneCut)
        {
            if (!_enabled || string.IsNullOrEmpty(zoneCut))
                return false;

            if (!_zones.TryGetValue(zoneCut, out long expires))
                return false;

            if (expires < Stopwatch.GetTimestamp())
            {
                _zones.TryRemove(zoneCut, out _);
                return false;
            }

            Interlocked.Increment(ref _skipped);
            return true;
        }

        internal static void CountFallback()
        {
            Interlocked.Increment(ref _fallbacks);
        }

        internal static void Remember(IReadOnlyList<string> zoneCuts)
        {
            if (!_enabled)
                return;

            long expires = Stopwatch.GetTimestamp() + REMEMBER_TICKS;

            foreach (string zoneCut in zoneCuts)
            {
                if (string.IsNullOrEmpty(zoneCut))
                    continue;

                if (_zones.Count >= MAX_ZONES)
                    _zones.Clear();

                _zones[zoneCut] = expires;
            }
        }

        #endregion

        #region public

        public static void Clear()
        {
            _zones.Clear();
        }

        public static IReadOnlyList<string> GetZones()
        {
            long now = Stopwatch.GetTimestamp();
            List<string> zones = new List<string>(_zones.Count);

            foreach (KeyValuePair<string, long> entry in _zones)
            {
                if (entry.Value >= now)
                    zones.Add(entry.Key);
            }

            zones.Sort(StringComparer.OrdinalIgnoreCase);
            return zones;
        }

        #endregion

        #region properties

        public static bool Enabled
        {
            get { return _enabled; }
            set
            {
                if (!value)
                    _zones.Clear();

                _enabled = value;
            }
        }

        public static int Zones
        { get { return _zones.Count; } }

        public static long Fallbacks
        { get { return Interlocked.Read(ref _fallbacks); } }

        public static long Skipped
        { get { return Interlocked.Read(ref _skipped); } }

        #endregion
    }
}
