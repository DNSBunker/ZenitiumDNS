/*
Technitium DNS Server
Copyright (C) 2025  Shreyas Zare (shreyas@technitium.com)

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

namespace ZenitiumDns.Core.Dns
{
    public enum DashboardStatsType
    {
        Unknown = 0,
        LastHour = 1,
        LastDay = 2,
        LastWeek = 3,
        LastMonth = 4,
        LastYear = 5,
        Custom = 6
    }

    public enum DashboardTopStatsType
    {
        Unknown = 0,
        TopClients = 1,
        TopDomains = 2,
        TopBlockedDomains = 3
    }

    public class DashboardStats
    {
        public StatsData Stats { get; set; }
        public ChartData MainChartData { get; set; }
        public ChartData QueryResponseChartData { get; set; }
        public ChartData QueryTypeChartData { get; set; }
        public ChartData ProtocolTypeChartData { get; set; }
        public TopClientStats[] TopClients { get; set; }
        public TopStats[] TopDomains { get; set; }
        public TopStats[] TopBlockedDomains { get; set; }

        public class StatsData
        {
            public long TotalQueries { get; set; }
            public long TotalNoError { get; set; }
            public long TotalServerFailure { get; set; }
            public long TotalNxDomain { get; set; }
            public long TotalRefused { get; set; }
            public long TotalAuthoritative { get; set; }
            public long TotalRecursive { get; set; }
            public long TotalCached { get; set; }
            public long TotalBlocked { get; set; }
            public long TotalDropped { get; set; }
            public long TotalClients { get; set; }
            public int Zones { get; set; }
            public long CachedEntries { get; set; }
            public int AllowedZones { get; set; }
            public int BlockedZones { get; set; }
            public int AllowListZones { get; set; }
            public int BlockListZones { get; set; }
        }

        public class ChartData
        {
            public required string[] Labels { get; set; }
            public required DataSet[] DataSets { get; set; }

            public void Trim(int limit)
            {
                if (Labels.Length <= limit)
                    return;

                string[] newLabels = Labels[..limit];
                newLabels[limit - 1] = "Others";
                Labels = newLabels;

                foreach (DataSet dataSet in DataSets)
                    dataSet.Trim(limit);
            }
        }

        public class DataSet
        {
            public string Label { get; set; }
            public required long[] Data { get; set; }

            public void Trim(int limit)
            {
                if (Data.Length <= limit)
                    return;

                long othersCount = 0;

                for (int i = limit - 1; i < Data.Length; i++)
                    othersCount += Data[i];

                long[] newData = Data[..limit];
                newData[limit - 1] = othersCount;
                Data = newData;
            }
        }

        public class TopStats
        {
            public required string Name { get; set; }
            public required long Hits { get; set; }
        }

        public class TopClientStats : TopStats
        {
            public string Domain { get; set; }
            public bool RateLimited { get; set; }
        }
    }
}
