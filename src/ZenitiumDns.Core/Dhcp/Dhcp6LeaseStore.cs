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
using System.Net.Sockets;
using System.Text.Json;
using System.Threading;

namespace ZenitiumDns.Core.Dhcp
{
    public sealed class Dhcp6Lease
    {
        public IPAddress Address { get; init; }

        public byte[] Duid { get; init; } = [];

        public uint Iaid { get; init; }

        public byte[] HardwareAddress { get; init; } = [];

        public string ClientHostName { get; init; }

        public string HostName { get; init; }

        public string Interface { get; init; }

        public DateTime Start { get; init; }

        public DateTime Expires { get; init; }

        public DhcpLeaseState State { get; init; }

        public bool Reserved { get; init; }

        public DateTime Updated { get; init; }

        public string ClientKey
        { get { return GetClientKey(Duid, Iaid); } }

        public bool IsInfinite
        { get { return Expires == DateTime.MaxValue; } }

        public bool IsActive(DateTime utcNow)
        {
            return ((State == DhcpLeaseState.Bound) || (State == DhcpLeaseState.Offered)) && (Expires > utcNow);
        }

        public static string GetClientKey(byte[] duid, uint iaid)
        {
            return Convert.ToHexString(duid) + "/" + iaid.ToString("x8");
        }

        public Dhcp6Lease With(DhcpLeaseState state, DateTime expires, DateTime updated)
        {
            return new Dhcp6Lease()
            {
                Address = Address,
                Duid = Duid,
                Iaid = Iaid,
                HardwareAddress = HardwareAddress,
                ClientHostName = ClientHostName,
                HostName = HostName,
                Interface = Interface,
                Start = Start,
                Expires = expires,
                State = state,
                Reserved = Reserved,
                Updated = updated
            };
        }

        public void WriteTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            writer.WriteString("address", Address.ToString());
            writer.WriteString("duid", DhcpUtilities.FormatHex(Duid));
            writer.WriteNumber("iaid", Iaid);

            if (HardwareAddress.Length > 0)
                writer.WriteString("hwaddr", DhcpUtilities.FormatHardwareAddress(HardwareAddress));

            if (ClientHostName is not null)
                writer.WriteString("clientHostName", ClientHostName);

            if (HostName is not null)
                writer.WriteString("hostName", HostName);

            if (Interface is not null)
                writer.WriteString("interface", Interface);

            writer.WriteNumber("start", DhcpLease.ToUnix(Start));
            writer.WriteNumber("expires", DhcpLease.ToUnix(Expires));
            writer.WriteString("state", State.ToString().ToLowerInvariant());
            writer.WriteBoolean("reserved", Reserved);
            writer.WriteNumber("updated", DhcpLease.ToUnix(Updated));
            writer.WriteEndObject();
        }

        public static Dhcp6Lease ReadFrom(JsonElement element)
        {
            IPAddress address = IPAddress.Parse(element.GetProperty("address").GetString());
            if (address.AddressFamily != AddressFamily.InterNetworkV6)
                throw new InvalidDataException("not an IPv6 address");

            if (!DhcpUtilities.TryParseHex(element.GetProperty("duid").GetString(), out byte[] duid) || (duid.Length < 2) || (duid.Length > 130))
                throw new InvalidDataException("invalid DUID");

            byte[] hardwareAddress = [];
            if (element.TryGetProperty("hwaddr", out JsonElement jsonHw) && !DhcpUtilities.TryParseHex(jsonHw.GetString(), out hardwareAddress))
                hardwareAddress = [];

            if (!Enum.TryParse(element.GetProperty("state").GetString(), true, out DhcpLeaseState state))
                throw new InvalidDataException("invalid lease state");

            return new Dhcp6Lease()
            {
                Address = address,
                Duid = duid,
                Iaid = element.GetProperty("iaid").GetUInt32(),
                HardwareAddress = hardwareAddress,
                ClientHostName = element.TryGetProperty("clientHostName", out JsonElement jsonClientName) ? jsonClientName.GetString() : null,
                HostName = element.TryGetProperty("hostName", out JsonElement jsonName) ? jsonName.GetString() : null,
                Interface = element.TryGetProperty("interface", out JsonElement jsonInterface) ? jsonInterface.GetString() : null,
                Start = DhcpLease.FromUnix(element.GetProperty("start").GetInt64()),
                Expires = DhcpLease.FromUnix(element.GetProperty("expires").GetInt64()),
                State = state,
                Reserved = element.TryGetProperty("reserved", out JsonElement jsonReserved) && jsonReserved.GetBoolean(),
                Updated = DhcpLease.FromUnix(element.GetProperty("updated").GetInt64())
            };
        }
    }

    public sealed class Dhcp6LeaseStore : IDisposable
    {
        #region variables

        const int FILE_VERSION = 1;
        const int SAVE_DELAY_MS = 1000;
        static readonly TimeSpan EXPIRED_RETENTION = TimeSpan.FromDays(30);

        readonly object _lock = new object();
        readonly string _file;
        readonly Action<string, Exception> _log;

        readonly Dictionary<UInt128, Dhcp6Lease> _byAddress = new Dictionary<UInt128, Dhcp6Lease>();
        readonly Dictionary<string, List<UInt128>> _byClient = new Dictionary<string, List<UInt128>>(StringComparer.Ordinal);

        readonly Timer _saveTimer;
        bool _savePending;
        bool _disposed;

        #endregion

        #region constructor

        public Dhcp6LeaseStore(string file, Action<string, Exception> log)
        {
            _file = file;
            _log = log;
            _saveTimer = new Timer(delegate (object state) { SaveNow(); });
        }

        #endregion

        #region IDisposable

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            _saveTimer.Dispose();
            SaveNow();
        }

        #endregion

        #region private

        private void IndexAdd(Dhcp6Lease lease)
        {
            UInt128 key = Dhcp6Utilities.ToUInt128(lease.Address);

            if (_byAddress.TryGetValue(key, out Dhcp6Lease existing))
                IndexRemoveClient(existing.ClientKey, key);

            _byAddress[key] = lease;

            string clientKey = lease.ClientKey;

            if (!_byClient.TryGetValue(clientKey, out List<UInt128> list))
            {
                list = new List<UInt128>(1);
                _byClient.Add(clientKey, list);
            }

            if (!list.Contains(key))
                list.Add(key);
        }

        private void IndexRemoveClient(string clientKey, UInt128 address)
        {
            if (_byClient.TryGetValue(clientKey, out List<UInt128> list))
            {
                list.Remove(address);

                if (list.Count == 0)
                    _byClient.Remove(clientKey);
            }
        }

        private void IndexRemove(UInt128 address)
        {
            if (_byAddress.Remove(address, out Dhcp6Lease existing))
                IndexRemoveClient(existing.ClientKey, address);
        }

        private void ScheduleSave()
        {
            if (_disposed || (_file is null))
                return;

            if (!_savePending)
            {
                _savePending = true;
                _saveTimer.Change(SAVE_DELAY_MS, Timeout.Infinite);
            }
        }

        private byte[] Serialize()
        {
            using (MemoryStream mS = new MemoryStream())
            {
                using (Utf8JsonWriter writer = new Utf8JsonWriter(mS))
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("version", FILE_VERSION);
                    writer.WriteStartArray("leases");

                    foreach (Dhcp6Lease lease in _byAddress.Values)
                    {
                        if (lease.State == DhcpLeaseState.Offered)
                            continue;

                        lease.WriteTo(writer);
                    }

                    writer.WriteEndArray();
                    writer.WriteEndObject();
                }

                return mS.ToArray();
            }
        }

        #endregion

        #region public

        public event Action<Dhcp6Lease> LeaseChanged;

        public void Load()
        {
            if ((_file is null) || !File.Exists(_file))
                return;

            try
            {
                List<Dhcp6Lease> leases = ParseSnapshot(File.ReadAllBytes(_file), delegate (string message) { _log("DHCP Server skipped an invalid IPv6 lease in " + _file + ": " + message, null); });

                lock (_lock)
                {
                    _byAddress.Clear();
                    _byClient.Clear();

                    foreach (Dhcp6Lease lease in leases)
                        IndexAdd(lease);
                }
            }
            catch (Exception ex)
            {
                _log("DHCP Server failed to load the lease file " + _file, ex);

                try
                {
                    File.Copy(_file, _file + ".invalid", true);
                }
                catch
                { }
            }
        }

        public void SaveNow()
        {
            if (_file is null)
                return;

            byte[] data;

            lock (_lock)
            {
                _savePending = false;
                data = Serialize();
            }

            try
            {
                string tmpFile = _file + ".tmp";

                using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.Write, FileShare.None))
                {
                    fS.Write(data);
                    fS.Flush(true);
                }

                File.Move(tmpFile, _file, true);
            }
            catch (Exception ex)
            {
                _log("DHCP Server failed to save the lease file " + _file, ex);
            }
        }

        public Dhcp6Lease Get(IPAddress address)
        {
            lock (_lock)
            {
                _byAddress.TryGetValue(Dhcp6Utilities.ToUInt128(address), out Dhcp6Lease lease);
                return lease;
            }
        }

        public Dhcp6Lease Get(UInt128 address)
        {
            lock (_lock)
            {
                _byAddress.TryGetValue(address, out Dhcp6Lease lease);
                return lease;
            }
        }

        public List<Dhcp6Lease> GetByClient(string clientKey)
        {
            List<Dhcp6Lease> result = new List<Dhcp6Lease>();

            lock (_lock)
            {
                if (_byClient.TryGetValue(clientKey, out List<UInt128> list))
                {
                    foreach (UInt128 address in list)
                    {
                        if (_byAddress.TryGetValue(address, out Dhcp6Lease lease))
                            result.Add(lease);
                    }
                }
            }

            return result;
        }

        public bool TryPut(Dhcp6Lease lease, Func<Dhcp6Lease, bool> canReplace)
        {
            UInt128 key = Dhcp6Utilities.ToUInt128(lease.Address);
            bool changed;

            lock (_lock)
            {
                if (_byAddress.TryGetValue(key, out Dhcp6Lease existing) && (canReplace is not null) && !canReplace(existing))
                    return false;

                changed = (existing is null) || (existing.State != lease.State) || (existing.HostName != lease.HostName) || (existing.Expires != lease.Expires);
                IndexAdd(lease);
            }

            if (lease.State != DhcpLeaseState.Offered)
                ScheduleSave();

            if (changed)
                LeaseChanged?.Invoke(lease);

            return true;
        }

        public void Put(Dhcp6Lease lease)
        {
            TryPut(lease, null);
        }

        public bool Remove(IPAddress address)
        {
            Dhcp6Lease removed;

            lock (_lock)
            {
                UInt128 key = Dhcp6Utilities.ToUInt128(address);

                if (!_byAddress.TryGetValue(key, out removed))
                    return false;

                IndexRemove(key);
            }

            ScheduleSave();
            LeaseChanged?.Invoke(removed);
            return true;
        }

        public void ReplaceAll(IEnumerable<Dhcp6Lease> leases)
        {
            lock (_lock)
            {
                _byAddress.Clear();
                _byClient.Clear();

                foreach (Dhcp6Lease lease in leases)
                    IndexAdd(lease);
            }

            ScheduleSave();
            LeaseChanged?.Invoke(null);
        }

        public List<Dhcp6Lease> GetAll()
        {
            lock (_lock)
            {
                return new List<Dhcp6Lease>(_byAddress.Values);
            }
        }

        public int Count
        {
            get
            {
                lock (_lock)
                {
                    return _byAddress.Count;
                }
            }
        }

        public int CountActive(DateTime utcNow)
        {
            int count = 0;

            lock (_lock)
            {
                foreach (Dhcp6Lease lease in _byAddress.Values)
                {
                    if ((lease.State == DhcpLeaseState.Bound) && lease.IsActive(utcNow))
                        count++;
                }
            }

            return count;
        }

        public void Maintain(DateTime utcNow)
        {
            List<Dhcp6Lease> changed = new List<Dhcp6Lease>();

            lock (_lock)
            {
                List<UInt128> remove = new List<UInt128>();

                foreach (KeyValuePair<UInt128, Dhcp6Lease> entry in _byAddress)
                {
                    Dhcp6Lease lease = entry.Value;

                    switch (lease.State)
                    {
                        case DhcpLeaseState.Offered:
                            if (lease.Expires <= utcNow)
                                remove.Add(entry.Key);

                            break;

                        case DhcpLeaseState.Bound:
                            if (!lease.IsInfinite && (lease.Expires <= utcNow))
                                changed.Add(lease.With(DhcpLeaseState.Expired, lease.Expires, utcNow));

                            break;

                        case DhcpLeaseState.Declined:
                            if (lease.Expires <= utcNow)
                                remove.Add(entry.Key);

                            break;

                        default:
                            if (lease.Updated.Add(EXPIRED_RETENTION) <= utcNow)
                                remove.Add(entry.Key);

                            break;
                    }
                }

                foreach (UInt128 key in remove)
                    IndexRemove(key);

                foreach (Dhcp6Lease lease in changed)
                    IndexAdd(lease);

                if ((remove.Count > 0) || (changed.Count > 0))
                    ScheduleSave();
            }

            foreach (Dhcp6Lease lease in changed)
                LeaseChanged?.Invoke(lease);
        }

        public byte[] ExportSnapshot()
        {
            lock (_lock)
            {
                return Serialize();
            }
        }

        public static List<Dhcp6Lease> ParseSnapshot(byte[] data, Action<string> skipped = null)
        {
            List<Dhcp6Lease> leases = new List<Dhcp6Lease>();

            using (JsonDocument document = JsonDocument.Parse(data))
            {
                JsonElement root = document.RootElement;

                if (root.GetProperty("version").GetInt32() != FILE_VERSION)
                    throw new InvalidDataException("unsupported lease file version");

                int skippedCount = 0;

                foreach (JsonElement jsonLease in root.GetProperty("leases").EnumerateArray())
                {
                    try
                    {
                        leases.Add(Dhcp6Lease.ReadFrom(jsonLease));
                    }
                    catch (Exception ex)
                    {
                        skippedCount++;

                        if ((skipped is not null) && (skippedCount <= 5))
                            skipped(ex.Message);
                    }
                }
            }

            return leases;
        }

        #endregion
    }
}
