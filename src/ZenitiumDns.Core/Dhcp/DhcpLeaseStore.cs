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
using System.Text.Json;
using System.Threading;

namespace ZenitiumDns.Core.Dhcp
{
    public enum DhcpLeaseState : byte
    {
        Free = 0,
        Offered = 1,
        Bound = 2,
        Released = 3,
        Expired = 4,
        Declined = 5
    }

    public sealed class DhcpLease
    {
        public IPAddress Address { get; init; }

        public string ClientKey { get; init; }

        public byte HardwareType { get; init; }

        public byte[] HardwareAddress { get; init; } = [];

        public byte[] ClientId { get; init; }

        public string ClientHostName { get; init; }

        public string HostName { get; init; }

        public string VendorClass { get; init; }

        public DateTime Start { get; init; }

        public DateTime Expires { get; init; }

        public DhcpLeaseState State { get; init; }

        public bool Reserved { get; init; }

        public long Sequence { get; init; }

        public string NodeId { get; init; }

        public DateTime Updated { get; init; }

        public bool IsInfinite
        { get { return Expires == DateTime.MaxValue; } }

        public bool IsActive(DateTime utcNow)
        {
            return ((State == DhcpLeaseState.Bound) || (State == DhcpLeaseState.Offered)) && (Expires > utcNow);
        }

        public DhcpLease With(DhcpLeaseState state, DateTime expires, DateTime updated)
        {
            return new DhcpLease()
            {
                Address = Address,
                ClientKey = ClientKey,
                HardwareType = HardwareType,
                HardwareAddress = HardwareAddress,
                ClientId = ClientId,
                ClientHostName = ClientHostName,
                HostName = HostName,
                VendorClass = VendorClass,
                Start = Start,
                Expires = expires,
                State = state,
                Reserved = Reserved,
                Sequence = Sequence,
                NodeId = NodeId,
                Updated = updated
            };
        }

        public DhcpLease WithSequence(long sequence, string nodeId)
        {
            return new DhcpLease()
            {
                Address = Address,
                ClientKey = ClientKey,
                HardwareType = HardwareType,
                HardwareAddress = HardwareAddress,
                ClientId = ClientId,
                ClientHostName = ClientHostName,
                HostName = HostName,
                VendorClass = VendorClass,
                Start = Start,
                Expires = Expires,
                State = State,
                Reserved = Reserved,
                Sequence = sequence,
                NodeId = nodeId,
                Updated = Updated
            };
        }

        public void WriteTo(Utf8JsonWriter writer)
        {
            writer.WriteStartObject();
            writer.WriteString("address", Address.ToString());
            writer.WriteString("client", ClientKey);
            writer.WriteNumber("htype", HardwareType);
            writer.WriteString("hwaddr", DhcpUtilities.FormatHardwareAddress(HardwareAddress));

            if ((ClientId is not null) && (ClientId.Length > 0))
                writer.WriteString("clientId", DhcpUtilities.FormatHex(ClientId));

            if (ClientHostName is not null)
                writer.WriteString("clientHostName", ClientHostName);

            if (HostName is not null)
                writer.WriteString("hostName", HostName);

            if (VendorClass is not null)
                writer.WriteString("vendorClass", VendorClass);

            writer.WriteNumber("start", ToUnix(Start));
            writer.WriteNumber("expires", IsInfinite ? -1 : ToUnix(Expires));
            writer.WriteNumber("state", (byte)State);

            if (Reserved)
                writer.WriteBoolean("reserved", true);

            writer.WriteNumber("seq", Sequence);

            if (NodeId is not null)
                writer.WriteString("node", NodeId);

            writer.WriteNumber("updated", ToUnix(Updated));
            writer.WriteEndObject();
        }

        public static DhcpLease ReadFrom(JsonElement element)
        {
            IPAddress address = IPAddress.Parse(element.GetProperty("address").GetString());
            byte[] hardwareAddress = [];
            string hwaddr = element.GetProperty("hwaddr").GetString();

            if (!string.IsNullOrEmpty(hwaddr) && !DhcpUtilities.TryParseHex(hwaddr, out hardwareAddress))
                throw new FormatException("invalid hardware address " + hwaddr);

            byte[] clientId = null;
            if (element.TryGetProperty("clientId", out JsonElement jsonClientId) && !DhcpUtilities.TryParseHex(jsonClientId.GetString(), out clientId))
                throw new FormatException("invalid client id");

            long expires = element.GetProperty("expires").GetInt64();

            DhcpLease lease = new DhcpLease()
            {
                Address = address,
                ClientKey = element.GetProperty("client").GetString(),
                HardwareType = element.GetProperty("htype").GetByte(),
                HardwareAddress = hardwareAddress ?? [],
                ClientId = clientId,
                ClientHostName = element.TryGetProperty("clientHostName", out JsonElement jsonClientHostName) ? jsonClientHostName.GetString() : null,
                HostName = element.TryGetProperty("hostName", out JsonElement jsonHostName) ? jsonHostName.GetString() : null,
                VendorClass = element.TryGetProperty("vendorClass", out JsonElement jsonVendorClass) ? jsonVendorClass.GetString() : null,
                Start = FromUnix(element.GetProperty("start").GetInt64()),
                Expires = expires < 0 ? DateTime.MaxValue : FromUnix(expires),
                State = (DhcpLeaseState)element.GetProperty("state").GetByte(),
                Reserved = element.TryGetProperty("reserved", out JsonElement jsonReserved) && jsonReserved.GetBoolean(),
                Sequence = element.GetProperty("seq").GetInt64(),
                NodeId = element.TryGetProperty("node", out JsonElement jsonNode) ? jsonNode.GetString() : null,
                Updated = FromUnix(element.GetProperty("updated").GetInt64())
            };

            if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
                throw new FormatException("not an IPv4 address: " + address);

            if (string.IsNullOrEmpty(lease.ClientKey) && (lease.State != DhcpLeaseState.Free) && (lease.State != DhcpLeaseState.Declined))
                throw new FormatException("lease without client");

            if (!Enum.IsDefined(lease.State))
                throw new FormatException("invalid lease state");

            return lease;
        }

        public static long ToUnix(DateTime value)
        {
            if (value == DateTime.MaxValue)
                return -1;

            return new DateTimeOffset(DateTime.SpecifyKind(value, DateTimeKind.Utc)).ToUnixTimeSeconds();
        }

        public static DateTime FromUnix(long value)
        {
            if (value < 0)
                return DateTime.MaxValue;

            return DateTimeOffset.FromUnixTimeSeconds(value).UtcDateTime;
        }
    }

    public sealed class DhcpLeaseStore : IDisposable
    {
        #region variables

        const int FILE_VERSION = 1;
        const int SAVE_DELAY_MS = 1000;
        static readonly TimeSpan TOMBSTONE_RETENTION = TimeSpan.FromDays(7);
        static readonly TimeSpan EXPIRED_RETENTION = TimeSpan.FromDays(90);

        readonly object _lock = new object();
        readonly string _file;
        readonly Action<string, Exception> _log;

        readonly Dictionary<uint, DhcpLease> _byAddress = new Dictionary<uint, DhcpLease>();
        readonly Dictionary<string, List<uint>> _byClient = new Dictionary<string, List<uint>>(StringComparer.Ordinal);

        long _sequence;
        long _term;
        readonly string _nodeId;

        readonly Timer _saveTimer;
        bool _savePending;
        bool _disposed;

        #endregion

        #region constructor

        public DhcpLeaseStore(string file, string nodeId, Action<string, Exception> log)
        {
            _file = file;
            _nodeId = nodeId;
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

        private void IndexAdd(DhcpLease lease)
        {
            uint key = DhcpUtilities.ToUInt32(lease.Address);

            if (_byAddress.TryGetValue(key, out DhcpLease existing))
                IndexRemoveClient(existing.ClientKey, key);

            _byAddress[key] = lease;

            if (!string.IsNullOrEmpty(lease.ClientKey))
            {
                if (!_byClient.TryGetValue(lease.ClientKey, out List<uint> list))
                {
                    list = new List<uint>(1);
                    _byClient.Add(lease.ClientKey, list);
                }

                if (!list.Contains(key))
                    list.Add(key);
            }
        }

        private void IndexRemoveClient(string clientKey, uint address)
        {
            if (string.IsNullOrEmpty(clientKey))
                return;

            if (_byClient.TryGetValue(clientKey, out List<uint> list))
            {
                list.Remove(address);

                if (list.Count == 0)
                    _byClient.Remove(clientKey);
            }
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

        #endregion

        #region public

        public event Action<DhcpLease> LeaseChanged;

        public void Load()
        {
            if ((_file is null) || !File.Exists(_file))
                return;

            try
            {
                using (JsonDocument document = JsonDocument.Parse(File.ReadAllBytes(_file)))
                {
                    JsonElement root = document.RootElement;

                    if (root.GetProperty("version").GetInt32() != FILE_VERSION)
                        throw new InvalidDataException("unsupported lease file version");

                    lock (_lock)
                    {
                        _byAddress.Clear();
                        _byClient.Clear();
                        _sequence = root.GetProperty("sequence").GetInt64();
                        _term = root.TryGetProperty("term", out JsonElement jsonTerm) ? jsonTerm.GetInt64() : 0;

                        int skipped = 0;

                        foreach (JsonElement jsonLease in root.GetProperty("leases").EnumerateArray())
                        {
                            try
                            {
                                DhcpLease lease = DhcpLease.ReadFrom(jsonLease);
                                IndexAdd(lease);

                                if (lease.Sequence > _sequence)
                                    _sequence = lease.Sequence;
                            }
                            catch (Exception ex)
                            {
                                skipped++;

                                if (skipped <= 5)
                                    _log("DHCP Server skipped an invalid lease in " + _file + ": " + ex.Message, null);
                            }
                        }
                    }
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
                data = Serialize(false);
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

        private byte[] Serialize(bool includeOffered)
        {
            using (MemoryStream mS = new MemoryStream())
            {
                using (Utf8JsonWriter writer = new Utf8JsonWriter(mS))
                {
                    writer.WriteStartObject();
                    writer.WriteNumber("version", FILE_VERSION);
                    writer.WriteNumber("term", _term);
                    writer.WriteNumber("sequence", _sequence);
                    writer.WriteStartArray("leases");

                    foreach (DhcpLease lease in _byAddress.Values)
                    {
                        if (!includeOffered && (lease.State == DhcpLeaseState.Offered))
                            continue;

                        lease.WriteTo(writer);
                    }

                    writer.WriteEndArray();
                    writer.WriteEndObject();
                }

                return mS.ToArray();
            }
        }

        public DhcpLease Get(IPAddress address)
        {
            lock (_lock)
            {
                _byAddress.TryGetValue(DhcpUtilities.ToUInt32(address), out DhcpLease lease);
                return lease;
            }
        }

        public DhcpLease Get(uint address)
        {
            lock (_lock)
            {
                _byAddress.TryGetValue(address, out DhcpLease lease);
                return lease;
            }
        }

        public List<DhcpLease> GetByClient(string clientKey)
        {
            List<DhcpLease> result = new List<DhcpLease>();

            lock (_lock)
            {
                if (_byClient.TryGetValue(clientKey, out List<uint> list))
                {
                    foreach (uint address in list)
                    {
                        if (_byAddress.TryGetValue(address, out DhcpLease lease))
                            result.Add(lease);
                    }
                }
            }

            return result;
        }

        public DhcpLease Put(DhcpLease lease)
        {
            DhcpLease stored;

            lock (_lock)
            {
                stored = lease.WithSequence(++_sequence, _nodeId);
                IndexAdd(stored);

                if (stored.State != DhcpLeaseState.Offered)
                    ScheduleSave();
            }

            LeaseChanged?.Invoke(stored);
            return stored;
        }

        public bool TryPut(DhcpLease lease, Func<DhcpLease, bool> canReplace, out DhcpLease stored)
        {
            lock (_lock)
            {
                _byAddress.TryGetValue(DhcpUtilities.ToUInt32(lease.Address), out DhcpLease existing);

                if ((existing is not null) && !canReplace(existing))
                {
                    stored = existing;
                    return false;
                }

                stored = lease.WithSequence(++_sequence, _nodeId);
                IndexAdd(stored);

                if (stored.State != DhcpLeaseState.Offered)
                    ScheduleSave();
            }

            LeaseChanged?.Invoke(stored);
            return true;
        }

        public void ReplaceAll(IEnumerable<DhcpLease> leases, long sequence, long term)
        {
            List<DhcpLease> changed = new List<DhcpLease>();

            lock (_lock)
            {
                Dictionary<uint, DhcpLease> old = new Dictionary<uint, DhcpLease>(_byAddress);

                _byAddress.Clear();
                _byClient.Clear();

                foreach (DhcpLease lease in leases)
                    IndexAdd(lease);

                _sequence = Math.Max(sequence, _sequence);
                _term = term;

                foreach (KeyValuePair<uint, DhcpLease> entry in _byAddress)
                {
                    if (!old.TryGetValue(entry.Key, out DhcpLease previous) || (previous.Sequence != entry.Value.Sequence))
                        changed.Add(entry.Value);
                }

                foreach (KeyValuePair<uint, DhcpLease> entry in old)
                {
                    if (!_byAddress.ContainsKey(entry.Key))
                        changed.Add(entry.Value.With(DhcpLeaseState.Free, entry.Value.Expires, DateTime.UtcNow));
                }

                ScheduleSave();
            }

            foreach (DhcpLease lease in changed)
                LeaseChanged?.Invoke(lease);
        }

        public List<DhcpLease> GetAll()
        {
            lock (_lock)
            {
                return new List<DhcpLease>(_byAddress.Values);
            }
        }

        public int CountActive(DateTime utcNow)
        {
            int count = 0;

            lock (_lock)
            {
                foreach (DhcpLease lease in _byAddress.Values)
                {
                    if (lease.IsActive(utcNow))
                        count++;
                }
            }

            return count;
        }

        public List<DhcpLease> Maintain(DateTime utcNow)
        {
            List<DhcpLease> changed = new List<DhcpLease>();

            lock (_lock)
            {
                List<uint> remove = new List<uint>();

                foreach (KeyValuePair<uint, DhcpLease> entry in _byAddress)
                {
                    DhcpLease lease = entry.Value;

                    switch (lease.State)
                    {
                        case DhcpLeaseState.Offered:
                            if (lease.Expires <= utcNow)
                                remove.Add(entry.Key);

                            break;

                        case DhcpLeaseState.Bound:
                            if (lease.Expires <= utcNow)
                                changed.Add(lease.With(DhcpLeaseState.Expired, lease.Expires, utcNow));

                            break;

                        case DhcpLeaseState.Declined:
                            if (lease.Expires <= utcNow)
                                changed.Add(lease.With(DhcpLeaseState.Free, lease.Expires, utcNow));

                            break;

                        case DhcpLeaseState.Free:
                            if (lease.Updated + TOMBSTONE_RETENTION <= utcNow)
                                remove.Add(entry.Key);

                            break;

                        case DhcpLeaseState.Released:
                        case DhcpLeaseState.Expired:
                            if ((lease.Updated + EXPIRED_RETENTION <= utcNow) && ((lease.Expires == DateTime.MaxValue) || (lease.Expires + EXPIRED_RETENTION <= utcNow)))
                                remove.Add(entry.Key);

                            break;
                    }
                }

                foreach (uint key in remove)
                {
                    if (_byAddress.Remove(key, out DhcpLease lease))
                        IndexRemoveClient(lease.ClientKey, key);
                }

                if (remove.Count > 0)
                    ScheduleSave();
            }

            List<DhcpLease> stored = new List<DhcpLease>(changed.Count);

            foreach (DhcpLease lease in changed)
                stored.Add(Put(lease));

            return stored;
        }

        public byte[] ExportSnapshot()
        {
            lock (_lock)
            {
                return Serialize(false);
            }
        }

        public static List<DhcpLease> ParseSnapshot(byte[] data, out long sequence, out long term)
        {
            List<DhcpLease> leases = new List<DhcpLease>();

            using (JsonDocument document = JsonDocument.Parse(data))
            {
                JsonElement root = document.RootElement;

                if (root.GetProperty("version").GetInt32() != FILE_VERSION)
                    throw new InvalidDataException("unsupported lease snapshot version");

                sequence = root.GetProperty("sequence").GetInt64();
                term = root.TryGetProperty("term", out JsonElement jsonTerm) ? jsonTerm.GetInt64() : 0;

                foreach (JsonElement jsonLease in root.GetProperty("leases").EnumerateArray())
                    leases.Add(DhcpLease.ReadFrom(jsonLease));
            }

            return leases;
        }

        #endregion

        #region properties

        public long Sequence
        {
            get
            {
                lock (_lock)
                {
                    return _sequence;
                }
            }
        }

        public long Term
        {
            get
            {
                lock (_lock)
                {
                    return _term;
                }
            }
            set
            {
                lock (_lock)
                {
                    _term = value;
                    ScheduleSave();
                }
            }
        }


        #endregion
    }
}
