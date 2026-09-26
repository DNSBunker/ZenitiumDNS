/*
Technitium Library
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

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
using System.IO;
using System.Threading;

namespace ZenitiumLibrary.Net.Dns
{
    public class NameServerMetadata
    {
        #region variables

        long _totalQueries;
        long _answeredQueries;
        double _srtt = 0;
        double _sprtt = 0;
        double _answerRate = -1;
        const double ALPHA = 0.25;

        const int MISCONFIGURED_MARK_TTL = 300;
        DateTime _misconfiguredMarkExpiry;

        readonly NameServerMetadata _parent;
        NameServerMetadata _ipv6Metadata;

        #endregion

        #region constructor

        public NameServerMetadata()
        { }

        private NameServerMetadata(NameServerMetadata parent)
        {
            _parent = parent;
        }

        public NameServerMetadata(BinaryReader bR)
        {
            byte version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    _totalQueries = bR.ReadInt64();
                    _answeredQueries = bR.ReadInt64();
                    _srtt = bR.ReadDouble();
                    _sprtt = bR.ReadDouble();

                    if (_totalQueries > 0)
                        _answerRate = _answeredQueries / (double)_totalQueries;

                    break;

                case 2:
                    ReadValuesFrom(bR);

                    if (bR.ReadBoolean())
                    {
                        _ipv6Metadata = new NameServerMetadata(this);
                        _ipv6Metadata.ReadValuesFrom(bR);
                    }

                    break;

                default:
                    throw new InvalidDataException("NameServerMetadata format version not supported.");
            }
        }

        #endregion

        #region private

        private void ReadValuesFrom(BinaryReader bR)
        {
            _totalQueries = bR.ReadInt64();
            _answeredQueries = bR.ReadInt64();
            _srtt = bR.ReadDouble();
            _sprtt = bR.ReadDouble();
            _answerRate = bR.ReadDouble();
        }

        private void WriteValuesTo(BinaryWriter bW)
        {
            bW.Write(_totalQueries);
            bW.Write(_answeredQueries);
            bW.Write(_srtt);
            bW.Write(_sprtt);
            bW.Write(_answerRate);
        }

        private static void UpdateAverage(ref double average, double value)
        {
            int tries = 10;
            while (tries-- > 0)
            {
                double current = Volatile.Read(ref average);
                double updated = current < 0 ? value : (ALPHA * value) + ((1 - ALPHA) * current);

                double original = Interlocked.CompareExchange(ref average, updated, current);
                if (original == current)
                    break;
            }
        }

        #endregion

        #region internal

        internal NameServerMetadata GetMetadataForIPv6()
        {
            if (_parent is not null)
                return this;

            NameServerMetadata ipv6Metadata = Volatile.Read(ref _ipv6Metadata);
            if (ipv6Metadata is not null)
                return ipv6Metadata;

            ipv6Metadata = new NameServerMetadata(this);

            return Interlocked.CompareExchange(ref _ipv6Metadata, ipv6Metadata, null) ?? ipv6Metadata;
        }

        internal void UpdateSuccess(double rtt)
        {
            Interlocked.Increment(ref _totalQueries);
            Interlocked.Increment(ref _answeredQueries);

            if (_srtt == 0)
                Interlocked.CompareExchange(ref _srtt, rtt, 0);
            else
                UpdateAverage(ref _srtt, rtt);

            UpdateAverage(ref _answerRate, 1);

            if (_parent is not null)
                IPv6Reachability.RecordSuccess();
        }

        internal void UpdateFailure(double penaltyRTT)
        {
            Interlocked.Increment(ref _totalQueries);

            UpdateAverage(ref _sprtt, penaltyRTT);
            UpdateAverage(ref _answerRate, 0);

            if (_parent is not null)
                IPv6Reachability.RecordFailure();
        }

        #endregion

        #region public

        public double GetAnswerRate()
        {
            if (_totalQueries < 1)
                return 0;

            return _answeredQueries / (double)_totalQueries * 100d;
        }

        public double GetNetRTT()
        {
            double rate = Volatile.Read(ref _answerRate);
            if (rate < 0)
                return 0;

            return (rate * _srtt) + ((1 - rate) * _sprtt);
        }

        public void MarkMisconfigured()
        {
            if (_parent is not null)
                _parent.MarkMisconfigured();
            else
                _misconfiguredMarkExpiry = DateTime.UtcNow.AddSeconds(MISCONFIGURED_MARK_TTL);
        }

        public void ClearMisconfiguredMark()
        {
            if (_parent is not null)
                _parent.ClearMisconfiguredMark();
            else
                _misconfiguredMarkExpiry = default;
        }

        public void WriteTo(BinaryWriter bW)
        {
            bW.Write((byte)2);

            WriteValuesTo(bW);

            NameServerMetadata ipv6Metadata = _ipv6Metadata;
            if (ipv6Metadata is null)
            {
                bW.Write(false);
            }
            else
            {
                bW.Write(true);
                ipv6Metadata.WriteValuesTo(bW);
            }
        }

        #endregion

        #region properties

        public long TotalQueries
        { get { return _totalQueries; } }

        public long AnsweredQueries
        { get { return _answeredQueries; } }

        public double SRTT
        { get { return _srtt; } }

        public double SPRTT
        { get { return _sprtt; } }

        public double RecentAnswerRate
        { get { return _answerRate < 0 ? 1 : _answerRate; } }

        public bool IsUnhealthy
        { get { return (_answerRate >= 0) && (_answerRate < 0.5); } }

        public bool IsMisconfigured
        {
            get
            {
                if (_parent is not null)
                    return _parent.IsMisconfigured;

                return DateTime.UtcNow < _misconfiguredMarkExpiry;
            }
        }

        public NameServerMetadata IPv6Metadata
        { get { return _ipv6Metadata; } }

        #endregion
    }
}
