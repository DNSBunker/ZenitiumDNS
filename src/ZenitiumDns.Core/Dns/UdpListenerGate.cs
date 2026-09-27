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

using System.Net.Sockets;
using System.Threading;

namespace ZenitiumDns.Core.Dns
{
    sealed class UdpListenerGate
    {
        const int PARK_TIMEOUT = 1000;
        const int BACKLOG_STREAK_THRESHOLD = 16;

        readonly Socket _socket;
        readonly SemaphoreSlim _signal;
        int _parked;
        int _backlogStreak;

        public UdpListenerGate(Socket socket, int helperCount)
        {
            _socket = socket;
            _signal = new SemaphoreSlim(0, helperCount);
        }

        public void ParkWhileIdle()
        {
            while (_socket.Available == 0)
            {
                Interlocked.Increment(ref _parked);

                try
                {
                    _signal.Wait(PARK_TIMEOUT);
                }
                finally
                {
                    Interlocked.Decrement(ref _parked);
                }
            }
        }

        public void TrackBacklog()
        {
            if (Volatile.Read(ref _parked) <= _signal.CurrentCount)
            {
                _backlogStreak = 0;
                return;
            }

            if (_socket.Available == 0)
            {
                _backlogStreak = 0;
                return;
            }

            if (++_backlogStreak < BACKLOG_STREAK_THRESHOLD)
                return;

            _backlogStreak = 0;

            try
            {
                _signal.Release();
            }
            catch (SemaphoreFullException)
            { }
        }
    }
}
