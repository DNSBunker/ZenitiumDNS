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
