/*
Technitium Library
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
using System.Threading;
using System.Threading.Tasks;

namespace ZenitiumLibrary
{
    public sealed class TaskPool : IDisposable
    {
        #region variables

        readonly int _queueSize;
        readonly int _maximumConcurrencyLevel;
        readonly TaskScheduler? _taskScheduler;

        readonly ConcurrentQueue<(Func<object?, Task> Task, object? State)> _queue = new ConcurrentQueue<(Func<object?, Task>, object?)>();
        int _queued;
        int _running;

        #endregion

        #region constructors

        public TaskPool(int queueSize = -1, int maximumConcurrencyLevel = -1, TaskScheduler? taskScheduler = null)
        {
            if (maximumConcurrencyLevel < 1)
                maximumConcurrencyLevel = Environment.ProcessorCount;

            _queueSize = queueSize;
            _maximumConcurrencyLevel = maximumConcurrencyLevel;

            if ((taskScheduler is not null) && !ReferenceEquals(taskScheduler, TaskScheduler.Default))
                _taskScheduler = taskScheduler;
        }

        #endregion

        #region IDisposable

        volatile bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;
            GC.SuppressFinalize(this);
        }

        #endregion

        #region private

        private bool TryAcquireSlot()
        {
            if (Interlocked.Increment(ref _running) <= _maximumConcurrencyLevel)
                return true;

            Interlocked.Decrement(ref _running);
            return false;
        }

        private void Start((Func<object?, Task> Task, object? State) item)
        {
            if (_taskScheduler is null)
            {
                ThreadPool.UnsafeQueueUserWorkItem(static delegate ((TaskPool Pool, (Func<object?, Task> Task, object? State) Item) state)
                {
                    _ = state.Pool.RunAsync(state.Item);
                }, (this, item), false);
            }
            else
            {
                _ = Task.Factory.StartNew(delegate ()
                {
                    return RunAsync(item);
                }, CancellationToken.None, TaskCreationOptions.DenyChildAttach, _taskScheduler);
            }
        }

        private async Task RunAsync((Func<object?, Task> Task, object? State) item)
        {
            try
            {
                await item.Task(item.State);
            }
            catch
            { }
            finally
            {
                Interlocked.Decrement(ref _running);
                Drain();
            }
        }

        private void Drain()
        {
            while (!_queue.IsEmpty)
            {
                if (!TryAcquireSlot())
                    return;

                if (!_queue.TryDequeue(out (Func<object?, Task> Task, object? State) item))
                {
                    Interlocked.Decrement(ref _running);
                    return;
                }

                Interlocked.Decrement(ref _queued);
                Start(item);
            }
        }

        #endregion

        #region public

        public bool TryQueueTask(Func<object?, Task> task)
        {
            return TryQueueTask(task, null);
        }

        public bool TryQueueTask(Func<object?, Task> task, object? state)
        {
            if (_disposed)
                return false;

            if (_queue.IsEmpty && TryAcquireSlot())
            {
                Start((task, state));
                return true;
            }

            int queued = Interlocked.Increment(ref _queued);

            if ((_queueSize > 0) && (queued > _queueSize))
            {
                Interlocked.Decrement(ref _queued);
                return false;
            }

            _queue.Enqueue((task, state));
            Drain();
            return true;
        }

        #endregion

        #region properties

        public int QueueSize
        { get { return _queueSize; } }

        public int MaximumConcurrencyLevel
        { get { return _maximumConcurrencyLevel; } }

        public int QueuedTasks
        { get { return Math.Max(0, Volatile.Read(ref _queued)); } }

        #endregion
    }
}
