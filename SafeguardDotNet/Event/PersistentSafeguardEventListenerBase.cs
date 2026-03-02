// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Event
{
    using System;
    using System.Threading;
    using System.Threading.Tasks;

    using Serilog;

    internal abstract class PersistentSafeguardEventListenerBase : ISafeguardEventListener
    {
        private bool _disposed;

        private SafeguardEventListener _eventListener;
        private readonly EventHandlerRegistry _eventHandlerRegistry;
        private SafeguardEventListenerStateCallback _eventListenerStateCallback;

        private Task _reconnectTask;
        private CancellationTokenSource _reconnectCancel;

        protected PersistentSafeguardEventListenerBase()
        {
            _eventHandlerRegistry = new EventHandlerRegistry();
        }

        public void RegisterEventHandler(string eventName, SafeguardEventHandler handler)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("PersistentSafeguardEventListener");
            }

            _eventHandlerRegistry.RegisterEventHandler(eventName, handler);
        }

        public void SetEventListenerStateCallback(SafeguardEventListenerStateCallback eventListenerStateCallback)
        {
            _eventListenerStateCallback = eventListenerStateCallback;
        }

        protected abstract SafeguardEventListener ReconnectEventListener();

        private void PersistentReconnectAndStart()
        {
            if (_reconnectTask != null)
            {
                return;
            }

            _reconnectCancel = new CancellationTokenSource();
            _reconnectTask = Task.Run(() =>
            {
                while (!_reconnectCancel.IsCancellationRequested)
                {
                    try
                    {
                        _eventListener?.Dispose();
                        Log.Debug("Attempting to connect and start internal event listener.");
                        _eventListener = ReconnectEventListener();
                        _eventListener.SetEventHandlerRegistry(_eventHandlerRegistry);
                        _eventListener.SetEventListenerStateCallback(_eventListenerStateCallback);
                        _eventListener.Start();
                        _eventListener.SetDisconnectHandler(PersistentReconnectAndStart);
                        break;
                    }
                    catch (Exception ex)
                    {
                        Log.Warning("Internal event listener connection error (see debug for more information), sleeping for 5 seconds...");
                        Log.Debug(ex, "Internal event listener connection error.");
                        Thread.Sleep(5000);
                    }
                }
            },
                _reconnectCancel.Token);
            _reconnectTask.ContinueWith((task) =>
            {
                _reconnectCancel?.Dispose();
                _reconnectCancel = null;
                _reconnectTask = null;
                if (!task.IsFaulted)
                {
                    Log.Debug("Internal event listener successfully connected and started.");
                }
            });
        }

        public void Start()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("PersistentSafeguardEventListener");
            }

            Log.Information("Internal event listener requested to start.");
            PersistentReconnectAndStart();
        }

        public void Stop()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("PersistentSafeguardEventListener");
            }

            Log.Information("Internal event listener requested to stop.");
            _reconnectCancel?.Cancel();
            _eventListener?.Stop();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
            {
                return;
            }

            try
            {
                _eventListener?.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
