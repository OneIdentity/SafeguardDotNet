// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Event
{
    using Serilog;

    internal class PersistentSafeguardEventListener : PersistentSafeguardEventListenerBase
    {
        private bool _disposed;

        private readonly ISafeguardConnection _connection;

        public PersistentSafeguardEventListener(ISafeguardConnection connection)
        {
            _connection = connection;
            Log.Debug("Persistent event listener successfully created.");
        }

        protected override SafeguardEventListener ReconnectEventListener()
        {
            if (_connection.GetAccessTokenLifetimeRemaining() == 0)
            {
                _connection.RefreshAccessToken();
            }

            return (SafeguardEventListener)_connection.GetEventListener();
        }

        protected override void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
            {
                return;
            }

            try
            {
                base.Dispose(disposing);
                _connection?.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
