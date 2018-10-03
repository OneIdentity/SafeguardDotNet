namespace OneIdentity.SafeguardDotNet.Event
{
    internal class PersistentSafeguardEventListener : PersistentSafeguardEventListenerBase
    {
        private bool _disposed;

        private readonly ISafeguardConnection _connection;

        public PersistentSafeguardEventListener(ISafeguardConnection connection)
        {
            _connection = connection;
        }

        protected override SafeguardEventListener ReconnectEventListener()
        {
            if (_connection.GetAccessTokenLifetimeRemaining() == 0)
                _connection.RefreshAccessToken();
            return (SafeguardEventListener)_connection.GetEventListener();
        }

        protected override void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
                return;
            try
            {
                base.Dispose(true);
                _connection?.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
