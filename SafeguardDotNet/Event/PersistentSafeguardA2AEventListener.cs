using System.Security;
using OneIdentity.SafeguardDotNet.A2A;
using Serilog;

namespace OneIdentity.SafeguardDotNet.Event
{
    internal class PersistentSafeguardA2AEventListener : PersistentSafeguardEventListenerBase
    {
        private bool _disposed;

        private readonly ISafeguardA2AContext _a2AContext;
        private readonly SecureString _apiKey;

        public PersistentSafeguardA2AEventListener(ISafeguardA2AContext a2AContext, SecureString apiKey, SafeguardEventHandler handler)
        {
            _a2AContext = a2AContext;
            _apiKey = apiKey.Copy();
            RegisterEventHandler("AssetAccountPasswordUpdated", handler);
            Log.Debug("Persistent A2A event listener successfully created.");
        }

        protected override SafeguardEventListener ReconnectEventListener()
        {
            // passing in a bogus handler because it will be overridden in PersistentSafeguardEventListenerBase
            return (SafeguardEventListener) _a2AContext.GetEventListener(_apiKey, (name, body) => { });
        }

        protected override void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
                return;
            try
            {
                base.Dispose(true);
                _apiKey.Dispose();
                _a2AContext?.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
