// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Event
{
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Security;

    using OneIdentity.SafeguardDotNet.A2A;

    using Serilog;

    internal class PersistentSafeguardA2AEventListener : PersistentSafeguardEventListenerBase
    {
        private bool _disposed;

        private readonly ISafeguardA2AContext _a2AContext;
        private readonly SecureString _apiKey;
        private readonly IList<SecureString> _apiKeys;

        public PersistentSafeguardA2AEventListener(ISafeguardA2AContext a2AContext, SecureString apiKey, SafeguardEventHandler handler)
        {
            _a2AContext = a2AContext;
            if (apiKey == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));
            }

            _apiKey = apiKey.Copy();
            RegisterEventHandler("AssetAccountPasswordUpdated", handler);
            RegisterEventHandler("AssetAccountSshKeyUpdated", handler);
            RegisterEventHandler("AccountApiKeySecretUpdated", handler);
            Log.Debug("Persistent A2A event listener successfully created.");
        }

        public PersistentSafeguardA2AEventListener(
            ISafeguardA2AContext a2AContext,
            IEnumerable<SecureString> apiKeys,
            SafeguardEventHandler handler)
        {
            _a2AContext = a2AContext;
            if (apiKeys == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(apiKeys));
            }

            _apiKeys = new List<SecureString>();
            foreach (var apiKey in apiKeys)
            {
                _apiKeys.Add(apiKey.Copy());
            }

            if (!_apiKeys.Any())
            {
                throw new ArgumentException("Parameter must include at least one item", nameof(apiKeys));
            }

            RegisterEventHandler("AssetAccountPasswordUpdated", handler);
            RegisterEventHandler("AssetAccountSshKeyUpdated", handler);
            RegisterEventHandler("AccountApiKeySecretUpdated", handler);
            Log.Debug("Persistent A2A event listener successfully created.");
        }

        protected override SafeguardEventListener ReconnectEventListener()
        {
            // passing in a bogus handler because it will be overridden in PersistentSafeguardEventListenerBase
            if (_apiKey != null)
            {
                return (SafeguardEventListener)_a2AContext.GetA2AEventListener(_apiKey, (name, body) => { });
            }

            return (SafeguardEventListener)_a2AContext.GetA2AEventListener(_apiKeys, (name, body) => { });
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
                _apiKey?.Dispose();
                if (_apiKeys != null)
                {
                    foreach (var apiKey in _apiKeys)
                    {
                        apiKey?.Dispose();
                    }
                }

                _a2AContext?.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
