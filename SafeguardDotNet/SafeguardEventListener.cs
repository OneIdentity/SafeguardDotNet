using System;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNet.SignalR.Client;

namespace OneIdentity.SafeguardDotNet
{
    internal class SafeguardEventListener : ISafeguardEventListener
    {
        bool _disposed;

        string _eventUrl;
        SecureString _apiToken;
        X509Certificate2 _certificate;

        HubConnection _signalrConnection;

        public SafeguardEventListener(string baseUrl, SecureString apiToken)
        {
            _apiToken = apiToken;

        }

        public SafeguardEventListener(string baseUrl, X509Certificate2 certificate)
        {
            _certificate = certificate;
        }

        public void Dispose()
        {
            if (!_disposed)
            {
                _apiToken?.Dispose();
                try
                {
                    _signalrConnection?.Dispose();
                }
                finally
                {
                    _signalrConnection = null;
                }
                _disposed = true;
            }
        }

        public void RegisterEventHandler(string eventName, SafeguardEventHandler handler)
        {
            throw new NotImplementedException();
        }

        public void Start()
        {
            throw new NotImplementedException();
        }

        public void Stop()
        {
            throw new NotImplementedException();
        }
    }
}
