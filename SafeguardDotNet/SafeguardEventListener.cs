using System;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNet.SignalR.Client;

namespace OneIdentity.SafeguardDotNet
{
    internal class SafeguardEventListener : ISafeguardEventListener
    {
        private bool _disposed;

        private string _eventUrl;
        private readonly SecureString _apiToken;
        private readonly SecureString _apiKey;
        private readonly X509Certificate2 _clientCertificate;

        HubConnection _signalrConnection;

        private SafeguardEventListener(string eventUrl)
        {
            _eventUrl = eventUrl;
        }

        public SafeguardEventListener(string eventUrl, SecureString apiToken) : this(eventUrl)
        {
            _apiToken = apiToken.Copy();
        }

        public SafeguardEventListener(string eventUrl, X509Certificate2 clientCertificate, SecureString apiKey) : this(eventUrl)
        {
            _clientCertificate = clientCertificate;
            _apiKey = apiKey.Copy();
        }

        public void RegisterEventHandler(string eventName, SafeguardEventHandler handler)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardEventListener");
            throw new NotImplementedException();
        }

        public void Start()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardEventListener");
            throw new NotImplementedException();
        }

        public void Stop()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardEventListener");
            throw new NotImplementedException();
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
                return;
            try
            {
                _signalrConnection?.Dispose();
                _apiToken?.Dispose();
                _clientCertificate?.Dispose();
                _apiKey?.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
