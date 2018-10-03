using System;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNet.SignalR.Client;
using Microsoft.AspNet.SignalR.Client.Http;

namespace OneIdentity.SafeguardDotNet.Event
{
    internal delegate void DisconnectHandler();

    internal class SafeguardEventListener : ISafeguardEventListener
    {
        private bool _disposed;

        private readonly string _eventUrl;
        private readonly bool _ignoreSsl;
        private readonly SecureString _accessToken;
        private readonly SecureString _apiKey;
        private readonly X509Certificate2 _clientCertificate;

        private EventHandlerRegistry _eventHandlerRegistry;
        private DisconnectHandler _disconnectHandler = () => throw new SafeguardEventListenerDisconnectedException();

        private bool _isStarted;
        private HubConnection _signalrConnection;
        public IHubProxy SignalrHubProxy { get; private set; }

        private const string NotificationHub = "notificationHub";

        private SafeguardEventListener(string eventUrl, bool ignoreSsl)
        {
            _eventUrl = eventUrl;
            _ignoreSsl = ignoreSsl;
            _eventHandlerRegistry = new EventHandlerRegistry();
        }

        public SafeguardEventListener(string eventUrl, SecureString accessToken, bool ignoreSsl) : 
            this(eventUrl, ignoreSsl)
        {
            _accessToken = accessToken.Copy();
        }

        public SafeguardEventListener(string eventUrl, X509Certificate2 clientCertificate, SecureString apiKey,
            bool ignoreSsl) : this(eventUrl, ignoreSsl)
        {
            _clientCertificate = clientCertificate;
            _apiKey = apiKey.Copy();
        }

        public void SetDisconnectHandler(DisconnectHandler handler)
        {
            _disconnectHandler = handler;
        }

        public void SetEventHandlerRegistry(EventHandlerRegistry registry)
        {
            _eventHandlerRegistry = registry;
        }

        private void HandleEvent(string eventObject)
        {
            _eventHandlerRegistry.HandleEvent(eventObject);
        }

        private void HandleDisconnect()
        {
            if (_isStarted)
                _disconnectHandler();
        }

        private void CleanupConnection()
        {
            try
            {
                if (_signalrConnection != null)
                {
                    _signalrConnection.Received -= HandleEvent;
                    _signalrConnection.Closed -= HandleDisconnect;
                }
                _signalrConnection?.Dispose();
                SignalrHubProxy = null;
            }
            finally
            {
                _signalrConnection = null;
            }
        }

        public void RegisterEventHandler(string eventName, SafeguardEventHandler handler)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardEventListener");
            _eventHandlerRegistry.RegisterEventHandler(eventName, handler);
        }

        public void Start()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardEventListener");
            CleanupConnection();
            _signalrConnection = new HubConnection(_eventUrl);
            if (_accessToken != null)
            {
                _signalrConnection.Headers.Add("Authorization", $"Bearer {_accessToken.ToInsecureString()}");
            }
            else
            {
                _signalrConnection.Headers.Add("Authorization", $"A2A {_apiKey.ToInsecureString()}");
                _signalrConnection.AddClientCertificate(_clientCertificate);
            }
            SignalrHubProxy = _signalrConnection.CreateHubProxy(NotificationHub);

            try
            {
                _signalrConnection.Received += HandleEvent;
                _signalrConnection.Closed += HandleDisconnect;
                _signalrConnection.Start(_ignoreSsl ? new IgnoreSslValidationHttpClient() : new DefaultHttpClient())
                    .Wait();
                _isStarted = true;
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException("Failure starting SignalR", ex);
            }
        }

        public void Stop()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardEventListener");
            try
            {
                _isStarted = false;
                _signalrConnection?.Stop();
                CleanupConnection();
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException("Failure stopping SignalR", ex);
            }
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
                CleanupConnection();
                _accessToken?.Dispose();
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
