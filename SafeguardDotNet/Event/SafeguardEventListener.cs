using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Net.Security;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNet.SignalR.Client;
using Microsoft.AspNet.SignalR.Client.Http;
using Serilog;

namespace OneIdentity.SafeguardDotNet.Event
{
    internal delegate void DisconnectHandler();

    internal class SafeguardEventListener : ISafeguardEventListener
    {
        private bool _disposed;
        
        private readonly string _eventUrl;
        private readonly bool _ignoreSsl;
        private readonly RemoteCertificateValidationCallback _validationCallback;
        private readonly SecureString _accessToken;
        private readonly SecureString _apiKey;
        private readonly IList<SecureString> _apiKeys;
        private readonly CertificateContext _clientCertificate;

        private EventHandlerRegistry _eventHandlerRegistry;
        private DisconnectHandler _disconnectHandler = () => throw new SafeguardEventListenerDisconnectedException();

        private bool _isStarted;
        private HubConnection _signalrConnection;
        public IHubProxy SignalrHubProxy { get; private set; }

        private const string NotificationHub = "notificationHub";

        private SafeguardEventListener(string eventUrl, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback)
        {
            _eventUrl = eventUrl;
            _ignoreSsl = ignoreSsl;
            _validationCallback = validationCallback;
            _eventHandlerRegistry = new EventHandlerRegistry();
        }

        public SafeguardEventListener(string eventUrl, SecureString accessToken, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : 
            this(eventUrl, ignoreSsl, validationCallback)
        {
            if (accessToken == null)
                throw new ArgumentException("Parameter may not be null", nameof(accessToken));
            _accessToken = accessToken.Copy();
        }

        public SafeguardEventListener(string eventUrl, CertificateContext clientCertificate, SecureString apiKey,
            bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : this(eventUrl, ignoreSsl, validationCallback)
        {
            _clientCertificate = clientCertificate.Clone();
            if (apiKey == null)
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));
            _apiKey = apiKey.Copy();
        }

        public SafeguardEventListener(string eventUrl, CertificateContext clientCertificate, IEnumerable<SecureString> apiKeys,
            bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : this(eventUrl, ignoreSsl, validationCallback)
        {
            _clientCertificate = clientCertificate.Clone();
            if (apiKeys == null)
                throw new ArgumentException("Parameter may not be null", nameof(apiKeys));
            _apiKeys = new List<SecureString>();
            foreach (var apiKey in apiKeys)
                _apiKeys.Add(apiKey.Copy());
            if (!_apiKeys.Any())
                throw new ArgumentException("Parameter must include at least one item", nameof(apiKeys));
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
            if (!_isStarted)
                return;
            Log.Warning("SignalR disconnect detected, calling handler...");
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
            catch (Exception ex)
            {
                Log.Warning(ex, "SignalR dispose threw an exception");
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
                _signalrConnection.Headers.Add("Authorization",
                    _apiKey != null
                        ? $"A2A {_apiKey.ToInsecureString()}"
                        : $"A2A {string.Join(" ", _apiKeys.Select(apiKey => apiKey.ToInsecureString()))}");
                _signalrConnection.AddClientCertificate(_clientCertificate.Certificate);
            }
            SignalrHubProxy = _signalrConnection.CreateHubProxy(NotificationHub);

            try
            {
                _signalrConnection.Received += HandleEvent;
                _signalrConnection.Closed += HandleDisconnect;
                if (_ignoreSsl)
                    _signalrConnection.Start(new IgnoreSslValidationHttpClient()).Wait();
                else if (_validationCallback != null)
                    _signalrConnection.Start(new CustomDelegateSslValidationHttpClient(_validationCallback)).Wait();
                else
                    _signalrConnection.Start(new DefaultHttpClient()).Wait();
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
                if (_apiKeys != null)
                    foreach (var apiKey in _apiKeys)
                        apiKey?.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
