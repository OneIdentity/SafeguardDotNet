using System;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNet.SignalR.Client;
using Microsoft.AspNet.SignalR.Client.Http;
using Serilog;

namespace OneIdentity.SafeguardDotNet
{
    internal class SafeguardEventListener : ISafeguardEventListener
    {
        private bool _disposed;

        private readonly string _eventUrl;
        private readonly bool _ignoreSsl;
        private readonly SecureString _accessToken;
        private readonly SecureString _apiKey;
        private readonly X509Certificate2 _clientCertificate;

        private HubConnection _signalrConnection;
        private IHubProxy _signalrHubProxy;
        private CancellationTokenSource _cancel;
        private const string NotificationHub = "notificationHub";

        private SafeguardEventListener(string eventUrl, bool ignoreSsl)
        {
            _eventUrl = eventUrl;
            _ignoreSsl = ignoreSsl;
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
            try
            {
                _cancel?.Cancel();
                _cancel?.Dispose();
                _signalrConnection?.Dispose();
            }
            finally
            {
                _cancel = null;
                _signalrConnection = null;
            }
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
            _signalrHubProxy = _signalrConnection.CreateHubProxy(NotificationHub);

            _cancel = new CancellationTokenSource();
Task.Run(() =>
            {
                try
                {
                    // TODO: Remove debugging below and connect real event handlers
                    _signalrConnection.Received += Log.Information;
                    _signalrConnection.Start(_ignoreSsl ? new IgnoreSslValidationHttpClient() : new DefaultHttpClient())
                        .Wait();
                }
                catch (Exception ex)
                {
                    // TODO: proper logging / error handling here
                    Log.Error(ex, "Failure starting SignalR");
                    throw;
                }
            }, _cancel.Token);
        }

        public void Stop()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardEventListener");
            try
            {
                _cancel?.Cancel();
            }
            catch (Exception ex)
            {
                // TODO: proper logging / error handling here
                Log.Error(ex, "Failure stopping SignalR");
                throw;
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
                _signalrConnection?.Dispose();
                _cancel?.Dispose();
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
