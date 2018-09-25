using System;
using System.Collections.Generic;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNet.SignalR.Client;
using Microsoft.AspNet.SignalR.Client.Http;
using Newtonsoft.Json.Linq;
using Serilog;

namespace OneIdentity.SafeguardDotNet
{
    using DelegateRegistry = Dictionary<string, List<SafeguardEventHandler>>;
    using ParsedDelegateRegistry = Dictionary<string, List<SafeguardParsedEventHandler>>;

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
        private CancellationTokenSource _signalrCancel;

        private readonly DelegateRegistry _delegateStringRegistry =
            new DelegateRegistry(StringComparer.InvariantCultureIgnoreCase);

        private readonly ParsedDelegateRegistry _delegateParsedRegistry =
            new ParsedDelegateRegistry(StringComparer.InvariantCultureIgnoreCase);

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

        private void UpdateRegistry<T>(string eventName, Dictionary<string, List<T>> registry, T handler, string name)
        {
            if (!registry.ContainsKey(eventName))
                registry[eventName] = new List<T>();
            registry[eventName].Add(handler);
            Log.Information("Registered event {Event} with delegate {Delegate}", eventName, name);
        }

        private (string, JToken)[] ParseEvents(string eventObject)
        {
            try
            {
                var events = new List<(string, JToken)>();
                var jObject = JObject.Parse(eventObject);
                var jEvents = jObject["A"];
                foreach (var jEvent in jEvents)
                {
                    var name = jEvent["Name"];
                    var body = jEvent["Data"];
                    // Work around for bug in A2A events in Safeguard 2.2 and 2.3
                    if (name != null && int.TryParse(name.ToString(), out _))
                        name = body["EventName"];
                    events.Add((name?.ToString(), body));
                }
                return events.ToArray();
            }
            catch (Exception)
            {
                Log.Warning("Unable to parse event object {EventObject}", eventObject);
                return null;
            }
        }

        private void HandleEvent(string eventObject)
        {
            var events = ParseEvents(eventObject);
            if (events == null)
                return;
            foreach (var eventInfo in events)
            {
                if (eventInfo.Item1 == null)
                {
                    Log.Warning("Found null event with body {EventBody}", eventInfo.Item2);
                    continue;
                }

                if (!_delegateStringRegistry.ContainsKey(eventInfo.Item1) && !_delegateParsedRegistry.ContainsKey(eventInfo.Item1))
                {
                    Log.Information("No handlers registered for event {Event}", eventInfo.Item1);
                    return;
                }

                if (_delegateStringRegistry.ContainsKey(eventInfo.Item1))
                {
                    foreach (var handler in _delegateStringRegistry[eventInfo.Item1])
                    {
                        Log.Information("Calling {Delegate} for event {Event}", handler.Method.Name, eventInfo.Item1);
                        Log.Debug("Event {Event} has body {EventBody}", eventInfo.Item1, eventInfo.Item2);
                        Task.Run(() =>
                        {
                            try
                            {
                                handler(eventInfo.Item1, eventInfo.Item2.ToString());
                            }
                            catch (Exception ex)
                            {
                                Log.Error(ex, "An error occured while calling {Delegate}", handler.Method.Name);
                            }
                        });
                    }
                }

                if (_delegateParsedRegistry.ContainsKey(eventInfo.Item1))
                {
                    foreach (var handler in _delegateParsedRegistry[eventInfo.Item1])
                    {
                        Log.Information("Calling {Delegate} for event {Event}", handler.Method.Name, eventInfo.Item1);
                        Log.Debug("Event {Event} has body {EventBody}", eventInfo.Item1, eventInfo.Item2);
                        Task.Run(() =>
                        {
                            try
                            {
                                handler(eventInfo.Item1, eventInfo.Item2);
                            }
                            catch (Exception ex)
                            {
                                Log.Error(ex, "An error occured while calling {Delegate}", handler.Method.Name);
                            }
                        });
                    }
                }
            }
        }

        private void CleanupConnection()
        {
            try
            {
                if (_signalrConnection != null)
                    _signalrConnection.Received -= HandleEvent;
                if (_signalrCancel != null && !_signalrCancel.IsCancellationRequested)
                    _signalrCancel?.Cancel();
                _signalrCancel?.Dispose();
                _signalrConnection?.Dispose();
            }
            finally
            {
                _signalrCancel = null;
                _signalrConnection = null;
            }
        }

        public void RegisterEventHandler(string eventName, SafeguardEventHandler handler)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardEventListener");
            UpdateRegistry(eventName, _delegateStringRegistry, handler, handler.Method.Name);
        }

        public void RegisterEventHandler(string eventName, SafeguardParsedEventHandler handler)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardEventListener");
            UpdateRegistry(eventName, _delegateParsedRegistry, handler, handler.Method.Name);
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
            _signalrHubProxy = _signalrConnection.CreateHubProxy(NotificationHub);

            _signalrCancel = new CancellationTokenSource();
            Task.Run(() =>
            {
                try
                {
                    _signalrConnection.Received += HandleEvent;
                    _signalrConnection.Start(_ignoreSsl ? new IgnoreSslValidationHttpClient() : new DefaultHttpClient())
                        .Wait();
                }
                catch (Exception ex)
                {
                    // TODO: proper logging / error handling here
                    Log.Error(ex, "Failure starting SignalR");
                    throw;
                }
            }, _signalrCancel.Token);
        }

        public void Stop()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardEventListener");
            try
            {
                _signalrCancel?.Cancel();
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
