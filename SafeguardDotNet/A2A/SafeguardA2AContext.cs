// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.A2A
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Security;
    using System.Security;
    using System.Text;
    using System.Threading.Tasks;

    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    using OneIdentity.SafeguardDotNet.Event;

    using Serilog;

    internal class SafeguardA2AContext : ISafeguardA2AContext, ICloneable
    {
        private bool _disposed;

        private static readonly string Core = "Core";
        private static readonly string A2A = "A2A";

        private readonly string _networkAddress;
        private readonly int _apiVersion;
        private readonly bool _ignoreSsl;
        private readonly RemoteCertificateValidationCallback _validationCallback;

        private readonly CertificateContext _clientCertificate;
        private readonly HttpClient _http;

        private SafeguardA2AContext(
            string networkAddress,
            CertificateContext clientCertificate,
            int apiVersion,
            bool ignoreSsl,
            RemoteCertificateValidationCallback validationCallback)
        {
            _networkAddress = networkAddress;
            _apiVersion = apiVersion;
            _ignoreSsl = ignoreSsl;
            _validationCallback = _ignoreSsl ? null : validationCallback;
            _clientCertificate = clientCertificate.Clone();

            _http = CreateHttpClient();
        }

        private HttpClient CreateHttpClient()
        {
            var handler = new HttpClientHandler
            {
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12,
            };

            if (_clientCertificate?.Certificate != null)
            {
                handler.ClientCertificateOptions = ClientCertificateOption.Manual;
                handler.ClientCertificates.Add(_clientCertificate.Certificate);
            }

            if (_ignoreSsl)
            {
#pragma warning disable S4830 // Server certificate validation is intentionally bypassed when IgnoreSsl is set
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
#pragma warning restore S4830
            }
            else if (_validationCallback != null)
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => _validationCallback(message, cert, chain, errors);
            }

            return new HttpClient(handler);
        }

        public SafeguardA2AContext(string networkAddress, string certificateThumbprint, int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback)
            : this(networkAddress, new CertificateContext(certificateThumbprint), apiVersion, ignoreSsl, validationCallback)
        {
        }

        public SafeguardA2AContext(
            string networkAddress,
            string certificatePath,
            SecureString certificatePassword,
            int apiVersion,
            bool ignoreSsl,
            RemoteCertificateValidationCallback validationCallback)
            : this(networkAddress, new CertificateContext(certificatePath, certificatePassword), apiVersion, ignoreSsl, validationCallback)
        {
        }

        public SafeguardA2AContext(
            string networkAddress,
            IEnumerable<byte> certificateData,
            SecureString certificatePassword,
            int apiVersion,
            bool ignoreSsl,
            RemoteCertificateValidationCallback validationCallback)
            : this(networkAddress, new CertificateContext(certificateData, certificatePassword), apiVersion, ignoreSsl, validationCallback)
        {
        }

        public IList<A2ARetrievableAccount> GetRetrievableAccounts()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardA2AContext");
            }

            var list = new List<A2ARetrievableAccount>();

            var json = ApiRequest(HttpMethod.Get, GetUrl(Core, "A2ARegistrations"), null, null);

            var registrations = JsonConvert.DeserializeObject<List<A2ARegistration>>(json);

            foreach (var registration in registrations)
            {
                json = ApiRequest(HttpMethod.Get, GetUrl(Core, $"A2ARegistrations/{registration.Id}/RetrievableAccounts"), null, null);

                var accounts = JsonConvert.DeserializeObject<List<A2ARetrievableAccount>>(json);

                foreach (var account in accounts)
                {
                    account.ApplicationName = registration.AppName;
                    account.Description = registration.Description;
                    account.Disabled |= registration.Disabled;
                }

                list.AddRange(accounts);
            }

            return list;
        }

        public SecureString RetrievePassword(SecureString apiKey)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardA2AContext");
            }

            if (apiKey == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));
            }

            var pwd = ApiRequest(HttpMethod.Get, GetUrl(A2A, "Credentials?type=Password"), null, apiKey);

            var raw = string.IsNullOrEmpty(pwd)
                ? pwd
                : JToken.Parse(pwd).ToString();
            Log.Information("Successfully retrieved A2A password.");
            return raw.ToSecureString();
        }

        public void SetPassword(SecureString apiKey, SecureString password)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardA2AContext");
            }

            if (apiKey == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));
            }

            if (password == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(password));
            }

            var data = JsonConvert.SerializeObject(password.ToInsecureString());

            _ = ApiRequest(HttpMethod.Put, GetUrl(A2A, "Credentials/Password"), data, apiKey);
            Log.Information("Successfully set A2A password.");
        }

        public SecureString RetrievePrivateKey(SecureString apiKey, KeyFormat keyFormat = KeyFormat.OpenSsh)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardA2AContext");
            }

            if (apiKey == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));
            }

            var key = ApiRequest(HttpMethod.Get, GetUrl(A2A, $"Credentials?type=PrivateKey&keyFormat={keyFormat}"), null, apiKey);

            var json = JToken.Parse(key);
            Log.Information("Successfully retrieved A2A private key.");
            return json.Root.ToString().ToSecureString();
        }

        public void SetPrivateKey(SecureString apiKey, SecureString privateKey, SecureString password, KeyFormat keyFormat = KeyFormat.OpenSsh)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardA2AContext");
            }

            if (apiKey == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));
            }

            if (privateKey == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(privateKey));
            }

            if (password == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(password));
            }

            var data = JsonConvert.SerializeObject(new SshKey
            {
                Passphrase = password.ToInsecureString(),
                PrivateKey = privateKey.ToInsecureString(),
            });

            _ = ApiRequest(HttpMethod.Put, GetUrl(A2A, $"Credentials/SshKey?keyFormat={keyFormat}"), data, apiKey);
            Log.Information("Successfully set A2A private key.");
        }

        public IList<ApiKeySecret> RetrieveApiKeySecret(SecureString apiKey)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardA2AContext");
            }

            if (apiKey == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));
            }

            var json = ApiRequest(HttpMethod.Get, GetUrl(A2A, "Credentials?type=ApiKey"), null, apiKey);

            Log.Information("Successfully retrieved A2A API key(s).");

            var list = JsonConvert.DeserializeObject<List<ApiKeySecret>>(json, new SecureStringConverter());

            return list;
        }

        public ISafeguardEventListener GetA2AEventListener(SecureString apiKey, SafeguardEventHandler handler)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardA2AContext");
            }

            if (apiKey == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));
            }

            var eventListener = new SafeguardEventListener(
                $"https://{_networkAddress}/service/a2a/signalr",
                _clientCertificate,
                apiKey,
                _ignoreSsl,
                _validationCallback);
            eventListener.RegisterEventHandler("AssetAccountPasswordUpdated", handler);
            eventListener.RegisterEventHandler("AssetAccountSshKeyUpdated", handler);
            eventListener.RegisterEventHandler("AccountApiKeySecretUpdated", handler);
            Log.Debug("Event listener successfully created for Safeguard A2A context.");
            return eventListener;
        }

        public ISafeguardEventListener GetA2AEventListener(IEnumerable<SecureString> apiKeys, SafeguardEventHandler handler)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardA2AContext");
            }

            if (apiKeys == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(apiKeys));
            }

            var eventListener = new SafeguardEventListener(
                $"https://{_networkAddress}/service/a2a/signalr",
                _clientCertificate,
                apiKeys,
                _ignoreSsl,
                _validationCallback);
            eventListener.RegisterEventHandler("AssetAccountPasswordUpdated", handler);
            eventListener.RegisterEventHandler("AssetAccountSshKeyUpdated", handler);
            eventListener.RegisterEventHandler("AccountApiKeySecretUpdated", handler);
            Log.Debug("Event listener successfully created for Safeguard A2A context.");
            return eventListener;
        }

        public ISafeguardEventListener GetPersistentA2AEventListener(SecureString apiKey, SafeguardEventHandler handler)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardA2AContext");
            }

            if (apiKey == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));
            }

            return new PersistentSafeguardA2AEventListener(Clone() as SafeguardA2AContext, apiKey, handler);
        }

        public ISafeguardEventListener GetPersistentA2AEventListener(IEnumerable<SecureString> apiKeys,
            SafeguardEventHandler handler)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardA2AContext");
            }

            if (apiKeys == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(apiKeys));
            }

            return new PersistentSafeguardA2AEventListener(Clone() as SafeguardA2AContext, apiKeys, handler);
        }

        public string BrokerAccessRequest(SecureString apiKey, BrokeredAccessRequest accessRequest)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardA2AContext");
            }

            if (apiKey == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));
            }

            if (accessRequest == null)
            {
                throw new ArgumentException("Parameter may not be null", nameof(accessRequest));
            }

            if (accessRequest.ForUserId == null && accessRequest.ForUserName == null)
            {
                throw new SafeguardDotNetException("You must specify a user to create an access request for");
            }

            if (accessRequest.AssetId == null && accessRequest.AssetName == null)
            {
                throw new SafeguardDotNetException("You must specify an asset to create an access request for");
            }

            var data = JsonConvert.SerializeObject(accessRequest);
            var json = ApiRequest(HttpMethod.Post, GetUrl(A2A, "AccessRequests"), data, apiKey);

            Log.Information("Successfully created A2A access request.");
            return json;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
            {
                return;
            }

            try
            {
                _clientCertificate?.Dispose();
                _http?.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }

        public object Clone()
        {
            return new SafeguardA2AContext(_networkAddress, _clientCertificate, _apiVersion, _ignoreSsl, _validationCallback);
        }

        private string GetUrl(string service, string pathAndQuery)
        {
            return $"https://{_networkAddress}/service/{service}/v{_apiVersion}/{pathAndQuery}";
        }

        private string ApiRequest(HttpMethod method, string url, string postData = null, SecureString apiKey = null)
        {
            var req = new HttpRequestMessage
            {
                Method = method,
                RequestUri = new Uri(url, UriKind.Absolute),
            };

            req.Headers.Add("Accept", "application/json");

            if (apiKey != null)
            {
                req.Headers.Add("Authorization", $"A2A {apiKey.ToInsecureString()}");
            }

            if (postData != null)
            {
                req.Content = new StringContent(postData, Encoding.UTF8, "application/json");
            }

            try
            {
                var res = _http.SendAsync(req).GetAwaiter().GetResult();
                var msg = res.Content?.ReadAsStringAsync().GetAwaiter().GetResult();

                if (!res.IsSuccessStatusCode)
                {
                    throw new SafeguardDotNetException($"Error returned from Safeguard API, Error: {res.StatusCode} {msg}", res.StatusCode, msg);
                }

                return msg;
            }
            catch (TaskCanceledException)
            {
                throw new SafeguardDotNetException($"Request timeout to {url}.");
            }
        }
    }

    internal class A2ARegistration
    {
        public string Id { get; set; }

        public string AppName { get; set; }

        public string Description { get; set; }

        public bool Disabled { get; set; }
    }
}
