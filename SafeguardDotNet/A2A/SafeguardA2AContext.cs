using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using OneIdentity.SafeguardDotNet.Event;
using RestSharp;
using Serilog;

namespace OneIdentity.SafeguardDotNet.A2A
{
    internal class SafeguardA2AContext : ISafeguardA2AContext, ICloneable
    {
        private bool _disposed;

        private readonly string _networkAddress;
        private readonly int _apiVersion; 
        private readonly bool _ignoreSsl;
        private readonly RemoteCertificateValidationCallback _validationCallback;

        private readonly CertificateContext _clientCertificate;
        private readonly RestClient _a2AClient;
        private readonly RestClient _coreClient;

        private SafeguardA2AContext(string networkAddress, CertificateContext clientCertificate, int apiVersion,
            bool ignoreSsl, RemoteCertificateValidationCallback validationCallback)
        {
            _networkAddress = networkAddress;
            _apiVersion = apiVersion;

            var safeguardA2AUrl = $"https://{_networkAddress}/service/a2a/v{_apiVersion}";
            _a2AClient = new RestClient(safeguardA2AUrl);

            var safeguardCoreUrl = $"https://{_networkAddress}/service/core/v{_apiVersion}";
            _coreClient = new RestClient(safeguardCoreUrl);

            if (ignoreSsl)
            {
                _ignoreSsl = true;
                _validationCallback = null;
                _a2AClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
                _coreClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
            }
            else if (validationCallback != null)
            {
                _ignoreSsl = false;
                _validationCallback = validationCallback;
                _a2AClient.RemoteCertificateValidationCallback += validationCallback;
                _coreClient.RemoteCertificateValidationCallback += validationCallback;
            }

            _clientCertificate = clientCertificate.Clone();
            _a2AClient.ClientCertificates = new X509Certificate2Collection() {_clientCertificate.Certificate};
            _coreClient.ClientCertificates = new X509Certificate2Collection() {_clientCertificate.Certificate};
        }

        public SafeguardA2AContext(string networkAddress, string certificateThumbprint, int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : 
            this(networkAddress, new CertificateContext(certificateThumbprint), apiVersion, ignoreSsl, validationCallback)
        {
        }

        public SafeguardA2AContext(string networkAddress, string certificatePath, SecureString certificatePassword,
            int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) :
            this(networkAddress, new CertificateContext(certificatePath, certificatePassword), apiVersion, ignoreSsl, validationCallback)
        {
        }

        public SafeguardA2AContext(string networkAddress, IEnumerable<byte> certificateData, SecureString certificatePassword,
            int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) :
            this(networkAddress, new CertificateContext(certificateData, certificatePassword), apiVersion, ignoreSsl, validationCallback)
        {
        }

        public IList<A2ARetrievableAccount> GetRetrievableAccounts()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardA2AContext");

            var list = new List<A2ARetrievableAccount>();

            var request = new RestRequest("A2ARegistrations", RestSharp.Method.GET)
                .AddHeader("Accept", "application/json");
            var response = _coreClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to web service {_coreClient.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException(
                    "Error returned from Safeguard API, Error: " + $"{response.StatusCode} {response.Content}",
                    response.StatusCode, response.Content);
            var json = JArray.Parse(response.Content);
            dynamic registrations = json;
            foreach (var registration in registrations)
            {
                var registrationId = registration.Id;
                var retrievalRequest = new RestRequest($"A2ARegistrations/{registrationId}/RetrievableAccounts")
                    .AddHeader("Accept", "application/json");
                var retrievalResponse = _coreClient.Execute(retrievalRequest);
                if (retrievalResponse.ResponseStatus != ResponseStatus.Completed)
                    throw new SafeguardDotNetException($"Unable to connect to web service {_coreClient.BaseUrl}, Error: " +
                                                       retrievalResponse.ErrorMessage);
                if (!retrievalResponse.IsSuccessful)
                    throw new SafeguardDotNetException(
                        "Error returned from Safeguard API, Error: " +
                        $"{retrievalResponse.StatusCode} {retrievalResponse.Content}", retrievalResponse.StatusCode,
                        retrievalResponse.Content);
                var retrievalJson = JArray.Parse(retrievalResponse.Content);
                dynamic retrievals = retrievalJson;
                foreach (var retrieval in retrievals)
                {
                    list.Add(new A2ARetrievableAccount
                    {
                        ApplicationName = registration.AppName,
                        Description = registration.Description,
                        Disabled = (bool) registration.Disabled || (bool) (retrieval.AccountDisabled),
                        ApiKey = ((string) retrieval.ApiKey).ToSecureString(),
                        AssetId = retrieval.AssetId,
                        AssetName = retrieval.AssetName,
                        AssetNetworkAddress = retrieval.NetworkAddress,
                        AssetDescription = retrieval.AssetDescription,
                        AccountId = retrieval.AccountId,
                        AccountName = retrieval.AccountName,
                        DomainName = retrieval.DomainName,
                        AccountType = retrieval.AccountType,
                        AccountDescription = retrieval.AccountDescription
                    });
                }
            }
            return list;
        }

        public SecureString RetrievePassword(SecureString apiKey)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardA2AContext");
            if (apiKey == null)
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));

            var request = new RestRequest("Credentials", RestSharp.Method.GET)
                .AddParameter("type", "Password", ParameterType.QueryString)
                .AddHeader("Accept", "application/json")
                .AddHeader("Authorization", $"A2A {apiKey.ToInsecureString()}");
            var response = _a2AClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to web service {_a2AClient.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException(
                    "Error returned from Safeguard API, Error: " + $"{response.StatusCode} {response.Content}",
                    response.StatusCode, response.Content);
            var raw = string.IsNullOrEmpty(response.Content)
                ? response.Content
                : JToken.Parse(response.Content).ToString();
            Log.Information("Successfully retrieved A2A password.");
            return raw.ToSecureString();
        }

        public SecureString RetrievePrivateKey(SecureString apiKey, KeyFormat keyFormat = KeyFormat.OpenSsh)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardA2AContext");
            if (apiKey == null)
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));

            var request = new RestRequest("Credentials", RestSharp.Method.GET)
                .AddParameter("type", "PrivateKey", ParameterType.QueryString)
                .AddParameter("keyFormat", keyFormat.ToString(), ParameterType.QueryString)
                .AddHeader("Accept", "application/json")
                .AddHeader("Authorization", $"A2A {apiKey.ToInsecureString()}");
            var response = _a2AClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to web service {_a2AClient.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException(
                    "Error returned from Safeguard API, Error: " + $"{response.StatusCode} {response.Content}",
                    response.StatusCode, response.Content);
            var json = JToken.Parse(response.Content);
            Log.Information("Successfully retrieved A2A private key.");
            return json.Root.ToString().ToSecureString();
        }

        public IList<ApiKeySecret> RetrieveApiKeySecret(SecureString apiKey)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardA2AContext");
            if (apiKey == null)
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));

            var list = new List<ApiKeySecret>();

            var request = new RestRequest("Credentials", RestSharp.Method.GET)
                .AddParameter("type", "ApiKey", ParameterType.QueryString)
                .AddHeader("Accept", "application/json")
                .AddHeader("Authorization", $"A2A {apiKey.ToInsecureString()}");
            var response = _a2AClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to web service {_a2AClient.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException(
                    "Error returned from Safeguard API, Error: " + $"{response.StatusCode} {response.Content}",
                    response.StatusCode, response.Content);
            var json = JToken.Parse(response.Content);
            Log.Information("Successfully retrieved A2A API key.");
            var apiKeySecretsJson = JArray.Parse(response.Content);
            dynamic apiKeySecrets = apiKeySecretsJson;
            foreach (var apiKeySecret in apiKeySecrets)
            {
                list.Add(new ApiKeySecret
                {
                    Id = apiKeySecret.Id,
                    Name = apiKeySecret.Name,
                    Description = apiKeySecret.Description,
                    ClientId = apiKeySecret.ClientId,
                    ClientSecret = ((string)apiKeySecret.ClientSecret).ToSecureString(),
                    ClientSecretId = apiKeySecret.ClientSecretId
                });
            }

            return list;
        }

        public ISafeguardEventListener GetA2AEventListener(SecureString apiKey, SafeguardEventHandler handler)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardA2AContext");
            if (apiKey == null)
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));

            var eventListener = new SafeguardEventListener($"https://{_networkAddress}/service/a2a/signalr",
                _clientCertificate, apiKey, _ignoreSsl, _validationCallback);
            eventListener.RegisterEventHandler("AssetAccountPasswordUpdated", handler);
            eventListener.RegisterEventHandler("AssetAccountSshKeyUpdated", handler);
            Log.Debug("Event listener successfully created for Safeguard A2A context.");
            return eventListener;
        }

        public ISafeguardEventListener GetA2AEventListener(IEnumerable<SecureString> apiKeys, SafeguardEventHandler handler)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardA2AContext");
            if (apiKeys == null)
                throw new ArgumentException("Parameter may not be null", nameof(apiKeys));

            var eventListener = new SafeguardEventListener($"https://{_networkAddress}/service/a2a/signalr", _clientCertificate,
                apiKeys, _ignoreSsl, _validationCallback);
            eventListener.RegisterEventHandler("AssetAccountPasswordUpdated", handler);
            eventListener.RegisterEventHandler("AssetAccountSshKeyUpdated", handler);
            Log.Debug("Event listener successfully created for Safeguard A2A context.");
            return eventListener;
        }

        public ISafeguardEventListener GetPersistentA2AEventListener(SecureString apiKey, SafeguardEventHandler handler)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardA2AContext");
            if (apiKey == null)
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));

            return new PersistentSafeguardA2AEventListener(Clone() as SafeguardA2AContext, apiKey, handler);
        }

        public ISafeguardEventListener GetPersistentA2AEventListener(IEnumerable<SecureString> apiKeys,
            SafeguardEventHandler handler)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardA2AContext");
            if (apiKeys == null)
                throw new ArgumentException("Parameter may not be null", nameof(apiKeys));

            return new PersistentSafeguardA2AEventListener(Clone() as SafeguardA2AContext, apiKeys, handler);
        }

        public string BrokerAccessRequest(SecureString apiKey, BrokeredAccessRequest accessRequest)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardA2AContext");
            if (apiKey == null)
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));
            if (accessRequest == null)
                throw new ArgumentException("Parameter may not be null", nameof(accessRequest));
            if (accessRequest.ForUserId == null && accessRequest.ForUserName == null)
                throw new SafeguardDotNetException("You must specify a user to create an access request for");
            if (accessRequest.AssetId == null && accessRequest.AssetName == null)
                throw new SafeguardDotNetException("You must specify an asset to create an access request for");

            var request = new RestRequest("AccessRequests", RestSharp.Method.POST)
                .AddHeader("Accept", "application/json")
                .AddHeader("Authorization", $"A2A {apiKey.ToInsecureString()}");
            var body = JsonConvert.SerializeObject(accessRequest);
            request.AddParameter("application/json", body, ParameterType.RequestBody);
            var response = _a2AClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to web service {_a2AClient.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException(
                    "Error returned from Safeguard API, Error: " + $"{response.StatusCode} {response.Content}",
                    response.StatusCode, response.Content);
            Log.Information("Successfully created A2A access request.");
            return response.Content;
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
                _clientCertificate?.Dispose();
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
    }
}
