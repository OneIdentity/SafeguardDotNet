using System;
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
        private readonly bool _ignoreSsl;

        private readonly X509Certificate2 _clientCertificate;
        private readonly RestClient _a2AClient;

        // only used for cloning
        private readonly string _certificateThumbprint;
        private readonly string _certificatePath;
        private readonly SecureString _certificatePassword;
        private readonly int _apiVersion;

        private SafeguardA2AContext(string networkAddress, string certificateThumbprint, string certificatePath,
            SecureString certificatePassword, int apiVersion, bool ignoreSsl)
        {
            _networkAddress = networkAddress;

            // set cloning properties
            _certificateThumbprint = certificateThumbprint;
            _certificatePath = certificatePath;
            _certificatePassword = certificatePassword.Copy();
            _apiVersion = apiVersion;

            var safeguardA2AUrl = $"https://{_networkAddress}/service/a2a/v{_apiVersion}";
            _a2AClient = new RestClient(safeguardA2AUrl);

            if (ignoreSsl)
            {
                _ignoreSsl = true;
                _a2AClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
            }
            _clientCertificate = !string.IsNullOrEmpty(_certificateThumbprint)
                ? CertificateUtilities.GetClientCertificateFromStore(_certificateThumbprint)
                : CertificateUtilities.GetClientCertificateFromFile(_certificatePath, _certificatePassword);
            _a2AClient.ClientCertificates = new X509Certificate2Collection() { _clientCertificate };
        }

        public SafeguardA2AContext(string networkAddress, string certificateThumbprint, int apiVersion, bool ignoreSsl) : 
            this(networkAddress, certificateThumbprint, null, null, apiVersion, ignoreSsl)
        {
        }

        public SafeguardA2AContext(string networkAddress, string certificatePath, SecureString certificatePassword,
            int apiVersion, bool ignoreSsl) :
            this(networkAddress, null, certificatePath, certificatePassword,
                apiVersion, ignoreSsl)
        {
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
                throw new SafeguardDotNetException("Error returned from Safeguard API, Error: " +
                                                   $"{response.StatusCode} {response.Content}", response.Content);
            var json = JToken.Parse(response.Content);
            Log.Information("Successfully retrieved A2A password.");
            return json.Root.ToString().ToSecureString();
        }

        public ISafeguardEventListener GetA2AEventListener(SecureString apiKey, SafeguardEventHandler handler)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardA2AContext");
            if (apiKey == null)
                throw new ArgumentException("Parameter may not be null", nameof(apiKey));

            var eventListener = new SafeguardEventListener($"https://{_networkAddress}/service/a2a", _clientCertificate,
                apiKey, _ignoreSsl);
            eventListener.RegisterEventHandler("AssetAccountPasswordUpdated", handler);
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
                throw new SafeguardDotNetException("Error returned from Safeguard API, Error: " +
                                                   $"{response.StatusCode} {response.Content}", response.Content);
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
            return !string.IsNullOrEmpty(_certificateThumbprint)
                ? new SafeguardA2AContext(_networkAddress, _certificateThumbprint, _apiVersion, _ignoreSsl)
                : new SafeguardA2AContext(_networkAddress, _certificatePath, _certificatePassword, _apiVersion, _ignoreSsl);
        }
    }
}
