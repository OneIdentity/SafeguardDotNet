using System;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json.Linq;
using RestSharp;

namespace OneIdentity.SafeguardDotNet
{
    internal class SafeguardA2AContext : ISafeguardA2AContext
    {
        private bool _disposed;

        private readonly X509Certificate2 _clientCertificate;
        private readonly RestClient _a2AClient;

        private SafeguardA2AContext(string networkAddress, string certificateThumbprint, string certificatePath,
            SecureString certificatePassword, int apiVersion, bool ignoreSsl)
        {
            var safeguardA2AUrl = $"https://{networkAddress}/service/a2a/v{apiVersion}";
            _a2AClient = new RestClient(safeguardA2AUrl);

            if (ignoreSsl)
                _a2AClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;

            _clientCertificate = !string.IsNullOrEmpty(certificateThumbprint)
                ? CertificateUtilities.GetClientCertificateFromStore(certificateThumbprint)
                : CertificateUtilities.GetClientCertificateFromFile(certificatePath, certificatePassword);
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

        public SecureString RetrievePassword(string apiKey)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardA2AContext");

            var request = new RestRequest("Credentials", RestSharp.Method.GET)
                .AddParameter("type", "Password", ParameterType.QueryString)
                .AddHeader("Accept", "application/json")
                .AddHeader("Authorization", $"A2A {apiKey}");
            var response = _a2AClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to web service {_a2AClient.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException("Error returned from Safeguard API, Error: " +
                                                   $"{response.StatusCode} {response.Content}", response.Content);
            var json = JToken.Parse(response.Content);
            return json.Root.ToString().ToSecureString();
        }

        public ISafeguardEventListener GetEventListener(SafeguardEventHandler handler)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardA2AContext");

            // TODO: get this right
            var eventHandler = new SafeguardEventListener("", null);
            eventHandler.RegisterEventHandler("AssetAccountPasswordUpdated", handler);
            return eventHandler;
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
    }
}
