using System;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json.Linq;
using RestSharp;

namespace OneIdentity.SafeguardDotNet
{
    internal class A2AContext : IA2AContext
    {
        private readonly RestClient _a2AClient;

        private A2AContext(string networkAddress, string certificateThumbprint, string certificatePath,
            SecureString certificatePassword, int apiVersion, bool ignoreSsl)
        {
            var safeguardA2AUrl = $"https://{networkAddress}/service/a2a/v{apiVersion}";
            _a2AClient = new RestClient(safeguardA2AUrl);

            if (ignoreSsl)
                _a2AClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;

            var userCert = !string.IsNullOrEmpty(certificateThumbprint)
                ? CertificateUtilities.GetClientCertificateFromStore(certificateThumbprint)
                : CertificateUtilities.GetClientCertificateFromFile(certificatePath, certificatePassword);
            _a2AClient.ClientCertificates = new X509Certificate2Collection() { userCert };
        }

        public A2AContext(string networkAddress, string certificateThumbprint, int apiVersion, bool ignoreSsl) : 
            this(networkAddress, certificateThumbprint, null, null, apiVersion, ignoreSsl)
        {
        }

        public A2AContext(string networkAddress, string certificatePath, SecureString certificatePassword,
            int apiVersion, bool ignoreSsl) :
            this(networkAddress, null, certificatePath, certificatePassword,
                apiVersion, ignoreSsl)
        {
        }

        public SecureString RetrievePassword(string apiKey)
        {
            var request = new RestRequest("Credentials", RestSharp.Method.GET)
                .AddParameter("type", "Password", ParameterType.QueryString)
                .AddHeader("Accept", "application/json")
                .AddHeader("Authorization", $"Bearer A2A {apiKey}");
            var response = _a2AClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new Exception($"Unable to connect to web service {_a2AClient.BaseUrl}, Error: " +
                                    response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new Exception("Error calling Safeguard Web API, Error: " +
                                    $"{response.StatusCode} {response.Content}");
            var jsonObject = JObject.Parse(response.Content);
            return "".ToSecureString();
        }
    }
}
