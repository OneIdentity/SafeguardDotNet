using System;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json.Linq;
using RestSharp;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class CertificateAuthenticator : AuthenticatorBase
    {
        private bool _disposed;

        private readonly string _certificateThumbprint;
        private readonly string _certificatePath;
        private readonly SecureString _certificatePassword;

        public CertificateAuthenticator(string networkAddress, string certificateThumbprint, int apiVersion,
            bool ignoreSsl) : base(networkAddress, apiVersion, ignoreSsl)
        {
            _certificateThumbprint = certificateThumbprint;
        }

        public CertificateAuthenticator(string networkAddress, string certificatePath, SecureString certificatePassword,
            int apiVersion, bool ignoreSsl) : base(networkAddress, apiVersion, ignoreSsl)
        {
            _certificatePath = certificatePath;
            _certificatePassword = certificatePassword.Copy();
        }

        protected override SecureString GetRstsTokenInternal()
        {
            if (_disposed)
                throw new ObjectDisposedException("CertificateAuthenticator");

            var request = new RestRequest("oauth2/token", RestSharp.Method.POST)
                .AddHeader("Accept", "application/json")
                .AddHeader("Content-type", "application/json")
                .AddJsonBody(new
                {
                    grant_type = "client_credentials",
                    scope = "rsts:sts:primaryproviderid:certificate"
                });
            var userCert = !string.IsNullOrEmpty(_certificateThumbprint)
                ? CertificateUtilities.GetClientCertificateFromStore(_certificateThumbprint)
                : CertificateUtilities.GetClientCertificateFromFile(_certificatePath, _certificatePassword);
            RstsClient.ClientCertificates = new X509Certificate2Collection() { userCert };
            var response = RstsClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to RSTS service {RstsClient.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException("Error using client_credentials grant_type with " +
                                                   $"{(string.IsNullOrEmpty(_certificatePath) ? $"thumbprint={_certificateThumbprint}" : $"file={_certificatePath}")}" +
                                                   $", Error: {response.StatusCode} {response.Content}", response.Content);
            var jObject = JObject.Parse(response.Content);
            return jObject.GetValue("access_token").ToString().ToSecureString();
        }

        protected override void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
                return;
            base.Dispose(true);
            try
            {
                _certificatePassword?.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
