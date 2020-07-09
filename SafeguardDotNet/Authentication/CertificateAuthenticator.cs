using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json.Linq;
using RestSharp;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class CertificateAuthenticator : AuthenticatorBase
    {
        private bool _disposed;

        private readonly CertificateContext _clientCertificate;

        public CertificateAuthenticator(string networkAddress, string certificateThumbprint, int apiVersion,
            bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : base(networkAddress, apiVersion, ignoreSsl, validationCallback)
        {
            _clientCertificate = new CertificateContext(certificateThumbprint);
        }

        public CertificateAuthenticator(string networkAddress, string certificatePath, SecureString certificatePassword,
            int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : base(networkAddress, apiVersion, ignoreSsl, validationCallback)
        {
            _clientCertificate = new CertificateContext(certificatePath, certificatePassword);
        }

        public CertificateAuthenticator(string networkAddress, IEnumerable<byte> certificateData, SecureString certificatePassword, 
            int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : base(networkAddress, apiVersion, ignoreSsl, validationCallback)
        {
            _clientCertificate = new CertificateContext(certificateData, certificatePassword);
        }

        private CertificateAuthenticator(string networkAddress, CertificateContext clientCertificate, int apiVersion,
            bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : base(networkAddress, apiVersion, ignoreSsl, validationCallback)
        {
            _clientCertificate = clientCertificate.Clone();
        }

        public override string Id => "Certificate";

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
            RstsClient.ClientCertificates = new X509Certificate2Collection() { _clientCertificate.Certificate };
            var response = RstsClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to RSTS service {RstsClient.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException(
                    $"Error using client_credentials grant_type with {_clientCertificate}" +
                    $", Error: {response.StatusCode} {response.Content}", response.StatusCode, response.Content);
            var jObject = JObject.Parse(response.Content);
            return jObject.GetValue("access_token").ToString().ToSecureString();
        }

        public override object Clone()
        {
            var auth = new CertificateAuthenticator(NetworkAddress, _clientCertificate, ApiVersion, IgnoreSsl, ValidationCallback)
            {
                AccessToken = AccessToken?.Copy()
            };
            return auth;
        }

        protected override void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
                return;
            base.Dispose(true);
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
