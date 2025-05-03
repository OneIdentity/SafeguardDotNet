﻿using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Security;
using System.Security;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class CertificateAuthenticator : AuthenticatorBase
    {
        private readonly string _provider;

        public CertificateAuthenticator(string networkAddress, string certificateThumbprint, int apiVersion,
            bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificateThumbprint))
        {
        }

        public CertificateAuthenticator(string networkAddress, string certificatePath, SecureString certificatePassword,
            int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificatePath, certificatePassword))
        {
        }

        public CertificateAuthenticator(string networkAddress, IEnumerable<byte> certificateData, SecureString certificatePassword, 
            int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificateData, certificatePassword))
        {
        }

        private CertificateAuthenticator(string networkAddress, CertificateContext clientCertificate, int apiVersion,
            bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) : base(networkAddress, apiVersion, ignoreSsl, validationCallback, clientCertificate.Clone())
        {
        }

        public CertificateAuthenticator(string networkAddress, string certificateThumbprint, int apiVersion,
            bool ignoreSsl, RemoteCertificateValidationCallback validationCallback, string provider) : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificateThumbprint))
        {
            _provider = provider;
        }

        public CertificateAuthenticator(string networkAddress, string certificatePath, SecureString certificatePassword,
            int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback, string provider) : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificatePath, certificatePassword))
        {
            _provider = provider;
        }

        public CertificateAuthenticator(string networkAddress, IEnumerable<byte> certificateData, SecureString certificatePassword,
            int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback, string provider) : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificateData, certificatePassword))
        {
            _provider = provider;
        }

        // Retaining this constructor in case we need to create from CertificateContext again in the future
        // ReSharper disable once UnusedMember.Local
        private CertificateAuthenticator(string networkAddress, CertificateContext clientCertificate, int apiVersion,
            bool ignoreSsl, RemoteCertificateValidationCallback validationCallback, string provider) : base(networkAddress, apiVersion, ignoreSsl, validationCallback, clientCertificate.Clone())
        {
            _provider = provider;
        }

        public override string Id => "Certificate";

        protected override SecureString GetRstsTokenInternal()
        {
            if (IsDisposed)
                throw new ObjectDisposedException("CertificateAuthenticator");

            var providerScope = "rsts:sts:primaryproviderid:certificate";

            if (!string.IsNullOrEmpty(_provider))
                providerScope = ResolveProviderToScope(_provider);

            var data = JsonConvert.SerializeObject(new
            {
                grant_type = "client_credentials",
                scope = providerScope,
            });

            var json = ApiRequest(HttpMethod.Post, $"https://{NetworkAddress}/RSTS/oauth2/token", data);

            var jObject = JObject.Parse(json);
            return jObject.GetValue("access_token")?.ToString().ToSecureString();
        }

        public override object Clone()
        {
            var auth = new CertificateAuthenticator(NetworkAddress, ClientCertificate, ApiVersion, IgnoreSsl, ValidationCallback)
            {
                AccessToken = AccessToken?.Copy()
            };
            return auth;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(true);
            ClientCertificate?.Dispose();
        }
    }
}
