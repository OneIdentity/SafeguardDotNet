// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Authentication
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Net.Security;
    using System.Security;

    using Newtonsoft.Json;
    using Newtonsoft.Json.Linq;

    internal class CertificateAuthenticator : AuthenticatorBase
    {
        private readonly string _provider;

        public CertificateAuthenticator(
            string networkAddress,
            string certificateThumbprint,
            int apiVersion,
            bool ignoreSsl,
            RemoteCertificateValidationCallback validationCallback)
            : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificateThumbprint))
        {
        }

        public CertificateAuthenticator(
            string networkAddress,
            string certificatePath,
            SecureString certificatePassword,
            int apiVersion,
            bool ignoreSsl,
            RemoteCertificateValidationCallback validationCallback)
            : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificatePath, certificatePassword))
        {
        }

        public CertificateAuthenticator(
            string networkAddress,
            IEnumerable<byte> certificateData,
            SecureString certificatePassword,
            int apiVersion,
            bool ignoreSsl,
            RemoteCertificateValidationCallback validationCallback)
            : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificateData, certificatePassword))
        {
        }

        private CertificateAuthenticator(
            string networkAddress,
            CertificateContext clientCertificate,
            int apiVersion,
            bool ignoreSsl,
            RemoteCertificateValidationCallback validationCallback)
            : base(networkAddress, apiVersion, ignoreSsl, validationCallback, clientCertificate.Clone())
        {
        }

        public CertificateAuthenticator(
            string networkAddress,
            string certificateThumbprint,
            int apiVersion,
            bool ignoreSsl,
            RemoteCertificateValidationCallback validationCallback,
            string provider)
            : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificateThumbprint))
        {
            _provider = provider;
        }

        public CertificateAuthenticator(
            string networkAddress,
            string certificatePath,
            SecureString certificatePassword,
            int apiVersion,
            bool ignoreSsl,
            RemoteCertificateValidationCallback validationCallback,
            string provider)
            : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificatePath, certificatePassword))
        {
            _provider = provider;
        }

        public CertificateAuthenticator(
            string networkAddress,
            IEnumerable<byte> certificateData,
            SecureString certificatePassword,
            int apiVersion,
            bool ignoreSsl,
            RemoteCertificateValidationCallback validationCallback,
            string provider)
            : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificateData, certificatePassword))
        {
            _provider = provider;
        }

        public override string Id => "Certificate";

        protected override SecureString GetRstsTokenInternal()
        {
            if (IsDisposed)
            {
                throw new ObjectDisposedException("CertificateAuthenticator");
            }

            var providerScope = "rsts:sts:primaryproviderid:certificate";

            if (!string.IsNullOrEmpty(_provider))
            {
                providerScope = ResolveProviderToScope(_provider);
            }

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
            var auth = new CertificateAuthenticator(NetworkAddress, clientCertificate, ApiVersion, IgnoreSsl, ValidationCallback)
            {
                accessToken = accessToken?.Copy(),
            };
            return auth;
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                base.Dispose(disposing);
                clientCertificate?.Dispose();
            }
        }
    }
}
