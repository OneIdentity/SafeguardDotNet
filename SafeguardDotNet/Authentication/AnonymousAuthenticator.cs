// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Authentication
{
    using System.Net.Http;
    using System.Net.Security;
    using System.Security;

    internal class AnonymousAuthenticator : AuthenticatorBase
    {
        public AnonymousAuthenticator(string networkAddress, int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback)
            : base(networkAddress, apiVersion, ignoreSsl, validationCallback)
        {
            var notificationUrl = $"https://{NetworkAddress}/service/notification/v{ApiVersion}/Status";

            try
            {
                _ = ApiRequest(HttpMethod.Get, notificationUrl);
            }
            catch (HttpRequestException ex)
            {
                throw new SafeguardDotNetException($"Unable to anonymously connect to {networkAddress}, Error: {ex.Message}");
            }
        }

        public override string Id => "Anonymous";

        public override bool IsAnonymous => true;

        protected override SecureString GetRstsTokenInternal()
        {
            throw new SafeguardDotNetException("Anonymous connection cannot be used to get an API access token, Error: Unsupported operation");
        }

        public override object Clone()
        {
            throw new SafeguardDotNetException("Anonymous authenticators are not cloneable");
        }
    }
}
