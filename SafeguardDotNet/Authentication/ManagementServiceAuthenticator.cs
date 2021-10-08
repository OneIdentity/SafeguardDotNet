using System;
using System.Collections.Generic;
using System.Net.Security;
using System.Security;
using System.Text;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class ManagementServiceAuthenticator : IAuthenticationMechanism
    {
        internal ManagementServiceAuthenticator(IAuthenticationMechanism parentAuthenticationMechanism, string networkAddress)
        {
            ApiVersion = parentAuthenticationMechanism.ApiVersion;
            IgnoreSsl = parentAuthenticationMechanism.IgnoreSsl;
            ValidationCallback = parentAuthenticationMechanism.ValidationCallback;
            NetworkAddress = networkAddress;
        }

        public string Id => "Management";

        public string NetworkAddress { get; }

        public int ApiVersion { get; }

        public bool IgnoreSsl { get; }

        public RemoteCertificateValidationCallback ValidationCallback { get; }

        public bool IsAnonymous => true;

        public void ClearAccessToken()
        {
            // There is no access token for anonymous auth
        }

        public object Clone()
        {
            throw new SafeguardDotNetException("Anonymous authenticators are not cloneable");
        }

        public void Dispose()
        {
            // Nothing to do
        }

        public SecureString GetAccessToken()
        {
            return null;
        }

        public int GetAccessTokenLifetimeRemaining()
        {
            return 0;
        }

        public bool HasAccessToken()
        {
            return false;
        }

        public void RefreshAccessToken()
        {
            throw new SafeguardDotNetException("Anonymous connection cannot be used to get an API access token, Error: Unsupported operation");
        }

        public string ResolveProviderToScope(string provider)
        {
            throw new SafeguardDotNetException("Anonymous connection does not require a provider, Error: Unsupported operation");
        }
    }
}
