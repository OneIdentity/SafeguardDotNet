// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Authentication
{
    using System;
    using System.Net.Security;
    using System.Security;

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
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            // Nothing to dispose
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
            throw new SafeguardDotNetException("Management Service connection cannot be used to get an API access token, Error: Unsupported operation");
        }

        public string ResolveProviderToScope(string provider)
        {
            throw new SafeguardDotNetException("Management Service connection does not require a provider, Error: Unsupported operation");
        }
    }
}
