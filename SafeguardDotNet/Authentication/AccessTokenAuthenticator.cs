using System;
using System.Security;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class AccessTokenAuthenticator : AuthenticatorBase
    {
        public AccessTokenAuthenticator(string networkAddress, SecureString accessToken,
            int apiVersion, bool ignoreSsl) : base(networkAddress, apiVersion, ignoreSsl)
        {
            AccessToken = accessToken;
        }

        protected override SecureString GetRstsTokenInternal()
        {
            throw new SafeguardDotNetException("Original authentication was with access token unable to refresh, Error: Unsupported operation");
        }
    }
}
