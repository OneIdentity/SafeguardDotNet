using System.Security;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class AccessTokenAuthenticator : AuthenticatorBase
    {
        private bool _disposed;

        public AccessTokenAuthenticator(string networkAddress, SecureString accessToken,
            int apiVersion, bool ignoreSsl) : base(networkAddress, apiVersion, ignoreSsl)
        {
            AccessToken = accessToken.Copy();
        }

        protected override SecureString GetRstsTokenInternal()
        {
            throw new SafeguardDotNetException("Original authentication was with access token unable to refresh, Error: Unsupported operation");
        }

        protected override void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
                return;
            base.Dispose(true);
            _disposed = true;
        }
    }
}
