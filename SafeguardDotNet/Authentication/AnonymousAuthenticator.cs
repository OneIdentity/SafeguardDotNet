using System.Security;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class AnonymousAuthenticator : AuthenticatorBase
    {
        private bool _disposed;

        public AnonymousAuthenticator(string networkAddress, int apiVersion, bool ignoreSsl) :
            base(networkAddress, apiVersion, ignoreSsl)
        {
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

        protected override void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
                return;
            base.Dispose(true);
            _disposed = true;
        }
    }
}
