using System.Security;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class AnonymousAuthenticator : AuthenticatorBase
    {
        public AnonymousAuthenticator(string networkAddress, int apiVersion, bool ignoreSsl) :
            base(networkAddress, apiVersion, ignoreSsl)
        {
        }

        protected override SecureString GetRstsTokenInternal()
        {
            throw new SafeguardDotNetException("Anonymous connection cannot be used to get an API access token, Error: Unsupported operation");
        }
    }
}
