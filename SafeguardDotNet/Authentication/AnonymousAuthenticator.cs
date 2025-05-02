using System.Net.Http;
using System.Net.Security;
using System.Security;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class AnonymousAuthenticator : AuthenticatorBase
    {
        public AnonymousAuthenticator(string networkAddress, int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) :
            base(networkAddress, apiVersion, ignoreSsl, validationCallback)
        {
            var notificationUrl = $"https://{NetworkAddress}/service/notification/v{ApiVersion}/Status";

            _ = ApiRequest(HttpMethod.Get, notificationUrl);
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
