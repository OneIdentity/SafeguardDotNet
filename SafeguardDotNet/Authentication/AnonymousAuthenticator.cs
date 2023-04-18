using System.Net.Security;
using System.Security;
using RestSharp;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class AnonymousAuthenticator : AuthenticatorBase
    {
        public AnonymousAuthenticator(string networkAddress, int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) :
            base(networkAddress, apiVersion, ignoreSsl, validationCallback)
        {
            var notificationUrl = $"https://{NetworkAddress}/service/notification/v{ApiVersion}";
            var notificationClient = CreateRestClient(notificationUrl);
            
            var request = new RestRequest("Status", RestSharp.Method.Get)
                .AddHeader("Accept", "application/json")
                .AddHeader("Content-type", "application/json");
            var response = notificationClient.Execute(request);
            if (!response.IsSuccessful)
            {
                throw new SafeguardDotNetException($"Unable to anonymously connect to {networkAddress}, Error: " +
                                                   response.ErrorMessage);
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
