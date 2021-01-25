using System.Net.Security;
using System.Security;
using RestSharp;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class AnonymousAuthenticator : AuthenticatorBase
    {
        private bool _disposed;

        public AnonymousAuthenticator(string networkAddress, int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback) :
            base(networkAddress, apiVersion, ignoreSsl, validationCallback)
        {
            var notificationUrl = $"https://{NetworkAddress}/service/notification/v{ApiVersion}";
            var notificationClient = new RestClient(notificationUrl);
            if (ignoreSsl)
                notificationClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
            else if (validationCallback != null)
                notificationClient.RemoteCertificateValidationCallback += validationCallback;
            var request = new RestRequest("Status", RestSharp.Method.GET)
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

        protected override void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
                return;
            base.Dispose(true);
            _disposed = true;
        }
    }
}
