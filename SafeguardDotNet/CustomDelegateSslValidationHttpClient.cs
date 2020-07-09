using System;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNet.SignalR.Client.Http;

namespace OneIdentity.SafeguardDotNet
{
    internal class CustomDelegateSslValidationHttpClient : DefaultHttpClient
    {
        private readonly RemoteCertificateValidationCallback _validationCallback;

        public CustomDelegateSslValidationHttpClient(RemoteCertificateValidationCallback validationCallback)
        {
            _validationCallback = validationCallback;
        }

        protected override HttpMessageHandler CreateHandler()
        {
            var messageHandler = base.CreateHandler();
            if (!(messageHandler is HttpClientHandler))
            {
                throw new Exception("Unable to create the customer HttpClientHandler");
            }
            if (_validationCallback == null)
            {
                throw new Exception("Unable to get HttpClientHandler to ignore certificate errors");
            }
            ((HttpClientHandler)messageHandler).ServerCertificateCustomValidationCallback = ValidationCallback;
            return messageHandler;
        }

        bool ValidationCallback(HttpRequestMessage sender, X509Certificate2 certificate, X509Chain chain,
            SslPolicyErrors sslPolicyErrors)
        {
            return _validationCallback(sender, certificate, chain, sslPolicyErrors);
        }
    }
}
