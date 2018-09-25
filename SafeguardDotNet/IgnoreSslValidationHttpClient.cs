using System;
using System.Net.Http;
using Microsoft.AspNet.SignalR.Client.Http;

namespace OneIdentity.SafeguardDotNet
{
    internal class IgnoreSslValidationHttpClient : DefaultHttpClient
    {
        protected override HttpMessageHandler CreateHandler()
        {
            var messageHandler = base.CreateHandler();
            if (!(messageHandler is HttpClientHandler))
            {
                throw new Exception("Unable to get HttpClientHandler to ignore certificate errors0");
            }
            ((HttpClientHandler)messageHandler).ServerCertificateCustomValidationCallback =
                (message, cert, chain, errors) => true;
            return messageHandler;
        }
    }
}
