using System.Collections.Generic;
using RestSharp;
using RestSharp.Authenticators;
using System.Security;
using System.Net;
using Serilog;
using System;

namespace OneIdentity.SafeguardDotNet.Sps
{
    /// <summary>
    /// This is the reusable connection interface that can be used to call SPS API.
    /// </summary>
    internal class SafeguardSessionsConnection : ISafeguardSessionsConnection
    {
        private bool _disposed;

        private readonly RestClient _client;

        private readonly ISpsAuthenticator _authenticator;

        private readonly Lazy<ISpsStreamingRequest> _lazyStreamingRequest;
        
        public ISpsStreamingRequest Streaming => _lazyStreamingRequest.Value;

        public SafeguardSessionsConnection(ISpsAuthenticator authenticator)
        {
            _authenticator = authenticator;

            _client = new RestClient($"https://{_authenticator.NetworkAddress}/api")
            {
                CookieContainer = new CookieContainer(),
                Authenticator = new HttpBasicAuthenticator(_authenticator.UserName, _authenticator.Password.ToInsecureString()),
            };

            if (_authenticator.IgnoreSsl)
            {
                _client.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
            }

            var authRequest = new RestRequest("authentication", RestSharp.Method.GET);

            _client.LogRequestDetails(authRequest);

            var response = _client.Get(new RestRequest("authentication", RestSharp.Method.GET));

            response.LogResponseDetails();

            if (!response.IsSuccessful)
            {
                throw new SafeguardDotNetException($"Error returned when authenticating to {_client.BaseUrl} sps api.", response.StatusCode, response.Content);
            }

            _lazyStreamingRequest = new Lazy<ISpsStreamingRequest>(() =>
            {
                return new SpsStreamingRequest(_authenticator, () => _disposed);
            });
        }

        public string InvokeMethod(Method method, string relativeUrl, string body = null)
        {
            return InvokeMethodFull(method, relativeUrl, body).Body;
        }

        /// <summary>
        /// Call a SafeguardForPrivilegedSessions API method and get a detailed response with status code, headers,
        /// and body. If there is a failure a SafeguardDotNetException will be thrown.
        /// </summary>
        /// <param name="method">HTTP method type to use.</param>
        /// <param name="relativeUrl">The url.</param>
        /// <param name="body">Request body to pass to the method.</param>
        /// <returns>Response with status code, headers, and body as string.</returns>
        public FullResponse InvokeMethodFull(Method method, string relativeUrl, string body = null)
        {
            var request = new RestRequest(relativeUrl, method.ConvertToRestSharpMethod());

            if ((method == Method.Post || method == Method.Put) && body != null)
                request.AddParameter("application/json", body, ParameterType.RequestBody);

            _client.LogRequestDetails(request);

            var response = _client.Execute(request);

            response.LogResponseDetails();

            if (response.ResponseStatus != ResponseStatus.Completed)
            {
                throw new SafeguardDotNetException($"Unable to connect to web service {_client.BaseUrl}, Error: {response.ErrorMessage}");
            }

            if (!response.IsSuccessful)
            {
                throw new SafeguardDotNetException($"Error returned from {_client.BaseUrl} sps api", response.StatusCode, response.Content);
            }

            return new FullResponse
            {
                StatusCode = response.StatusCode,
                Headers = new Dictionary<string, string>(),
                Body = response.Content
            };
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
            {
                return;
            }

            try
            {
                if (_lazyStreamingRequest.IsValueCreated)
                    Streaming.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }

    }
}
