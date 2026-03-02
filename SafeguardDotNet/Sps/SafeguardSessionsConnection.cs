// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Sps
{
    using System;
    using System.Collections.Generic;
    using System.Net;
    using System.Net.Http;
    using System.Text;
    using System.Threading.Tasks;

    /// <summary>
    /// This is the reusable connection interface that can be used to call SPS API.
    /// </summary>
    internal class SafeguardSessionsConnection : ISafeguardSessionsConnection
    {
        private bool _disposed;

        private readonly HttpClient _client;

        private readonly Uri _spsUri;

        private readonly ISpsAuthenticator _authenticator;

        private readonly Lazy<ISpsStreamingRequest> _lazyStreamingRequest;

        public ISpsStreamingRequest Streaming => _lazyStreamingRequest.Value;

        public SafeguardSessionsConnection(ISpsAuthenticator authenticator)
        {
            _authenticator = authenticator;
            _spsUri = new Uri($"https://{_authenticator.NetworkAddress}/api/", UriKind.Absolute);

            _client = CreateHttpClient();

            _ = InvokeMethod(Method.Get, "authentication");

            _lazyStreamingRequest = new Lazy<ISpsStreamingRequest>(() =>
            {
                return new SpsStreamingRequest(_authenticator, () => _disposed);
            });
        }

        private HttpClient CreateHttpClient()
        {
            var handler = new HttpClientHandler
            {
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12,
            };

            if (_authenticator.IgnoreSsl)
            {
#pragma warning disable S4830 // Server certificate validation is intentionally bypassed when IgnoreSsl is set
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
#pragma warning restore S4830
            }

            handler.CookieContainer = new CookieContainer();
            handler.UseCookies = true;
            handler.PreAuthenticate = true;

            var c = new HttpClient(handler);

            c.DefaultRequestHeaders.Authorization = _authenticator.GetAuthenticationHeader();

            return c;
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
        /// <param name="relativeUrl">Relative portion of the URL. Do not include a leading forward slash.</param>
        /// <param name="body">Request body to pass to the method.</param>
        /// <returns>Response with status code, headers, and body as string.</returns>
        public FullResponse InvokeMethodFull(Method method, string relativeUrl, string body = null)
        {
            var req = new HttpRequestMessage
            {
                Method = method.ConvertToHttpMethod(),
                RequestUri = new Uri(_spsUri, relativeUrl),
            };

            req.Headers.Add("Accept", "application/json");

            if ((method == Method.Post || method == Method.Put) && body != null)
            {
                req.Content = new StringContent(body, Encoding.UTF8, "application/json");
            }

            try
            {
                req.LogRequestDetails();

                var res = _client.SendAsync(req).GetAwaiter().GetResult();
                var msg = res.Content?.ReadAsStringAsync().GetAwaiter().GetResult();

                if (!res.IsSuccessStatusCode)
                {
                    throw new SafeguardDotNetException($"Error returned from Safeguard API, Error: {res.StatusCode} {msg}", res.StatusCode, msg);
                }

                var fr = new FullResponse
                {
                    StatusCode = res.StatusCode,
                    Headers = new Dictionary<string, string>(),
                    Body = msg,
                };

                fr.LogResponseDetails();

                return fr;
            }
            catch (TaskCanceledException)
            {
                throw new SafeguardDotNetException($"Request timeout to {req.RequestUri}.");
            }
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
                {
                    Streaming.Dispose();
                }
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
