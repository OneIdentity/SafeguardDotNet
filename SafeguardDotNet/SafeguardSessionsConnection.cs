using System;
using System.Collections.Generic;
using OneIdentity.SafeguardDotNet.Event;
using RestSharp;
using RestSharp.Authenticators;
using System.Security;
using System.Net;
using Serilog;

namespace OneIdentity.SafeguardDotNet
{
    /// <summary>
    /// This is the reusable connection interface that can be used to call SPS API.
    /// </summary>
    internal class SafeguardSessionsConnection : ISafeguardSessionsConnection
    {
        private readonly RestClient _client;
        public SafeguardSessionsConnection(string networkAddress, string username,
            SecureString password, bool ignoreSsl = false)
        {
            var spsApiUrl = $"https://{networkAddress}/api";
            _client = new RestClient(spsApiUrl);
            CookieContainer _cookieJar = new CookieContainer();
            _client.CookieContainer = _cookieJar;

            Log.Debug("Starting authentication.");
            _client.Authenticator = new HttpBasicAuthenticator(username, password.ToInsecureString());
            if (ignoreSsl)
            {
                _client.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
            }
            var request = new RestRequest("authentication", RestSharp.Method.GET);
            var response = _client.Get(request);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException(
                    "Error returned when authenticating to sps api, Error: " + $"{response.StatusCode} {response.Content}",
                    response.StatusCode, response.Content);
            Log.Debug("Response content.", response.Content);
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
            Log.Debug("Invoking method on sps.", relativeUrl);
            var request = new RestRequest(relativeUrl, method.ConvertToRestSharpMethod());
            if ((method == Method.Post || method == Method.Put) && body != null)
                request.AddParameter("application/json", body, ParameterType.RequestBody);
            var response = _client.Execute(request);

            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to web service {_client.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException(
                    "Error returned from SPS API, Error: " + $"{response.StatusCode} {response.Content}",
                    response.StatusCode, response.Content);

            Log.Debug("Invoking method finished.", response.Content);

            return new FullResponse
            {
                StatusCode = response.StatusCode,
                Headers = new Dictionary<string, string>(),
                Body = response.Content
            };
        }
    }
}
