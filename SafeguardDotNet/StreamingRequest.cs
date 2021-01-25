using Microsoft.AspNetCore.WebUtilities;
using OneIdentity.SafeguardDotNet.Authentication;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Handlers;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace OneIdentity.SafeguardDotNet
{
    internal class StreamingRequest : IStreamingRequest
    {
        const int DefaultBufferSize = 81920;
        private readonly ProgressMessageHandler _progressMessageHandler = new ProgressMessageHandler();
        private readonly IAuthenticationMechanism _authenticationMechanism;
        private readonly Func<bool> _isDisposed;
        private readonly Lazy<HttpClient> _lazyHttpClient;
        private HttpClient Client => _lazyHttpClient.Value;

        internal StreamingRequest(IAuthenticationMechanism authenticationMechanism, Func<bool> isDisposed)
        {
            _authenticationMechanism = authenticationMechanism;
            _isDisposed = isDisposed;
            _lazyHttpClient = new Lazy<HttpClient>(()=> CreateHttpClient(_progressMessageHandler));
        }

        public async Task<string> UploadAsync(Service service, string relativeUrl, Stream stream, IProgress<UploadProgress> progress = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, CancellationToken? cancellationToken = null)
        {
            if (_isDisposed())
                throw new ObjectDisposedException("SafeguardConnection");
            if (string.IsNullOrEmpty(relativeUrl))
                throw new ArgumentException("Parameter may not be null or empty", nameof(relativeUrl));

            var token = cancellationToken ?? CancellationToken.None;
            var uri = $"https://{_authenticationMechanism.NetworkAddress}/service/{service}/v{_authenticationMechanism.ApiVersion}/{relativeUrl}";
            if (parameters != null)
            {
                uri = QueryHelpers.AddQueryString(uri, parameters);
            }

            using (var request = new HttpRequestMessage(HttpMethod.Post, uri))
            {
                if (!_authenticationMechanism.IsAnonymous)
                {
                    if (!_authenticationMechanism.HasAccessToken())
                        throw new SafeguardDotNetException("Access token is missing due to log out, you must refresh the access token to invoke a method");
                    // SecureString handling here basically negates the use of a secure string anyway, but when calling a Web API
                    // I'm not sure there is anything you can do about it.
                    request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _authenticationMechanism.GetAccessToken().ToInsecureString());
                }

                if (additionalHeaders != null && !additionalHeaders.ContainsKey("Accept"))
                    request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

                if (additionalHeaders != null)
                {
                    foreach (var header in additionalHeaders)
                        request.Headers.Add(header.Key, header.Value);
                }

                SafeguardConnection.LogRequestDetails(Method.Post, new Uri(uri), parameters, additionalHeaders);

                EventHandler<HttpProgressEventArgs> progressHandlerFunc = null;

                using (var content = new StreamContent(stream, DefaultBufferSize))
                {
                    request.Content = content;
                    request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

                    if(progress != null)
                    {
                        progressHandlerFunc = (sender, args) =>
                        {
                            var uploadProgress = new UploadProgress
                            {
                                BytesTotal = args.TotalBytes.GetValueOrDefault(0),
                                BytesTransferred = args.BytesTransferred
                            };
                            progress.Report(uploadProgress);
                        };
                        _progressMessageHandler.HttpSendProgress += progressHandlerFunc;
                    }
                    try
                    {
                        var response = await Client.SendAsync(request, completionOption: HttpCompletionOption.ResponseHeadersRead, token);

                        var fullResponse = new FullResponse
                        {
                            Body = await response.Content.ReadAsStringAsync(),
                            Headers = response.Headers.ToDictionary(key => key.Key, value => value.Value.FirstOrDefault()),
                            StatusCode = response.StatusCode
                        };

                        if (!response.IsSuccessStatusCode)
                            throw new SafeguardDotNetException(
                                $"Error returned from Safeguard API, Error: {fullResponse.StatusCode} {fullResponse.Body}",
                                fullResponse.StatusCode, fullResponse.Body);

                        SafeguardConnection.LogResponseDetails(fullResponse);

                        return fullResponse.Body;
                    }
                    finally
                    {
                        if(progressHandlerFunc != null)
                        {
                            _progressMessageHandler.HttpSendProgress -= progressHandlerFunc;
                        }
                    }
                }
            }
        }

        private HttpClient CreateHttpClient(ProgressMessageHandler progressHandler)
        {
            var httpClientHandler = new HttpClientHandler();
            progressHandler.InnerHandler = httpClientHandler;
            if (_authenticationMechanism.IgnoreSsl)
            {
                httpClientHandler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
            }
            else if (_authenticationMechanism.ValidationCallback != null)
            {
                httpClientHandler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => _authenticationMechanism.ValidationCallback(message, cert, chain, errors);
            }
            
            return new HttpClient(progressHandler); // do not dispose
        }
    }
}
