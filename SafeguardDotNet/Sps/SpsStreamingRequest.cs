// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Sps
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Handlers;
    using System.Net.Http.Headers;
    using System.Threading;
    using System.Threading.Tasks;

    internal class SpsStreamingRequest : ISpsStreamingRequest
    {
        private const int DefaultBufferSize = 81920;
        private readonly ProgressMessageHandler _progressMessageHandler = new ProgressMessageHandler();

        private readonly Func<bool> _isDisposed;
        private readonly ISpsAuthenticator _authenticator;
        private readonly Lazy<HttpClient> _lazyHttpClient;

        private HttpClient Client => _lazyHttpClient.Value;

        internal SpsStreamingRequest(ISpsAuthenticator authenticator, Func<bool> isDisposed)
        {
            _isDisposed = isDisposed;
            _authenticator = authenticator;
            _lazyHttpClient = new Lazy<HttpClient>(() => CreateHttpClient(_progressMessageHandler));
        }

        public async Task<string> UploadAsync(string relativeUrl, Stream stream, IProgress<TransferProgress> progress = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, CancellationToken? cancellationToken = null)
        {
            var token = cancellationToken ?? CancellationToken.None;

            // Ideally we'd authenticate when creating the http client, but this way we don't have to worry about token lifetime issues.
            await Authenticate(token);

            using (var request = PrepareStreamingRequest(HttpMethod.Post, relativeUrl, parameters, additionalHeaders))
            {
                EventHandler<HttpProgressEventArgs> progressHandlerFunc = null;

                using (var content = new StreamContent(stream, DefaultBufferSize))
                {
                    request.Content = content;
                    request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/octet-stream");

                    if (progress != null)
                    {
                        progressHandlerFunc = (sender, args) =>
                        {
                            var uploadProgress = new TransferProgress
                            {
                                BytesTotal = args.TotalBytes.GetValueOrDefault(0),
                                BytesTransferred = args.BytesTransferred,
                            };
                            progress.Report(uploadProgress);
                        };

                        _progressMessageHandler.HttpSendProgress += progressHandlerFunc;
                    }

                    try
                    {
                        var response = await Client.SendAsync(request, completionOption: HttpCompletionOption.ResponseHeadersRead, token);
                        return await ValidatePostResponse(response);
                    }
                    finally
                    {
                        if (progressHandlerFunc != null)
                        {
                            _progressMessageHandler.HttpSendProgress -= progressHandlerFunc;
                        }
                    }
                }
            }
        }

        public async Task<StreamResponse> DownloadStreamAsync(string relativeUrl, IProgress<TransferProgress> progress = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, CancellationToken? cancellationToken = null)
        {
            PreconditionCheck(relativeUrl);

            var token = cancellationToken ?? CancellationToken.None;

            // Ideally we'd authenticate when creating the http client, but this way we don't have to worry about token lifetime issues.
            await Authenticate(token);

            using (var request = PrepareStreamingRequest(HttpMethod.Get, relativeUrl, parameters, additionalHeaders))
            {
                var progressHandlerFunc = ConfigureProgressHandler(progress);
                try
                {
                    var response = await Client.SendAsync(request, completionOption: HttpCompletionOption.ResponseContentRead, cancellationToken: token);
                    ValidateGetResponse(response);
                    return new StreamResponse(response, () => CleanupProgress(progressHandlerFunc));
                }
                catch (Exception)
                {
                    CleanupProgress(progressHandlerFunc);
                    throw;
                }
            }
        }

        private void PreconditionCheck(string relativeUrl)
        {
            if (_isDisposed())
            {
                throw new ObjectDisposedException("SpsConnection");
            }

            if (string.IsNullOrEmpty(relativeUrl))
            {
                throw new ArgumentException("Parameter may not be null or empty", nameof(relativeUrl));
            }
        }

        private EventHandler<HttpProgressEventArgs> ConfigureProgressHandler(IProgress<TransferProgress> progress)
        {
            if (progress != null)
            {
                void progressHandlerFunc(object sender, HttpProgressEventArgs args)
                {
                    var downloadProgress = new TransferProgress
                    {
                        BytesTotal = args.TotalBytes.GetValueOrDefault(0),
                        BytesTransferred = args.BytesTransferred,
                    };
                    progress.Report(downloadProgress);
                }

                _progressMessageHandler.HttpReceiveProgress += progressHandlerFunc;
                return progressHandlerFunc;
            }

            return null;
        }

        private void CleanupProgress(EventHandler<HttpProgressEventArgs> progressHandlerFn)
        {
            if (progressHandlerFn != null)
            {
                _progressMessageHandler.HttpReceiveProgress -= progressHandlerFn;
            }
        }

        private HttpClient CreateHttpClient(ProgressMessageHandler progressHandler)
        {
            var httpClientHandler = new HttpClientHandler();
            if (_authenticator.IgnoreSsl)
            {
#pragma warning disable S4830 // Server certificate validation is intentionally bypassed when IgnoreSsl is set
                httpClientHandler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
#pragma warning restore S4830
            }

            progressHandler.InnerHandler = httpClientHandler;

            // do not time out on streaming requests, let the cancellation token handle timeouts
            return new HttpClient(progressHandler) { Timeout = Timeout.InfiniteTimeSpan };
        }

        private async Task Authenticate(CancellationToken token)
        {
            var responseMessage = await Client.SendAsync(PrepareGenericRequest(HttpMethod.Get, "authentication"), token);

            if (!responseMessage.IsSuccessStatusCode)
            {
                var responseContent = await responseMessage.Content.ReadAsStringAsync();

                throw new SafeguardDotNetException("Error returned when authenticating to sps api.", responseMessage.StatusCode, responseContent);
            }
        }

        private HttpRequestMessage PrepareStreamingRequest(HttpMethod method, string relativeUrl, IDictionary<string, string> parameters, IDictionary<string, string> additionalHeaders)
        {
            var request = new HttpRequestMessage(method, ConfigureUri(relativeUrl, parameters));

            request.Headers.Authorization = _authenticator.GetAuthenticationHeader();

            if (additionalHeaders != null)
            {
                foreach (var header in additionalHeaders)
                {
                    request.Headers.Add(header.Key, header.Value);
                }
            }

            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/octet-stream"));

            request.LogRequestDetails(parameters, additionalHeaders);

            return request;
        }

        private HttpRequestMessage PrepareGenericRequest(HttpMethod method, string relativeUrl)
        {
            var request = new HttpRequestMessage(method, ConfigureUri(relativeUrl));
            request.Headers.Authorization = _authenticator.GetAuthenticationHeader();
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            return request;
        }

        private string ConfigureUri(string relativeUrl, IDictionary<string, string> parameters = null)
        {
            return SafeguardConnection.AddQueryParameters($"https://{_authenticator.NetworkAddress}/api/{relativeUrl}", parameters);
        }

        private void ValidateGetResponse(HttpResponseMessage response)
        {
            var fullResponse = new FullResponse
            {
                Headers = response.Headers.ToDictionary(key => key.Key, value => value.Value.FirstOrDefault()),
                StatusCode = response.StatusCode,
            };

            // Check for 200 OK here because 204 Accepted doesn't return a stream,
            // better to fail in that case.
            if (response.StatusCode != System.Net.HttpStatusCode.OK)
            {
                fullResponse.Body = response.Content.ReadAsStringAsync().Result;
                throw new SafeguardDotNetException(
                    $"Response does not indicate OK status. Error: {fullResponse.StatusCode} {fullResponse.Body}",
                    fullResponse.StatusCode,
                    fullResponse.Body);
            }

            fullResponse.LogResponseDetails();
        }

        private async Task<string> ValidatePostResponse(HttpResponseMessage response)
        {
            var fullResponse = new FullResponse
            {
                Body = await response.Content.ReadAsStringAsync(),
                Headers = response.Headers.ToDictionary(key => key.Key, value => value.Value.FirstOrDefault()),
                StatusCode = response.StatusCode,
            };

            fullResponse.LogResponseDetails();

            if (!response.IsSuccessStatusCode)
            {
                throw new SafeguardDotNetException($"Error returned from sps api.", fullResponse.StatusCode, fullResponse.Body);
            }

            return fullResponse.Body;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_isDisposed() || !disposing)
            {
                return;
            }

            Client.Dispose();
        }
    }
}
