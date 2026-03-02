// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet
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

    using OneIdentity.SafeguardDotNet.Authentication;

    internal class StreamingRequest : IStreamingRequest
    {
        private const int DefaultBufferSize = 81920;
        private readonly ProgressMessageHandler _progressMessageHandler = new ProgressMessageHandler();
        private readonly IAuthenticationMechanism _authenticationMechanism;
        private readonly Func<bool> _isDisposed;
        private readonly Lazy<HttpClient> _lazyHttpClient;

        private HttpClient Client => _lazyHttpClient.Value;

        internal StreamingRequest(IAuthenticationMechanism authenticationMechanism, Func<bool> isDisposed)
        {
            _authenticationMechanism = authenticationMechanism;
            _isDisposed = isDisposed;
            _lazyHttpClient = new Lazy<HttpClient>(() => CreateHttpClient(_progressMessageHandler));
        }

        public async Task<string> UploadAsync(Service service, string relativeUrl, Stream stream, IProgress<TransferProgress> progress = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, CancellationToken? cancellationToken = null)
        {
            PreconditionCheck(relativeUrl);

            var token = cancellationToken ?? CancellationToken.None;
            var uri = ConfigureUri(service, relativeUrl, parameters);

            using (var request = PrepareStreamingRequest(HttpMethod.Post, uri, null, additionalHeaders, parameters))
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

        public async Task DownloadAsync(Service service, string relativeUrl, string outputFilePath, string body = null, IProgress<TransferProgress> progress = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, CancellationToken? cancellationToken = null)
        {
            PreconditionCheck(relativeUrl);

            var token = cancellationToken ?? CancellationToken.None;
            var uri = ConfigureUri(service, relativeUrl, parameters);

            using (var request = PrepareStreamingRequest(HttpMethod.Get, uri, body, additionalHeaders, parameters))
            {
                EventHandler<HttpProgressEventArgs> progressHandlerFunc = null;
                if (progress != null)
                {
                    progressHandlerFunc = (sender, args) =>
                    {
                        var downloadProgress = new TransferProgress
                        {
                            BytesTotal = args.TotalBytes.GetValueOrDefault(0),
                            BytesTransferred = args.BytesTransferred,
                        };
                        progress.Report(downloadProgress);
                    };
                    _progressMessageHandler.HttpReceiveProgress += progressHandlerFunc;
                }

                try
                {
                    var response = await Client.SendAsync(request, completionOption: HttpCompletionOption.ResponseHeadersRead, token);
                    ValidateGetResponse(response);
                    using (var fs = new FileStream(outputFilePath, FileMode.Create, FileAccess.ReadWrite))
                    {
                        var downloadStream = await response.Content.ReadAsStreamAsync();
                        await downloadStream.CopyToAsync(fs, DefaultBufferSize);
                    }
                }
                finally
                {
                    if (progressHandlerFunc != null)
                    {
                        _progressMessageHandler.HttpReceiveProgress -= progressHandlerFunc;
                    }
                }
            }
        }

        public async Task<StreamResponse> DownloadStreamAsync(Service service, string relativeUrl, string body = null, IProgress<TransferProgress> progress = null, IDictionary<string, string> parameters = null, IDictionary<string, string> additionalHeaders = null, CancellationToken? cancellationToken = null)
        {
            PreconditionCheck(relativeUrl);

            var token = cancellationToken ?? CancellationToken.None;
            var uri = $"https://{_authenticationMechanism.NetworkAddress}/service/{service}/v{_authenticationMechanism.ApiVersion}/{relativeUrl}";
            uri = SafeguardConnection.AddQueryParameters(uri, parameters);

            using (var request = PrepareStreamingRequest(HttpMethod.Get, uri, body, additionalHeaders, parameters))
            {
                var progressHandlerFunc = ConfigureProgressHandler(progress);
                try
                {
                    var response = await Client.SendAsync(request, completionOption: HttpCompletionOption.ResponseHeadersRead, token);
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

        private string ConfigureUri(Service service, string relativeUrl, IDictionary<string, string> parameters)
        {
            var uri = $"https://{_authenticationMechanism.NetworkAddress}/service/{service}/v{_authenticationMechanism.ApiVersion}/{relativeUrl}";

            return SafeguardConnection.AddQueryParameters(uri, parameters);
        }

        // ReSharper disable once ParameterOnlyUsedForPreconditionCheck.Local
        private void PreconditionCheck(string relativeUrl)
        {
            if (_isDisposed())
            {
                throw new ObjectDisposedException("SafeguardConnection");
            }

            if (string.IsNullOrEmpty(relativeUrl))
            {
                throw new ArgumentException("Parameter may not be null or empty", nameof(relativeUrl));
            }
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

            if (!response.IsSuccessStatusCode)
            {
                throw new SafeguardDotNetException(
                    $"Error returned from Safeguard API, Error: {fullResponse.StatusCode} {fullResponse.Body}",
                    fullResponse.StatusCode,
                    fullResponse.Body);
            }

            fullResponse.LogResponseDetails();

            return fullResponse.Body;
        }

        private void CleanupProgress(EventHandler<HttpProgressEventArgs> progressHandlerFn)
        {
            if (progressHandlerFn != null)
            {
                _progressMessageHandler.HttpReceiveProgress -= progressHandlerFn;
            }
        }

        private HttpRequestMessage PrepareStreamingRequest(HttpMethod method, string uri, string body, IDictionary<string, string> additionalHeaders, IDictionary<string, string> parameters)
        {
            var request = new HttpRequestMessage(method, uri);
            if (!_authenticationMechanism.IsAnonymous)
            {
                if (!_authenticationMechanism.HasAccessToken())
                {
                    throw new SafeguardDotNetException("Access token is missing due to log out, you must refresh the access token to invoke a method");
                }

                // SecureString handling here basically negates the use of a secure string anyway, but when calling a Web API
                // I'm not sure there is anything you can do about it.
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _authenticationMechanism.GetAccessToken().ToInsecureString());
            }

            if (additionalHeaders != null)
            {
                foreach (var header in additionalHeaders)
                {
                    request.Headers.Add(header.Key, header.Value);
                }
            }

            var acceptHeaderValue = GetMediaTypeForMethod(method);
            if (!request.Headers.Accept.Contains(acceptHeaderValue))
            {
                request.Headers.Accept.Add(acceptHeaderValue);
            }

            request.LogRequestDetails(parameters, additionalHeaders);

            if (method == HttpMethod.Get && !string.IsNullOrEmpty(body))
            {
                request.Content = new StringContent(body);
                request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            }

            return request;
        }

        private static MediaTypeWithQualityHeaderValue GetMediaTypeForMethod(HttpMethod method)
        {
            MediaTypeWithQualityHeaderValue acceptHeaderValue;
            if (method == HttpMethod.Get)
            {
                acceptHeaderValue = new MediaTypeWithQualityHeaderValue("application/octet-stream");
            }
            else if (method == HttpMethod.Post)
            {
                acceptHeaderValue = new MediaTypeWithQualityHeaderValue("application/json");
            }
            else
            {
                throw new SafeguardDotNetException($"Streaming not supported for method: {method}");
            }

            return acceptHeaderValue;
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

        private HttpClient CreateHttpClient(ProgressMessageHandler progressHandler)
        {
            var httpClientHandler = new HttpClientHandler();
            progressHandler.InnerHandler = httpClientHandler;
            if (_authenticationMechanism.IgnoreSsl)
            {
#pragma warning disable S4830 // Server certificate validation is intentionally bypassed when IgnoreSsl is set
                httpClientHandler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
#pragma warning restore S4830
            }
            else if (_authenticationMechanism.ValidationCallback != null)
            {
                httpClientHandler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => _authenticationMechanism.ValidationCallback(message, cert, chain, errors);
            }

            var client = new HttpClient(progressHandler)
            {
                // do not time out on streaming requests, let the cancellation token handle timeouts
                Timeout = Timeout.InfiniteTimeSpan,
            };
            return client;
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
