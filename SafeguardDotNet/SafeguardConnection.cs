// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet
{
    using System;
    using System.Collections.Generic;
    using System.Net.Http;
    using System.Security;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    using Newtonsoft.Json;

    using OneIdentity.SafeguardDotNet.Authentication;
    using OneIdentity.SafeguardDotNet.Event;
    using OneIdentity.SafeguardDotNet.Sps;

    using Serilog;

    internal class SafeguardConnection : ISafeguardConnection, ICloneable
    {
        private bool _disposed;

        protected readonly IAuthenticationMechanism authenticationMechanism;

        private readonly Uri _coreUrl;
        private readonly Uri _applianceUrl;
        private readonly Uri _notificationUrl;
        private readonly HttpClient _http;

        private HttpClient CreateHttpClient()
        {
            var handler = new HttpClientHandler
            {
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12,
            };

            if (authenticationMechanism.IgnoreSsl)
            {
#pragma warning disable S4830 // Server certificate validation is intentionally bypassed when IgnoreSsl is set
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
#pragma warning restore S4830
            }
            else if (authenticationMechanism.ValidationCallback != null)
            {
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => authenticationMechanism.ValidationCallback(message, cert, chain, errors);
            }

            return new HttpClient(handler);
        }

        public SecureString GetAccessToken() => authenticationMechanism.GetAccessToken();

        public SafeguardConnection(IAuthenticationMechanism authenticationMechanism)
        {
            this.authenticationMechanism = authenticationMechanism;

            _coreUrl = new Uri($"https://{authenticationMechanism.NetworkAddress}/service/core/v{authenticationMechanism.ApiVersion}/", UriKind.Absolute);
            _applianceUrl = new Uri($"https://{authenticationMechanism.NetworkAddress}/service/appliance/v{authenticationMechanism.ApiVersion}/", UriKind.Absolute);
            _notificationUrl = new Uri($"https://{authenticationMechanism.NetworkAddress}/service/notification/v{authenticationMechanism.ApiVersion}/", UriKind.Absolute);

            _http = CreateHttpClient();

            _lazyStreamingRequest = new Lazy<IStreamingRequest>(() =>
            {
                return new StreamingRequest(authenticationMechanism, () => _disposed);
            });
        }

        private readonly Lazy<IStreamingRequest> _lazyStreamingRequest;

        public IStreamingRequest Streaming => _lazyStreamingRequest.Value;

        public int GetAccessTokenLifetimeRemaining()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardConnection");
            }

            var lifetime = authenticationMechanism.GetAccessTokenLifetimeRemaining();
            if (lifetime > 0)
            {
                Log.Debug("Access token lifetime remaining (in minutes): {AccessTokenLifetime}", lifetime);
            }
            else
            {
                Log.Debug("Access token invalid or server unavailable");
            }

            return lifetime;
        }

        public void RefreshAccessToken()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardConnection");
            }

            authenticationMechanism.RefreshAccessToken();
            Log.Debug("Successfully obtained a new access token");
        }

        public string InvokeMethod(
            Service service,
            Method method,
            string relativeUrl,
            string body = null,
            IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null,
            TimeSpan? timeout = null)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardConnection");
            }

            return InvokeMethodFull(service, method, relativeUrl, body, parameters, additionalHeaders, timeout).Body;
        }

        /// <summary>Make a call to the Safeguard API.</summary>
        /// <param name="service">Which of the Safeguard API service end points to call.</param>
        /// <param name="method">The HTTP method used to make the API request.</param>
        /// <param name="relativeUrl">The relative portion of the URL to the API. Do not include a leading forward slash.</param>
        /// <param name="body">The body data of the request, if required.</param>
        /// <param name="parameters">Additional query string parameters to be added to the URL.</param>
        /// <param name="additionalHeaders">Additional HTTP headers to be added to the request.</param>
        /// <param name="timeout">Override the default request timeout of 100 seconds.</param>
        /// <returns>The HTTP response data.</returns>
        public FullResponse InvokeMethodFull(
            Service service,
            Method method,
            string relativeUrl,
            string body = null,
            IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null,
            TimeSpan? timeout = null)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardConnection");
            }

            if (string.IsNullOrEmpty(relativeUrl))
            {
                throw new ArgumentException("Parameter may not be null or empty", nameof(relativeUrl));
            }

            // There is one use case where an application incorrectly passed in a relativeUrl value with a leading forward
            // slash. The Uri class treats that as absolute, completely removing any existing path segments on the base URL.
            // RestSharp sanitized this, so we'll have to do the same.
            if (relativeUrl[0] == '/')
            {
                relativeUrl = relativeUrl.Substring(1);
            }

            relativeUrl = AddQueryParameters(relativeUrl, parameters);

            var req = new HttpRequestMessage
            {
                Method = method.ConvertToHttpMethod(),
                RequestUri = new Uri(GetClientForService(service), relativeUrl),
            };

            if (!authenticationMechanism.IsAnonymous)
            {
                if (!authenticationMechanism.HasAccessToken())
                {
                    throw new SafeguardDotNetException("Access token is missing due to log out, you must refresh the access token to invoke a method");
                }

                // SecureString handling here basically negates the use of a secure string anyway, but when calling a Web API
                // I'm not sure there is anything you can do about it.
                req.Headers.Add("Authorization",
                    $"Bearer {authenticationMechanism.GetAccessToken().ToInsecureString()}");
            }

            if (additionalHeaders != null && !additionalHeaders.ContainsKey("Accept"))
            {
                req.Headers.Add("Accept", "application/json"); // Assume JSON unless specified
            }

            if (additionalHeaders != null)
            {
                foreach (var header in additionalHeaders)
                {
                    req.Headers.Add(header.Key, header.Value);
                }
            }

            if (method == Method.Post || method == Method.Put)
            {
                req.Content = new StringContent(body ?? string.Empty, Encoding.UTF8, "application/json");
            }

            var cts = new CancellationTokenSource(timeout ?? TimeSpan.FromSeconds(100)); // 100 seconds is the default timeout.

            req.LogRequestDetails(parameters, additionalHeaders);
            Log.Debug("  Body size: {RequestBodySize}", body == null ? "None" : $"{body.Length}");

            try
            {
                var res = _http.SendAsync(req, cts.Token).GetAwaiter().GetResult();
                var msg = res.Content?.ReadAsStringAsync().GetAwaiter().GetResult();

                if (!res.IsSuccessStatusCode)
                {
                    throw new SafeguardDotNetException($"Error returned from Safeguard API, Error: {res.StatusCode} {msg}", res.StatusCode, msg);
                }

                var fullResponse = new FullResponse
                {
                    StatusCode = res.StatusCode,
                    Headers = new Dictionary<string, string>(),
                    Body = msg,
                };

                foreach (var header in res.Headers)
                {
                    if (fullResponse.Headers.ContainsKey(header.Key))
                    {
                        if (!string.IsNullOrEmpty(header.Value.ToString()))
                        {
                            fullResponse.Headers[header.Key] = string.Join(", ", fullResponse.Headers[header.Key], string.Join(", ", header.Value));
                        }
                    }
                    else
                    {
                        fullResponse.Headers.Add(header.Key, string.Join(", ", header.Value));
                    }
                }

                fullResponse.LogResponseDetails();

                return fullResponse;
            }
            catch (HttpRequestException ex)
            {
                throw new SafeguardDotNetException($"Exception while calling {GetClientForService(service)}, Error: {ex.Message}", ex);
            }
            catch (TaskCanceledException)
            {
                throw new SafeguardDotNetException($"Request timeout to {req.RequestUri}.");
            }
            finally
            {
                req.Dispose();
                cts.Dispose();
            }
        }

        public string InvokeMethodCsv(
            Service service,
            Method method,
            string relativeUrl,
            string body = null,
            IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null,
            TimeSpan? timeout = null)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardConnection");
            }

            if (additionalHeaders == null)
            {
                additionalHeaders = new Dictionary<string, string>();
            }

            additionalHeaders.Add("Accept", "text/csv");
            return InvokeMethodFull(service, method, relativeUrl, body, parameters, additionalHeaders, timeout).Body;
        }

        public virtual FullResponse JoinSps(ISafeguardSessionsConnection spsConnection, string certificateChain, string sppAddress)
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardConnection");
            }

            var request = new JoinRequest
            {
                spp = sppAddress,
                spp_api_token = authenticationMechanism.GetAccessToken().ToInsecureString(),
                spp_cert_chain = certificateChain,
            };
            var joinBody = JsonConvert.SerializeObject(request);

            Log.Debug("Sending join request.");
            var joinResponse = spsConnection.InvokeMethodFull(Method.Post, "cluster/spp", joinBody);

            joinResponse.LogResponseDetails();

            return joinResponse;
        }

        public virtual ISafeguardEventListener GetEventListener()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardConnection");
            }

            var eventListener = new SafeguardEventListener(
                $"https://{authenticationMechanism.NetworkAddress}/service/event/signalr",
                authenticationMechanism.GetAccessToken(),
                authenticationMechanism.IgnoreSsl,
                authenticationMechanism.ValidationCallback);
            Log.Debug("Event listener successfully created for Safeguard connection.");
            return eventListener;
        }

        public virtual ISafeguardEventListener GetPersistentEventListener()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardConnection");
            }

            if (authenticationMechanism.GetType() == typeof(PasswordAuthenticator) ||
                authenticationMechanism.GetType() == typeof(CertificateAuthenticator))
            {
                return new PersistentSafeguardEventListener(Clone() as ISafeguardConnection);
            }

            throw new SafeguardDotNetException(
                $"Unable to create persistent event listener from {authenticationMechanism.GetType()}");
        }

        public ISafeguardConnection GetManagementServiceConnection(string networkAddress)
        {
            return new SafeguardManagementServiceConnection(authenticationMechanism, networkAddress);
        }

        public void LogOut()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException("SafeguardConnection");
            }

            if (!authenticationMechanism.HasAccessToken())
            {
                return;
            }

            try
            {
                InvokeMethodFull(Service.Core, Method.Post, "Token/Logout");
                Log.Debug("Successfully logged out");
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Exception occurred during logout");
            }

            authenticationMechanism.ClearAccessToken();
            Log.Debug("Cleared access token");
        }

        protected virtual Uri GetClientForService(Service service)
        {
            switch (service)
            {
                case Service.Core:
                    return _coreUrl;
                case Service.Appliance:
                    return _applianceUrl;
                case Service.Notification:
                    return _notificationUrl;
                case Service.A2A:
                    throw new SafeguardDotNetException(
                        "You must call the A2A service using the A2A specific method, Error: Unsupported operation");
                default:
                    throw new SafeguardDotNetException("Unknown or unsupported service specified");
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
                authenticationMechanism?.Dispose();
                _http?.Dispose();
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

        public object Clone()
        {
            return new SafeguardConnection(authenticationMechanism.Clone() as IAuthenticationMechanism);
        }

        public static string AddQueryParameters(string url, IDictionary<string, string> parameters)
        {
            if (parameters == null || parameters.Count == 0)
            {
                return url;
            }

            var sb = new StringBuilder(url ?? string.Empty);

            // Try to be compensating with an existing Url, if it were to be passed in with an existing query string.
            if (!url.Contains("?"))
            {
                sb.Append("?");
            }
            else if (!url.EndsWith("&"))
            {
                sb.Append("&");
            }

            foreach (var item in parameters)
            {
                sb.Append($"{Uri.EscapeDataString(item.Key)}={Uri.EscapeDataString(item.Value)}&");
            }

            sb.Length -= 1; // Remove the last '&' character.

            return sb.ToString();
        }
    }
}
