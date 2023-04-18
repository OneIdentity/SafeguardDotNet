using System;
using System.Collections.Generic;
using System.Linq;
using OneIdentity.SafeguardDotNet.Authentication;
using OneIdentity.SafeguardDotNet.Event;
using RestSharp;
using Serilog;
using Newtonsoft.Json;
using OneIdentity.SafeguardDotNet.Sps;
using Microsoft.Extensions.Options;
using System.Security.Cryptography.X509Certificates;

namespace OneIdentity.SafeguardDotNet
{
    internal class SafeguardConnection : ISafeguardConnection, ICloneable
    {
        private bool _disposed;

        protected readonly IAuthenticationMechanism _authenticationMechanism;

        private readonly RestClient _coreClient;
        private readonly RestClient _applianceClient;
        private readonly RestClient _notificationClient;
        

        public SafeguardConnection(IAuthenticationMechanism authenticationMechanism)
        {
            _authenticationMechanism = authenticationMechanism;

            var safeguardCoreUrl = $"https://{_authenticationMechanism.NetworkAddress}/service/core/v{_authenticationMechanism.ApiVersion}";
            _coreClient = CreateRestClient(safeguardCoreUrl);

            var safeguardApplianceUrl = $"https://{_authenticationMechanism.NetworkAddress}/service/appliance/v{_authenticationMechanism.ApiVersion}";
            _applianceClient = CreateRestClient(safeguardApplianceUrl);

            var safeguardNotificationUrl = $"https://{_authenticationMechanism.NetworkAddress}/service/notification/v{_authenticationMechanism.ApiVersion}";
            _notificationClient = CreateRestClient(safeguardNotificationUrl);

            _lazyStreamingRequest = new Lazy<IStreamingRequest>(() =>
            {
                return new StreamingRequest(_authenticationMechanism, () => _disposed);
            });
        }


        private readonly Lazy<IStreamingRequest> _lazyStreamingRequest;
        public IStreamingRequest Streaming => _lazyStreamingRequest.Value;

        public int GetAccessTokenLifetimeRemaining()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardConnection");
            var lifetime = _authenticationMechanism.GetAccessTokenLifetimeRemaining();
            if (lifetime > 0)
                Log.Debug("Access token lifetime remaining (in minutes): {AccessTokenLifetime}", lifetime);
            else
                Log.Debug("Access token invalid or server unavailable");
            return lifetime;
        }

        public void RefreshAccessToken()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardConnection");
            _authenticationMechanism.RefreshAccessToken();
            Log.Debug("Successfully obtained a new access token");
        }

        public string InvokeMethod(Service service, Method method, string relativeUrl, string body,
            IDictionary<string, string> parameters, IDictionary<string, string> additionalHeaders,
            TimeSpan? timeout = null)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardConnection");
            return InvokeMethodFull(service, method, relativeUrl, body, parameters, additionalHeaders, timeout).Body;
        }

        public FullResponse InvokeMethodFull(Service service, Method method, string relativeUrl,
            string body = null, IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null, TimeSpan? timeout = null)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardConnection");
            if (string.IsNullOrEmpty(relativeUrl))
                throw new ArgumentException("Parameter may not be null or empty", nameof(relativeUrl));

            var request = new RestRequest(relativeUrl, method.ConvertToRestSharpMethod());
            if (!_authenticationMechanism.IsAnonymous)
            {
                if (!_authenticationMechanism.HasAccessToken())
                    throw new SafeguardDotNetException("Access token is missing due to log out, you must refresh the access token to invoke a method");
                // SecureString handling here basically negates the use of a secure string anyway, but when calling a Web API
                // I'm not sure there is anything you can do about it.
                request.AddHeader("Authorization",
                    $"Bearer {_authenticationMechanism.GetAccessToken().ToInsecureString()}");
            }
            if (additionalHeaders != null && !additionalHeaders.ContainsKey("Accept"))
                request.AddHeader("Accept", "application/json"); // Assume JSON unless specified
            if (additionalHeaders != null)
            {
                foreach (var header in additionalHeaders)
                    request.AddHeader(header.Key, header.Value);
            }
            if ((method == Method.Post || method == Method.Put) && body != null)
                request.AddParameter("application/json", body, ParameterType.RequestBody);
            else if (method == Method.Post || method == Method.Put) // have to set the Content-type header even if empty body or Safeguard chokes
                request.AddHeader("Content-type", "application/json");
            if (parameters != null)
            {
                foreach (var param in parameters)
                    request.AddParameter(param.Key, param.Value, ParameterType.QueryString);
            }
            if (timeout.HasValue)
            {
                request.Timeout = (timeout.Value.TotalMilliseconds > int.MaxValue)
                    ? int.MaxValue : (int)timeout.Value.TotalMilliseconds;
            }

            var client = GetClientForService(service);
            client.LogRequestDetails(request, parameters, additionalHeaders);

            var response = client.Execute(request);
            Log.Debug("  Body size: {RequestBodySize}", body == null ? "None" : $"{body.Length}");
            if (response.ResponseStatus != ResponseStatus.Completed && response.ResponseStatus != ResponseStatus.Error)
                throw new SafeguardDotNetException($"Unable to connect to web service {client.Options.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException(
                    "Error returned from Safeguard API, Error: " + $"{response.StatusCode} {response.Content}",
                    response.StatusCode, response.Content);
            var fullResponse = new FullResponse
            {
                StatusCode = response.StatusCode,
                Headers = new Dictionary<string, string>(),
                Body = response.Content
            };
            foreach (var header in response.Headers)
            {
                if (header.Name != null)
                {
                    if (fullResponse.Headers.ContainsKey(header.Name))
                    {
                        if (!string.IsNullOrEmpty(header?.Value.ToString()))
                        {
                            fullResponse.Headers[header.Name] = string.Join(", ", fullResponse.Headers[header.Name], header.Value.ToString());
                        }
                    }
                    else
                    {
                        fullResponse.Headers.Add(header.Name, header.Value?.ToString());
                    }
                }
            }
            
            fullResponse.LogResponseDetails();

            return fullResponse;
        }

        public string InvokeMethodCsv(Service service, Method method, string relativeUrl,
            string body = null, IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null, TimeSpan? timeout = null)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardConnection");
            if (additionalHeaders == null)
                additionalHeaders = new Dictionary<string, string>();
            additionalHeaders.Add("Accept", "text/csv");
            return InvokeMethodFull(service, method, relativeUrl, body, parameters, additionalHeaders, timeout).Body;
        }

        public virtual FullResponse JoinSps(ISafeguardSessionsConnection spsConnection, string certificateChain, string sppAddress)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardConnection");

            var request = new JoinRequest
            {
                spp = sppAddress,
                spp_api_token = _authenticationMechanism.GetAccessToken().ToInsecureString(),
                spp_cert_chain = certificateChain
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
                throw new ObjectDisposedException("SafeguardConnection");
            var eventListener = new SafeguardEventListener(
                $"https://{_authenticationMechanism.NetworkAddress}/service/event/signalr",
                _authenticationMechanism.GetAccessToken(), _authenticationMechanism.IgnoreSsl, _authenticationMechanism.ValidationCallback);
            Log.Debug("Event listener successfully created for Safeguard connection.");
            return eventListener;
        }

        public virtual ISafeguardEventListener GetPersistentEventListener()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardConnection");

            if (_authenticationMechanism.GetType() == typeof(PasswordAuthenticator) ||
                _authenticationMechanism.GetType() == typeof(CertificateAuthenticator))
            {
                return new PersistentSafeguardEventListener(Clone() as ISafeguardConnection);
            }
            throw new SafeguardDotNetException(
                $"Unable to create persistent event listener from {_authenticationMechanism.GetType()}");
        }

        public ISafeguardConnection GetManagementServiceConnection(string networkAddress)
        {
            return new SafeguardManagementServiceConnection(_authenticationMechanism, networkAddress);
        }

        public void LogOut()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardConnection");
            if (!_authenticationMechanism.HasAccessToken())
                return;
            try
            {
                InvokeMethodFull(Service.Core, Method.Post, "Token/Logout");
                Log.Debug("Successfully logged out");
            }
            catch (Exception ex)
            {
                Log.Debug(ex, "Exception occurred during logout");
            }
            _authenticationMechanism.ClearAccessToken();
            Log.Debug("Cleared access token");
        }

        protected virtual RestClient GetClientForService(Service service)
        {
            switch (service)
            {
                case Service.Core:
                    return _coreClient;
                case Service.Appliance:
                    return _applianceClient;
                case Service.Notification:
                    return _notificationClient;
                case Service.A2A:
                    throw new SafeguardDotNetException(
                        "You must call the A2A service using the A2A specific method, Error: Unsupported operation");
                default:
                    throw new SafeguardDotNetException("Unknown or unsupported service specified");
            }
        }
        protected RestClient CreateRestClient(string baseUrl)
        {
            return new RestClient(baseUrl,
                options =>
                {
                    options.RemoteCertificateValidationCallback = _authenticationMechanism.IgnoreSsl
                    ? (sender, certificate, chain, errors) => true
                    : (_authenticationMechanism.ValidationCallback ?? options.RemoteCertificateValidationCallback);
                });
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
                return;
            try
            {
                _authenticationMechanism?.Dispose();
                if (_lazyStreamingRequest.IsValueCreated)
                    Streaming.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }

        public object Clone()
        {
            return new SafeguardConnection(_authenticationMechanism.Clone() as IAuthenticationMechanism);
        }
    }
}
