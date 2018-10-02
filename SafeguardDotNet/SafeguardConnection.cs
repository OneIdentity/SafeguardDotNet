using System;
using System.Collections.Generic;
using System.Linq;
using OneIdentity.SafeguardDotNet.Authentication;
using OneIdentity.SafeguardDotNet.Event;
using RestSharp;
using Serilog;

namespace OneIdentity.SafeguardDotNet
{
    internal class SafeguardConnection : ISafeguardConnection
    {
        private bool _disposed;

        private readonly IAuthenticationMechanism _authenticationMechanism;

        private readonly RestClient _coreClient;
        private readonly RestClient _applianceClient;
        private readonly RestClient _notificationClient;

        public SafeguardConnection(IAuthenticationMechanism authenticationMechanism)
        {
            _authenticationMechanism = authenticationMechanism;

            var safeguardCoreUrl = $"https://{_authenticationMechanism.NetworkAddress}/service/core/v{_authenticationMechanism.ApiVersion}";
            _coreClient = new RestClient(safeguardCoreUrl);

            var safeguardApplianceUrl = $"https://{_authenticationMechanism.NetworkAddress}/service/appliance/v{_authenticationMechanism.ApiVersion}";
            _applianceClient = new RestClient(safeguardApplianceUrl);

            var safeguardNotificationUrl = $"https://{_authenticationMechanism.NetworkAddress}/service/notification/v{_authenticationMechanism.ApiVersion}";
            _notificationClient = new RestClient(safeguardNotificationUrl);

            if (authenticationMechanism.IgnoreSsl)
            {
                _coreClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
                _applianceClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
                _notificationClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
            }
        }

        public int GetAccessTokenLifetimeRemaining()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardConnection");
            var lifetime = _authenticationMechanism.GetAccessTokenLifetimeRemaining();
            Log.Information("Access token lifetime remaining (in minutes): {AccessTokenLifetime}", lifetime);
            return lifetime;
        }

        public void RefreshAccessToken()
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardConnection");
            _authenticationMechanism.RefreshAccessToken();
            Log.Information("Successfully obtained a new access token");
        }

        public string InvokeMethod(Service service, Method method, string relativeUrl, string body,
            IDictionary<string, string> parameters, IDictionary<string, string> additionalHeaders)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardConnection");
            return InvokeMethodFull(service, method, relativeUrl, body, parameters, additionalHeaders).Body;
        }

        public FullResponse InvokeMethodFull(Service service, Method method, string relativeUrl,
            string body = null, IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null)
        {
            if (_disposed)
                throw new ObjectDisposedException("SafeguardConnection");
            var request = new RestRequest(relativeUrl, method.ConvertToRestSharpMethod())
                .AddHeader("Accept", "application/json");
            if (service != Service.Notification)
                // SecureString handling here basically negates the use of a secure string anyway, but when calling a Web API
                // I'm not sure there is anything you can do about it.
                request.AddHeader("Authorization",
                    $"Bearer {_authenticationMechanism.GetAccessToken().ToInsecureString()}");
            if (additionalHeaders != null)
            {
                foreach (var header in additionalHeaders)
                    request.AddHeader(header.Key, header.Value);
            }
            if (method == Method.Post || method == Method.Put)
                request.AddParameter("application/json", body, ParameterType.RequestBody);
            if (parameters != null)
            {
                foreach (var param in parameters)
                    request.AddParameter(param.Key, param.Value, ParameterType.QueryString);
            }

            var client = GetClientForService(service);
            Log.Information("Invoking method: {Method} {Endpoint}", method.ToString().ToUpper(),
                client.BaseUrl + $"/{relativeUrl}");
            Log.Debug("  Query parameters: {QueryParameters}",
                parameters?.Select(kv => $"{kv.Key}={kv.Value}").Aggregate("", (str, param) => $"{str}{param}&")
                    .TrimEnd('&') ?? "None");
            Log.Debug("  Additional headers: {AdditionalHeaders}",
                additionalHeaders?.Select(kv => $"{kv.Key}: {kv.Value}")
                    .Aggregate("", (str, header) => $"{str}{header}, ").TrimEnd(',', ' ') ?? "None");
            var response = client.Execute(request);
            Log.Debug("  Body size: {RequestBodySize}", body == null ? "None" : $"{body.Length}");
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to web service {client.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException("Error returned from Safeguard API, Error: " +
                                                   $"{response.StatusCode} {response.Content}", response.Content);
            var fullResponse = new FullResponse
            {
                StatusCode = response.StatusCode,
                Headers = new Dictionary<string, string>(),
                Body = response.Content
            };
            if (response.Headers != null)
            {
                foreach (var header in response.Headers)
                    fullResponse.Headers.Add(header.Name, header.Value?.ToString());
            }
            Log.Information("Reponse status code: {StatusCode}", fullResponse.StatusCode);
            Log.Debug("  Response headers: {ResponseHeaders}",
                fullResponse.Headers?.Select(kv => $"{kv.Key}: {kv.Value}")
                    .Aggregate("", (str, header) => $"{str}{header}, ").TrimEnd(',', ' ') ?? "None");
            Log.Debug("  Body size: {ResponseBodySize}",
                fullResponse.Body == null ? "None" : $"{fullResponse.Body.Length}");
            return fullResponse;
        }

        public ISafeguardEventListener GetEventListener()
        {
            var eventListener = new SafeguardEventListener(
                $"https://{_authenticationMechanism.NetworkAddress}/service/event",
                _authenticationMechanism.GetAccessToken(), _authenticationMechanism.IgnoreSsl);
            Log.Information("Event listener successfully created for Safeguard connection.");
            return eventListener;
        }

        private RestClient GetClientForService(Service service)
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
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
