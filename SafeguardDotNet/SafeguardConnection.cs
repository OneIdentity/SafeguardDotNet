using System;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;
using OneIdentity.SafeguardDotNet.Authentication;
using RestSharp;

namespace OneIdentity.SafeguardDotNet
{
    internal class SafeguardConnection : ISafeguardConnection
    {
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
            return _authenticationMechanism.GetAccessTokenLifetimeRemaining();
        }

        public void RefreshAccessToken()
        {
            _authenticationMechanism.RefreshAccessToken();
        }

        public string InvokeMethod(Service service, Method method, string relativeUrl, string body,
            IDictionary<string, string> parameters, IDictionary<string, string> additionalHeaders)
        {
            return InvokeMethodFull(service, method, relativeUrl, body, parameters, additionalHeaders).Body;
        }

        public JToken InvokeMethodParsed(Service service, Method method, string relativeUrl, JToken body,
            IDictionary<string, string> parameters, IDictionary<string, string> additionalHeaders)
        {
            var content = InvokeMethod(service, method, relativeUrl, body?.ToString(), parameters, additionalHeaders);
            try
            {
                return string.IsNullOrEmpty(content) ? null : JToken.Parse(content);
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException("Unable to parse Safeguard API response as JSON", ex);
            }
        }

        public FullResponse InvokeMethodFull(Service service, Method method, string relativeUrl,
            string body = null, IDictionary<string, string> parameters = null,
            IDictionary<string, string> additionalHeaders = null)
        {
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
            var response = client.Execute(request);
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
            return fullResponse;
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
    }
}
