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

        public JToken InvokeMethod(Service service, Method method, string relativeUrl, JToken body,
            IDictionary<string, string> parameters, IDictionary<string, string> additionalHeaders)
        {
            var content = InvokeMethod(service, method, relativeUrl, body.ToString(), parameters, additionalHeaders);
            try
            {
                return JToken.Parse(content);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        public string InvokeMethod(Service service, Method method, string relativeUrl, string body,
            IDictionary<string, string> parameters, IDictionary<string, string> additionalHeaders)
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
                throw new Exception($"Unable to connect to web service {client.BaseUrl}, Error: " +
                                    response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new Exception("Error calling Safeguard Web API, Error: " +
                                    $"{response.StatusCode} {response.Content}");
            return response.Content;
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
                    throw new Exception("You must call the A2A service using the A2A specific method, Error: Unsupported operation");
                default:
                    throw new Exception("Unknown or unsupported service specified");
            }
        }
    }
}
