using System;
using System.Linq;
using System.Security;
using OneIdentity.SafeguardDotNet;
using RestSharp;
using RestSharp.Authenticators;
using Serilog;
using ServiceNowTicketValidator.DTOs;
using Method = RestSharp.Method;

namespace ServiceNowTicketValidator
{
    internal class ServiceNowClient : IDisposable
    {
        private const string TokenAuthUriFormat = "{0}/oauth_token.do";
        private const string IncidentByTicketNumberFormat = "api/now/table/incident?sysparm_query=number%3D{0}&sysparm_limit=1";

        private readonly string _applicationUrl;
        private readonly SecureString _clientSecret;
        private readonly string _userName;
        private readonly SecureString _password;
        private ServiceNowToken _accessToken;
        private RestClient _restClient;

        public ServiceNowClient(string applicationUrl, SecureString clientSecret, string userName,
            SecureString password)
        {
            _applicationUrl = applicationUrl;
            _clientSecret = clientSecret?.Copy();
            _userName = userName;
            _password = password.Copy();
        }

        private void EnsureRestClient()
        {
            if (_restClient == null || _accessToken == null || _accessToken.Expired)
                _restClient = GetRestClient();
        }

        private void HandleHeaders(ref RestRequest request)
        {
            request.AddHeader("Accept", "application/json");
            if (!UseBasicAuth)
                request.AddHeader("Authorization", $"Bearer {_accessToken.access_token}");
        }

        public ServiceNowIncident GetIncident(string ticketNumber)
        {
            try
            {
                EnsureRestClient();
                var request =
                    new RestRequest($"api/now/table/incident?sysparm_query=number%3D{ticketNumber}&sysparm_limit=1",
                        Method.GET);
                HandleHeaders(ref request);
                var response = _restClient.Execute<ServiceNowResult<ServiceNowIncident>>(request);
                return response?.Data?.result?.FirstOrDefault();
            }
            catch (Exception ex)
            {
                Log.Error(ex, $"Unable to find incident for ticket number {ticketNumber}");
                return null;
            }
        }

        private T FollowLink<T>(string linkUrl) where T : class
        {
            try
            {
                EnsureRestClient();
                var relativeUrl = new Uri(linkUrl).PathAndQuery;
                var request = new RestRequest(relativeUrl);
                HandleHeaders(ref request);
                var response = _restClient.Execute<ServiceNowResult<T>>(request);
                return response?.Data?.result?.FirstOrDefault();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Unable to follow link {ServiceNowLink} for type {ObjectType}", linkUrl,
                    typeof(T).ToString());
                return null;
            }
        }

        public ServiceNowCmdbCi GetConfigurationItem(string linkUrl)
        {
            return FollowLink<ServiceNowCmdbCi>(linkUrl);
        }

        public ServiceNowSysUser GetSystemUser(string linkUrl)
        {
            return FollowLink<ServiceNowSysUser>(linkUrl);
        }

        private bool UseBasicAuth => _clientSecret == null;

        private RestClient GetRestClient()
        {
            var restClient = _restClient ?? new RestClient(_applicationUrl);
            if (UseBasicAuth)
                restClient.Authenticator = new HttpBasicAuthenticator(_userName, _password.ToInsecureString());
            else
                HandleOAuth();
            return restClient;
        }

        private void HandleOAuth()
        {
            
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _clientSecret?.Dispose();
                _password?.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
