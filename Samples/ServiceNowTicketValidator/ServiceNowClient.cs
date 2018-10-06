using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security;
using OneIdentity.SafeguardDotNet;
using RestSharp;
using RestSharp.Authenticators;
using Serilog;

using Method = RestSharp.Method;

namespace ServiceNowTicketValidator
{
    [SuppressMessage("ReSharper", "InconsistentNaming")]
    internal class ServiceNowResult<T> where T : class
    {
        public IEnumerable<T> result { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    internal class Incident
    {
        public string number { get; set; }
        public string state { get; set; }
        public bool Active => active != "false";
        public string active { get; set; }
        public string opened_at { get; set; }
        public string resolved_at { get; set; }
        public string closed_at { get; set; }
    }

    [SuppressMessage("ReSharper", "InconsistentNaming")]
    internal class ServiceNowToken
    {
        private int _expires_in;
        public string access_token { get; set; }
        public string refresh_token { get; set; }
        public string scope { get; set; }
        public string token_type { get; set; }
        public int expires_in
        {
            get => _expires_in;
            set
            {
                _expires_in = value;
                ExpiresAt = DateTime.UtcNow.AddSeconds(value);
            }
        }
        public DateTime ExpiresAt { get; set; }
        public bool Expired => DateTime.UtcNow > ExpiresAt;
    }

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
            _clientSecret = clientSecret.Copy();
            _userName = userName;
            _password = password.Copy();
        }

        public Incident GetIncident(string ticketNumber)
        {
            try
            {
                if (_restClient == null || _accessToken == null || _accessToken.Expired)
                    _restClient = GetRestClient();
                var request =
                    new RestRequest($"api/now/table/incident?sysparm_query=number%3D{ticketNumber}&sysparm_limit=1",
                        Method.GET);
                request.AddHeader("Accept", "application/json");
                if (!UseBasicAuth)
                    request.AddHeader("Authorization", $"Bearer {_accessToken.access_token}");
                var response = _restClient.Execute<ServiceNowResult<Incident>>(request);
                return response?.Data?.result?.FirstOrDefault();
            }
            catch (Exception ex)
            {
                Log.Error(ex, $"Unable to find incident for ticket number {ticketNumber}");
                return null;
            }
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
