// Copyright (c) One Identity LLC. All rights reserved.

namespace ServiceNowTicketValidator
{
    using System;
    using System.Linq;
    using System.Net.Http;
    using System.Net.Http.Headers;
    using System.Security;
    using System.Text;

    using global::ServiceNowTicketValidator.DTOs;

    using Newtonsoft.Json;
    using OneIdentity.SafeguardDotNet;
    using Serilog;

    internal class ServiceNowClient : IDisposable
    {
        private const string IncidentByTicketNumberFormat = "api/now/table/incident?sysparm_query=number%3D{0}&sysparm_limit=1";

        private readonly Uri _applicationUrl;
        private readonly string _userName;
        private readonly SecureString _password;
        private HttpClient _restClient;

        public ServiceNowClient(
            string applicationUrl,
            SecureString clientSecret,
            string userName,
            SecureString password)
        {
            _applicationUrl = new Uri(applicationUrl, UriKind.Absolute);
            _userName = userName;
            _password = password.Copy();

            if (clientSecret != null && clientSecret.Length != 0)
            {
                throw new NotImplementedException("Only basic authentication with a username and password is supported in this example. Do not specify a client secret. OAuth authentication is not implemented.");
            }

            CreateHttpClient();
        }

        public ServiceNowIncident GetIncident(string ticketNumber)
        {
            var url = string.Format(IncidentByTicketNumberFormat, Uri.EscapeDataString(ticketNumber));
            var req = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri(_applicationUrl, url),
            };

            try
            {
                var res = _restClient.SendAsync(req).GetAwaiter().GetResult();
                var msg = res.Content?.ReadAsStringAsync().GetAwaiter().GetResult();

                return JsonConvert.DeserializeObject<ServiceNowResult<ServiceNowIncident>>(msg)?.result?.FirstOrDefault();
            }
            catch (Exception ex)
            {
                Log.Error(ex, "Unable to find incident for ticket number {TicketNumber}", ticketNumber);
                return null;
            }
        }

        private T FollowLink<T>(string linkUrl)
            where T : class
        {
            var relativeUrl = new Uri(linkUrl).PathAndQuery;
            var req = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri(_applicationUrl, relativeUrl),
            };

            try
            {
                var res = _restClient.SendAsync(req).GetAwaiter().GetResult();
                var msg = res.Content?.ReadAsStringAsync().GetAwaiter().GetResult();

                return JsonConvert.DeserializeObject<ServiceNowResult<T>>(msg)?.result?.FirstOrDefault();
            }
            catch (Exception ex)
            {
                Log.Error(
                    ex,
                    "Unable to follow link {ServiceNowLink} for type {ObjectType}",
                    linkUrl,
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

        private void CreateHttpClient()
        {
            var handler = new HttpClientHandler();

            handler.SslProtocols = System.Security.Authentication.SslProtocols.Tls12;

            _restClient = new HttpClient(handler);

            _restClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            _restClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_userName}:{_password.ToInsecureString()}")));
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                _password?.Dispose();
                _restClient?.Dispose();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
