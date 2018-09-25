using System;
using System.Linq;
using System.Net;
using System.Security;
using Newtonsoft.Json.Linq;
using RestSharp;
using Serilog;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal class PasswordAuthenticator : AuthenticatorBase
    {
        private bool _disposed;

        private readonly string _provider;
        private string _providerScope;
        private readonly string _username;
        private readonly SecureString _password;

        public PasswordAuthenticator(string networkAddress, string provider, string username,
            SecureString password, int apiVersion, bool ignoreSsl) : base(networkAddress, apiVersion, ignoreSsl)
        {
            _provider = provider;
            if (string.IsNullOrEmpty(_provider))
                _providerScope = "rsts:sts:primaryproviderid:local";
            _username = username;
            _password = password;
        }

        private void ResolveProviderToScope()
        {
            try
            {
                IRestResponse response;
                try
                {
                    var request = new RestRequest("UserLogin/LoginController", RestSharp.Method.POST)
                        .AddHeader("Accept", "application/json")
                        .AddHeader("Content-type", "application/x-www-form-urlencoded")
                        .AddParameter("response_type", "token", ParameterType.QueryString)
                        .AddParameter("redirect_uri", "urn:InstalledApplication", ParameterType.QueryString)
                        .AddParameter("loginRequestStep", 1, ParameterType.QueryString)
                        .AddBody("RelayState=");
                    response = RstsClient.Execute(request);
                }
                catch (WebException)
                {
                    Log.Debug("Caught exception with POST to find identity provider scopes, trying GET");
                    var request = new RestRequest("UserLogin/LoginController", RestSharp.Method.GET)
                        .AddHeader("Accept", "application/json")
                        .AddHeader("Content-type", "application/x-www-form-urlencoded")
                        .AddParameter("response_type", "token", ParameterType.QueryString)
                        .AddParameter("redirect_uri", "urn:InstalledApplication", ParameterType.QueryString)
                        .AddParameter("loginRequestStep", 1, ParameterType.QueryString);
                    response = RstsClient.Execute(request);
                }
                if (response.ResponseStatus != ResponseStatus.Completed)
                    throw new SafeguardDotNetException("Unable to connect to RSTS to find identity provider scopes, Error: " +
                                                       response.ErrorMessage);
                if (!response.IsSuccessful)
                    throw new SafeguardDotNetException("Error requesting identity provider scopes from RSTS, Error: " +
                                                       $"{response.StatusCode} {response.Content}", response.Content);
                var jObject = JObject.Parse(response.Content);
                var jProviders = (JArray)jObject["Providers"];
                var knownScopes = jProviders.Select(s => s["Id"]).Values<string>().ToArray();
                var scope = knownScopes.FirstOrDefault(s => s.EqualsNoCase(_provider));
                if (scope != null)
                    _providerScope = $"rsts:sts:primaryproviderid:{scope}";
                else
                {
                    scope = knownScopes.FirstOrDefault(s => s.ContainsNoCase(_provider));
                    if (_providerScope != null)
                        _providerScope = $"rsts:sts:primaryproviderid:{scope}";
                    else
                        throw new SafeguardDotNetException($"Unable to find scope matching '{_provider}' in [{string.Join(",", knownScopes)}]");
                }
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException("Unable to connect to determine identity provider", ex);
            }
        }

        protected override SecureString GetRstsTokenInternal()
        {
            if (_disposed)
                throw new ObjectDisposedException("PasswordAuthenticator");
            if (_providerScope == null)
                ResolveProviderToScope();
            var request = new RestRequest("oauth2/token", RestSharp.Method.POST)
                .AddHeader("Accept", "application/json")
                .AddHeader("Content-type", "application/json")
                .AddJsonBody(new
                {
                    grant_type = "password",
                    username = _username,
                    // SecureString handling here basically negates the use of a secure string anyway, but when calling a Web API
                    // I'm not sure there is anything you can do about it.
                    password = _password.ToInsecureString(),
                    scope = _providerScope
                });
            var response = RstsClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to RSTS service {RstsClient.BaseUrl}, Error: " +
                                                   response.ErrorMessage);
            if (!response.IsSuccessful)
                throw new SafeguardDotNetException($"Error using password grant_type with scope {_providerScope}, Error: " +
                                                   $"{response.StatusCode} {response.Content}", response.Content);
            var jObject = JObject.Parse(response.Content);
            return jObject.GetValue("access_token").ToString().ToSecureString();
        }

        protected override void Dispose(bool disposing)
        {
            if (_disposed || !disposing)
                return;
            base.Dispose(true);
            try
            {
                _password?.Dispose();
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
