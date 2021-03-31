using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Security;
using Newtonsoft.Json.Linq;
using RestSharp;
using Serilog;

namespace OneIdentity.SafeguardDotNet.Authentication
{
    internal abstract class AuthenticatorBase : IAuthenticationMechanism
    {
        private bool _disposed;

        protected SecureString AccessToken;

        protected readonly string SafeguardRstsUrl;
        protected readonly string SafeguardCoreUrl;

        protected RestClient RstsClient;
        protected RestClient CoreClient;

        protected AuthenticatorBase(string networkAddress, int apiVersion, bool ignoreSsl, RemoteCertificateValidationCallback validationCallback)
        {
            NetworkAddress = networkAddress;
            ApiVersion = apiVersion;

            SafeguardRstsUrl = $"https://{NetworkAddress}/RSTS";
            RstsClient = new RestClient(SafeguardRstsUrl);

            SafeguardCoreUrl = $"https://{NetworkAddress}/service/core/v{ApiVersion}";
            CoreClient = new RestClient(SafeguardCoreUrl);

            if (ignoreSsl)
            {
                IgnoreSsl = true;
                ValidationCallback = null;
                RstsClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
                CoreClient.RemoteCertificateValidationCallback += (sender, certificate, chain, errors) => true;
            } 
            else if (validationCallback != null)
            {
                IgnoreSsl = false;
                ValidationCallback = validationCallback;
                RstsClient.RemoteCertificateValidationCallback += validationCallback;
                CoreClient.RemoteCertificateValidationCallback += validationCallback;
            }
        }

        public abstract string Id { get; }

        public string NetworkAddress { get; }

        public int ApiVersion { get; }

        public bool IgnoreSsl { get; }

        public RemoteCertificateValidationCallback ValidationCallback { get; }

        public virtual bool IsAnonymous => false;

        public bool HasAccessToken()
        {
            return AccessToken != null;
        }

        public void ClearAccessToken()
        {
            AccessToken?.Dispose();
            AccessToken = null;
        }

        public SecureString GetAccessToken()
        {
            if (_disposed)
                throw new ObjectDisposedException("AuthenticatorBase");
            return AccessToken;
        }

        public int GetAccessTokenLifetimeRemaining()
        {
            if (_disposed)
                throw new ObjectDisposedException("AuthenticatorBase");
            if (!HasAccessToken())
                return 0;
            var request = new RestRequest("LoginMessage", RestSharp.Method.GET)
                .AddHeader("Accept", "application/json")
                // SecureString handling here basically negates the use of a secure string anyway, but when calling a Web API
                // I'm not sure there is anything you can do about it.
                .AddHeader("Authorization", $"Bearer {AccessToken.ToInsecureString()}")
                .AddHeader("X-TokenLifetimeRemaining", "");
            var response = CoreClient.Execute(request);
            if (response.ResponseStatus != ResponseStatus.Completed)
                throw new SafeguardDotNetException($"Unable to connect to web service {CoreClient.BaseUrl}, Error: " +
                                    response.ErrorMessage);
            if (!response.IsSuccessful)
                return 0;
            var remainingStr = response.Headers.ToList().FirstOrDefault(x => x.Name == "X-TokenLifetimeRemaining")?.Value?.ToString();
            if (remainingStr == null || !int.TryParse(remainingStr, out var remaining))
                return 10; // Random magic value... the access token was good, but for some reason it didn't return the remaining lifetime
            return remaining;
        }

        public void RefreshAccessToken()
        {
            if (_disposed)
                throw new ObjectDisposedException("AuthenticatorBase");
            using (var rStsToken = GetRstsTokenInternal())
            {
                var request = new RestRequest("Token/LoginResponse", RestSharp.Method.POST)
                    .AddHeader("Accept", "application/json")
                    .AddHeader("Content-type", "application/json")
                    // SecureString handling here basically negates the use of a secure string anyway, but when calling a Web API
                    // I'm not sure there is anything you can do about it.
                    .AddJsonBody(new { StsAccessToken = rStsToken.ToInsecureString() });
                var response = CoreClient.Execute(request);
                if (response.ResponseStatus != ResponseStatus.Completed)
                    throw new SafeguardDotNetException($"Unable to connect to web service {CoreClient.BaseUrl}, Error: " +
                                                       response.ErrorMessage);
                if (!response.IsSuccessful)
                    throw new SafeguardDotNetException(
                        $"Error exchanging RSTS token from {Id} authenticator for Safeguard API access token, Error: " +
                        $"{response.StatusCode} {response.Content}", response.StatusCode, response.Content);
                var jObject = JObject.Parse(response.Content);
                AccessToken = jObject.GetValue("UserToken")?.ToString().ToSecureString();
            }
        }

        public string ResolveProviderToScope(string provider)
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
                        .AddJsonBody("RelayState=");
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
                    throw new SafeguardDotNetException(
                        "Unable to connect to RSTS to find identity provider scopes, Error: " +
                        response.ErrorMessage);
                if (!response.IsSuccessful)
                    throw new SafeguardDotNetException(
                        "Error requesting identity provider scopes from RSTS, Error: " +
                        $"{response.StatusCode} {response.Content}", response.StatusCode, response.Content);
                var jObject = JObject.Parse(response.Content);
                var jProviders = (JArray)jObject["Providers"];
                var knownScopes = new List<(string Id, string DisplayName)>();
                if (jProviders != null)
                    knownScopes = jProviders.Select(s => (Id: s["Id"].ToString(), DisplayName: s["DisplayName"].ToString())).ToList();

                // 3 step check for determining if the user provided scope is valid:
                //
                // 1. User value == RSTSProviderId
                // 2. User value == Identity Provider Display Name.
                //    - This allows the caller to specify the domain name for AD.
                // 3. User Value is contained in RSTSProviderId.
                //    - This allows the caller to specify the provider Id rather than the full RSTSProviderId.
                //    - Such a broad check could provide some issues with false matching, however since this
                //      was in the original code, this check has been left in place.
                var scope = knownScopes.FirstOrDefault(s => s.Id.EqualsNoCase(provider));
                if (scope.Id == null)
                { 
                    scope = knownScopes.FirstOrDefault(s => s.DisplayName.EqualsNoCase(provider));

                    if (scope.DisplayName == null)
                    {
                        scope = knownScopes.FirstOrDefault(s => s.Id.ContainsNoCase(provider));

                        if (scope.Id == null)
                        {
                            throw new SafeguardDotNetException(
                            $"Unable to find scope matching '{provider}' in [{string.Join(",", knownScopes)}]");
                        }
                    }
                        
                }

                return $"rsts:sts:primaryproviderid:{scope.Id}";
            }
            catch (SafeguardDotNetException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException("Unable to connect to determine identity provider", ex);
            }
        }

        protected abstract SecureString GetRstsTokenInternal();

        public abstract object Clone();

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
               ClearAccessToken();
            }
            finally
            {
                _disposed = true;
            }
        }
    }
}
