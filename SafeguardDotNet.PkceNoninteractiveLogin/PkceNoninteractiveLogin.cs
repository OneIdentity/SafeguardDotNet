// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.PkceNoninteractiveLogin
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Linq;
    using System.Net.Http;
    using System.Security;
    using System.Text;
    using System.Threading.Tasks;
    using System.Web;

    using Newtonsoft.Json.Linq;

    using Serilog;

    /// <summary>
    /// Provides PKCE-based authentication to Safeguard without launching a browser.
    /// This class enables programmatic authentication by manually handling the OAuth2/PKCE flow.
    /// </summary>
    public static class PkceNoninteractiveLogin
    {
        /// <summary>
        /// Connect to Safeguard API using PKCE (Proof Key for Code Exchange) authentication without launching a browser.
        /// This method programmatically simulates the browser-based OAuth2/PKCE flow by directly interacting with
        /// the Safeguard login endpoints.
        /// </summary>
        /// <param name="appliance">Network address of the Safeguard appliance.</param>
        /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
        /// <param name="username">User name to use for authentication.</param>
        /// <param name="password">User password to use for authentication.</param>
        /// <param name="apiVersion">Target API version to use.</param>
        /// <param name="ignoreSsl">Ignore server certificate validation.</param>
        /// <returns>Reusable Safeguard API connection.</returns>
        /// <exception cref="SafeguardDotNetException">Thrown when authentication fails or the API returns an error.</exception>
        public static ISafeguardConnection Connect(
            string appliance,
            string provider,
            string username,
            SecureString password,
            int apiVersion = Safeguard.DefaultApiVersion,
            bool ignoreSsl = false)
        {
            var csrfToken = Safeguard.AgentBasedLoginUtils.GenerateCsrfToken();
            var oauthCodeVerifier = Safeguard.AgentBasedLoginUtils.OAuthCodeVerifier();
            var oauthCodeChallenge = Safeguard.AgentBasedLoginUtils.OAuthCodeChallenge(oauthCodeVerifier);
            var redirectUri = Safeguard.AgentBasedLoginUtils.RedirectUri;

            var http = CreateHttpClient(appliance, csrfToken, ignoreSsl);

            var identityProvider = ResolveIdentityProvider(http, appliance, apiVersion, provider);

            // Form data to submit to the rSTS login screen
            var data = $"directoryComboBox={identityProvider}&usernameTextbox={Uri.EscapeDataString(username)}&" +
                $"passwordTextbox={Uri.EscapeDataString(password.ToInsecureString())}&csrfTokenTextbox={csrfToken}";
            var pkceUrl = $"https://{appliance}/RSTS/UserLogin/LoginController?response_type=code&code_challenge_method=S256&" +
                $"code_challenge={oauthCodeChallenge}&redirect_uri={redirectUri}&loginRequestStep=";

            Log.Debug("Calling RSTS for primary authentication");
            _ = ApiRequest(http, HttpMethod.Post, pkceUrl + "1", data, "application/x-www-form-urlencoded");
            Log.Debug("Calling RSTS for primary login post");
            _ = ApiRequest(http, HttpMethod.Post, pkceUrl + "3", data, "application/x-www-form-urlencoded");
            Log.Debug("Calling RSTS for generate claims");
            var response = ApiRequest(http, HttpMethod.Post, pkceUrl + "6", data, "application/x-www-form-urlencoded");

            string authorizationCode;
            try
            {
                var jsonObject = JObject.Parse(response);
                var relyingPartyUrl = jsonObject["RelyingPartyUrl"].ToString();

                // Parse the query string to extract the authorization code
                var uri = new Uri(relyingPartyUrl);
                authorizationCode = HttpUtility.ParseQueryString(uri.Query)["code"];
            }
            catch (Exception ex)
            {
                throw new SafeguardDotNetException("Failed to parse authorization code from rSTS", ex);
            }

            if (authorizationCode == null)
            {
                throw new SafeguardDotNetException("Unable to get authorization code from rSTS, unknown reason");
            }

            Log.Debug("Redeeming RSTS authorization code");

            using (var rstsAccessToken = Safeguard.AgentBasedLoginUtils.PostAuthorizationCodeFlow(
                appliance, authorizationCode, oauthCodeVerifier, Safeguard.AgentBasedLoginUtils.RedirectUri))
            {
                Log.Debug("Exchanging RSTS access token");

                var responseObject = Safeguard.AgentBasedLoginUtils.PostLoginResponse(appliance, rstsAccessToken, apiVersion);

                var statusValue = responseObject.GetValue("Status")?.ToString();

                if (string.IsNullOrEmpty(statusValue) || statusValue != "Success")
                {
                    throw new SafeguardDotNetException($"Error response status {statusValue} from RSTS");
                }

                using (var accessToken = responseObject.GetValue("UserToken")?.ToString().ToSecureString())
                {
                    return Safeguard.Connect(appliance, accessToken, apiVersion, ignoreSsl);
                }
            }

            throw new SafeguardDotNetException("Unable to correctly simulate the browser for Safeguard login");
        }

        private static string ResolveIdentityProvider(HttpClient http, string appliance, int apiVersion, string provider)
        {
            var coreUrl = $"https://{appliance}/service/core/v{apiVersion}";

            var response = ApiRequest(http, HttpMethod.Get, $"{coreUrl}/AuthenticationProviders", null, "application/json");
            var jProviders = JArray.Parse(response);
            var knownScopes = new List<(string RstsProviderId, string Name, string RstsProviderScope)>();
            if (jProviders != null)
            {
                knownScopes = jProviders.Select(s => (Id: s["RstsProviderId"].ToString(), Name: s["Name"].ToString(), Scope: s["RstsProviderScope"].ToString())).ToList();
            }

            // try to match what the user typed for provider to an rSTS ID
            var scope = knownScopes.FirstOrDefault(s => string.Equals(s.RstsProviderId, provider, StringComparison.OrdinalIgnoreCase));
            if (scope.RstsProviderId == null)
            {
                scope = knownScopes.FirstOrDefault(s => string.Equals(s.Name, provider, StringComparison.OrdinalIgnoreCase));

                if (scope.Name == null)
                {
                    scope = knownScopes.FirstOrDefault(s => CultureInfo.InvariantCulture.CompareInfo.IndexOf(
                        s.RstsProviderId,
                        provider,
                        CompareOptions.IgnoreCase) >= 0);

                    if (scope.RstsProviderId == null)
                    {
                        throw new SafeguardDotNetException(
                            $"Unable to find scope matching '{provider}' in [{string.Join(",", knownScopes)}]");
                    }
                }
            }

            return scope.RstsProviderId;
        }

        private static string ApiRequest(HttpClient http, HttpMethod method, string url, string postData, string contentType)
        {
            var req = new HttpRequestMessage
            {
                Method = method,
                RequestUri = new Uri(url, UriKind.Absolute),
            };

            req.Headers.Add("Accept", "application/json");

            if (postData != null)
            {
                req.Content = new StringContent(postData, Encoding.UTF8, contentType);
            }

            try
            {
                var res = http.SendAsync(req).GetAwaiter().GetResult();
                var msg = res.Content?.ReadAsStringAsync().GetAwaiter().GetResult();

                if (!res.IsSuccessStatusCode)
                {
                    throw new SafeguardDotNetException($"Error returned from Safeguard API, Error: {res.StatusCode} {msg}", res.StatusCode, msg);
                }

                return msg;
            }
            catch (TaskCanceledException)
            {
                throw new SafeguardDotNetException($"Request timeout to {url}.");
            }
        }

        private static HttpClient CreateHttpClient(string appliance, string csrfToken, bool ignoreSsl)
        {
            // Create HttpClient with cookie container to maintain session state across requests
            var cookieContainer = new System.Net.CookieContainer();
            cookieContainer.SetCookies(new Uri($"https://{appliance}/RSTS"), $"CsrfToken={csrfToken}");
            var handler = new HttpClientHandler()
            {
                SslProtocols = System.Security.Authentication.SslProtocols.Tls12,
                UseCookies = true,
                CookieContainer = cookieContainer,
            };

            if (ignoreSsl)
            {
#pragma warning disable S4830 // Intentional SSL bypass when user explicitly opts in via ignoreSsl parameter
                handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => true;
#pragma warning restore S4830
            }

            return new HttpClient(handler);
        }
    }
}
