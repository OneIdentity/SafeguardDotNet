// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.BrowserLogin
{
    using System;
    using System.Threading;

    using Serilog;

    /// <summary>
    /// Provides browser-based authentication to Safeguard using OAuth2/PKCE flow.
    /// This class launches the default browser and listens for the OAuth callback to complete authentication.
    /// </summary>
    public static class DefaultBrowserLogin
    {
        /// <summary>
        /// Connect to Safeguard by launching the default browser for OAuth2/PKCE authentication.
        /// Opens a local TCP listener to receive the authorization code callback from the browser.
        /// </summary>
        /// <param name="appliance">Network address of Safeguard appliance</param>
        /// <param name="username">Optional username to pre-fill the login form</param>
        /// <param name="port">Local TCP port to listen for OAuth callback (default: 8400)</param>
        /// <param name="apiVersion">Target API version to use (default: 4)</param>
        /// <param name="ignoreSsl">Ignore validation of Safeguard appliance SSL certificate (default: false)</param>
        /// <returns>Reusable Safeguard API connection</returns>
        public static ISafeguardConnection Connect(
            string appliance, string username = "", int port = 8400, int apiVersion = Safeguard.DefaultApiVersion, bool ignoreSsl = false)
        {
            Log.Debug("Calling RSTS for primary authentication");

            var oauthCodeVerifier = Safeguard.AgentBasedLoginUtils.OAuthCodeVerifier();
            var tokenExtractor = new AuthorizationCodeExtractor();
            var browserLauncher = new BrowserLauncher(appliance, oauthCodeVerifier);

            using var source = new CancellationTokenSource();
            Console.CancelKeyPress += (sender, e) => { source.Cancel(); };

            browserLauncher.Show(username, port);
            tokenExtractor.Listen(port, source.Token);

            if (string.IsNullOrEmpty(tokenExtractor.AuthorizationCode))
            {
                throw new SafeguardDotNetException("Unable to obtain authorization code");
            }

            Log.Debug("Redeeming RSTS authorization code");

            using var rstsAccessToken = Safeguard.AgentBasedLoginUtils.PostAuthorizationCodeFlow(
                appliance, tokenExtractor.AuthorizationCode, oauthCodeVerifier, Safeguard.AgentBasedLoginUtils.RedirectUri);

            Log.Debug("Exchanging RSTS access token");

            var responseObject = Safeguard.AgentBasedLoginUtils.PostLoginResponse(appliance, rstsAccessToken, apiVersion);

            var statusValue = responseObject.GetValue("Status")?.ToString();

            if (string.IsNullOrEmpty(statusValue) || statusValue != "Success")
            {
                throw new SafeguardDotNetException($"Error response status {statusValue} from RSTS");
            }

            using var accessToken = responseObject.GetValue("UserToken")?.ToString().ToSecureString();
            return Safeguard.Connect(appliance, accessToken, apiVersion, ignoreSsl);
        }
    }
}
