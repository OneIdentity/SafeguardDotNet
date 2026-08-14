// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.BrowserLogin;

using System;
using System.Threading;
using System.Threading.Tasks;

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
    /// <remarks>
    /// WARNING: This method blocks indefinitely until the browser callback is received.
    /// If the user does not complete authentication, this call will never return.
    /// For programmatic cancellation, use <see cref="ConnectAsync"/> with a
    /// <see cref="CancellationToken"/> or
    /// <see cref="Safeguard.AgentBasedLoginUtils.CreateConsoleCancellationToken"/>.
    /// </remarks>
    /// <param name="appliance">Network address of Safeguard appliance</param>
    /// <param name="username">Optional username to pre-fill the login form</param>
    /// <param name="port">Local TCP port to listen for OAuth callback (default: 8400)</param>
    /// <param name="apiVersion">Target API version to use (default: 4)</param>
    /// <param name="ignoreSsl">Ignore validation of Safeguard appliance SSL certificate (default: false)</param>
    /// <param name="minTlsVersion">Lowest allowed TLS version, or null to let the operating system negotiate.</param>
    /// <param name="maxTlsVersion">Highest allowed TLS version, or null to let the operating system negotiate.</param>
    /// <returns>Reusable Safeguard API connection</returns>
    public static ISafeguardConnection Connect(
        string appliance,
        string username = "",
        int port = 8400,
        int apiVersion = Safeguard.DefaultApiVersion,
        bool ignoreSsl = false,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
    {
        return ConnectAsync(appliance, username, port, apiVersion, ignoreSsl, CancellationToken.None, minTlsVersion, maxTlsVersion)
            .GetAwaiter().GetResult();
    }

    /// <summary>
    /// Connect to Safeguard by launching the default browser for OAuth2/PKCE authentication (async).
    /// Opens a local TCP listener to receive the authorization code callback from the browser.
    /// Returns when the user completes authentication or the cancellation token is triggered.
    /// </summary>
    /// <remarks>
    /// WARNING: This method blocks indefinitely until the browser callback is received.
    /// If no <paramref name="cancellationToken"/> is provided, the call will never return
    /// if the user does not complete authentication. Always provide a cancellation token
    /// with a timeout or use <see cref="Safeguard.AgentBasedLoginUtils.CreateConsoleCancellationToken"/>
    /// to enable Ctrl+C cancellation.
    /// </remarks>
    /// <param name="appliance">Network address of Safeguard appliance</param>
    /// <param name="username">Optional username to pre-fill the login form</param>
    /// <param name="port">Local TCP port to listen for OAuth callback (default: 8400)</param>
    /// <param name="apiVersion">Target API version to use (default: 4)</param>
    /// <param name="ignoreSsl">Ignore validation of Safeguard appliance SSL certificate (default: false)</param>
    /// <param name="cancellationToken">Cancellation token to abort the flow.</param>
    /// <param name="minTlsVersion">Lowest allowed TLS version, or null to let the operating system negotiate.</param>
    /// <param name="maxTlsVersion">Highest allowed TLS version, or null to let the operating system negotiate.</param>
    /// <returns>Reusable Safeguard API connection</returns>
    /// <exception cref="SafeguardDotNetException">Thrown when authentication fails or API error.</exception>
    /// <exception cref="OperationCanceledException">Thrown when cancellation is requested.</exception>
    public static async Task<ISafeguardConnection> ConnectAsync(
        string appliance,
        string username = "",
        int port = 8400,
        int apiVersion = Safeguard.DefaultApiVersion,
        bool ignoreSsl = false,
        CancellationToken cancellationToken = default,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
    {
        Log.Debug("Calling RSTS for primary authentication");

        var oauthCodeVerifier = Safeguard.AgentBasedLoginUtils.OAuthCodeVerifier();
        var browserLauncher = new BrowserLauncher(appliance, oauthCodeVerifier);

        browserLauncher.Show(username, port);

        var authorizationCode = await AuthorizationCodeExtractor.ListenAsync(port, cancellationToken).ConfigureAwait(false);

        Log.Debug("Redeeming RSTS authorization code");

        using var rstsAccessToken = await Safeguard.AgentBasedLoginUtils.PostAuthorizationCodeFlowAsync(
            appliance,
            authorizationCode,
            oauthCodeVerifier,
            Safeguard.AgentBasedLoginUtils.RedirectUriTcpListener,
            ignoreSsl,
            cancellationToken,
            minTlsVersion,
            maxTlsVersion)
            .ConfigureAwait(false);

        Log.Debug("Exchanging RSTS access token");

        return await Safeguard.AgentBasedLoginUtils.ExchangeRstsTokenForConnectionAsync(
            appliance, rstsAccessToken, apiVersion, ignoreSsl, cancellationToken, minTlsVersion, maxTlsVersion)
            .ConfigureAwait(false);
    }
}
