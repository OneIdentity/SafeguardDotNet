// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.PkceNoninteractiveLogin;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Web;

using Serilog;

/// <summary>
/// Provides PKCE-based authentication to Safeguard without launching a browser.
/// This class enables programmatic authentication by manually handling the OAuth2/PKCE flow.
/// </summary>
public static class PkceNoninteractiveLogin
{
    // rSTS login controller step numbers (from rSTS Login.js)
    private const string StepInit = "1";
    private const string StepPrimaryAuth = "3";
    private const string StepSecondaryInit = "7";
    private const string StepSecondaryAuth = "5";
    private const string StepGenerateClaims = "6";

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
    /// <param name="minTlsVersion">Lowest allowed TLS version, or null to let the operating system negotiate.</param>
    /// <param name="maxTlsVersion">Highest allowed TLS version, or null to let the operating system negotiate.</param>
    /// <returns>Reusable Safeguard API connection.</returns>
    /// <exception cref="SafeguardDotNetException">Thrown when authentication fails or the API returns an error.</exception>
    public static ISafeguardConnection Connect(
        string appliance,
        string provider,
        string username,
        SecureString password,
        int apiVersion = Safeguard.DefaultApiVersion,
        bool ignoreSsl = false,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
    {
        return ConnectAsync(appliance, provider, username, password, null, apiVersion, ignoreSsl, CancellationToken.None, minTlsVersion, maxTlsVersion)
            .GetAwaiter().GetResult();
    }

    /// <summary>
    /// Connect to Safeguard API using PKCE (Proof Key for Code Exchange) authentication without launching a browser,
    /// with support for multi-factor authentication (MFA).
    /// This method programmatically simulates the browser-based OAuth2/PKCE flow by directly interacting with
    /// the Safeguard login endpoints. When the identity provider requires a second factor (e.g. TOTP, RADIUS),
    /// the <paramref name="secondaryPassword"/> is submitted as the one-time password.
    /// </summary>
    /// <param name="appliance">Network address of the Safeguard appliance.</param>
    /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
    /// <param name="username">User name to use for authentication.</param>
    /// <param name="password">User password to use for authentication.</param>
    /// <param name="secondaryPassword">One-time password or code for multi-factor authentication (e.g. TOTP code).
    /// Pass null if MFA is not required.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation.</param>
    /// <param name="minTlsVersion">Lowest allowed TLS version, or null to let the operating system negotiate.</param>
    /// <param name="maxTlsVersion">Highest allowed TLS version, or null to let the operating system negotiate.</param>
    /// <returns>Reusable Safeguard API connection.</returns>
    /// <exception cref="SafeguardDotNetException">Thrown when authentication fails, MFA is required but no
    /// secondary password was provided, or the API returns an error.</exception>
    public static ISafeguardConnection Connect(
        string appliance,
        string provider,
        string username,
        SecureString password,
        SecureString secondaryPassword,
        int apiVersion = Safeguard.DefaultApiVersion,
        bool ignoreSsl = false,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
    {
        return ConnectAsync(appliance, provider, username, password, secondaryPassword, apiVersion, ignoreSsl, CancellationToken.None, minTlsVersion, maxTlsVersion)
            .GetAwaiter().GetResult();
    }

    /// <summary>
    /// Connect to Safeguard API using PKCE authentication without launching a browser (async).
    /// </summary>
    /// <param name="appliance">Network address of the Safeguard appliance.</param>
    /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
    /// <param name="username">User name to use for authentication.</param>
    /// <param name="password">User password to use for authentication.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation.</param>
    /// <param name="cancellationToken">Cancellation token to abort the flow.</param>
    /// <param name="minTlsVersion">Lowest allowed TLS version, or null to let the operating system negotiate.</param>
    /// <param name="maxTlsVersion">Highest allowed TLS version, or null to let the operating system negotiate.</param>
    /// <returns>Reusable Safeguard API connection.</returns>
    /// <exception cref="SafeguardDotNetException">Thrown when authentication fails or the API returns an error.</exception>
    /// <exception cref="OperationCanceledException">Thrown when cancellation is requested.</exception>
    public static Task<ISafeguardConnection> ConnectAsync(
        string appliance,
        string provider,
        string username,
        SecureString password,
        int apiVersion = Safeguard.DefaultApiVersion,
        bool ignoreSsl = false,
        CancellationToken cancellationToken = default,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
    {
        return ConnectAsync(appliance, provider, username, password, null, apiVersion, ignoreSsl, cancellationToken, minTlsVersion, maxTlsVersion);
    }

    /// <summary>
    /// Connect to Safeguard API using PKCE authentication without launching a browser (async),
    /// with support for multi-factor authentication (MFA).
    /// </summary>
    /// <param name="appliance">Network address of the Safeguard appliance.</param>
    /// <param name="provider">Safeguard authentication provider name (e.g. local).</param>
    /// <param name="username">User name to use for authentication.</param>
    /// <param name="password">User password to use for authentication.</param>
    /// <param name="secondaryPassword">One-time password or code for multi-factor authentication (e.g. TOTP code).
    /// Pass null if MFA is not required.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation.</param>
    /// <param name="cancellationToken">Cancellation token to abort the flow.</param>
    /// <param name="minTlsVersion">Lowest allowed TLS version, or null to let the operating system negotiate.</param>
    /// <param name="maxTlsVersion">Highest allowed TLS version, or null to let the operating system negotiate.</param>
    /// <returns>Reusable Safeguard API connection.</returns>
    /// <exception cref="SafeguardDotNetException">Thrown when authentication fails, MFA is required but no
    /// secondary password was provided, or the API returns an error.</exception>
    /// <exception cref="OperationCanceledException">Thrown when cancellation is requested.</exception>
    public static async Task<ISafeguardConnection> ConnectAsync(
        string appliance,
        string provider,
        string username,
        SecureString password,
        SecureString secondaryPassword,
        int apiVersion = Safeguard.DefaultApiVersion,
        bool ignoreSsl = false,
        CancellationToken cancellationToken = default,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
    {
        var csrfToken = Safeguard.AgentBasedLoginUtils.GenerateCsrfToken();
        var oauthCodeVerifier = Safeguard.AgentBasedLoginUtils.OAuthCodeVerifier();
        var oauthCodeChallenge = Safeguard.AgentBasedLoginUtils.OAuthCodeChallenge(oauthCodeVerifier);
        var redirectUri = Safeguard.AgentBasedLoginUtils.RedirectUri;

        using var http = Safeguard.AgentBasedLoginUtils.CreateSessionHttpClient(appliance, csrfToken, ignoreSsl, minTlsVersion, maxTlsVersion);

        cancellationToken.ThrowIfCancellationRequested();

        var identityProvider = await ResolveIdentityProviderAsync(http, appliance, apiVersion, provider, cancellationToken)
            .ConfigureAwait(false);

        var primaryFormData = $"directoryComboBox={identityProvider}" +
            $"&usernameTextbox={Uri.EscapeDataString(username)}" +
            $"&passwordTextbox={Uri.EscapeDataString(password.ToInsecureString())}" +
            $"&csrfTokenTextbox={csrfToken}";
        var pkceUrl = $"https://{appliance}/RSTS/UserLogin/LoginController?response_type=code&code_challenge_method=S256&" +
            $"code_challenge={oauthCodeChallenge}&redirect_uri={redirectUri}&loginRequestStep=";

        cancellationToken.ThrowIfCancellationRequested();

        Log.Debug("Calling RSTS for provider initialization");
        await RstsRequestAsync(http, pkceUrl + StepInit, primaryFormData, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();

        Log.Debug("Calling RSTS for primary authentication");
        var (primaryBody, _) = await RstsRequestAsync(http, pkceUrl + StepPrimaryAuth, primaryFormData, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();

        await HandleSecondaryAuthenticationAsync(http, pkceUrl, primaryFormData, primaryBody, secondaryPassword, cancellationToken)
            .ConfigureAwait(false);

        cancellationToken.ThrowIfCancellationRequested();

        Log.Debug("Calling RSTS for generate claims");
        var (claimsBody, claimsStatus) = await RstsRequestAsync(http, pkceUrl + StepGenerateClaims, primaryFormData, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        if (claimsStatus != HttpStatusCode.OK)
        {
            throw new SafeguardDotNetException(
                $"Failed to generate claims: {claimsBody}", claimsStatus, claimsBody);
        }

        var authorizationCode = ExtractAuthorizationCode(claimsBody);

        cancellationToken.ThrowIfCancellationRequested();

        Log.Debug("Redeeming RSTS authorization code");

        using var rstsAccessToken = await Safeguard.AgentBasedLoginUtils.PostAuthorizationCodeFlowAsync(
            appliance,
            authorizationCode,
            oauthCodeVerifier,
            Safeguard.AgentBasedLoginUtils.RedirectUri,
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

    private static async Task HandleSecondaryAuthenticationAsync(
        HttpClient http,
        string pkceUrl,
        string primaryFormData,
        string primaryAuthBody,
        SecureString secondaryPassword,
        CancellationToken cancellationToken)
    {
        JsonDocument primaryResponse;
        try
        {
            primaryResponse = JsonDocument.Parse(primaryAuthBody);
        }
        catch
        {
            return; // Non-JSON response means no secondary auth info
        }

        using (primaryResponse)
        {
            var root = primaryResponse.RootElement;
            var secondaryProviderId = root.TryGetProperty("SecondaryProviderID", out var spId) ? spId.GetString() : null;

            if (string.IsNullOrEmpty(secondaryProviderId))
            {
                return; // No MFA required
            }

            Log.Debug("Secondary authentication required, provider: {SecondaryProviderId}", secondaryProviderId);

            if (secondaryPassword == null)
            {
                throw new SafeguardDotNetException(
                    $"Multi-factor authentication is required (provider: {secondaryProviderId}) " +
                    "but no secondary password was provided. Use the secondaryPassword parameter to supply the one-time code.");
            }
        }

        cancellationToken.ThrowIfCancellationRequested();

        Log.Debug("Calling RSTS for secondary provider initialization");
        var (initBody, initStatus) = await RstsRequestAsync(http, pkceUrl + StepSecondaryInit, primaryFormData, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        // Parse the MFA state from the secondary init response
        var mfaState = string.Empty;
        if (initStatus == HttpStatusCode.OK || (int)initStatus == 203)
        {
            try
            {
                using var initResponse = JsonDocument.Parse(initBody);
                var initRoot = initResponse.RootElement;
                mfaState = initRoot.TryGetProperty("State", out var stateEl) ? stateEl.GetString() ?? string.Empty : string.Empty;
                var mfaMessage = initRoot.TryGetProperty("Message", out var msgEl) ? msgEl.GetString() : null;
                if (!string.IsNullOrEmpty(mfaMessage))
                {
                    Log.Debug("MFA prompt: {Message}", mfaMessage);
                }
            }
            catch
            {
                // Proceed without state if response isn't JSON
            }
        }

        cancellationToken.ThrowIfCancellationRequested();

        // Submit the secondary password (OTP code) along with the primary form data
        var mfaFormData = primaryFormData +
            $"&secondaryLoginTextbox={Uri.EscapeDataString(secondaryPassword.ToInsecureString())}" +
            $"&secondaryAuthenticationStateTextbox={Uri.EscapeDataString(mfaState)}";

        Log.Debug("Calling RSTS for secondary authentication");
        var (mfaBody, mfaStatus) = await RstsRequestAsync(http, pkceUrl + StepSecondaryAuth, mfaFormData, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        // Step 5 returns empty string on success, or 203 with error details on failure
        if ((int)mfaStatus == 203)
        {
            var errorMessage = "Secondary authentication failed.";
            try
            {
                using var mfaResponse = JsonDocument.Parse(mfaBody);
                errorMessage = mfaResponse.RootElement.TryGetProperty("Message", out var mEl) ? mEl.GetString() ?? errorMessage : errorMessage;
            }
            catch
            {
                if (!string.IsNullOrEmpty(mfaBody))
                {
                    errorMessage = mfaBody;
                }
            }

            throw new SafeguardDotNetException(
                $"Multi-factor authentication failed: {errorMessage}");
        }

        if (!IsSuccessStatusCode(mfaStatus))
        {
            throw new SafeguardDotNetException(
                $"Multi-factor authentication failed: {mfaBody}", mfaStatus, mfaBody);
        }

        Log.Debug("Secondary authentication completed successfully");
    }

    private static string ExtractAuthorizationCode(string response)
    {
        string authorizationCode;
        try
        {
            using var jsonDoc = JsonDocument.Parse(response);
            var relyingPartyUrl = jsonDoc.RootElement.TryGetProperty("RelyingPartyUrl", out var rpEl) ? rpEl.GetString() : null;

            if (string.IsNullOrEmpty(relyingPartyUrl))
            {
                throw new SafeguardDotNetException(
                    "rSTS response did not contain a RelyingPartyUrl. " +
                    "The authentication process may be incomplete.");
            }

            // Parse the query string to extract the authorization code
            var uri = new Uri(relyingPartyUrl);
            authorizationCode = HttpUtility.ParseQueryString(uri.Query)["code"];
        }
        catch (SafeguardDotNetException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new SafeguardDotNetException("Failed to parse authorization code from rSTS response", ex);
        }

        if (string.IsNullOrEmpty(authorizationCode))
        {
            throw new SafeguardDotNetException("rSTS response did not contain an authorization code");
        }

        return authorizationCode;
    }

    private static async Task<string> ResolveIdentityProviderAsync(
        HttpClient http,
        string appliance,
        int apiVersion,
        string provider,
        CancellationToken cancellationToken)
    {
        var coreUrl = $"https://{appliance}/service/core/v{apiVersion}";

        var (response, _) = await RstsRequestAsync(
            http,
            $"{coreUrl}/AuthenticationProviders",
            null,
            HttpMethod.Get,
            "application/json",
            cancellationToken)
            .ConfigureAwait(false);

        var knownScopes = new List<(string RstsProviderId, string Name, string RstsProviderScope)>();
        using (var jProviders = JsonDocument.Parse(response))
        {
            foreach (var item in jProviders.RootElement.EnumerateArray())
            {
                var id = item.TryGetProperty("RstsProviderId", out var idEl) ? idEl.GetString() : null;
                var name = item.TryGetProperty("Name", out var nameEl) ? nameEl.GetString() : null;
                var providerScope = item.TryGetProperty("RstsProviderScope", out var scopeEl) ? scopeEl.GetString() : null;
                knownScopes.Add((id, name, providerScope));
            }
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

    private static async Task<(string Body, HttpStatusCode StatusCode)> RstsRequestAsync(
        HttpClient http,
        string url,
        string postData,
        HttpMethod method = null,
        string contentType = "application/x-www-form-urlencoded",
        CancellationToken cancellationToken = default)
    {
        method ??= HttpMethod.Post;

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
            var res = await http.SendAsync(req, cancellationToken).ConfigureAwait(false);
            var body = await res.Content.ReadAsStringAsync().ConfigureAwait(false) ?? string.Empty;
            var statusCode = res.StatusCode;

            if (!IsSuccessStatusCode(statusCode) && (int)statusCode != 203)
            {
                var errorMessage = !string.IsNullOrWhiteSpace(body) ? body.Trim() : statusCode.ToString();
                throw new SafeguardDotNetException(
                    $"rSTS authentication error: {errorMessage}", statusCode, body);
            }

            return (body, statusCode);
        }
        catch (TaskCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }
        catch (TaskCanceledException)
        {
            throw new SafeguardDotNetException($"Request timed out connecting to {url}");
        }
        catch (HttpRequestException ex)
        {
            throw new SafeguardDotNetException($"Unable to connect to {url}: {ex.Message}", ex);
        }
    }

    private static bool IsSuccessStatusCode(HttpStatusCode statusCode)
    {
        return statusCode is >= HttpStatusCode.OK and <= (HttpStatusCode)299;
    }
}
