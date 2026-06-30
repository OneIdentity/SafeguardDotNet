// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.DeviceCodeLogin;

using System;
using System.Net;
using System.Net.Http;
using System.Security;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

using OneIdentity.SafeguardDotNet.DeviceCodeLogin.Internal;
using OneIdentity.SafeguardDotNet.DeviceCodeLogin.Serialization;

using Serilog;

/// <summary>
/// Exchanges an rSTS access token for a Safeguard API connection. Production uses
/// the SDK's agent-based login utilities; unit tests substitute a fake.
/// </summary>
/// <param name="appliance">Network address of the Safeguard appliance.</param>
/// <param name="rstsAccessToken">The rSTS access token to exchange. Caller retains ownership.</param>
/// <param name="apiVersion">Target API version to use.</param>
/// <param name="ignoreSsl">Ignore server certificate validation (dev only).</param>
/// <param name="cancellationToken">Cancellation token to abort the exchange.</param>
/// <returns>A reusable Safeguard API connection.</returns>
internal delegate Task<ISafeguardConnection> RstsTokenExchange(
    string appliance,
    SecureString rstsAccessToken,
    int apiVersion,
    bool ignoreSsl,
    CancellationToken cancellationToken);

/// <summary>
/// Provides device code-based authentication to Safeguard using OAuth 2.0
/// Device Authorization Grant (RFC 8628).
/// </summary>
public static class DeviceCodeLogin
{
    private const string DefaultScope = "rsts:sts:primaryproviderid:local";

    private const string DeviceCodeGrantDisabledMarker = "device code grant type is not allowed";

    /// <summary>
    /// Connect to Safeguard API using the Device Authorization Grant.
    /// Blocks until the user completes authentication or the code expires.
    /// </summary>
    /// <param name="appliance">Network address of the Safeguard appliance.</param>
    /// <param name="parameters">Device code flow parameters including the display callback.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation (dev only).</param>
    /// <returns>Reusable Safeguard API connection.</returns>
    /// <exception cref="ArgumentException">Thrown when DisplayCallback is null or appliance is empty.</exception>
    /// <exception cref="SafeguardDotNetException">Thrown when authentication fails, code expires, or API error.</exception>
    public static ISafeguardConnection Connect(
        string appliance,
        DeviceCodeLoginParameters parameters,
        int apiVersion = Safeguard.DefaultApiVersion,
        bool ignoreSsl = false)
    {
        return ConnectAsync(appliance, parameters, apiVersion, ignoreSsl, CancellationToken.None)
            .GetAwaiter().GetResult();
    }

    /// <summary>
    /// Connect to Safeguard API using the Device Authorization Grant (async).
    /// Returns when the user completes authentication, the code expires,
    /// or the cancellation token is triggered.
    /// </summary>
    /// <param name="appliance">Network address of the Safeguard appliance.</param>
    /// <param name="parameters">Device code flow parameters including the display callback.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation (dev only).</param>
    /// <param name="cancellationToken">Cancellation token to abort the flow.</param>
    /// <returns>Reusable Safeguard API connection.</returns>
    /// <exception cref="ArgumentException">Thrown when DisplayCallback is null or appliance is empty.</exception>
    /// <exception cref="SafeguardDotNetException">Thrown when authentication fails, code expires, or API error.</exception>
    /// <exception cref="OperationCanceledException">Thrown when cancellation is requested.</exception>
    public static async Task<ISafeguardConnection> ConnectAsync(
        string appliance,
        DeviceCodeLoginParameters parameters,
        int apiVersion = Safeguard.DefaultApiVersion,
        bool ignoreSsl = false,
        CancellationToken cancellationToken = default)
    {
        using var httpClient = Safeguard.AgentBasedLoginUtils.CreateStatelessHttpClient(ignoreSsl);
        return await ConnectInternalAsync(
            appliance,
            parameters,
            apiVersion,
            ignoreSsl,
            httpClient,
            new SystemDeviceCodeClock(),
            Safeguard.AgentBasedLoginUtils.ExchangeRstsTokenForConnectionAsync,
            cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Runs the full device-code connect flow against injected collaborators.
    /// Used by the public <see cref="ConnectAsync"/> entry point and by unit tests.
    /// </summary>
    /// <param name="appliance">Network address of the Safeguard appliance.</param>
    /// <param name="parameters">Device code flow parameters including the display callback.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation (dev only).</param>
    /// <param name="httpClient">HTTP client used to talk to rSTS.</param>
    /// <param name="clock">Clock/delay abstraction driving the poll loop.</param>
    /// <param name="exchange">rSTS-to-Safeguard token exchange delegate.</param>
    /// <param name="cancellationToken">Cancellation token to abort the flow.</param>
    /// <returns>Reusable Safeguard API connection.</returns>
    internal static async Task<ISafeguardConnection> ConnectInternalAsync(
        string appliance,
        DeviceCodeLoginParameters parameters,
        int apiVersion,
        bool ignoreSsl,
        HttpClient httpClient,
        IDeviceCodeClock clock,
        RstsTokenExchange exchange,
        CancellationToken cancellationToken)
    {
        if (exchange == null)
        {
            throw new ArgumentNullException(nameof(exchange));
        }

        var rstsAccessToken = await RequestRstsDeviceTokenAsync(
            appliance, parameters, httpClient, clock, cancellationToken).ConfigureAwait(false);

        // Step 4: Exchange RSTS token for Safeguard UserToken
        Log.Debug("Exchanging RSTS access token for Safeguard user token");

        using (rstsAccessToken)
        {
            return await exchange(
                appliance, rstsAccessToken, apiVersion, ignoreSsl, cancellationToken).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Runs the device authorization request and token poll loop and returns the
    /// rSTS access token. The caller owns and must dispose the returned
    /// <see cref="SecureString"/>. This method performs no rSTS-to-Safeguard
    /// exchange, leaving that to <see cref="ConnectInternalAsync"/>.
    /// </summary>
    /// <param name="appliance">Network address of the Safeguard appliance.</param>
    /// <param name="parameters">Device code flow parameters including the display callback.</param>
    /// <param name="httpClient">HTTP client used to talk to rSTS.</param>
    /// <param name="clock">Clock/delay abstraction driving the poll loop.</param>
    /// <param name="cancellationToken">Cancellation token to abort the flow.</param>
    /// <returns>The rSTS access token as a <see cref="SecureString"/>.</returns>
    internal static async Task<SecureString> RequestRstsDeviceTokenAsync(
        string appliance,
        DeviceCodeLoginParameters parameters,
        HttpClient httpClient,
        IDeviceCodeClock clock,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrEmpty(appliance))
        {
            throw new ArgumentException("Appliance network address is required.", nameof(appliance));
        }

        if (parameters?.DisplayCallback == null)
        {
            throw new ArgumentException("DisplayCallback is required.", nameof(parameters));
        }

        if (httpClient == null)
        {
            throw new ArgumentNullException(nameof(httpClient));
        }

        if (clock == null)
        {
            throw new ArgumentNullException(nameof(clock));
        }

        cancellationToken.ThrowIfCancellationRequested();

        var clientId = parameters.ClientId ?? string.Empty;
        var scope = parameters.Scope ?? DefaultScope;

        // RSTS normalizes empty client_id to its built-in ApplicationClientId in
        // both the device-code cache (OAuthTokenManager.GetDeviceCode) and the
        // browser-completion path (LoginController.ProcessDeviceLogin). When the
        // user finishes via verification_uri_complete, RSTS never propagates a
        // non-empty cached client_id to the auth code; the JWT clientIdClaim is
        // baked as ApplicationClientId. Sending an empty client_id here makes
        // the polling-side comparison value also normalize to ApplicationClientId,
        // so both browser flows succeed end-to-end.

        // Step 1: Request device code (CRITICAL: no trailing slash on URL)
        Log.Debug("Requesting device authorization from {Appliance}", appliance);

        var deviceAuthUrl = $"https://{appliance}/RSTS/oauth2/DeviceLogin";
        var requestBody = JsonSerializer.Serialize(
            new DeviceAuthRequest { ClientId = clientId, Scope = scope },
            DeviceCodeJsonContext.Default.DeviceAuthRequest);

        (HttpStatusCode StatusCode, bool IsSuccess, string Body) deviceResult;
        try
        {
            deviceResult = await PostJsonAsync(httpClient, deviceAuthUrl, requestBody, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new SafeguardDotNetException(
                $"Device authorization request failed: unable to connect to {appliance} — {ex.Message}", ex);
        }

        if (!deviceResult.IsSuccess)
        {
            // Disabled-grant detection is reactive and happens before any JSON parse:
            // a disabled DeviceCode grant returns an HTML body, not JSON.
            if (!string.IsNullOrEmpty(deviceResult.Body)
                && deviceResult.Body.IndexOf(DeviceCodeGrantDisabledMarker, StringComparison.OrdinalIgnoreCase) >= 0)
            {
                throw new SafeguardDotNetException(
                    "Device authorization request failed: the Device Code grant type is not allowed on this appliance. "
                    + "Enable \"DeviceCode\" under Settings/Allowed OAuth2 Grant Types and try again.",
                    deviceResult.StatusCode,
                    deviceResult.Body);
            }

            throw new SafeguardDotNetException(
                $"Device authorization request failed: {deviceResult.StatusCode} {deviceResult.Body}",
                deviceResult.StatusCode,
                deviceResult.Body);
        }

        string deviceCode;
        int expiresIn;
        using (var deviceResponse = JsonDocument.Parse(deviceResult.Body))
        {
            var deviceRoot = deviceResponse.RootElement;
            deviceCode = deviceRoot.TryGetProperty("device_code", out var dcEl) ? dcEl.GetString() : null;
            var userCode = deviceRoot.TryGetProperty("user_code", out var ucEl) ? ucEl.GetString() : null;
            var verificationUri = deviceRoot.TryGetProperty("verification_uri", out var vuEl) ? vuEl.GetString() : null;
            var verificationUriComplete = deviceRoot.TryGetProperty("verification_uri_complete", out var vucEl) ? vucEl.GetString() : null;
            expiresIn = deviceRoot.TryGetProperty("expires_in", out var eiEl) && eiEl.TryGetInt32(out var eiVal) ? eiVal : 300;

            // Step 2: Display to user via callback (the library never owns console I/O)
            parameters.DisplayCallback(new DeviceCodeInfo
            {
                VerificationUri = verificationUri,
                UserCode = userCode,
                VerificationUriComplete = verificationUriComplete,
                ExpiresIn = expiresIn,
            });
        }

        // Step 3: Poll token endpoint
        Log.Debug("Polling token endpoint for device code redemption");

        var tokenUrl = $"https://{appliance}/RSTS/oauth2/token";
        var intervalSeconds = parameters.PollingIntervalSeconds > 0 ? parameters.PollingIntervalSeconds : 5;
        var deadline = clock.UtcNow.AddSeconds(expiresIn);

        while (clock.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();

            await clock.DelayAsync(TimeSpan.FromSeconds(intervalSeconds), cancellationToken).ConfigureAwait(false);

            var pollBody = JsonSerializer.Serialize(
                new DeviceTokenRequest
                {
                    GrantType = "urn:ietf:params:oauth:grant-type:device_code",
                    DeviceCode = deviceCode,
                    ClientId = clientId,
                },
                DeviceCodeJsonContext.Default.DeviceTokenRequest);

            var pollResult = await PostJsonAsync(httpClient, tokenUrl, pollBody, cancellationToken).ConfigureAwait(false);

            JsonDocument pollJson;
            try
            {
                pollJson = JsonDocument.Parse(pollResult.Body);
            }
            catch (JsonException)
            {
                throw new SafeguardDotNetException(
                    $"Device code token request returned an unexpected non-JSON response: {pollResult.StatusCode}",
                    pollResult.StatusCode,
                    pollResult.Body);
            }

            using (pollJson)
            {
                var pollRoot = pollJson.RootElement;

                if (pollResult.IsSuccess)
                {
                    var accessTokenValue = pollRoot.TryGetProperty("access_token", out var atEl) ? atEl.GetString() : null;
                    if (string.IsNullOrEmpty(accessTokenValue))
                    {
                        throw new SafeguardDotNetException(
                            "Device code token response did not contain an access_token.",
                            pollResult.StatusCode,
                            pollResult.Body);
                    }

                    return accessTokenValue.ToSecureString();
                }

                var error = pollRoot.TryGetProperty("error", out var errEl) ? errEl.GetString() : null;
                switch (error)
                {
                    case "authorization_pending":
                        break;
                    case "slow_down":
                        intervalSeconds += 5;
                        break;
                    case "access_denied":
                        throw new SafeguardDotNetException(
                            "Device code authentication was denied by the user.",
                            pollResult.StatusCode,
                            pollResult.Body);
                    case "expired_token":
                        throw new SafeguardDotNetException(
                            "Device code has expired before it was authorized. Please try again.",
                            pollResult.StatusCode,
                            pollResult.Body);
                    default:
                        throw new SafeguardDotNetException(
                            $"Unexpected error during device code polling: {error}",
                            pollResult.StatusCode,
                            pollResult.Body);
                }
            }
        }

        throw new SafeguardDotNetException("Device code expired before user authenticated.");
    }

    /// <summary>
    /// Posts a JSON body to an rSTS endpoint and returns the status and raw body.
    /// </summary>
    private static async Task<(HttpStatusCode StatusCode, bool IsSuccess, string Body)> PostJsonAsync(
        HttpClient httpClient,
        string url,
        string jsonBody,
        CancellationToken cancellationToken)
    {
        using var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        using var response = await httpClient.PostAsync(url, content, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        return (response.StatusCode, response.IsSuccessStatusCode, body);
    }
}
