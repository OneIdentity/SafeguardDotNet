// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.DeviceCodeLogin;

using System;
using System.Net.Http;
using System.Security;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Serilog;

/// <summary>
/// Provides device code-based authentication to Safeguard using OAuth 2.0
/// Device Authorization Grant (RFC 8628).
/// </summary>
public static class DeviceCodeLogin
{
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
        if (string.IsNullOrEmpty(appliance))
        {
            throw new ArgumentException("Appliance network address is required.", nameof(appliance));
        }

        if (parameters?.DisplayCallback == null)
        {
            throw new ArgumentException("DisplayCallback is required.", nameof(parameters));
        }

        var clientId = parameters.ClientId ?? string.Empty;
        var scope = parameters.Scope ?? "rsts:sts:primaryproviderid:local";

        // RSTS normalizes empty client_id to its built-in ApplicationClientId in
        // both the device-code cache (OAuthTokenManager.GetDeviceCode) and the
        // browser-completion path (LoginController.ProcessDeviceLogin). When the
        // user finishes via verification_uri_complete, RSTS never propagates a
        // non-empty cached client_id to the auth code; the JWT clientIdClaim is
        // baked as ApplicationClientId. Sending an empty client_id here makes
        // the polling-side comparison value also normalize to ApplicationClientId,
        // so both browser flows succeed end-to-end.
        using var http = Safeguard.AgentBasedLoginUtils.CreateStatelessHttpClient(ignoreSsl);

        // Step 1: Request device code (CRITICAL: no trailing slash on URL)
        Log.Debug("Requesting device authorization from {Appliance}", appliance);

        var deviceAuthUrl = $"https://{appliance}/RSTS/oauth2/DeviceLogin";
        var requestBody = JsonConvert.SerializeObject(new { client_id = clientId, scope });
        var content = new StringContent(requestBody, Encoding.UTF8, "application/json");

        HttpResponseMessage response;
        try
        {
            response = await http.PostAsync(deviceAuthUrl, content, cancellationToken).ConfigureAwait(false);
        }
        catch (HttpRequestException ex)
        {
            throw new SafeguardDotNetException(
                $"Device authorization request failed: unable to connect to {appliance} — {ex.Message}", ex);
        }

        var responseBody = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        if (!response.IsSuccessStatusCode)
        {
            throw new SafeguardDotNetException(
                $"Device authorization request failed: {response.StatusCode} {responseBody}",
                response.StatusCode,
                responseBody);
        }

        var deviceResponse = JObject.Parse(responseBody);
        var deviceCode = deviceResponse["device_code"]?.ToString();
        var userCode = deviceResponse["user_code"]?.ToString();
        var verificationUri = deviceResponse["verification_uri"]?.ToString();
        var verificationUriComplete = deviceResponse["verification_uri_complete"]?.ToString();
        var expiresIn = deviceResponse["expires_in"]?.Value<int>() ?? 300;

        // Step 2: Display to user via callback
        parameters.DisplayCallback(new DeviceCodeInfo
        {
            VerificationUri = verificationUri,
            UserCode = userCode,
            VerificationUriComplete = verificationUriComplete,
            ExpiresIn = expiresIn,
        });

        // Step 3: Poll token endpoint
        Log.Debug("Polling token endpoint for device code redemption");

        var tokenUrl = $"https://{appliance}/RSTS/oauth2/token";
        var intervalSeconds = parameters.PollingIntervalSeconds > 0 ? parameters.PollingIntervalSeconds : 5;
        var deadline = DateTime.UtcNow.AddSeconds(expiresIn);
        SecureString rstsAccessToken = null;

        while (DateTime.UtcNow < deadline)
        {
            cancellationToken.ThrowIfCancellationRequested();

            await Task.Delay(TimeSpan.FromSeconds(intervalSeconds), cancellationToken).ConfigureAwait(false);

            var pollBody = JsonConvert.SerializeObject(new
            {
                grant_type = "urn:ietf:params:oauth:grant-type:device_code",
                device_code = deviceCode,
                client_id = clientId,
            });
            var pollContent = new StringContent(pollBody, Encoding.UTF8, "application/json");
            var pollResponse = await http.PostAsync(tokenUrl, pollContent, cancellationToken).ConfigureAwait(false);
            var pollResponseBody = await pollResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
            var pollJson = JObject.Parse(pollResponseBody);

            if (pollResponse.IsSuccessStatusCode)
            {
                rstsAccessToken = pollJson["access_token"]?.ToString().ToSecureString();
                break;
            }

            var error = pollJson["error"]?.ToString();
            switch (error)
            {
                case "authorization_pending":
                    continue;
                case "slow_down":
                    intervalSeconds += 5;
                    continue;
                case "access_denied":
                    throw new SafeguardDotNetException(
                        "Device code authentication was denied.",
                        pollResponse.StatusCode,
                        pollResponseBody);
                case "expired_token":
                    throw new SafeguardDotNetException(
                        "Device code has expired. Please try again.",
                        pollResponse.StatusCode,
                        pollResponseBody);
                default:
                    throw new SafeguardDotNetException(
                        $"Unexpected error during device code polling: {error}",
                        pollResponse.StatusCode,
                        pollResponseBody);
            }
        }

        if (rstsAccessToken == null)
        {
            throw new SafeguardDotNetException("Device code expired before user authenticated.");
        }

        // Step 4: Exchange RSTS token for Safeguard UserToken
        Log.Debug("Exchanging RSTS access token for Safeguard user token");

        using (rstsAccessToken)
        {
            return await Safeguard.AgentBasedLoginUtils.ExchangeRstsTokenForConnectionAsync(
                appliance, rstsAccessToken, apiVersion, ignoreSsl, cancellationToken)
                .ConfigureAwait(false);
        }
    }
}
