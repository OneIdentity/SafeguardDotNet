// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.DeviceCodeLogin.Internal;

using System;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Production <see cref="IDeviceCodeHttpTransport"/> that posts to rSTS using a
/// stateless <see cref="HttpClient"/> created by the SDK's login utilities.
/// </summary>
internal sealed class DeviceCodeHttpTransport : IDeviceCodeHttpTransport, IDisposable
{
    private readonly HttpClient _http;

    /// <summary>
    /// Initializes a new instance of the <see cref="DeviceCodeHttpTransport"/> class.
    /// </summary>
    /// <param name="ignoreSsl">Ignore server certificate validation (dev only).</param>
    public DeviceCodeHttpTransport(bool ignoreSsl)
    {
        _http = Safeguard.AgentBasedLoginUtils.CreateStatelessHttpClient(ignoreSsl);
    }

    /// <inheritdoc />
    public async Task<DeviceCodeHttpResult> PostJsonAsync(
        string url,
        string jsonBody,
        CancellationToken cancellationToken)
    {
        using var content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        using var response = await _http.PostAsync(url, content, cancellationToken).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        return new DeviceCodeHttpResult(response.StatusCode, response.IsSuccessStatusCode, body);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        _http.Dispose();
    }
}
