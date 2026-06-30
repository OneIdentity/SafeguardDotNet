// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.DeviceCodeLogin.Internal;

using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Internal abstraction over the HTTP transport used by the device-code flow so
/// deterministic unit tests can queue rSTS responses without a live appliance.
/// </summary>
internal interface IDeviceCodeHttpTransport
{
    /// <summary>
    /// Posts a JSON body to the given rSTS URL and returns the raw status and body.
    /// </summary>
    /// <param name="url">Absolute rSTS endpoint URL.</param>
    /// <param name="jsonBody">Serialized JSON request body.</param>
    /// <param name="cancellationToken">Cancellation token to abort the request.</param>
    /// <returns>The status code, success flag, and raw response body.</returns>
    Task<DeviceCodeHttpResult> PostJsonAsync(
        string url,
        string jsonBody,
        CancellationToken cancellationToken);
}
