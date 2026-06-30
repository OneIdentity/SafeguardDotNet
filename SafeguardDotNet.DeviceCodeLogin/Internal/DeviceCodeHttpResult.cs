// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.DeviceCodeLogin.Internal;

using System.Net;

/// <summary>
/// Immutable result of an rSTS HTTP request captured by
/// <see cref="IDeviceCodeHttpTransport"/>. Carries the raw status and body so the
/// device-code flow can inspect responses without owning an <see cref="System.Net.Http.HttpClient"/>.
/// </summary>
internal sealed class DeviceCodeHttpResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="DeviceCodeHttpResult"/> class.
    /// </summary>
    /// <param name="statusCode">HTTP status code returned by rSTS.</param>
    /// <param name="isSuccessStatusCode">Whether the status code indicates success.</param>
    /// <param name="body">Raw response body.</param>
    public DeviceCodeHttpResult(
        HttpStatusCode statusCode,
        bool isSuccessStatusCode,
        string body)
    {
        StatusCode = statusCode;
        IsSuccessStatusCode = isSuccessStatusCode;
        Body = body;
    }

    /// <summary>Gets the HTTP status code returned by rSTS.</summary>
    public HttpStatusCode StatusCode { get; }

    /// <summary>Gets a value indicating whether the status code indicates success.</summary>
    public bool IsSuccessStatusCode { get; }

    /// <summary>Gets the raw response body.</summary>
    public string Body { get; }
}
