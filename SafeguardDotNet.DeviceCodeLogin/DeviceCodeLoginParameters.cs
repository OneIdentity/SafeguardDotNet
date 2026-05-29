// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.DeviceCodeLogin;

using System;

/// <summary>
/// Parameters for the Device Code authentication flow.
/// </summary>
public class DeviceCodeLoginParameters
{
    /// <summary>
    /// Callback invoked when the user must visit a URL and enter a code.
    /// The calling application is responsible for displaying this information
    /// to the user (e.g., Console.WriteLine, GUI dialog, etc.).
    /// This callback is required; passing null will throw ArgumentException.
    /// </summary>
    public Action<DeviceCodeInfo> DisplayCallback { get; set; }

    /// <summary>
    /// Optional identity provider scope. Format: "rsts:sts:primaryproviderid:{provider}".
    /// If not specified, defaults to "rsts:sts:primaryproviderid:local".
    /// Note: RSTS accepts but does not functionally use this value for device code flow.
    /// </summary>
    public string Scope { get; set; }

    /// <summary>
    /// OAuth2 client identifier for the device authorization request.
    /// Default: "SafeguardDotNet". Only change if the appliance has
    /// RelyingPartyApplications configured with a specific client_id.
    /// </summary>
    public string ClientId { get; set; } = "SafeguardDotNet";

    /// <summary>
    /// Polling interval in seconds between token requests. Default: 5 (RFC 8628 default).
    /// Will be automatically increased if the server returns "slow_down".
    /// </summary>
    public int PollingIntervalSeconds { get; set; } = 5;
}
