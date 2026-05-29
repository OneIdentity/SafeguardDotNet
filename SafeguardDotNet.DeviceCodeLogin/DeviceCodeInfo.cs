// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.DeviceCodeLogin;

/// <summary>
/// Contains the device authorization response information displayed to the user.
/// </summary>
public class DeviceCodeInfo
{
    /// <summary>The URI the user must visit to authenticate (for manual code entry).</summary>
    public string VerificationUri { get; set; }

    /// <summary>The code the user must enter at the verification URI. Format: XXX-XXX-XXX.</summary>
    public string UserCode { get; set; }

    /// <summary>
    /// Complete URI with the user code pre-filled. The user can simply click/open this
    /// URL without manually typing the code. Always provided by Safeguard RSTS.
    /// </summary>
    public string VerificationUriComplete { get; set; }

    /// <summary>Lifetime in seconds before the codes expire (always 300 from RSTS).</summary>
    public int ExpiresIn { get; set; }
}
