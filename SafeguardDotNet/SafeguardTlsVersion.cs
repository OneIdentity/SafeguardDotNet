// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet;

/// <summary>
/// Identifies a TLS protocol version that can be used to constrain the TLS handshake with a
/// Safeguard appliance. The values are ordered so that a larger value represents a newer
/// protocol version, which allows them to be used as the lower and upper bounds of an allowed
/// TLS version range. Safeguard requires TLS 1.2 or later, so only 1.2 and 1.3 are represented.
/// </summary>
public enum SafeguardTlsVersion
{
    /// <summary>
    /// TLS 1.2.
    /// </summary>
    Tls12 = 0,

    /// <summary>
    /// TLS 1.3.
    /// </summary>
    Tls13 = 1,
}
