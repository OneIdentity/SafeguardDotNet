// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet;

using System;
using System.Security.Authentication;

/// <summary>
/// Maps an optional minimum/maximum <see cref="SafeguardTlsVersion"/> range onto the
/// <see cref="SslProtocols"/> flags value that configures an <c>HttpClientHandler</c> or
/// SignalR connection. When neither bound is supplied the result is
/// <see cref="SslProtocols.None"/>, which lets the operating system negotiate the best
/// available protocol (including TLS 1.3 where supported).
/// </summary>
internal static class TlsVersionMapper
{
    // SslProtocols.Tls13 (0x3000) is not present in the netstandard2.0 reference assembly,
    // even though every runtime that supports TLS 1.3 defines it. Reference the numeric value
    // so the SDK compiles against netstandard2.0 while still enabling TLS 1.3 at run time.
    private const SslProtocols Tls13 = (SslProtocols)0x3000;

    // Lowest and highest TLS versions that Safeguard supports today. Used to backfill an
    // unspecified bound so that a single bound still produces a sensible range.
    private const SafeguardTlsVersion LowestSupported = SafeguardTlsVersion.Tls12;
    private const SafeguardTlsVersion HighestSupported = SafeguardTlsVersion.Tls13;

    /// <summary>
    /// Converts a minimum/maximum <see cref="SafeguardTlsVersion"/> pair into the matching
    /// <see cref="SslProtocols"/> flags.
    /// </summary>
    /// <param name="minTlsVersion">Lowest allowed TLS version, or null to leave it unconstrained.</param>
    /// <param name="maxTlsVersion">Highest allowed TLS version, or null to leave it unconstrained.</param>
    /// <returns>
    /// <see cref="SslProtocols.None"/> when both bounds are null (system-negotiated); otherwise the
    /// OR-combination of every supported TLS version that falls within the requested range.
    /// </returns>
    /// <exception cref="ArgumentException">Thrown when <paramref name="minTlsVersion"/> is newer than <paramref name="maxTlsVersion"/>.</exception>
    public static SslProtocols ToSslProtocols(SafeguardTlsVersion? minTlsVersion, SafeguardTlsVersion? maxTlsVersion)
    {
        if (minTlsVersion == null && maxTlsVersion == null)
        {
            return SslProtocols.None;
        }

        var lower = minTlsVersion ?? LowestSupported;
        var upper = maxTlsVersion ?? HighestSupported;

        if (lower > upper)
        {
            throw new ArgumentException($"minTlsVersion ({lower}) cannot be greater than maxTlsVersion ({upper}).", nameof(minTlsVersion));
        }

        var result = SslProtocols.None;
        for (var version = lower; version <= upper; version++)
        {
            result |= ToSingle(version);
        }

        return result;
    }

    private static SslProtocols ToSingle(SafeguardTlsVersion version)
    {
        switch (version)
        {
            case SafeguardTlsVersion.Tls12:
                return SslProtocols.Tls12;
            case SafeguardTlsVersion.Tls13:
                return Tls13;
            default:
                throw new ArgumentOutOfRangeException(nameof(version), version, "Unsupported TLS version.");
        }
    }
}
