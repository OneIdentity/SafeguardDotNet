// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetUnitTest;

using System;
using System.Security.Authentication;

using OneIdentity.SafeguardDotNet;

public class TlsVersionMapperTests
{
    // SslProtocols.Tls13 is not defined in the netstandard2.0 reference assembly the SDK
    // compiles against, so the expected value is expressed with the raw flag (0x3000).
    private const SslProtocols Tls13 = (SslProtocols)0x3000;

    [Fact]
    public void BothNull_NegotiatesSystemDefault()
    {
        Assert.Equal(SslProtocols.None, TlsVersionMapper.ToSslProtocols(null, null));
    }

    [Fact]
    public void MinTls13_PinsToTls13()
    {
        Assert.Equal(Tls13, TlsVersionMapper.ToSslProtocols(SafeguardTlsVersion.Tls13, null));
    }

    [Fact]
    public void MaxTls12_PinsToTls12()
    {
        Assert.Equal(SslProtocols.Tls12, TlsVersionMapper.ToSslProtocols(null, SafeguardTlsVersion.Tls12));
    }

    [Fact]
    public void MinTls12_AllowsTls12AndTls13()
    {
        Assert.Equal(SslProtocols.Tls12 | Tls13, TlsVersionMapper.ToSslProtocols(SafeguardTlsVersion.Tls12, null));
    }

    [Fact]
    public void EqualBounds_ProducesSingleVersion()
    {
        Assert.Equal(SslProtocols.Tls12, TlsVersionMapper.ToSslProtocols(SafeguardTlsVersion.Tls12, SafeguardTlsVersion.Tls12));
        Assert.Equal(Tls13, TlsVersionMapper.ToSslProtocols(SafeguardTlsVersion.Tls13, SafeguardTlsVersion.Tls13));
    }

    [Fact]
    public void FullRange_OrsAllSupportedVersions()
    {
        Assert.Equal(SslProtocols.Tls12 | Tls13, TlsVersionMapper.ToSslProtocols(SafeguardTlsVersion.Tls12, SafeguardTlsVersion.Tls13));
    }

    [Fact]
    public void MinGreaterThanMax_Throws()
    {
        Assert.Throws<ArgumentException>(
            () => TlsVersionMapper.ToSslProtocols(SafeguardTlsVersion.Tls13, SafeguardTlsVersion.Tls12));
    }
}
