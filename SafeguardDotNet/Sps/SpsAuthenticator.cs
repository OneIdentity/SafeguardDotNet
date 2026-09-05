// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Sps;

using System;
using System.Net.Http.Headers;
using System.Security;
using System.Security.Authentication;
using System.Text;

internal class SpsAuthenticator : ISpsAuthenticator
{
    internal SpsAuthenticator(
        string networkAddress,
        string userName,
        SecureString password,
        bool ignoreSsl = false,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
    {
        NetworkAddress = networkAddress;
        UserName = userName;
        Password = password;
        IgnoreSsl = ignoreSsl;
        SslProtocols = TlsVersionMapper.ToSslProtocols(minTlsVersion, maxTlsVersion);
    }

    public string NetworkAddress { get; }

    public string UserName { get; }

    public SecureString Password { get; }

    public bool IgnoreSsl { get; }

    public SslProtocols SslProtocols { get; }

    public AuthenticationHeaderValue GetAuthenticationHeader() => new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes($"{UserName}:{Password.ToInsecureString()}")));
}
