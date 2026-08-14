// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Authentication;

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Security;
using System.Security;

using OneIdentity.SafeguardDotNet.Serialization;

internal class PasswordAuthenticator : AuthenticatorBase
{
    private bool _disposed;

    private readonly string _provider;
    private string _providerScope;
    private readonly string _username;
    private readonly SecureString _password;

    public PasswordAuthenticator(
        string networkAddress,
        string provider,
        string username,
        SecureString password,
        int apiVersion,
        bool ignoreSsl,
        RemoteCertificateValidationCallback validationCallback,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
        : base(networkAddress, apiVersion, ignoreSsl, validationCallback, null, minTlsVersion, maxTlsVersion)
    {
        _provider = provider;
        if (string.IsNullOrEmpty(_provider))
        {
            _providerScope = "rsts:sts:primaryproviderid:local";
        }

        _username = username;
        if (password == null)
        {
            throw new ArgumentException("Parameter may not be null", nameof(password));
        }

        _password = password.Copy();
    }

    public override string Id => "Password";

    protected override SecureString GetRstsTokenInternal()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException("PasswordAuthenticator");
        }

        if (_providerScope == null)
        {
            _providerScope = ResolveProviderToScope(_provider);
        }

        var data = SafeguardJson.Serialize(new Dictionary<string, string>
        {
            ["grant_type"] = "password",
            ["username"] = _username,
            ["password"] = _password.ToInsecureString(),
            ["scope"] = _providerScope,
        });

        var json = ApiRequest(HttpMethod.Post, $"https://{NetworkAddress}/RSTS/oauth2/token", data);

        using var doc = SafeguardJson.Parse(json);
        return doc.RootElement.GetProperty("access_token").GetString().ToSecureString();
    }

    public override object Clone()
    {
        var auth =
            new PasswordAuthenticator(NetworkAddress, _provider, _username, _password, ApiVersion, IgnoreSsl, ValidationCallback, MinTlsVersion, MaxTlsVersion)
            {
                accessToken = accessToken?.Copy(),
            };
        return auth;
    }

    protected override void Dispose(bool disposing)
    {
        if (_disposed || !disposing)
        {
            return;
        }

        try
        {
            base.Dispose(disposing);
            _password?.Dispose();
        }
        finally
        {
            _disposed = true;
        }
    }
}
