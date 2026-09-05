// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Authentication;

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Security;
using System.Security;

using OneIdentity.SafeguardDotNet.Serialization;

internal class CertificateAuthenticator : AuthenticatorBase
{
    private readonly string _provider;

    public CertificateAuthenticator(
        string networkAddress,
        string certificateThumbprint,
        int apiVersion,
        bool ignoreSsl,
        RemoteCertificateValidationCallback validationCallback,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
        : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificateThumbprint), minTlsVersion, maxTlsVersion)
    {
    }

    public CertificateAuthenticator(
        string networkAddress,
        string certificatePath,
        SecureString certificatePassword,
        int apiVersion,
        bool ignoreSsl,
        RemoteCertificateValidationCallback validationCallback,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
        : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificatePath, certificatePassword), minTlsVersion, maxTlsVersion)
    {
    }

    public CertificateAuthenticator(
        string networkAddress,
        IEnumerable<byte> certificateData,
        SecureString certificatePassword,
        int apiVersion,
        bool ignoreSsl,
        RemoteCertificateValidationCallback validationCallback,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
        : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificateData, certificatePassword), minTlsVersion, maxTlsVersion)
    {
    }

    private CertificateAuthenticator(
        string networkAddress,
        CertificateContext clientCertificate,
        int apiVersion,
        bool ignoreSsl,
        RemoteCertificateValidationCallback validationCallback,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
        : base(networkAddress, apiVersion, ignoreSsl, validationCallback, clientCertificate.Clone(), minTlsVersion, maxTlsVersion)
    {
    }

    public CertificateAuthenticator(
        string networkAddress,
        string certificateThumbprint,
        int apiVersion,
        bool ignoreSsl,
        RemoteCertificateValidationCallback validationCallback,
        string provider,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
        : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificateThumbprint), minTlsVersion, maxTlsVersion)
    {
        _provider = provider;
    }

    public CertificateAuthenticator(
        string networkAddress,
        string certificatePath,
        SecureString certificatePassword,
        int apiVersion,
        bool ignoreSsl,
        RemoteCertificateValidationCallback validationCallback,
        string provider,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
        : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificatePath, certificatePassword), minTlsVersion, maxTlsVersion)
    {
        _provider = provider;
    }

    public CertificateAuthenticator(
        string networkAddress,
        IEnumerable<byte> certificateData,
        SecureString certificatePassword,
        int apiVersion,
        bool ignoreSsl,
        RemoteCertificateValidationCallback validationCallback,
        string provider,
        SafeguardTlsVersion? minTlsVersion = null,
        SafeguardTlsVersion? maxTlsVersion = null)
        : base(networkAddress, apiVersion, ignoreSsl, validationCallback, new CertificateContext(certificateData, certificatePassword), minTlsVersion, maxTlsVersion)
    {
        _provider = provider;
    }

    public override string Id => "Certificate";

    protected override SecureString GetRstsTokenInternal()
    {
        if (IsDisposed)
        {
            throw new ObjectDisposedException("CertificateAuthenticator");
        }

        var providerScope = "rsts:sts:primaryproviderid:certificate";

        if (!string.IsNullOrEmpty(_provider))
        {
            providerScope = ResolveProviderToScope(_provider);
        }

        var data = SafeguardJson.Serialize(new Dictionary<string, string>
        {
            ["grant_type"] = "client_credentials",
            ["scope"] = providerScope,
        });

        var json = ApiRequest(HttpMethod.Post, $"https://{NetworkAddress}/RSTS/oauth2/token", data);

        using var doc = SafeguardJson.Parse(json);
        return doc.RootElement.GetProperty("access_token").GetString().ToSecureString();
    }

    public override object Clone()
    {
        var auth = new CertificateAuthenticator(NetworkAddress, clientCertificate, ApiVersion, IgnoreSsl, ValidationCallback, MinTlsVersion, MaxTlsVersion)
        {
            accessToken = accessToken?.Copy(),
        };
        return auth;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            base.Dispose(disposing);
            clientCertificate?.Dispose();
        }
    }
}
