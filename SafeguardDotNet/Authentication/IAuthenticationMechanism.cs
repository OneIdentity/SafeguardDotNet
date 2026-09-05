// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Authentication;

using System;
using System.Net.Security;
using System.Security;
using System.Security.Authentication;

internal interface IAuthenticationMechanism : IDisposable, ICloneable
{
    string Id { get; }

    string NetworkAddress { get; }

    int ApiVersion { get; }

    bool IgnoreSsl { get; }

    RemoteCertificateValidationCallback ValidationCallback { get; }

    SslProtocols SslProtocols { get; }

    bool IsAnonymous { get; }

    bool HasAccessToken();

    void ClearAccessToken();

    SecureString GetAccessToken();

    int GetAccessTokenLifetimeRemaining();

    void RefreshAccessToken();

    string ResolveProviderToScope(string provider);
}
