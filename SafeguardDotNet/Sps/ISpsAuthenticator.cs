// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Sps;

using System.Net.Http.Headers;
using System.Security;
using System.Security.Authentication;

internal interface ISpsAuthenticator
{
    string NetworkAddress { get; }

    string UserName { get; }

    SecureString Password { get; }

    bool IgnoreSsl { get; }

    SslProtocols SslProtocols { get; }

    AuthenticationHeaderValue GetAuthenticationHeader();
}
