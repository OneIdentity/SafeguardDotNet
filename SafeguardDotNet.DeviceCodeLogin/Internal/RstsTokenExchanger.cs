// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.DeviceCodeLogin.Internal;

using System.Security;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Production <see cref="IRstsTokenExchanger"/> that delegates to the SDK's
/// agent-based login utilities to exchange an rSTS token for a connection.
/// </summary>
internal sealed class RstsTokenExchanger : IRstsTokenExchanger
{
    /// <inheritdoc />
    public Task<ISafeguardConnection> ExchangeAsync(
        string appliance,
        SecureString rstsAccessToken,
        int apiVersion,
        bool ignoreSsl,
        CancellationToken cancellationToken)
    {
        return Safeguard.AgentBasedLoginUtils.ExchangeRstsTokenForConnectionAsync(
            appliance, rstsAccessToken, apiVersion, ignoreSsl, cancellationToken);
    }
}
