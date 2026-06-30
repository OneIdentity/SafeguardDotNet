// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.DeviceCodeLogin.Internal;

using System.Security;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Internal abstraction over the rSTS-to-Safeguard token exchange so the public
/// connect path can be unit tested without contacting an appliance.
/// </summary>
internal interface IRstsTokenExchanger
{
    /// <summary>
    /// Exchanges an rSTS access token for a Safeguard API connection.
    /// </summary>
    /// <param name="appliance">Network address of the Safeguard appliance.</param>
    /// <param name="rstsAccessToken">The rSTS access token to exchange. Caller retains ownership.</param>
    /// <param name="apiVersion">Target API version to use.</param>
    /// <param name="ignoreSsl">Ignore server certificate validation (dev only).</param>
    /// <param name="cancellationToken">Cancellation token to abort the exchange.</param>
    /// <returns>A reusable Safeguard API connection.</returns>
    Task<ISafeguardConnection> ExchangeAsync(
        string appliance,
        SecureString rstsAccessToken,
        int apiVersion,
        bool ignoreSsl,
        CancellationToken cancellationToken);
}
