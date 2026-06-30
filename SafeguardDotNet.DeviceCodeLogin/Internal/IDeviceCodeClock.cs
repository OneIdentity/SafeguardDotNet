// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.DeviceCodeLogin.Internal;

using System;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Internal abstraction over the system clock and delay so unit tests can advance
/// virtual time and record requested polling delays without sleeping.
/// </summary>
internal interface IDeviceCodeClock
{
    /// <summary>Gets the current UTC time.</summary>
    DateTime UtcNow { get; }

    /// <summary>
    /// Waits for the requested delay, observing cancellation.
    /// </summary>
    /// <param name="delay">Amount of time to wait.</param>
    /// <param name="cancellationToken">Cancellation token to abort the wait.</param>
    /// <returns>A task that completes after the delay.</returns>
    Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken);
}
