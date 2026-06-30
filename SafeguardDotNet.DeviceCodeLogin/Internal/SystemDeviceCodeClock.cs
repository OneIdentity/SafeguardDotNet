// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.DeviceCodeLogin.Internal;

using System;
using System.Threading;
using System.Threading.Tasks;

/// <summary>
/// Production <see cref="IDeviceCodeClock"/> backed by the system clock and
/// <see cref="Task.Delay(TimeSpan, CancellationToken)"/>.
/// </summary>
internal sealed class SystemDeviceCodeClock : IDeviceCodeClock
{
    /// <inheritdoc />
    public DateTime UtcNow => DateTime.UtcNow;

    /// <inheritdoc />
    public Task DelayAsync(TimeSpan delay, CancellationToken cancellationToken)
    {
        return Task.Delay(delay, cancellationToken);
    }
}
