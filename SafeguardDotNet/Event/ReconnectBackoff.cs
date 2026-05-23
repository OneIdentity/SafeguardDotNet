// Copyright (c) One Identity LLC. All rights reserved.

namespace OneIdentity.SafeguardDotNet.Event;

using System;

/// <summary>
/// Exponential reconnect backoff with multiplicative ±25% jitter and a 60-second cap.
/// </summary>
/// <remarks>
/// <para>
/// This is the cross-SDK reference implementation for the Safeguard SDK family
/// (SafeguardDotNet, SafeguardJava, safeguard.js). The Safeguard security review
/// (work unit W6) requires that every persistent event listener cap its reconnect
/// frequency so that sustained appliance downtime or a network partition cannot
/// turn the SDK's reconnect loop into a resource-exhaustion vector against either
/// the calling process or the appliance.
/// </para>
/// <para>
/// Algorithm:
/// <code>
///   delay_n = min(60s, 2^n * 1s)              for n = 0, 1, 2, ...
///   actual_n = delay_n * (0.75 + 0.5 * rng()) // ±25% multiplicative jitter
/// </code>
/// where <c>rng()</c> returns a value in <c>[0.0, 1.0)</c>. The internal counter
/// <c>n</c> advances on every call to <see cref="GetNextDelay"/> and resets to
/// zero on <see cref="OnSuccess"/>. The cap takes effect at n = 6 (2^6 = 64 &gt; 60).
/// </para>
/// <para>
/// The jitter source is injectable so callers and unit tests can substitute a
/// deterministic function for the default <see cref="Random"/>-based source.
/// Values returned outside <c>[0.0, 1.0]</c> are clamped to that range so a
/// misbehaving RNG cannot produce negative or unbounded delays.
/// </para>
/// <para>
/// <b>Parity note for other SDKs:</b> the algorithm and constants
/// (start = 1s, factor = 2, max = 60s, jitter band = ±25%) are normative.
/// The injection seam (constructor-injected jitter source) and reset semantics
/// (counter zeroed on success, not on stop) are part of the contract.
/// </para>
/// </remarks>
internal sealed class ReconnectBackoff
{
    /// <summary>Initial delay before the first retry (n = 0), in seconds.</summary>
    public const double InitialDelaySeconds = 1.0;

    /// <summary>Maximum delay between retries, in seconds.</summary>
    public const double MaxDelaySeconds = 60.0;

    /// <summary>Half-width of the multiplicative jitter band (0.25 = ±25%).</summary>
    public const double JitterFraction = 0.25;

    private static readonly Random DefaultRandom = new Random();

    private readonly Func<double> _jitterSource;
    private readonly object _lock = new object();

    private int _attempt;

    /// <summary>
    /// Initializes a new instance of the <see cref="ReconnectBackoff"/> class
    /// using a shared thread-safe default jitter source.
    /// </summary>
    public ReconnectBackoff()
        : this(DefaultJitter)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ReconnectBackoff"/> class
    /// with an injected jitter source. Provided primarily for deterministic
    /// unit testing of the algorithm.
    /// </summary>
    /// <param name="jitterSource">
    /// A function returning a value in <c>[0.0, 1.0)</c>. Values outside that
    /// range are clamped. Must not be <c>null</c>.
    /// </param>
    public ReconnectBackoff(Func<double> jitterSource)
    {
        _jitterSource = jitterSource ?? throw new ArgumentNullException(nameof(jitterSource));
    }

    /// <summary>
    /// Computes the next delay and advances the internal attempt counter.
    /// </summary>
    /// <returns>A <see cref="TimeSpan"/> with the delay to wait before the next reconnect attempt.</returns>
    public TimeSpan GetNextDelay()
    {
        int currentAttempt;
        lock (_lock)
        {
            currentAttempt = _attempt;
            _attempt++;
        }

        var baseSeconds = ComputeBaseDelaySeconds(currentAttempt);
        var raw = _jitterSource();
        var clamped = ClampUnitInterval(raw);
        var jitterMultiplier = 1.0 - JitterFraction + (2.0 * JitterFraction * clamped);
        return TimeSpan.FromSeconds(baseSeconds * jitterMultiplier);
    }

    /// <summary>
    /// Resets the attempt counter so the next call to <see cref="GetNextDelay"/>
    /// returns an n = 0 (≈1 second) delay. Call this immediately after a
    /// successful reconnect.
    /// </summary>
    public void OnSuccess()
    {
        lock (_lock)
        {
            _attempt = 0;
        }
    }

    private static double ComputeBaseDelaySeconds(int attempt)
    {
        // 2^attempt * InitialDelaySeconds, capped at MaxDelaySeconds.
        // attempt is clamped at 30 to avoid double overflow even though the cap
        // engages long before that point.
        var safeAttempt = ClampAttempt(attempt);
        var doubled = InitialDelaySeconds * Math.Pow(2.0, safeAttempt);
        return doubled > MaxDelaySeconds ? MaxDelaySeconds : doubled;
    }

    private static int ClampAttempt(int attempt)
    {
        if (attempt < 0)
        {
            return 0;
        }

        if (attempt > 30)
        {
            return 30;
        }

        return attempt;
    }

    private static double ClampUnitInterval(double value)
    {
        if (value < 0.0)
        {
            return 0.0;
        }

        if (value > 1.0)
        {
            return 1.0;
        }

        return value;
    }

    private static double DefaultJitter()
    {
        // Random is not thread-safe in netstandard2.0. Synchronize on the
        // shared instance so concurrent reconnect loops can share one RNG.
        lock (DefaultRandom)
        {
            return DefaultRandom.NextDouble();
        }
    }
}
