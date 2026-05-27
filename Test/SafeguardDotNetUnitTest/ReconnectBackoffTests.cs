// Copyright (c) One Identity LLC. All rights reserved.

namespace SafeguardDotNetUnitTest;

using System;
using System.Collections.Generic;
using System.Linq;

using OneIdentity.SafeguardDotNet.Event;

public class ReconnectBackoffTests
{
    // Algorithm under test (see SafeguardDotNet/Event/ReconnectBackoff.cs):
    //   delay_n = min(60s, 2^n * 1s)       for n = 0, 1, 2, ...
    //   actual  = delay_n * (0.75 + 0.5 * rng())   ; ±25% multiplicative jitter
    //   OnSuccess() resets n back to 0.
    //
    // Tests inject a deterministic RNG so the jitter envelope is exercised at
    // its extremes (0.0 -> -25%, 1.0 -> +25%, 0.5 -> 0%) and intermediate
    // values are validated via uniform sampling.

    private static readonly (double Min, double Max)[] ExpectedBands =
    {
        (0.75,  1.25),   // n=0  base 1s
        (1.5,   2.5),    // n=1  base 2s
        (3.0,   5.0),    // n=2  base 4s
        (6.0,  10.0),    // n=3  base 8s
        (12.0, 20.0),    // n=4  base 16s
        (24.0, 40.0),    // n=5  base 32s
        (45.0, 75.0),    // n=6  base 60s (capped)
        (45.0, 75.0),    // n=7  base 60s (capped)
        (45.0, 75.0),    // n=8  base 60s (capped)
        (45.0, 75.0),    // n=9  base 60s (capped)
    };

    [Fact]
    public void Sequence_FollowsExponentialDoublingThenCapsAt60Seconds()
    {
        // No jitter (rng -> 0.5 keeps the base value).
        var backoff = new ReconnectBackoff(() => 0.5);

        var observed = Enumerable.Range(0, ExpectedBands.Length)
                                 .Select(_ => backoff.GetNextDelay().TotalSeconds)
                                 .ToArray();

        double[] expectedBase = { 1, 2, 4, 8, 16, 32, 60, 60, 60, 60 };
        Assert.Equal(expectedBase, observed);
    }

    [Fact]
    public void JitterLowerBound_IsMinus25Percent()
    {
        var backoff = new ReconnectBackoff(() => 0.0);

        var d0 = backoff.GetNextDelay().TotalSeconds;
        var d1 = backoff.GetNextDelay().TotalSeconds;
        var d6 = SkipTo(backoff, 4); // n=2..5
        var d6Final = backoff.GetNextDelay().TotalSeconds; // n=6 capped

        Assert.Equal(0.75, d0, 6);
        Assert.Equal(1.5, d1, 6);
        Assert.Equal(45.0, d6Final, 6);
        Assert.True(d6 > 0);
    }

    [Fact]
    public void JitterUpperBound_IsPlus25Percent()
    {
        var backoff = new ReconnectBackoff(() => 1.0);

        var d0 = backoff.GetNextDelay().TotalSeconds;
        var d1 = backoff.GetNextDelay().TotalSeconds;
        _ = SkipTo(backoff, 4); // burn n=2..5
        var d6 = backoff.GetNextDelay().TotalSeconds;
        var d7 = backoff.GetNextDelay().TotalSeconds;

        Assert.Equal(1.25, d0, 6);
        Assert.Equal(2.5, d1, 6);
        Assert.Equal(75.0, d6, 6);
        Assert.Equal(75.0, d7, 6);
    }

    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    [InlineData(4)]
    [InlineData(5)]
    [InlineData(6)]
    [InlineData(7)]
    [InlineData(8)]
    [InlineData(9)]
    public void RandomSamples_StayInsideExpectedBand(int n)
    {
        var rng = new Random(Seed: 0xBEEF + n);

        // For each attempt index n, hammer GetNextDelay 200 times from a fresh
        // backoff that has been advanced to n, and check every sample lands
        // inside the expected band.
        for (var i = 0; i < 200; i++)
        {
            var backoff = new ReconnectBackoff(() => rng.NextDouble());
            for (var k = 0; k < n; k++)
            {
                backoff.GetNextDelay();
            }

            var delay = backoff.GetNextDelay().TotalSeconds;
            var band = ExpectedBands[n];

            Assert.InRange(delay, band.Min, band.Max);
        }
    }

    [Fact]
    public void JitterDistribution_IsApproximatelyUniformInsideBand()
    {
        // Sample 1000 delays at attempt n=2 (base 4s, band 3..5s) and verify
        // each quartile of the band receives roughly its share of the samples.
        var rng = new Random(Seed: 12345);
        var counts = new int[4];

        for (var i = 0; i < 1000; i++)
        {
            var backoff = new ReconnectBackoff(() => rng.NextDouble());
            backoff.GetNextDelay(); // n=0
            backoff.GetNextDelay(); // n=1
            var d = backoff.GetNextDelay().TotalSeconds; // n=2

            var bucket = (int)Math.Min(3, Math.Floor((d - 3.0) / 0.5));
            counts[bucket]++;
        }

        // Each bucket should hold ~250 of the 1000 samples. Allow generous slack.
        foreach (var c in counts)
        {
            Assert.InRange(c, 150, 350);
        }
    }

    [Fact]
    public void OnSuccess_ResetsCounterToZero()
    {
        var backoff = new ReconnectBackoff(() => 0.5);

        // Advance to n=6 (capped).
        for (var i = 0; i < 6; i++)
        {
            backoff.GetNextDelay();
        }

        var capped = backoff.GetNextDelay().TotalSeconds;
        Assert.Equal(60.0, capped, 6);

        backoff.OnSuccess();

        var afterReset = backoff.GetNextDelay().TotalSeconds;
        Assert.Equal(1.0, afterReset, 6);
    }

    [Fact]
    public void Constructor_RejectsNullJitterSource()
    {
        Assert.Throws<ArgumentNullException>(() => new ReconnectBackoff(null!));
    }

    [Fact]
    public void DefaultConstructor_ProducesDelaysInsideFirstBand()
    {
        var backoff = new ReconnectBackoff();

        var d0 = backoff.GetNextDelay().TotalSeconds;
        var d1 = backoff.GetNextDelay().TotalSeconds;

        Assert.InRange(d0, 0.75, 1.25);
        Assert.InRange(d1, 1.5, 2.5);
    }

    [Fact]
    public void JitterSource_OutsideZeroOneIsClampedNotPropagated()
    {
        // A misbehaving RNG (>1 or <0) must not produce negative or unbounded delays.
        var backoff = new ReconnectBackoff(() => 5.0);
        var d = backoff.GetNextDelay().TotalSeconds;
        Assert.InRange(d, 0.75, 1.25);

        var backoff2 = new ReconnectBackoff(() => -3.0);
        var d2 = backoff2.GetNextDelay().TotalSeconds;
        Assert.InRange(d2, 0.75, 1.25);
    }

    private static double SkipTo(ReconnectBackoff backoff, int count)
    {
        double last = 0;
        for (var i = 0; i < count; i++)
        {
            last = backoff.GetNextDelay().TotalSeconds;
        }

        return last;
    }
}
