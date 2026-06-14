using FluentAssertions;
using UniversalClipboard.App.Web;

namespace UniversalClipboard.App.Tests.Web;

public sealed class RequestRateLimiterTests
{
    [Fact]
    public void Pair_limit_is_exactly_five_per_source_and_twenty_per_process_per_minute()
    {
        var clock = new ManualTimeProvider(AuthorizationTestFactory.Now);
        var limiter = RequestRateLimiter.CreatePairing(clock);

        Enumerable.Range(0, 5)
            .Should().OnlyContain(_ => limiter.TryAcquire("source-a", out _));
        limiter.TryAcquire("source-a", out var sourceRetry).Should().BeFalse();
        sourceRetry.Should().Be(60);

        foreach (var source in Enumerable.Range(0, 15).Select(index => $"source-{index}"))
        {
            limiter.TryAcquire(source, out _).Should().BeTrue();
        }

        limiter.TryAcquire("source-final", out var processRetry).Should().BeFalse();
        processRetry.Should().Be(60);

        clock.Advance(TimeSpan.FromMinutes(1));
        limiter.TryAcquire("source-a", out _).Should().BeTrue();
    }

    [Fact]
    public void Clip_limit_is_exactly_two_per_authorization_per_second()
    {
        var clock = new ManualTimeProvider(AuthorizationTestFactory.Now);
        var limiter = RequestRateLimiter.CreateClips(clock);

        limiter.TryAcquire("authorization", out _).Should().BeTrue();
        limiter.TryAcquire("authorization", out _).Should().BeTrue();
        limiter.TryAcquire("authorization", out var retryAfter).Should().BeFalse();
        retryAfter.Should().Be(1);

        clock.Advance(TimeSpan.FromSeconds(1));
        limiter.TryAcquire("authorization", out _).Should().BeTrue();
    }

    [Fact]
    public void Expired_keys_are_pruned_instead_of_growing_for_process_lifetime()
    {
        var clock = new ManualTimeProvider(AuthorizationTestFactory.Now);
        var limiter = RequestRateLimiter.CreatePairing(clock);

        for (var index = 0; index < 100; index++)
        {
            limiter.TryAcquire($"source-{index}", out _).Should().BeTrue();
            clock.Advance(TimeSpan.FromMinutes(1));
        }

        limiter.TrackedKeyCount.Should().Be(1);
    }
}
