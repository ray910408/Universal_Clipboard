using System.Collections.Concurrent;
using FluentAssertions;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.Core.Tests.Authorization;

public sealed class PairingCodeManagerTests
{
    [Fact]
    public void Create_uses_192_bits_and_base64url_without_padding()
    {
        var entropy = new QueueEntropySource(Enumerable.Range(0, 24).Select(value => (byte)value).ToArray());
        var clock = new ManualTimeProvider(new DateTimeOffset(2026, 6, 12, 0, 0, 0, TimeSpan.Zero));
        var manager = new PairingCodeManager(clock, entropy);

        var pairingCode = manager.Create();

        pairingCode.Value.Should().Be("AAECAwQFBgcICQoLDA0ODxAREhMUFRYX");
        pairingCode.Value.Should().NotContain("=");
        pairingCode.ExpiresAtUtc.Should().Be(clock.GetUtcNow().AddMinutes(2));
        entropy.RequestedLengths.Should().Equal(24);
    }

    [Fact]
    public void Creating_new_code_invalidates_previous_code()
    {
        var manager = new PairingCodeManager(
            new ManualTimeProvider(DateTimeOffset.UtcNow),
            new QueueEntropySource(new byte[24], Enumerable.Repeat((byte)1, 24).ToArray()));

        var first = manager.Create();
        var second = manager.Create();

        manager.TryConsume(first.Value).Should().BeFalse();
        manager.TryConsume(second.Value).Should().BeTrue();
    }

    [Fact]
    public void Code_expires_at_two_minute_boundary()
    {
        var clock = new ManualTimeProvider(DateTimeOffset.UtcNow);
        var manager = new PairingCodeManager(clock, new QueueEntropySource(new byte[24]));
        var code = manager.Create();

        clock.Advance(TimeSpan.FromMinutes(2));

        manager.TryConsume(code.Value).Should().BeFalse();
    }

    [Fact]
    public async Task Concurrent_consumers_have_exactly_one_winner()
    {
        var manager = new PairingCodeManager(
            new ManualTimeProvider(DateTimeOffset.UtcNow),
            new QueueEntropySource(new byte[24]));
        var code = manager.Create();
        var results = new ConcurrentBag<bool>();
        using var start = new ManualResetEventSlim();

        var consumers = Enumerable.Range(0, 32).Select(_ => Task.Run(() =>
        {
            start.Wait();
            results.Add(manager.TryConsume(code.Value));
        })).ToArray();

        start.Set();
        await Task.WhenAll(consumers);

        results.Count(result => result).Should().Be(1);
    }
}
