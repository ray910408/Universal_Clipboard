using System.Net;
using System.Security.Cryptography;
using FluentAssertions;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.Core.Tests.Authorization;

public sealed class SessionTokenServiceTests
{
    public static TheoryData<AuthorizationDuration, TimeSpan?> Durations => new()
    {
        { AuthorizationDuration.OneHour, TimeSpan.FromHours(1) },
        { AuthorizationDuration.FiveHours, TimeSpan.FromHours(5) },
        { AuthorizationDuration.OneDay, TimeSpan.FromDays(1) },
        { AuthorizationDuration.OneWeek, TimeSpan.FromDays(7) },
        { AuthorizationDuration.Permanent, null },
    };

    [Theory]
    [MemberData(nameof(Durations))]
    public void Issue_creates_digest_only_record_with_expected_expiry(
        AuthorizationDuration duration,
        TimeSpan? expectedLifetime)
    {
        var now = new DateTimeOffset(2026, 6, 12, 8, 30, 0, TimeSpan.Zero);
        var entropy = new QueueEntropySource(
            Enumerable.Range(0, 16).Select(value => (byte)value).ToArray(),
            Enumerable.Range(16, 32).Select(value => (byte)value).ToArray(),
            Enumerable.Range(48, 32).Select(value => (byte)value).ToArray());
        var service = new SessionTokenService(new ManualTimeProvider(now), entropy);

        var issue = service.Issue("Office browser", IPAddress.Parse("192.168.1.20"), duration);

        issue.Authorization.Id.Should().Be(new Guid(Enumerable.Range(0, 16).Select(value => (byte)value).ToArray()));
        issue.Authorization.Label.Should().Be("Office browser");
        issue.Authorization.CreatedAtUtc.Should().Be(now);
        issue.Authorization.BoundHostIpv4.Should().Be(IPAddress.Parse("192.168.1.20"));
        issue.Authorization.ExpiresAtUtc.Should().Be(expectedLifetime is null ? null : now + expectedLifetime);
        issue.Authorization.DeviceName.Should().BeNull();
        issue.Authorization.BrowserName.Should().BeNull();
        issue.Authorization.LastAccessedAtUtc.Should().BeNull();
        issue.Authorization.Permissions.Should().Be(AuthorizationPermissions.Read);
        issue.Authorization.TokenDigest.Should().Equal(
            SHA256.HashData(Enumerable.Range(16, 32).Select(value => (byte)value).ToArray()));
        issue.Authorization.TokenDigest.Should().HaveCount(32);
        issue.Authorization.SessionProofDigest.Should().Equal(
            SHA256.HashData(Enumerable.Range(48, 32).Select(value => (byte)value).ToArray()));
        issue.Authorization.SessionProofDigest.Should().HaveCount(32);
        issue.SessionProof.Should().HaveLength(43);
        entropy.RequestedLengths.Should().Equal(16, 32, 32);
    }

    [Fact]
    public void Issue_preserves_explicit_read_write_permissions_and_metadata()
    {
        var now = new DateTimeOffset(2026, 6, 12, 8, 30, 0, TimeSpan.Zero);
        var service = new SessionTokenService(
            new ManualTimeProvider(now),
            new QueueEntropySource(new byte[16], new byte[32], new byte[32]));

        var issue = service.Issue(
            "Office browser",
            IPAddress.Parse("192.168.1.20"),
            AuthorizationDuration.OneHour,
            AuthorizationPermissions.ReadWrite,
            deviceName: "Kenneth's iPhone",
            browserName: "Safari");

        issue.Authorization.Permissions.Should().Be(AuthorizationPermissions.ReadWrite);
        issue.Authorization.DeviceName.Should().Be("Kenneth's iPhone");
        issue.Authorization.BrowserName.Should().Be("Safari");
        issue.Authorization.LastAccessedAtUtc.Should().BeNull();
        var metadata = new AuthorizationMetadata(
            issue.Authorization.Id,
            issue.Authorization.Label,
            issue.Authorization.CreatedAtUtc,
            issue.Authorization.BoundHostIpv4,
            issue.Authorization.ExpiresAtUtc,
            issue.Authorization.DeviceName,
            issue.Authorization.BrowserName,
            issue.Authorization.LastAccessedAtUtc,
            issue.Authorization.Permissions);
        metadata.Should().BeEquivalentTo(
            new AuthorizationMetadata(
                issue.Authorization.Id,
                "Office browser",
                now,
                IPAddress.Parse("192.168.1.20"),
                now.AddHours(1),
                "Kenneth's iPhone",
                "Safari",
                null,
                AuthorizationPermissions.ReadWrite));
    }

    [Fact]
    public void VerifyToken_accepts_exact_token_and_rejects_other_values()
    {
        var service = new SessionTokenService(
            new ManualTimeProvider(DateTimeOffset.UtcNow),
            new QueueEntropySource(new byte[16], Enumerable.Repeat((byte)7, 32).ToArray()));
        var issue = service.Issue("Browser", IPAddress.Loopback, AuthorizationDuration.OneHour);

        service.VerifyToken(issue.Authorization, issue.Token).Should().BeTrue();
        service.VerifyToken(
            issue.Authorization,
            SessionToken.FromBytes(Enumerable.Repeat((byte)8, 32).ToArray())).Should().BeFalse();
    }

    [Fact]
    public void Sensitive_token_is_not_revealed_by_ToString()
    {
        var bytes = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var token = SessionToken.FromBytes(bytes);
        var encoded = Convert.ToBase64String(bytes);

        token.ToString().Should().NotContain(encoded);
        token.ToString().Should().Be("[REDACTED]");
    }

    [Fact]
    public void Token_uses_256_bit_base64url_wire_format_and_round_trips()
    {
        var bytes = Enumerable.Range(0, 32).Select(value => (byte)value).ToArray();
        var token = SessionToken.FromBytes(bytes);

        var parsed = SessionToken.TryParse(token.Value, out var roundTripped);

        parsed.Should().BeTrue();
        token.Value.Should().HaveLength(43);
        token.Value.Should().NotContainAny("=", "+", "/");
        roundTripped!.Value.Should().Be(token.Value);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not/base64url")]
    [InlineData("AA")]
    public void Token_parse_rejects_invalid_wire_values(string value)
    {
        SessionToken.TryParse(value, out var token).Should().BeFalse();
        token.Should().BeNull();
    }

    [Fact]
    public void Issue_rejects_non_ipv4_binding()
    {
        var service = new SessionTokenService(
            new ManualTimeProvider(DateTimeOffset.UtcNow),
            new QueueEntropySource(new byte[16], new byte[32]));

        var act = () => service.Issue("Browser", IPAddress.IPv6Loopback, AuthorizationDuration.OneHour);

        act.Should().Throw<ArgumentException>();
    }

    [Fact]
    public void Session_token_public_surface_does_not_expose_raw_bytes()
    {
        typeof(SessionToken).GetProperty("Bytes").Should().BeNull();
        typeof(SessionToken).GetMethods()
            .Where(method => method.IsPublic && !method.IsSpecialName)
            .Select(method => method.ReturnType)
            .Should().NotContain(returnType =>
                returnType == typeof(byte[]) ||
                returnType == typeof(Memory<byte>) ||
                returnType == typeof(ReadOnlyMemory<byte>));
    }
}
