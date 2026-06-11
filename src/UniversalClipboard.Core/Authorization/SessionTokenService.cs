using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace UniversalClipboard.Core.Authorization;

public sealed class SessionTokenService
{
    public const int AuthorizationIdByteCount = 16;
    public const int TokenByteCount = 32;

    private readonly TimeProvider _timeProvider;
    private readonly IEntropySource _entropySource;

    public SessionTokenService(
        TimeProvider? timeProvider = null,
        IEntropySource? entropySource = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _entropySource = entropySource ?? CryptographicEntropySource.Shared;
    }

    public SessionTokenIssue Issue(
        string label,
        IPAddress boundHostIpv4,
        AuthorizationDuration duration)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(label);
        ArgumentNullException.ThrowIfNull(boundHostIpv4);

        if (boundHostIpv4.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("Authorization bindings must use IPv4.", nameof(boundHostIpv4));
        }

        Span<byte> authorizationIdBytes = stackalloc byte[AuthorizationIdByteCount];
        _entropySource.Fill(authorizationIdBytes);

        Span<byte> tokenBytes = stackalloc byte[TokenByteCount];
        _entropySource.Fill(tokenBytes);

        var token = SessionToken.FromBytes(tokenBytes);
        var createdAtUtc = _timeProvider.GetUtcNow().ToUniversalTime();
        var authorization = new AuthorizationRecord(
            new Guid(authorizationIdBytes),
            label,
            createdAtUtc,
            boundHostIpv4,
            GetExpiry(createdAtUtc, duration),
            ImmutableArray.Create(SHA256.HashData(tokenBytes)));

        return new SessionTokenIssue(authorization, token);
    }

    public bool VerifyToken(AuthorizationRecord authorization, SessionToken token)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(token);

        Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(token.Bytes.Span, digest);

        return authorization.TokenDigest.Length == digest.Length &&
            CryptographicOperations.FixedTimeEquals(authorization.TokenDigest.AsSpan(), digest);
    }

    private static DateTimeOffset? GetExpiry(
        DateTimeOffset createdAtUtc,
        AuthorizationDuration duration) =>
        duration switch
        {
            AuthorizationDuration.OneHour => createdAtUtc.AddHours(1),
            AuthorizationDuration.FiveHours => createdAtUtc.AddHours(5),
            AuthorizationDuration.OneDay => createdAtUtc.AddDays(1),
            AuthorizationDuration.OneWeek => createdAtUtc.AddDays(7),
            AuthorizationDuration.Permanent => null,
            _ => throw new ArgumentOutOfRangeException(nameof(duration)),
        };
}
