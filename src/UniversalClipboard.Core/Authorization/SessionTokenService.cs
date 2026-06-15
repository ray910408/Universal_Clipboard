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
        AuthorizationDuration duration,
        AuthorizationPermissions permissions = AuthorizationPermissions.Read,
        string? deviceName = null,
        string? browserName = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(label);
        ArgumentNullException.ThrowIfNull(boundHostIpv4);

        if (boundHostIpv4.AddressFamily != AddressFamily.InterNetwork)
        {
            throw new ArgumentException("Authorization bindings must use IPv4.", nameof(boundHostIpv4));
        }

        if (!IsValidPermissions(permissions))
        {
            throw new ArgumentException("Authorization permissions must include Read or Write.", nameof(permissions));
        }

        Span<byte> authorizationIdBytes = stackalloc byte[AuthorizationIdByteCount];
        _entropySource.Fill(authorizationIdBytes);

        Span<byte> tokenBytes = stackalloc byte[TokenByteCount];
        _entropySource.Fill(tokenBytes);
        Span<byte> proofBytes = stackalloc byte[TokenByteCount];
        _entropySource.Fill(proofBytes);

        var token = SessionToken.FromBytes(tokenBytes);
        var sessionProof = Base64Url.Encode(proofBytes);
        var createdAtUtc = _timeProvider.GetUtcNow().ToUniversalTime();
        var authorization = new AuthorizationRecord(
            new Guid(authorizationIdBytes),
            label,
            createdAtUtc,
            boundHostIpv4,
            GetExpiry(createdAtUtc, duration),
            deviceName,
            browserName,
            null,
            permissions,
            ImmutableArray.Create(SHA256.HashData(tokenBytes)),
            ImmutableArray.Create(SHA256.HashData(proofBytes)));

        return new SessionTokenIssue(authorization, token, sessionProof);
    }

    public bool VerifyToken(AuthorizationRecord authorization, SessionToken token)
    {
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(token);

        Span<byte> tokenBytes = stackalloc byte[TokenByteCount];
        token.CopyBytesTo(tokenBytes);
        Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(tokenBytes, digest);

        return authorization.TokenDigest.Length == digest.Length &&
            CryptographicOperations.FixedTimeEquals(authorization.TokenDigest.AsSpan(), digest);
    }

    public bool VerifySessionProof(AuthorizationRecord authorization, string sessionProof)
    {
        ArgumentNullException.ThrowIfNull(authorization);

        Span<byte> proofBytes = stackalloc byte[TokenByteCount];
        var base64 = sessionProof.Replace('-', '+').Replace('_', '/');
        base64 = base64.PadRight(base64.Length + (4 - base64.Length % 4) % 4, '=');
        if (!Convert.TryFromBase64String(base64, proofBytes, out var written) ||
            written != TokenByteCount)
        {
            return false;
        }

        Span<byte> digest = stackalloc byte[SHA256.HashSizeInBytes];
        SHA256.HashData(proofBytes, digest);

        return authorization.SessionProofDigest.Length == digest.Length &&
            CryptographicOperations.FixedTimeEquals(authorization.SessionProofDigest.AsSpan(), digest);
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

    internal static bool IsValidPermissions(AuthorizationPermissions permissions) =>
        permissions is not AuthorizationPermissions.None &&
        (permissions & ~AuthorizationPermissions.ReadWrite) == 0;
}
