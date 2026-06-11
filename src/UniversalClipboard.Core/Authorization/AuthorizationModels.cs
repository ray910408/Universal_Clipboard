using System.Collections.Immutable;
using System.Net;

namespace UniversalClipboard.Core.Authorization;

public enum AuthorizationDuration
{
    OneHour,
    FiveHours,
    OneDay,
    OneWeek,
    Permanent,
}

public sealed record AuthorizationRecord(
    Guid Id,
    string Label,
    DateTimeOffset CreatedAtUtc,
    IPAddress BoundHostIpv4,
    DateTimeOffset? ExpiresAtUtc,
    ImmutableArray<byte> TokenDigest);

public sealed record AuthorizationDocument(
    ImmutableArray<AuthorizationRecord> Authorizations)
{
    public static AuthorizationDocument Empty { get; } =
        new(ImmutableArray<AuthorizationRecord>.Empty);
}

public sealed record AuthorizationSnapshot(
    ImmutableArray<AuthorizationRecord> Authorizations)
{
    public static AuthorizationSnapshot Empty { get; } =
        new(ImmutableArray<AuthorizationRecord>.Empty);
}

public enum AuthorizationFailure
{
    None,
    InvalidPairingCode,
    InvalidRequest,
    InvalidToken,
    Expired,
    BoundHostMismatch,
    NotFound,
    Revoking,
    PersistenceFailed,
    Canceled,
    Disposed,
}

public sealed record ExchangeAuthorizationRequest(
    string PairingCode,
    string Label,
    IPAddress BoundHostIpv4,
    AuthorizationDuration Duration);

public sealed class ExchangeAuthorizationResult
{
    private ExchangeAuthorizationResult(
        AuthorizationFailure failure,
        AuthorizationRecord? authorization,
        SessionToken? token)
    {
        Failure = failure;
        Authorization = authorization;
        Token = token;
    }

    public bool Succeeded => Failure == AuthorizationFailure.None;

    public AuthorizationFailure Failure { get; }

    public AuthorizationRecord? Authorization { get; }

    public SessionToken? Token { get; }

    internal static ExchangeAuthorizationResult Success(SessionTokenIssue issue) =>
        new(AuthorizationFailure.None, issue.Authorization, issue.Token);

    internal static ExchangeAuthorizationResult Failed(AuthorizationFailure failure) =>
        new(failure, null, null);

    public override string ToString() =>
        $"{nameof(ExchangeAuthorizationResult)} {{ Succeeded = {Succeeded}, Failure = {Failure}, " +
        $"AuthorizationId = {Authorization?.Id}, Token = {(Token is null ? "null" : "[REDACTED]")} }}";
}

public sealed record AcquireLeaseRequest(
    Guid AuthorizationId,
    SessionToken Token,
    IPAddress HostIpv4);

public sealed class AcquireLeaseResult
{
    internal AcquireLeaseResult(AuthorizationFailure failure, AuthorizationLease? lease)
    {
        Failure = failure;
        Lease = lease;
    }

    public bool Succeeded => Failure == AuthorizationFailure.None;

    public AuthorizationFailure Failure { get; }

    public AuthorizationLease? Lease { get; }
}

public sealed class AuthorizationMutationResult
{
    internal AuthorizationMutationResult(
        AuthorizationFailure failure,
        AuthorizationSnapshot snapshot)
    {
        Failure = failure;
        Snapshot = snapshot;
    }

    public bool Succeeded => Failure == AuthorizationFailure.None;

    public AuthorizationFailure Failure { get; }

    public AuthorizationSnapshot Snapshot { get; }
}

public sealed class AuthorizationLease : IDisposable
{
    internal AuthorizationLease(CancellationToken revocationToken, Action release)
    {
        RevocationToken = revocationToken;
        _release = release;
    }

    private Action? _release;

    public CancellationToken RevocationToken { get; }

    public void Dispose() => Interlocked.Exchange(ref _release, null)?.Invoke();
}

public sealed class PairingCode
{
    internal PairingCode(string value, DateTimeOffset expiresAtUtc)
    {
        Value = value;
        ExpiresAtUtc = expiresAtUtc;
    }

    public string Value { get; }

    public DateTimeOffset ExpiresAtUtc { get; }

    public override string ToString() => "[REDACTED]";
}

public sealed class SessionToken
{
    private readonly byte[] _bytes;

    private SessionToken(byte[] bytes)
    {
        _bytes = bytes;
        Value = Base64Url.Encode(bytes);
    }

    public string Value { get; }

    public ReadOnlyMemory<byte> Bytes => _bytes;

    public static SessionToken FromBytes(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != SessionTokenService.TokenByteCount)
        {
            throw new ArgumentException(
                $"Session tokens must contain {SessionTokenService.TokenByteCount} bytes.",
                nameof(bytes));
        }

        return new SessionToken(bytes.ToArray());
    }

    public static bool TryParse(string? value, out SessionToken? token)
    {
        token = null;
        if (value is null || value.Length != 43 ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '-' and not '_'))
        {
            return false;
        }

        var base64 = value.Replace('-', '+').Replace('_', '/') + "=";
        Span<byte> bytes = stackalloc byte[SessionTokenService.TokenByteCount];
        if (!Convert.TryFromBase64String(base64, bytes, out var bytesWritten) ||
            bytesWritten != bytes.Length ||
            Base64Url.Encode(bytes) != value)
        {
            return false;
        }

        token = FromBytes(bytes);
        return true;
    }

    public override string ToString() => "[REDACTED]";
}

public sealed class SessionTokenIssue
{
    internal SessionTokenIssue(AuthorizationRecord authorization, SessionToken token)
    {
        Authorization = authorization;
        Token = token;
    }

    public AuthorizationRecord Authorization { get; }

    public SessionToken Token { get; }

    public override string ToString() =>
        $"{nameof(SessionTokenIssue)} {{ AuthorizationId = {Authorization.Id}, Token = [REDACTED] }}";
}

internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
