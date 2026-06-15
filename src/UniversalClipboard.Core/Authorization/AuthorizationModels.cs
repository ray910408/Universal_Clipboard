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

[Flags]
public enum AuthorizationPermissions
{
    None = 0,
    Read = 1,
    Write = 2,
    ReadWrite = Read | Write,
}

public sealed record AuthorizationRecord(
    Guid Id,
    string Label,
    DateTimeOffset CreatedAtUtc,
    IPAddress BoundHostIpv4,
    DateTimeOffset? ExpiresAtUtc,
    string? DeviceName,
    string? BrowserName,
    DateTimeOffset? LastAccessedAtUtc,
    AuthorizationPermissions Permissions,
    ImmutableArray<byte> TokenDigest,
    ImmutableArray<byte> SessionProofDigest = default);

public sealed record AuthorizationDocument(
    ImmutableArray<AuthorizationRecord> Authorizations)
{
    public static AuthorizationDocument Empty { get; } =
        new(ImmutableArray<AuthorizationRecord>.Empty);
}

internal sealed record AuthorizationStateSnapshot(
    ImmutableArray<AuthorizationRecord> Authorizations);

public sealed record AuthorizationMetadata(
    Guid Id,
    string Label,
    DateTimeOffset CreatedAtUtc,
    IPAddress BoundHostIpv4,
    DateTimeOffset? ExpiresAtUtc,
    string? DeviceName,
    string? BrowserName,
    DateTimeOffset? LastAccessedAtUtc,
    AuthorizationPermissions Permissions)
{
    internal static AuthorizationMetadata FromRecord(AuthorizationRecord authorization) =>
        new(
            authorization.Id,
            authorization.Label,
            authorization.CreatedAtUtc,
            authorization.BoundHostIpv4,
            authorization.ExpiresAtUtc,
            authorization.DeviceName,
            authorization.BrowserName,
            authorization.LastAccessedAtUtc,
            authorization.Permissions);
}

public sealed record AuthorizationAdministrationSnapshot(
    ImmutableArray<AuthorizationMetadata> Authorizations);

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
    QueueFull,
    Disposed,
    PermissionDenied,
}

public sealed record ExchangeAuthorizationRequest(
    string PairingCode,
    string Label,
    IPAddress BoundHostIpv4,
    AuthorizationDuration Duration,
    string? DeviceName = null,
    string? BrowserName = null)
{
    public override string ToString() =>
        $"{nameof(ExchangeAuthorizationRequest)} {{ PairingCode = [REDACTED], " +
        $"Label = {Label}, BoundHostIpv4 = {BoundHostIpv4}, Duration = {Duration}, " +
        $"DeviceName = {DeviceName}, BrowserName = {BrowserName} }}";
}

public sealed class ExchangeAuthorizationResult
{
    private ExchangeAuthorizationResult(
        AuthorizationFailure failure,
        AuthorizationMetadata? authorization,
        SessionToken? token,
        string? sessionProof)
    {
        Failure = failure;
        Authorization = authorization;
        Token = token;
        SessionProof = sessionProof;
    }

    public bool Succeeded => Failure == AuthorizationFailure.None;

    public AuthorizationFailure Failure { get; }

    public AuthorizationMetadata? Authorization { get; }

    public SessionToken? Token { get; }

    public string? SessionProof { get; }

    internal static ExchangeAuthorizationResult Success(SessionTokenIssue issue) =>
        new(
            AuthorizationFailure.None,
            AuthorizationMetadata.FromRecord(issue.Authorization),
            issue.Token,
            issue.SessionProof);

    internal static ExchangeAuthorizationResult Failed(AuthorizationFailure failure) =>
        new(failure, null, null, null);

    public override string ToString() =>
        $"{nameof(ExchangeAuthorizationResult)} {{ Succeeded = {Succeeded}, Failure = {Failure}, " +
        $"AuthorizationId = {Authorization?.Id}, Token = {(Token is null ? "null" : "[REDACTED]")} }}";
}

public sealed record AcquireLeaseRequest(
    Guid AuthorizationId,
    SessionToken Token,
    IPAddress HostIpv4,
    string SessionProof = "",
    AuthorizationPermissions RequiredPermission = AuthorizationPermissions.Read);

public sealed class AcquireLeaseResult
{
    internal AcquireLeaseResult(
        AuthorizationFailure failure,
        AuthorizationLease? lease,
        AuthorizationMetadata? authorization = null)
    {
        Failure = failure;
        Lease = lease;
        Authorization = authorization;
    }

    public bool Succeeded => Failure == AuthorizationFailure.None;

    public AuthorizationFailure Failure { get; }

    public AuthorizationLease? Lease { get; }

    public AuthorizationMetadata? Authorization { get; }
}

public sealed class AuthorizationMutationResult
{
    internal AuthorizationMutationResult(
        AuthorizationFailure failure,
        AuthorizationAdministrationSnapshot snapshot)
    {
        Failure = failure;
        Snapshot = snapshot;
    }

    public bool Succeeded => Failure == AuthorizationFailure.None;

    public AuthorizationFailure Failure { get; }

    public AuthorizationAdministrationSnapshot Snapshot { get; }
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
    internal PairingCode(
        string value,
        DateTimeOffset expiresAtUtc,
        AuthorizationDuration duration,
        AuthorizationPermissions permissions)
    {
        Value = value;
        ExpiresAtUtc = expiresAtUtc;
        Duration = duration;
        Permissions = permissions;
    }

    public string Value { get; }

    public DateTimeOffset ExpiresAtUtc { get; }

    public AuthorizationDuration Duration { get; }

    public AuthorizationPermissions Permissions { get; }

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

    internal void CopyBytesTo(Span<byte> destination)
    {
        if (destination.Length < _bytes.Length)
        {
            throw new ArgumentException("Destination is too short.", nameof(destination));
        }

        _bytes.CopyTo(destination);
    }

    public override string ToString() => "[REDACTED]";
}

public sealed class SessionTokenIssue
{
    internal SessionTokenIssue(
        AuthorizationRecord authorization,
        SessionToken token,
        string sessionProof)
    {
        Authorization = authorization;
        Token = token;
        SessionProof = sessionProof;
    }

    public AuthorizationRecord Authorization { get; }

    public SessionToken Token { get; }

    public string SessionProof { get; }

    public override string ToString() =>
        $"{nameof(SessionTokenIssue)} {{ AuthorizationId = {Authorization.Id}, Token = [REDACTED], SessionProof = [REDACTED] }}";
}

internal static class Base64Url
{
    public static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
