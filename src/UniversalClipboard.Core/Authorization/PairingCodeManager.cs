using System.Security.Cryptography;

namespace UniversalClipboard.Core.Authorization;

public interface IEntropySource
{
    void Fill(Span<byte> destination);
}

public sealed class CryptographicEntropySource : IEntropySource
{
    public static CryptographicEntropySource Shared { get; } = new();

    private CryptographicEntropySource()
    {
    }

    public void Fill(Span<byte> destination) => RandomNumberGenerator.Fill(destination);
}

public sealed class PairingCodeManager
{
    public const int EntropyByteCount = 24;
    public static readonly TimeSpan Lifetime = TimeSpan.FromMinutes(2);

    private readonly object _gate = new();
    private readonly TimeProvider _timeProvider;
    private readonly IEntropySource _entropySource;
    private ActivePairingCode? _activeCode;

    public PairingCodeManager(
        TimeProvider? timeProvider = null,
        IEntropySource? entropySource = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _entropySource = entropySource ?? CryptographicEntropySource.Shared;
    }

    public PairingCode Create() => Create(AuthorizationDuration.FiveHours);

    public PairingCode Create(
        AuthorizationDuration duration,
        AuthorizationPermissions permissions = AuthorizationPermissions.Read)
    {
        if (!Enum.IsDefined(duration))
        {
            throw new ArgumentOutOfRangeException(nameof(duration));
        }

        if (!SessionTokenService.IsValidPermissions(permissions))
        {
            throw new ArgumentOutOfRangeException(nameof(permissions));
        }

        Span<byte> bytes = stackalloc byte[EntropyByteCount];
        _entropySource.Fill(bytes);

        var value = Base64Url.Encode(bytes);
        var expiresAtUtc = _timeProvider.GetUtcNow().ToUniversalTime() + Lifetime;

        lock (_gate)
        {
            _activeCode = new ActivePairingCode(value, expiresAtUtc, duration, permissions);
        }

        return new PairingCode(value, expiresAtUtc, duration, permissions);
    }

    public void Invalidate()
    {
        lock (_gate)
        {
            _activeCode = null;
        }
    }

    public bool TryConsume(string? value) => TryConsume(value, out _);

    public bool TryConsume(
        string? value,
        out AuthorizationDuration duration) =>
        TryConsume(value, out duration, out _);

    public bool TryConsume(
        string? value,
        out AuthorizationDuration duration,
        out AuthorizationPermissions permissions)
    {
        duration = default;
        permissions = default;
        if (string.IsNullOrEmpty(value))
        {
            return false;
        }

        lock (_gate)
        {
            var activeCode = _activeCode;
            if (activeCode is null)
            {
                return false;
            }

            if (_timeProvider.GetUtcNow() >= activeCode.ExpiresAtUtc ||
                !FixedTimeEquals(value, activeCode.Value))
            {
                return false;
            }

            _activeCode = null;
            duration = activeCode.Duration;
            permissions = activeCode.Permissions;
            return true;
        }
    }

    private static bool FixedTimeEquals(string left, string right)
    {
        var leftBytes = System.Text.Encoding.UTF8.GetBytes(left);
        var rightBytes = System.Text.Encoding.UTF8.GetBytes(right);
        return CryptographicOperations.FixedTimeEquals(leftBytes, rightBytes);
    }

    private sealed record ActivePairingCode(
        string Value,
        DateTimeOffset ExpiresAtUtc,
        AuthorizationDuration Duration,
        AuthorizationPermissions Permissions);
}
