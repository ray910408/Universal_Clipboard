using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using Microsoft.Extensions.Logging;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.App.Tests.Web;

internal sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
{
    private DateTimeOffset _utcNow = utcNow;

    public override DateTimeOffset GetUtcNow() => _utcNow;

    public void Advance(TimeSpan duration) => _utcNow += duration;
}

internal sealed class IncrementingEntropySource : IEntropySource
{
    private byte _next = 1;

    public void Fill(Span<byte> destination)
    {
        for (var index = 0; index < destination.Length; index++)
        {
            destination[index] = _next++;
        }
    }
}

internal sealed class FakeAuthorizationPersistence : IAuthorizationPersistence
{
    private AuthorizationDocument _document;

    public FakeAuthorizationPersistence(AuthorizationDocument? document = null)
    {
        _document = document ?? AuthorizationDocument.Empty;
    }

    public Func<AuthorizationDocument, Task>? OnSaveAsync { get; set; }

    public AuthorizationDocument Document => _document;

    public Task<AuthorizationDocument> LoadAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(_document);

    public async Task SaveAsync(
        AuthorizationDocument document,
        CancellationToken cancellationToken = default)
    {
        if (OnSaveAsync is not null)
        {
            await OnSaveAsync(document);
        }

        _document = document;
    }
}

internal sealed class RecordingAuthorizationService(IAuthorizationService inner)
    : IAuthorizationService
{
    private readonly TaskCompletionSource<CancellationToken> _exchangeEntered =
        new(TaskCreationOptions.RunContinuationsAsynchronously);

    public Task<CancellationToken> ExchangeEntered => _exchangeEntered.Task;

    public ValueTask<ExchangeAuthorizationResult> ExchangeAsync(
        ExchangeAuthorizationRequest request,
        CancellationToken cancellationToken = default)
    {
        _exchangeEntered.TrySetResult(cancellationToken);
        return inner.ExchangeAsync(request, cancellationToken);
    }

    public AcquireLeaseResult AcquireLease(AcquireLeaseRequest request) =>
        inner.AcquireLease(request);
}

internal sealed class CapturingLoggerProvider : ILoggerProvider
{
    private readonly ConcurrentQueue<string> _messages = new();

    public IReadOnlyCollection<string> Messages => _messages.ToArray();

    public ILogger CreateLogger(string categoryName) => new Logger(_messages);

    public void Dispose()
    {
    }

    private sealed class Logger(ConcurrentQueue<string> messages) : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            messages.Enqueue(formatter(state, exception));
    }
}

internal static class AuthorizationTestFactory
{
    public static readonly DateTimeOffset Now =
        new(2026, 6, 12, 8, 30, 0, TimeSpan.Zero);

    public static async Task<(
        AuthorizationCoordinator Coordinator,
        PairingCodeManager PairingCodes)> CreateCoordinatorAsync(
        FakeAuthorizationPersistence persistence,
        ManualTimeProvider clock)
    {
        var entropy = new IncrementingEntropySource();
        var pairingCodes = new PairingCodeManager(clock, entropy);
        var coordinator = await AuthorizationCoordinator.CreateAsync(
            persistence,
            pairingCodes,
            new SessionTokenService(clock, entropy),
            clock);
        return (coordinator, pairingCodes);
    }

    public static AuthorizationRecord CreateRecord(
        Guid id,
        byte tokenByte,
        DateTimeOffset? expiresAtUtc = null,
        byte proofByte = 10)
    {
        var digest = System.Security.Cryptography.SHA256.HashData(
            Enumerable.Repeat(tokenByte, 32).ToArray());
        var proofDigest = System.Security.Cryptography.SHA256.HashData(
            Enumerable.Repeat(proofByte, 32).ToArray());
        return new AuthorizationRecord(
            id,
            "Existing browser",
            Now,
            IPAddress.Loopback,
            expiresAtUtc ?? Now.AddHours(5),
            ImmutableArray.Create(digest),
            ImmutableArray.Create(proofDigest));
    }

    public static string CreateProof(byte proofByte = 10) =>
        Convert.ToBase64String(Enumerable.Repeat(proofByte, 32).ToArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
