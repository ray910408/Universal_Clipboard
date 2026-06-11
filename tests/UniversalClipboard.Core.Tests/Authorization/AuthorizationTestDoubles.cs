using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Security.Cryptography;
using FluentAssertions;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.Core.Tests.Authorization;

internal sealed class ManualTimeProvider(DateTimeOffset utcNow) : TimeProvider
{
    private DateTimeOffset _utcNow = utcNow;

    public override DateTimeOffset GetUtcNow() => _utcNow;

    public void Advance(TimeSpan duration) => _utcNow += duration;
}

internal sealed class QueueEntropySource(params byte[][] values) : IEntropySource
{
    private readonly Queue<byte[]> _values = new(values);
    private readonly List<int> _requestedLengths = [];

    public IReadOnlyList<int> RequestedLengths => _requestedLengths;

    public void Fill(Span<byte> destination)
    {
        _requestedLengths.Add(destination.Length);
        var value = _values.Dequeue();
        value.Length.Should().Be(destination.Length);
        value.CopyTo(destination);
    }
}

internal sealed class FakeAuthorizationPersistence : IAuthorizationPersistence
{
    private readonly AuthorizationDocument _loadedDocument;
    private readonly ConcurrentQueue<AuthorizationDocument> _saveAttempts = new();

    public FakeAuthorizationPersistence(AuthorizationDocument? loadedDocument = null)
    {
        _loadedDocument = loadedDocument ?? AuthorizationDocument.Empty;
    }

    public Func<AuthorizationDocument, CancellationToken, Task>? OnSaveAsync { get; init; }

    public IReadOnlyCollection<AuthorizationDocument> SaveAttempts => _saveAttempts.ToArray();

    public AuthorizationDocument? SavedDocument { get; private set; }

    public Task<AuthorizationDocument> LoadAsync(CancellationToken cancellationToken = default) =>
        Task.FromResult(_loadedDocument);

    public async Task SaveAsync(
        AuthorizationDocument document,
        CancellationToken cancellationToken = default)
    {
        _saveAttempts.Enqueue(document);

        if (OnSaveAsync is not null)
        {
            await OnSaveAsync(document, cancellationToken);
        }

        SavedDocument = document;
    }
}

internal static class AuthorizationRecordFactory
{
    public static readonly DateTimeOffset Now =
        new(2026, 6, 12, 8, 30, 0, TimeSpan.Zero);

    public static AuthorizationRecord Create(
        Guid? id = null,
        string label = "Existing browser",
        IPAddress? boundHostIpv4 = null,
        DateTimeOffset? expiresAtUtc = null,
        byte tokenByte = 9)
    {
        var tokenBytes = Enumerable.Repeat(tokenByte, SessionTokenService.TokenByteCount).ToArray();
        return new AuthorizationRecord(
            id ?? Guid.NewGuid(),
            label,
            Now,
            boundHostIpv4 ?? IPAddress.Loopback,
            expiresAtUtc ?? Now.AddHours(5),
            ImmutableArray.Create(SHA256.HashData(tokenBytes)));
    }
}
