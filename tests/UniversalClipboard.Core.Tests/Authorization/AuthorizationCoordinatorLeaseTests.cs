using System.Net;
using FluentAssertions;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.Core.Tests.Authorization;

public sealed class AuthorizationCoordinatorLeaseTests
{
    [Fact]
    public async Task AcquireLease_validates_token_expiry_and_bound_ipv4()
    {
        var clock = new ManualTimeProvider(AuthorizationRecordFactory.Now);
        var validToken = SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray());
        var record = AuthorizationRecordFactory.Create(
            boundHostIpv4: IPAddress.Parse("192.168.1.20"));
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]));
        await using var coordinator = await CreateCoordinatorAsync(persistence, clock);

        var valid = coordinator.AcquireLease(
            new AcquireLeaseRequest(record.Id, validToken, IPAddress.Parse("192.168.1.20")));
        var wrongToken = coordinator.AcquireLease(
            new AcquireLeaseRequest(
                record.Id,
                SessionToken.FromBytes(new byte[32]),
                IPAddress.Parse("192.168.1.20")));
        var wrongHost = coordinator.AcquireLease(
            new AcquireLeaseRequest(record.Id, validToken, IPAddress.Parse("192.168.1.21")));

        valid.Succeeded.Should().BeTrue();
        wrongToken.Failure.Should().Be(AuthorizationFailure.InvalidToken);
        wrongHost.Failure.Should().Be(AuthorizationFailure.BoundHostMismatch);
        valid.Lease!.Dispose();

        clock.Advance(TimeSpan.FromHours(6));
        var expired = coordinator.AcquireLease(
            new AcquireLeaseRequest(record.Id, validToken, IPAddress.Parse("192.168.1.20")));

        expired.Failure.Should().Be(AuthorizationFailure.Expired);
        await WaitUntilAsync(() => persistence.SaveAttempts.Count == 1);
        coordinator.List().Should().BeEmpty();
    }

    [Fact]
    public async Task Persisted_token_can_acquire_after_forced_restart()
    {
        var token = SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray());
        var record = AuthorizationRecordFactory.Create() with { ExpiresAtUtc = null };
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]));

        await using var restarted = await CreateCoordinatorAsync(
            persistence,
            new ManualTimeProvider(AuthorizationRecordFactory.Now.AddDays(30)));

        using var lease = restarted.AcquireLease(
            new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback)).Lease;

        lease.Should().NotBeNull();
    }

    [Fact]
    public async Task Revoke_blocks_new_leases_cancels_and_drains_existing_before_save()
    {
        var saveStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSave = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var token = SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray());
        var record = AuthorizationRecordFactory.Create();
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]))
        {
            OnSaveAsync = async (_, _) =>
            {
                saveStarted.SetResult();
                await releaseSave.Task;
            },
        };
        await using var coordinator = await CreateCoordinatorAsync(persistence);
        var lease = coordinator.AcquireLease(
            new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback)).Lease!;

        var revokeTask = coordinator.RevokeAsync(record.Id).AsTask();
        await WaitUntilAsync(() => lease.RevocationToken.IsCancellationRequested);

        coordinator.AcquireLease(
                new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback))
            .Failure.Should().Be(AuthorizationFailure.Revoking);
        persistence.SaveAttempts.Should().BeEmpty();
        revokeTask.IsCompleted.Should().BeFalse();

        lease.Dispose();
        await saveStarted.Task;

        coordinator.List().Should().Equal(AuthorizationRecordFactory.Metadata(record));
        revokeTask.IsCompleted.Should().BeFalse();

        releaseSave.SetResult();
        var result = await revokeTask;

        result.Succeeded.Should().BeTrue();
        coordinator.List().Should().BeEmpty();
    }

    [Fact]
    public async Task Failed_revoke_restores_old_state_only_after_leases_are_drained()
    {
        var token = SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray());
        var record = AuthorizationRecordFactory.Create();
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]))
        {
            OnSaveAsync = (_, _) => throw new InvalidOperationException("simulated failure"),
        };
        await using var coordinator = await CreateCoordinatorAsync(persistence);
        var lease = coordinator.AcquireLease(
            new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback)).Lease!;

        var revokeTask = coordinator.RevokeAsync(record.Id).AsTask();
        await WaitUntilAsync(() => lease.RevocationToken.IsCancellationRequested);

        coordinator.AcquireLease(
                new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback))
            .Failure.Should().Be(AuthorizationFailure.Revoking);
        revokeTask.IsCompleted.Should().BeFalse();

        lease.Dispose();
        var result = await revokeTask;

        result.Failure.Should().Be(AuthorizationFailure.PersistenceFailed);
        coordinator.List().Should().Equal(AuthorizationRecordFactory.Metadata(record));
        using var restoredLease = coordinator.AcquireLease(
            new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback)).Lease;
        restoredLease.Should().NotBeNull();
    }

    [Fact]
    public async Task RevokeAll_removes_every_authorization_durably()
    {
        var records = new[]
        {
            AuthorizationRecordFactory.Create(tokenByte: 1),
            AuthorizationRecordFactory.Create(tokenByte: 2),
        };
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([.. records]));
        await using var coordinator = await CreateCoordinatorAsync(persistence);

        var result = await coordinator.RevokeAllAsync();

        result.Succeeded.Should().BeTrue();
        result.Snapshot.Authorizations.Should().BeEmpty();
        persistence.SavedDocument!.Authorizations.Should().BeEmpty();
    }

    [Fact]
    public async Task Successful_revoke_survives_restart_and_old_token_cannot_acquire()
    {
        var token = SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray());
        var record = AuthorizationRecordFactory.Create();
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]));

        await using (var coordinator = await CreateCoordinatorAsync(persistence))
        {
            var result = await coordinator.RevokeAsync(record.Id);

            result.Succeeded.Should().BeTrue();
        }

        persistence.SavedDocument!.Authorizations.Should().NotContain(
            authorization => authorization.Id == record.Id);

        await using var restarted = await CreateCoordinatorAsync(persistence);
        var acquisition = restarted.AcquireLease(
            new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback));

        acquisition.Succeeded.Should().BeFalse();
        acquisition.Failure.Should().Be(AuthorizationFailure.NotFound);
    }

    private static ValueTask<AuthorizationCoordinator> CreateCoordinatorAsync(
        FakeAuthorizationPersistence persistence,
        ManualTimeProvider? clock = null)
    {
        clock ??= new ManualTimeProvider(AuthorizationRecordFactory.Now);
        return AuthorizationCoordinator.CreateAsync(
            persistence,
            new PairingCodeManager(clock, new QueueEntropySource(new byte[24])),
            new SessionTokenService(
                clock,
                new QueueEntropySource(new byte[16], new byte[32])),
            clock);
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!condition())
        {
            await Task.Delay(10, timeout.Token);
        }
    }
}
