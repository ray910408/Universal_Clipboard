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

    [Fact]
    public async Task Throwing_revocation_callback_does_not_fault_worker_or_leave_revoking_state()
    {
        var token = SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray());
        var record = AuthorizationRecordFactory.Create();
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]));
        await using var coordinator = await CreateCoordinatorAsync(persistence);
        var lease = coordinator.AcquireLease(
            new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback)).Lease!;
        var callbackEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var registration = lease.RevocationToken.Register(() =>
        {
            callbackEntered.SetResult();
            throw new InvalidOperationException("simulated callback failure");
        });

        var revokeTask = coordinator.RevokeAsync(record.Id).AsTask();
        await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        lease.Dispose();

        var result = await revokeTask.WaitAsync(TimeSpan.FromSeconds(5));

        result.Succeeded.Should().BeTrue();
        coordinator.AcquireLease(
                new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback))
            .Failure.Should().Be(AuthorizationFailure.NotFound);
    }

    [Fact]
    public async Task Blocking_revocation_callback_does_not_block_worker_after_lease_drains()
    {
        var token = SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray());
        var record = AuthorizationRecordFactory.Create();
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]));
        await using var coordinator = await CreateCoordinatorAsync(persistence);
        var lease = coordinator.AcquireLease(
            new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback)).Lease!;
        var callbackEntered = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var releaseCallback = new ManualResetEventSlim();
        using var registration = lease.RevocationToken.Register(() =>
        {
            callbackEntered.SetResult();
            releaseCallback.Wait();
        });

        try
        {
            var revokeTask = coordinator.RevokeAsync(record.Id).AsTask();
            await callbackEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));
            lease.Dispose();

            var completed = await Task.WhenAny(revokeTask, Task.Delay(250)) == revokeTask;

            completed.Should().BeTrue("the single mutation worker must not run lease callbacks");
            (await revokeTask).Succeeded.Should().BeTrue();
        }
        finally
        {
            releaseCallback.Set();
            lease.Dispose();
        }
    }

    [Fact]
    public async Task Reentrant_revocation_callback_can_queue_mutation_without_deadlock()
    {
        var token = SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray());
        var record = AuthorizationRecordFactory.Create();
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]));
        await using var coordinator = await CreateCoordinatorAsync(persistence);
        var lease = coordinator.AcquireLease(
            new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback)).Lease!;
        var nestedSucceeded = new TaskCompletionSource<bool>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using var registration = lease.RevocationToken.Register(() =>
        {
            lease.Dispose();
            var nested = coordinator.RevokeAsync(Guid.NewGuid()).AsTask();
            nestedSucceeded.SetResult(
                nested.Wait(TimeSpan.FromSeconds(1)) &&
                nested.Result.Failure == AuthorizationFailure.NotFound);
        });

        var result = await coordinator.RevokeAsync(record.Id).AsTask()
            .WaitAsync(TimeSpan.FromSeconds(5));

        result.Succeeded.Should().BeTrue();
        (await nestedSucceeded.Task.WaitAsync(TimeSpan.FromSeconds(5))).Should().BeTrue();
    }

    [Fact]
    public async Task Repeated_expired_acquire_coalesces_cleanup_even_when_persistence_fails()
    {
        var clock = new ManualTimeProvider(AuthorizationRecordFactory.Now.AddDays(1));
        var token = SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray());
        var record = AuthorizationRecordFactory.Create();
        var saveStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSave = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]))
        {
            OnSaveAsync = async (_, _) =>
            {
                saveStarted.TrySetResult();
                await releaseSave.Task;
                throw new InvalidOperationException("simulated failure");
            },
        };
        await using var coordinator = await CreateCoordinatorAsync(persistence, clock);
        var request = new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback);

        Enumerable.Range(0, 1_000).Should().OnlyContain(_ =>
            coordinator.AcquireLease(request).Failure == AuthorizationFailure.Expired);
        await saveStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));
        Enumerable.Range(0, 1_000).Should().OnlyContain(_ =>
            coordinator.AcquireLease(request).Failure == AuthorizationFailure.Expired);

        releaseSave.SetResult();
        await Task.Delay(250);

        persistence.SaveAttempts.Should().ContainSingle();
        coordinator.List().Should().ContainSingle();

        coordinator.AcquireLease(request).Failure.Should().Be(AuthorizationFailure.Expired);
        await WaitUntilAsync(() => persistence.SaveAttempts.Count == 2);
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
