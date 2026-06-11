using System.Net;
using FluentAssertions;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.Core.Tests.Authorization;

public sealed class AuthorizationCoordinatorMutationTests
{
    [Fact]
    public async Task RemoveStaleBindings_saves_before_publishing()
    {
        var current = AuthorizationRecordFactory.Create(
            boundHostIpv4: IPAddress.Parse("192.168.1.10"));
        var stale = AuthorizationRecordFactory.Create(
            boundHostIpv4: IPAddress.Parse("192.168.1.11"));
        var saveStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSave = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var persistence = new FakeAuthorizationPersistence(
            new AuthorizationDocument([current, stale]))
        {
            OnSaveAsync = async (_, _) =>
            {
                saveStarted.SetResult();
                await releaseSave.Task;
            },
        };
        await using var coordinator = await CreateCoordinatorAsync(persistence);

        var removalTask = coordinator.RemoveStaleBindingsAsync(
            [IPAddress.Parse("192.168.1.10")]).AsTask();
        await saveStarted.Task;

        coordinator.Snapshot.Authorizations.Should().Equal(current, stale);
        releaseSave.SetResult();

        var result = await removalTask;
        result.Succeeded.Should().BeTrue();
        result.Snapshot.Authorizations.Should().Equal(current);
    }

    [Fact]
    public async Task Failed_stale_binding_save_keeps_old_snapshot()
    {
        var record = AuthorizationRecordFactory.Create();
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]))
        {
            OnSaveAsync = (_, _) => throw new InvalidOperationException("simulated failure"),
        };
        await using var coordinator = await CreateCoordinatorAsync(persistence);

        var result = await coordinator.RemoveStaleBindingsAsync([]);

        result.Failure.Should().Be(AuthorizationFailure.PersistenceFailed);
        coordinator.Snapshot.Authorizations.Should().Equal(record);
    }

    [Fact]
    public async Task Dispose_allows_started_save_to_finish_and_cancels_queued_mutation()
    {
        var saveStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSave = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var persistence = new FakeAuthorizationPersistence
        {
            OnSaveAsync = async (_, _) =>
            {
                saveStarted.SetResult();
                await releaseSave.Task;
            },
        };
        var clock = new ManualTimeProvider(AuthorizationRecordFactory.Now);
        var pairingCodes = new PairingCodeManager(
            clock,
            new QueueEntropySource(Enumerable.Repeat((byte)3, 24).ToArray()));
        var code = pairingCodes.Create();
        var coordinator = await AuthorizationCoordinator.CreateAsync(
            persistence,
            pairingCodes,
            new SessionTokenService(
                clock,
                new QueueEntropySource(new byte[16], new byte[32])),
            clock);

        var exchangeTask = coordinator.ExchangeAsync(
            new ExchangeAuthorizationRequest(
                code.Value,
                "Browser",
                IPAddress.Loopback,
                AuthorizationDuration.OneHour)).AsTask();
        await saveStarted.Task;
        var queuedTask = coordinator.RemoveStaleBindingsAsync([IPAddress.Loopback]).AsTask();

        var disposeTask = coordinator.DisposeAsync().AsTask();
        disposeTask.IsCompleted.Should().BeFalse();
        releaseSave.SetResult();

        var exchange = await exchangeTask;
        var queued = await queuedTask;
        await disposeTask;

        exchange.Succeeded.Should().BeTrue();
        queued.Failure.Should().Be(AuthorizationFailure.Disposed);
    }

    [Fact]
    public async Task Dispose_cancels_revoke_waiting_for_lease_drain_without_deadlock()
    {
        var token = SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray());
        var record = AuthorizationRecordFactory.Create();
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]));
        var coordinator = await CreateCoordinatorAsync(persistence);
        var lease = coordinator.AcquireLease(
            new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback)).Lease!;
        var revokeTask = coordinator.RevokeAsync(record.Id).AsTask();
        await WaitUntilAsync(() => lease.RevocationToken.IsCancellationRequested);

        var disposeTask = coordinator.DisposeAsync().AsTask();
        await disposeTask.WaitAsync(TimeSpan.FromSeconds(5));
        var revoke = await revokeTask;

        revoke.Failure.Should().Be(AuthorizationFailure.Disposed);
        persistence.SaveAttempts.Should().BeEmpty();
        lease.Dispose();
    }

    private static ValueTask<AuthorizationCoordinator> CreateCoordinatorAsync(
        FakeAuthorizationPersistence persistence)
    {
        var clock = new ManualTimeProvider(AuthorizationRecordFactory.Now);
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
