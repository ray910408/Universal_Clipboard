using System.Net;
using System.Reflection;
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

        coordinator.List().Should().Equal(
            AuthorizationRecordFactory.Metadata(current),
            AuthorizationRecordFactory.Metadata(stale));
        releaseSave.SetResult();

        var result = await removalTask;
        result.Succeeded.Should().BeTrue();
        result.Snapshot.Authorizations.Should().Equal(
            AuthorizationRecordFactory.Metadata(current));
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
        coordinator.List().Should().Equal(AuthorizationRecordFactory.Metadata(record));
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
            new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback, AuthorizationRecordFactory.ProofForByte())).Lease!;
        var revokeTask = coordinator.RevokeAsync(record.Id).AsTask();
        await WaitUntilAsync(() => lease.RevocationToken.IsCancellationRequested);

        var disposeTask = coordinator.DisposeAsync().AsTask();
        await disposeTask.WaitAsync(TimeSpan.FromSeconds(5));
        var revoke = await revokeTask;

        revoke.Failure.Should().Be(AuthorizationFailure.Disposed);
        persistence.SaveAttempts.Should().BeEmpty();
        lease.Dispose();
    }

    [Fact]
    public async Task Queued_command_cancellation_completes_before_blocking_head_drains()
    {
        var token = SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray());
        var record = AuthorizationRecordFactory.Create();
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]));
        await using var coordinator = await CreateCoordinatorAsync(persistence);
        var lease = coordinator.AcquireLease(
            new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback, AuthorizationRecordFactory.ProofForByte())).Lease!;
        var revokeTask = coordinator.RevokeAsync(record.Id).AsTask();
        await WaitUntilAsync(() => lease.RevocationToken.IsCancellationRequested);
        using var cancellation = new CancellationTokenSource();
        var queuedTask = coordinator.RemoveStaleBindingsAsync(
            [IPAddress.Loopback],
            cancellation.Token).AsTask();

        cancellation.Cancel();
        var completedBeforeDrain =
            await Task.WhenAny(queuedTask, Task.Delay(250)) == queuedTask;

        lease.Dispose();
        await revokeTask.WaitAsync(TimeSpan.FromSeconds(5));
        var queued = await queuedTask.WaitAsync(TimeSpan.FromSeconds(5));

        completedBeforeDrain.Should().BeTrue();
        queued.Failure.Should().Be(AuthorizationFailure.Canceled);
    }

    [Fact]
    public async Task Mutation_queue_is_bounded_and_rejects_excess_work_immediately()
    {
        var token = SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray());
        var record = AuthorizationRecordFactory.Create();
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]));
        await using var coordinator = await CreateCoordinatorAsync(persistence);
        var lease = coordinator.AcquireLease(
            new AcquireLeaseRequest(record.Id, token, IPAddress.Loopback, AuthorizationRecordFactory.ProofForByte())).Lease!;
        var revokeTask = coordinator.RevokeAsync(record.Id).AsTask();
        await WaitUntilAsync(() => lease.RevocationToken.IsCancellationRequested);

        var queued = Enumerable.Range(0, AuthorizationCoordinator.MutationQueueCapacity + 32)
            .Select(_ => coordinator.RemoveStaleBindingsAsync([IPAddress.Loopback]).AsTask())
            .ToArray();
        await Task.Delay(50);

        queued.Count(task =>
                task.IsCompletedSuccessfully &&
                task.Result.Failure == AuthorizationFailure.QueueFull)
            .Should().BeGreaterThan(0);

        lease.Dispose();
        await revokeTask.WaitAsync(TimeSpan.FromSeconds(5));
        await Task.WhenAll(queued).WaitAsync(TimeSpan.FromSeconds(5));
    }

    [Fact]
    public async Task Enqueue_racing_dispose_never_reports_queue_full_or_hangs()
    {
        const int iterations = 200;
        const int enqueuesPerIteration = 32;

        for (var iteration = 0; iteration < iterations; iteration++)
        {
            var coordinator = await CreateCoordinatorAsync(new FakeAuthorizationPersistence());
            using var start = new ManualResetEventSlim();
            var enqueues = Enumerable.Range(0, enqueuesPerIteration)
                .Select(_ => Task.Run(async () =>
                {
                    start.Wait();
                    return await coordinator.RemoveStaleBindingsAsync([IPAddress.Loopback]);
                }))
                .ToArray();
            var dispose = Task.Run(async () =>
            {
                start.Wait();
                await coordinator.DisposeAsync();
            });

            start.Set();
            var results = await Task.WhenAll(enqueues).WaitAsync(TimeSpan.FromSeconds(5));
            await dispose.WaitAsync(TimeSpan.FromSeconds(5));

            results.Should().OnlyContain(
                result =>
                    result.Failure == AuthorizationFailure.None ||
                    result.Failure == AuthorizationFailure.Disposed,
                $"iteration {iteration} has fewer enqueues than queue capacity");
        }
    }

    [Fact]
    public async Task Rejected_command_clears_operation_reference()
    {
        var commandType = typeof(AuthorizationCoordinator)
            .GetNestedType("Command`1", BindingFlags.NonPublic)!
            .MakeGenericType(typeof(AuthorizationFailure));
        var payload = new object();
        Func<Task<AuthorizationFailure>> operation = () =>
        {
            GC.KeepAlive(payload);
            throw new InvalidOperationException("must not execute");
        };
        Func<AuthorizationFailure, AuthorizationFailure> failureFactory = failure => failure;
        var command = Activator.CreateInstance(
            commandType,
            BindingFlags.Instance | BindingFlags.Public | BindingFlags.NonPublic,
            binder: null,
            args: [operation, failureFactory, CancellationToken.None],
            culture: null)!;

        commandType.GetMethod("Cancel")!.Invoke(
            command,
            [AuthorizationFailure.Disposed]);

        commandType.GetField("_operation", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(command).Should().BeNull();
        var completion = (Task<AuthorizationFailure>)commandType.GetProperty("Completion")!
            .GetValue(command)!;
        (await completion).Should().Be(AuthorizationFailure.Disposed);
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
