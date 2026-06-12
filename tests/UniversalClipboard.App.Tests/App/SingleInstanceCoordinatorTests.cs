using FluentAssertions;
using UniversalClipboard.App.App;

namespace UniversalClipboard.App.Tests.App;

public sealed class SingleInstanceCoordinatorTests
{
    [Fact]
    public async Task Simultaneous_launches_create_one_owner_and_one_notified_second_instance()
    {
        var mutexes = new FakeSingleInstanceMutexFactory();
        var transport = new FakeSingleInstanceTransport();

        var first = SingleInstanceCoordinator.TryStartAsync(
            TestOptions(mutexes, transport),
            CancellationToken.None);
        var second = SingleInstanceCoordinator.TryStartAsync(
            TestOptions(mutexes, transport),
            CancellationToken.None);

        var results = await Task.WhenAll(first, second);

        results.Should().ContainSingle(result => result.Role == SingleInstanceRole.Owner);
        results.Should().ContainSingle(result => result.Role == SingleInstanceRole.SecondaryNotified);
        transport.SentMessages.Should().Equal("ShowTray");
        transport.StartedServers.Should().HaveCount(1);
    }

    [Fact]
    public async Task Second_launch_times_out_when_mutex_exists_but_pipe_does_not_answer()
    {
        var mutexes = new FakeSingleInstanceMutexFactory { InitiallyOwned = true };
        var transport = new FakeSingleInstanceTransport { SendSucceeds = false };

        var result = await SingleInstanceCoordinator.TryStartAsync(
            TestOptions(mutexes, transport),
            CancellationToken.None);

        result.Role.Should().Be(SingleInstanceRole.SecondaryPipeUnavailable);
        result.Error.Should().Contain("ShowTray");
        transport.StartedServers.Should().BeEmpty();
        transport.LastTimeout.Should().Be(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task Names_include_user_sid_and_pipe_acl_is_current_user_only()
    {
        var mutexes = new FakeSingleInstanceMutexFactory();
        var transport = new FakeSingleInstanceTransport();

        await using var result = await SingleInstanceCoordinator.TryStartAsync(
            TestOptions(mutexes, transport, "S-1-5-21-100"),
            CancellationToken.None);

        result.Role.Should().Be(SingleInstanceRole.Owner);
        mutexes.CreatedNames.Single().Should().Contain("S-1-5-21-100");
        transport.StartedServers.Single().PipeName.Should().Contain("S-1-5-21-100");
        transport.StartedServers.Single().AllowedUserSid.Should().Be("S-1-5-21-100");
        transport.StartedServers.Single().AllowsCurrentUserOnly.Should().BeTrue();
    }

    private static SingleInstanceCoordinatorOptions TestOptions(
        FakeSingleInstanceMutexFactory mutexes,
        FakeSingleInstanceTransport transport,
        string sid = "S-1-5-21-test") =>
        new(
            new StaticUserIdentity(sid),
            mutexes,
            transport,
            TimeProvider.System);

    private sealed class StaticUserIdentity(string sid) : IUserIdentity
    {
        public string UserSid => sid;
    }

    private sealed class FakeSingleInstanceMutexFactory : ISingleInstanceMutexFactory
    {
        private int _owned;

        public bool InitiallyOwned
        {
            set => _owned = value ? 1 : 0;
        }

        public List<string> CreatedNames { get; } = [];

        public ISingleInstanceMutex Create(string name)
        {
            CreatedNames.Add(name);
            return new FakeMutex(this);
        }

        private sealed class FakeMutex(FakeSingleInstanceMutexFactory owner) : ISingleInstanceMutex
        {
            private bool _owns;

            public bool TryAcquire()
            {
                _owns = Interlocked.CompareExchange(ref owner._owned, 1, 0) == 0;
                return _owns;
            }

            public void Dispose()
            {
                if (_owns)
                {
                    Volatile.Write(ref owner._owned, 0);
                }
            }
        }
    }

    private sealed class FakeSingleInstanceTransport : ISingleInstanceTransport
    {
        public bool SendSucceeds { get; set; } = true;

        public List<SingleInstancePipeRegistration> StartedServers { get; } = [];

        public List<string> SentMessages { get; } = [];

        public TimeSpan? LastTimeout { get; private set; }

        public ISingleInstancePipeServer StartServer(
            SingleInstancePipeRegistration registration,
            Func<string, CancellationToken, ValueTask> onMessage)
        {
            StartedServers.Add(registration);
            return new FakeServer();
        }

        public ValueTask<bool> TrySendAsync(
            string pipeName,
            string message,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            LastTimeout = timeout;
            if (SendSucceeds)
            {
                SentMessages.Add(message);
            }

            return ValueTask.FromResult(SendSucceeds);
        }

        private sealed class FakeServer : ISingleInstancePipeServer
        {
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }
}
