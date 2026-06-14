using System.Diagnostics;
using System.IO.Pipes;
using System.Text;
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
        var transport = new FakeSingleInstanceTransport
        {
            SendResult = SingleInstanceSendResult.Unavailable,
        };

        var result = await SingleInstanceCoordinator.TryStartAsync(
            TestOptions(mutexes, transport),
            CancellationToken.None);

        result.Role.Should().Be(SingleInstanceRole.SecondaryPipeUnavailable);
        result.Error.Should().Contain("ShowTray");
        transport.StartedServers.Should().BeEmpty();
        transport.LastTimeout.Should().Be(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public void Second_launch_does_not_capture_pre_message_loop_synchronization_context()
    {
        var mutexes = new FakeSingleInstanceMutexFactory { InitiallyOwned = true };
        var transport = new FakeSingleInstanceTransport
        {
            CompleteSendAsynchronously = true,
        };
        Exception? exception = null;
        SingleInstanceCoordinatorResult? result = null;
        var context = new NonPumpingSynchronizationContext();
        var thread = new Thread(() =>
        {
            try
            {
                SynchronizationContext.SetSynchronizationContext(context);
                result = SingleInstanceCoordinator.TryStartAsync(
                    TestOptions(mutexes, transport),
                    CancellationToken.None).GetAwaiter().GetResult();
            }
            catch (Exception caught)
            {
                exception = caught;
            }
        });
        thread.IsBackground = true;
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        thread.Join(TimeSpan.FromSeconds(5)).Should().BeTrue(
            "secondary startup must exit before the WinForms message loop is pumping");
        exception.Should().BeNull();
        result!.Role.Should().Be(SingleInstanceRole.SecondaryNotified);
        context.PostCount.Should().Be(0);
    }

    [Fact]
    public async Task Second_launch_reports_rejected_when_owner_handler_fails()
    {
        var mutexes = new FakeSingleInstanceMutexFactory { InitiallyOwned = true };
        var transport = new FakeSingleInstanceTransport
        {
            SendResult = SingleInstanceSendResult.Rejected,
        };

        var result = await SingleInstanceCoordinator.TryStartAsync(
            TestOptions(mutexes, transport),
            CancellationToken.None);

        result.Role.Should().Be(SingleInstanceRole.SecondaryPipeUnavailable);
        result.Error.Should().Contain("rejected ShowTray");
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

    [Fact]
    public async Task Owner_server_uses_injected_message_handler()
    {
        var mutexes = new FakeSingleInstanceMutexFactory();
        var transport = new FakeSingleInstanceTransport();
        var handled = new List<string>();

        await using var result = await SingleInstanceCoordinator.TryStartAsync(
            TestOptions(
                mutexes,
                transport,
                onOwnerMessage: (message, _) =>
                {
                    handled.Add(message);
                    return ValueTask.CompletedTask;
                }),
            CancellationToken.None);

        await transport.DeliverToOwnerAsync(SingleInstanceCoordinator.ShowTrayMessage);

        result.Role.Should().Be(SingleInstanceRole.Owner);
        handled.Should().Equal(SingleInstanceCoordinator.ShowTrayMessage);
    }

    [Fact]
    public async Task Windows_transport_reports_handler_failure_and_keeps_accepting_messages()
    {
        var transport = new WindowsSingleInstanceTransport();
        var pipeName = "UniversalClipboard.test." + Guid.NewGuid().ToString("N");
        var failNext = true;
        await using var server = transport.StartServer(
            new SingleInstancePipeRegistration(
                pipeName,
                "S-1-5-21-test",
                AllowsCurrentUserOnly: true),
            (_, _) =>
            {
                if (failNext)
                {
                    failNext = false;
                    throw new InvalidOperationException("handler failed");
                }

                return ValueTask.CompletedTask;
            });

        var failed = await transport.TrySendAsync(
            pipeName,
            SingleInstanceCoordinator.ShowTrayMessage,
            TimeSpan.FromSeconds(5),
            CancellationToken.None);
        var succeeded = await transport.TrySendAsync(
            pipeName,
            SingleInstanceCoordinator.ShowTrayMessage,
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        failed.Should().Be(SingleInstanceSendResult.Rejected);
        succeeded.Should().Be(SingleInstanceSendResult.Delivered);
    }

    [Fact]
    public async Task Windows_transport_rejects_unknown_messages_before_owner_handler()
    {
        var transport = new WindowsSingleInstanceTransport();
        var pipeName = "UniversalClipboard.test." + Guid.NewGuid().ToString("N");
        var handled = new List<string>();
        await using var server = transport.StartServer(
            new SingleInstancePipeRegistration(
                pipeName,
                "S-1-5-21-test",
                AllowsCurrentUserOnly: true),
            (message, _) =>
            {
                handled.Add(message);
                return ValueTask.CompletedTask;
            });

        var rejected = await transport.TrySendAsync(
            pipeName,
            "ShowTray\0Injected",
            TimeSpan.FromSeconds(5),
            CancellationToken.None);
        var accepted = await transport.TrySendAsync(
            pipeName,
            SingleInstanceCoordinator.ShowTrayMessage,
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        rejected.Should().Be(SingleInstanceSendResult.Rejected);
        accepted.Should().Be(SingleInstanceSendResult.Delivered);
        handled.Should().Equal(SingleInstanceCoordinator.ShowTrayMessage);
    }

    [Fact]
    public async Task Windows_transport_times_out_no_newline_client_and_accepts_next_show_tray()
    {
        var transport = new WindowsSingleInstanceTransport();
        var pipeName = "UniversalClipboard.test." + Guid.NewGuid().ToString("N");
        var handled = new List<string>();
        await using var server = transport.StartServer(
            new SingleInstancePipeRegistration(
                pipeName,
                "S-1-5-21-test",
                AllowsCurrentUserOnly: true),
            (message, _) =>
            {
                handled.Add(message);
                return ValueTask.CompletedTask;
            });

        await using var slowClient = await ConnectAndWritePipeBytesAsync(
            pipeName,
            Encoding.UTF8.GetBytes("Show"));
        var started = Stopwatch.StartNew();
        var accepted = await transport.TrySendAsync(
            pipeName,
            SingleInstanceCoordinator.ShowTrayMessage,
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        accepted.Should().Be(SingleInstanceSendResult.Delivered);
        started.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(4));
        handled.Should().Equal(SingleInstanceCoordinator.ShowTrayMessage);
    }

    [Fact]
    public async Task Windows_transport_rejects_overlong_message_and_accepts_next_show_tray()
    {
        var transport = new WindowsSingleInstanceTransport();
        var pipeName = "UniversalClipboard.test." + Guid.NewGuid().ToString("N");
        var handled = new List<string>();
        await using var server = transport.StartServer(
            new SingleInstancePipeRegistration(
                pipeName,
                "S-1-5-21-test",
                AllowsCurrentUserOnly: true),
            (message, _) =>
            {
                handled.Add(message);
                return ValueTask.CompletedTask;
            });

        var rejected = await transport.TrySendAsync(
            pipeName,
            new string('A', 65),
            TimeSpan.FromSeconds(5),
            CancellationToken.None);
        var accepted = await transport.TrySendAsync(
            pipeName,
            SingleInstanceCoordinator.ShowTrayMessage,
            TimeSpan.FromSeconds(5),
            CancellationToken.None);

        rejected.Should().Be(SingleInstanceSendResult.Rejected);
        accepted.Should().Be(SingleInstanceSendResult.Delivered);
        handled.Should().Equal(SingleInstanceCoordinator.ShowTrayMessage);
    }

    [Fact]
    public void Windows_mutex_factory_enforces_same_user_single_owner()
    {
        var factory = new WindowsSingleInstanceMutexFactory();
        var name = @"Local\UniversalClipboard.test." + Guid.NewGuid().ToString("N");
        using var acquired = new ManualResetEventSlim();
        using var release = new ManualResetEventSlim();
        Exception? threadException = null;
        var owner = new Thread(() =>
        {
            try
            {
                using var first = factory.Create(name);
                first.TryAcquire().Should().BeTrue();
                acquired.Set();
                release.Wait(TimeSpan.FromSeconds(5)).Should().BeTrue();
            }
            catch (Exception exception)
            {
                threadException = exception;
            }
        });
        owner.Start();
        acquired.Wait(TimeSpan.FromSeconds(5)).Should().BeTrue();

        using var second = factory.Create(name);
        second.TryAcquire().Should().BeFalse();

        release.Set();
        owner.Join(TimeSpan.FromSeconds(5)).Should().BeTrue();
        threadException.Should().BeNull();
    }

    private static SingleInstanceCoordinatorOptions TestOptions(
        FakeSingleInstanceMutexFactory mutexes,
        FakeSingleInstanceTransport transport,
        string sid = "S-1-5-21-test",
        Func<string, CancellationToken, ValueTask>? onOwnerMessage = null) =>
        new(
            new StaticUserIdentity(sid),
            mutexes,
            transport,
            TimeProvider.System,
            onOwnerMessage);

    private static async Task<NamedPipeClientStream> ConnectAndWritePipeBytesAsync(
        string pipeName,
        byte[] bytes)
    {
        var client = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.InOut,
            PipeOptions.Asynchronous);
        await client.ConnectAsync(TimeSpan.FromSeconds(5), CancellationToken.None);
        await client.WriteAsync(bytes, CancellationToken.None);
        await client.FlushAsync(CancellationToken.None);
        return client;
    }

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
        public SingleInstanceSendResult SendResult { get; set; } =
            SingleInstanceSendResult.Delivered;

        public bool CompleteSendAsynchronously { get; set; }

        public List<SingleInstancePipeRegistration> StartedServers { get; } = [];

        public List<string> SentMessages { get; } = [];

        public List<Func<string, CancellationToken, ValueTask>> Handlers { get; } = [];

        public TimeSpan? LastTimeout { get; private set; }

        public ISingleInstancePipeServer StartServer(
            SingleInstancePipeRegistration registration,
            Func<string, CancellationToken, ValueTask> onMessage)
        {
            StartedServers.Add(registration);
            Handlers.Add(onMessage);
            return new FakeServer();
        }

        public async ValueTask<SingleInstanceSendResult> TrySendAsync(
            string pipeName,
            string message,
            TimeSpan timeout,
            CancellationToken cancellationToken)
        {
            LastTimeout = timeout;
            if (CompleteSendAsynchronously)
            {
                await Task.Delay(10, cancellationToken).ConfigureAwait(false);
            }

            if (SendResult == SingleInstanceSendResult.Delivered)
            {
                SentMessages.Add(message);
            }

            return SendResult;
        }

        public async ValueTask DeliverToOwnerAsync(string message) =>
            await Handlers.Single()(message, CancellationToken.None);

        private sealed class FakeServer : ISingleInstancePipeServer
        {
            public ValueTask DisposeAsync() => ValueTask.CompletedTask;
        }
    }

    private sealed class NonPumpingSynchronizationContext : SynchronizationContext
    {
        public int PostCount { get; private set; }

        public override void Post(SendOrPostCallback d, object? state)
        {
            ArgumentNullException.ThrowIfNull(d);
            PostCount++;
        }

        public override void Send(SendOrPostCallback d, object? state)
        {
            ArgumentNullException.ThrowIfNull(d);
            PostCount++;
        }
    }
}
