using System.IO.Pipes;
using System.Security.Principal;

namespace UniversalClipboard.App.App;

public interface IUserIdentity
{
    string UserSid { get; }
}

public interface ISingleInstanceMutex : IDisposable
{
    bool TryAcquire();
}

public interface ISingleInstanceMutexFactory
{
    ISingleInstanceMutex Create(string name);
}

public interface ISingleInstancePipeServer : IAsyncDisposable;

public interface ISingleInstanceTransport
{
    ISingleInstancePipeServer StartServer(
        SingleInstancePipeRegistration registration,
        Func<string, CancellationToken, ValueTask> onMessage);

    ValueTask<SingleInstanceSendResult> TrySendAsync(
        string pipeName,
        string message,
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

public sealed record SingleInstancePipeRegistration(
    string PipeName,
    string AllowedUserSid,
    bool AllowsCurrentUserOnly);

public sealed record SingleInstanceCoordinatorOptions(
    IUserIdentity UserIdentity,
    ISingleInstanceMutexFactory MutexFactory,
    ISingleInstanceTransport Transport,
    TimeProvider TimeProvider,
    Func<string, CancellationToken, ValueTask>? OnOwnerMessage = null);

public enum SingleInstanceRole
{
    Owner,
    SecondaryNotified,
    SecondaryPipeUnavailable,
}

public enum SingleInstanceSendResult
{
    Delivered,
    Rejected,
    Unavailable,
}

public sealed class SingleInstanceCoordinatorResult : IAsyncDisposable
{
    internal SingleInstanceCoordinatorResult(
        SingleInstanceRole role,
        ISingleInstanceMutex? mutex,
        ISingleInstancePipeServer? pipeServer,
        string? error = null)
    {
        Role = role;
        _mutex = mutex;
        _pipeServer = pipeServer;
        Error = error;
    }

    private ISingleInstanceMutex? _mutex;
    private ISingleInstancePipeServer? _pipeServer;

    public SingleInstanceRole Role { get; }

    public string? Error { get; }

    public async ValueTask DisposeAsync()
    {
        var server = Interlocked.Exchange(ref _pipeServer, null);
        if (server is not null)
        {
            await server.DisposeAsync();
        }

        Interlocked.Exchange(ref _mutex, null)?.Dispose();
    }
}

public sealed class SingleInstanceCoordinator
{
    public const string ShowTrayMessage = "ShowTray";
    private static readonly TimeSpan SecondInstanceTimeout = TimeSpan.FromSeconds(2);

    public static async Task<SingleInstanceCoordinatorResult> TryStartAsync(
        SingleInstanceCoordinatorOptions options,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(options);
        var sid = options.UserIdentity.UserSid;
        if (string.IsNullOrWhiteSpace(sid))
        {
            throw new InvalidOperationException("The current Windows user SID is required.");
        }

        var mutexName = BuildMutexName(sid);
        var pipeName = BuildPipeName(sid);
        var mutex = options.MutexFactory.Create(mutexName);
        if (mutex.TryAcquire())
        {
            var registration = new SingleInstancePipeRegistration(
                pipeName,
                sid,
                AllowsCurrentUserOnly: true);
            var server = options.Transport.StartServer(
                registration,
                options.OnOwnerMessage ?? IgnoreOwnerMessageAsync);
            return new SingleInstanceCoordinatorResult(
                SingleInstanceRole.Owner,
                mutex,
                server);
        }

        mutex.Dispose();
        var sendResult = await options.Transport.TrySendAsync(
            pipeName,
            ShowTrayMessage,
            SecondInstanceTimeout,
            cancellationToken);
        return sendResult switch
        {
            SingleInstanceSendResult.Delivered => new SingleInstanceCoordinatorResult(
                SingleInstanceRole.SecondaryNotified,
                null,
                null),
            SingleInstanceSendResult.Rejected => new SingleInstanceCoordinatorResult(
                SingleInstanceRole.SecondaryPipeUnavailable,
                null,
                null,
                "Existing Universal Clipboard instance rejected ShowTray."),
            _ => new SingleInstanceCoordinatorResult(
                SingleInstanceRole.SecondaryPipeUnavailable,
                null,
                null,
                "Existing Universal Clipboard instance did not accept ShowTray within 2 seconds."),
        };
    }

    private static string BuildMutexName(string sid) =>
        $@"Local\UniversalClipboard.mutex.{sid}";

    private static string BuildPipeName(string sid) =>
        $"UniversalClipboard.pipe.{sid}";

    private static ValueTask IgnoreOwnerMessageAsync(
        string message,
        CancellationToken cancellationToken) =>
        ValueTask.CompletedTask;
}

public sealed class WindowsUserIdentity : IUserIdentity
{
    public string UserSid =>
        WindowsIdentity.GetCurrent().User?.Value ??
        throw new InvalidOperationException("Unable to determine the current Windows user SID.");
}

public sealed class WindowsSingleInstanceMutexFactory : ISingleInstanceMutexFactory
{
    public ISingleInstanceMutex Create(string name) => new WindowsMutex(name);

    private sealed class WindowsMutex(string name) : ISingleInstanceMutex
    {
        private readonly Mutex _mutex = new(initiallyOwned: false, name);

        private bool _owns;

        public bool TryAcquire()
        {
            _owns = _mutex.WaitOne(0);
            return _owns;
        }

        public void Dispose()
        {
            if (_owns)
            {
                _mutex.ReleaseMutex();
            }

            _mutex.Dispose();
        }
    }
}

public sealed class WindowsSingleInstanceTransport : ISingleInstanceTransport
{
    private const string AckOk = "OK";
    private const string AckError = "ERROR";

    public ISingleInstancePipeServer StartServer(
        SingleInstancePipeRegistration registration,
        Func<string, CancellationToken, ValueTask> onMessage)
    {
        ArgumentNullException.ThrowIfNull(registration);
        ArgumentNullException.ThrowIfNull(onMessage);
        if (!registration.AllowsCurrentUserOnly)
        {
            throw new InvalidOperationException("Single-instance pipes must be current-user-only.");
        }

        return new WindowsPipeServer(registration.PipeName, onMessage);
    }

    public async ValueTask<SingleInstanceSendResult> TrySendAsync(
        string pipeName,
        string message,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        using var timeoutSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutSource.CancelAfter(timeout);
        try
        {
            await using var client = new NamedPipeClientStream(
                ".",
                pipeName,
                PipeDirection.InOut,
                PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
            await client.ConnectAsync(timeoutSource.Token);
            await using var writer = new StreamWriter(client, leaveOpen: true) { AutoFlush = true };
            using var reader = new StreamReader(client, leaveOpen: true);
            await writer.WriteLineAsync(message.AsMemory(), timeoutSource.Token);
            var ack = await reader.ReadLineAsync(timeoutSource.Token);
            return string.Equals(ack, AckOk, StringComparison.Ordinal)
                ? SingleInstanceSendResult.Delivered
                : SingleInstanceSendResult.Rejected;
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return SingleInstanceSendResult.Unavailable;
        }
        catch (IOException)
        {
            return SingleInstanceSendResult.Unavailable;
        }
        catch (UnauthorizedAccessException)
        {
            return SingleInstanceSendResult.Unavailable;
        }
    }

    private sealed class WindowsPipeServer : ISingleInstancePipeServer
    {
        private readonly string _pipeName;
        private readonly Func<string, CancellationToken, ValueTask> _onMessage;
        private readonly CancellationTokenSource _shutdown = new();
        private readonly Task _worker;

        public WindowsPipeServer(
            string pipeName,
            Func<string, CancellationToken, ValueTask> onMessage)
        {
            _pipeName = pipeName;
            _onMessage = onMessage;
            _worker = Task.Run(AcceptLoopAsync);
        }

        public async ValueTask DisposeAsync()
        {
            _shutdown.Cancel();
            try
            {
                await _worker;
            }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
            {
            }

            _shutdown.Dispose();
        }

        private async Task AcceptLoopAsync()
        {
            while (!_shutdown.IsCancellationRequested)
            {
                await using var server = new NamedPipeServerStream(
                    _pipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 1,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
                try
                {
                    await server.WaitForConnectionAsync(_shutdown.Token);
                    using var reader = new StreamReader(server, leaveOpen: true);
                    await using var writer = new StreamWriter(server, leaveOpen: true)
                    {
                        AutoFlush = true,
                    };
                    var message = await reader.ReadLineAsync(_shutdown.Token);
                    if (message is not null)
                    {
                        try
                        {
                            await _onMessage(message, _shutdown.Token);
                            await writer.WriteLineAsync(AckOk.AsMemory(), _shutdown.Token);
                        }
                        catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
                        {
                            return;
                        }
                        catch (Exception)
                        {
                            await writer.WriteLineAsync(AckError.AsMemory(), _shutdown.Token);
                        }
                    }
                }
                catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
                {
                    return;
                }
                catch (IOException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
            }
        }
    }
}
