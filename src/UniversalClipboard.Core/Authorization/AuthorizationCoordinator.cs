using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Threading.Channels;

namespace UniversalClipboard.Core.Authorization;

public sealed class AuthorizationCoordinator :
    IAuthorizationService,
    IAuthorizationAdministration,
    IAsyncDisposable
{
    public const int MutationQueueCapacity = 256;

    private readonly IAuthorizationPersistence _persistence;
    private readonly PairingCodeManager _pairingCodes;
    private readonly SessionTokenService _tokenService;
    private readonly TimeProvider _timeProvider;
    private readonly object _leaseGate = new();
    private readonly Dictionary<Guid, LeaseTracker> _leaseTrackers = [];
    private readonly HashSet<Guid> _revoking = [];
    private readonly HashSet<Guid> _expiredCleanupPending = [];
    private readonly CancellationTokenSource _shutdown = new();
    private readonly Channel<ICommand> _commands;
    private readonly Task _worker;
    private AuthorizationDocument _document;
    private AuthorizationStateSnapshot _snapshot;
    private int _disposeStarted;

    private AuthorizationCoordinator(
        IAuthorizationPersistence persistence,
        PairingCodeManager pairingCodes,
        SessionTokenService tokenService,
        TimeProvider timeProvider,
        AuthorizationDocument document)
    {
        _persistence = persistence;
        _pairingCodes = pairingCodes;
        _tokenService = tokenService;
        _timeProvider = timeProvider;
        _document = document;
        _snapshot = new AuthorizationStateSnapshot(document.Authorizations);
        _commands = Channel.CreateBounded<ICommand>(
            new BoundedChannelOptions(MutationQueueCapacity)
            {
                SingleReader = true,
                SingleWriter = false,
                AllowSynchronousContinuations = false,
                FullMode = BoundedChannelFullMode.Wait,
            });
        _worker = Task.Run(ProcessCommandsAsync);
    }

    public static async ValueTask<AuthorizationCoordinator> CreateAsync(
        IAuthorizationPersistence persistence,
        PairingCodeManager pairingCodes,
        SessionTokenService tokenService,
        TimeProvider? timeProvider = null,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(persistence);
        ArgumentNullException.ThrowIfNull(pairingCodes);
        ArgumentNullException.ThrowIfNull(tokenService);

        var document = await persistence.LoadAsync(cancellationToken);
        ArgumentNullException.ThrowIfNull(document);

        return new AuthorizationCoordinator(
            persistence,
            pairingCodes,
            tokenService,
            timeProvider ?? TimeProvider.System,
            document);
    }

    public ImmutableArray<AuthorizationMetadata> List() =>
        CreateAdministrationSnapshot().Authorizations;

    public ValueTask<ExchangeAuthorizationResult> ExchangeAsync(
        ExchangeAuthorizationRequest request,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (!_pairingCodes.TryConsume(request.PairingCode))
        {
            return ValueTask.FromResult(
                ExchangeAuthorizationResult.Failed(AuthorizationFailure.InvalidPairingCode));
        }

        SessionTokenIssue issue;
        try
        {
            issue = _tokenService.Issue(
                request.Label,
                request.BoundHostIpv4,
                request.Duration);
        }
        catch (ArgumentException)
        {
            return ValueTask.FromResult(
                ExchangeAuthorizationResult.Failed(AuthorizationFailure.InvalidRequest));
        }

        return EnqueueAsync(
            () => ExchangeCoreAsync(issue),
            ExchangeAuthorizationResult.Failed,
            cancellationToken);
    }

    public AcquireLeaseResult AcquireLease(AcquireLeaseRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);

        Guid? expiredAuthorizationId = null;
        AcquireLeaseResult result;

        lock (_leaseGate)
        {
            if (Volatile.Read(ref _disposeStarted) != 0)
            {
                return new AcquireLeaseResult(AuthorizationFailure.Disposed, null);
            }

            var authorization = _snapshot.Authorizations.FirstOrDefault(
                item => item.Id == request.AuthorizationId);
            if (authorization is null)
            {
                return new AcquireLeaseResult(AuthorizationFailure.NotFound, null);
            }

            if (authorization.ExpiresAtUtc is { } expiry &&
                _timeProvider.GetUtcNow() >= expiry)
            {
                if (_expiredCleanupPending.Add(authorization.Id))
                {
                    expiredAuthorizationId = authorization.Id;
                }

                result = new AcquireLeaseResult(AuthorizationFailure.Expired, null);
            }
            else if (_revoking.Contains(authorization.Id))
            {
                result = new AcquireLeaseResult(AuthorizationFailure.Revoking, null);
            }
            else if (!authorization.BoundHostIpv4.Equals(request.HostIpv4))
            {
                result = new AcquireLeaseResult(AuthorizationFailure.BoundHostMismatch, null);
            }
            else if (!_tokenService.VerifyToken(authorization, request.Token))
            {
                result = new AcquireLeaseResult(AuthorizationFailure.InvalidToken, null);
            }
            else
            {
                if (!_leaseTrackers.TryGetValue(authorization.Id, out var tracker))
                {
                    tracker = new LeaseTracker();
                    _leaseTrackers.Add(authorization.Id, tracker);
                }

                tracker.Count++;
                var lease = new AuthorizationLease(
                    tracker.RevocationSource.Token,
                    () => ReleaseLease(authorization.Id, tracker));
                result = new AcquireLeaseResult(AuthorizationFailure.None, lease);
            }
        }

        if (expiredAuthorizationId is { } id)
        {
            ScheduleExpiredCleanup(id);
        }

        return result;
    }

    public ValueTask<AuthorizationMutationResult> RevokeAsync(
        Guid authorizationId,
        CancellationToken cancellationToken = default) =>
        EnqueueMutationAsync(
            () => RevokeCoreAsync([authorizationId], requireAllIds: true),
            cancellationToken);

    public ValueTask<AuthorizationMutationResult> RevokeAllAsync(
        CancellationToken cancellationToken = default) =>
        EnqueueMutationAsync(
            () => RevokeCoreAsync(
                _document.Authorizations.Select(authorization => authorization.Id).ToImmutableArray(),
                requireAllIds: false),
            cancellationToken);

    public ValueTask<AuthorizationMutationResult> RemoveStaleBindingsAsync(
        IReadOnlyCollection<IPAddress> activeHostIpv4Addresses,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(activeHostIpv4Addresses);
        if (activeHostIpv4Addresses.Any(address =>
            address.AddressFamily != AddressFamily.InterNetwork))
        {
            throw new ArgumentException(
                "Active authorization bindings must use IPv4.",
                nameof(activeHostIpv4Addresses));
        }

        var activeAddresses = activeHostIpv4Addresses.ToHashSet();
        return EnqueueMutationAsync(
            () => RemoveStaleBindingsCoreAsync(activeAddresses),
            cancellationToken);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref _disposeStarted, 1) != 0)
        {
            await _worker;
            return;
        }

        _shutdown.Cancel();
        _commands.Writer.TryComplete();
        await _worker;
    }

    private async Task<ExchangeAuthorizationResult> ExchangeCoreAsync(SessionTokenIssue issue)
    {
        var candidate = new AuthorizationDocument(
            _document.Authorizations.Add(issue.Authorization));

        try
        {
            await _persistence.SaveAsync(candidate, CancellationToken.None);
        }
        catch (Exception)
        {
            return ExchangeAuthorizationResult.Failed(AuthorizationFailure.PersistenceFailed);
        }

        Publish(candidate);
        return ExchangeAuthorizationResult.Success(issue);
    }

    private async Task<AuthorizationMutationResult> RevokeCoreAsync(
        ImmutableArray<Guid> authorizationIds,
        bool requireAllIds)
    {
        if (authorizationIds.IsDefaultOrEmpty)
        {
            return MutationSucceeded();
        }

        var existingIds = _document.Authorizations
            .Select(authorization => authorization.Id)
            .ToHashSet();
        if (requireAllIds && authorizationIds.Any(id => !existingIds.Contains(id)))
        {
            return MutationFailed(AuthorizationFailure.NotFound);
        }

        var ids = authorizationIds.Where(existingIds.Contains).ToImmutableArray();
        if (ids.IsDefaultOrEmpty)
        {
            return MutationSucceeded();
        }

        var drains = BeginRevocation(ids);
        try
        {
            try
            {
                await Task.WhenAll(drains).WaitAsync(_shutdown.Token);
            }
            catch (OperationCanceledException) when (_shutdown.IsCancellationRequested)
            {
                return MutationFailed(AuthorizationFailure.Disposed);
            }

            var idSet = ids.ToHashSet();
            var candidate = new AuthorizationDocument(
                _document.Authorizations
                    .Where(authorization => !idSet.Contains(authorization.Id))
                    .ToImmutableArray());

            if (!await TrySaveAsync(candidate))
            {
                return MutationFailed(AuthorizationFailure.PersistenceFailed);
            }

            Publish(candidate);
            return MutationSucceeded();
        }
        finally
        {
            EndRevocation(ids);
        }
    }

    private async Task<AuthorizationMutationResult> RemoveStaleBindingsCoreAsync(
        HashSet<IPAddress> activeHostIpv4Addresses)
    {
        var staleIds = _document.Authorizations
            .Where(authorization => !activeHostIpv4Addresses.Contains(authorization.BoundHostIpv4))
            .Select(authorization => authorization.Id)
            .ToImmutableArray();

        return await RevokeCoreAsync(staleIds, requireAllIds: false);
    }

    private async Task<AuthorizationMutationResult> CleanupExpiredCoreAsync(Guid authorizationId)
    {
        var authorization = _document.Authorizations.FirstOrDefault(
            item => item.Id == authorizationId);
        if (authorization?.ExpiresAtUtc is not { } expiry ||
            _timeProvider.GetUtcNow() < expiry)
        {
            return MutationSucceeded();
        }

        return await RevokeCoreAsync([authorizationId], requireAllIds: false);
    }

    private async Task<bool> TrySaveAsync(AuthorizationDocument candidate)
    {
        try
        {
            await _persistence.SaveAsync(candidate, CancellationToken.None);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private ImmutableArray<Task> BeginRevocation(ImmutableArray<Guid> authorizationIds)
    {
        var trackers = ImmutableArray.CreateBuilder<LeaseTracker>();

        lock (_leaseGate)
        {
            foreach (var authorizationId in authorizationIds)
            {
                _revoking.Add(authorizationId);
                if (_leaseTrackers.TryGetValue(authorizationId, out var tracker))
                {
                    trackers.Add(tracker);
                }
            }
        }

        foreach (var tracker in trackers)
        {
            ThreadPool.UnsafeQueueUserWorkItem(
                static state => state.CancelCallbacks(),
                tracker,
                preferLocal: false);
        }

        return trackers.Select(tracker => tracker.Drained.Task).ToImmutableArray();
    }

    private void EndRevocation(ImmutableArray<Guid> authorizationIds)
    {
        lock (_leaseGate)
        {
            foreach (var authorizationId in authorizationIds)
            {
                _revoking.Remove(authorizationId);
                _leaseTrackers.Remove(authorizationId);
            }
        }
    }

    private void ReleaseLease(Guid authorizationId, LeaseTracker tracker)
    {
        lock (_leaseGate)
        {
            if (!_leaseTrackers.TryGetValue(authorizationId, out var current) ||
                !ReferenceEquals(current, tracker))
            {
                return;
            }

            tracker.Count--;
            if (tracker.Count == 0)
            {
                tracker.Drained.TrySetResult();
                if (!_revoking.Contains(authorizationId))
                {
                    _leaseTrackers.Remove(authorizationId);
                }
            }
        }
    }

    private void ScheduleExpiredCleanup(Guid authorizationId)
    {
        var cleanup = EnqueueMutationAsync(
            () => CleanupExpiredCoreAsync(authorizationId),
            CancellationToken.None);
        _ = ObserveExpiredCleanupAsync(authorizationId, cleanup);
    }

    private async Task ObserveExpiredCleanupAsync(
        Guid authorizationId,
        ValueTask<AuthorizationMutationResult> cleanup)
    {
        try
        {
            await cleanup;
        }
        finally
        {
            lock (_leaseGate)
            {
                _expiredCleanupPending.Remove(authorizationId);
            }
        }
    }

    private ValueTask<AuthorizationMutationResult> EnqueueMutationAsync(
        Func<Task<AuthorizationMutationResult>> operation,
        CancellationToken cancellationToken) =>
        EnqueueAsync(
            operation,
            failure => new AuthorizationMutationResult(failure, CreateAdministrationSnapshot()),
            cancellationToken);

    private ValueTask<T> EnqueueAsync<T>(
        Func<Task<T>> operation,
        Func<AuthorizationFailure, T> failureFactory,
        CancellationToken cancellationToken)
    {
        if (Volatile.Read(ref _disposeStarted) != 0)
        {
            return ValueTask.FromResult(failureFactory(AuthorizationFailure.Disposed));
        }

        var command = new Command<T>(operation, failureFactory, cancellationToken);
        if (!_commands.Writer.TryWrite(command))
        {
            command.Cancel(AuthorizationFailure.QueueFull);
        }

        return new ValueTask<T>(command.Completion);
    }

    private async Task ProcessCommandsAsync()
    {
        await foreach (var command in _commands.Reader.ReadAllAsync())
        {
            if (Volatile.Read(ref _disposeStarted) != 0)
            {
                command.Cancel(AuthorizationFailure.Disposed);
                continue;
            }

            if (!command.TryStart())
            {
                command.Cancel(AuthorizationFailure.Canceled);
                continue;
            }

            await command.ExecuteAsync();
        }
    }

    private void Publish(AuthorizationDocument document)
    {
        lock (_leaseGate)
        {
            _document = document;
            Volatile.Write(ref _snapshot, new AuthorizationStateSnapshot(document.Authorizations));
        }
    }

    private AuthorizationMutationResult MutationSucceeded() =>
        new(AuthorizationFailure.None, CreateAdministrationSnapshot());

    private AuthorizationMutationResult MutationFailed(AuthorizationFailure failure) =>
        new(failure, CreateAdministrationSnapshot());

    private AuthorizationAdministrationSnapshot CreateAdministrationSnapshot() =>
        new(
            Volatile.Read(ref _snapshot).Authorizations
                .Select(AuthorizationMetadata.FromRecord)
                .ToImmutableArray());

    private interface ICommand
    {
        Task ExecuteAsync();

        bool TryStart();

        void Cancel(AuthorizationFailure failure);
    }

    private sealed class Command<T> : ICommand
    {
        private readonly TaskCompletionSource<T> _completion =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private Func<Task<T>>? _operation;
        private Func<AuthorizationFailure, T>? _failureFactory;
        private CancellationTokenRegistration _cancellationRegistration;
        private int _state;

        public Command(
            Func<Task<T>> operation,
            Func<AuthorizationFailure, T> failureFactory,
            CancellationToken cancellationToken)
        {
            _operation = operation;
            _failureFactory = failureFactory;
            _cancellationRegistration = cancellationToken.UnsafeRegister(
                static state => ((Command<T>)state!).CancelFromCaller(),
                this);

            if (Volatile.Read(ref _state) == 2)
            {
                _cancellationRegistration.Dispose();
            }
        }

        public Task<T> Completion => _completion.Task;

        public bool TryStart() =>
            Interlocked.CompareExchange(ref _state, 1, 0) == 0;

        public async Task ExecuteAsync()
        {
            var operation = Interlocked.Exchange(ref _operation, null);
            try
            {
                _completion.TrySetResult(await operation!());
            }
            catch (Exception exception)
            {
                _completion.TrySetException(exception);
            }
            finally
            {
                Interlocked.Exchange(ref _failureFactory, null);
                Volatile.Write(ref _state, 2);
                _cancellationRegistration.Dispose();
            }
        }

        public void Cancel(AuthorizationFailure failure)
        {
            if (Interlocked.CompareExchange(ref _state, 2, 0) != 0)
            {
                if (Volatile.Read(ref _state) == 2)
                {
                    _cancellationRegistration.Dispose();
                }

                return;
            }

            CompleteFailure(failure);
            _cancellationRegistration.Dispose();
        }

        private void CancelFromCaller()
        {
            if (Interlocked.CompareExchange(ref _state, 2, 0) == 0)
            {
                CompleteFailure(AuthorizationFailure.Canceled);
            }
        }

        private void CompleteFailure(AuthorizationFailure failure)
        {
            Interlocked.Exchange(ref _operation, null);
            var failureFactory = Interlocked.Exchange(ref _failureFactory, null);
            _completion.TrySetResult(failureFactory!(failure));
        }
    }

    private sealed class LeaseTracker
    {
        public CancellationTokenSource RevocationSource { get; } = new();

        public TaskCompletionSource Drained { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public int Count { get; set; }

        public void CancelCallbacks()
        {
            try
            {
                RevocationSource.Cancel(throwOnFirstException: false);
            }
            catch (AggregateException)
            {
                // Lease callbacks are external code; revocation must continue.
            }
        }
    }
}
