namespace UniversalClipboard.App.Web;

internal sealed class RequestRateLimiter
{
    private readonly object _gate = new();
    private readonly TimeProvider _timeProvider;
    private readonly TimeSpan _window;
    private readonly int _perKeyLimit;
    private readonly int? _processLimit;
    private readonly Dictionary<string, Queue<DateTimeOffset>> _perKey = new(StringComparer.Ordinal);
    private readonly Queue<DateTimeOffset> _process = new();

    private RequestRateLimiter(
        TimeProvider timeProvider,
        TimeSpan window,
        int perKeyLimit,
        int? processLimit)
    {
        _timeProvider = timeProvider;
        _window = window;
        _perKeyLimit = perKeyLimit;
        _processLimit = processLimit;
    }

    public static RequestRateLimiter CreatePairing(TimeProvider timeProvider) =>
        new(timeProvider, TimeSpan.FromMinutes(1), perKeyLimit: 5, processLimit: 20);

    public static RequestRateLimiter CreateClips(TimeProvider timeProvider) =>
        new(timeProvider, TimeSpan.FromSeconds(1), perKeyLimit: 2, processLimit: null);

    internal int TrackedKeyCount
    {
        get
        {
            lock (_gate)
            {
                return _perKey.Count;
            }
        }
    }

    public bool TryAcquire(string key, out int retryAfterSeconds)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(key);
        var now = _timeProvider.GetUtcNow();

        lock (_gate)
        {
            RemoveExpired(_process, now);
            PruneExpiredKeys(now);
            _perKey.TryGetValue(key, out var keyAttempts);

            if (keyAttempts is not null && keyAttempts.Count >= _perKeyLimit)
            {
                retryAfterSeconds = GetRetryAfter(keyAttempts, now);
                return false;
            }

            if (_processLimit is { } processLimit && _process.Count >= processLimit)
            {
                retryAfterSeconds = GetRetryAfter(_process, now);
                return false;
            }

            if (keyAttempts is null)
            {
                keyAttempts = new Queue<DateTimeOffset>();
                _perKey.Add(key, keyAttempts);
            }

            keyAttempts.Enqueue(now);
            if (_processLimit.HasValue)
            {
                _process.Enqueue(now);
            }

            retryAfterSeconds = 0;
            return true;
        }
    }

    private void PruneExpiredKeys(DateTimeOffset now)
    {
        foreach (var (key, attempts) in _perKey.ToArray())
        {
            RemoveExpired(attempts, now);
            if (attempts.Count == 0)
            {
                _perKey.Remove(key);
            }
        }
    }

    private void RemoveExpired(Queue<DateTimeOffset> attempts, DateTimeOffset now)
    {
        while (attempts.TryPeek(out var oldest) && oldest + _window <= now)
        {
            attempts.Dequeue();
        }
    }

    private int GetRetryAfter(Queue<DateTimeOffset> attempts, DateTimeOffset now)
    {
        var remaining = attempts.Peek() + _window - now;
        return Math.Max(1, (int)Math.Ceiling(remaining.TotalSeconds));
    }
}
