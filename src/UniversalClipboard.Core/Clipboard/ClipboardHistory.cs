using System.Collections.Immutable;

namespace UniversalClipboard.Core.Clipboard;

public sealed class ClipboardHistory
{
    public const int Capacity = 3;

    private readonly object _gate = new();
    private readonly List<ClipboardItem> _items = [];
    private readonly TimeProvider _timeProvider;
    private ClipboardSnapshot _snapshot;
    private ulong _version;

    public ClipboardHistory(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        InstanceId = Guid.NewGuid();
        _snapshot = new ClipboardSnapshot(
            InstanceId,
            0,
            ImmutableArray<ClipboardItem>.Empty);
    }

    public Guid InstanceId { get; }

    public ClipboardSnapshot Snapshot => Volatile.Read(ref _snapshot);

    public HistoryAddResult Add(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        var item = new ClipboardItem(
            Guid.NewGuid(),
            _timeProvider.GetUtcNow().ToUniversalTime(),
            text);

        return Add(item);
    }

    public HistoryAddResult Add(ClipboardItem item)
    {
        ArgumentNullException.ThrowIfNull(item);

        lock (_gate)
        {
            _items.Insert(0, item);

            ClipboardItem? evictedItem = null;
            if (_items.Count > Capacity)
            {
                evictedItem = _items[^1];
                _items.RemoveAt(_items.Count - 1);
            }

            _version++;
            var snapshot = PublishSnapshot();
            return new HistoryAddResult(item, evictedItem, snapshot);
        }
    }

    public HistoryWithdrawResult Withdraw(Guid id)
    {
        lock (_gate)
        {
            var index = _items.FindIndex(item => item.Id == id);
            if (index < 0)
            {
                return new HistoryWithdrawResult(false, null, _snapshot);
            }

            var item = _items[index];
            _items.RemoveAt(index);
            _version++;

            var snapshot = PublishSnapshot();
            return new HistoryWithdrawResult(true, item, snapshot);
        }
    }

    private ClipboardSnapshot PublishSnapshot()
    {
        var snapshot = new ClipboardSnapshot(
            InstanceId,
            _version,
            _items.ToImmutableArray());
        Volatile.Write(ref _snapshot, snapshot);
        return snapshot;
    }
}
