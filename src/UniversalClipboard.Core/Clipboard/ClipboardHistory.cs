using System.Collections.Immutable;

namespace UniversalClipboard.Core.Clipboard;

public sealed class ClipboardHistory
{
    public const int Capacity = 3;

    private readonly List<ClipboardItem> _items = [];
    private readonly TimeProvider _timeProvider;
    private ulong _version;

    public ClipboardHistory(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        InstanceId = Guid.NewGuid();
    }

    public Guid InstanceId { get; }

    public ClipboardSnapshot Snapshot => CreateSnapshot();

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

        _items.Insert(0, item);

        ClipboardItem? evictedItem = null;
        if (_items.Count > Capacity)
        {
            evictedItem = _items[^1];
            _items.RemoveAt(_items.Count - 1);
        }

        _version++;
        return new HistoryAddResult(item, evictedItem, CreateSnapshot());
    }

    public HistoryWithdrawResult Withdraw(Guid id)
    {
        var index = _items.FindIndex(item => item.Id == id);
        if (index < 0)
        {
            return new HistoryWithdrawResult(false, null, CreateSnapshot());
        }

        var item = _items[index];
        _items.RemoveAt(index);
        _version++;

        return new HistoryWithdrawResult(true, item, CreateSnapshot());
    }

    private ClipboardSnapshot CreateSnapshot() =>
        new(InstanceId, _version, _items.ToImmutableArray());
}
