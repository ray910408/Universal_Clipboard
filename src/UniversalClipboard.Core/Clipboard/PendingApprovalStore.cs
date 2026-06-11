using System.Collections.Immutable;
using System.Text;

namespace UniversalClipboard.Core.Clipboard;

public sealed record PendingApprovalSnapshot(
    ImmutableArray<ClipboardItem> Items,
    long Utf8ByteCount);

public sealed record PendingAddResult(
    bool IsStored,
    ClipboardItem AddedItem,
    ImmutableArray<ClipboardItem> EvictedItems,
    PendingApprovalSnapshot Snapshot);

public sealed record PendingTakeResult(
    bool Found,
    ClipboardItem? Item,
    PendingApprovalSnapshot Snapshot);

public sealed class PendingApprovalStore
{
    public const int MaxCount = 3;
    public const long MaxUtf8Bytes = 3L * 1024 * 1024;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    private readonly List<StoredItem> _items = [];
    private long _utf8ByteCount;

    public PendingApprovalSnapshot Snapshot => CreateSnapshot();

    public PendingAddResult Add(ClipboardItem item)
    {
        ArgumentNullException.ThrowIfNull(item);

        var storedItem = new StoredItem(item, StrictUtf8.GetByteCount(item.Text));
        _items.Add(storedItem);
        _utf8ByteCount += storedItem.Utf8ByteCount;

        var evicted = ImmutableArray.CreateBuilder<ClipboardItem>();
        while (_items.Count > MaxCount || _utf8ByteCount > MaxUtf8Bytes)
        {
            var oldest = _items[0];
            _items.RemoveAt(0);
            _utf8ByteCount -= oldest.Utf8ByteCount;
            evicted.Add(oldest.Item);
        }

        return new PendingAddResult(
            _items.Any(stored => stored.Item.Id == item.Id),
            item,
            evicted.ToImmutable(),
            CreateSnapshot());
    }

    public PendingTakeResult Allow(Guid id) => Take(id);

    public PendingTakeResult Discard(Guid id) => Take(id);

    private PendingTakeResult Take(Guid id)
    {
        var index = _items.FindIndex(stored => stored.Item.Id == id);
        if (index < 0)
        {
            return new PendingTakeResult(false, null, CreateSnapshot());
        }

        var storedItem = _items[index];
        _items.RemoveAt(index);
        _utf8ByteCount -= storedItem.Utf8ByteCount;

        return new PendingTakeResult(true, storedItem.Item, CreateSnapshot());
    }

    private PendingApprovalSnapshot CreateSnapshot() =>
        new(_items.Select(stored => stored.Item).ToImmutableArray(), _utf8ByteCount);

    private sealed record StoredItem(ClipboardItem Item, int Utf8ByteCount);
}
