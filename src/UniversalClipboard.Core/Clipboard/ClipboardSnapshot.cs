using System.Collections.Immutable;

namespace UniversalClipboard.Core.Clipboard;

public sealed record ClipboardSnapshot(
    Guid InstanceId,
    ulong Version,
    ImmutableArray<ClipboardItem> Items);

public sealed record HistoryAddResult(
    ClipboardItem AddedItem,
    ClipboardItem? EvictedItem,
    ClipboardSnapshot Snapshot);

public sealed record HistoryWithdrawResult(
    bool WasWithdrawn,
    ClipboardItem? WithdrawnItem,
    ClipboardSnapshot Snapshot);
