using FluentAssertions;
using UniversalClipboard.Core.Clipboard;

namespace UniversalClipboard.Core.Tests.Clipboard;

public sealed class PendingApprovalStoreTests
{
    [Fact]
    public void Add_evicts_oldest_item_when_four_items_are_pending()
    {
        var store = new PendingApprovalStore();
        var items = Enumerable.Range(1, 4).Select(index => Item($"item-{index}")).ToArray();

        store.Add(items[0]);
        store.Add(items[1]);
        store.Add(items[2]);
        var result = store.Add(items[3]);

        result.EvictedItems.Should().Equal(items[0]);
        result.Snapshot.Items.Should().Equal(items[1], items[2], items[3]);
        result.Snapshot.Utf8ByteCount.Should().Be(18);
    }

    [Fact]
    public void Add_evicts_fifo_until_total_is_at_most_three_mib()
    {
        var store = new PendingApprovalStore();
        var first = Item(new string('a', 1_600_000));
        var second = Item(new string('b', 1_600_000));
        var third = Item("small");

        store.Add(first);
        var secondResult = store.Add(second);
        var thirdResult = store.Add(third);

        secondResult.EvictedItems.Should().Equal(first);
        thirdResult.EvictedItems.Should().BeEmpty();
        thirdResult.Snapshot.Items.Should().Equal(second, third);
        thirdResult.Snapshot.Utf8ByteCount.Should().Be(1_600_005);
    }

    [Fact]
    public void Add_keeps_three_items_at_exact_byte_budget()
    {
        var store = new PendingApprovalStore();
        var items = new[]
        {
            Item(new string('a', 1_048_576)),
            Item(new string('b', 1_048_576)),
            Item(new string('c', 1_048_576)),
        };

        store.Add(items[0]);
        store.Add(items[1]);
        var result = store.Add(items[2]);

        result.EvictedItems.Should().BeEmpty();
        result.Snapshot.Items.Should().Equal(items);
        result.Snapshot.Utf8ByteCount.Should().Be(PendingApprovalStore.MaxUtf8Bytes);
    }

    [Fact]
    public void Allow_removes_and_returns_item_by_id()
    {
        var store = new PendingApprovalStore();
        var item = Item("secret");
        store.Add(item);

        var result = store.Allow(item.Id);

        result.Found.Should().BeTrue();
        result.Item.Should().Be(item);
        result.Snapshot.Items.Should().BeEmpty();
    }

    [Fact]
    public void Discard_removes_item_and_missing_id_is_noop()
    {
        var store = new PendingApprovalStore();
        var item = Item("secret");
        store.Add(item);

        var missing = store.Discard(Guid.NewGuid());
        var result = store.Discard(item.Id);

        missing.Found.Should().BeFalse();
        missing.Snapshot.Items.Should().Equal(item);
        result.Found.Should().BeTrue();
        result.Item.Should().Be(item);
        result.Snapshot.Items.Should().BeEmpty();
    }

    private static ClipboardItem Item(string text) =>
        new(Guid.NewGuid(), DateTimeOffset.UtcNow, text);
}
