using FluentAssertions;
using UniversalClipboard.Core.Clipboard;

namespace UniversalClipboard.Core.Tests.Clipboard;

public sealed class ClipboardHistoryTests
{
    [Fact]
    public void New_history_has_random_instance_id_and_zero_version()
    {
        var first = new ClipboardHistory().Snapshot;
        var second = new ClipboardHistory().Snapshot;

        first.InstanceId.Should().NotBe(Guid.Empty);
        second.InstanceId.Should().NotBe(Guid.Empty);
        first.InstanceId.Should().NotBe(second.InstanceId);
        first.Version.Should().Be(0);
        first.Items.Should().BeEmpty();
    }

    [Fact]
    public void Add_creates_random_item_with_utc_timestamp_and_exact_text()
    {
        var before = DateTimeOffset.UtcNow;
        var history = new ClipboardHistory();

        var first = history.Add(" first\r\n");
        var second = history.Add("second");
        var after = DateTimeOffset.UtcNow;

        first.AddedItem.Id.Should().NotBe(Guid.Empty);
        second.AddedItem.Id.Should().NotBe(first.AddedItem.Id);
        first.AddedItem.CapturedAtUtc.Offset.Should().Be(TimeSpan.Zero);
        first.AddedItem.CapturedAtUtc.Should().BeOnOrAfter(before).And.BeOnOrBefore(after);
        first.AddedItem.Text.Should().Be(" first\r\n");
        second.Snapshot.Items.Select(item => item.Text).Should().Equal("second", " first\r\n");
        second.Snapshot.Version.Should().Be(2);
    }

    [Fact]
    public void Add_evicts_oldest_at_three_items_and_increments_version_once()
    {
        var history = new ClipboardHistory();
        history.Add("one");
        history.Add("two");
        history.Add("three");

        var result = history.Add("four");

        result.Snapshot.Version.Should().Be(4);
        result.Snapshot.Items.Select(item => item.Text).Should().Equal("four", "three", "two");
        result.EvictedItem!.Text.Should().Be("one");
    }

    [Fact]
    public void Withdraw_increments_only_when_item_exists()
    {
        var history = new ClipboardHistory();
        var added = history.Add("one").AddedItem;

        var missing = history.Withdraw(Guid.NewGuid());
        var removed = history.Withdraw(added.Id);

        missing.WasWithdrawn.Should().BeFalse();
        missing.Snapshot.Version.Should().Be(1);
        removed.WasWithdrawn.Should().BeTrue();
        removed.WithdrawnItem.Should().Be(added);
        removed.Snapshot.Version.Should().Be(2);
        removed.Snapshot.Items.Should().BeEmpty();
    }

    [Fact]
    public void Snapshots_remain_immutable_after_later_mutations()
    {
        var history = new ClipboardHistory();
        var original = history.Add("one").Snapshot;

        history.Add("two");
        history.Withdraw(original.Items[0].Id);

        original.Version.Should().Be(1);
        original.Items.Select(item => item.Text).Should().Equal("one");
    }
}
