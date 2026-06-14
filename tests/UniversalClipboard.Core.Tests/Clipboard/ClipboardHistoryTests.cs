using System.Collections.Concurrent;
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

    [Fact]
    public async Task Concurrent_readers_and_writers_observe_consistent_bounded_snapshots()
    {
        const int writerCount = 8;
        const int addsPerWriter = 2_000;
        const int readerCount = 4;
        const int readsPerReader = 8_000;

        var history = new ClipboardHistory();
        var failures = new ConcurrentQueue<string>();
        using var start = new ManualResetEventSlim();

        var writers = Enumerable.Range(0, writerCount)
            .Select(writer => Task.Run(() =>
            {
                start.Wait();

                for (var index = 0; index < addsPerWriter; index++)
                {
                    try
                    {
                        var result = history.Add($"{writer}:{index}");
                        ValidateSnapshot(result.Snapshot, failures);

                        if (!result.Snapshot.Items.Contains(result.AddedItem))
                        {
                            failures.Enqueue("Add result snapshot did not contain its added item.");
                        }
                    }
                    catch (Exception exception)
                    {
                        failures.Enqueue(exception.ToString());
                    }
                }
            }))
            .ToArray();

        var readers = Enumerable.Range(0, readerCount)
            .Select(_ => Task.Run(() =>
            {
                start.Wait();

                for (var index = 0; index < readsPerReader; index++)
                {
                    try
                    {
                        ValidateSnapshot(history.Snapshot, failures);
                    }
                    catch (Exception exception)
                    {
                        failures.Enqueue(exception.ToString());
                    }
                }
            }))
            .ToArray();

        start.Set();
        await Task.WhenAll(writers.Concat(readers));

        failures.Should().BeEmpty();
        history.Snapshot.Version.Should().Be((ulong)(writerCount * addsPerWriter));
        history.Snapshot.Items.Should().HaveCount(ClipboardHistory.Capacity);
    }

    private static void ValidateSnapshot(
        ClipboardSnapshot snapshot,
        ConcurrentQueue<string> failures)
    {
        if (snapshot.Items.Length > ClipboardHistory.Capacity)
        {
            failures.Enqueue($"Snapshot contained {snapshot.Items.Length} items.");
        }

        if (snapshot.Items.Select(item => item.Id).Distinct().Count() != snapshot.Items.Length)
        {
            failures.Enqueue("Snapshot contained duplicate item IDs.");
        }

        var expectedItemCount = (int)Math.Min(
            snapshot.Version,
            (ulong)ClipboardHistory.Capacity);
        if (snapshot.Items.Length != expectedItemCount)
        {
            failures.Enqueue(
                $"Version {snapshot.Version} snapshot contained {snapshot.Items.Length} items.");
        }
    }
}
