using FluentAssertions;
using UniversalClipboard.Core.Clipboard;

namespace UniversalClipboard.Core.Tests.Clipboard;

public sealed class ClipboardCapturePipelineTests
{
    [Fact]
    public void Normal_text_is_added_to_shared_history()
    {
        var pipeline = new ClipboardCapturePipeline();

        var result = pipeline.Capture(ClipboardReadResult.Success("hello"));

        result.Outcome.Should().Be(ClipboardCaptureOutcome.Shared);
        result.Item!.Text.Should().Be("hello");
        pipeline.HistorySnapshot.Items.Should().Equal(result.Item);
        pipeline.PendingSnapshot.Items.Should().BeEmpty();
    }

    [Fact]
    public void Sensitive_text_is_added_to_pending_approval()
    {
        var pipeline = new ClipboardCapturePipeline();
        var text = $"ghp_{new string('A', 36)}";

        var result = pipeline.Capture(ClipboardReadResult.Success(text));

        result.Outcome.Should().Be(ClipboardCaptureOutcome.PendingApproval);
        result.SensitiveRule.Should().Be(SensitiveTextClassifier.GitHubTokenRule);
        pipeline.PendingSnapshot.Items.Should().Equal(result.Item!);
        pipeline.HistorySnapshot.Items.Should().BeEmpty();
    }

    [Fact]
    public void Read_failure_and_no_unicode_do_not_update_previous_text()
    {
        var pipeline = new ClipboardCapturePipeline();
        pipeline.Capture(ClipboardReadResult.Success("same"));

        pipeline.Capture(ClipboardReadResult.Failed()).Outcome
            .Should().Be(ClipboardCaptureOutcome.ReadFailed);
        pipeline.Capture(ClipboardReadResult.NoUnicodeText()).Outcome
            .Should().Be(ClipboardCaptureOutcome.NoUnicodeText);
        var result = pipeline.Capture(ClipboardReadResult.Success("same"));

        result.Outcome.Should().Be(ClipboardCaptureOutcome.Duplicate);
        pipeline.HistorySnapshot.Items.Should().HaveCount(1);
    }

    [Theory]
    [MemberData(nameof(RejectedTextRows))]
    public void Empty_invalid_and_over_limit_text_update_previous(
        string rejectedText,
        ClipboardCaptureOutcome expected)
    {
        var pipeline = new ClipboardCapturePipeline();
        pipeline.Capture(ClipboardReadResult.Success("before"));

        var rejection = pipeline.Capture(ClipboardReadResult.Success(rejectedText));
        var sameRejection = pipeline.Capture(ClipboardReadResult.Success(rejectedText));
        var beforeAgain = pipeline.Capture(ClipboardReadResult.Success("before"));

        rejection.Outcome.Should().Be(expected);
        sameRejection.Outcome.Should().Be(ClipboardCaptureOutcome.Duplicate);
        beforeAgain.Outcome.Should().Be(ClipboardCaptureOutcome.Shared);
    }

    public static TheoryData<string, ClipboardCaptureOutcome> RejectedTextRows =>
        new()
        {
            { string.Empty, ClipboardCaptureOutcome.Empty },
            { new string('a', StrictUtf8TextValidator.MaxUtf8Bytes + 1), ClipboardCaptureOutcome.OverLimit },
        };

    [Fact]
    public void Invalid_utf16_updates_previous_text()
    {
        var pipeline = new ClipboardCapturePipeline();
        var invalidText = new string('\uD800', 1);
        pipeline.Capture(ClipboardReadResult.Success("before"));

        var rejection = pipeline.Capture(ClipboardReadResult.Success(invalidText));
        var sameRejection = pipeline.Capture(ClipboardReadResult.Success(invalidText));
        var beforeAgain = pipeline.Capture(ClipboardReadResult.Success("before"));

        rejection.Outcome.Should().Be(ClipboardCaptureOutcome.InvalidUtf16);
        sameRejection.Outcome.Should().Be(ClipboardCaptureOutcome.Duplicate);
        beforeAgain.Outcome.Should().Be(ClipboardCaptureOutcome.Shared);
    }

    [Fact]
    public void Exact_ordinal_duplicate_is_ignored()
    {
        var pipeline = new ClipboardCapturePipeline();
        pipeline.Capture(ClipboardReadResult.Success("Case"));

        var duplicate = pipeline.Capture(ClipboardReadResult.Success("Case"));
        var differentCase = pipeline.Capture(ClipboardReadResult.Success("case"));

        duplicate.Outcome.Should().Be(ClipboardCaptureOutcome.Duplicate);
        differentCase.Outcome.Should().Be(ClipboardCaptureOutcome.Shared);
        pipeline.HistorySnapshot.Items.Select(item => item.Text).Should().Equal("case", "Case");
    }

    [Fact]
    public void Discard_does_not_clear_previous_text()
    {
        var pipeline = new ClipboardCapturePipeline();
        var text = $"ghp_{new string('B', 36)}";
        var captured = pipeline.Capture(ClipboardReadResult.Success(text));

        var discarded = pipeline.Discard(captured.Item!.Id);
        var repeated = pipeline.Capture(ClipboardReadResult.Success(text));

        discarded.Found.Should().BeTrue();
        repeated.Outcome.Should().Be(ClipboardCaptureOutcome.Duplicate);
        pipeline.PendingSnapshot.Items.Should().BeEmpty();
    }

    [Fact]
    public void Allow_moves_same_item_to_shared_history_without_clearing_previous()
    {
        var pipeline = new ClipboardCapturePipeline();
        var text = $"AKIA{new string('7', 16)}";
        var captured = pipeline.Capture(ClipboardReadResult.Success(text));

        var allowed = pipeline.Allow(captured.Item!.Id);
        var repeated = pipeline.Capture(ClipboardReadResult.Success(text));

        allowed.Found.Should().BeTrue();
        allowed.Item.Should().Be(captured.Item);
        pipeline.HistorySnapshot.Items.Should().Equal(captured.Item);
        pipeline.PendingSnapshot.Items.Should().BeEmpty();
        repeated.Outcome.Should().Be(ClipboardCaptureOutcome.Duplicate);
    }

    [Fact]
    public void Withdraw_does_not_clear_previous_text()
    {
        var pipeline = new ClipboardCapturePipeline();
        var captured = pipeline.Capture(ClipboardReadResult.Success("shared"));

        var withdrawn = pipeline.Withdraw(captured.Item!.Id);
        var repeated = pipeline.Capture(ClipboardReadResult.Success("shared"));

        withdrawn.WasWithdrawn.Should().BeTrue();
        repeated.Outcome.Should().Be(ClipboardCaptureOutcome.Duplicate);
        pipeline.HistorySnapshot.Items.Should().BeEmpty();
    }

    [Fact]
    public void History_eviction_does_not_replace_previous_with_evicted_text()
    {
        var pipeline = new ClipboardCapturePipeline();
        pipeline.Capture(ClipboardReadResult.Success("one"));
        pipeline.Capture(ClipboardReadResult.Success("two"));
        pipeline.Capture(ClipboardReadResult.Success("three"));

        var fourth = pipeline.Capture(ClipboardReadResult.Success("four"));
        var repeated = pipeline.Capture(ClipboardReadResult.Success("four"));

        fourth.EvictedItems.Select(item => item.Text).Should().Equal("one");
        repeated.Outcome.Should().Be(ClipboardCaptureOutcome.Duplicate);
    }
}
