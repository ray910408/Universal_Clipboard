using System.Collections.Immutable;

namespace UniversalClipboard.Core.Clipboard;

public enum ClipboardReadStatus
{
    Success,
    NoUnicodeText,
    Failed,
}

public sealed record ClipboardReadResult(
    ClipboardReadStatus Status,
    string? Text)
{
    public static ClipboardReadResult Success(string text) =>
        new(ClipboardReadStatus.Success, text);

    public static ClipboardReadResult NoUnicodeText() =>
        new(ClipboardReadStatus.NoUnicodeText, null);

    public static ClipboardReadResult Failed() =>
        new(ClipboardReadStatus.Failed, null);
}

public enum ClipboardCaptureOutcome
{
    Shared,
    PendingApproval,
    NoUnicodeText,
    ReadFailed,
    Duplicate,
    Empty,
    InvalidUtf16,
    OverLimit,
    RejectedReadStatus,
}

public sealed record ClipboardCaptureResult(
    ClipboardCaptureOutcome Outcome,
    ClipboardItem? Item,
    string? SensitiveRule,
    ImmutableArray<ClipboardItem> EvictedItems);

public sealed record PipelineAllowResult(
    bool Found,
    ClipboardItem? Item,
    ClipboardItem? EvictedItem,
    ClipboardSnapshot HistorySnapshot,
    PendingApprovalSnapshot PendingSnapshot);

public sealed class ClipboardCapturePipeline
{
    private readonly ClipboardHistory _history;
    private readonly PendingApprovalStore _pending;
    private readonly StrictUtf8TextValidator _validator;
    private readonly SensitiveTextClassifier _classifier;
    private readonly TimeProvider _timeProvider;
    private bool _hasPreviousText;
    private string? _previousText;

    public ClipboardCapturePipeline(
        ClipboardHistory? history = null,
        PendingApprovalStore? pending = null,
        StrictUtf8TextValidator? validator = null,
        SensitiveTextClassifier? classifier = null,
        TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
        _history = history ?? new ClipboardHistory(_timeProvider);
        _pending = pending ?? new PendingApprovalStore();
        _validator = validator ?? new StrictUtf8TextValidator();
        _classifier = classifier ?? new SensitiveTextClassifier();
    }

    public ClipboardSnapshot HistorySnapshot => _history.Snapshot;

    public PendingApprovalSnapshot PendingSnapshot => _pending.Snapshot;

    public ClipboardCaptureResult Capture(ClipboardReadResult readResult)
    {
        ArgumentNullException.ThrowIfNull(readResult);

        switch (readResult.Status)
        {
            case ClipboardReadStatus.Success:
                break;
            case ClipboardReadStatus.NoUnicodeText:
                return Result(ClipboardCaptureOutcome.NoUnicodeText);
            case ClipboardReadStatus.Failed:
                return Result(ClipboardCaptureOutcome.ReadFailed);
            default:
                return Result(ClipboardCaptureOutcome.RejectedReadStatus);
        }

        var text = readResult.Text
            ?? throw new ArgumentException("A successful clipboard read must contain text.", nameof(readResult));

        if (_hasPreviousText && string.Equals(text, _previousText, StringComparison.Ordinal))
        {
            return Result(ClipboardCaptureOutcome.Duplicate);
        }

        _hasPreviousText = true;
        _previousText = text;

        if (text.Length == 0)
        {
            return Result(ClipboardCaptureOutcome.Empty);
        }

        var validation = _validator.Validate(text);
        if (validation.Status == TextValidationStatus.InvalidUtf16)
        {
            return Result(ClipboardCaptureOutcome.InvalidUtf16);
        }

        if (validation.Status == TextValidationStatus.OverLimit)
        {
            return Result(ClipboardCaptureOutcome.OverLimit);
        }

        var item = new ClipboardItem(
            Guid.NewGuid(),
            _timeProvider.GetUtcNow().ToUniversalTime(),
            text);
        var sensitiveRule = _classifier.Classify(text);

        if (sensitiveRule is not null)
        {
            var pendingResult = _pending.Add(item);
            return new ClipboardCaptureResult(
                ClipboardCaptureOutcome.PendingApproval,
                item,
                sensitiveRule,
                pendingResult.EvictedItems);
        }

        var historyResult = _history.Add(item);
        var evictedItems = historyResult.EvictedItem is null
            ? ImmutableArray<ClipboardItem>.Empty
            : ImmutableArray.Create(historyResult.EvictedItem);

        return new ClipboardCaptureResult(
            ClipboardCaptureOutcome.Shared,
            item,
            null,
            evictedItems);
    }

    public PipelineAllowResult Allow(Guid id)
    {
        var pendingResult = _pending.Allow(id);
        if (!pendingResult.Found)
        {
            return new PipelineAllowResult(
                false,
                null,
                null,
                _history.Snapshot,
                pendingResult.Snapshot);
        }

        var historyResult = _history.Add(pendingResult.Item!);
        return new PipelineAllowResult(
            true,
            pendingResult.Item,
            historyResult.EvictedItem,
            historyResult.Snapshot,
            pendingResult.Snapshot);
    }

    public PendingTakeResult Discard(Guid id) => _pending.Discard(id);

    public HistoryWithdrawResult Withdraw(Guid id) => _history.Withdraw(id);

    private static ClipboardCaptureResult Result(ClipboardCaptureOutcome outcome) =>
        new(outcome, null, null, ImmutableArray<ClipboardItem>.Empty);
}
