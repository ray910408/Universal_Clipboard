namespace UniversalClipboard.Core.Clipboard;

public sealed record ClipboardItem(
    Guid Id,
    DateTimeOffset CapturedAtUtc,
    string Text);
