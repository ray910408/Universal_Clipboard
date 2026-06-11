using System.Text;

namespace UniversalClipboard.Core.Clipboard;

public enum TextValidationStatus
{
    Valid,
    InvalidUtf16,
    OverLimit,
}

public readonly record struct TextValidationResult(
    TextValidationStatus Status,
    int? Utf8ByteCount);

public sealed class StrictUtf8TextValidator
{
    public const int MaxUtf8Bytes = 1_048_576;

    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    public TextValidationResult Validate(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        try
        {
            var byteCount = StrictUtf8.GetByteCount(text);
            var status = byteCount <= MaxUtf8Bytes
                ? TextValidationStatus.Valid
                : TextValidationStatus.OverLimit;

            return new TextValidationResult(status, byteCount);
        }
        catch (EncoderFallbackException)
        {
            return new TextValidationResult(TextValidationStatus.InvalidUtf16, null);
        }
    }
}
