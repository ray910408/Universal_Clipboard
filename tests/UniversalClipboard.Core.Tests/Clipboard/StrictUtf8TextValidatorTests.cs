using FluentAssertions;
using UniversalClipboard.Core.Clipboard;

namespace UniversalClipboard.Core.Tests.Clipboard;

public sealed class StrictUtf8TextValidatorTests
{
    [Theory]
    [InlineData(1_048_575, TextValidationStatus.Valid)]
    [InlineData(1_048_576, TextValidationStatus.Valid)]
    [InlineData(1_048_577, TextValidationStatus.OverLimit)]
    public void Validate_enforces_utf8_byte_limit(int length, TextValidationStatus expected)
    {
        var subject = new StrictUtf8TextValidator();

        var result = subject.Validate(new string('a', length));

        result.Status.Should().Be(expected);
        result.Utf8ByteCount.Should().Be(length);
    }

    [Fact]
    public void Validate_accepts_empty_text()
    {
        var result = new StrictUtf8TextValidator().Validate(string.Empty);

        result.Should().Be(new TextValidationResult(TextValidationStatus.Valid, 0));
    }

    [Fact]
    public void Validate_counts_astral_characters_as_four_utf8_bytes()
    {
        var text = string.Concat(Enumerable.Repeat("\U0001F600", 262_144));

        var result = new StrictUtf8TextValidator().Validate(text);

        result.Should().Be(
            new TextValidationResult(TextValidationStatus.Valid, StrictUtf8TextValidator.MaxUtf8Bytes));
    }

    [Fact]
    public void Validate_rejects_unpaired_surrogates()
    {
        var subject = new StrictUtf8TextValidator();
        var invalidTexts = new[]
        {
            new string('\uD800', 1),
            new string('\uDC00', 1),
            string.Concat("before", new string('\uD800', 1), "after"),
        };

        foreach (var text in invalidTexts)
        {
            var result = subject.Validate(text);

            result.Status.Should().Be(TextValidationStatus.InvalidUtf16);
            result.Utf8ByteCount.Should().BeNull();
        }
    }

    [Fact]
    public void Validate_does_not_change_text_line_endings_or_normalization()
    {
        const string text = " e\u0301\r\nline two\n";
        var pipeline = new ClipboardCapturePipeline();

        var result = pipeline.Capture(ClipboardReadResult.Success(text));

        result.Outcome.Should().Be(ClipboardCaptureOutcome.Shared);
        result.Item!.Text.Should().Be(text);
    }
}
