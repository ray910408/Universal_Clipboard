namespace UniversalClipboard.Core.Clipboard;

public sealed class SensitiveTextClassifier
{
    public const string PemPrivateKeyRule = "pem-private-key";
    public const string GitHubTokenRule = "github-token";
    public const string AwsAccessKeyRule = "aws-access-key";

    private static readonly string[] PemTypes =
    [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
    ];

    public string? Classify(string text)
    {
        ArgumentNullException.ThrowIfNull(text);

        if (ContainsPemPrivateKey(text))
        {
            return PemPrivateKeyRule;
        }

        if (ContainsGitHubToken(text))
        {
            return GitHubTokenRule;
        }

        return ContainsAwsAccessKey(text) ? AwsAccessKeyRule : null;
    }

    private static bool ContainsPemPrivateKey(string text)
    {
        foreach (var pemType in PemTypes)
        {
            var header = $"-----BEGIN {pemType}-----";
            var footer = $"-----END {pemType}-----";
            var hasHeader = false;
            var lineStart = 0;

            while (lineStart >= 0)
            {
                if (!hasHeader && IsLineMarker(text, lineStart, header))
                {
                    hasHeader = true;
                }
                else if (hasHeader && IsLineMarker(text, lineStart, footer))
                {
                    return true;
                }

                lineStart = FindNextLineStart(text, lineStart);
            }
        }

        return false;
    }

    private static bool IsLineMarker(string text, int lineStart, string marker) =>
        lineStart + marker.Length <= text.Length
        && text.AsSpan(lineStart, marker.Length).SequenceEqual(marker)
        && HasMarkerTerminator(text, lineStart + marker.Length);

    private static int FindNextLineStart(string text, int currentIndex)
    {
        var newlineIndex = text.IndexOf('\n', currentIndex);
        return newlineIndex < 0 ? -1 : newlineIndex + 1;
    }

    private static bool HasMarkerTerminator(string text, int markerEnd)
    {
        if (markerEnd == text.Length)
        {
            return true;
        }

        if (text[markerEnd] == '\n')
        {
            return true;
        }

        return text[markerEnd] == '\r'
            && markerEnd + 1 < text.Length
            && text[markerEnd + 1] == '\n';
    }

    private static bool ContainsGitHubToken(string text)
    {
        const string fineGrainedPrefix = "github_pat_";
        var fineGrainedIndex = text.IndexOf(fineGrainedPrefix, StringComparison.Ordinal);
        while (fineGrainedIndex >= 0)
        {
            var payloadStart = fineGrainedIndex + fineGrainedPrefix.Length;
            var payloadEnd = payloadStart;
            while (payloadEnd < text.Length && IsGitHubFineGrainedTokenCharacter(text[payloadEnd]))
            {
                payloadEnd++;
            }

            // GitHub fine-grained PATs use multiple underscore-delimited base62-ish
            // segments and are substantially longer than classic gh[pousr]_ tokens.
            // Require at least one delimiter in the payload to avoid classifying prose
            // that merely mentions the prefix.
            var payload = text.AsSpan(payloadStart, payloadEnd - payloadStart);
            if (payload.Length is >= 40 and <= 255 && payload.Contains('_'))
            {
                return true;
            }

            fineGrainedIndex = text.IndexOf(
                fineGrainedPrefix,
                Math.Max(payloadEnd, fineGrainedIndex + 1),
                StringComparison.Ordinal);
        }

        for (var index = 0; index + 4 <= text.Length; index++)
        {
            if (text[index] != 'g'
                || text[index + 1] != 'h'
                || !IsGitHubKind(text[index + 2])
                || text[index + 3] != '_')
            {
                continue;
            }

            var payloadEnd = index + 4;
            while (payloadEnd < text.Length && IsAsciiAlphaNumeric(text[payloadEnd]))
            {
                payloadEnd++;
            }

            var payloadLength = payloadEnd - (index + 4);
            if (payloadLength is >= 36 and <= 255)
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsAwsAccessKey(string text)
    {
        const int keyLength = 20;
        ReadOnlySpan<string> prefixes = ["AKIA", "ASIA"];

        for (var index = 0; index + keyLength <= text.Length; index++)
        {
            if (!HasAnyPrefix(text, index, prefixes))
            {
                continue;
            }

            var isValid = true;
            for (var payloadIndex = index + 4; payloadIndex < index + keyLength; payloadIndex++)
            {
                if (!IsUpperAsciiAlphaNumeric(text[payloadIndex]))
                {
                    isValid = false;
                    break;
                }
            }

            if (isValid
                && (index + keyLength == text.Length
                    || !IsUpperAsciiAlphaNumeric(text[index + keyLength])))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsGitHubKind(char value) =>
        value is 'p' or 'o' or 'u' or 's' or 'r';

    private static bool IsGitHubFineGrainedTokenCharacter(char value) =>
        IsAsciiAlphaNumeric(value) || value == '_';

    private static bool HasAnyPrefix(string text, int index, ReadOnlySpan<string> prefixes)
    {
        foreach (var prefix in prefixes)
        {
            if (index + prefix.Length <= text.Length &&
                text.AsSpan(index, prefix.Length).SequenceEqual(prefix))
            {
                return true;
            }
        }

        return false;
    }

    private static bool IsAsciiAlphaNumeric(char value) =>
        value is >= '0' and <= '9'
            or >= 'A' and <= 'Z'
            or >= 'a' and <= 'z';

    private static bool IsUpperAsciiAlphaNumeric(char value) =>
        value is >= '0' and <= '9'
            or >= 'A' and <= 'Z';
}
