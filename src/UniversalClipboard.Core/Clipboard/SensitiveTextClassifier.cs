namespace UniversalClipboard.Core.Clipboard;

public sealed class SensitiveTextClassifier
{
    public const string PemPrivateKeyRule = "pem-private-key";
    public const string GitHubTokenRule = "github-token";
    public const string AwsAccessKeyRule = "aws-access-key";
    public const string SlackTokenRule = "slack-token";
    public const string StripeKeyRule = "stripe-key";
    public const string GoogleApiKeyRule = "google-api-key";
    public const string SkApiKeyRule = "sk-api-key";
    public const string JwtRule = "jwt";
    public const string KeywordHighEntropyRule = "keyword-high-entropy";

    public const int MinSecretValueLength = 16;
    public const double MinEntropyRatio = 0.75;

    private const int MaxSecretNameLength = 64;

    private static readonly string[] PemTypes =
    [
        "PRIVATE KEY",
        "RSA PRIVATE KEY",
        "EC PRIVATE KEY",
        "DSA PRIVATE KEY",
        "OPENSSH PRIVATE KEY",
        "ENCRYPTED PRIVATE KEY",
        "PGP PRIVATE KEY BLOCK",
    ];

    private static readonly string[] SlackPrefixes =
        ["xoxb-", "xoxp-", "xoxa-", "xoxr-", "xoxs-", "xoxe-"];

    private static readonly string[] StripePrefixes = ["sk_live_", "rk_live_"];

    private static readonly string[] SecretNameKeywords =
        ["key", "secret", "token", "passw", "pwd", "credential", "auth"];

    private static readonly string[] AuthorizationSchemes = ["Bearer ", "Basic "];

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

        if (ContainsAwsAccessKey(text))
        {
            return AwsAccessKeyRule;
        }

        if (ContainsAnyPrefixedToken(text, SlackPrefixes, 20, 255, requireDigit: true, requireMixedCase: false))
        {
            return SlackTokenRule;
        }

        if (ContainsAnyPrefixedToken(text, StripePrefixes, 24, 255, requireDigit: false, requireMixedCase: false))
        {
            return StripeKeyRule;
        }

        if (ContainsPrefixedToken(text, "AIza", 35, 35, requireDigit: false, requireMixedCase: false))
        {
            return GoogleApiKeyRule;
        }

        // "sk-" also appears inside ordinary words ("task-"), so demand a random-looking payload.
        if (ContainsPrefixedToken(text, "sk-", 32, 512, requireDigit: true, requireMixedCase: true))
        {
            return SkApiKeyRule;
        }

        if (ContainsJwt(text))
        {
            return JwtRule;
        }

        return ContainsKeywordHighEntropyValue(text) ? KeywordHighEntropyRule : null;
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

    private static bool ContainsAnyPrefixedToken(
        string text,
        string[] prefixes,
        int minLength,
        int maxLength,
        bool requireDigit,
        bool requireMixedCase)
    {
        foreach (var prefix in prefixes)
        {
            if (ContainsPrefixedToken(text, prefix, minLength, maxLength, requireDigit, requireMixedCase))
            {
                return true;
            }
        }

        return false;
    }

    private static bool ContainsPrefixedToken(
        string text,
        string prefix,
        int minLength,
        int maxLength,
        bool requireDigit,
        bool requireMixedCase)
    {
        var index = text.IndexOf(prefix, StringComparison.Ordinal);
        while (index >= 0)
        {
            var payloadStart = index + prefix.Length;
            var payloadEnd = payloadStart;
            while (payloadEnd < text.Length && IsTokenCharacter(text[payloadEnd]))
            {
                payloadEnd++;
            }

            var payload = text.AsSpan(payloadStart, payloadEnd - payloadStart);
            if ((index == 0 || !IsTokenCharacter(text[index - 1]))
                && payload.Length >= minLength
                && payload.Length <= maxLength
                && (!requireDigit || payload.ContainsAnyInRange('0', '9'))
                && (!requireMixedCase
                    || (payload.ContainsAnyInRange('A', 'Z') && payload.ContainsAnyInRange('a', 'z'))))
            {
                return true;
            }

            // Every later prefix inside this payload is preceded by a token character,
            // so it cannot pass the boundary check; skipping keeps the scan linear.
            index = text.IndexOf(prefix, Math.Max(payloadEnd, index + 1), StringComparison.Ordinal);
        }

        return false;
    }

    private static bool ContainsJwt(string text)
    {
        const string headerPrefix = "eyJ";
        var index = text.IndexOf(headerPrefix, StringComparison.Ordinal);
        while (index >= 0)
        {
            var headerEnd = SkipBase64Url(text, index);
            if (IsJwtTail(text, index, headerEnd))
            {
                return true;
            }

            // Any later "eyJ" inside this header shares the same tail, so skip past it.
            index = text.IndexOf(headerPrefix, Math.Max(headerEnd, index + 1), StringComparison.Ordinal);
        }

        return false;
    }

    private static bool IsJwtTail(string text, int headerStart, int headerEnd)
    {
        if (headerEnd - headerStart < 10 || headerEnd >= text.Length || text[headerEnd] != '.')
        {
            return false;
        }

        var payloadStart = headerEnd + 1;
        var payloadEnd = SkipBase64Url(text, payloadStart);
        if (payloadEnd - payloadStart < 10
            || !text.AsSpan(payloadStart).StartsWith("eyJ", StringComparison.Ordinal)
            || payloadEnd >= text.Length
            || text[payloadEnd] != '.')
        {
            return false;
        }

        var signatureStart = payloadEnd + 1;
        return SkipBase64Url(text, signatureStart) - signatureStart >= 16;
    }

    private static int SkipBase64Url(string text, int index)
    {
        while (index < text.Length && IsTokenCharacter(text[index]))
        {
            index++;
        }

        return index;
    }

    private static bool ContainsKeywordHighEntropyValue(string text)
    {
        // '=' and ':' end every value, so value spans never overlap and the scan stays linear.
        for (var index = 0; index < text.Length; index++)
        {
            if (text[index] is not ('=' or ':') || !HasSecretName(text, index))
            {
                continue;
            }

            var valueStart = SkipValuePrefix(text, index + 1);
            var valueEnd = valueStart;
            while (valueEnd < text.Length && IsValueCharacter(text[valueEnd]))
            {
                valueEnd++;
            }

            if (IsHighEntropySecret(text.AsSpan(valueStart, valueEnd - valueStart)))
            {
                return true;
            }
        }

        return false;
    }

    private static bool HasSecretName(string text, int separatorIndex)
    {
        var end = separatorIndex;
        while (end > 0 && text[end - 1] is ' ' or '\t')
        {
            end--;
        }

        if (end > 0 && text[end - 1] is '"' or '\'')
        {
            end--;
        }

        var start = end;
        while (start > 0 && end - start < MaxSecretNameLength && IsSecretNameCharacter(text[start - 1]))
        {
            start--;
        }

        var name = text.AsSpan(start, end - start);
        if (name.IsEmpty || name.Contains("public", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        foreach (var keyword in SecretNameKeywords)
        {
            if (name.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private static int SkipValuePrefix(string text, int index)
    {
        // Covers "a = b", "a := b", "a => b", and quoted values.
        while (index < text.Length && text[index] is ' ' or '\t' or '=' or '>')
        {
            index++;
        }

        if (index < text.Length && text[index] is '"' or '\'' or '`')
        {
            index++;
        }

        foreach (var scheme in AuthorizationSchemes)
        {
            if (text.AsSpan(index).StartsWith(scheme, StringComparison.OrdinalIgnoreCase))
            {
                return index + scheme.Length;
            }
        }

        return index;
    }

    private static bool IsHighEntropySecret(ReadOnlySpan<char> value)
    {
        if (value.Length < MinSecretValueLength)
        {
            return false;
        }

        Span<int> counts = stackalloc int[128];
        bool hasUpper = false, hasLower = false, hasDigit = false, allHex = true;
        foreach (var character in value)
        {
            counts[character]++;
            hasUpper |= char.IsAsciiLetterUpper(character);
            hasLower |= char.IsAsciiLetterLower(character);
            hasDigit |= char.IsAsciiDigit(character);
            allHex &= char.IsAsciiHexDigit(character);
        }

        // Paths, URLs, versions, and identifiers rarely mix all three classes; random keys do.
        var looksRandom = allHex
            ? hasDigit && (hasUpper || hasLower)
            : hasUpper && hasLower && hasDigit;
        if (!looksRandom)
        {
            return false;
        }

        double entropy = 0;
        foreach (var count in counts)
        {
            if (count > 0)
            {
                var probability = (double)count / value.Length;
                entropy -= probability * Math.Log2(probability);
            }
        }

        // Short strings cannot exceed log2(length) bits per character, so scale the bar.
        var alphabetSize = allHex ? 16 : 64;
        return entropy >= MinEntropyRatio * Math.Log2(Math.Min(value.Length, alphabetSize));
    }

    private static bool IsTokenCharacter(char value) =>
        IsAsciiAlphaNumeric(value) || value is '_' or '-';

    private static bool IsSecretNameCharacter(char value) =>
        IsAsciiAlphaNumeric(value) || value is '_' or '-' or '.';

    // Printable ASCII only, so CJK text and whitespace end a value.
    private static bool IsValueCharacter(char value) =>
        value is >= '!' and <= '~'
            and not ('"' or '\'' or '`' or ',' or ';' or '&' or '(' or ')' or '[' or ']'
                or '{' or '}' or '<' or '>' or '=' or ':');

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
