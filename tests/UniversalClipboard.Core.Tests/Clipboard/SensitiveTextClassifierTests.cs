using FluentAssertions;
using UniversalClipboard.Core.Clipboard;

namespace UniversalClipboard.Core.Tests.Clipboard;

public sealed class SensitiveTextClassifierTests
{
    public static TheoryData<string> PemTypes =>
        new()
        {
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "DSA PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "PGP PRIVATE KEY BLOCK",
        };

    [Theory]
    [MemberData(nameof(PemTypes))]
    public void Classify_detects_complete_pem_marker_pairs(string pemType)
    {
        var text = $"prefix\r\n-----BEGIN {pemType}-----\r\nbody\r\n-----END {pemType}-----";

        var result = new SensitiveTextClassifier().Classify(text);

        result.Should().Be(SensitiveTextClassifier.PemPrivateKeyRule);
    }

    [Fact]
    public void Classify_accepts_lf_after_each_pem_marker()
    {
        var text = $"{PemMarker("BEGIN")}\nbody\n{PemMarker("END")}\ntrailing";

        new SensitiveTextClassifier().Classify(text)
            .Should().Be(SensitiveTextClassifier.PemPrivateKeyRule);
    }

    [Theory]
    [MemberData(nameof(IncompletePemMarkers))]
    public void Classify_rejects_incomplete_or_non_line_markers(string text)
    {
        new SensitiveTextClassifier().Classify(text).Should().BeNull();
    }

    public static TheoryData<string> IncompletePemMarkers =>
        new()
        {
            $"x{PemMarker("BEGIN")}",
            PemMarker("BEGIN"),
            PemMarker("END"),
            $"{PemMarker("BEGIN")} ",
        };

    private static string PemMarker(string direction) => $"-----{direction} PRIVATE KEY-----";

    [Theory]
    [InlineData('p')]
    [InlineData('o')]
    [InlineData('u')]
    [InlineData('s')]
    [InlineData('r')]
    public void Classify_detects_github_token_kinds(char kind)
    {
        var token = $"gh{kind}_{new string('A', 36)}";

        new SensitiveTextClassifier().Classify($"before {token} after")
            .Should().Be(SensitiveTextClassifier.GitHubTokenRule);
    }

    [Fact]
    public void Classify_detects_github_fine_grained_personal_access_token()
    {
        var token = $"github_pat_{new string('A', 22)}_{new string('b', 59)}";

        new SensitiveTextClassifier().Classify($"token={token}")
            .Should().Be(SensitiveTextClassifier.GitHubTokenRule);
    }

    [Theory]
    [InlineData(35, false)]
    [InlineData(36, true)]
    [InlineData(255, true)]
    [InlineData(256, false)]
    public void Classify_enforces_github_token_length_boundaries(int payloadLength, bool isSensitive)
    {
        var token = $"ghp_{new string('7', payloadLength)}";

        var result = new SensitiveTextClassifier().Classify(token);

        result.Should().Be(isSensitive ? SensitiveTextClassifier.GitHubTokenRule : null);
    }

    [Fact]
    public void Classify_finds_github_token_after_an_overlong_candidate()
    {
        var text = $"ghp_{new string('A', 256)}ghp_{new string('B', 36)}";

        new SensitiveTextClassifier().Classify(text)
            .Should().Be(SensitiveTextClassifier.GitHubTokenRule);
    }

    [Theory]
    [InlineData("AKIA")]
    [InlineData("ASIA")]
    public void Classify_detects_aws_access_key(string prefix)
    {
        var token = prefix + "1234567890ABCDEF";

        new SensitiveTextClassifier().Classify($"key={token};")
            .Should().Be(SensitiveTextClassifier.AwsAccessKeyRule);
    }

    [Theory]
    [InlineData("AKIA1234567890ABCDE")]
    [InlineData("AKIA1234567890ABCDEFG")]
    [InlineData("akia1234567890ABCDEF")]
    [InlineData("AKIA1234567890abcDEF")]
    [InlineData("ASIA1234567890abcDEF")]
    public void Classify_rejects_invalid_aws_access_keys(string text)
    {
        new SensitiveTextClassifier().Classify(text).Should().BeNull();
    }

    [Fact]
    public void Classify_handles_maximum_validator_sized_input()
    {
        var token = $"ghr_{new string('z', 36)}";
        var text = string.Concat(new string('x', StrictUtf8TextValidator.MaxUtf8Bytes - token.Length), token);

        new SensitiveTextClassifier().Classify(text)
            .Should().Be(SensitiveTextClassifier.GitHubTokenRule);
    }

    // Test tokens are assembled at runtime so repository secret scanners never see a literal key.
    private const string Base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private const string Base64 = Base62 + "+/";
    private const string Base64Url = Base62 + "-_";
    private const string LowerHex = "0123456789abcdef";
    private const string Symbols = Base62 + "!@#$%^*-_+";

    // Steps through the alphabet with a stride coprime to its size: deterministic, no repeats per cycle.
    private static string Scrambled(int length, string alphabet = Base62) =>
        string.Create(length, alphabet, static (span, chars) =>
        {
            for (var index = 0; index < span.Length; index++)
            {
                span[index] = chars[(index * 37 + 11) % chars.Length];
            }
        });

    public static TheoryData<string, string> PrefixedTokens =>
        new()
        {
            { $"bot: xox" + $"b-1234567890-9876543210-{Scrambled(24)}", SensitiveTextClassifier.SlackTokenRule },
            { $"xox" + $"p-1234567890-1234567890-1234567890-{Scrambled(32, LowerHex)}", SensitiveTextClassifier.SlackTokenRule },
            { $"stripe sk" + $"_live_{Scrambled(24)}", SensitiveTextClassifier.StripeKeyRule },
            { $"rk" + $"_live_{Scrambled(99)}", SensitiveTextClassifier.StripeKeyRule },
            { $"maps AI" + $"za{Scrambled(35, Base64Url)}.", SensitiveTextClassifier.GoogleApiKeyRule },
            { $"OPENAI=s" + $"k-proj-{Scrambled(48)}", SensitiveTextClassifier.SkApiKeyRule },
            { $"\"s" + $"k-ant-api03-{Scrambled(90, Base64Url)}\"", SensitiveTextClassifier.SkApiKeyRule },
            { $"Bearer ey" + $"J{Scrambled(20, Base64Url)}.ey" + $"J{Scrambled(40, Base64Url)}.{Scrambled(43, Base64Url)}", SensitiveTextClassifier.JwtRule },
        };

    [Theory]
    [MemberData(nameof(PrefixedTokens))]
    public void Classify_detects_prefixed_service_tokens(string text, string expectedRule)
    {
        new SensitiveTextClassifier().Classify(text).Should().Be(expectedRule);
    }

    public static TheoryData<string> NonTokenPrefixes =>
        new()
        {
            "task-management-system-architecture-overview-v2-draft",
            $"s" + $"k-{Scrambled(40, LowerHex)}",
            $"s" + $"k-{Scrambled(31)}",
            $"xs" + $"k-{Scrambled(40)}",
            $"AI" + $"za{Scrambled(34, Base64Url)}",
            $"AI" + $"za{Scrambled(36, Base64Url)}",
            $"xox" + $"b-{Scrambled(19)}",
            $"xox" + $"b-{new string('a', 30)}",
            $"sk" + $"_live_{Scrambled(23)}",
            $"ey" + $"J{Scrambled(20, Base64Url)}.ey" + $"J{Scrambled(40, Base64Url)}",
            $"ey" + $"J{Scrambled(20, Base64Url)}.ey" + $"J{Scrambled(40, Base64Url)}.{Scrambled(15, Base64Url)}",
        };

    [Theory]
    [MemberData(nameof(NonTokenPrefixes))]
    public void Classify_rejects_near_miss_service_tokens(string text)
    {
        new SensitiveTextClassifier().Classify(text).Should().BeNull();
    }

    public static TheoryData<string> KeywordSecrets =>
        new()
        {
            $"aws_secret_access_key = {Scrambled(40, Base64)}",
            $"{{\"client_secret\": \"{Scrambled(32, LowerHex)}\"}}",
            $"curl -H \"Authorization: Bearer {Scrambled(40)}\" https://api.example.com",
            $"https://api.example.com/v1/items?api_key={Scrambled(32)}&page=2",
            $"DB_PASSWORD={Scrambled(20, Symbols)}",
            $"token := \"{Scrambled(24)}\"",
            $"'signing_secret' => '{Scrambled(30)}',",
            $"金鑰：x-api-key: {Scrambled(36)}",
            $"api_key = {Scrambled(SensitiveTextClassifier.MinSecretValueLength)}",
            "{\"password\":\"Ab9!Cd8@Ef7&Gh6#Ij5\"}",
            "db_password = 'Xy7&Zq3:Wv9=Rt5;Pm2'",
            """{"password":"Ab9\"Cd8@Ef7&Gh6#Ij5"}""",
        };

    [Theory]
    [MemberData(nameof(KeywordSecrets))]
    public void Classify_detects_high_entropy_values_after_secret_names(string text)
    {
        new SensitiveTextClassifier().Classify(text)
            .Should().Be(SensitiveTextClassifier.KeywordHighEntropyRule);
    }

    public static TheoryData<string> KeywordNonSecrets =>
        new()
        {
            $"public_key: {Scrambled(40, Base64)}",
            $"description: {Scrambled(40)}",
            Scrambled(40),
            $"api_key = {Scrambled(SensitiveTextClassifier.MinSecretValueLength - 1)}",
            "api_key = aaaaaaaaaaaaaaaaaaaaAAAA1111",
            "key: user_profile_settings_page",
            "token_url = https://oauth2.googleapis.com/token",
            "password: hunter2",
            "secret_name: prod/database/credentials",
            "cache_key = v1.2.3-beta.4+build.567",
            "auth_id: 550e8400-e29b-41d4-a716-446655440000",
            "PWD=/home/kenneth/projects/app2",
            "token = getAccessToken(request)",
            "\"auth_message\": \"Please Sign In With Your Account 2024\"",
            "api_key = \"aaaaaaaa&AAAA:1111=aaaa\"",
            "金鑰說明：今天下午三點在會議室開會討論專案進度與上線時程",
        };

    [Theory]
    [MemberData(nameof(KeywordNonSecrets))]
    public void Classify_ignores_low_entropy_or_unnamed_values(string text)
    {
        new SensitiveTextClassifier().Classify(text).Should().BeNull();
    }

    [Theory]
    [InlineData("eyJ")]
    [InlineData("sk-")]
    [InlineData("key=")]
    [InlineData("key: ")]
    [InlineData("key=\"")]
    [InlineData("key=\"key='key=`")]
    [InlineData("key=\"\\\"")]
    [InlineData("xoxb-")]
    [InlineData("AIza")]
    public void Classify_scans_repeated_candidate_prefixes_in_linear_time(string unit)
    {
        var text = string.Concat(Enumerable.Repeat(unit, StrictUtf8TextValidator.MaxUtf8Bytes / unit.Length));

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        new SensitiveTextClassifier().Classify(text).Should().BeNull();
        stopwatch.Elapsed.Should().BeLessThan(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public void Classify_finds_keyword_secret_at_end_of_maximum_input()
    {
        var secret = $"\nsecret={Scrambled(40)}";
        var text = string.Concat(new string('=', StrictUtf8TextValidator.MaxUtf8Bytes - secret.Length), secret);

        new SensitiveTextClassifier().Classify(text)
            .Should().Be(SensitiveTextClassifier.KeywordHighEntropyRule);
    }
}
