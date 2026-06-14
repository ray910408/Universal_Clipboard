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
        const string text =
            "-----BEGIN PRIVATE KEY-----\nbody\n-----END PRIVATE KEY-----\ntrailing";

        new SensitiveTextClassifier().Classify(text)
            .Should().Be(SensitiveTextClassifier.PemPrivateKeyRule);
    }

    [Theory]
    [InlineData("x-----BEGIN PRIVATE KEY-----\nbody\n-----END PRIVATE KEY-----")]
    [InlineData("-----BEGIN PRIVATE KEY-----\nbody")]
    [InlineData("-----END PRIVATE KEY-----")]
    [InlineData("-----BEGIN PRIVATE KEY----- ")]
    public void Classify_rejects_incomplete_or_non_line_markers(string text)
    {
        new SensitiveTextClassifier().Classify(text).Should().BeNull();
    }

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
}
