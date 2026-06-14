using System.Collections.Immutable;
using System.Net;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using FluentAssertions;
using UniversalClipboard.App.Security;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.App.Tests.Security;

public sealed class DpapiAuthorizationPersistenceTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "UniversalClipboard.Tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task Round_trip_preserves_complete_authorization_document()
    {
        var path = Path.Combine(_directory, "authorizations.v1.bin");
        var persistence = new DpapiAuthorizationPersistence(path);
        var expected = CreateDocument();

        await persistence.SaveAsync(expected);
        var actual = await persistence.LoadAsync();

        actual.Should().BeEquivalentTo(expected);
        actual.Authorizations[0].SessionProofDigest.Should().Equal(
            expected.Authorizations[0].SessionProofDigest);
    }

    [Fact]
    public async Task Legacy_document_without_session_proof_digest_revokes_authorizations_on_load()
    {
        var files = new MemoryAuthorizationFileOperations();
        var persistence = new DpapiAuthorizationPersistence(
            "auth.bin",
            files,
            new TestDataProtector());
        files.WriteAllBytesAndFlush("auth.bin", CreateLegacyVersion1DocumentWithoutProofDigest());

        var loaded = await persistence.LoadAsync();

        loaded.Authorizations.Should().BeEmpty();
        files.Exists("auth.bin.corrupt").Should().BeFalse();
    }

    [Theory]
    [InlineData("schema")]
    [InlineData("truncated")]
    [InlineData("decrypt")]
    public async Task Invalid_document_fails_closed_and_is_renamed_corrupt(string failure)
    {
        var files = new MemoryAuthorizationFileOperations();
        var protector = new TestDataProtector();
        var persistence = new DpapiAuthorizationPersistence("auth.bin", files, protector);
        await persistence.SaveAsync(CreateDocument());

        if (failure == "schema")
        {
            protector.UnprotectTransform = bytes =>
            {
                bytes[0] = 99;
                return bytes;
            };
        }
        else if (failure == "truncated")
        {
            protector.UnprotectTransform = bytes => bytes[..3];
        }
        else
        {
            protector.UnprotectException = new InvalidDataException("decrypt failed");
        }

        var loaded = await persistence.LoadAsync();

        loaded.Should().BeEquivalentTo(AuthorizationDocument.Empty);
        files.Exists("auth.bin").Should().BeFalse();
        files.Exists("auth.bin.corrupt").Should().BeTrue();
    }

    [Theory]
    [InlineData("write")]
    [InlineData("replace")]
    public async Task Save_failure_preserves_previous_readable_document(string failure)
    {
        var files = new MemoryAuthorizationFileOperations();
        var persistence = new DpapiAuthorizationPersistence(
            "auth.bin",
            files,
            new TestDataProtector());
        var original = CreateDocument();
        await persistence.SaveAsync(original);

        files.Failure = failure;
        var changed = new AuthorizationDocument(
            [original.Authorizations[0] with { Label = "Changed browser" }]);

        var action = () => persistence.SaveAsync(changed);

        await action.Should().ThrowAsync<IOException>();
        files.Failure = null;
        (await persistence.LoadAsync()).Should().BeEquivalentTo(original);
    }

    [Fact]
    public async Task Real_file_and_directory_allow_only_current_user()
    {
        var path = Path.Combine(_directory, "authorizations.v1.bin");
        var persistence = new DpapiAuthorizationPersistence(path);

        await persistence.SaveAsync(CreateDocument());

        AssertCurrentUserOnly(new DirectoryInfo(_directory).GetAccessControl());
        AssertCurrentUserOnly(new FileInfo(path).GetAccessControl());
    }

    [Fact]
    public async Task Real_atomic_replace_keeps_new_document_readable_and_acl_restricted()
    {
        var path = Path.Combine(_directory, "authorizations.v1.bin");
        var persistence = new DpapiAuthorizationPersistence(path);
        var original = CreateDocument();
        var changed = new AuthorizationDocument(
            [original.Authorizations[0] with { Label = "Replacement" }]);

        await persistence.SaveAsync(original);
        await persistence.SaveAsync(changed);

        (await persistence.LoadAsync()).Should().BeEquivalentTo(changed);
        AssertCurrentUserOnly(new FileInfo(path).GetAccessControl());
    }

    [Fact]
    public void Default_path_is_under_local_app_data_with_versioned_name()
    {
        DpapiAuthorizationPersistence.DefaultPath.Should().Be(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "UniversalClipboard",
                "authorizations.v1.bin"));
    }

    [Fact]
    public async Task Persisted_bytes_do_not_contain_authorization_plaintext()
    {
        var path = Path.Combine(_directory, "authorizations.v1.bin");
        var persistence = new DpapiAuthorizationPersistence(path);
        var document = CreateDocument();

        await persistence.SaveAsync(document);
        var bytes = await File.ReadAllBytesAsync(path);
        var text = Encoding.UTF8.GetString(bytes);

        text.Should().NotContain(document.Authorizations[0].Label);
        text.Should().NotContain(Convert.ToHexString(document.Authorizations[0].TokenDigest.AsSpan()));
        text.Should().NotContain("clipboard secret");
        text.Should().NotContain("pairing-code");
        text.Should().NotContain("masked preview");
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private static AuthorizationDocument CreateDocument()
    {
        var record = new AuthorizationRecord(
            Guid.Parse("84f8b095-f6f1-4c07-9d93-27424763e884"),
            "My iPhone",
            new DateTimeOffset(2026, 6, 12, 1, 2, 3, TimeSpan.Zero),
            IPAddress.Parse("192.168.1.25"),
            new DateTimeOffset(2026, 6, 12, 6, 2, 3, TimeSpan.Zero),
            ImmutableArray.Create(Enumerable.Range(1, 32).Select(value => (byte)value).ToArray()),
            ImmutableArray.Create(Enumerable.Range(33, 32).Select(value => (byte)value).ToArray()));
        return new AuthorizationDocument([record]);
    }

    private static byte[] CreateLegacyVersion1DocumentWithoutProofDigest()
    {
        var document = CreateDocument();
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(1);
        writer.Write(document.Authorizations.Length);

        foreach (var authorization in document.Authorizations)
        {
            writer.Write(authorization.Id.ToByteArray());
            writer.Write(authorization.Label);
            writer.Write(authorization.CreatedAtUtc.UtcTicks);
            writer.Write(authorization.BoundHostIpv4.GetAddressBytes());
            writer.Write(authorization.ExpiresAtUtc.HasValue);
            if (authorization.ExpiresAtUtc is { } expiresAtUtc)
            {
                writer.Write(expiresAtUtc.UtcTicks);
            }

            writer.Write(authorization.TokenDigest.Length);
            writer.Write(authorization.TokenDigest.AsSpan());
        }

        writer.Flush();
        return stream.ToArray();
    }

    private static void AssertCurrentUserOnly(FileSystemSecurity security)
    {
        var currentUser = WindowsIdentity.GetCurrent().User;
        currentUser.Should().NotBeNull();
        security.AreAccessRulesProtected.Should().BeTrue();
        var rules = security.GetAccessRules(true, true, typeof(SecurityIdentifier))
            .Cast<FileSystemAccessRule>()
            .Where(rule => rule.AccessControlType == AccessControlType.Allow)
            .ToArray();
        rules.Should().NotBeEmpty();
        rules.Should().OnlyContain(rule => Equals(rule.IdentityReference, currentUser));
    }
}

internal sealed class TestDataProtector : IAuthorizationDataProtector
{
    public Func<byte[], byte[]>? UnprotectTransform { get; set; }

    public Exception? UnprotectException { get; set; }

    public byte[] Protect(byte[] plaintext) => [.. plaintext];

    public byte[] Unprotect(byte[] ciphertext)
    {
        if (UnprotectException is not null)
        {
            throw UnprotectException;
        }

        var bytes = ciphertext.ToArray();
        return UnprotectTransform?.Invoke(bytes) ?? bytes;
    }
}

internal sealed class MemoryAuthorizationFileOperations : IAuthorizationFileOperations
{
    private readonly Dictionary<string, byte[]> _files = new(StringComparer.Ordinal);

    public string? Failure { get; set; }

    public bool Exists(string path) => _files.ContainsKey(path);

    public byte[] ReadAllBytes(string path) => _files[path].ToArray();

    public void EnsureSecureDirectory(string path)
    {
    }

    public void WriteAllBytesAndFlush(string path, byte[] bytes)
    {
        if (Failure == "write")
        {
            throw new IOException("simulated write failure");
        }

        _files[path] = bytes.ToArray();
    }

    public void ApplyCurrentUserOnlyFileAcl(string path)
    {
    }

    public void Replace(string sourcePath, string destinationPath)
    {
        if (Failure == "replace")
        {
            throw new IOException("simulated replace failure");
        }

        _files[destinationPath] = _files[sourcePath];
        _files.Remove(sourcePath);
    }

    public void Move(string sourcePath, string destinationPath)
    {
        _files[destinationPath] = _files[sourcePath];
        _files.Remove(sourcePath);
    }

    public void DeleteIfExists(string path) => _files.Remove(path);

    public void MoveCorrupt(string sourcePath, string destinationPath)
    {
        _files[destinationPath] = _files[sourcePath];
        _files.Remove(sourcePath);
    }
}
