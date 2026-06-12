using System.Collections.Immutable;
using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.App.Security;

public sealed class DpapiAuthorizationPersistence : IAuthorizationPersistence
{
    private const int SchemaVersion = 1;
    private const int MaximumDocumentBytes = 4 * 1024 * 1024;
    private static readonly byte[] OptionalEntropy =
        "UniversalClipboard.Authorization.v1"u8.ToArray();

    private readonly string _path;
    private readonly IAuthorizationFileOperations _files;
    private readonly IAuthorizationDataProtector _protector;

    public static string DefaultPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "UniversalClipboard",
            "authorizations.v1.bin");

    public DpapiAuthorizationPersistence(string? path = null)
        : this(
            path ?? DefaultPath,
            new AuthorizationFileOperations(),
            new CurrentUserDataProtector(OptionalEntropy))
    {
    }

    internal DpapiAuthorizationPersistence(
        string path,
        IAuthorizationFileOperations files,
        IAuthorizationDataProtector protector)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(protector);

        _path = path;
        _files = files;
        _protector = protector;
    }

    public Task<AuthorizationDocument> LoadAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_files.Exists(_path))
        {
            return Task.FromResult(AuthorizationDocument.Empty);
        }

        try
        {
            var ciphertext = _files.ReadAllBytes(_path);
            if (ciphertext.Length == 0 || ciphertext.Length > MaximumDocumentBytes)
            {
                throw new InvalidDataException("Invalid authorization document length.");
            }

            var plaintext = _protector.Unprotect(ciphertext);
            return Task.FromResult(Deserialize(plaintext));
        }
        catch (Exception exception) when (
            exception is CryptographicException or
            InvalidDataException or
            IOException or
            UnauthorizedAccessException or
            EndOfStreamException or
            FormatException or
            ArgumentException)
        {
            QuarantineCorruptFile();
            return Task.FromResult(AuthorizationDocument.Empty);
        }
    }

    public Task SaveAsync(
        AuthorizationDocument document,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(document);
        cancellationToken.ThrowIfCancellationRequested();

        var directory = Path.GetDirectoryName(_path);
        if (string.IsNullOrEmpty(directory))
        {
            directory = ".";
        }

        _files.EnsureSecureDirectory(directory);
        var plaintext = Serialize(document);
        var ciphertext = _protector.Protect(plaintext);
        var temporaryPath = Path.Combine(
            directory,
            $".{Path.GetFileName(_path)}.{Guid.NewGuid():N}.tmp");

        try
        {
            _files.WriteAllBytesAndFlush(temporaryPath, ciphertext);
            _files.ApplyCurrentUserOnlyFileAcl(temporaryPath);

            if (_files.Exists(_path))
            {
                _files.Replace(temporaryPath, _path);
            }
            else
            {
                _files.Move(temporaryPath, _path);
            }
        }
        catch
        {
            _files.DeleteIfExists(temporaryPath);
            throw;
        }

        return Task.CompletedTask;
    }

    private static byte[] Serialize(AuthorizationDocument document)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(SchemaVersion);
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

    private static AuthorizationDocument Deserialize(byte[] plaintext)
    {
        if (plaintext.Length == 0 || plaintext.Length > MaximumDocumentBytes)
        {
            throw new InvalidDataException("Invalid authorization document length.");
        }

        using var stream = new MemoryStream(plaintext, writable: false);
        using var reader = new BinaryReader(stream);
        if (reader.ReadInt32() != SchemaVersion)
        {
            throw new InvalidDataException("Unknown authorization schema.");
        }

        var count = reader.ReadInt32();
        if (count is < 0 or > 10_000)
        {
            throw new InvalidDataException("Invalid authorization count.");
        }

        var authorizations = ImmutableArray.CreateBuilder<AuthorizationRecord>(count);
        for (var index = 0; index < count; index++)
        {
            var id = new Guid(ReadExact(reader, 16));
            var label = reader.ReadString();
            var createdAtUtc = ReadUtc(reader);
            var addressBytes = ReadExact(reader, 4);
            var boundAddress = new IPAddress(addressBytes);
            DateTimeOffset? expiresAtUtc = reader.ReadBoolean() ? ReadUtc(reader) : null;
            var digestLength = reader.ReadInt32();
            if (digestLength != SHA256.HashSizeInBytes)
            {
                throw new InvalidDataException("Invalid token digest length.");
            }

            authorizations.Add(
                new AuthorizationRecord(
                    id,
                    label,
                    createdAtUtc,
                    boundAddress,
                    expiresAtUtc,
                    ImmutableArray.Create(ReadExact(reader, digestLength))));
        }

        if (stream.Position != stream.Length)
        {
            throw new InvalidDataException("Unexpected trailing authorization data.");
        }

        return new AuthorizationDocument(authorizations.MoveToImmutable());
    }

    private static DateTimeOffset ReadUtc(BinaryReader reader)
    {
        var ticks = reader.ReadInt64();
        if (ticks < DateTime.MinValue.Ticks || ticks > DateTime.MaxValue.Ticks)
        {
            throw new InvalidDataException("Invalid UTC timestamp.");
        }

        return new DateTimeOffset(ticks, TimeSpan.Zero);
    }

    private static byte[] ReadExact(BinaryReader reader, int length)
    {
        var bytes = reader.ReadBytes(length);
        if (bytes.Length != length)
        {
            throw new EndOfStreamException();
        }

        return bytes;
    }

    private void QuarantineCorruptFile()
    {
        try
        {
            if (!_files.Exists(_path))
            {
                return;
            }

            var corruptPath = _path + ".corrupt";
            _files.DeleteIfExists(corruptPath);
            _files.MoveCorrupt(_path, corruptPath);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}

internal interface IAuthorizationDataProtector
{
    byte[] Protect(byte[] plaintext);

    byte[] Unprotect(byte[] ciphertext);
}

internal sealed class CurrentUserDataProtector(byte[] optionalEntropy)
    : IAuthorizationDataProtector
{
    public byte[] Protect(byte[] plaintext) =>
        ProtectedData.Protect(plaintext, optionalEntropy, DataProtectionScope.CurrentUser);

    public byte[] Unprotect(byte[] ciphertext) =>
        ProtectedData.Unprotect(ciphertext, optionalEntropy, DataProtectionScope.CurrentUser);
}

internal interface IAuthorizationFileOperations
{
    bool Exists(string path);

    byte[] ReadAllBytes(string path);

    void EnsureSecureDirectory(string path);

    void WriteAllBytesAndFlush(string path, byte[] bytes);

    void ApplyCurrentUserOnlyFileAcl(string path);

    void Replace(string sourcePath, string destinationPath);

    void Move(string sourcePath, string destinationPath);

    void DeleteIfExists(string path);

    void MoveCorrupt(string sourcePath, string destinationPath);
}

internal sealed class AuthorizationFileOperations : IAuthorizationFileOperations
{
    public bool Exists(string path) => File.Exists(path);

    public byte[] ReadAllBytes(string path) => File.ReadAllBytes(path);

    public void EnsureSecureDirectory(string path)
    {
        Directory.CreateDirectory(path);
        var security = new DirectorySecurity();
        var currentUser = GetCurrentUser();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(
            new FileSystemAccessRule(
                currentUser,
                FileSystemRights.FullControl,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));
        new DirectoryInfo(path).SetAccessControl(security);
    }

    public void WriteAllBytesAndFlush(string path, byte[] bytes)
    {
        using var stream = new FileStream(
            path,
            FileMode.CreateNew,
            FileAccess.Write,
            FileShare.None,
            bufferSize: 4096,
            FileOptions.WriteThrough);
        stream.Write(bytes);
        stream.Flush(flushToDisk: true);
    }

    public void ApplyCurrentUserOnlyFileAcl(string path)
    {
        var security = new FileSecurity();
        var currentUser = GetCurrentUser();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(
            new FileSystemAccessRule(
                currentUser,
                FileSystemRights.FullControl,
                AccessControlType.Allow));
        new FileInfo(path).SetAccessControl(security);
    }

    public void Replace(string sourcePath, string destinationPath) =>
        File.Replace(sourcePath, destinationPath, destinationBackupFileName: null);

    public void Move(string sourcePath, string destinationPath) =>
        File.Move(sourcePath, destinationPath);

    public void DeleteIfExists(string path) => File.Delete(path);

    public void MoveCorrupt(string sourcePath, string destinationPath) =>
        File.Move(sourcePath, destinationPath);

    private static SecurityIdentifier GetCurrentUser() =>
        WindowsIdentity.GetCurrent().User ??
        throw new InvalidOperationException("The current Windows user has no SID.");
}
