using System.Collections.Immutable;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace UniversalClipboard.App.Security;

public interface IHttpsCertificateProvider
{
    HttpsCertificateIdentity? CurrentIdentity { get; }

    Task<HttpsCertificateLease> GetOrCreateAsync(
        IPAddress address,
        CancellationToken cancellationToken = default);

    Task ResetAsync(CancellationToken cancellationToken = default);

    Task AcknowledgeAuthorizationResetAsync(CancellationToken cancellationToken = default);
}

public enum HttpsCertificateIdentityStatus
{
    Reused,
    Created,
    ReplacedStoredIdentity,
}

public sealed record HttpsCertificateIdentity(
    IPAddress BoundIpv4,
    string FingerprintSha256,
    string ShortCode,
    DateTimeOffset NotAfterUtc,
    HttpsCertificateIdentityStatus Status = HttpsCertificateIdentityStatus.Reused);

public sealed record HttpsCertificateLease(
    HttpsCertificateIdentity Identity,
    X509Certificate2 Certificate)
    : IDisposable
{
    public IPAddress BoundIpv4 => Identity.BoundIpv4;

    public string FingerprintSha256 => Identity.FingerprintSha256;

    public string ShortCode => Identity.ShortCode;

    public DateTimeOffset NotAfterUtc => Identity.NotAfterUtc;

    public HttpsCertificateIdentityStatus Status => Identity.Status;

    public void Dispose() => Certificate.Dispose();
}

public sealed class DpapiHttpsCertificateProvider : IHttpsCertificateProvider
{
    private const int SchemaVersion = 1;
    private const int MaximumDocumentBytes = 4 * 1024 * 1024;
    private const int MaximumCertificateBytes = 64 * 1024;
    private static readonly byte[] OptionalEntropy =
        "UniversalClipboard.HttpsCertificate.v1"u8.ToArray();

    private readonly string _path;
    private readonly IAuthorizationFileOperations _files;
    private readonly IAuthorizationDataProtector _protector;
    private readonly TimeProvider _timeProvider;
    private readonly object _gate = new();
    private HttpsCertificateIdentity? _currentIdentity;

    public static string DefaultPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "UniversalClipboard",
            "https-certificates.v1.bin");

    private string AuthorizationResetRequiredPath => _path + ".authorization-reset-required";

    public DpapiHttpsCertificateProvider(string? path = null, TimeProvider? timeProvider = null)
        : this(
            path ?? DefaultPath,
            new AuthorizationFileOperations(),
            new CurrentUserDataProtector(OptionalEntropy),
            timeProvider ?? TimeProvider.System)
    {
    }

    internal DpapiHttpsCertificateProvider(
        string path,
        IAuthorizationFileOperations files,
        IAuthorizationDataProtector protector,
        TimeProvider timeProvider)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(files);
        ArgumentNullException.ThrowIfNull(protector);
        ArgumentNullException.ThrowIfNull(timeProvider);

        _path = path;
        _files = files;
        _protector = protector;
        _timeProvider = timeProvider;
    }

    public HttpsCertificateIdentity? CurrentIdentity
    {
        get
        {
            lock (_gate)
            {
                return _currentIdentity;
            }
        }
    }

    public Task<HttpsCertificateLease> GetOrCreateAsync(
        IPAddress address,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
        {
            throw new ArgumentException("HTTPS certificates can only bind IPv4 addresses.", nameof(address));
        }

        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            var now = _timeProvider.GetUtcNow().ToUniversalTime();
            var loadResult = LoadRecords();
            var records = loadResult.Records;
            var record = records.FirstOrDefault(item => item.Address.Equals(address));
            var reusableStatus = _files.Exists(AuthorizationResetRequiredPath)
                ? HttpsCertificateIdentityStatus.ReplacedStoredIdentity
                : HttpsCertificateIdentityStatus.Reused;
            if (record is not null &&
                TryCreateReusableIdentity(record, address, now, reusableStatus, out var lease))
            {
                _currentIdentity = lease.Identity;
                return Task.FromResult(lease);
            }

            var status = record is not null || loadResult.HadStoredDocument
                ? HttpsCertificateIdentityStatus.ReplacedStoredIdentity
                : HttpsCertificateIdentityStatus.Created;
            var (replacement, pfxBytes) = CreateIdentity(address, now, status);
            records = records
                .Where(item => !item.Address.Equals(address))
                .Append(new HttpsCertificateRecord(
                    address,
                    now,
                    replacement.Certificate.NotBefore.ToUniversalTime(),
                    replacement.NotAfterUtc,
                    pfxBytes))
                .ToImmutableArray();
            try
            {
                MarkAuthorizationResetRequired();
                SaveRecords(records);
                _currentIdentity = replacement.Identity;
                return Task.FromResult(replacement);
            }
            catch
            {
                replacement.Dispose();
                throw;
            }
        }
    }

    public Task ResetAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            _files.DeleteIfExists(_path);
            _files.DeleteIfExists(_path + ".corrupt");
            _files.DeleteIfExists(AuthorizationResetRequiredPath);
            _currentIdentity = null;
        }

        return Task.CompletedTask;
    }

    public Task AcknowledgeAuthorizationResetAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_gate)
        {
            _files.DeleteIfExists(AuthorizationResetRequiredPath);
        }

        return Task.CompletedTask;
    }

    private HttpsCertificateLoadResult LoadRecords()
    {
        if (!_files.Exists(_path))
        {
            return new HttpsCertificateLoadResult([], HadStoredDocument: false);
        }

        try
        {
            var ciphertext = _files.ReadAllBytes(_path);
            if (ciphertext.Length == 0 || ciphertext.Length > MaximumDocumentBytes)
            {
                throw new InvalidDataException("Invalid HTTPS certificate document length.");
            }

            var plaintext = _protector.Unprotect(ciphertext);
            return new HttpsCertificateLoadResult(
                Deserialize(plaintext),
                HadStoredDocument: true);
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
            return new HttpsCertificateLoadResult([], HadStoredDocument: true);
        }
    }

    private void SaveRecords(ImmutableArray<HttpsCertificateRecord> records)
    {
        var directory = Path.GetDirectoryName(_path);
        if (string.IsNullOrEmpty(directory))
        {
            directory = ".";
        }

        _files.EnsureSecureDirectory(directory);
        var plaintext = Serialize(records);
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
    }

    private void MarkAuthorizationResetRequired()
    {
        var directory = Path.GetDirectoryName(AuthorizationResetRequiredPath);
        if (string.IsNullOrEmpty(directory))
        {
            directory = ".";
        }

        _files.EnsureSecureDirectory(directory);
        _files.DeleteIfExists(AuthorizationResetRequiredPath);
        _files.WriteAllBytesAndFlush(AuthorizationResetRequiredPath, [1]);
        _files.ApplyCurrentUserOnlyFileAcl(AuthorizationResetRequiredPath);
    }

    private static byte[] Serialize(ImmutableArray<HttpsCertificateRecord> records)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(SchemaVersion);
        writer.Write(records.Length);
        foreach (var record in records)
        {
            writer.Write(record.Address.GetAddressBytes());
            writer.Write(record.CreatedAtUtc.UtcTicks);
            writer.Write(record.NotBeforeUtc.UtcTicks);
            writer.Write(record.NotAfterUtc.UtcTicks);
            writer.Write(record.PfxBytes.Length);
            writer.Write(record.PfxBytes);
        }

        writer.Flush();
        return stream.ToArray();
    }

    private static ImmutableArray<HttpsCertificateRecord> Deserialize(byte[] plaintext)
    {
        if (plaintext.Length == 0 || plaintext.Length > MaximumDocumentBytes)
        {
            throw new InvalidDataException("Invalid HTTPS certificate document length.");
        }

        using var stream = new MemoryStream(plaintext, writable: false);
        using var reader = new BinaryReader(stream);
        var version = reader.ReadInt32();
        if (version != SchemaVersion)
        {
            throw new InvalidDataException("Unknown HTTPS certificate schema.");
        }

        var count = reader.ReadInt32();
        if (count is < 0 or > 1024)
        {
            throw new InvalidDataException("Invalid HTTPS certificate count.");
        }

        var records = ImmutableArray.CreateBuilder<HttpsCertificateRecord>(count);
        for (var index = 0; index < count; index++)
        {
            var address = new IPAddress(ReadExact(reader, 4));
            var createdAtUtc = ReadUtc(reader);
            var notBeforeUtc = ReadUtc(reader);
            var notAfterUtc = ReadUtc(reader);
            if (notAfterUtc <= notBeforeUtc)
            {
                throw new InvalidDataException("Invalid HTTPS certificate validity range.");
            }

            var pfxLength = reader.ReadInt32();
            if (pfxLength is <= 0 or > MaximumCertificateBytes)
            {
                throw new InvalidDataException("Invalid HTTPS certificate length.");
            }

            records.Add(new HttpsCertificateRecord(
                address,
                createdAtUtc,
                notBeforeUtc,
                notAfterUtc,
                ReadExact(reader, pfxLength)));
        }

        if (stream.Position != stream.Length)
        {
            throw new InvalidDataException("Unexpected trailing HTTPS certificate data.");
        }

        return records.ToImmutable();
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

    private static bool TryCreateReusableIdentity(
        HttpsCertificateRecord record,
        IPAddress requestedAddress,
        DateTimeOffset now,
        HttpsCertificateIdentityStatus status,
        out HttpsCertificateLease lease)
    {
        lease = null!;
        try
        {
            var certificate = X509CertificateLoader.LoadPkcs12(
                record.PfxBytes,
                password: null,
                X509KeyStorageFlags.UserKeySet);
            var notAfterUtc = certificate.NotAfter.ToUniversalTime();
            if (!certificate.HasPrivateKey ||
                notAfterUtc <= now ||
                !CertificateHasSanIpAddress(certificate, requestedAddress))
            {
                certificate.Dispose();
                return false;
            }

            lease = new HttpsCertificateLease(
                CreateIdentitySnapshot(requestedAddress, certificate, status),
                certificate);
            return true;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    private static (HttpsCertificateLease Lease, byte[] PfxBytes) CreateIdentity(
        IPAddress address,
        DateTimeOffset now,
        HttpsCertificateIdentityStatus status)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            "CN=Universal Clipboard Local Web",
            key,
            HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(address);
        if (!IPAddress.IsLoopback(address))
        {
            san.AddIpAddress(IPAddress.Loopback);
        }

        san.AddDnsName("localhost");
        request.CertificateExtensions.Add(san.Build());
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, critical: true));
        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection
                {
                    new Oid("1.3.6.1.5.5.7.3.1"),
                },
                critical: false));

        using var certificate = request.CreateSelfSigned(
            now.AddMinutes(-5),
            now.AddDays(365));
        var pfxBytes = certificate.Export(X509ContentType.Pkcs12);
        var loaded = X509CertificateLoader.LoadPkcs12(
            pfxBytes,
            password: null,
            X509KeyStorageFlags.UserKeySet);
        return (new HttpsCertificateLease(
            CreateIdentitySnapshot(address, loaded, status),
            loaded), pfxBytes);
    }

    private static HttpsCertificateIdentity CreateIdentitySnapshot(
        IPAddress address,
        X509Certificate2 certificate,
        HttpsCertificateIdentityStatus status = HttpsCertificateIdentityStatus.Reused)
    {
        var fingerprint = Convert.ToHexString(
            certificate.GetCertHash(HashAlgorithmName.SHA256));
        return new HttpsCertificateIdentity(
            address,
            fingerprint,
            $"{fingerprint[..4]}-{fingerprint.Substring(4, 4)}-{fingerprint.Substring(8, 4)}",
            certificate.NotAfter.ToUniversalTime(),
            status);
    }

    private static bool CertificateHasSanIpAddress(
        X509Certificate2 certificate,
        IPAddress requestedAddress)
    {
        var extension = certificate.Extensions
            .Cast<X509Extension>()
            .SingleOrDefault(candidate => candidate.Oid?.Value == "2.5.29.17");
        if (extension is null)
        {
            return false;
        }

        var san = new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);
        return san.EnumerateIPAddresses().Any(candidate => candidate.Equals(requestedAddress));
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

    private sealed record HttpsCertificateRecord(
        IPAddress Address,
        DateTimeOffset CreatedAtUtc,
        DateTimeOffset NotBeforeUtc,
        DateTimeOffset NotAfterUtc,
        byte[] PfxBytes);

    private sealed record HttpsCertificateLoadResult(
        ImmutableArray<HttpsCertificateRecord> Records,
        bool HadStoredDocument);
}
