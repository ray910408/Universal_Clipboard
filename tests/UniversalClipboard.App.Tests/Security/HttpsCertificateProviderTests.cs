using System.Net;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using FluentAssertions;
using UniversalClipboard.App.Security;

namespace UniversalClipboard.App.Tests.Security;

public sealed class HttpsCertificateProviderTests : IDisposable
{
    private readonly string _directory =
        Path.Combine(Path.GetTempPath(), "UniversalClipboard.Tests", Guid.NewGuid().ToString("N"));

    [Fact]
    public async Task GetOrCreateHttpsCertificate_generates_persists_and_reuses_identity_for_same_ipv4()
    {
        var files = new MemoryAuthorizationFileOperations();
        var protector = new TestDataProtector();
        var clock = new TestTimeProvider(new DateTimeOffset(2026, 6, 15, 8, 0, 0, TimeSpan.Zero));
        var address = IPAddress.Parse("192.168.1.25");
        var provider = new DpapiHttpsCertificateProvider(
            "https-certificates.v1.bin",
            files,
            protector,
            clock);

        using var first = await provider.GetOrCreateAsync(address);
        await provider.AcknowledgeAuthorizationResetAsync();
        using var second = await new DpapiHttpsCertificateProvider(
                "https-certificates.v1.bin",
                files,
                protector,
                clock)
            .GetOrCreateAsync(address);

        first.BoundIpv4.Should().Be(address);
        first.Certificate.HasPrivateKey.Should().BeTrue();
        first.NotAfterUtc.Should().Be(clock.GetUtcNow().AddDays(365));
        first.Status.Should().Be(HttpsCertificateIdentityStatus.Created);
        AssertIdentityMatchesCertificate(first);
        AssertSubjectAlternativeNames(first.Certificate, address);
        second.FingerprintSha256.Should().Be(first.FingerprintSha256);
        second.ShortCode.Should().Be(first.ShortCode);
        second.NotAfterUtc.Should().Be(first.NotAfterUtc);
        second.Status.Should().Be(HttpsCertificateIdentityStatus.Reused);
        files.Exists("https-certificates.v1.bin").Should().BeTrue();
    }

    [Fact]
    public async Task GetOrCreateHttpsCertificate_requires_authorization_reset_until_acknowledged()
    {
        var files = new MemoryAuthorizationFileOperations();
        var protector = new TestDataProtector();
        var clock = new TestTimeProvider(new DateTimeOffset(2026, 6, 15, 8, 0, 0, TimeSpan.Zero));
        var address = IPAddress.Parse("192.168.1.25");
        var provider = new DpapiHttpsCertificateProvider(
            "https-certificates.v1.bin",
            files,
            protector,
            clock);

        using var first = await provider.GetOrCreateAsync(address);
        using var stillPending = await new DpapiHttpsCertificateProvider(
                "https-certificates.v1.bin",
                files,
                protector,
                clock)
            .GetOrCreateAsync(address);
        await provider.AcknowledgeAuthorizationResetAsync();
        using var acknowledged = await new DpapiHttpsCertificateProvider(
                "https-certificates.v1.bin",
                files,
                protector,
                clock)
            .GetOrCreateAsync(address);

        first.Status.Should().Be(HttpsCertificateIdentityStatus.Created);
        stillPending.FingerprintSha256.Should().Be(first.FingerprintSha256);
        stillPending.Status.Should().Be(HttpsCertificateIdentityStatus.ReplacedStoredIdentity);
        acknowledged.FingerprintSha256.Should().Be(first.FingerprintSha256);
        acknowledged.Status.Should().Be(HttpsCertificateIdentityStatus.Reused);
    }

    [Fact]
    public async Task GetOrCreateHttpsCertificate_keeps_separate_identities_per_ipv4()
    {
        var files = new MemoryAuthorizationFileOperations();
        var protector = new TestDataProtector();
        var clock = new TestTimeProvider(new DateTimeOffset(2026, 6, 15, 8, 0, 0, TimeSpan.Zero));
        var provider = new DpapiHttpsCertificateProvider(
            "https-certificates.v1.bin",
            files,
            protector,
            clock);
        var firstAddress = IPAddress.Parse("192.168.1.25");
        var secondAddress = IPAddress.Parse("10.0.0.44");

        using var first = await provider.GetOrCreateAsync(firstAddress);
        using var second = await provider.GetOrCreateAsync(secondAddress);
        using var firstReloaded = await new DpapiHttpsCertificateProvider(
                "https-certificates.v1.bin",
                files,
                protector,
                clock)
            .GetOrCreateAsync(firstAddress);

        second.FingerprintSha256.Should().NotBe(first.FingerprintSha256);
        AssertSubjectAlternativeNames(second.Certificate, secondAddress);
        firstReloaded.FingerprintSha256.Should().Be(first.FingerprintSha256);
    }

    [Fact]
    public async Task GetOrCreateHttpsCertificate_regenerates_when_stored_certificate_is_expired()
    {
        var files = new MemoryAuthorizationFileOperations();
        var protector = new TestDataProtector();
        var clock = new TestTimeProvider(new DateTimeOffset(2026, 6, 15, 8, 0, 0, TimeSpan.Zero));
        var provider = new DpapiHttpsCertificateProvider(
            "https-certificates.v1.bin",
            files,
            protector,
            clock);
        var address = IPAddress.Parse("192.168.1.25");
        using var first = await provider.GetOrCreateAsync(address);

        clock.Advance(TimeSpan.FromDays(365));
        using var replacement = await provider.GetOrCreateAsync(address);

        replacement.FingerprintSha256.Should().NotBe(first.FingerprintSha256);
        replacement.NotAfterUtc.Should().Be(clock.GetUtcNow().AddDays(365));
        replacement.Status.Should().Be(HttpsCertificateIdentityStatus.ReplacedStoredIdentity);
        AssertSubjectAlternativeNames(replacement.Certificate, address);
    }

    [Fact]
    public async Task GetOrCreateHttpsCertificate_retries_after_save_failure_with_pending_authorization_reset_marker()
    {
        var files = new MemoryAuthorizationFileOperations();
        var protector = new TestDataProtector();
        var clock = new TestTimeProvider(new DateTimeOffset(2026, 6, 15, 8, 0, 0, TimeSpan.Zero));
        var provider = new DpapiHttpsCertificateProvider(
            "https-certificates.v1.bin",
            files,
            protector,
            clock);
        var address = IPAddress.Parse("192.168.1.25");
        using var first = await provider.GetOrCreateAsync(address);
        await provider.AcknowledgeAuthorizationResetAsync();
        clock.Advance(TimeSpan.FromDays(365));

        files.Failure = "replace";
        Func<Task> failedSave = async () =>
        {
            using var lease = await provider.GetOrCreateAsync(address);
        };

        await failedSave.Should().ThrowAsync<IOException>();
        files.Failure = null;
        using var replacement = await provider.GetOrCreateAsync(address);

        replacement.FingerprintSha256.Should().NotBe(first.FingerprintSha256);
        replacement.Status.Should().Be(HttpsCertificateIdentityStatus.ReplacedStoredIdentity);
    }

    [Fact]
    public async Task GetOrCreateHttpsCertificate_regenerates_when_stored_certificate_san_does_not_match_ipv4()
    {
        var files = new MemoryAuthorizationFileOperations();
        var protector = new TestDataProtector();
        var clock = new TestTimeProvider(new DateTimeOffset(2026, 6, 15, 8, 0, 0, TimeSpan.Zero));
        var requestedAddress = IPAddress.Parse("192.168.1.25");
        var mismatchedPfx = CreatePfxForSan(IPAddress.Parse("10.0.0.44"), clock.GetUtcNow());
        using var mismatchedCertificate = X509CertificateLoader.LoadPkcs12(
            mismatchedPfx,
            password: null);
        var mismatchedFingerprint = Convert.ToHexString(
            mismatchedCertificate.GetCertHash(HashAlgorithmName.SHA256));
        files.WriteAllBytesAndFlush(
            "https-certificates.v1.bin",
            protector.Protect(WriteDocument(requestedAddress, clock.GetUtcNow(), mismatchedPfx)));
        var provider = new DpapiHttpsCertificateProvider(
            "https-certificates.v1.bin",
            files,
            protector,
            clock);

        using var identity = await provider.GetOrCreateAsync(requestedAddress);

        AssertSubjectAlternativeNames(identity.Certificate, requestedAddress);
        identity.FingerprintSha256.Should().NotBe(mismatchedFingerprint);
        identity.Status.Should().Be(HttpsCertificateIdentityStatus.ReplacedStoredIdentity);
    }

    [Fact]
    public async Task GetOrCreateHttpsCertificate_quarantines_corrupt_document_and_generates_new_identity()
    {
        var files = new MemoryAuthorizationFileOperations();
        var protector = new TestDataProtector();
        files.WriteAllBytesAndFlush("https-certificates.v1.bin", [1, 2, 3]);
        var provider = new DpapiHttpsCertificateProvider(
            "https-certificates.v1.bin",
            files,
            protector,
            new TestTimeProvider(new DateTimeOffset(2026, 6, 15, 8, 0, 0, TimeSpan.Zero)));

        using var identity = await provider.GetOrCreateAsync(IPAddress.Parse("192.168.1.25"));

        identity.Certificate.HasPrivateKey.Should().BeTrue();
        identity.Status.Should().Be(HttpsCertificateIdentityStatus.ReplacedStoredIdentity);
        files.Exists("https-certificates.v1.bin").Should().BeTrue();
        files.Exists("https-certificates.v1.bin.corrupt").Should().BeTrue();
    }

    [Fact]
    public async Task ResetHttpsIdentity_deletes_persisted_document()
    {
        var files = new MemoryAuthorizationFileOperations();
        var protector = new TestDataProtector();
        var clock = new TestTimeProvider(new DateTimeOffset(2026, 6, 15, 8, 0, 0, TimeSpan.Zero));
        var provider = new DpapiHttpsCertificateProvider(
            "https-certificates.v1.bin",
            files,
            protector,
            clock);
        var address = IPAddress.Parse("192.168.1.25");
        using var first = await provider.GetOrCreateAsync(address);
        files.WriteAllBytesAndFlush("https-certificates.v1.bin.corrupt", [1, 2, 3]);

        await provider.ResetAsync();
        using var replacement = await provider.GetOrCreateAsync(address);

        replacement.FingerprintSha256.Should().NotBe(first.FingerprintSha256);
        files.Exists("https-certificates.v1.bin.corrupt").Should().BeFalse();
    }

    [Fact]
    public async Task Real_https_certificate_file_and_directory_allow_only_current_user()
    {
        var path = Path.Combine(_directory, "https-certificates.v1.bin");
        var provider = new DpapiHttpsCertificateProvider(
            path,
            TimeProvider.System);

        using var identity = await provider.GetOrCreateAsync(IPAddress.Parse("127.0.0.1"));

        AssertCurrentUserOnly(new DirectoryInfo(_directory).GetAccessControl());
        AssertCurrentUserOnly(new FileInfo(path).GetAccessControl());
    }

    [Fact]
    public void DefaultHttpsCertificatePath_is_under_local_app_data_with_versioned_name()
    {
        DpapiHttpsCertificateProvider.DefaultPath.Should().Be(
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "UniversalClipboard",
                "https-certificates.v1.bin"));
    }

    public void Dispose()
    {
        if (Directory.Exists(_directory))
        {
            Directory.Delete(_directory, recursive: true);
        }
    }

    private static void AssertIdentityMatchesCertificate(HttpsCertificateLease identity)
    {
        var expectedFingerprint = Convert.ToHexString(
            identity.Certificate.GetCertHash(HashAlgorithmName.SHA256));
        identity.FingerprintSha256.Should().Be(expectedFingerprint);
        identity.ShortCode.Should().Be(
            $"{expectedFingerprint[..4]}-{expectedFingerprint.Substring(4, 4)}-{expectedFingerprint.Substring(8, 4)}");
    }

    private static void AssertSubjectAlternativeNames(
        X509Certificate2 certificate,
        IPAddress selectedAddress)
    {
        var extension = certificate.Extensions
            .Cast<X509Extension>()
            .Single(candidate => candidate.Oid?.Value == "2.5.29.17");
        var san = new X509SubjectAlternativeNameExtension(extension.RawData, extension.Critical);
        var addresses = san.EnumerateIPAddresses().ToArray();
        var dnsNames = san.EnumerateDnsNames().ToArray();

        addresses.Should().Contain(selectedAddress);
        if (!IPAddress.IsLoopback(selectedAddress))
        {
            addresses.Should().Contain(IPAddress.Loopback);
        }

        dnsNames.Should().Contain("localhost");
    }

    private static byte[] CreatePfxForSan(IPAddress address, DateTimeOffset now)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            "CN=Universal Clipboard Local Web",
            key,
            HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(address);
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
        return certificate.Export(X509ContentType.Pkcs12);
    }

    private static byte[] WriteDocument(
        IPAddress address,
        DateTimeOffset createdAtUtc,
        byte[] pfxBytes)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(1);
        writer.Write(1);
        writer.Write(address.GetAddressBytes());
        writer.Write(createdAtUtc.UtcTicks);
        writer.Write(createdAtUtc.AddMinutes(-5).UtcTicks);
        writer.Write(createdAtUtc.AddDays(365).UtcTicks);
        writer.Write(pfxBytes.Length);
        writer.Write(pfxBytes);
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

    private sealed class TestTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan duration) => _utcNow += duration;
    }
}
