using System.Buffers;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using UniversalClipboard.Core.Authorization;
using UniversalClipboard.Core.Clipboard;

namespace UniversalClipboard.App.Web;

public interface IClipResponseWriter
{
    Task WriteAsync(
        HttpContext context,
        ClipSnapshotResponse response,
        CancellationToken cancellationToken);
}

public sealed record LocalWebHostTimeouts(TimeSpan Drain, TimeSpan CancelJoin)
{
    public static LocalWebHostTimeouts Production { get; } =
        new(TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(2));
}

public sealed record LocalWebHostStopResult(bool CompletedOrderly)
{
    public static LocalWebHostStopResult Orderly { get; } = new(true);

    public static LocalWebHostStopResult Incomplete { get; } = new(false);
}

internal interface ILocalWebHostInstance : IAsyncDisposable
{
    Task StartAsync(CancellationToken cancellationToken = default);

    Task<LocalWebHostStopResult> StopAsync(CancellationToken cancellationToken = default);
}

public sealed class LocalWebHost : IAsyncDisposable, ILocalWebHostInstance
{
    public const int Port = 43127;
    public const string ContentSecurityPolicy =
        "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
        "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";

    private const int PairBodyLimit = 1024;
    private const string SessionCookieName = "clip_session";
    private const string SessionProofHeaderName = "X-Clip-Session";
    private const string SessionCookiePath = "/clip-api";
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web)
    {
        UnmappedMemberHandling = JsonUnmappedMemberHandling.Disallow,
    };

    private readonly IPEndPoint _endpoint;
    private readonly IAuthorizationService _authorization;
    private readonly Func<ClipboardSnapshot> _snapshotProvider;
    private readonly Func<AuthorizationDuration> _pairingDurationProvider;
    private readonly TimeProvider _timeProvider;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger _logger;
    private readonly IClipResponseWriter _responseWriter;
    private readonly LocalWebHostTimeouts _timeouts;
    private readonly RequestRateLimiter _pairRateLimiter;
    private readonly RequestRateLimiter _clipRateLimiter;

    private readonly CancellationTokenSource _handlerShutdown = new();
    private readonly object _handlerGate = new();
    private TaskCompletionSource _handlersDrained =
        new(TaskCreationOptions.RunContinuationsAsynchronously);
    private WebApplication? _application;
    private X509Certificate2? _httpsCertificate;
    private int _activeHandlers;
    private int _stopStarted;

    public LocalWebHost(
        IPEndPoint endpoint,
        IAuthorizationService authorization,
        Func<ClipboardSnapshot> snapshotProvider,
        AuthorizationDuration pairingDuration,
        TimeProvider? timeProvider = null,
        ILoggerFactory? loggerFactory = null,
        IClipResponseWriter? responseWriter = null,
        LocalWebHostTimeouts? timeouts = null)
        : this(
            endpoint,
            authorization,
            snapshotProvider,
            () => pairingDuration,
            timeProvider,
            loggerFactory,
            responseWriter,
            timeouts)
    {
    }

    public LocalWebHost(
        IPEndPoint endpoint,
        IAuthorizationService authorization,
        Func<ClipboardSnapshot> snapshotProvider,
        Func<AuthorizationDuration> pairingDurationProvider,
        TimeProvider? timeProvider = null,
        ILoggerFactory? loggerFactory = null,
        IClipResponseWriter? responseWriter = null,
        LocalWebHostTimeouts? timeouts = null)
    {
        ArgumentNullException.ThrowIfNull(endpoint);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(snapshotProvider);
        ArgumentNullException.ThrowIfNull(pairingDurationProvider);
        if (endpoint.AddressFamily != AddressFamily.InterNetwork || endpoint.Port != Port)
        {
            throw new ArgumentException(
                $"The local host must bind one selected IPv4 address on port {Port}.",
                nameof(endpoint));
        }

        _endpoint = endpoint;
        _authorization = authorization;
        _snapshotProvider = snapshotProvider;
        _pairingDurationProvider = pairingDurationProvider;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _loggerFactory = loggerFactory ?? LoggerFactory.Create(builder => builder.ClearProviders());
        _logger = _loggerFactory.CreateLogger<LocalWebHost>();
        _responseWriter = responseWriter ?? new JsonClipResponseWriter();
        _timeouts = timeouts ?? LocalWebHostTimeouts.Production;
        _pairRateLimiter = RequestRateLimiter.CreatePairing(_timeProvider);
        _clipRateLimiter = RequestRateLimiter.CreateClips(_timeProvider);
    }

    public IPEndPoint Endpoint => _endpoint;

    public async Task StartAsync(CancellationToken cancellationToken = default)
    {
        if (_application is not null)
        {
            throw new InvalidOperationException("The local web host has already been started.");
        }

        var builder = WebApplication.CreateSlimBuilder(
            new WebApplicationOptions
            {
                ApplicationName = typeof(LocalWebHost).Assembly.GetName().Name,
            });
        builder.Logging.ClearProviders();
        builder.Services.AddSingleton(_loggerFactory);
        var httpsCertificate = CreateHttpsCertificate(_endpoint.Address);
        builder.WebHost.ConfigureKestrel(options =>
        {
            options.Listen(_endpoint, listen => listen.UseHttps(httpsCertificate));
            options.Limits.MaxRequestBodySize = 1_048_576;
            options.AddServerHeader = false;
        });

        var application = builder.Build();
        application.Run(DispatchAsync);
        _application = application;
        _httpsCertificate = httpsCertificate;

        try
        {
            await application.StartAsync(cancellationToken);
        }
        catch
        {
            _application = null;
            _httpsCertificate = null;
            await application.DisposeAsync();
            httpsCertificate.Dispose();
            throw;
        }
    }

    public async Task<LocalWebHostStopResult> StopAsync(CancellationToken cancellationToken = default)
    {
        var application = _application;
        if (application is null || Interlocked.Exchange(ref _stopStarted, 1) != 0)
        {
            return LocalWebHostStopResult.Orderly;
        }

        using var drain = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        drain.CancelAfter(_timeouts.Drain);
        try
        {
            await application.StopAsync(drain.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
        }

        if (Volatile.Read(ref _activeHandlers) == 0)
        {
            return LocalWebHostStopResult.Orderly;
        }

        _handlerShutdown.Cancel();
        using var join = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        join.CancelAfter(_timeouts.CancelJoin);
        try
        {
            await application.StopAsync(join.Token);
            await WaitForHandlersDrainedAsync(join.Token);
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return LocalWebHostStopResult.Incomplete;
        }

        return Volatile.Read(ref _activeHandlers) == 0
            ? LocalWebHostStopResult.Orderly
            : LocalWebHostStopResult.Incomplete;
    }

    public async ValueTask DisposeAsync()
    {
        await StopAsync();
        if (_application is not null)
        {
            await _application.DisposeAsync();
            _application = null;
        }

        _httpsCertificate?.Dispose();
        _httpsCertificate = null;
        _handlerShutdown.Dispose();
    }

    private async Task DispatchAsync(HttpContext context)
    {
        BeginHandler();
        ApplySecurityHeaders(context.Response);
        var started = Stopwatch.GetTimestamp();
        var route = context.Request.Path.Value ?? "/";
        var source = GetCoarseSource(context.Connection.RemoteIpAddress);

        try
        {
            if (!HasExpectedHost(context.Request))
            {
                await WriteErrorAsync(
                    context,
                    StatusCodes.Status400BadRequest,
                    "invalid_request",
                    "The request host is invalid.");
                return;
            }

            if (route == "/clip-api/pair/exchange")
            {
                if (context.Request.Method != HttpMethods.Post)
                {
                    context.Response.Headers.Allow = HttpMethods.Post;
                    await WriteErrorAsync(
                        context,
                        StatusCodes.Status405MethodNotAllowed,
                        "method_not_allowed",
                        "The method is not allowed.");
                    return;
                }

                await HandlePairExchangeAsync(context);
                return;
            }

            if (route == "/clip-api/clips")
            {
                if (context.Request.Method != HttpMethods.Get)
                {
                    context.Response.Headers.Allow = HttpMethods.Get;
                    await WriteErrorAsync(
                        context,
                        StatusCodes.Status405MethodNotAllowed,
                        "method_not_allowed",
                        "The method is not allowed.");
                    return;
                }

                await HandleClipsAsync(context);
                return;
            }

            if (route == "/clip-api" ||
                route.StartsWith("/clip-api/", StringComparison.Ordinal))
            {
                await WriteErrorAsync(
                    context,
                    StatusCodes.Status404NotFound,
                    "not_found",
                    "The API route was not found.");
                return;
            }

            if (route == "/favicon.ico" &&
                context.Request.Method == HttpMethods.Get)
            {
                context.Response.StatusCode = StatusCodes.Status204NoContent;
                return;
            }

            var asset = WebAssets.Get(route);
            if (asset is not null)
            {
                if (context.Request.Method != HttpMethods.Get)
                {
                    context.Response.Headers.Allow = HttpMethods.Get;
                    context.Response.StatusCode = StatusCodes.Status405MethodNotAllowed;
                    return;
                }

                context.Response.StatusCode = StatusCodes.Status200OK;
                context.Response.ContentType = asset.Value.ContentType;
                await context.Response.Body.WriteAsync(asset.Value.Bytes, context.RequestAborted);
                return;
            }

            context.Response.StatusCode = StatusCodes.Status404NotFound;
        }
        catch (Exception) when (!context.Response.HasStarted)
        {
            await WriteErrorAsync(
                context,
                StatusCodes.Status500InternalServerError,
                "internal_error",
                "An internal error occurred.");
        }
        finally
        {
            var duration = Stopwatch.GetElapsedTime(started).TotalMilliseconds;
            _logger.LogInformation(
                "route={Route} status={Status} durationMs={Duration:F1} source={Source}",
                route,
                context.Response.StatusCode,
                duration,
                source);
            EndHandler();
        }
    }

    private void BeginHandler()
    {
        lock (_handlerGate)
        {
            if (_activeHandlers == 0)
            {
                _handlersDrained = new TaskCompletionSource(
                    TaskCreationOptions.RunContinuationsAsynchronously);
            }

            _activeHandlers++;
        }
    }

    private void EndHandler()
    {
        lock (_handlerGate)
        {
            _activeHandlers--;
            if (_activeHandlers == 0)
            {
                _handlersDrained.TrySetResult();
            }
        }
    }

    private Task WaitForHandlersDrainedAsync(CancellationToken cancellationToken)
    {
        lock (_handlerGate)
        {
            return _activeHandlers == 0
                ? Task.CompletedTask
                : _handlersDrained.Task.WaitAsync(cancellationToken);
        }
    }

    private async Task HandlePairExchangeAsync(HttpContext context)
    {
        if (IsCrossSiteBrowserRequest(context.Request))
        {
            await WriteErrorAsync(
                context,
                StatusCodes.Status403Forbidden,
                "cross_origin_denied",
                "Cross-origin pairing requests are not allowed.");
            return;
        }

        if (!IsJsonContentType(context.Request.ContentType))
        {
            await WriteErrorAsync(
                context,
                StatusCodes.Status415UnsupportedMediaType,
                "unsupported_media_type",
                "The request must use application/json.");
            return;
        }

        var source = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        if (!_pairRateLimiter.TryAcquire(source, out var retryAfter))
        {
            context.Response.Headers.RetryAfter = retryAfter.ToString(CultureInfo.InvariantCulture);
            await WriteErrorAsync(
                context,
                StatusCodes.Status429TooManyRequests,
                "rate_limited",
                "Too many pairing attempts.");
            return;
        }

        if (context.Request.ContentLength > PairBodyLimit)
        {
            await WriteErrorAsync(
                context,
                StatusCodes.Status413PayloadTooLarge,
                "request_too_large",
                "The pairing request is too large.");
            return;
        }

        byte[] body;
        try
        {
            body = await ReadBodyAsync(context.Request, PairBodyLimit, context.RequestAborted);
        }
        catch (RequestBodyTooLargeException)
        {
            await WriteErrorAsync(
                context,
                StatusCodes.Status413PayloadTooLarge,
                "request_too_large",
                "The pairing request is too large.");
            return;
        }

        PairExchangeRequest? request;
        try
        {
            request = JsonSerializer.Deserialize<PairExchangeRequest>(body, JsonOptions);
        }
        catch (JsonException)
        {
            request = null;
        }

        if (request is null ||
            !TryValidatePairingCode(request.Code, out var pairingCode) ||
            !TryNormalizeLabel(request.Label, out var label))
        {
            await WriteErrorAsync(
                context,
                StatusCodes.Status400BadRequest,
                "invalid_request",
                "The pairing request is invalid.");
            return;
        }

        using var exchangeCancellation = CancellationTokenSource.CreateLinkedTokenSource(
            context.RequestAborted,
            _handlerShutdown.Token);
        var result = await _authorization.ExchangeAsync(
            new ExchangeAuthorizationRequest(
                pairingCode,
                label,
                _endpoint.Address,
                _pairingDurationProvider()),
            exchangeCancellation.Token);

        if (!result.Succeeded)
        {
            if (result.Failure == AuthorizationFailure.Canceled &&
                exchangeCancellation.IsCancellationRequested)
            {
                context.Abort();
                return;
            }

            if (result.Failure == AuthorizationFailure.InvalidPairingCode)
            {
                await WriteErrorAsync(
                    context,
                    StatusCodes.Status401Unauthorized,
                    "pairing_failed",
                    "Pairing failed. Generate a new code on Windows.");
                return;
            }

            await WriteErrorAsync(
                context,
                StatusCodes.Status500InternalServerError,
                "internal_error",
                "An internal error occurred.");
            return;
        }

        var authorization = result.Authorization!;
        var cookieValue =
            $"{EncodeGuid(authorization.Id)}.{result.Token!.Value}";
        var sessionProof = result.SessionProof!;
        var maxAge = authorization.ExpiresAtUtc is { } expiresAtUtc
            ? expiresAtUtc - authorization.CreatedAtUtc
            : TimeSpan.FromDays(3650);
        context.Response.Cookies.Append(
            SessionCookieName,
            cookieValue,
            new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.Strict,
                Path = SessionCookiePath,
                MaxAge = maxAge,
                Expires = authorization.ExpiresAtUtc ?? _timeProvider.GetUtcNow().Add(maxAge),
                IsEssential = true,
            });
        await WriteJsonAsync(
            context,
            StatusCodes.Status200OK,
            new PairExchangeResponse(
                true,
                EncodeGuid(authorization.Id),
                authorization.ExpiresAtUtc,
                sessionProof));
    }

    private async Task HandleClipsAsync(HttpContext context)
    {
        if (!TryReadSession(context.Request, out var authorizationId, out var token, out var sessionProof))
        {
            await WriteUnauthorizedAsync(context);
            return;
        }

        var leaseResult = _authorization.AcquireLease(
            new AcquireLeaseRequest(authorizationId, token, _endpoint.Address, sessionProof));
        if (!leaseResult.Succeeded)
        {
            await WriteUnauthorizedAsync(context);
            return;
        }

        using var lease = leaseResult.Lease!;
        if (!_clipRateLimiter.TryAcquire(authorizationId.ToString("N"), out var retryAfter))
        {
            context.Response.Headers.RetryAfter = retryAfter.ToString(CultureInfo.InvariantCulture);
            await WriteErrorAsync(
                context,
                StatusCodes.Status429TooManyRequests,
                "rate_limited",
                "Too many clipboard requests.");
            return;
        }

        if (!TryReadClipQuery(context.Request.Query, out var instanceId, out var since))
        {
            await WriteErrorAsync(
                context,
                StatusCodes.Status400BadRequest,
                "invalid_request",
                "The clipboard query is invalid.");
            return;
        }

        var snapshot = _snapshotProvider();
        if (instanceId == snapshot.InstanceId && since == snapshot.Version)
        {
            context.Response.StatusCode = StatusCodes.Status204NoContent;
            return;
        }

        var response = new ClipSnapshotResponse(
            EncodeGuid(snapshot.InstanceId),
            snapshot.Version,
            snapshot.Items
                .Select(item => new ClipItemResponse(
                    EncodeGuid(item.Id),
                    item.CapturedAtUtc,
                    item.Text))
                .ToArray());
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(
            context.RequestAborted,
            lease.RevocationToken,
            _handlerShutdown.Token);
        await _responseWriter.WriteAsync(context, response, linked.Token);
    }

    private bool HasExpectedHost(HttpRequest request) =>
        IsExpectedHost(request.Host, _endpoint);

    internal static bool IsExpectedHost(HostString host, IPEndPoint endpoint) =>
        string.Equals(
            host.Value,
            $"{endpoint.Address}:{endpoint.Port}",
            StringComparison.Ordinal);

    private static bool IsJsonContentType(string? contentType) =>
        contentType is not null &&
        Microsoft.Net.Http.Headers.MediaTypeHeaderValue.TryParse(contentType, out var parsed) &&
        string.Equals(parsed.MediaType.Value, "application/json", StringComparison.OrdinalIgnoreCase);

    private static async Task<byte[]> ReadBodyAsync(
        HttpRequest request,
        int maximumBytes,
        CancellationToken cancellationToken)
    {
        using var memory = new MemoryStream();
        var buffer = ArrayPool<byte>.Shared.Rent(Math.Min(maximumBytes + 1, 4096));
        try
        {
            while (true)
            {
                var read = await request.Body.ReadAsync(buffer, cancellationToken);
                if (read == 0)
                {
                    return memory.ToArray();
                }

                if (memory.Length + read > maximumBytes)
                {
                    throw new RequestBodyTooLargeException();
                }

                memory.Write(buffer, 0, read);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static bool TryValidatePairingCode(string? value, out string pairingCode)
    {
        pairingCode = "";
        if (value is null || value.Length != 32 ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '-' and not '_'))
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[24];
        var base64 = value.Replace('-', '+').Replace('_', '/');
        if (!Convert.TryFromBase64String(base64, bytes, out var written) ||
            written != bytes.Length ||
            EncodeBytes(bytes) != value)
        {
            return false;
        }

        pairingCode = value;
        return true;
    }

    private static bool TryNormalizeLabel(string? value, out string label)
    {
        label = value?.Trim() ?? "";
        if (label.Length == 0)
        {
            label = "Unnamed browser";
            return true;
        }

        var scalarCount = 0;
        for (var index = 0; index < label.Length;)
        {
            var status = Rune.DecodeFromUtf16(
                label.AsSpan(index),
                out _,
                out var consumed);
            if (status != OperationStatus.Done)
            {
                return false;
            }

            scalarCount++;
            if (scalarCount > 64)
            {
                return false;
            }

            index += consumed;
        }

        return true;
    }

    private bool TryReadSession(
        HttpRequest request,
        out Guid authorizationId,
        out SessionToken token,
        out string sessionProof)
    {
        authorizationId = default;
        token = null!;
        sessionProof = "";
        if (!request.Cookies.TryGetValue(SessionCookieName, out var cookie) ||
            !request.Headers.TryGetValue(SessionProofHeaderName, out var proofValues) ||
            proofValues.Count != 1)
        {
            return false;
        }

        var separator = cookie.IndexOf('.');
        if (separator <= 0 ||
            !TryDecodeGuid(cookie[..separator], out authorizationId) ||
            !SessionToken.TryParse(cookie[(separator + 1)..], out var parsedToken))
        {
            return false;
        }

        token = parsedToken!;
        sessionProof = proofValues[0]!;
        return true;
    }

    private static bool TryReadClipQuery(
        IQueryCollection query,
        out Guid? instanceId,
        out ulong? since)
    {
        instanceId = null;
        since = null;
        if (query.Count == 0)
        {
            return true;
        }

        if (query.Count != 2 ||
            !query.TryGetValue("instance", out var instanceValues) ||
            instanceValues.Count != 1 ||
            !query.TryGetValue("since", out var sinceValues) ||
            sinceValues.Count != 1 ||
            !TryDecodeGuid(instanceValues[0], out var parsedInstance) ||
            !ulong.TryParse(
                sinceValues[0],
                NumberStyles.None,
                CultureInfo.InvariantCulture,
                out var parsedSince))
        {
            return false;
        }

        instanceId = parsedInstance;
        since = parsedSince;
        return true;
    }

    private static string EncodeGuid(Guid value) => EncodeBytes(value.ToByteArray());

    private static string EncodeBytes(ReadOnlySpan<byte> value) =>
        Convert.ToBase64String(value)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static bool TryDecodeGuid(string? value, out Guid guid)
    {
        guid = default;
        if (value is null || value.Length != 22 ||
            value.Any(character =>
                !char.IsAsciiLetterOrDigit(character) &&
                character is not '-' and not '_'))
        {
            return false;
        }

        Span<byte> bytes = stackalloc byte[16];
        var base64 = value.Replace('-', '+').Replace('_', '/') + "==";
        if (!Convert.TryFromBase64String(base64, bytes, out var written) ||
            written != bytes.Length ||
            EncodeBytes(bytes) != value)
        {
            return false;
        }

        guid = new Guid(bytes);
        return true;
    }

    private async Task WriteUnauthorizedAsync(HttpContext context)
    {
        await WriteErrorAsync(
            context,
            StatusCodes.Status401Unauthorized,
            "unauthorized",
            "Pairing is required.");
    }

    private static Task WriteErrorAsync(
        HttpContext context,
        int status,
        string code,
        string message)
    {
        if (status == StatusCodes.Status401Unauthorized &&
            context.Request.Cookies.ContainsKey(SessionCookieName))
        {
            ExpireSessionCookie(context.Response);
        }

        return WriteJsonAsync(context, status, new ApiErrorEnvelope(new ApiError(code, message)));
    }

    private static void ExpireSessionCookie(HttpResponse response)
    {
        response.Cookies.Append(
            SessionCookieName,
            "",
            new CookieOptions
            {
                Path = SessionCookiePath,
                HttpOnly = true,
                SameSite = SameSiteMode.Strict,
                Secure = true,
                MaxAge = TimeSpan.Zero,
                Expires = DateTimeOffset.UnixEpoch,
            });
    }

    private static Task WriteJsonAsync<T>(HttpContext context, int status, T value)
    {
        context.Response.StatusCode = status;
        context.Response.ContentType = "application/json; charset=utf-8";
        return context.Response.WriteAsJsonAsync(value, JsonOptions, context.RequestAborted);
    }

    private static void ApplySecurityHeaders(HttpResponse response)
    {
        response.Headers.CacheControl = "no-store, max-age=0";
        response.Headers.Pragma = "no-cache";
        response.Headers.ContentSecurityPolicy = ContentSecurityPolicy;
        response.Headers["Referrer-Policy"] = "no-referrer";
        response.Headers.XContentTypeOptions = "nosniff";
    }

    private bool IsCrossSiteBrowserRequest(HttpRequest request)
    {
        if (request.Headers.TryGetValue("Sec-Fetch-Site", out var fetchSiteValues) &&
            fetchSiteValues.Any(value =>
                string.Equals(value, "cross-site", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        if (!request.Headers.TryGetValue("Origin", out var originValues))
        {
            return false;
        }

        return originValues.Count != 1 ||
            !Uri.TryCreate(originValues[0], UriKind.Absolute, out var origin) ||
            !string.Equals(origin.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(origin.Host, _endpoint.Address.ToString(), StringComparison.OrdinalIgnoreCase) ||
            origin.Port != _endpoint.Port;
    }

    private static X509Certificate2 CreateHttpsCertificate(IPAddress address)
    {
        using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var request = new CertificateRequest(
            "CN=Universal Clipboard Local Web",
            key,
            HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        san.AddIpAddress(address);
        if (!IPAddress.Loopback.Equals(address))
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

        var now = DateTimeOffset.UtcNow;
        using var certificate = request.CreateSelfSigned(
            now.AddMinutes(-5),
            now.AddDays(7));
        return X509CertificateLoader.LoadPkcs12(
            certificate.Export(X509ContentType.Pkcs12),
            password: null,
            X509KeyStorageFlags.EphemeralKeySet);
    }

    private static string GetCoarseSource(IPAddress? address)
    {
        if (address is null)
        {
            return "unknown";
        }

        if (IPAddress.IsLoopback(address))
        {
            return "loopback";
        }

        var bytes = address.GetAddressBytes();
        return bytes.Length == 4 &&
            (bytes[0] == 10 ||
             bytes[0] == 192 && bytes[1] == 168 ||
             bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
            ? "private"
            : "other";
    }

    private sealed class JsonClipResponseWriter : IClipResponseWriter
    {
        public Task WriteAsync(
            HttpContext context,
            ClipSnapshotResponse response,
            CancellationToken cancellationToken)
        {
            context.Response.StatusCode = StatusCodes.Status200OK;
            context.Response.ContentType = "application/json; charset=utf-8";
            return context.Response.WriteAsJsonAsync(response, JsonOptions, cancellationToken);
        }
    }

    private sealed class RequestBodyTooLargeException : Exception;
}
