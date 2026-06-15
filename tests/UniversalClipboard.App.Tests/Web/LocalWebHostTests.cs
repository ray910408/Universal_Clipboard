using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using UniversalClipboard.App.Web;
using UniversalClipboard.Core.Authorization;
using UniversalClipboard.Core.Clipboard;

namespace UniversalClipboard.App.Tests.Web;

public sealed class LocalWebHostTests
{
    private static readonly IPEndPoint Endpoint = new(IPAddress.Loopback, 43127);

    [Theory]
    [InlineData("/")]
    [InlineData("/pair")]
    [InlineData("/app.css")]
    [InlineData("/app.js")]
    public async Task Static_routes_have_security_and_no_cache_headers(string path)
    {
        await using var fixture = await HostFixture.StartAsync();

        var response = await fixture.Client.GetAsync(path);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        AssertSecurityHeaders(response);
        (await response.Content.ReadAsStringAsync()).Should().NotBeEmpty();
    }

    [Fact]
    public async Task Favicon_request_returns_no_content_with_security_and_no_cache_headers()
    {
        await using var fixture = await HostFixture.StartAsync();

        var response = await fixture.Client.GetAsync("/favicon.ico");

        response.StatusCode.Should().Be(HttpStatusCode.NoContent);
        (await response.Content.ReadAsByteArrayAsync()).Should().BeEmpty();
        AssertSecurityHeaders(response);
    }

    [Theory]
    [InlineData("127.0.0.2:43127")]
    [InlineData("127.0.0.1:9999")]
    public async Task Wrong_host_address_or_port_is_rejected_with_unified_json_error(
        string host)
    {
        await using var fixture = await HostFixture.StartAsync();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/clip-api/clips");
        request.Headers.Host = host;

        var response = await fixture.Client.SendAsync(request);

        await AssertErrorAsync(response, HttpStatusCode.BadRequest, "invalid_request");
        AssertSecurityHeaders(response);
    }

    [Fact]
    public void Host_validation_rejects_missing_host()
    {
        LocalWebHost.IsExpectedHost(new HostString(), Endpoint).Should().BeFalse();
    }

    [Fact]
    public async Task Pair_success_sets_scoped_cookie_after_durable_exchange()
    {
        await using var fixture = await HostFixture.StartAsync();
        var code = fixture.PairingCodes.Create().Value;

        var response = await fixture.PostPairAsync(code, "  My iPhone  ");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var cookie = response.Headers.GetValues("Set-Cookie").Single();
        cookie.Should().Contain("clip_session=");
        cookie.Should().Contain("httponly");
        cookie.Should().Contain("samesite=strict");
        cookie.Should().Contain("path=/clip-api");
        cookie.Should().Contain("max-age=18000");
        cookie.Should().Contain("secure");
        var json = await ReadJsonAsync(response);
        json.RootElement.GetProperty("authorized").GetBoolean().Should().BeTrue();
        json.RootElement.GetProperty("authorizationId").GetString().Should().HaveLength(22);
        json.RootElement.GetProperty("sessionProof").GetString().Should().HaveLength(43);
        json.RootElement.GetProperty("expiresAt").ValueKind.Should().Be(JsonValueKind.String);
        fixture.Coordinator.List().Single().Label.Should().Be("My iPhone");
    }

    [Fact]
    public async Task Pair_success_stores_permissions_device_and_browser_metadata()
    {
        await using var fixture = await HostFixture.StartAsync();
        var code = fixture.PairingCodes
            .Create(AuthorizationDuration.FiveHours, AuthorizationPermissions.ReadWrite)
            .Value;

        var response = await fixture.PostPairAsync(
            new
            {
                code,
                label = "  My iPhone  ",
                deviceName = "  Kenneth's iPhone  ",
                browserName = "  Safari  ",
            });

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var authorization = fixture.Coordinator.List().Single();
        authorization.Label.Should().Be("My iPhone");
        authorization.DeviceName.Should().Be("Kenneth's iPhone");
        authorization.BrowserName.Should().Be("Safari");
        authorization.Permissions.Should().Be(AuthorizationPermissions.ReadWrite);
        var json = await ReadJsonAsync(response);
        json.RootElement.GetProperty("permission").GetString().Should().Be("readWrite");
        json.RootElement.GetProperty("deviceName").GetString().Should().Be("Kenneth's iPhone");
        json.RootElement.GetProperty("browserName").GetString().Should().Be("Safari");
    }

    [Fact]
    public async Task Pair_omitted_permission_defaults_to_read_only()
    {
        await using var fixture = await HostFixture.StartAsync();

        var response = await fixture.PostPairAsync(
            fixture.PairingCodes.Create().Value,
            "Phone");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        fixture.Coordinator.List().Single().Permissions.Should().Be(AuthorizationPermissions.Read);
        var json = await ReadJsonAsync(response);
        json.RootElement.GetProperty("permission").GetString().Should().Be("read");
    }

    [Fact]
    public async Task Pair_mobile_permission_field_is_rejected_and_cannot_escalate()
    {
        await using var fixture = await HostFixture.StartAsync();
        var code = fixture.PairingCodes.Create().Value;

        var response = await fixture.PostPairAsync(
            new
            {
                code,
                label = "Phone",
                permission = "readWrite",
            });

        await AssertErrorAsync(response, HttpStatusCode.BadRequest, "invalid_request");
        fixture.Coordinator.List().Should().BeEmpty();
    }

    [Theory]
    [InlineData("{\"code\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY\",\"label\":\"Phone\",\"deviceName\":\"\\uD800\"}")]
    [InlineData("{\"code\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY\",\"label\":\"Phone\",\"browserName\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}")]
    public async Task Pair_invalid_metadata_returns_400(string body)
    {
        await using var fixture = await HostFixture.StartAsync();

        var response = await fixture.Client.PostAsync(
            "/clip-api/pair/exchange",
            new StringContent(body, Encoding.UTF8, "application/json"));

        await AssertErrorAsync(response, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task Pair_exchange_uses_duration_bound_to_generated_code()
    {
        var duration = AuthorizationDuration.OneHour;
        await using var fixture = await HostFixture.StartAsync(
            pairingDurationProvider: () => duration);
        var code = fixture.PairingCodes.Create(duration).Value;
        duration = AuthorizationDuration.OneWeek;

        var response = await fixture.PostPairAsync(code, "Phone");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var authorization = fixture.Coordinator.List().Single();
        authorization.ExpiresAtUtc.Should().Be(
            authorization.CreatedAtUtc.AddHours(1));
    }

    [Theory]
    [InlineData("{\"code\":\"bad\",\"label\":\"Phone\"}")]
    [InlineData("{\"code\":\"AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY\",\"extra\":1}")]
    [InlineData("[]")]
    [InlineData("{")]
    public async Task Pair_invalid_requests_return_400_without_framework_html(string body)
    {
        await using var fixture = await HostFixture.StartAsync();

        var response = await fixture.Client.PostAsync(
            "/clip-api/pair/exchange",
            new StringContent(body, Encoding.UTF8, "application/json"));

        await AssertErrorAsync(response, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task Pair_errors_cover_media_type_size_method_and_rate_limit()
    {
        await using var fixture = await HostFixture.StartAsync();

        var media = await fixture.Client.PostAsync(
            "/clip-api/pair/exchange",
            new StringContent("{}", Encoding.UTF8, "text/plain"));
        await AssertErrorAsync(
            media,
            HttpStatusCode.UnsupportedMediaType,
            "unsupported_media_type");

        var oversized = await fixture.Client.PostAsync(
            "/clip-api/pair/exchange",
            new StringContent(
                JsonSerializer.Serialize(new { code = new string('a', 1_025) }),
                Encoding.UTF8,
                "application/json"));
        await AssertErrorAsync(
            oversized,
            HttpStatusCode.RequestEntityTooLarge,
            "request_too_large");

        var method = await fixture.Client.GetAsync("/clip-api/pair/exchange");
        await AssertErrorAsync(
            method,
            HttpStatusCode.MethodNotAllowed,
            "method_not_allowed");
        method.Content.Headers.Allow.Should().Contain("POST");
    }

    [Fact]
    public async Task Pair_body_limit_applies_to_chunked_requests_and_accepts_exactly_1_kib()
    {
        await using var fixture = await HostFixture.StartAsync();
        var code = fixture.PairingCodes.Create().Value;
        var validPrefix = JsonSerializer.Serialize(new { code, label = "Phone" });
        var exactBody = validPrefix + new string(' ', 1_024 - Encoding.UTF8.GetByteCount(validPrefix));
        using var exactContent = new StreamContent(
            new MemoryStream(Encoding.UTF8.GetBytes(exactBody)));
        exactContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var exactRequest = new HttpRequestMessage(HttpMethod.Post, "/clip-api/pair/exchange")
        {
            Content = exactContent,
        };
        exactRequest.Headers.TransferEncodingChunked = true;

        var exact = await fixture.Client.SendAsync(exactRequest);

        exact.StatusCode.Should().Be(HttpStatusCode.OK);

        fixture.Clock.Advance(TimeSpan.FromMinutes(1));
        var oversizedBody = new string(' ', 1_025);
        using var oversizedContent = new StreamContent(
            new MemoryStream(Encoding.UTF8.GetBytes(oversizedBody)));
        oversizedContent.Headers.ContentType = new MediaTypeHeaderValue("application/json");
        using var oversizedRequest = new HttpRequestMessage(
            HttpMethod.Post,
            "/clip-api/pair/exchange")
        {
            Content = oversizedContent,
        };
        oversizedRequest.Headers.TransferEncodingChunked = true;

        var oversized = await fixture.Client.SendAsync(oversizedRequest);

        await AssertErrorAsync(
            oversized,
            HttpStatusCode.RequestEntityTooLarge,
            "request_too_large");
    }

    [Fact]
    public async Task Pair_host_rate_limit_allows_five_attempts_then_returns_retry_after()
    {
        await using var fixture = await HostFixture.StartAsync();
        const string nonexistentCode = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY";

        for (var attempt = 0; attempt < 5; attempt++)
        {
            var response = await fixture.PostPairAsync(nonexistentCode, "Phone");
            await AssertErrorAsync(
                response,
                HttpStatusCode.Unauthorized,
                "pairing_failed");
        }

        var limited = await fixture.PostPairAsync(nonexistentCode, "Phone");

        await AssertErrorAsync(limited, HttpStatusCode.TooManyRequests, "rate_limited");
        limited.Headers.GetValues("Retry-After").Single().Should().Be("60");
    }

    [Fact]
    public async Task Permanent_pairing_has_null_server_expiry_and_far_future_cookie()
    {
        await using var fixture = await HostFixture.StartAsync(
            pairingDuration: AuthorizationDuration.Permanent);
        var response = await fixture.PostPairAsync(
            fixture.PairingCodes.Create(AuthorizationDuration.Permanent).Value,
            "Phone");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await ReadJsonAsync(response);
        json.RootElement.GetProperty("expiresAt").ValueKind.Should().Be(JsonValueKind.Null);
        response.Headers.GetValues("Set-Cookie").Single().Should().Contain("max-age=315360000");
        fixture.Coordinator.List().Single().ExpiresAtUtc.Should().BeNull();
    }

    [Fact]
    public async Task All_pairing_code_failures_are_indistinguishable()
    {
        await using var fixture = await HostFixture.StartAsync();
        var code = fixture.PairingCodes.Create().Value;
        (await fixture.PostPairAsync(code, "Phone")).EnsureSuccessStatusCode();

        var reused = await fixture.PostPairAsync(code, "Phone");
        fixture.Clock.Advance(TimeSpan.FromMinutes(3));
        var expiredCode = fixture.PairingCodes.Create().Value;
        fixture.Clock.Advance(TimeSpan.FromMinutes(3));
        var expired = await fixture.PostPairAsync(expiredCode, "Phone");

        await AssertErrorAsync(reused, HttpStatusCode.Unauthorized, "pairing_failed");
        await AssertErrorAsync(expired, HttpStatusCode.Unauthorized, "pairing_failed");
    }

    [Fact]
    public async Task Persistence_failure_returns_500_without_cookie_and_consumes_code()
    {
        var persistence = new FakeAuthorizationPersistence
        {
            OnSaveAsync = _ => throw new IOException("disk full"),
        };
        await using var fixture = await HostFixture.StartAsync(persistence: persistence);
        var code = fixture.PairingCodes.Create().Value;

        var failed = await fixture.PostPairAsync(code, "Phone");
        persistence.OnSaveAsync = null;
        var retried = await fixture.PostPairAsync(code, "Phone");

        await AssertErrorAsync(failed, HttpStatusCode.InternalServerError, "internal_error");
        failed.Headers.TryGetValues("Set-Cookie", out _).Should().BeFalse();
        await AssertErrorAsync(retried, HttpStatusCode.Unauthorized, "pairing_failed");
    }

    [Fact]
    public async Task Protected_401_clears_the_api_cookie()
    {
        await using var fixture = await HostFixture.StartAsync();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/clip-api/clips");
        request.Headers.Add("Cookie", "clip_session=invalid");

        var response = await fixture.Client.SendAsync(request);

        await AssertErrorAsync(response, HttpStatusCode.Unauthorized, "unauthorized");
        response.Headers.GetValues("Set-Cookie").Single().Should().Contain("max-age=0");
        response.Headers.GetValues("Set-Cookie").Single().Should().Contain("path=/clip-api");
    }

    [Fact]
    public async Task Clips_accepts_read_only_authorization()
    {
        await using var fixture = await HostFixture.StartAsync();
        fixture.History.Add("shared");
        var session = await fixture.PairAsync("read");

        var response = await fixture.GetClipsAsync(session);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task Clips_returns_403_for_write_only_without_clearing_cookie()
    {
        await using var fixture = await HostFixture.StartAsync();
        fixture.History.Add("shared");
        var session = await fixture.PairAsync("write");

        var response = await fixture.GetClipsAsync(session);

        await AssertErrorAsync(response, HttpStatusCode.Forbidden, "forbidden");
        response.Headers.TryGetValues("Set-Cookie", out _).Should().BeFalse();
    }

    [Fact]
    public async Task Incoming_text_accepts_write_authorization_and_returns_id()
    {
        await using var fixture = await HostFixture.StartAsync();
        var session = await fixture.PairAsync("write");

        var response = await fixture.PostIncomingTextAsync(session, "from phone");

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await ReadJsonAsync(response);
        json.RootElement.GetProperty("accepted").GetBoolean().Should().BeTrue();
        json.RootElement.GetProperty("incomingId").GetString().Should().HaveLength(22);
        fixture.Incoming.Items.Should().ContainSingle()
            .Which.Text.Should().Be("from phone");
    }

    [Fact]
    public async Task Incoming_text_returns_403_for_read_only_without_clearing_cookie()
    {
        await using var fixture = await HostFixture.StartAsync();
        var session = await fixture.PairAsync("read");

        var response = await fixture.PostIncomingTextAsync(session, "from phone");

        await AssertErrorAsync(response, HttpStatusCode.Forbidden, "forbidden");
        response.Headers.TryGetValues("Set-Cookie", out _).Should().BeFalse();
    }

    [Fact]
    public async Task Incoming_text_unauthenticated_returns_401_and_clears_cookie_when_present()
    {
        await using var fixture = await HostFixture.StartAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/clip-api/incoming-text")
        {
            Content = JsonContent.Create(new { text = "from phone" }),
        };
        request.Headers.Add("Cookie", "clip_session=invalid");

        var response = await fixture.Client.SendAsync(request);

        await AssertErrorAsync(response, HttpStatusCode.Unauthorized, "unauthorized");
        response.Headers.GetValues("Set-Cookie").Single().Should().Contain("max-age=0");
    }

    [Fact]
    public async Task Incoming_text_unauthenticated_wrong_content_type_returns_401_before_validation()
    {
        await using var fixture = await HostFixture.StartAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/clip-api/incoming-text")
        {
            Content = new StringContent("not json", Encoding.UTF8, "text/plain"),
        };
        request.Headers.Add("Cookie", "clip_session=invalid");

        var response = await fixture.Client.SendAsync(request);

        await AssertErrorAsync(response, HttpStatusCode.Unauthorized, "unauthorized");
        response.Headers.GetValues("Set-Cookie").Single().Should().Contain("max-age=0");
    }

    [Theory]
    [InlineData("text/plain", "{\"text\":\"ok\"}", HttpStatusCode.UnsupportedMediaType, "unsupported_media_type")]
    [InlineData("application/json", "{", HttpStatusCode.BadRequest, "invalid_request")]
    [InlineData("application/json", "{}", HttpStatusCode.BadRequest, "invalid_request")]
    [InlineData("application/json", "{\"text\":123}", HttpStatusCode.BadRequest, "invalid_request")]
    [InlineData("application/json", "{\"text\":\"\"}", HttpStatusCode.BadRequest, "invalid_request")]
    [InlineData("application/json", "{\"text\":\"\\uD800\"}", HttpStatusCode.BadRequest, "invalid_request")]
    public async Task Incoming_text_invalid_requests_are_rejected(
        string mediaType,
        string body,
        HttpStatusCode status,
        string code)
    {
        await using var fixture = await HostFixture.StartAsync();
        var session = await fixture.PairAsync("write");
        using var request = new HttpRequestMessage(HttpMethod.Post, "/clip-api/incoming-text")
        {
            Content = new StringContent(body, Encoding.UTF8, mediaType),
        };
        AddSession(request, session);

        var response = await fixture.Client.SendAsync(request);

        await AssertErrorAsync(response, status, code);
    }

    [Fact]
    public async Task Incoming_text_oversized_text_is_rejected()
    {
        await using var fixture = await HostFixture.StartAsync();
        var session = await fixture.PairAsync("write");

        var response = await fixture.PostIncomingTextAsync(
            session,
            new string('x', StrictUtf8TextValidator.MaxUtf8Bytes + 1));

        await AssertErrorAsync(response, HttpStatusCode.RequestEntityTooLarge, "request_too_large");
    }

    [Fact]
    public async Task Incoming_text_method_not_allowed_allows_post()
    {
        await using var fixture = await HostFixture.StartAsync();

        var response = await fixture.Client.GetAsync("/clip-api/incoming-text");

        await AssertErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed");
        response.Content.Headers.Allow.Should().Contain("POST");
    }

    [Fact]
    public async Task Clips_rejects_stolen_cookie_without_session_proof_header()
    {
        await using var fixture = await HostFixture.StartAsync();
        var session = await fixture.PairAsync();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/clip-api/clips");
        request.Headers.Add("Cookie", session.Cookie);

        var response = await fixture.Client.SendAsync(request);

        await AssertErrorAsync(response, HttpStatusCode.Unauthorized, "unauthorized");
        response.Headers.GetValues("Set-Cookie").Single().Should().Contain("max-age=0");
    }

    [Fact]
    public async Task Clips_rejects_wrong_session_proof_for_valid_cookie()
    {
        await using var fixture = await HostFixture.StartAsync();
        var session = await fixture.PairAsync();

        var response = await fixture.GetClipsAsync(session with { Proof = "wrong-proof" });

        await AssertErrorAsync(response, HttpStatusCode.Unauthorized, "unauthorized");
        response.Headers.GetValues("Set-Cookie").Single().Should().Contain("max-age=0");
    }

    [Fact]
    public async Task Clips_rejects_stolen_authorization_token_replayed_as_proof()
    {
        await using var fixture = await HostFixture.StartAsync();
        var session = await fixture.PairAsync();
        var bearer = session.Cookie["clip_session=".Length..];

        var response = await fixture.GetClipsAsync(session with { Proof = bearer });

        await AssertErrorAsync(response, HttpStatusCode.Unauthorized, "unauthorized");
        response.Headers.GetValues("Set-Cookie").Single().Should().Contain("max-age=0");
    }

    [Fact]
    public async Task Clips_rejects_session_proof_without_cookie()
    {
        await using var fixture = await HostFixture.StartAsync();
        var session = await fixture.PairAsync();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/clip-api/clips");
        request.Headers.Add("X-Clip-Session", session.Proof);

        var response = await fixture.Client.SendAsync(request);

        await AssertErrorAsync(response, HttpStatusCode.Unauthorized, "unauthorized");
        response.Headers.Contains("Set-Cookie").Should().BeFalse();
    }

    [Fact]
    public async Task Clips_rejects_invalid_token_cookie_and_expires_session_cookie()
    {
        var authorizationId = Guid.Parse("c7439162-df34-4c76-9cc7-9cffd158f8e4");
        var record = AuthorizationTestFactory.CreateRecord(authorizationId, tokenByte: 9);
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]));
        await using var fixture = await HostFixture.StartAsync(persistence: persistence);
        var cookie = CreateSessionCookie(authorizationId, tokenByte: 8);

        using var request = new HttpRequestMessage(HttpMethod.Get, "/clip-api/clips");
        AddSession(request, new SessionPair(cookie, "wrong-proof"));
        var response = await fixture.Client.SendAsync(request);

        await AssertErrorAsync(response, HttpStatusCode.Unauthorized, "unauthorized");
        response.Headers.GetValues("Set-Cookie").Single().Should().Contain("max-age=0");
    }

    [Fact]
    public async Task Clips_rejects_revoked_token_after_durable_revoke()
    {
        await using var fixture = await HostFixture.StartAsync();
        var session = await fixture.PairAsync();
        var authorizationId = fixture.Coordinator.List().Single().Id;
        (await fixture.Coordinator.RevokeAsync(authorizationId)).Succeeded.Should().BeTrue();

        var response = await fixture.GetClipsAsync(session);

        await AssertErrorAsync(response, HttpStatusCode.Unauthorized, "unauthorized");
        response.Headers.GetValues("Set-Cookie").Single().Should().Contain("max-age=0");
    }

    [Fact]
    public async Task Clips_rejects_expired_token_and_removes_stale_authorization()
    {
        await using var fixture = await HostFixture.StartAsync(
            pairingDuration: AuthorizationDuration.OneHour);
        var session = await fixture.PairAsync();
        fixture.Clock.Advance(TimeSpan.FromHours(1));

        var response = await fixture.GetClipsAsync(session);

        await AssertErrorAsync(response, HttpStatusCode.Unauthorized, "unauthorized");
        response.Headers.GetValues("Set-Cookie").Single().Should().Contain("max-age=0");
        await WaitUntilAsync(() => fixture.Coordinator.List().IsEmpty);
    }

    [Fact]
    public async Task Clips_rejects_session_bound_to_a_different_local_ipv4()
    {
        var authorizationId = Guid.Parse("5e459bc0-c2f1-47ab-903f-17fe81c5b4bc");
        var record = AuthorizationTestFactory.CreateRecord(authorizationId, tokenByte: 9)
            with { BoundHostIpv4 = IPAddress.Parse("127.0.0.2") };
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]));
        await using var fixture = await HostFixture.StartAsync(persistence: persistence);
        var cookie = CreateSessionCookie(authorizationId, tokenByte: 9);

        var response = await fixture.GetClipsAsync(new SessionPair(cookie, "wrong-proof"));

        await AssertErrorAsync(response, HttpStatusCode.Unauthorized, "unauthorized");
        response.Headers.GetValues("Set-Cookie").Single().Should().Contain("max-age=0");
    }

    [Fact]
    public async Task Browser_origin_header_does_not_get_cors_grant_for_clip_api()
    {
        await using var fixture = await HostFixture.StartAsync();
        fixture.History.Add("same-origin readable only");
        var session = await fixture.PairAsync();
        using var request = new HttpRequestMessage(HttpMethod.Get, "/clip-api/clips");
        AddSession(request, session);
        request.Headers.Add("Origin", "https://attacker.example");

        var response = await fixture.Client.SendAsync(request);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        response.Headers.TryGetValues("Access-Control-Allow-Origin", out _).Should().BeFalse();
        AssertSecurityHeaders(response);
    }

    [Fact]
    public async Task Cors_preflight_to_clip_api_is_not_granted()
    {
        await using var fixture = await HostFixture.StartAsync();
        using var request = new HttpRequestMessage(HttpMethod.Options, "/clip-api/clips");
        request.Headers.Add("Origin", "https://attacker.example");
        request.Headers.Add("Access-Control-Request-Method", "GET");

        var response = await fixture.Client.SendAsync(request);

        await AssertErrorAsync(response, HttpStatusCode.MethodNotAllowed, "method_not_allowed");
        response.Headers.TryGetValues("Access-Control-Allow-Origin", out _).Should().BeFalse();
        response.Headers.TryGetValues("Access-Control-Allow-Credentials", out _).Should().BeFalse();
    }

    [Fact]
    public async Task Pair_exchange_rejects_cross_origin_browser_form_before_content_type()
    {
        await using var fixture = await HostFixture.StartAsync();
        using var request = new HttpRequestMessage(HttpMethod.Post, "/clip-api/pair/exchange")
        {
            Content = new StringContent(
                "code=AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY&label=Phone",
                Encoding.UTF8,
                "application/x-www-form-urlencoded"),
        };
        request.Headers.Add("Origin", "https://attacker.example");

        var response = await fixture.Client.SendAsync(request);

        await AssertErrorAsync(
            response,
            HttpStatusCode.Forbidden,
            "cross_origin_denied");
        response.Headers.TryGetValues("Access-Control-Allow-Origin", out _).Should().BeFalse();
    }

    [Fact]
    public async Task Pair_exchange_cross_origin_form_posts_do_not_consume_pairing_rate_limit()
    {
        await using var fixture = await HostFixture.StartAsync();
        const string nonexistentCode = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY";

        for (var attempt = 0; attempt < 5; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, "/clip-api/pair/exchange")
            {
                Content = new StringContent(
                    "code=" + nonexistentCode + "&label=Phone",
                    Encoding.UTF8,
                    "application/x-www-form-urlencoded"),
            };
            request.Headers.Add("Origin", "https://attacker.example");

            var response = await fixture.Client.SendAsync(request);

            await AssertErrorAsync(
                response,
                HttpStatusCode.Forbidden,
                "cross_origin_denied");
        }

        var json = await fixture.PostPairAsync(nonexistentCode, "Phone");

        await AssertErrorAsync(json, HttpStatusCode.Unauthorized, "pairing_failed");
    }

    [Fact]
    public async Task Pairing_401_also_clears_an_existing_api_cookie()
    {
        await using var fixture = await HostFixture.StartAsync();
        using var request = new HttpRequestMessage(
            HttpMethod.Post,
            "/clip-api/pair/exchange")
        {
            Content = JsonContent.Create(
                new
                {
                    code = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY",
                    label = "Phone",
                }),
        };
        request.Headers.Add("Cookie", "clip_session=existing");

        var response = await fixture.Client.SendAsync(request);

        await AssertErrorAsync(response, HttpStatusCode.Unauthorized, "pairing_failed");
        var cookie = response.Headers.GetValues("Set-Cookie").Single();
        cookie.Should().Contain("max-age=0");
        cookie.Should().Contain("path=/clip-api");
    }

    [Fact]
    public async Task Clips_support_full_unchanged_future_and_instance_mismatch_semantics()
    {
        await using var fixture = await HostFixture.StartAsync();
        fixture.History.Add(
            new ClipboardItem(
                Guid.Parse("59d94a29-4b1c-4f85-a786-4aef41cc02cd"),
                AuthorizationTestFactory.Now,
                "exact clipboard text"));
        var session = await fixture.PairAsync();

        var initial = await fixture.GetClipsAsync(session);
        initial.StatusCode.Should().Be(HttpStatusCode.OK);
        var json = await ReadJsonAsync(initial);
        var instance = json.RootElement.GetProperty("instanceId").GetString();
        var version = json.RootElement.GetProperty("version").GetUInt64();
        json.RootElement.GetProperty("items")[0].GetProperty("text").GetString()
            .Should().Be("exact clipboard text");

        var unchanged = await fixture.GetClipsAsync(session, instance, version);
        unchanged.StatusCode.Should().Be(HttpStatusCode.NoContent);
        (await unchanged.Content.ReadAsByteArrayAsync()).Should().BeEmpty();
        AssertSecurityHeaders(unchanged);

        fixture.Clock.Advance(TimeSpan.FromSeconds(1));
        var future = await fixture.GetClipsAsync(session, instance, version + 100);
        future.StatusCode.Should().Be(HttpStatusCode.OK);

        fixture.Clock.Advance(TimeSpan.FromSeconds(1));
        var different = await fixture.GetClipsAsync(
            session,
            Convert.ToBase64String(Guid.NewGuid().ToByteArray())
                .TrimEnd('=').Replace('+', '-').Replace('/', '_'),
            version);
        different.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Theory]
    [InlineData("?instance=bad&since=0")]
    [InlineData("?instance=AQIDBAUGBwgJCgsMDQ4PEA")]
    [InlineData("?since=0")]
    [InlineData("?instance=AQIDBAUGBwgJCgsMDQ4PEA&since=-1")]
    [InlineData("?instance=AQIDBAUGBwgJCgsMDQ4PEA&since=18446744073709551616")]
    public async Task Clips_reject_invalid_query_pairs(string query)
    {
        await using var fixture = await HostFixture.StartAsync();
        var session = await fixture.PairAsync();

        var response = await fixture.GetClipsRawAsync(session, query);

        await AssertErrorAsync(response, HttpStatusCode.BadRequest, "invalid_request");
    }

    [Fact]
    public async Task Clips_are_limited_to_two_requests_per_second_per_authorization()
    {
        await using var fixture = await HostFixture.StartAsync();
        var session = await fixture.PairAsync();

        (await fixture.GetClipsAsync(session)).StatusCode.Should().Be(HttpStatusCode.OK);
        (await fixture.GetClipsAsync(session)).StatusCode.Should().Be(HttpStatusCode.OK);
        var limited = await fixture.GetClipsAsync(session);

        await AssertErrorAsync(limited, HttpStatusCode.TooManyRequests, "rate_limited");
        limited.Headers.GetValues("Retry-After").Single().Should().Be("1");
    }

    [Fact]
    public async Task Unknown_api_route_and_wrong_method_are_unified_json()
    {
        await using var fixture = await HostFixture.StartAsync();

        var missing = await fixture.Client.GetAsync("/clip-api/missing");
        var method = await fixture.Client.PostAsync("/clip-api/clips", content: null);

        await AssertErrorAsync(missing, HttpStatusCode.NotFound, "not_found");
        await AssertErrorAsync(method, HttpStatusCode.MethodNotAllowed, "method_not_allowed");
        method.Content.Headers.Allow.Should().Contain("GET");
    }

    [Fact]
    public async Task Static_miss_is_empty_but_still_has_security_headers()
    {
        await using var fixture = await HostFixture.StartAsync();

        var response = await fixture.Client.GetAsync("/missing");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await response.Content.ReadAsByteArrayAsync()).Should().BeEmpty();
        AssertSecurityHeaders(response);
    }

    [Fact]
    public async Task Similar_api_prefix_is_a_static_miss_not_an_api_route()
    {
        await using var fixture = await HostFixture.StartAsync();

        var response = await fixture.Client.GetAsync("/clip-apix");

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        (await response.Content.ReadAsByteArrayAsync()).Should().BeEmpty();
        AssertSecurityHeaders(response);
    }

    [Fact]
    public async Task Logs_never_include_cookie_code_body_or_clipboard_content()
    {
        var logger = new CapturingLoggerProvider();
        await using var fixture = await HostFixture.StartAsync(loggerProvider: logger);
        fixture.History.Add("clipboard secret");
        var code = fixture.PairingCodes.Create().Value;
        var response = await fixture.PostPairAsync(code, "masked preview");
        var cookie = HostFixture.GetCookie(response);
        var proof = (await ReadJsonAsync(response)).RootElement.GetProperty("sessionProof").GetString()!;
        await fixture.GetClipsAsync(new SessionPair(cookie, proof));

        var combined = string.Join("\n", logger.Messages);
        combined.Should().Contain("/clip-api/pair/exchange");
        combined.Should().Contain("status=200");
        combined.Should().NotContain(code);
        combined.Should().NotContain(cookie);
        combined.Should().NotContain("clipboard secret");
        combined.Should().NotContain("masked preview");
    }

    [Fact]
    public async Task Port_collision_fails_startup_and_shutdown_stops_accepting()
    {
        await using var first = await HostFixture.StartAsync();
        await using var second = await HostFixture.CreateAsync();

        var start = () => second.Host.StartAsync();

        await start.Should().ThrowAsync<IOException>();
        await first.Host.StopAsync();
        var request = () => first.Client.GetAsync("/");
        await request.Should().ThrowAsync<HttpRequestException>();
    }

    [Fact]
    public async Task Revoke_waits_for_inflight_response_and_cancels_content_before_success()
    {
        var writer = new BlockingClipResponseWriter();
        await using var fixture = await HostFixture.StartAsync(responseWriter: writer);
        fixture.History.Add("must not complete after revoke");
        var session = await fixture.PairAsync();
        var authorizationId = fixture.Coordinator.List().Single().Id;

        var responseTask = fixture.GetClipsAsync(
            session,
            completionOption: HttpCompletionOption.ResponseHeadersRead);
        await writer.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var revokeTask = fixture.Coordinator.RevokeAsync(authorizationId).AsTask();
        await writer.Canceled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        revokeTask.IsCompleted.Should().BeFalse();

        writer.Release();
        var response = await responseTask;
        var revoke = await revokeTask.WaitAsync(TimeSpan.FromSeconds(5));

        revoke.Succeeded.Should().BeTrue();
        (await response.Content.ReadAsStringAsync()).Should().NotContain(
            "must not complete after revoke");
    }

    [Fact]
    public async Task Shutdown_drains_then_cancels_active_handlers_with_configured_bounds()
    {
        var writer = new CancellationAwareClipResponseWriter();
        await using var fixture = await HostFixture.StartAsync(
            responseWriter: writer,
            timeouts: new LocalWebHostTimeouts(
                TimeSpan.FromMilliseconds(75),
                TimeSpan.FromMilliseconds(250)));
        fixture.History.Add("active response");
        var session = await fixture.PairAsync();
        var request = fixture.GetClipsAsync(
            session,
            completionOption: HttpCompletionOption.ResponseHeadersRead);
        await writer.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var started = DateTimeOffset.UtcNow;
        await fixture.Host.StopAsync();
        var elapsed = DateTimeOffset.UtcNow - started;

        await writer.Canceled.Task.WaitAsync(TimeSpan.FromSeconds(5));
        elapsed.Should().BeLessThan(TimeSpan.FromSeconds(1));
        try
        {
            await request;
        }
        catch (HttpRequestException)
        {
        }
    }

    [Fact]
    public async Task Shutdown_reports_incomplete_when_handlers_ignore_cancel_join()
    {
        var writer = new BlockingClipResponseWriter();
        await using var fixture = await HostFixture.StartAsync(
            responseWriter: writer,
            timeouts: new LocalWebHostTimeouts(
                TimeSpan.FromMilliseconds(25),
                TimeSpan.FromMilliseconds(25)));
        fixture.History.Add("active response");
        var session = await fixture.PairAsync();
        var request = fixture.GetClipsAsync(
            session,
            completionOption: HttpCompletionOption.ResponseHeadersRead);
        await writer.Started.Task.WaitAsync(TimeSpan.FromSeconds(5));

        var result = await fixture.Host.StopAsync();
        writer.Release();

        result.CompletedOrderly.Should().BeFalse();
        try
        {
            await request;
        }
        catch (HttpRequestException)
        {
        }
    }

    [Fact]
    public void Production_shutdown_timeouts_are_five_second_drain_and_two_second_join()
    {
        LocalWebHostTimeouts.Production.Drain.Should().Be(TimeSpan.FromSeconds(5));
        LocalWebHostTimeouts.Production.CancelJoin.Should().Be(TimeSpan.FromSeconds(2));
    }

    [Fact]
    public async Task Shutdown_does_not_cancel_persistence_that_already_started()
    {
        var saveStarted = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSave = new TaskCompletionSource(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var persistence = new FakeAuthorizationPersistence
        {
            OnSaveAsync = async _ =>
            {
                saveStarted.TrySetResult();
                await releaseSave.Task;
            },
        };
        await using var fixture = await HostFixture.StartAsync(
            persistence: persistence,
            timeouts: new LocalWebHostTimeouts(
                TimeSpan.FromMilliseconds(50),
                TimeSpan.FromMilliseconds(50)));
        var pairTask = fixture.PostPairAsync(
            fixture.PairingCodes.Create().Value,
            "Phone");
        await saveStarted.Task.WaitAsync(TimeSpan.FromSeconds(5));

        await fixture.Host.StopAsync();
        releaseSave.TrySetResult();

        await WaitUntilAsync(() => fixture.Coordinator.List().Length == 1);
        try
        {
            await pairTask;
        }
        catch (HttpRequestException)
        {
        }

        fixture.Coordinator.List().Should().ContainSingle();
    }

    [Fact]
    public async Task Shutdown_cancels_pairing_command_that_has_not_started_persistence()
    {
        var authorizationId = Guid.Parse("7ff875e5-6de1-487f-8bb4-2669a7397722");
        var record = AuthorizationTestFactory.CreateRecord(authorizationId, tokenByte: 9);
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([record]));
        RecordingAuthorizationService? recording = null;
        await using var fixture = await HostFixture.StartAsync(
            persistence: persistence,
            timeouts: new LocalWebHostTimeouts(
                TimeSpan.FromMilliseconds(75),
                TimeSpan.FromMilliseconds(250)),
            authorizationServiceFactory: coordinator =>
            {
                recording = new RecordingAuthorizationService(coordinator);
                return recording;
            });
        using var lease = fixture.Coordinator.AcquireLease(
            new AcquireLeaseRequest(
                authorizationId,
                SessionToken.FromBytes(Enumerable.Repeat((byte)9, 32).ToArray()),
                IPAddress.Loopback,
                AuthorizationTestFactory.CreateProof())).Lease!;
        var revokeTask = fixture.Coordinator.RevokeAsync(authorizationId).AsTask();
        await WaitUntilAsync(() => lease.RevocationToken.IsCancellationRequested);

        var pairTask = fixture.PostPairAsync(
            fixture.PairingCodes.Create().Value,
            "Must not persist");
        var exchangeToken = await recording!.ExchangeEntered.WaitAsync(TimeSpan.FromSeconds(5));

        exchangeToken.CanBeCanceled.Should().BeTrue(
            "shutdown must cancel a queued exchange before persistence starts");
        var stopTask = fixture.Host.StopAsync();
        await WaitUntilAsync(() => exchangeToken.IsCancellationRequested);
        lease.Dispose();

        (await revokeTask.WaitAsync(TimeSpan.FromSeconds(5))).Succeeded.Should().BeTrue();
        await stopTask.WaitAsync(TimeSpan.FromSeconds(5));
        try
        {
            await pairTask;
        }
        catch (HttpRequestException)
        {
        }

        fixture.Coordinator.List().Should().BeEmpty();
        persistence.Document.Authorizations.Should().BeEmpty();
    }

    private static async Task<JsonDocument> ReadJsonAsync(HttpResponseMessage response) =>
        JsonDocument.Parse(await response.Content.ReadAsByteArrayAsync());

    private static string CreateSessionCookie(Guid authorizationId, byte tokenByte) =>
        "clip_session=" +
        Convert.ToBase64String(authorizationId.ToByteArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_') +
        "." +
        SessionToken.FromBytes(Enumerable.Repeat(tokenByte, 32).ToArray()).Value;

    private sealed record SessionPair(string Cookie, string Proof);

    private static void AddSession(HttpRequestMessage request, SessionPair session)
    {
        request.Headers.Add("Cookie", session.Cookie);
        request.Headers.Add("X-Clip-Session", session.Proof);
    }

    private static async Task AssertErrorAsync(
        HttpResponseMessage response,
        HttpStatusCode status,
        string code)
    {
        response.StatusCode.Should().Be(status);
        response.Content.Headers.ContentType!.MediaType.Should().Be("application/json");
        var json = await ReadJsonAsync(response);
        json.RootElement.GetProperty("error").GetProperty("code").GetString().Should().Be(code);
        AssertSecurityHeaders(response);
    }

    private static void AssertSecurityHeaders(HttpResponseMessage response)
    {
        response.Headers.CacheControl!.NoStore.Should().BeTrue();
        response.Headers.CacheControl.MaxAge.Should().Be(TimeSpan.Zero);
        response.Headers.GetValues("Pragma").Should().Contain("no-cache");
        response.Headers.GetValues("Content-Security-Policy").Single().Should().Be(
            "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
            "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
        response.Headers.GetValues("Referrer-Policy").Single().Should().Be("no-referrer");
        response.Headers.GetValues("X-Content-Type-Options").Single().Should().Be("nosniff");
    }

    private sealed class HostFixture : IAsyncDisposable
    {
        private HostFixture(
            LocalWebHost host,
            AuthorizationCoordinator coordinator,
            PairingCodeManager pairingCodes,
            ClipboardHistory history,
            RecordingIncomingTextSink incoming,
            ManualTimeProvider clock,
            AuthorizationDuration pairingDuration)
        {
            Host = host;
            Coordinator = coordinator;
            PairingCodes = pairingCodes;
            History = history;
            Incoming = incoming;
            Clock = clock;
            PairingDuration = pairingDuration;
            Client = new HttpClient(new HttpClientHandler
            {
                ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator,
            })
            {
                BaseAddress = new Uri("https://127.0.0.1:43127"),
                Timeout = TimeSpan.FromSeconds(5),
            };
        }

        public LocalWebHost Host { get; }

        public AuthorizationCoordinator Coordinator { get; }

        public PairingCodeManager PairingCodes { get; }

        public ClipboardHistory History { get; }

        public RecordingIncomingTextSink Incoming { get; }

        public ManualTimeProvider Clock { get; }

        public HttpClient Client { get; }

        private AuthorizationDuration PairingDuration { get; }

        public static async Task<HostFixture> StartAsync(
            FakeAuthorizationPersistence? persistence = null,
            CapturingLoggerProvider? loggerProvider = null,
            IClipResponseWriter? responseWriter = null,
            AuthorizationDuration pairingDuration = AuthorizationDuration.FiveHours,
            Func<AuthorizationDuration>? pairingDurationProvider = null,
            LocalWebHostTimeouts? timeouts = null,
            Func<AuthorizationCoordinator, IAuthorizationService>?
                authorizationServiceFactory = null)
        {
            var fixture = await CreateAsync(
                persistence,
                loggerProvider,
                responseWriter,
                pairingDuration,
                pairingDurationProvider,
                timeouts,
                authorizationServiceFactory);
            await fixture.Host.StartAsync();
            return fixture;
        }

        public static async Task<HostFixture> CreateAsync(
            FakeAuthorizationPersistence? persistence = null,
            CapturingLoggerProvider? loggerProvider = null,
            IClipResponseWriter? responseWriter = null,
            AuthorizationDuration pairingDuration = AuthorizationDuration.FiveHours,
            Func<AuthorizationDuration>? pairingDurationProvider = null,
            LocalWebHostTimeouts? timeouts = null,
            Func<AuthorizationCoordinator, IAuthorizationService>?
                authorizationServiceFactory = null)
        {
            var clock = new ManualTimeProvider(AuthorizationTestFactory.Now);
            var (coordinator, pairingCodes) =
                await AuthorizationTestFactory.CreateCoordinatorAsync(
                    persistence ?? new FakeAuthorizationPersistence(),
                    clock);
            var history = new ClipboardHistory(clock);
            var loggerFactory = LoggerFactory.Create(builder =>
            {
                builder.SetMinimumLevel(LogLevel.Trace);
                builder.AddFilter("Microsoft", LogLevel.None);
                if (loggerProvider is not null)
                {
                    builder.AddProvider(loggerProvider);
                }
            });
            var incoming = new RecordingIncomingTextSink();
            var host = new LocalWebHost(
                Endpoint,
                authorizationServiceFactory?.Invoke(coordinator) ?? coordinator,
                () => history.Snapshot,
                pairingDurationProvider ?? (() => pairingDuration),
                clock,
                loggerFactory,
                responseWriter,
                timeouts,
                incoming);
            return new HostFixture(host, coordinator, pairingCodes, history, incoming, clock, pairingDuration);
        }

        public async Task<HttpResponseMessage> PostPairAsync(string code, string label) =>
            await PostPairAsync(new { code, label });

        public async Task<HttpResponseMessage> PostPairAsync(object body) =>
            await Client.PostAsync(
                "/clip-api/pair/exchange",
                JsonContent.Create(body));

        public async Task<SessionPair> PairAsync(string permission = "read")
        {
            var boundPermission = permission switch
            {
                "read" => AuthorizationPermissions.Read,
                "write" => AuthorizationPermissions.Write,
                "readWrite" => AuthorizationPermissions.ReadWrite,
                _ => throw new ArgumentOutOfRangeException(nameof(permission)),
            };
            var response = await PostPairAsync(
                new
                {
                    code = PairingCodes.Create(PairingDuration, boundPermission).Value,
                    label = "Phone",
                });
            response.EnsureSuccessStatusCode();
            var proof = (await ReadJsonAsync(response)).RootElement.GetProperty("sessionProof").GetString()!;
            return new SessionPair(GetCookie(response), proof);
        }

        public Task<HttpResponseMessage> PostIncomingTextAsync(SessionPair session, string text)
        {
            var request = new HttpRequestMessage(HttpMethod.Post, "/clip-api/incoming-text")
            {
                Content = JsonContent.Create(new { text }),
            };
            AddSession(request, session);
            return Client.SendAsync(request);
        }

        public Task<HttpResponseMessage> GetClipsAsync(
            SessionPair session,
            string? instance = null,
            ulong? since = null,
            HttpCompletionOption completionOption = HttpCompletionOption.ResponseContentRead)
        {
            var query = instance is null
                ? ""
                : $"?instance={Uri.EscapeDataString(instance)}&since={since}";
            return GetClipsRawAsync(session, query, completionOption);
        }

        public Task<HttpResponseMessage> GetClipsRawAsync(
            SessionPair session,
            string query,
            HttpCompletionOption completionOption = HttpCompletionOption.ResponseContentRead)
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/clip-api/clips" + query);
            AddSession(request, session);
            return Client.SendAsync(request, completionOption);
        }

        public static string GetCookie(HttpResponseMessage response) =>
            response.Headers.GetValues("Set-Cookie").Single().Split(';')[0];

        public async ValueTask DisposeAsync()
        {
            Client.Dispose();
            await Host.DisposeAsync();
            await Coordinator.DisposeAsync();
        }
    }

    private sealed class BlockingClipResponseWriter : IClipResponseWriter
    {
        private readonly TaskCompletionSource _release =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Canceled { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task WriteAsync(
            HttpContext context,
            ClipSnapshotResponse response,
            CancellationToken cancellationToken)
        {
            context.Response.StatusCode = StatusCodes.Status200OK;
            context.Response.ContentType = "application/json; charset=utf-8";
            await context.Response.StartAsync(cancellationToken);
            Started.TrySetResult();
            using var registration = cancellationToken.Register(() => Canceled.TrySetResult());
            await _release.Task;
            if (!cancellationToken.IsCancellationRequested)
            {
                await context.Response.WriteAsJsonAsync(response, cancellationToken);
            }
        }

        public void Release() => _release.TrySetResult();
    }

    private sealed class RecordingIncomingTextSink : IIncomingTextSink
    {
        public List<IncomingTextItem> Items { get; } = [];

        public ValueTask<IncomingTextItem> EnqueueAsync(
            IncomingTextRequest request,
            CancellationToken cancellationToken = default)
        {
            var item = new IncomingTextItem(
                Guid.NewGuid(),
                request.Authorization.Id,
                request.Authorization.DeviceName,
                request.Authorization.BrowserName,
                request.Text,
                DateTimeOffset.UtcNow);
            Items.Add(item);
            return ValueTask.FromResult(item);
        }
    }

    private sealed class CancellationAwareClipResponseWriter : IClipResponseWriter
    {
        public TaskCompletionSource Started { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Canceled { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async Task WriteAsync(
            HttpContext context,
            ClipSnapshotResponse response,
            CancellationToken cancellationToken)
        {
            context.Response.StatusCode = StatusCodes.Status200OK;
            context.Response.ContentType = "application/json; charset=utf-8";
            await context.Response.StartAsync(cancellationToken);
            Started.TrySetResult();
            try
            {
                await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                Canceled.TrySetResult();
            }
        }
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!condition())
        {
            await Task.Delay(10, timeout.Token);
        }
    }
}
