using System.Net;
using FluentAssertions;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.Core.Tests.Authorization;

public sealed class AuthorizationCoordinatorExchangeTests
{
    [Fact]
    public async Task Create_loads_persisted_authorizations_into_snapshot()
    {
        var record = AuthorizationRecordFactory.Create();
        var persistence = new FakeAuthorizationPersistence(
            new AuthorizationDocument([record]));

        await using var coordinator = await CreateCoordinatorAsync(persistence);

        coordinator.List().Should().Equal(AuthorizationRecordFactory.Metadata(record));
    }

    [Fact]
    public async Task Exchange_rejects_invalid_pairing_code_without_saving()
    {
        var persistence = new FakeAuthorizationPersistence();
        await using var coordinator = await CreateCoordinatorAsync(persistence);

        var result = await coordinator.ExchangeAsync(
            new ExchangeAuthorizationRequest(
                "invalid",
                "Browser",
                IPAddress.Parse("192.168.1.5"),
                AuthorizationDuration.FiveHours));

        result.Succeeded.Should().BeFalse();
        result.Failure.Should().Be(AuthorizationFailure.InvalidPairingCode);
        result.Token.Should().BeNull();
        persistence.SaveAttempts.Should().BeEmpty();
    }

    [Fact]
    public async Task Exchange_reports_invalid_request_after_consuming_valid_code()
    {
        var persistence = new FakeAuthorizationPersistence();
        var pairingCodes = CreatePairingCodes();
        var code = pairingCodes.Create();
        await using var coordinator = await CreateCoordinatorAsync(persistence, pairingCodes);
        var request = new ExchangeAuthorizationRequest(
            code.Value,
            "",
            IPAddress.Loopback,
            AuthorizationDuration.FiveHours);

        var invalid = await coordinator.ExchangeAsync(request);
        var retried = await coordinator.ExchangeAsync(request);

        invalid.Failure.Should().Be(AuthorizationFailure.InvalidRequest);
        invalid.Token.Should().BeNull();
        retried.Failure.Should().Be(AuthorizationFailure.InvalidPairingCode);
        persistence.SaveAttempts.Should().BeEmpty();
    }

    [Fact]
    public async Task Exchange_saves_before_publishing_and_returns_token_after_durable_save()
    {
        var saveStarted = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var releaseSave = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var persistence = new FakeAuthorizationPersistence
        {
            OnSaveAsync = async (_, _) =>
            {
                saveStarted.SetResult();
                await releaseSave.Task;
            },
        };
        var pairingCodes = CreatePairingCodes();
        var code = pairingCodes.Create();
        await using var coordinator = await CreateCoordinatorAsync(persistence, pairingCodes);

        var exchangeTask = coordinator.ExchangeAsync(
            new ExchangeAuthorizationRequest(
                code.Value,
                "Browser",
                IPAddress.Parse("192.168.1.5"),
                AuthorizationDuration.FiveHours));
        await saveStarted.Task;

        coordinator.List().Should().BeEmpty();
        exchangeTask.IsCompleted.Should().BeFalse();

        releaseSave.SetResult();
        var result = await exchangeTask;

        result.Succeeded.Should().BeTrue();
        result.Token.Should().NotBeNull();
        result.Authorization.Should().NotBeNull();
        coordinator.List().Should().Equal(result.Authorization);
        persistence.SavedDocument!.Authorizations.Should().ContainSingle(
            authorization => authorization.Id == result.Authorization!.Id);
    }

    [Fact]
    public async Task Exchange_uses_duration_bound_to_pairing_code()
    {
        var persistence = new FakeAuthorizationPersistence();
        var pairingCodes = CreatePairingCodes();
        var code = pairingCodes.Create(AuthorizationDuration.OneHour);
        await using var coordinator = await CreateCoordinatorAsync(persistence, pairingCodes);

        var result = await coordinator.ExchangeAsync(
            new ExchangeAuthorizationRequest(
                code.Value,
                "Browser",
                IPAddress.Parse("192.168.1.5"),
                AuthorizationDuration.Permanent));

        result.Succeeded.Should().BeTrue();
        result.Authorization!.ExpiresAtUtc.Should().Be(
            result.Authorization.CreatedAtUtc.AddHours(1));
    }

    [Theory]
    [InlineData(AuthorizationPermissions.Write)]
    [InlineData(AuthorizationPermissions.ReadWrite)]
    public async Task Exchange_uses_permissions_bound_to_pairing_code(
        AuthorizationPermissions permissions)
    {
        var persistence = new FakeAuthorizationPersistence();
        var pairingCodes = CreatePairingCodes();
        var code = pairingCodes.Create(AuthorizationDuration.OneHour, permissions);
        await using var coordinator = await CreateCoordinatorAsync(persistence, pairingCodes);

        var result = await coordinator.ExchangeAsync(
            new ExchangeAuthorizationRequest(
                code.Value,
                "Browser",
                IPAddress.Parse("192.168.1.5"),
                AuthorizationDuration.Permanent));

        result.Succeeded.Should().BeTrue();
        result.Authorization!.Permissions.Should().Be(permissions);
    }

    [Fact]
    public async Task Failed_exchange_keeps_old_state_returns_no_token_and_consumes_code()
    {
        var existing = AuthorizationRecordFactory.Create();
        var persistence = new FakeAuthorizationPersistence(new AuthorizationDocument([existing]))
        {
            OnSaveAsync = (_, _) => throw new InvalidOperationException("simulated failure"),
        };
        var pairingCodes = CreatePairingCodes();
        var code = pairingCodes.Create();
        await using var coordinator = await CreateCoordinatorAsync(persistence, pairingCodes);
        var request = new ExchangeAuthorizationRequest(
            code.Value,
            "Browser",
            IPAddress.Parse("192.168.1.5"),
            AuthorizationDuration.OneHour);

        var failed = await coordinator.ExchangeAsync(request);
        var retried = await coordinator.ExchangeAsync(request);

        failed.Succeeded.Should().BeFalse();
        failed.Failure.Should().Be(AuthorizationFailure.PersistenceFailed);
        failed.Authorization.Should().BeNull();
        failed.Token.Should().BeNull();
        retried.Failure.Should().Be(AuthorizationFailure.InvalidPairingCode);
        coordinator.List().Should().Equal(AuthorizationRecordFactory.Metadata(existing));
    }

    [Fact]
    public async Task Exchange_result_does_not_leak_token_from_ToString()
    {
        var persistence = new FakeAuthorizationPersistence();
        var pairingCodes = CreatePairingCodes();
        var code = pairingCodes.Create();
        await using var coordinator = await CreateCoordinatorAsync(persistence, pairingCodes);

        var result = await coordinator.ExchangeAsync(
            new ExchangeAuthorizationRequest(
                code.Value,
                "Browser",
                IPAddress.Loopback,
                AuthorizationDuration.Permanent));

        result.ToString().Should().NotContain(result.Token!.Value);
    }

    [Fact]
    public async Task Concurrent_exchange_of_same_pairing_code_has_one_success()
    {
        var persistence = new FakeAuthorizationPersistence();
        var pairingCodes = CreatePairingCodes();
        var code = pairingCodes.Create();
        await using var coordinator = await CreateCoordinatorAsync(persistence, pairingCodes);
        var request = new ExchangeAuthorizationRequest(
            code.Value,
            "Browser",
            IPAddress.Loopback,
            AuthorizationDuration.OneHour);

        var results = await Task.WhenAll(
            Enumerable.Range(0, 32)
                .Select(_ => coordinator.ExchangeAsync(request).AsTask()));

        results.Count(result => result.Succeeded).Should().Be(1);
        persistence.SaveAttempts.Should().ContainSingle();
    }

    [Fact]
    public void Exchange_request_ToString_redacts_pairing_code()
    {
        const string pairingCode = "sensitive-pairing-code";
        var request = new ExchangeAuthorizationRequest(
            pairingCode,
            "Browser",
            IPAddress.Loopback,
            AuthorizationDuration.OneHour);

        request.ToString().Should().NotContain(pairingCode);
        request.ToString().Should().Contain("[REDACTED]");
    }

    private static PairingCodeManager CreatePairingCodes() =>
        new(
            new ManualTimeProvider(AuthorizationRecordFactory.Now),
            new QueueEntropySource(Enumerable.Repeat((byte)3, 24).ToArray()));

    private static ValueTask<AuthorizationCoordinator> CreateCoordinatorAsync(
        FakeAuthorizationPersistence persistence,
        PairingCodeManager? pairingCodes = null)
    {
        var clock = new ManualTimeProvider(AuthorizationRecordFactory.Now);
        var tokens = new SessionTokenService(
            clock,
            new QueueEntropySource(
                Enumerable.Repeat((byte)4, 16).ToArray(),
                Enumerable.Repeat((byte)5, 32).ToArray()));

        return AuthorizationCoordinator.CreateAsync(
            persistence,
            pairingCodes ?? CreatePairingCodes(),
            tokens,
            clock);
    }
}
