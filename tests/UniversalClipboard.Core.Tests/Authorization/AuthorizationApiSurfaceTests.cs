using System.Collections.Immutable;
using FluentAssertions;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.Core.Tests.Authorization;

public sealed class AuthorizationApiSurfaceTests
{
    [Fact]
    public void Web_facing_service_exposes_only_exchange_and_acquire_lease()
    {
        var service = typeof(IAuthorizationService);

        service.GetProperties().Should().BeEmpty();
        service.GetMethods().Select(method => method.Name).Should().BeEquivalentTo(
            nameof(IAuthorizationService.ExchangeAsync),
            nameof(IAuthorizationService.AcquireLease));
    }

    [Fact]
    public void Administration_surface_exposes_sanitized_list_and_mutations()
    {
        var administration = typeof(IAuthorizationAdministration);

        administration.GetProperties().Should().BeEmpty();
        administration.GetMethods().Select(method => method.Name).Should().BeEquivalentTo(
            nameof(IAuthorizationAdministration.List),
            nameof(IAuthorizationAdministration.RevokeAsync),
            nameof(IAuthorizationAdministration.RevokeAllAsync),
            nameof(IAuthorizationAdministration.RemoveStaleBindingsAsync));
        administration.GetMethod(nameof(IAuthorizationAdministration.List))!
            .ReturnType.Should().Be(typeof(ImmutableArray<AuthorizationMetadata>));
        typeof(AuthorizationMetadata).GetProperty("TokenDigest").Should().BeNull();
        typeof(AuthorizationMutationResult).GetProperty(nameof(AuthorizationMutationResult.Snapshot))!
            .PropertyType.Should().Be(typeof(AuthorizationAdministrationSnapshot));
    }

    [Fact]
    public void Web_exchange_result_and_public_coordinator_do_not_expose_digest_state()
    {
        typeof(ExchangeAuthorizationResult)
            .GetProperty(nameof(ExchangeAuthorizationResult.Authorization))!
            .PropertyType.Should().Be(typeof(AuthorizationMetadata));
        typeof(AuthorizationCoordinator).GetProperty("Snapshot").Should().BeNull();
        typeof(AuthorizationCoordinator).Should().Implement<IAuthorizationService>();
        typeof(AuthorizationCoordinator).Should().Implement<IAuthorizationAdministration>();
    }
}
