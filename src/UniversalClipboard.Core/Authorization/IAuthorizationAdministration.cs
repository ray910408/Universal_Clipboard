using System.Collections.Immutable;
using System.Net;

namespace UniversalClipboard.Core.Authorization;

public interface IAuthorizationAdministration
{
    ImmutableArray<AuthorizationMetadata> List();

    ValueTask<AuthorizationMutationResult> RevokeAsync(
        Guid authorizationId,
        CancellationToken cancellationToken = default);

    ValueTask<AuthorizationMutationResult> RevokeAllAsync(
        CancellationToken cancellationToken = default);

    ValueTask<AuthorizationMutationResult> RemoveStaleBindingsAsync(
        IReadOnlyCollection<IPAddress> activeHostIpv4Addresses,
        CancellationToken cancellationToken = default);
}
