using System.Collections.Immutable;
using System.Net;

namespace UniversalClipboard.Core.Authorization;

public interface IAuthorizationService
{
    AuthorizationSnapshot Snapshot { get; }

    ImmutableArray<AuthorizationRecord> List();

    ValueTask<ExchangeAuthorizationResult> ExchangeAsync(
        ExchangeAuthorizationRequest request,
        CancellationToken cancellationToken = default);

    AcquireLeaseResult AcquireLease(AcquireLeaseRequest request);

    ValueTask<AuthorizationMutationResult> RevokeAsync(
        Guid authorizationId,
        CancellationToken cancellationToken = default);

    ValueTask<AuthorizationMutationResult> RevokeAllAsync(
        CancellationToken cancellationToken = default);

    ValueTask<AuthorizationMutationResult> RemoveStaleBindingsAsync(
        IReadOnlyCollection<IPAddress> activeHostIpv4Addresses,
        CancellationToken cancellationToken = default);
}
