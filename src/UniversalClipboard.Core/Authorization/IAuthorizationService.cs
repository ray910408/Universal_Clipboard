namespace UniversalClipboard.Core.Authorization;

public interface IAuthorizationService
{
    ValueTask<ExchangeAuthorizationResult> ExchangeAsync(
        ExchangeAuthorizationRequest request,
        CancellationToken cancellationToken = default);

    AcquireLeaseResult AcquireLease(AcquireLeaseRequest request);
}
