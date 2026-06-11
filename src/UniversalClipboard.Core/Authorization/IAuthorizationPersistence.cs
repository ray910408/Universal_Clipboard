namespace UniversalClipboard.Core.Authorization;

public interface IAuthorizationPersistence
{
    Task<AuthorizationDocument> LoadAsync(CancellationToken cancellationToken = default);

    Task SaveAsync(
        AuthorizationDocument document,
        CancellationToken cancellationToken = default);
}
