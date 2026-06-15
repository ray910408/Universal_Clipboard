using System.Text.Json.Serialization;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.App.Web;

internal sealed record PairExchangeRequest(
    [property: JsonPropertyName("code")] string? Code,
    [property: JsonPropertyName("label")] string? Label,
    [property: JsonPropertyName("deviceName")] string? DeviceName = null,
    [property: JsonPropertyName("browserName")] string? BrowserName = null);

public sealed record PairExchangeResponse(
    bool Authorized,
    string AuthorizationId,
    DateTimeOffset? ExpiresAt,
    string SessionProof,
    string Permission,
    string? DeviceName,
    string? BrowserName);

internal sealed record IncomingTextPostRequest(
    [property: JsonPropertyName("text")] string? Text);

public sealed record IncomingTextPostResponse(
    bool Accepted,
    string IncomingId);

public sealed record IncomingTextRequest(
    AuthorizationMetadata Authorization,
    string Text);

public sealed record IncomingTextItem(
    Guid IncomingId,
    Guid AuthorizationId,
    string? DeviceName,
    string? BrowserName,
    string Text,
    DateTimeOffset ReceivedAtUtc);

public interface IIncomingTextSink
{
    ValueTask<IncomingTextItem> EnqueueAsync(
        IncomingTextRequest request,
        CancellationToken cancellationToken = default);

    ValueTask ClearAuthorizationAsync(
        Guid authorizationId,
        CancellationToken cancellationToken = default) =>
        ValueTask.CompletedTask;

    ValueTask ClearAllAsync(CancellationToken cancellationToken = default) =>
        ValueTask.CompletedTask;
}

public sealed record ClipItemResponse(
    string Id,
    DateTimeOffset CopiedAt,
    string Text);

public sealed record ClipSnapshotResponse(
    string InstanceId,
    ulong Version,
    IReadOnlyList<ClipItemResponse> Items);

internal sealed record ApiError(string Code, string Message);

internal sealed record ApiErrorEnvelope(ApiError Error);
