using System.Text.Json.Serialization;

namespace UniversalClipboard.App.Web;

internal sealed record PairExchangeRequest(
    [property: JsonPropertyName("code")] string? Code,
    [property: JsonPropertyName("label")] string? Label);

public sealed record PairExchangeResponse(
    bool Authorized,
    string AuthorizationId,
    DateTimeOffset? ExpiresAt);

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
