using System.Collections.Immutable;
using System.Globalization;
using System.Net;
using System.Windows.Forms;
using QRCoder;
using UniversalClipboard.App.Clipboard;
using UniversalClipboard.App.Network;
using UniversalClipboard.App.Security;
using UniversalClipboard.App.Web;
using UniversalClipboard.Core.Authorization;
using UniversalClipboard.Core.Clipboard;
using CoreClipboardReadResult = UniversalClipboard.Core.Clipboard.ClipboardReadResult;

namespace UniversalClipboard.App.App;

public sealed record ClipboardApplicationServices(
    ITrayWindow Window,
    ITrayNotifier Notifier,
    ISharingController Sharing,
    IPairingCodeProvider PairingCodes,
    IAuthorizationAdministration Authorizations,
    IClipboardContentStore Clipboard,
    IWindowsClipboardWriter IncomingClipboard,
    IQrCodeRenderer QrCodeRenderer,
    IHttpsCertificateProvider HttpsCertificates,
    TimeProvider? TimeProvider = null,
    Func<CancellationToken, Task>? ExitAsync = null);

public interface ITrayWindow
{
    void Render(TrayViewState state);

    void ShowTray();
}

public interface ITrayNotifier
{
    void Notify(TrayNotification notification);
}

public interface ITrayCommandSource
{
    event EventHandler? StartSharingRequested;

    event EventHandler? StopSharingRequested;

    event EventHandler? ExitRequested;

    event EventHandler? PairingCodeRequested;

    event EventHandler? ResetHttpsIdentityRequested;

    event EventHandler<AuthorizationDuration>? AuthorizationDurationChanged;

    event EventHandler<AuthorizationPermissions>? AuthorizationPermissionsChanged;

    event EventHandler<Guid>? RevokeAuthorizationRequested;

    event EventHandler? RevokeAllAuthorizationsRequested;

    event EventHandler<Guid>? AllowPendingRequested;

    event EventHandler<Guid>? DiscardPendingRequested;

    event EventHandler<Guid>? WithdrawSharedRequested;

    event EventHandler<Guid>? ApplyIncomingRequested;

    event EventHandler<Guid>? DiscardIncomingRequested;

    event EventHandler<string>? InterfaceSelected;
}

public interface ISharingController
{
    NetworkSharingState CurrentState { get; }

    Task<NetworkSharingState> StartAsync(CancellationToken cancellationToken = default);

    Task<NetworkSharingState> ShutdownAsync(CancellationToken cancellationToken = default);

    Task<NetworkSharingState> SetSelectedInterfaceAsync(
        string interfaceId,
        CancellationToken cancellationToken = default);

    Task<NetworkSharingState> RefreshAsync(CancellationToken cancellationToken = default);
}

public interface IPairingCodeProvider
{
    PairingCodeSnapshot Create(
        AuthorizationDuration duration,
        AuthorizationPermissions permissions);

    void Invalidate();
}

public interface IQrCodeRenderer
{
    byte[] RenderPng(string payload);
}

public interface IClipboardContentStore
{
    ClipboardSnapshot HistorySnapshot { get; }

    PendingApprovalSnapshot PendingSnapshot { get; }

    IReadOnlyList<PendingClipboardViewItem> PendingItems { get; }

    ClipboardCaptureResult CaptureText(string text);

    PipelineAllowResult Allow(Guid id);

    PendingTakeResult Discard(Guid id);

    HistoryWithdrawResult Withdraw(Guid id);

    void Clear();
}

public interface IWindowsClipboardWriter
{
    void SetText(string text);
}

public sealed record PairingCodeSnapshot(
    string Value,
    DateTimeOffset ExpiresAtUtc,
    AuthorizationPermissions Permissions);

public sealed record TrayNotification(
    string Title,
    string Body);

public sealed record PairingViewState(
    string PairingUrl,
    byte[] QrCodePng,
    DateTimeOffset ExpiresAtUtc);

public sealed record HttpsIdentityViewState(
    string Status,
    string ShortCode,
    string Fingerprint,
    string Expiry,
    string DisplayText)
{
    public static HttpsIdentityViewState NotGenerated { get; } =
        new(
            "Not generated",
            "",
            "",
            "Not generated",
            "Not generated until sharing starts");
}

public sealed record BrowserAuthorizationRow(
    Guid AuthorizationId,
    string Label,
    string DeviceName,
    string BrowserName,
    DateTimeOffset CreatedAtUtc,
    string Created,
    string LastAccessed,
    string AuthorizationIdSuffix,
    string BoundHost,
    string Expiry,
    string Permissions,
    string DisplayName);

public sealed record ClipboardItemRow(
    Guid ItemId,
    string Preview,
    DateTimeOffset CapturedAtUtc);

public sealed record PendingClipboardViewItem(
    Guid ItemId,
    string Rule,
    string MaskedPreview,
    DateTimeOffset CapturedAtUtc);

public sealed record PendingIncomingTextRow(
    Guid ItemId,
    Guid AuthorizationId,
    string DisplayName,
    string MaskedPreview,
    DateTimeOffset ReceivedAtUtc);

public sealed record NetworkInterfaceOptionRow(
    string InterfaceId,
    string DisplayName);

public sealed record DurationOptionRow(
    AuthorizationDuration Duration,
    string DisplayName);

public sealed record PermissionOptionRow(
    AuthorizationPermissions Permissions,
    string DisplayName);

public sealed record TrayViewState(
    string ServiceStatus,
    string? SelectedUrl,
    AuthorizationDuration SelectedDuration,
    AuthorizationPermissions SelectedPermissions,
    ImmutableArray<DurationOptionRow> DurationOptions,
    ImmutableArray<PermissionOptionRow> PermissionOptions,
    PairingViewState? Pairing,
    HttpsIdentityViewState HttpsIdentity,
    ImmutableArray<BrowserAuthorizationRow> PairedBrowsers,
    ImmutableArray<ClipboardItemRow> SharedItems,
    ImmutableArray<PendingClipboardViewItem> PendingSensitiveItems,
    ImmutableArray<PendingIncomingTextRow> PendingIncomingItems,
    ImmutableArray<NetworkInterfaceOptionRow> InterfaceOptions,
    string FirewallStatus,
    string NetworkProfile,
    string PortListeningStatus,
    string FirewallSetupHelp,
    string? BlockingWarning,
    int ClipboardRetryExhaustionCount)
{
    public static TrayViewState Empty { get; } =
        new(
            "Stopped",
            null,
            AuthorizationDuration.FiveHours,
            AuthorizationPermissions.Read,
            ClipboardApplicationContext.DurationOptions,
            ClipboardApplicationContext.PermissionOptions,
            null,
            HttpsIdentityViewState.NotGenerated,
            ImmutableArray<BrowserAuthorizationRow>.Empty,
            ImmutableArray<ClipboardItemRow>.Empty,
            ImmutableArray<PendingClipboardViewItem>.Empty,
            ImmutableArray<PendingIncomingTextRow>.Empty,
            ImmutableArray<NetworkInterfaceOptionRow>.Empty,
            "Unknown - test from iPhone",
            "Unknown",
            "Not listening",
            "docs/firewall-setup.md",
            null,
            0);
}

public sealed class ClipboardApplicationContext :
    ApplicationContext,
    IClipboardNotificationSink,
    IIncomingTextSink,
    IAsyncDisposable
{
    private readonly ClipboardApplicationServices _services;
    private readonly TimeProvider _timeProvider;
    private readonly object _gate = new();
    private readonly Dictionary<Guid, PendingIncomingText> _pendingIncoming = [];
    private PairingViewState? _pairing;
    private string? _suppressNextClipboardText;
    private DateTimeOffset _suppressNextClipboardTextUntilUtc;
    private int _clipboardRetryExhaustionCount;
    private int _shutdownStarted;
    private AuthorizationDuration _selectedDuration = AuthorizationDuration.FiveHours;
    private AuthorizationPermissions _selectedPermissions = AuthorizationPermissions.Read;
    private TrayViewState _viewState = TrayViewState.Empty;

    public static LocalWebHostTimeouts ShutdownTimeouts { get; } = LocalWebHostTimeouts.Production;

    internal static TimeSpan ClipboardApplyEchoSuppressionWindow { get; } = TimeSpan.FromSeconds(2);

    public static ImmutableArray<DurationOptionRow> DurationOptions { get; } =
        ImmutableArray.Create(
            new DurationOptionRow(AuthorizationDuration.OneHour, "1 hour"),
            new DurationOptionRow(AuthorizationDuration.FiveHours, "5 hours"),
            new DurationOptionRow(AuthorizationDuration.OneDay, "1 day"),
            new DurationOptionRow(AuthorizationDuration.OneWeek, "1 week"),
            new DurationOptionRow(AuthorizationDuration.Permanent, "Permanent"));

    public static ImmutableArray<PermissionOptionRow> PermissionOptions { get; } =
        ImmutableArray.Create(
            new PermissionOptionRow(AuthorizationPermissions.Read, "Read only"),
            new PermissionOptionRow(AuthorizationPermissions.Write, "Write only"),
            new PermissionOptionRow(AuthorizationPermissions.ReadWrite, "Read + Write"));

    public ClipboardApplicationContext(ClipboardApplicationServices services)
    {
        ArgumentNullException.ThrowIfNull(services);
        _services = services;
        _timeProvider = services.TimeProvider ?? TimeProvider.System;
        AttachWindowCommands(services.Window as ITrayCommandSource);
        RefreshView();
    }

    public TrayViewState ViewState
    {
        get
        {
            lock (_gate)
            {
                return _viewState;
            }
        }
    }

    public AuthorizationDuration SelectedDuration
    {
        get
        {
            lock (_gate)
            {
                return _selectedDuration;
            }
        }
    }

    public AuthorizationPermissions SelectedPermissions
    {
        get
        {
            lock (_gate)
            {
                return _selectedPermissions;
            }
        }
    }

    public async Task StartSharingAsync(CancellationToken cancellationToken = default)
    {
        await _services.Sharing.StartAsync(cancellationToken);
        RefreshView();
    }

    public async Task StopSharingAsync(CancellationToken cancellationToken = default)
    {
        await _services.Sharing.ShutdownAsync(cancellationToken);
        lock (_gate)
        {
            _pairing = null;
        }

        RefreshView();
    }

    public async Task ResetHttpsIdentityAsync(CancellationToken cancellationToken = default)
    {
        var wasRunning = _services.Sharing.CurrentState.Status == NetworkSharingStatus.Running;
        if (wasRunning)
        {
            await _services.Sharing.ShutdownAsync(cancellationToken);
        }

        var revoke = await _services.Authorizations.RevokeAllAsync(cancellationToken);
        if (!revoke.Succeeded)
        {
            if (wasRunning)
            {
                await _services.Sharing.StartAsync(cancellationToken);
            }

            NotifyAndShow(
                "HTTPS identity was not reset",
                $"Authorizations were not revoked. Reason: {revoke.Failure}");
            RefreshView();
            return;
        }

        lock (_gate)
        {
            _pairing = null;
        }

        _services.PairingCodes.Invalidate();
        ClearAllIncoming();
        try
        {
            await _services.HttpsCertificates.ResetAsync(cancellationToken);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
            if (wasRunning)
            {
                await _services.Sharing.StartAsync(cancellationToken);
            }

            NotifyAndShow(
                "HTTPS identity was not reset",
                $"Authorizations were revoked, but HTTPS identity reset failed. Reason: {exception.GetType().Name}");
            RefreshView();
            return;
        }

        if (wasRunning)
        {
            await _services.Sharing.StartAsync(cancellationToken);
        }

        NotifyAndShow(
            "HTTPS identity reset",
            "Safari will ask you to trust the new certificate the next time you pair.");
        RefreshView();
    }

    public async Task SelectInterfaceAsync(
        string interfaceId,
        CancellationToken cancellationToken = default)
    {
        await _services.Sharing.SetSelectedInterfaceAsync(interfaceId, cancellationToken);
        RefreshView();
    }

    public async Task RefreshSharingAsync(CancellationToken cancellationToken = default)
    {
        await _services.Sharing.RefreshAsync(cancellationToken);
        RefreshView();
    }

    public void SetAuthorizationDuration(AuthorizationDuration duration)
    {
        if (!Enum.IsDefined(duration))
        {
            throw new ArgumentOutOfRangeException(nameof(duration));
        }

        lock (_gate)
        {
            _selectedDuration = duration;
            _pairing = null;
        }

        _services.PairingCodes.Invalidate();
        RefreshView();
    }

    public void CreatePairingCode()
    {
        var state = _services.Sharing.CurrentState;
        if (string.IsNullOrWhiteSpace(state.SelectedUrl))
        {
            return;
        }

        var duration = SelectedDuration;
        var permissions = SelectedPermissions;
        var code = _services.PairingCodes.Create(duration, permissions);
        var pairingUrl = BuildPairingUrl(state.SelectedUrl, code.Value);
        var qrCode = _services.QrCodeRenderer.RenderPng(pairingUrl);
        lock (_gate)
        {
            _pairing = new PairingViewState(pairingUrl, qrCode, code.ExpiresAtUtc);
        }

        RefreshView();
    }

    public async Task RevokeAsync(
        Guid authorizationId,
        CancellationToken cancellationToken = default)
    {
        var result = await _services.Authorizations.RevokeAsync(
            authorizationId,
            cancellationToken);
        if (!result.Succeeded)
        {
            NotifyAndShow(
                "Authorization was not revoked",
                $"Reason: {result.Failure}");
        }
        else
        {
            ClearIncomingForAuthorization(authorizationId);
        }

        RefreshView();
    }

    public void SetAuthorizationPermissions(AuthorizationPermissions permissions)
    {
        if (!IsValidPermissions(permissions))
        {
            throw new ArgumentOutOfRangeException(nameof(permissions));
        }

        lock (_gate)
        {
            _selectedPermissions = permissions;
            _pairing = null;
        }

        _services.PairingCodes.Invalidate();
        RefreshView();
    }

    public async Task RevokeAllAsync(CancellationToken cancellationToken = default)
    {
        var result = await _services.Authorizations.RevokeAllAsync(cancellationToken);
        if (!result.Succeeded)
        {
            NotifyAndShow(
                "Authorizations were not revoked",
                $"Reason: {result.Failure}");
        }
        else
        {
            ClearAllIncoming();
        }

        RefreshView();
    }

    public IncomingTextItem EnqueueIncomingText(
        Guid authorizationId,
        string? deviceName,
        string? browserName,
        string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        var item = new PendingIncomingText(
            Guid.NewGuid(),
            authorizationId,
            deviceName,
            browserName,
            text,
            _timeProvider.GetUtcNow().ToUniversalTime());
        lock (_gate)
        {
            _pendingIncoming[item.IncomingId] = item;
        }

        NotifyAndShow(
            "Pending incoming text",
            "Text from a paired browser is waiting for approval.");
        RefreshView();
        return new IncomingTextItem(
            item.IncomingId,
            item.AuthorizationId,
            item.DeviceName,
            item.BrowserName,
            item.Text,
            item.ReceivedAtUtc);
    }

    public ValueTask<IncomingTextItem> EnqueueAsync(
        IncomingTextRequest request,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ArgumentNullException.ThrowIfNull(request);
        var item = EnqueueIncomingText(
            request.Authorization.Id,
            request.Authorization.DeviceName,
            request.Authorization.BrowserName,
            request.Text);
        return ValueTask.FromResult(item);
    }

    public ValueTask ClearAuthorizationAsync(
        Guid authorizationId,
        CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ClearIncomingForAuthorization(authorizationId);
        RefreshView();
        return ValueTask.CompletedTask;
    }

    public ValueTask ClearAllAsync(CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ClearAllIncoming();
        RefreshView();
        return ValueTask.CompletedTask;
    }

    public void ApplyIncoming(Guid incomingId)
    {
        PendingIncomingText? item;
        lock (_gate)
        {
            _pendingIncoming.TryGetValue(incomingId, out item);
        }

        if (item is not null)
        {
            lock (_gate)
            {
                _suppressNextClipboardText = item.Text;
                _suppressNextClipboardTextUntilUtc =
                    _timeProvider.GetUtcNow().ToUniversalTime() + ClipboardApplyEchoSuppressionWindow;
            }

            try
            {
                _services.IncomingClipboard.SetText(item.Text);
            }
            catch
            {
                ClearClipboardTextSuppression(item.Text);
                throw;
            }

            lock (_gate)
            {
                _pendingIncoming.Remove(incomingId);
            }
        }

        RefreshView();
    }

    public void DiscardIncoming(Guid incomingId)
    {
        lock (_gate)
        {
            _pendingIncoming.Remove(incomingId);
        }

        RefreshView();
    }

    public void ClearIncomingForAuthorization(Guid authorizationId)
    {
        lock (_gate)
        {
            foreach (var id in _pendingIncoming
                .Where(pair => pair.Value.AuthorizationId == authorizationId)
                .Select(pair => pair.Key)
                .ToArray())
            {
                _pendingIncoming.Remove(id);
            }
        }
    }

    public void ClearAllIncoming()
    {
        lock (_gate)
        {
            _pendingIncoming.Clear();
        }
    }

    public void AllowPending(Guid itemId)
    {
        _services.Clipboard.Allow(itemId);
        RefreshView();
    }

    public void DiscardPending(Guid itemId)
    {
        _services.Clipboard.Discard(itemId);
        RefreshView();
    }

    public void WithdrawShared(Guid itemId)
    {
        _services.Clipboard.Withdraw(itemId);
        RefreshView();
    }

    public void RefreshView()
    {
        var state = BuildViewState();
        lock (_gate)
        {
            _viewState = state;
        }

        _services.Window.Render(state);
    }

    public void ShowTray() => _services.Window.ShowTray();

    public void OnClipboardText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (ShouldSuppressClipboardText(text))
        {
            RefreshView();
            return;
        }

        var result = _services.Clipboard.CaptureText(text);
        switch (result.Outcome)
        {
            case ClipboardCaptureOutcome.Shared:
                break;
            case ClipboardCaptureOutcome.PendingApproval:
                NotifyAndShow(
                    "Possible sensitive content detected",
                    $"Rule: {FormatSensitiveRule(result.SensitiveRule)}; Preview: {MaskPreview(text)}");
                break;
            case ClipboardCaptureOutcome.InvalidUtf16:
                NotifyAndShow(
                    "Clipboard item was not shared",
                    "Text was not shared because it is not valid UTF-16.");
                break;
            case ClipboardCaptureOutcome.OverLimit:
                NotifyAndShow(
                    "Clipboard item was not shared",
                    "Text was not shared because it exceeds the 1 MiB limit.");
                break;
        }

        RefreshView();
    }

    private bool ShouldSuppressClipboardText(string text)
    {
        lock (_gate)
        {
            if (_suppressNextClipboardText is null)
            {
                return false;
            }

            if (_timeProvider.GetUtcNow().ToUniversalTime() > _suppressNextClipboardTextUntilUtc)
            {
                ClearClipboardTextSuppression();
                return false;
            }

            if (!string.Equals(_suppressNextClipboardText, text, StringComparison.Ordinal))
            {
                ClearClipboardTextSuppression();
                return false;
            }

            return true;
        }
    }

    private void ClearClipboardTextSuppression(string text)
    {
        lock (_gate)
        {
            if (string.Equals(_suppressNextClipboardText, text, StringComparison.Ordinal))
            {
                ClearClipboardTextSuppression();
            }
        }
    }

    private void ClearClipboardTextSuppression()
    {
        _suppressNextClipboardText = null;
        _suppressNextClipboardTextUntilUtc = default;
    }

    public void OnClipboardReadExhausted(ClipboardReadDiagnostic diagnostic)
    {
        lock (_gate)
        {
            _clipboardRetryExhaustionCount++;
        }

        NotifyAndShow(
            "Clipboard read delayed",
            $"Read retries exhausted after {diagnostic.AttemptCount} attempts.");
        RefreshView();
    }

    public async Task ShutdownAsync(CancellationToken cancellationToken = default)
    {
        if (Interlocked.Exchange(ref _shutdownStarted, 1) != 0)
        {
            return;
        }

        var completedOrderly = true;
        try
        {
            await _services.Sharing.ShutdownAsync(cancellationToken);
        }
        catch (LocalWebHostShutdownIncompleteException)
        {
            completedOrderly = false;
            ClearAllIncoming();
            RefreshView();
            NotifyAndShow(
                "Sharing did not stop cleanly",
                "Network handlers did not exit after bounded shutdown; terminating without clearing clipboard memory.");
        }

        if (completedOrderly)
        {
            ClearAllIncoming();
            _services.Clipboard.Clear();
            RefreshView();
        }

        ExitThread();
    }

    public async ValueTask DisposeAsync()
    {
        await ShutdownAsync();
        Dispose();
    }

    private TrayViewState BuildViewState()
    {
        var network = _services.Sharing.CurrentState;
        PairingViewState? pairing;
        int retries;
        AuthorizationDuration selectedDuration;
        AuthorizationPermissions selectedPermissions;
        lock (_gate)
        {
            pairing = IsPairingCurrent(_pairing) ? _pairing : null;
            if (!ReferenceEquals(pairing, _pairing))
            {
                _pairing = null;
            }

            retries = _clipboardRetryExhaustionCount;
            selectedDuration = _selectedDuration;
            selectedPermissions = _selectedPermissions;
        }

        return new TrayViewState(
            BuildServiceStatus(network),
            network.SelectedUrl,
            selectedDuration,
            selectedPermissions,
            DurationOptions,
            PermissionOptions,
            pairing,
            BuildHttpsIdentity(_services.HttpsCertificates.CurrentIdentity),
            ToAuthorizationRows(_services.Authorizations.List()),
            _services.Clipboard.HistorySnapshot.Items
                .Reverse()
                .Select(ToClipboardRow)
                .ToImmutableArray(),
            _services.Clipboard.PendingItems.ToImmutableArray(),
            ToIncomingRows(),
            BuildInterfaceOptions(network),
            BuildFirewallStatus(network.FirewallRuleStatus),
            BuildNetworkProfile(network),
            BuildPortListeningStatus(network),
            "docs/firewall-setup.md",
            BuildBlockingWarning(network, selectedDuration),
            retries);
    }

    private bool IsPairingCurrent(PairingViewState? pairing) =>
        pairing is not null && _timeProvider.GetUtcNow() < pairing.ExpiresAtUtc;

    private void NotifyAndShow(string title, string body)
    {
        _services.Notifier.Notify(new TrayNotification(title, body));
        _services.Window.ShowTray();
    }

    private void AttachWindowCommands(ITrayCommandSource? commands)
    {
        if (commands is null)
        {
            return;
        }

        commands.StartSharingRequested += (_, _) => RunCommand(() => StartSharingAsync());
        commands.StopSharingRequested += (_, _) => RunCommand(() => StopSharingAsync());
        commands.ExitRequested += (_, _) => RunCommand(HandleExitRequestedAsync);
        commands.PairingCodeRequested += (_, _) => RunCommand(() =>
        {
            CreatePairingCode();
            return Task.CompletedTask;
        });
        commands.ResetHttpsIdentityRequested += (_, _) => RunCommand(
            () => ResetHttpsIdentityAsync());
        commands.AuthorizationDurationChanged += (_, duration) => RunCommand(() =>
        {
            SetAuthorizationDuration(duration);
            return Task.CompletedTask;
        });
        commands.AuthorizationPermissionsChanged += (_, permissions) => RunCommand(() =>
        {
            SetAuthorizationPermissions(permissions);
            return Task.CompletedTask;
        });
        commands.RevokeAuthorizationRequested += (_, id) => RunCommand(() => RevokeAsync(id));
        commands.RevokeAllAuthorizationsRequested += (_, _) => RunCommand(() => RevokeAllAsync());
        commands.AllowPendingRequested += (_, id) => RunCommand(() =>
        {
            AllowPending(id);
            return Task.CompletedTask;
        });
        commands.DiscardPendingRequested += (_, id) => RunCommand(() =>
        {
            DiscardPending(id);
            return Task.CompletedTask;
        });
        commands.WithdrawSharedRequested += (_, id) => RunCommand(() =>
        {
            WithdrawShared(id);
            return Task.CompletedTask;
        });
        commands.ApplyIncomingRequested += (_, id) => RunCommand(() =>
        {
            ApplyIncoming(id);
            return Task.CompletedTask;
        });
        commands.DiscardIncomingRequested += (_, id) => RunCommand(() =>
        {
            DiscardIncoming(id);
            return Task.CompletedTask;
        });
        commands.InterfaceSelected += (_, interfaceId) => RunCommand(() => SelectInterfaceAsync(interfaceId));
    }

    private void RunCommand(Func<Task> command)
    {
        _ = RunCommandAsync(command);
    }

    private async Task RunCommandAsync(Func<Task> command)
    {
        try
        {
            await command();
        }
        catch (Exception)
        {
            NotifyAndShow(
                "Universal Clipboard command failed",
                "The requested action could not be completed. Check status and try again.");
            RefreshView();
        }
    }

    private async Task HandleExitRequestedAsync()
    {
        if (_services.ExitAsync is not null)
        {
            await _services.ExitAsync(CancellationToken.None);
            return;
        }

        await ShutdownAsync();
    }

    private static ImmutableArray<BrowserAuthorizationRow> ToAuthorizationRows(
        ImmutableArray<AuthorizationMetadata> authorizations)
    {
        var ordered = authorizations
            .OrderBy(item => item.Label, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Id)
            .ToArray();
        var authorizationIds = ordered
            .Select(item => EncodeAuthorizationId(item.Id))
            .ToArray();

        return ordered
            .Select((authorization, index) => ToAuthorizationRow(
                authorization,
                UniqueAuthorizationSuffix(authorizationIds, index)))
            .ToImmutableArray();
    }

    private static BrowserAuthorizationRow ToAuthorizationRow(
        AuthorizationMetadata authorization,
        string suffix)
    {
        var deviceName = string.IsNullOrWhiteSpace(authorization.DeviceName)
            ? authorization.Label
            : authorization.DeviceName!;
        var browserName = string.IsNullOrWhiteSpace(authorization.BrowserName)
            ? "Unknown browser"
            : authorization.BrowserName!;
        var created = FormatUtc(authorization.CreatedAtUtc);
        var lastAccessed = FormatLastAccess(authorization.LastAccessedAtUtc);
        var expiry = FormatExpiry(authorization.ExpiresAtUtc);
        var permissions = FormatPermissionDisplay(authorization.Permissions);
        return new BrowserAuthorizationRow(
            authorization.Id,
            authorization.Label,
            deviceName,
            browserName,
            authorization.CreatedAtUtc,
            created,
            lastAccessed,
            suffix,
            authorization.BoundHostIpv4.ToString(),
            expiry,
            permissions,
            $"Device: {deviceName}; Browser: {browserName}; Id: {suffix}; Created: {created}; " +
            $"Last access: {lastAccessed}; Expires: {expiry}; Permissions: {permissions}");
    }

    private static string UniqueAuthorizationSuffix(
        IReadOnlyList<string> authorizationIds,
        int index)
    {
        var id = authorizationIds[index];
        for (var length = 8; length <= id.Length; length += 4)
        {
            var prefix = id[..Math.Min(length, id.Length)];
            if (authorizationIds.Count(candidate =>
                    candidate.StartsWith(prefix, StringComparison.Ordinal)) == 1)
            {
                return prefix;
            }
        }

        return id;
    }

    private static string EncodeAuthorizationId(Guid authorizationId) =>
        Convert.ToBase64String(authorizationId.ToByteArray())
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string FormatUtc(DateTimeOffset value) =>
        value.ToUniversalTime().ToString(
            "yyyy-MM-dd HH:mm 'UTC'",
            CultureInfo.InvariantCulture);

    private static string FormatExpiry(DateTimeOffset? expiresAtUtc) =>
        expiresAtUtc is null ? "Until revoked" : FormatUtc(expiresAtUtc.Value);

    private static string FormatLastAccess(DateTimeOffset? lastAccessedAtUtc) =>
        lastAccessedAtUtc is null ? "Never" : FormatUtc(lastAccessedAtUtc.Value);

    private static string FormatPermissionDisplay(AuthorizationPermissions permissions) =>
        permissions switch
        {
            AuthorizationPermissions.Read => "Read",
            AuthorizationPermissions.Write => "Write",
            AuthorizationPermissions.ReadWrite => "Read / Write",
            _ => "Unknown",
        };

    private static bool IsValidPermissions(AuthorizationPermissions permissions) =>
        permissions is not AuthorizationPermissions.None &&
        (permissions & ~AuthorizationPermissions.ReadWrite) == 0;

    private static ClipboardItemRow ToClipboardRow(ClipboardItem item) =>
        new(item.Id, item.Text, item.CapturedAtUtc);

    private ImmutableArray<PendingIncomingTextRow> ToIncomingRows()
    {
        lock (_gate)
        {
            return _pendingIncoming.Values
                .OrderByDescending(item => item.ReceivedAtUtc)
                .Select(item => new PendingIncomingTextRow(
                    item.IncomingId,
                    item.AuthorizationId,
                    FormatIncomingDisplayName(item),
                    MaskPreview(item.Text),
                    item.ReceivedAtUtc))
                .ToImmutableArray();
        }
    }

    private static string FormatIncomingDisplayName(PendingIncomingText item)
    {
        var parts = new[] { item.DeviceName, item.BrowserName }
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .ToArray();
        return parts.Length == 0 ? "Paired browser" : string.Join(" - ", parts);
    }

    private static ImmutableArray<NetworkInterfaceOptionRow> BuildInterfaceOptions(
        NetworkSharingState network) =>
        network.InterfaceOptions.IsDefaultOrEmpty
            ? ImmutableArray<NetworkInterfaceOptionRow>.Empty
            : network.InterfaceOptions
                .Select(item => new NetworkInterfaceOptionRow(
                    item.InterfaceId,
                    $"{item.DisplayName} - {item.Address}"))
                .ToImmutableArray();

    private static string BuildServiceStatus(NetworkSharingState network) =>
        network.Status switch
        {
            NetworkSharingStatus.Running => "Running",
            NetworkSharingStatus.Starting => "Starting",
            NetworkSharingStatus.Shutdown => "Stopped",
            NetworkSharingStatus.PublicProfileBlocked => "Blocked",
            NetworkSharingStatus.SelectionRequired => "Select interface",
            NetworkSharingStatus.NoEligibleInterface => "No eligible interface",
            NetworkSharingStatus.PortConflict => "Port conflict",
            NetworkSharingStatus.AuthorizationPersistenceFailed => "Authorization persistence failed",
            _ => network.Status.ToString(),
        };

    private static string BuildFirewallStatus(FirewallRuleStatus status) =>
        status switch
        {
            FirewallRuleStatus.ExactRuleFound => "Ready",
            FirewallRuleStatus.Missing => "Missing",
            FirewallRuleStatus.Unknown => "Unknown - test from iPhone",
            _ => "Unknown - test from iPhone",
        };

    private static string BuildNetworkProfile(NetworkSharingState network) =>
        network.SelectedNetworkProfile?.ToString() ?? "Unknown";

    private static string BuildPortListeningStatus(NetworkSharingState network) =>
        network.IsPortListening
            ? $"Listening on TCP {network.Port}"
            : $"Not listening on TCP {network.Port}";

    private static HttpsIdentityViewState BuildHttpsIdentity(
        HttpsCertificateIdentity? identity)
    {
        if (identity is null)
        {
            return HttpsIdentityViewState.NotGenerated;
        }

        var expiry = FormatUtc(identity.NotAfterUtc);
        return new HttpsIdentityViewState(
            "Ready",
            identity.ShortCode,
            identity.FingerprintSha256,
            expiry,
            $"Ready - {identity.ShortCode} - expires {expiry}{Environment.NewLine}" +
            $"SHA-256 {identity.FingerprintSha256}");
    }

    private static string? BuildBlockingWarning(
        NetworkSharingState network,
        AuthorizationDuration selectedDuration) =>
        network.Status == NetworkSharingStatus.PublicProfileBlocked ||
        network.SelectedNetworkProfile == NetworkProfile.Public
            ? "Windows reports this network as Public. Switch it to Private before sharing."
            : selectedDuration == AuthorizationDuration.Permanent
                ? "Permanent pairing is high risk. Revoke it when you no longer need this browser."
                : null;

    private static string BuildPairingUrl(string selectedUrl, string pairingCode)
    {
        var baseUrl = selectedUrl.EndsWith("/", StringComparison.Ordinal)
            ? selectedUrl
            : selectedUrl + "/";
        return baseUrl + "pair#code=" + Uri.EscapeDataString(pairingCode);
    }

    private static string FormatSensitiveRule(string? rule) =>
        rule switch
        {
            SensitiveTextClassifier.GitHubTokenRule => "GitHub token",
            SensitiveTextClassifier.AwsAccessKeyRule => "AWS access key",
            SensitiveTextClassifier.PemPrivateKeyRule => "PEM private key",
            null or "" => "Sensitive text",
            _ => rule,
        };

    public static string MaskPreview(string text)
    {
        var scalarCount = 0;
        for (var index = 0; index < text.Length;)
        {
            var status = System.Text.Rune.DecodeFromUtf16(
                text.AsSpan(index),
                out _,
                out var consumed);
            if (status != System.Buffers.OperationStatus.Done)
            {
                break;
            }

            scalarCount++;
            index += consumed;
        }

        return $"[masked {scalarCount} chars]";
    }
}

internal sealed record PendingIncomingText(
    Guid IncomingId,
    Guid AuthorizationId,
    string? DeviceName,
    string? BrowserName,
    string Text,
    DateTimeOffset ReceivedAtUtc);

public sealed class ClipboardPipelineContentStore : IClipboardContentStore
{
    private readonly object _gate = new();
    private ClipboardCapturePipeline _pipeline = new();
    private Dictionary<Guid, PendingClipboardViewItem> _pendingItems = [];

    public ClipboardSnapshot HistorySnapshot
    {
        get
        {
            lock (_gate)
            {
                return _pipeline.HistorySnapshot;
            }
        }
    }

    public PendingApprovalSnapshot PendingSnapshot
    {
        get
        {
            lock (_gate)
            {
                return _pipeline.PendingSnapshot;
            }
        }
    }

    public IReadOnlyList<PendingClipboardViewItem> PendingItems
    {
        get
        {
            lock (_gate)
            {
                var pendingIds = _pipeline.PendingSnapshot.Items.Select(item => item.Id).ToHashSet();
                foreach (var missing in _pendingItems.Keys.Where(id => !pendingIds.Contains(id)).ToArray())
                {
                    _pendingItems.Remove(missing);
                }

                return _pipeline.PendingSnapshot.Items
                    .Select(item => _pendingItems.TryGetValue(item.Id, out var view)
                        ? view
                        : new PendingClipboardViewItem(
                            item.Id,
                            "Sensitive text",
                            ClipboardApplicationContext.MaskPreview(item.Text),
                            item.CapturedAtUtc))
                    .ToArray();
            }
        }
    }

    public ClipboardCaptureResult CaptureText(string text)
    {
        lock (_gate)
        {
            var result = _pipeline.Capture(CoreClipboardReadResult.Success(text));
            foreach (var evicted in result.EvictedItems)
            {
                _pendingItems.Remove(evicted.Id);
            }

            if (result.Outcome == ClipboardCaptureOutcome.PendingApproval &&
                result.Item is not null)
            {
                _pendingItems[result.Item.Id] = new PendingClipboardViewItem(
                    result.Item.Id,
                    FormatPendingRule(result.SensitiveRule),
                    ClipboardApplicationContext.MaskPreview(result.Item.Text),
                    result.Item.CapturedAtUtc);
            }

            return result;
        }
    }

    public PipelineAllowResult Allow(Guid id)
    {
        lock (_gate)
        {
            var result = _pipeline.Allow(id);
            if (result.Found)
            {
                _pendingItems.Remove(id);
            }

            return result;
        }
    }

    public PendingTakeResult Discard(Guid id)
    {
        lock (_gate)
        {
            var result = _pipeline.Discard(id);
            if (result.Found)
            {
                _pendingItems.Remove(id);
            }

            return result;
        }
    }

    public HistoryWithdrawResult Withdraw(Guid id)
    {
        lock (_gate)
        {
            return _pipeline.Withdraw(id);
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _pipeline = new ClipboardCapturePipeline();
            _pendingItems = [];
        }
    }

    private static string FormatPendingRule(string? rule) =>
        rule switch
        {
            SensitiveTextClassifier.GitHubTokenRule => "GitHub token",
            SensitiveTextClassifier.AwsAccessKeyRule => "AWS access key",
            SensitiveTextClassifier.PemPrivateKeyRule => "PEM private key",
            null or "" => "Sensitive text",
            _ => rule,
        };
}

public sealed class PairingCodeProvider(PairingCodeManager pairingCodes) : IPairingCodeProvider
{
    public PairingCodeSnapshot Create(
        AuthorizationDuration duration,
        AuthorizationPermissions permissions)
    {
        var code = pairingCodes.Create(duration, permissions);
        return new PairingCodeSnapshot(code.Value, code.ExpiresAtUtc, code.Permissions);
    }

    public void Invalidate() => pairingCodes.Invalidate();
}

public sealed class QrCodeRenderer : IQrCodeRenderer
{
    public byte[] RenderPng(string payload)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(payload);
        using var generator = new QRCodeGenerator();
        using var data = generator.CreateQrCode(payload, QRCodeGenerator.ECCLevel.Q);
        var qrCode = new PngByteQRCode(data);
        return qrCode.GetGraphic(20);
    }
}

public sealed class NetworkSharingController(NetworkCoordinator coordinator) : ISharingController
{
    public NetworkSharingState CurrentState => coordinator.CurrentState;

    public Task<NetworkSharingState> StartAsync(CancellationToken cancellationToken = default) =>
        coordinator.StartAsync(cancellationToken);

    public Task<NetworkSharingState> ShutdownAsync(CancellationToken cancellationToken = default) =>
        coordinator.ShutdownAsync(cancellationToken);

    public Task<NetworkSharingState> SetSelectedInterfaceAsync(
        string interfaceId,
        CancellationToken cancellationToken = default) =>
        coordinator.SetSelectedInterfaceAsync(interfaceId, cancellationToken);

    public Task<NetworkSharingState> RefreshAsync(CancellationToken cancellationToken = default) =>
        coordinator.RefreshAsync(cancellationToken);
}

internal sealed class PairingCodeInvalidator(PairingCodeManager pairingCodes) : IPairingCodeInvalidator
{
    public ValueTask InvalidateActiveCodesAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        pairingCodes.Invalidate();
        return ValueTask.CompletedTask;
    }
}

internal sealed class LocalWebHostController(
    IAuthorizationService authorization,
    Func<ClipboardSnapshot> snapshotProvider,
    Func<AuthorizationDuration> durationProvider,
    IHttpsCertificateProvider? httpsCertificates = null,
    IIncomingTextSink? incomingTextSink = null,
    TimeProvider? timeProvider = null,
    Func<IPEndPoint, ILocalWebHostInstance>? hostFactory = null)
    : ILocalWebHostController,
    IAsyncDisposable
{
    private readonly object _gate = new();
    private ILocalWebHostInstance? _host;

    public async ValueTask StartAsync(IPEndPoint endpoint, CancellationToken cancellationToken)
    {
        ILocalWebHostInstance host;
        lock (_gate)
        {
            if (_host is not null)
            {
                throw new InvalidOperationException("The local web host is already running.");
            }

            host = hostFactory?.Invoke(endpoint) ?? new LocalWebHost(
                endpoint: endpoint,
                authorization: authorization,
                snapshotProvider: snapshotProvider,
                pairingDurationProvider: durationProvider,
                timeProvider: timeProvider,
                incomingTextSink: incomingTextSink,
                httpsCertificates: httpsCertificates ?? new DpapiHttpsCertificateProvider(
                    timeProvider: timeProvider),
                authorizationAdministration: authorization as IAuthorizationAdministration);
            _host = host;
        }

        try
        {
            await host.StartAsync(cancellationToken);
        }
        catch
        {
            lock (_gate)
            {
                if (ReferenceEquals(_host, host))
                {
                    _host = null;
                }
            }

            await host.DisposeAsync();
            throw;
        }
    }

    public async ValueTask StopAsync(CancellationToken cancellationToken)
    {
        ILocalWebHostInstance? host;
        lock (_gate)
        {
            host = _host;
            _host = null;
        }

        if (host is null)
        {
            return;
        }

        var result = await host.StopAsync(cancellationToken);
        if (!result.CompletedOrderly)
        {
            throw new LocalWebHostShutdownIncompleteException();
        }

        await host.DisposeAsync();
    }

    public async ValueTask DisposeAsync() => await StopAsync(CancellationToken.None);
}

public sealed class LocalWebHostShutdownIncompleteException : Exception
{
    public LocalWebHostShutdownIncompleteException()
        : base("The local web host did not complete bounded shutdown.")
    {
    }
}
