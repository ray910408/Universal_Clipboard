using System.ComponentModel;
using System.Drawing;
using System.Windows.Forms;
using UniversalClipboard.App.App;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.App.Ui;

public sealed partial class TrayWindow :
    Form,
    ITrayWindow,
    ITrayNotifier,
    ITrayCommandSource
{
    private TrayViewState _state = TrayViewState.Empty;
    private bool _suppressInterfaceSelectionChanged;

    public TrayWindow()
    {
        InitializeComponent();
        notifyIcon.DoubleClick += (_, _) => ShowTray();
        notifyIcon.BalloonTipClicked += (_, _) => ShowTray();
        startButton.Click += (_, _) => StartSharingRequested?.Invoke(this, EventArgs.Empty);
        stopButton.Click += (_, _) => StopSharingRequested?.Invoke(this, EventArgs.Empty);
        exitButton.Click += (_, _) => ExitRequested?.Invoke(this, EventArgs.Empty);
        pairButton.Click += (_, _) => PairingCodeRequested?.Invoke(this, EventArgs.Empty);
        revokeAllButton.Click += (_, _) => RevokeAllAuthorizationsRequested?.Invoke(this, EventArgs.Empty);
        revokeButton.Click += (_, _) => RaiseSelectedBrowser(RevokeAuthorizationRequested);
        allowButton.Click += (_, _) => RaiseSelectedPending(AllowPendingRequested);
        discardButton.Click += (_, _) => RaiseSelectedPending(DiscardPendingRequested);
        withdrawButton.Click += (_, _) => RaiseSelectedShared(WithdrawSharedRequested);
        durationComboBox.SelectedValueChanged += DurationComboBoxChanged;
        interfaceComboBox.SelectedValueChanged += InterfaceComboBoxChanged;
    }

    public event EventHandler? StartSharingRequested;

    public event EventHandler? StopSharingRequested;

    public event EventHandler? ExitRequested;

    public event EventHandler? PairingCodeRequested;

    public event EventHandler<AuthorizationDuration>? AuthorizationDurationChanged;

    public event EventHandler<Guid>? RevokeAuthorizationRequested;

    public event EventHandler? RevokeAllAuthorizationsRequested;

    public event EventHandler<Guid>? AllowPendingRequested;

    public event EventHandler<Guid>? DiscardPendingRequested;

    public event EventHandler<Guid>? WithdrawSharedRequested;

    public event EventHandler<string>? InterfaceSelected;

    internal bool IsNotifyIconVisibleForTests => notifyIcon.Visible;

    public void Render(TrayViewState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        _state = state;
        serviceStatusValue.Text = state.ServiceStatus;
        urlValue.Text = state.SelectedUrl ?? "Not sharing";
        firewallValue.Text = state.FirewallStatus;
        networkProfileValue.Text = state.NetworkProfile;
        portListeningValue.Text = state.PortListeningStatus;
        firewallSetupValue.Text = state.FirewallSetupHelp;
        warningLabel.Text = state.BlockingWarning ?? "";
        retryValue.Text = state.ClipboardRetryExhaustionCount.ToString();
        RenderDurationOptions(state);
        RenderInterfaceOptions(state);
        RenderList(browserListBox, state.PairedBrowsers);
        RenderList(sharedListBox, state.SharedItems);
        RenderList(pendingListBox, state.PendingSensitiveItems);
        RenderPairing(state.Pairing);
    }

    public void ShowTray()
    {
        if (WindowState == FormWindowState.Minimized)
        {
            WindowState = FormWindowState.Normal;
        }

        Show();
        Activate();
    }

    public void Notify(TrayNotification notification)
    {
        ArgumentNullException.ThrowIfNull(notification);
        notifyIcon.BalloonTipTitle = notification.Title;
        notifyIcon.BalloonTipText = notification.Body;
        notifyIcon.ShowBalloonTip(5000);
    }

    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        if (e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            Hide();
            return;
        }

        base.OnFormClosing(e);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            notifyIcon.Visible = false;
            notifyIcon.Dispose();
            qrPictureBox.Image?.Dispose();
        }

        base.Dispose(disposing);
    }

    private void RenderDurationOptions(TrayViewState state)
    {
        durationComboBox.SelectedValueChanged -= DurationComboBoxChanged;
        try
        {
            durationComboBox.DataSource = state.DurationOptions.ToArray();
            durationComboBox.DisplayMember = nameof(DurationOptionRow.DisplayName);
            durationComboBox.SelectedItem = state.DurationOptions.FirstOrDefault(
                item => item.Duration == state.SelectedDuration);
        }
        finally
        {
            durationComboBox.SelectedValueChanged += DurationComboBoxChanged;
        }
    }

    private void RenderInterfaceOptions(TrayViewState state)
    {
        _suppressInterfaceSelectionChanged = true;
        try
        {
            interfaceComboBox.Visible = state.InterfaceOptions.Length > 0;
            interfaceLabel.Visible = state.InterfaceOptions.Length > 0;
            interfaceComboBox.DataSource = state.InterfaceOptions.ToArray();
            interfaceComboBox.DisplayMember = nameof(NetworkInterfaceOptionRow.DisplayName);
            interfaceComboBox.SelectedIndex = -1;
        }
        finally
        {
            _suppressInterfaceSelectionChanged = false;
        }
    }

    private static void RenderList<T>(ListBox listBox, IEnumerable<T> items)
    {
        listBox.DataSource = items.ToArray();
        listBox.DisplayMember = typeof(T) == typeof(BrowserAuthorizationRow)
            ? nameof(BrowserAuthorizationRow.DisplayName)
            : typeof(T) == typeof(PendingClipboardViewItem)
                ? nameof(PendingClipboardViewItem.MaskedPreview)
                : nameof(ClipboardItemRow.Preview);
    }

    private void RenderPairing(PairingViewState? pairing)
    {
        pairingUrlValue.Text = pairing?.PairingUrl ?? "Generate a code while sharing";
        qrPictureBox.Image?.Dispose();
        qrPictureBox.Image = null;
        if (pairing is null)
        {
            return;
        }

        using var stream = new MemoryStream(pairing.QrCodePng);
        using var loaded = Image.FromStream(stream);
        qrPictureBox.Image = new Bitmap(loaded);
    }

    private void RaiseSelectedBrowser(EventHandler<Guid>? handler)
    {
        if (browserListBox.SelectedItem is BrowserAuthorizationRow row)
        {
            handler?.Invoke(this, row.AuthorizationId);
        }
    }

    private void RaiseSelectedShared(EventHandler<Guid>? handler)
    {
        if (sharedListBox.SelectedItem is ClipboardItemRow row)
        {
            handler?.Invoke(this, row.ItemId);
        }
    }

    private void RaiseSelectedPending(EventHandler<Guid>? handler)
    {
        if (pendingListBox.SelectedItem is PendingClipboardViewItem row)
        {
            handler?.Invoke(this, row.ItemId);
        }
    }

    private void DurationComboBoxChanged(object? sender, EventArgs e)
    {
        if (durationComboBox.SelectedItem is DurationOptionRow row &&
            row.Duration != _state.SelectedDuration)
        {
            AuthorizationDurationChanged?.Invoke(this, row.Duration);
        }
    }

    private void InterfaceComboBoxChanged(object? sender, EventArgs e)
    {
        if (_suppressInterfaceSelectionChanged)
        {
            return;
        }

        if (interfaceComboBox.SelectedItem is NetworkInterfaceOptionRow row)
        {
            InterfaceSelected?.Invoke(this, row.InterfaceId);
        }
    }
}
