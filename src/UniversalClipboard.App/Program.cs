using UniversalClipboard.App.App;
using UniversalClipboard.App.Clipboard;
using UniversalClipboard.App.Network;
using UniversalClipboard.App.Security;
using UniversalClipboard.App.Ui;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.App;

internal static class Program
{
    [STAThread]
    private static void Main()
    {
        ApplicationConfiguration.Initialize();
        using var scheduler = new WinFormsStaScheduler();

        ClipboardApplicationContext? context = null;
        WindowsClipboardMonitor? monitor = null;
        LocalWebHostController? hostController = null;
        AuthorizationCoordinator? authorization = null;
        SingleInstanceCoordinatorResult? singleInstance = null;
        TrayWindow? trayWindow = null;

        try
        {
            singleInstance = SingleInstanceCoordinator.TryStartAsync(
                new SingleInstanceCoordinatorOptions(
                    new WindowsUserIdentity(),
                    new WindowsSingleInstanceMutexFactory(),
                    new WindowsSingleInstanceTransport(),
                    TimeProvider.System,
                    (message, _) =>
                    {
                        if (string.Equals(
                            message,
                            SingleInstanceCoordinator.ShowTrayMessage,
                            StringComparison.Ordinal))
                        {
                            try
                            {
                                scheduler.Post(() => context?.ShowTray());
                            }
                            catch (InvalidOperationException)
                            {
                            }
                        }

                        return ValueTask.CompletedTask;
                    })).GetAwaiter().GetResult();

            if (!ShouldContinueStartupAfterSingleInstanceResult(
                    singleInstance,
                    ShowStartupError))
            {
                return;
            }

            var pairingCodes = new PairingCodeManager();
            authorization = AuthorizationCoordinator.CreateAsync(
                new DpapiAuthorizationPersistence(),
                pairingCodes,
                new SessionTokenService()).GetAwaiter().GetResult();
            var clipboard = new ClipboardPipelineContentStore();

            hostController = new LocalWebHostController(
                authorization,
                () => clipboard.HistorySnapshot,
                () => context?.SelectedDuration ?? AuthorizationDuration.FiveHours);
            var network = new NetworkCoordinator(
                new WindowsNetworkEnvironment(),
                new TcpPortProbe(new SystemTcpPortInspector()),
                new WindowsFirewallInspector(
                    new WindowsFirewallComRuleQuery(new WindowsFirewallComRules())),
                hostController,
                new PairingCodeInvalidator(pairingCodes),
                authorization);

            trayWindow = new TrayWindow();
            var sharing = new NetworkSharingController(network);
            context = new ClipboardApplicationContext(
                new ClipboardApplicationServices(
                    trayWindow,
                    trayWindow,
                    sharing,
                    new PairingCodeProvider(pairingCodes),
                    authorization,
                    clipboard,
                    new QrCodeRenderer(),
                    ExitAsync: cancellationToken => ShutdownFromTrayAsync(
                        () => monitor,
                        value => monitor = value,
                        () => context,
                        cancellationToken)));
            monitor = StartSharingThenRegisterClipboard(
                sharing,
                context.RefreshView,
                () => new WindowsClipboardMonitor(
                    new WindowsClipboardReader(),
                    context,
                    new WindowsClipboardNativeListener(),
                    scheduler));

            Application.Run(context);
        }
        finally
        {
            monitor?.Dispose();
            if (context is not null)
            {
                context.ShutdownAsync().GetAwaiter().GetResult();
                context.Dispose();
            }

            DisposeTrayWindow(trayWindow);

            if (hostController is not null)
            {
                hostController.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            if (authorization is not null)
            {
                authorization.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }

            if (singleInstance is not null)
            {
                singleInstance.DisposeAsync().AsTask().GetAwaiter().GetResult();
            }
        }
    }

    internal static bool ShouldContinueStartupAfterSingleInstanceResult(
        SingleInstanceCoordinatorResult result,
        Action<string> reportError)
    {
        ArgumentNullException.ThrowIfNull(result);
        ArgumentNullException.ThrowIfNull(reportError);

        if (result.Role == SingleInstanceRole.Owner)
        {
            return true;
        }

        // Secondary instances must never block on UI; the owner either handled
        // ShowTray or this process exits without leaving a stuck dialog.
        return false;
    }

    internal static void DisposeTrayWindow(IDisposable? trayWindow) =>
        trayWindow?.Dispose();

    internal static async Task ShutdownFromTrayAsync<TMonitor>(
        Func<TMonitor?> getMonitor,
        Action<TMonitor?> setMonitor,
        Func<ClipboardApplicationContext?> getContext,
        CancellationToken cancellationToken = default)
        where TMonitor : IDisposable
    {
        ArgumentNullException.ThrowIfNull(getMonitor);
        ArgumentNullException.ThrowIfNull(setMonitor);
        ArgumentNullException.ThrowIfNull(getContext);

        var monitor = getMonitor();
        if (monitor is not null)
        {
            try
            {
                monitor.Dispose();
            }
            finally
            {
                setMonitor(default);
            }
        }

        var context = getContext();
        if (context is not null)
        {
            await context.ShutdownAsync(cancellationToken);
        }
    }

    private static void ShowStartupError(string message) =>
        MessageBox.Show(
            message,
            "Universal Clipboard",
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);

    internal static TMonitor StartSharingThenRegisterClipboard<TMonitor>(
        ISharingController sharing,
        Action refreshView,
        Func<TMonitor> registerClipboardMonitor)
    {
        ArgumentNullException.ThrowIfNull(sharing);
        ArgumentNullException.ThrowIfNull(refreshView);
        ArgumentNullException.ThrowIfNull(registerClipboardMonitor);

        StartSharingForStartup(sharing, refreshView);
        return registerClipboardMonitor();
    }

    private static void StartSharingForStartup(
        ISharingController sharing,
        Action refreshView,
        CancellationToken cancellationToken = default)
    {
        sharing.StartAsync(cancellationToken).ConfigureAwait(false).GetAwaiter().GetResult();
        refreshView();
    }

    private sealed class WinFormsStaScheduler : IStaScheduler, IDisposable
    {
        private readonly Control _control = new();
        private readonly int _threadId = Environment.CurrentManagedThreadId;
        private bool _disposed;

        public WinFormsStaScheduler()
        {
            _control.CreateControl();
            _ = _control.Handle;
        }

        public bool CheckAccess() => Environment.CurrentManagedThreadId == _threadId;

        public void Post(Action action)
        {
            ArgumentNullException.ThrowIfNull(action);
            if (_disposed)
            {
                return;
            }

            if (CheckAccess())
            {
                action();
                return;
            }

            _control.BeginInvoke(action);
        }

        public void PostDelayed(TimeSpan delay, Action action)
        {
            ArgumentNullException.ThrowIfNull(action);
            if (_disposed)
            {
                return;
            }

            var timer = new System.Windows.Forms.Timer
            {
                Interval = Math.Max(1, (int)Math.Min(delay.TotalMilliseconds, int.MaxValue)),
            };
            timer.Tick += (_, _) =>
            {
                timer.Stop();
                timer.Dispose();
                if (!_disposed)
                {
                    action();
                }
            };
            timer.Start();
        }

        public void Dispose()
        {
            _disposed = true;
            _control.Dispose();
        }
    }
}
