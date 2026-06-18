using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;
using System.Text.Json;
using UniversalClipboard.App.App;
using UniversalClipboard.App.Clipboard;
using UniversalClipboard.App.Network;
using UniversalClipboard.App.Security;
using UniversalClipboard.App.Ui;
using UniversalClipboard.App.Web;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.App;

internal static class Program
{
    private const string ConfigureFirewallArgument = "--configure-firewall-rule";
    private const string RemoveFirewallArgument = "--remove-firewall-rule";
    private const string DependencyManifestFile = "UniversalClipboard.deps.json";
    private static readonly string[] RequiredRuntimePayloadFiles =
    [
        "UniversalClipboard.dll",
        "UniversalClipboard.Core.dll",
        DependencyManifestFile,
        "UniversalClipboard.runtimeconfig.json",
        "QRCoder.dll",
    ];

    [STAThread]
    private static int Main(string[] args)
    {
        if (TryRunFirewallCommand(args, out var commandExitCode))
        {
            return commandExitCode;
        }

        ApplicationConfiguration.Initialize();
        using var scheduler = new WinFormsStaScheduler();

        ClipboardApplicationContext? context = null;
        WindowsClipboardMonitor? monitor = null;
        LocalWebHostController? hostController = null;
        AuthorizationCoordinator? authorization = null;
        SingleInstanceCoordinatorResult? singleInstance = null;
        TrayWindow? trayWindow = null;
        WindowsFirewallRuleManager? firewallRules = null;
        var firewallConfigured = false;

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
                return 0;
            }

            if (!VerifyRuntimePayload(AppContext.BaseDirectory, ShowStartupError))
            {
                return 1;
            }

            firewallRules = CreateFirewallRuleManager();
            if (!ConfigureFirewallForApp(firewallRules))
            {
                return 1;
            }

            firewallConfigured = true;
            var pairingCodes = new PairingCodeManager();
            authorization = AuthorizationCoordinator.CreateAsync(
                new DpapiAuthorizationPersistence(),
                pairingCodes,
                new SessionTokenService()).GetAwaiter().GetResult();
            var clipboard = new ClipboardPipelineContentStore();
            var incomingSink = new DeferredIncomingTextSink(() => context);
            var httpsCertificates = new DpapiHttpsCertificateProvider();
            var firewallRuleQuery = CreateFirewallRuleQuery();

            hostController = new LocalWebHostController(
                authorization,
                () => clipboard.HistorySnapshot,
                () => context?.SelectedDuration ?? AuthorizationDuration.FiveHours,
                httpsCertificates,
                incomingSink);
            var network = new NetworkCoordinator(
                new WindowsNetworkEnvironment(),
                new TcpPortProbe(new SystemTcpPortInspector()),
                new WindowsFirewallInspector(
                    firewallRuleQuery),
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
                    new WindowsClipboardWriter(scheduler),
                    new QrCodeRenderer(),
                    httpsCertificates,
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
            
            context.ShowTray();

            Application.Run(context);
            return 0;
        }
        finally
        {
            RunCleanupThenFirewallRemoval(
                () =>
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
                },
                () =>
                {
                    if (firewallConfigured && firewallRules is not null)
                    {
                        RemoveFirewallForApp(firewallRules);
                    }
                });
        }
    }

    private static bool TryRunFirewallCommand(string[] args, out int exitCode)
    {
        exitCode = 0;
        if (!IsFirewallCommand(args))
        {
            return false;
        }

        if (!VerifyRuntimePayload(AppContext.BaseDirectory, ShowStartupError))
        {
            exitCode = 1;
            return true;
        }

        return TryRunFirewallCommand(args, CreateFirewallRuleManager(), out exitCode);
    }

    internal static bool TryRunFirewallCommand(
        string[] args,
        WindowsFirewallRuleManager manager,
        out int exitCode)
    {
        exitCode = 0;
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(manager);

        if (!IsFirewallCommand(args))
        {
            return false;
        }

        return RunFirewallCommand(args[0], manager, out exitCode);
    }

    internal static bool TryRunFirewallCommand(
        string[] args,
        WindowsFirewallRuleManager manager,
        string baseDirectory,
        Action<string> reportError,
        out int exitCode)
    {
        exitCode = 0;
        ArgumentNullException.ThrowIfNull(args);
        ArgumentNullException.ThrowIfNull(manager);
        ArgumentNullException.ThrowIfNull(reportError);

        if (!IsFirewallCommand(args))
        {
            return false;
        }

        if (!VerifyRuntimePayload(baseDirectory, reportError))
        {
            exitCode = 1;
            return true;
        }

        return RunFirewallCommand(args[0], manager, out exitCode);
    }

    private static bool IsFirewallCommand(string[] args) =>
        args.Length == 1 &&
        (string.Equals(args[0], ConfigureFirewallArgument, StringComparison.Ordinal) ||
         string.Equals(args[0], RemoveFirewallArgument, StringComparison.Ordinal));

    private static bool RunFirewallCommand(
        string argument,
        WindowsFirewallRuleManager manager,
        out int exitCode)
    {
        exitCode = 0;
        try
        {
            switch (argument)
            {
                case ConfigureFirewallArgument:
                    manager.EnsureRule(LocalWebHost.Port);
                    return true;
                case RemoveFirewallArgument:
                    manager.RemoveRule();
                    return true;
                default:
                    return false;
            }
        }
        catch (Exception exception) when (IsFirewallManagementException(exception))
        {
            exitCode = 1;
            return true;
        }
    }

    private static WindowsFirewallRuleManager CreateFirewallRuleManager()
    {
        var bridge = new ReflectionWindowsFirewallComBridge();
        return new WindowsFirewallRuleManager(
            CreateFirewallRuleQuery(bridge),
            new WindowsFirewallComRuleEditor(bridge));
    }

    private static IFirewallRuleQuery CreateFirewallRuleQuery(
        IWindowsFirewallComBridge? bridge = null) =>
        new WindowsFirewallComRuleQuery(new WindowsFirewallComRules(
            bridge ?? new ReflectionWindowsFirewallComBridge()));

    private static bool ConfigureFirewallForApp(WindowsFirewallRuleManager manager)
    {
        try
        {
            if (manager.IsRuleReady(LocalWebHost.Port))
            {
                return true;
            }
        }
        catch (Exception exception) when (IsFirewallManagementException(exception))
        {
            // Non-elevated inspection can fail on locked-down hosts; the elevated helper gets the final attempt.
        }

        try
        {
            RunFirewallManagement(manager, ConfigureFirewallArgument);
            return true;
        }
        catch (Exception exception) when (IsFirewallManagementException(exception))
        {
            ShowFirewallError(
                "Windows Firewall rule was not configured.",
                "Universal Clipboard needs an inbound Private + LocalSubnet TCP 43127 rule before the phone can connect.",
                exception);
            return false;
        }
    }

    private static void RemoveFirewallForApp(WindowsFirewallRuleManager manager)
    {
        try
        {
            RunFirewallManagement(manager, RemoveFirewallArgument);
        }
        catch (Exception exception) when (IsFirewallManagementException(exception))
        {
            ShowFirewallError(
                "Windows Firewall rule was not removed.",
                "Run .\\scripts\\remove-firewall.ps1 from Administrator PowerShell to remove the Universal Clipboard LAN rule.",
                exception);
        }
    }

    private static void RunFirewallManagement(
        WindowsFirewallRuleManager manager,
        string elevatedArgument)
    {
        if (TestIsAdministrator())
        {
            if (string.Equals(elevatedArgument, ConfigureFirewallArgument, StringComparison.Ordinal))
            {
                manager.EnsureRule(LocalWebHost.Port);
            }
            else
            {
                manager.RemoveRule();
            }

            return;
        }

        RunElevatedFirewallCommand(elevatedArgument);
    }

    private static void RunElevatedFirewallCommand(string argument)
    {
        var executable = Environment.ProcessPath ?? Application.ExecutablePath;
        using var process = Process.Start(new ProcessStartInfo
        {
            FileName = executable,
            Arguments = argument,
            UseShellExecute = true,
            Verb = "runas",
            WindowStyle = ProcessWindowStyle.Hidden,
        }) ?? throw new InvalidOperationException("Windows did not start the elevated firewall helper.");

        process.WaitForExit();
        if (process.ExitCode != 0)
        {
            throw new InvalidOperationException(
                $"The elevated firewall helper failed with exit code {process.ExitCode}.");
        }
    }

    private static bool TestIsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    private static bool IsFirewallManagementException(Exception exception) =>
        exception is Win32Exception or InvalidOperationException or UnauthorizedAccessException ||
        exception is System.Runtime.InteropServices.COMException or System.Reflection.TargetInvocationException ||
        exception is MissingMethodException or ArgumentException;

    private static void ShowFirewallError(string title, string detail, Exception exception) =>
        MessageBox.Show(
            $"{detail}{Environment.NewLine}{Environment.NewLine}Details: {exception.GetType().Name}",
            title,
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);

    internal static bool VerifyRuntimePayload(
        string baseDirectory,
        Action<string> reportError,
        IEnumerable<string>? requiredFiles = null)
    {
        ArgumentNullException.ThrowIfNull(reportError);
        var missing = GetMissingRuntimePayloadFiles(baseDirectory, requiredFiles);
        if (missing.Count == 0)
        {
            return true;
        }

        reportError(
            "Universal Clipboard is missing required runtime files. Extract the full UniversalClipboard-win-x64.zip again, or run .\\scripts\\run.ps1 from the source tree to restore packages and rebuild."
            + Environment.NewLine
            + Environment.NewLine
            + "Missing files:"
            + Environment.NewLine
            + string.Join(Environment.NewLine, missing.Select(file => "- " + file)));
        return false;
    }

    internal static IReadOnlyList<string> GetMissingRuntimePayloadFiles(
        string baseDirectory,
        IEnumerable<string>? requiredFiles = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(baseDirectory);
        return (requiredFiles ?? RequiredRuntimePayloadFiles)
            .Concat(GetDependencyManifestRuntimeFiles(baseDirectory))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Where(file => !File.Exists(Path.Combine(baseDirectory, file)))
            .ToArray();
    }

    private static IEnumerable<string> GetDependencyManifestRuntimeFiles(string baseDirectory)
    {
        var manifestPath = Path.Combine(baseDirectory, DependencyManifestFile);
        if (!File.Exists(manifestPath))
        {
            return [];
        }

        try
        {
            using var stream = File.OpenRead(manifestPath);
            using var document = JsonDocument.Parse(stream);
            if (!document.RootElement.TryGetProperty("targets", out var targets) ||
                targets.ValueKind != JsonValueKind.Object)
            {
                return [];
            }

            var files = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var target in targets.EnumerateObject())
            {
                if (target.Value.ValueKind != JsonValueKind.Object)
                {
                    continue;
                }

                foreach (var library in target.Value.EnumerateObject())
                {
                    AddDependencyAssetFiles(library.Value, "runtime", files);
                    AddDependencyAssetFiles(library.Value, "native", files);
                }
            }

            return files.ToArray();
        }
        catch (JsonException)
        {
            return [DependencyManifestFile];
        }
        catch (IOException)
        {
            return [DependencyManifestFile];
        }
        catch (UnauthorizedAccessException)
        {
            return [DependencyManifestFile];
        }
    }

    private static void AddDependencyAssetFiles(
        JsonElement library,
        string assetGroup,
        ISet<string> files)
    {
        if (!library.TryGetProperty(assetGroup, out var assets) ||
            assets.ValueKind != JsonValueKind.Object)
        {
            return;
        }

        foreach (var asset in assets.EnumerateObject())
        {
            var fileName = Path.GetFileName(asset.Name.Replace('/', Path.DirectorySeparatorChar));
            if (!string.IsNullOrWhiteSpace(fileName) &&
                !string.Equals(fileName, "_._", StringComparison.Ordinal))
            {
                files.Add(fileName);
            }
        }
    }

    internal static void RunCleanupThenFirewallRemoval(
        Action cleanup,
        Action removeFirewall)
    {
        ArgumentNullException.ThrowIfNull(cleanup);
        ArgumentNullException.ThrowIfNull(removeFirewall);

        try
        {
            cleanup();
        }
        finally
        {
            removeFirewall();
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

    private sealed class DeferredIncomingTextSink(Func<IIncomingTextSink?> sinkProvider)
        : IIncomingTextSink
    {
        public ValueTask<IncomingTextItem> EnqueueAsync(
            IncomingTextRequest request,
            CancellationToken cancellationToken = default)
        {
            return GetSink().EnqueueAsync(request, cancellationToken);
        }

        public ValueTask ClearAuthorizationAsync(
            Guid authorizationId,
            CancellationToken cancellationToken = default) =>
            sinkProvider()?.ClearAuthorizationAsync(authorizationId, cancellationToken)
            ?? ValueTask.CompletedTask;

        public ValueTask ClearAllAsync(CancellationToken cancellationToken = default) =>
            sinkProvider()?.ClearAllAsync(cancellationToken) ?? ValueTask.CompletedTask;

        private IIncomingTextSink GetSink() =>
            sinkProvider() ??
            throw new InvalidOperationException("The incoming text sink is not available.");
    }

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
