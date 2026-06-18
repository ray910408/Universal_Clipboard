using System.Collections.Immutable;
using System.Globalization;
using System.Net.NetworkInformation;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using UniversalClipboard.App.Web;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.App.Network;

public interface INetworkEnvironment
{
    ValueTask<IReadOnlyList<NetworkInterfaceState>> GetInterfacesAsync(
        CancellationToken cancellationToken = default);
}

public interface IPortProbe
{
    PortProbeResult Check(IPAddress address, int port);
}

public sealed record TcpPortOwnerSnapshot(IPAddress Address, int Port, string Diagnostic);

public interface ITcpPortInspector
{
    IReadOnlyList<TcpPortOwnerSnapshot> GetActiveListeners();
}

public sealed record PortProbeResult(bool IsAvailable, string? OwnerDiagnostic)
{
    public static PortProbeResult Available { get; } = new(true, null);

    public static PortProbeResult Conflict(string ownerDiagnostic) => new(false, ownerDiagnostic);
}

public sealed class TcpPortProbe(ITcpPortInspector inspector) : IPortProbe
{
    public PortProbeResult Check(IPAddress address, int port)
    {
        var listener = inspector.GetActiveListeners().FirstOrDefault(item =>
            item.Port == port &&
            (item.Address.Equals(address) ||
             item.Address.Equals(IPAddress.Any) ||
             item.Address.Equals(IPAddress.IPv6Any)));

        return listener is null
            ? PortProbeResult.Available
            : PortProbeResult.Conflict(
                $"{listener.Address}:{listener.Port} {listener.Diagnostic}");
    }
}

public sealed class SystemTcpPortInspector : ITcpPortInspector
{
    public IReadOnlyList<TcpPortOwnerSnapshot> GetActiveListeners()
    {
        var properties = IPGlobalProperties.GetIPGlobalProperties();
        return properties.GetActiveTcpListeners()
            .Select(endpoint => new TcpPortOwnerSnapshot(
                endpoint.Address,
                endpoint.Port,
                "owning process unavailable from IPGlobalProperties"))
            .Concat(properties.GetActiveTcpConnections()
                .Where(connection => connection.State == TcpState.Listen)
                .Select(connection => new TcpPortOwnerSnapshot(
                    connection.LocalEndPoint.Address,
                    connection.LocalEndPoint.Port,
                    "owning process unavailable from IPGlobalProperties")))
            .Distinct()
            .ToArray();
    }
}

public interface IFirewallInspector
{
    FirewallInspectionResult Inspect(int port);
}

public interface IFirewallRuleQuery
{
    IReadOnlyList<FirewallRuleSnapshot> GetRules();
}

public enum FirewallRuleStatus
{
    Unknown,
    ExactRuleFound,
    Missing,
}

public enum FirewallRuleAction
{
    Allow,
    Block,
}

public enum FirewallRuleProtocol
{
    Tcp,
    Udp,
    Any,
}

public enum FirewallRuleProfile
{
    Private,
    Public,
    Any,
}

public enum FirewallRemoteAddressScope
{
    LocalSubnet,
    Any,
    Other,
}

public sealed record FirewallRuleSnapshot(
    string Name,
    string DisplayName,
    bool IsEnabled,
    FirewallRuleAction Action,
    FirewallRuleProtocol Protocol,
    int LocalPort,
    FirewallRuleProfile Profile,
    FirewallRemoteAddressScope RemoteAddressScope);

public sealed record FirewallInspectionResult(FirewallRuleStatus Status);

public interface IFirewallRuleEditor
{
    void AddRule(FirewallRuleDefinition definition);

    void RemoveRule(string name);
}

public sealed record FirewallRuleDefinition(
    string Name,
    string DisplayName,
    bool IsEnabled,
    FirewallRuleAction Action,
    FirewallRuleProtocol Protocol,
    int LocalPort,
    FirewallRuleProfile Profile,
    FirewallRemoteAddressScope RemoteAddressScope);

public sealed class WindowsFirewallRuleManager(
    IFirewallRuleQuery ruleQuery,
    IFirewallRuleEditor ruleEditor)
{
    public bool IsRuleReady(int port)
    {
        var matchingNameRules = GetMatchingNameRules();
        return matchingNameRules is [var rule] && IsExactRule(rule, port);
    }

    public void EnsureRule(int port)
    {
        var matchingNameRules = GetMatchingNameRules();
        if (matchingNameRules is [var rule] && IsExactRule(rule, port))
        {
            return;
        }

        RemoveExpectedRules(matchingNameRules);
        ruleEditor.AddRule(ExpectedDefinition(port));
    }

    public void RemoveRule()
    {
        RemoveExpectedRules(GetMatchingNameRules());
    }

    private FirewallRuleSnapshot[] GetMatchingNameRules() =>
        ruleQuery.GetRules()
            .Where(IsExpectedName)
            .ToArray();

    private static FirewallRuleDefinition ExpectedDefinition(int port) =>
        new(
            WindowsFirewallInspector.ExpectedRuleName,
            WindowsFirewallInspector.ExpectedRuleName,
            IsEnabled: true,
            FirewallRuleAction.Allow,
            FirewallRuleProtocol.Tcp,
            port,
            FirewallRuleProfile.Private,
            FirewallRemoteAddressScope.LocalSubnet);

    private void RemoveExpectedRules(IReadOnlyList<FirewallRuleSnapshot> rules)
    {
        foreach (var rule in rules)
        {
            ruleEditor.RemoveRule(rule.Name);
        }
    }

    private static bool IsExpectedName(FirewallRuleSnapshot rule) =>
        string.Equals(rule.Name, WindowsFirewallInspector.ExpectedRuleName, StringComparison.Ordinal) ||
        string.Equals(rule.DisplayName, WindowsFirewallInspector.ExpectedRuleName, StringComparison.Ordinal);

    private static bool IsExactRule(FirewallRuleSnapshot rule, int port) =>
        string.Equals(rule.Name, WindowsFirewallInspector.ExpectedRuleName, StringComparison.Ordinal) &&
        string.Equals(rule.DisplayName, WindowsFirewallInspector.ExpectedRuleName, StringComparison.Ordinal) &&
        rule.IsEnabled &&
        rule.Action == FirewallRuleAction.Allow &&
        rule.Protocol == FirewallRuleProtocol.Tcp &&
        rule.LocalPort == port &&
        rule.Profile == FirewallRuleProfile.Private &&
        rule.RemoteAddressScope == FirewallRemoteAddressScope.LocalSubnet;
}

public sealed class WindowsFirewallInspector : IFirewallInspector
{
    public const string ExpectedRuleName = "Universal Clipboard LAN";
    private static readonly TimeSpan DefaultInspectionTimeout = TimeSpan.FromMilliseconds(250);
    private readonly IFirewallRuleQuery _ruleQuery;
    private readonly TimeSpan _inspectionTimeout;
    private readonly object _inspectionGate = new();
    private Task<FirewallInspectionResult>? _activeInspection;
    private int _activeInspectionPort;

    public WindowsFirewallInspector(IFirewallRuleQuery ruleQuery)
        : this(ruleQuery, DefaultInspectionTimeout)
    {
    }

    internal WindowsFirewallInspector(IFirewallRuleQuery ruleQuery, TimeSpan inspectionTimeout)
    {
        _ruleQuery = ruleQuery;
        _inspectionTimeout = inspectionTimeout > TimeSpan.Zero
            ? inspectionTimeout
            : throw new ArgumentOutOfRangeException(nameof(inspectionTimeout));
    }

    public FirewallInspectionResult Inspect(int port)
    {
        var inspection = TryStartInspection(port);
        if (inspection is null || !inspection.Wait(_inspectionTimeout))
        {
            return new FirewallInspectionResult(FirewallRuleStatus.Unknown);
        }

        var result = inspection.GetAwaiter().GetResult();
        ClearCompletedInspection(inspection);
        return result;
    }

    private Task<FirewallInspectionResult>? TryStartInspection(int port)
    {
        lock (_inspectionGate)
        {
            if (_activeInspection is { IsCompleted: false })
            {
                // A hung COM enumeration should consume at most one background worker per inspector.
                return null;
            }

            if (_activeInspection is { IsCompleted: true } completed)
            {
                _activeInspection = null;
                if (_activeInspectionPort == port)
                {
                    return completed;
                }
            }

            _activeInspectionPort = port;
            _activeInspection = Task.Run(() => InspectCore(port));
            return _activeInspection;
        }
    }

    private void ClearCompletedInspection(Task<FirewallInspectionResult> inspection)
    {
        lock (_inspectionGate)
        {
            if (ReferenceEquals(_activeInspection, inspection) && inspection.IsCompleted)
            {
                _activeInspection = null;
            }
        }
    }

    private FirewallInspectionResult InspectCore(int port)
    {
        try
        {
            var hasExactRule = _ruleQuery.GetRules().Any(rule =>
                string.Equals(rule.Name, ExpectedRuleName, StringComparison.Ordinal) &&
                string.Equals(rule.DisplayName, ExpectedRuleName, StringComparison.Ordinal) &&
                rule.IsEnabled &&
                rule.Action == FirewallRuleAction.Allow &&
                rule.Protocol == FirewallRuleProtocol.Tcp &&
                rule.LocalPort == port &&
                rule.Profile == FirewallRuleProfile.Private &&
                rule.RemoteAddressScope == FirewallRemoteAddressScope.LocalSubnet);
            return new FirewallInspectionResult(
                hasExactRule ? FirewallRuleStatus.ExactRuleFound : FirewallRuleStatus.Unknown);
        }
        catch (COMException)
        {
            return new FirewallInspectionResult(FirewallRuleStatus.Unknown);
        }
        catch (UnauthorizedAccessException)
        {
            return new FirewallInspectionResult(FirewallRuleStatus.Unknown);
        }
        catch (TargetInvocationException)
        {
            return new FirewallInspectionResult(FirewallRuleStatus.Unknown);
        }
        catch (ArgumentException)
        {
            return new FirewallInspectionResult(FirewallRuleStatus.Unknown);
        }
        catch (MissingMethodException)
        {
            return new FirewallInspectionResult(FirewallRuleStatus.Unknown);
        }
        catch (InvalidOperationException)
        {
            return new FirewallInspectionResult(FirewallRuleStatus.Unknown);
        }
    }
}

public sealed record ComFirewallRuleSnapshot(
    string Name,
    string DisplayName,
    bool Enabled,
    int Action,
    int Protocol,
    string LocalPorts,
    int Profiles,
    string RemoteAddresses);

public interface IComFirewallRules
{
    IReadOnlyList<ComFirewallRuleSnapshot> GetRules();
}

public sealed class WindowsFirewallComRuleQuery(IComFirewallRules rules) : IFirewallRuleQuery
{
    public const int DomainProfile = 1;
    public const int PrivateProfile = 2;
    public const int PublicProfile = 4;
    public const int AllProfiles = int.MaxValue;
    public const int InboundDirection = 1;
    public const int AllowAction = 1;
    public const int BlockAction = 0;
    public const int TcpProtocol = 6;
    public const int UdpProtocol = 17;

    public IReadOnlyList<FirewallRuleSnapshot> GetRules() =>
        rules.GetRules()
            .SelectMany(MapRule)
            .ToArray();

    private static IEnumerable<FirewallRuleSnapshot> MapRule(ComFirewallRuleSnapshot rule)
    {
        yield return new FirewallRuleSnapshot(
            rule.Name,
            rule.DisplayName,
            rule.Enabled,
            rule.Action == AllowAction ? FirewallRuleAction.Allow : FirewallRuleAction.Block,
            rule.Protocol == TcpProtocol ? FirewallRuleProtocol.Tcp : FirewallRuleProtocol.Udp,
            ParseSinglePort(rule.LocalPorts),
            rule.Profiles == PrivateProfile
                ? FirewallRuleProfile.Private
                : rule.Profiles == PublicProfile
                    ? FirewallRuleProfile.Public
                    : FirewallRuleProfile.Any,
            string.Equals(rule.RemoteAddresses, "LocalSubnet", StringComparison.OrdinalIgnoreCase)
                ? FirewallRemoteAddressScope.LocalSubnet
                : string.Equals(rule.RemoteAddresses, "*", StringComparison.Ordinal)
                    ? FirewallRemoteAddressScope.Any
                    : FirewallRemoteAddressScope.Other);
    }

    private static int ParseSinglePort(string localPorts)
    {
        var parts = localPorts.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        return parts is [var part] && int.TryParse(part, out var port)
            ? port
            : 0;
    }

    internal static int ToComAction(FirewallRuleAction action) =>
        action switch
        {
            FirewallRuleAction.Allow => AllowAction,
            FirewallRuleAction.Block => BlockAction,
            _ => throw new ArgumentOutOfRangeException(nameof(action)),
        };

    internal static int ToComProtocol(FirewallRuleProtocol protocol) =>
        protocol switch
        {
            FirewallRuleProtocol.Tcp => TcpProtocol,
            FirewallRuleProtocol.Udp => UdpProtocol,
            FirewallRuleProtocol.Any => 256,
            _ => throw new ArgumentOutOfRangeException(nameof(protocol)),
        };

    internal static int ToComProfile(FirewallRuleProfile profile) =>
        profile switch
        {
            FirewallRuleProfile.Private => PrivateProfile,
            FirewallRuleProfile.Public => PublicProfile,
            FirewallRuleProfile.Any => AllProfiles,
            _ => throw new ArgumentOutOfRangeException(nameof(profile)),
        };

    internal static string ToComRemoteAddress(FirewallRemoteAddressScope scope) =>
        scope switch
        {
            FirewallRemoteAddressScope.LocalSubnet => "LocalSubnet",
            FirewallRemoteAddressScope.Any => "*",
            FirewallRemoteAddressScope.Other => throw new ArgumentOutOfRangeException(nameof(scope)),
            _ => throw new ArgumentOutOfRangeException(nameof(scope)),
        };
}

public sealed class WindowsFirewallComRules : IComFirewallRules
{
    private readonly IWindowsFirewallComBridge _bridge;

    public WindowsFirewallComRules()
        : this(new ReflectionWindowsFirewallComBridge())
    {
    }

    internal WindowsFirewallComRules(IWindowsFirewallComBridge bridge)
    {
        _bridge = bridge;
    }

    public IReadOnlyList<ComFirewallRuleSnapshot> GetRules()
    {
        object? policy = null;
        object? rules = null;
        try
        {
            policy = _bridge.CreatePolicy();
            if (policy is null)
            {
                return [];
            }

            rules = _bridge.GetRules(policy);
            if (rules is not System.Collections.IEnumerable enumerable)
            {
                return [];
            }

            var snapshots = new List<ComFirewallRuleSnapshot>();
            foreach (var rule in enumerable)
            {
                try
                {
                    var name = GetProperty<string>(rule, "Name") ?? "";
                    snapshots.Add(new ComFirewallRuleSnapshot(
                        name,
                        GetOptionalProperty<string>(rule, "DisplayName") ?? name,
                        GetProperty<bool>(rule, "Enabled"),
                        GetProperty<int>(rule, "Action"),
                        GetProperty<int>(rule, "Protocol"),
                        GetProperty<string>(rule, "LocalPorts") ?? "",
                        GetProperty<int>(rule, "Profiles"),
                        GetProperty<string>(rule, "RemoteAddresses") ?? ""));
                }
                catch (COMException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
                catch (ArgumentException)
                {
                }
                catch (TargetInvocationException)
                {
                }
                finally
                {
                    ReleaseIfComObject(rule);
                }
            }

            return snapshots;
        }
        catch (COMException)
        {
            return [];
        }
        catch (UnauthorizedAccessException)
        {
            return [];
        }
        finally
        {
            ReleaseIfComObject(rules);
            ReleaseIfComObject(policy);
        }
    }

    private T? GetProperty<T>(object target, string name)
    {
        var value = _bridge.GetProperty(target, name);
        return value is T typed ? typed : default;
    }

    private T? GetOptionalProperty<T>(object target, string name)
    {
        try
        {
            return GetProperty<T>(target, name);
        }
        catch (COMException)
        {
            return default;
        }
        catch (TargetInvocationException)
        {
            return default;
        }
        catch (ArgumentException)
        {
            return default;
        }
        catch (MissingMethodException)
        {
            return default;
        }
    }

    private void ReleaseIfComObject(object? target)
    {
        if (target is not null && _bridge.IsComObject(target))
        {
            _bridge.Release(target);
        }
    }
}

public sealed class WindowsFirewallComRuleEditor : IFirewallRuleEditor
{
    private readonly IWindowsFirewallComBridge _bridge;

    public WindowsFirewallComRuleEditor()
        : this(new ReflectionWindowsFirewallComBridge())
    {
    }

    internal WindowsFirewallComRuleEditor(IWindowsFirewallComBridge bridge)
    {
        _bridge = bridge;
    }

    public void AddRule(FirewallRuleDefinition definition)
    {
        object? policy = null;
        object? rules = null;
        object? rule = null;
        try
        {
            policy = _bridge.CreatePolicy();
            rules = policy is null ? null : _bridge.GetRules(policy);
            rule = _bridge.CreateRule();
            if (rules is null || rule is null)
            {
                throw new InvalidOperationException("Windows Firewall COM automation is unavailable.");
            }

            _bridge.SetProperty(rule, "Name", definition.Name);
            TrySetOptionalProperty(rule, "DisplayName", definition.DisplayName);
            _bridge.SetProperty(
                rule,
                "Description",
                "Allows Universal Clipboard phone access on trusted Private LANs only.");
            _bridge.SetProperty(rule, "Enabled", definition.IsEnabled);
            _bridge.SetProperty(rule, "Direction", WindowsFirewallComRuleQuery.InboundDirection);
            _bridge.SetProperty(rule, "Action", WindowsFirewallComRuleQuery.ToComAction(definition.Action));
            _bridge.SetProperty(rule, "Protocol", WindowsFirewallComRuleQuery.ToComProtocol(definition.Protocol));
            _bridge.SetProperty(rule, "LocalPorts", definition.LocalPort.ToString(CultureInfo.InvariantCulture));
            _bridge.SetProperty(rule, "Profiles", WindowsFirewallComRuleQuery.ToComProfile(definition.Profile));
            _bridge.SetProperty(
                rule,
                "RemoteAddresses",
                WindowsFirewallComRuleQuery.ToComRemoteAddress(definition.RemoteAddressScope));
            _bridge.AddRule(rules, rule);
        }
        finally
        {
            ReleaseIfComObject(rule);
            ReleaseIfComObject(rules);
            ReleaseIfComObject(policy);
        }
    }

    private void TrySetOptionalProperty(object target, string name, object value)
    {
        try
        {
            _bridge.SetProperty(target, name, value);
        }
        catch (COMException)
        {
        }
        catch (TargetInvocationException)
        {
        }
        catch (ArgumentException)
        {
        }
        catch (MissingMethodException)
        {
        }
    }

    public void RemoveRule(string name)
    {
        object? policy = null;
        object? rules = null;
        try
        {
            policy = _bridge.CreatePolicy();
            rules = policy is null ? null : _bridge.GetRules(policy);
            if (rules is null)
            {
                throw new InvalidOperationException("Windows Firewall COM automation is unavailable.");
            }

            _bridge.RemoveRule(rules, name);
        }
        finally
        {
            ReleaseIfComObject(rules);
            ReleaseIfComObject(policy);
        }
    }

    private void ReleaseIfComObject(object? target)
    {
        if (target is not null && _bridge.IsComObject(target))
        {
            _bridge.Release(target);
        }
    }
}

internal interface IWindowsFirewallComBridge
{
    object? CreatePolicy();

    object? CreateRule();

    object? GetRules(object policy);

    object? GetProperty(object target, string name);

    void SetProperty(object target, string name, object value);

    void AddRule(object rules, object rule);

    void RemoveRule(object rules, string name);

    bool IsComObject(object target);

    void Release(object target);
}

internal sealed class ReflectionWindowsFirewallComBridge : IWindowsFirewallComBridge
{
    public object? CreatePolicy()
    {
        var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2");
        return policyType is null ? null : Activator.CreateInstance(policyType);
    }

    public object? CreateRule()
    {
        var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule");
        return ruleType is null ? null : Activator.CreateInstance(ruleType);
    }

    public object? GetRules(object policy) =>
        policy.GetType().InvokeMember(
            "Rules",
            BindingFlags.GetProperty,
            null,
            policy,
            null);

    public object? GetProperty(object target, string name) =>
        target.GetType().InvokeMember(
            name,
            BindingFlags.GetProperty,
            null,
            target,
            null);

    public void SetProperty(object target, string name, object value) =>
        target.GetType().InvokeMember(
            name,
            BindingFlags.SetProperty,
            null,
            target,
            [value]);

    public void AddRule(object rules, object rule) =>
        rules.GetType().InvokeMember(
            "Add",
            BindingFlags.InvokeMethod,
            null,
            rules,
            [rule]);

    public void RemoveRule(object rules, string name) =>
        rules.GetType().InvokeMember(
            "Remove",
            BindingFlags.InvokeMethod,
            null,
            rules,
            [name]);

    public bool IsComObject(object target) => Marshal.IsComObject(target);

    public void Release(object target) => Marshal.ReleaseComObject(target);
}

public interface ILocalWebHostController
{
    ValueTask StartAsync(IPEndPoint endpoint, CancellationToken cancellationToken);

    ValueTask StopAsync(CancellationToken cancellationToken);
}

public interface IPairingCodeInvalidator
{
    ValueTask InvalidateActiveCodesAsync(CancellationToken cancellationToken);
}

public enum NetworkSharingStatus
{
    Shutdown,
    NoEligibleInterface,
    PublicProfileBlocked,
    SelectionRequired,
    PortConflict,
    AuthorizationPersistenceFailed,
    Starting,
    Running,
}

public sealed record NetworkSharingState(
    NetworkSharingStatus Status,
    string? SelectedInterfaceId,
    IPAddress? SelectedAddress,
    string? SelectedUrl,
    NetworkProfile? SelectedNetworkProfile,
    int Port,
    bool IsPortListening,
    FirewallRuleStatus FirewallRuleStatus,
    string? PortDiagnostic,
    ImmutableArray<NetworkInterfaceSelectionOption> InterfaceOptions = default)
{
    public static NetworkSharingState Initial { get; } =
        new(
            NetworkSharingStatus.Shutdown,
            null,
            null,
            null,
            null,
            LocalWebHost.Port,
            IsPortListening: false,
            FirewallRuleStatus.Unknown,
            null);
}

public sealed record NetworkInterfaceSelectionOption(
    string InterfaceId,
    string DisplayName,
    IPAddress Address);

public sealed class NetworkCoordinator
{
    private readonly INetworkEnvironment _environment;
    private readonly IPortProbe _portProbe;
    private readonly IFirewallInspector _firewall;
    private readonly ILocalWebHostController _host;
    private readonly IPairingCodeInvalidator _pairingCodeInvalidator;
    private readonly IAuthorizationAdministration _authorization;
    private readonly object _coalesceGate = new();
    private Task<NetworkSharingState>? _activeEvaluation;
    private bool _evaluateAgain;
    private string? _selectedInterfaceId;
    private IPEndPoint? _runningEndpoint;
    private bool _shutdown = true;
    private long _lifecycleVersion;
    private NetworkSharingState _currentState = NetworkSharingState.Initial;

    public NetworkCoordinator(
        INetworkEnvironment environment,
        IPortProbe portProbe,
        IFirewallInspector firewall,
        ILocalWebHostController host,
        IPairingCodeInvalidator pairingCodeInvalidator,
        IAuthorizationAdministration authorization)
    {
        _environment = environment;
        _portProbe = portProbe;
        _firewall = firewall;
        _host = host;
        _pairingCodeInvalidator = pairingCodeInvalidator;
        _authorization = authorization;
    }

    public NetworkSharingState CurrentState => Volatile.Read(ref _currentState);

    public Task<NetworkSharingState> StartAsync(CancellationToken cancellationToken = default)
    {
        if (Volatile.Read(ref _shutdown))
        {
            Interlocked.Increment(ref _lifecycleVersion);
        }

        Volatile.Write(ref _shutdown, false);
        return RefreshAsync(cancellationToken);
    }

    public async Task<NetworkSharingState> ShutdownAsync(CancellationToken cancellationToken = default)
    {
        Volatile.Write(ref _shutdown, true);
        Interlocked.Increment(ref _lifecycleVersion);
        await StopRunningHostAsync(cancellationToken).ConfigureAwait(false);
        var state = NetworkSharingState.Initial;
        Publish(state);
        return state;
    }

    public Task<NetworkSharingState> SetSelectedInterfaceAsync(
        string interfaceId,
        CancellationToken cancellationToken = default)
    {
        _selectedInterfaceId = interfaceId;
        Interlocked.Increment(ref _lifecycleVersion);
        return RefreshAsync(cancellationToken);
    }

    public Task<NetworkSharingState> RefreshAsync(CancellationToken cancellationToken = default)
    {
        lock (_coalesceGate)
        {
            if (_activeEvaluation is not null && !_activeEvaluation.IsCompleted)
            {
                _evaluateAgain = true;
                return _activeEvaluation;
            }

            _activeEvaluation = RunCoalescedAsync(cancellationToken);
            return _activeEvaluation;
        }
    }

    private async Task<NetworkSharingState> RunCoalescedAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            NetworkSharingState state;
            if (Volatile.Read(ref _shutdown))
            {
                await StopRunningHostAsync(cancellationToken).ConfigureAwait(false);
                state = NetworkSharingState.Initial;
                Publish(state);
            }
            else
            {
                state = await EvaluateAsync(cancellationToken).ConfigureAwait(false);
            }

            lock (_coalesceGate)
            {
                if (!_evaluateAgain)
                {
                    _activeEvaluation = null;
                    return state;
                }

                _evaluateAgain = false;
            }
        }
    }

    private async Task<NetworkSharingState> EvaluateAsync(CancellationToken cancellationToken)
    {
        var lifecycleVersion = Volatile.Read(ref _lifecycleVersion);
        var interfaces = await _environment.GetInterfacesAsync(cancellationToken).ConfigureAwait(false);
        if (!IsEvaluationCurrent(lifecycleVersion))
        {
            return await StopStaleEvaluationAsync(cancellationToken).ConfigureAwait(false);
        }

        if (interfaces.Any(IsPublicProfileCandidate))
        {
            await StopRunningHostAndInvalidateAsync(cancellationToken).ConfigureAwait(false);
            return Publish(new NetworkSharingState(
                NetworkSharingStatus.PublicProfileBlocked,
                null,
                null,
                null,
                NetworkProfile.Public,
                LocalWebHost.Port,
                IsPortListening: false,
                _firewall.Inspect(LocalWebHost.Port).Status,
                null));
        }

        var selection = NetworkInterfaceSelector.Select(interfaces, _selectedInterfaceId);
        if (selection.Status == NetworkSelectionStatus.NoEligibleInterface)
        {
            await StopRunningHostAndInvalidateAsync(cancellationToken).ConfigureAwait(false);
            return Publish(new NetworkSharingState(
                NetworkSharingStatus.NoEligibleInterface,
                null,
                null,
                null,
                null,
                LocalWebHost.Port,
                IsPortListening: false,
                _firewall.Inspect(LocalWebHost.Port).Status,
                null));
        }

        if (selection.Status == NetworkSelectionStatus.SelectionRequired)
        {
            await StopRunningHostAndInvalidateAsync(cancellationToken).ConfigureAwait(false);
            return Publish(new NetworkSharingState(
                NetworkSharingStatus.SelectionRequired,
                null,
                null,
                null,
                null,
                LocalWebHost.Port,
                IsPortListening: false,
                _firewall.Inspect(LocalWebHost.Port).Status,
                null,
                ToInterfaceOptions(selection.EligibleInterfaces)));
        }

        var selected = selection.Selected!;
        var address = selection.SelectedAddress!;
        var endpoint = new IPEndPoint(address, LocalWebHost.Port);
        if (_runningEndpoint is not null && _runningEndpoint.Equals(endpoint))
        {
            return Publish(RunningState(selected, address));
        }

        var probe = _portProbe.Check(address, LocalWebHost.Port);
        if (!probe.IsAvailable)
        {
            await StopRunningHostAsync(cancellationToken).ConfigureAwait(false);
            return Publish(new NetworkSharingState(
                NetworkSharingStatus.PortConflict,
                selected.Id,
                address,
                null,
                selected.Profile,
                LocalWebHost.Port,
                IsPortListening: false,
                _firewall.Inspect(LocalWebHost.Port).Status,
                probe.OwnerDiagnostic));
        }

        var hadRunningEndpoint = _runningEndpoint is not null;
        if (hadRunningEndpoint)
        {
            await StopRunningHostAsync(cancellationToken).ConfigureAwait(false);
            var revoke = await _authorization.RevokeAllAsync(cancellationToken).ConfigureAwait(false);
            if (!revoke.Succeeded)
            {
                return Publish(AuthPersistenceFailedState(selected, address));
            }
        }

        var staleRemoval = await _authorization.RemoveStaleBindingsAsync(
            [address],
            cancellationToken).ConfigureAwait(false);
        if (!IsEvaluationCurrent(lifecycleVersion))
        {
            return await StopStaleEvaluationAsync(cancellationToken).ConfigureAwait(false);
        }

        if (!staleRemoval.Succeeded)
        {
            return Publish(AuthPersistenceFailedState(selected, address));
        }

        if (!IsEvaluationCurrent(lifecycleVersion))
        {
            return await StopStaleEvaluationAsync(cancellationToken).ConfigureAwait(false);
        }

        Publish(new NetworkSharingState(
            NetworkSharingStatus.Starting,
            selected.Id,
            address,
            BuildUrl(address),
            selected.Profile,
            LocalWebHost.Port,
            IsPortListening: false,
            _firewall.Inspect(LocalWebHost.Port).Status,
            null));
        try
        {
            await _host.StartAsync(endpoint, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception) when (IsHostStartPortConflict(exception))
        {
            if (!IsEvaluationCurrent(lifecycleVersion))
            {
                return await StopStaleEvaluationAsync(cancellationToken).ConfigureAwait(false);
            }

            _runningEndpoint = null;
            return Publish(new NetworkSharingState(
                NetworkSharingStatus.PortConflict,
                selected.Id,
                address,
                null,
                selected.Profile,
                LocalWebHost.Port,
                IsPortListening: false,
                _firewall.Inspect(LocalWebHost.Port).Status,
                exception.Message));
        }
        catch (LocalWebHostAuthorizationResetException)
        {
            if (!IsEvaluationCurrent(lifecycleVersion))
            {
                return await StopStaleEvaluationAsync(cancellationToken).ConfigureAwait(false);
            }

            _runningEndpoint = null;
            return Publish(AuthPersistenceFailedState(selected, address));
        }

        if (!IsEvaluationCurrent(lifecycleVersion))
        {
            _runningEndpoint = endpoint;
            return await StopStaleEvaluationAsync(cancellationToken).ConfigureAwait(false);
        }

        _runningEndpoint = endpoint;
        return Publish(RunningState(selected, address));
    }

    private bool IsEvaluationCurrent(long lifecycleVersion) =>
        !Volatile.Read(ref _shutdown) &&
        Volatile.Read(ref _lifecycleVersion) == lifecycleVersion;

    private async ValueTask<NetworkSharingState> StopStaleEvaluationAsync(
        CancellationToken cancellationToken)
    {
        await StopRunningHostAsync(cancellationToken).ConfigureAwait(false);
        return Volatile.Read(ref _shutdown)
            ? Publish(NetworkSharingState.Initial)
            : CurrentState;
    }

    private async ValueTask StopRunningHostAndInvalidateAsync(CancellationToken cancellationToken)
    {
        var hadRunningEndpoint = _runningEndpoint is not null;
        await StopRunningHostAsync(cancellationToken).ConfigureAwait(false);
        if (hadRunningEndpoint)
        {
            await _pairingCodeInvalidator.InvalidateActiveCodesAsync(cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async ValueTask StopRunningHostAsync(CancellationToken cancellationToken)
    {
        if (_runningEndpoint is null)
        {
            return;
        }

        _runningEndpoint = null;
        await _host.StopAsync(cancellationToken).ConfigureAwait(false);
    }

    private NetworkSharingState RunningState(
        NetworkInterfaceState selected,
        IPAddress address) =>
        new(
            NetworkSharingStatus.Running,
            selected.Id,
            address,
            BuildUrl(address),
            selected.Profile,
            LocalWebHost.Port,
            IsPortListening: true,
            _firewall.Inspect(LocalWebHost.Port).Status,
            null);

    private NetworkSharingState AuthPersistenceFailedState(
        NetworkInterfaceState selected,
        IPAddress address) =>
        new(
            NetworkSharingStatus.AuthorizationPersistenceFailed,
            selected.Id,
            address,
            null,
            selected.Profile,
            LocalWebHost.Port,
            IsPortListening: false,
            _firewall.Inspect(LocalWebHost.Port).Status,
            null);

    private static bool IsPublicProfileCandidate(NetworkInterfaceState item) =>
        NetworkInterfaceSelector.IsUsableLanInterface(item) &&
        item.Profile == NetworkProfile.Public &&
        item.Ipv4Addresses.Any(NetworkInterfaceSelector.IsPrivateIpv4);

    private static ImmutableArray<NetworkInterfaceSelectionOption> ToInterfaceOptions(
        ImmutableArray<NetworkInterfaceState> interfaces) =>
        interfaces
            .Select(item => new NetworkInterfaceSelectionOption(
                item.Id,
                item.Name,
                NetworkInterfaceSelector.FirstPrivateIpv4(item)))
            .ToImmutableArray();

    private static bool IsHostStartPortConflict(Exception exception) =>
        exception is IOException or SocketException ||
        exception is InvalidOperationException &&
        exception.Message.Contains("address", StringComparison.OrdinalIgnoreCase);

    private static string BuildUrl(IPAddress address) =>
        $"https://{address}:{LocalWebHost.Port}/";

    private NetworkSharingState Publish(NetworkSharingState state)
    {
        Volatile.Write(ref _currentState, state);
        return state;
    }
}
