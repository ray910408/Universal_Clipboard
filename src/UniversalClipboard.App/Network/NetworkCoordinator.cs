using System.Net;
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

public sealed record PortProbeResult(bool IsAvailable, string? OwnerDiagnostic)
{
    public static PortProbeResult Available { get; } = new(true, null);

    public static PortProbeResult Conflict(string ownerDiagnostic) => new(false, ownerDiagnostic);
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

public sealed record FirewallRuleSnapshot(
    string Name,
    bool IsEnabled,
    FirewallRuleAction Action,
    FirewallRuleProtocol Protocol,
    int LocalPort);

public sealed record FirewallInspectionResult(FirewallRuleStatus Status);

public sealed class WindowsFirewallInspector(IFirewallRuleQuery ruleQuery) : IFirewallInspector
{
    public FirewallInspectionResult Inspect(int port)
    {
        var hasExactRule = ruleQuery.GetRules().Any(rule =>
            rule.IsEnabled &&
            rule.Action == FirewallRuleAction.Allow &&
            rule.Protocol == FirewallRuleProtocol.Tcp &&
            rule.LocalPort == port);
        return new FirewallInspectionResult(
            hasExactRule ? FirewallRuleStatus.ExactRuleFound : FirewallRuleStatus.Unknown);
    }
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
    string? PortDiagnostic)
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
        _shutdown = false;
        return RefreshAsync(cancellationToken);
    }

    public async Task<NetworkSharingState> ShutdownAsync(CancellationToken cancellationToken = default)
    {
        _shutdown = true;
        await StopRunningHostAsync(cancellationToken);
        var state = NetworkSharingState.Initial;
        Publish(state);
        return state;
    }

    public Task<NetworkSharingState> SetSelectedInterfaceAsync(
        string interfaceId,
        CancellationToken cancellationToken = default)
    {
        _selectedInterfaceId = interfaceId;
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
            if (_shutdown)
            {
                await StopRunningHostAsync(cancellationToken);
                state = NetworkSharingState.Initial;
                Publish(state);
            }
            else
            {
                state = await EvaluateAsync(cancellationToken);
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
        var interfaces = await _environment.GetInterfacesAsync(cancellationToken);
        if (interfaces.Any(IsPublicProfileCandidate))
        {
            await StopRunningHostAndInvalidateAsync(cancellationToken);
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
            await StopRunningHostAndInvalidateAsync(cancellationToken);
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
            await StopRunningHostAndInvalidateAsync(cancellationToken);
            return Publish(new NetworkSharingState(
                NetworkSharingStatus.SelectionRequired,
                null,
                null,
                null,
                null,
                LocalWebHost.Port,
                IsPortListening: false,
                _firewall.Inspect(LocalWebHost.Port).Status,
                null));
        }

        var selected = selection.Selected!;
        var address = selection.SelectedAddress!;
        var endpoint = new IPEndPoint(address, LocalWebHost.Port);
        var probe = _portProbe.Check(address, LocalWebHost.Port);
        if (!probe.IsAvailable)
        {
            await StopRunningHostAsync(cancellationToken);
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

        if (_runningEndpoint is not null && _runningEndpoint.Equals(endpoint))
        {
            return Publish(RunningState(selected, address));
        }

        var hadRunningEndpoint = _runningEndpoint is not null;
        if (hadRunningEndpoint)
        {
            await StopRunningHostAsync(cancellationToken);
            var revoke = await _authorization.RevokeAllAsync(cancellationToken);
            if (!revoke.Succeeded)
            {
                return Publish(AuthPersistenceFailedState(selected, address));
            }
        }

        var staleRemoval = await _authorization.RemoveStaleBindingsAsync(
            [address],
            cancellationToken);
        if (!staleRemoval.Succeeded)
        {
            return Publish(AuthPersistenceFailedState(selected, address));
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
        await _host.StartAsync(endpoint, cancellationToken);
        _runningEndpoint = endpoint;
        return Publish(RunningState(selected, address));
    }

    private async ValueTask StopRunningHostAndInvalidateAsync(CancellationToken cancellationToken)
    {
        var hadRunningEndpoint = _runningEndpoint is not null;
        await StopRunningHostAsync(cancellationToken);
        if (hadRunningEndpoint)
        {
            await _pairingCodeInvalidator.InvalidateActiveCodesAsync(cancellationToken);
        }
    }

    private async ValueTask StopRunningHostAsync(CancellationToken cancellationToken)
    {
        if (_runningEndpoint is null)
        {
            return;
        }

        _runningEndpoint = null;
        await _host.StopAsync(cancellationToken);
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

    private static string BuildUrl(IPAddress address) =>
        $"http://{address}:{LocalWebHost.Port}/";

    private NetworkSharingState Publish(NetworkSharingState state)
    {
        Volatile.Write(ref _currentState, state);
        return state;
    }
}
