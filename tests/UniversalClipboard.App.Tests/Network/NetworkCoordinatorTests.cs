using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using FluentAssertions;
using UniversalClipboard.App.Network;
using UniversalClipboard.Core.Authorization;

namespace UniversalClipboard.App.Tests.Network;

public sealed class NetworkCoordinatorTests
{
    [Fact]
    public async Task State_priority_is_shutdown_noeligible_public_selection_port_starting_running()
    {
        var fixture = new Fixture();

        (await fixture.Coordinator.ShutdownAsync()).Status.Should().Be(NetworkSharingStatus.Shutdown);

        fixture.Environment.Interfaces = [];
        (await fixture.Coordinator.StartAsync()).Status.Should().Be(NetworkSharingStatus.NoEligibleInterface);

        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5", profile: NetworkProfile.Public)];
        (await fixture.Coordinator.RefreshAsync()).Status.Should().Be(NetworkSharingStatus.PublicProfileBlocked);

        fixture.Environment.Interfaces =
        [
            Iface("eth", "10.0.0.5"),
            Iface("wifi", "192.168.1.5"),
        ];
        (await fixture.Coordinator.StartAsync()).Status.Should().Be(NetworkSharingStatus.SelectionRequired);

        await fixture.Coordinator.SetSelectedInterfaceAsync("wifi");
        fixture.Ports.Available = false;
        fixture.Ports.OwnerDiagnostic = "pid=42 name=other";
        var conflict = await fixture.Coordinator.RefreshAsync();
        conflict.Status.Should().Be(NetworkSharingStatus.PortConflict);
        conflict.PortDiagnostic.Should().Be("pid=42 name=other");

        fixture.Ports.Available = true;
        fixture.Host.BlockStart = true;
        var startingTask = fixture.Coordinator.RefreshAsync();
        await fixture.Host.StartEntered.WaitAsync(TimeSpan.FromSeconds(5));
        fixture.Coordinator.CurrentState.Status.Should().Be(NetworkSharingStatus.Starting);
        fixture.Host.ReleaseStart();

        (await startingTask).Status.Should().Be(NetworkSharingStatus.Running);
    }

    [Fact]
    public async Task Port_conflict_disables_sharing_without_alternate_port_and_reports_owner()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];
        fixture.Ports.Available = false;
        fixture.Ports.OwnerDiagnostic = "pid=123";

        var state = await fixture.Coordinator.StartAsync();

        state.Status.Should().Be(NetworkSharingStatus.PortConflict);
        state.Port.Should().Be(43127);
        state.PortDiagnostic.Should().Be("pid=123");
        fixture.Host.Starts.Should().BeEmpty();
    }

    [Fact]
    public async Task Selected_interface_loss_stops_host_and_invalidates_pairing_codes()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];
        (await fixture.Coordinator.StartAsync()).Status.Should().Be(NetworkSharingStatus.Running);

        fixture.Environment.Interfaces = [];
        var state = await fixture.Coordinator.RefreshAsync();

        state.Status.Should().Be(NetworkSharingStatus.NoEligibleInterface);
        fixture.Host.Events.Should().ContainInOrder("start:192.168.1.5:43127", "stop");
        fixture.Pairing.Invalidations.Should().Be(1);
    }

    [Fact]
    public async Task Dhcp_ipv4_change_stops_drains_revokes_all_removes_stale_bindings_then_binds_new_address()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];
        await fixture.Coordinator.StartAsync();

        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.9")];
        await fixture.Coordinator.RefreshAsync();

        fixture.Events.Should().ContainInOrder(
            "host:start:192.168.1.5:43127",
            "host:stop",
            "auth:revoke-all",
            "auth:remove-stale:192.168.1.9",
            "host:start:192.168.1.9:43127");
    }

    [Fact]
    public async Task Startup_removes_stale_bound_authorizations_before_bind()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];

        await fixture.Coordinator.StartAsync();

        fixture.Events.Should().ContainInOrder(
            "auth:remove-stale:192.168.1.5",
            "host:start:192.168.1.5:43127");
    }

    [Fact]
    public async Task Revoke_persistence_failure_pauses_sharing_before_new_address_start()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];
        await fixture.Coordinator.StartAsync();
        fixture.Authorization.FailRevokeAll = true;
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.9")];

        var state = await fixture.Coordinator.RefreshAsync();

        state.Status.Should().Be(NetworkSharingStatus.AuthorizationPersistenceFailed);
        fixture.Host.Starts.Should().NotContain(endpoint => endpoint.Address.Equals(IPAddress.Parse("192.168.1.9")));
    }

    [Fact]
    public async Task Refresh_events_are_serialized_and_coalesced()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];
        fixture.Environment.BlockSnapshot = true;

        var first = fixture.Coordinator.StartAsync();
        await fixture.Environment.SnapshotEntered.WaitAsync(TimeSpan.FromSeconds(5));
        var second = fixture.Coordinator.RefreshAsync();
        var third = fixture.Coordinator.RefreshAsync();
        fixture.Environment.ReleaseSnapshot();

        await Task.WhenAll(first, second, third);

        fixture.Environment.MaxConcurrentSnapshots.Should().Be(1);
        fixture.Host.Starts.Should().ContainSingle();
    }

    [Fact]
    public async Task Diagnostic_model_exposes_url_profile_listening_and_unknown_firewall_status()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];
        fixture.Firewall.Status = FirewallRuleStatus.Unknown;

        var state = await fixture.Coordinator.StartAsync();

        state.SelectedUrl.Should().Be("http://192.168.1.5:43127/");
        state.SelectedNetworkProfile.Should().Be(NetworkProfile.Private);
        state.IsPortListening.Should().BeTrue();
        state.FirewallRuleStatus.Should().Be(FirewallRuleStatus.Unknown);
    }

    [Fact]
    public void Firewall_query_reports_exact_rule_only_for_enabled_tcp_43127_allow_rule()
    {
        var rules = new FakeFirewallRuleQuery
        {
            Rules =
            [
                new FirewallRuleSnapshot(
                    "Universal Clipboard",
                    IsEnabled: true,
                    FirewallRuleAction.Allow,
                    FirewallRuleProtocol.Tcp,
                    LocalPort: 43127),
                new FirewallRuleSnapshot(
                    "Similar disabled",
                    IsEnabled: false,
                    FirewallRuleAction.Allow,
                    FirewallRuleProtocol.Tcp,
                    LocalPort: 43127),
            ],
        };

        var inspector = new WindowsFirewallInspector(rules);

        inspector.Inspect(43127).Status.Should().Be(FirewallRuleStatus.ExactRuleFound);
        inspector.Inspect(43128).Status.Should().Be(FirewallRuleStatus.Unknown);
    }

    private static NetworkInterfaceState Iface(
        string id,
        string address,
        NetworkProfile profile = NetworkProfile.Private) =>
        new(
            id,
            id,
            id == "eth" ? NetworkInterfaceKind.Ethernet : NetworkInterfaceKind.WiFi,
            NetworkOperationalStatus.Up,
            profile,
            [IPAddress.Parse(address)],
            HasDefaultGateway: true);

    private sealed class Fixture
    {
        public ConcurrentQueue<string> Events { get; } = new();

        public FakeNetworkEnvironment Environment { get; }

        public FakePortProbe Ports { get; } = new();

        public FakeFirewallInspector Firewall { get; } = new();

        public FakeHostController Host { get; }

        public FakePairingInvalidator Pairing { get; } = new();

        public FakeAuthorizationAdministration Authorization { get; }

        public NetworkCoordinator Coordinator { get; }

        public Fixture()
        {
            Environment = new FakeNetworkEnvironment();
            Host = new FakeHostController(Events);
            Authorization = new FakeAuthorizationAdministration(Events);
            Coordinator = new NetworkCoordinator(
                Environment,
                Ports,
                Firewall,
                Host,
                Pairing,
                Authorization);
        }
    }

    private sealed class FakeNetworkEnvironment : INetworkEnvironment
    {
        private int _activeSnapshots;
        private readonly TaskCompletionSource _snapshotEntered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseSnapshot =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public IReadOnlyList<NetworkInterfaceState> Interfaces { get; set; } = [];

        public bool BlockSnapshot { get; set; }

        public Task SnapshotEntered => _snapshotEntered.Task;

        public int MaxConcurrentSnapshots { get; private set; }

        public async ValueTask<IReadOnlyList<NetworkInterfaceState>> GetInterfacesAsync(
            CancellationToken cancellationToken = default)
        {
            var active = Interlocked.Increment(ref _activeSnapshots);
            MaxConcurrentSnapshots = Math.Max(MaxConcurrentSnapshots, active);
            try
            {
                if (BlockSnapshot)
                {
                    _snapshotEntered.TrySetResult();
                    await _releaseSnapshot.Task.WaitAsync(cancellationToken);
                    BlockSnapshot = false;
                }

                return Interfaces;
            }
            finally
            {
                Interlocked.Decrement(ref _activeSnapshots);
            }
        }

        public void ReleaseSnapshot() => _releaseSnapshot.TrySetResult();
    }

    private sealed class FakePortProbe : IPortProbe
    {
        public bool Available { get; set; } = true;

        public string? OwnerDiagnostic { get; set; }

        public PortProbeResult Check(IPAddress address, int port) =>
            Available
                ? PortProbeResult.Available
                : PortProbeResult.Conflict(OwnerDiagnostic ?? "unknown");
    }

    private sealed class FakeFirewallInspector : IFirewallInspector
    {
        public FirewallRuleStatus Status { get; set; } = FirewallRuleStatus.Unknown;

        public FirewallInspectionResult Inspect(int port) => new(Status);
    }

    private sealed class FakeFirewallRuleQuery : IFirewallRuleQuery
    {
        public IReadOnlyList<FirewallRuleSnapshot> Rules { get; set; } = [];

        public IReadOnlyList<FirewallRuleSnapshot> GetRules() => Rules;
    }

    private sealed class FakeHostController(ConcurrentQueue<string> events) : ILocalWebHostController
    {
        private readonly TaskCompletionSource _startEntered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseStart =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool BlockStart { get; set; }

        public Task StartEntered => _startEntered.Task;

        public List<IPEndPoint> Starts { get; } = [];

        public List<string> Events { get; } = [];

        public async ValueTask StartAsync(IPEndPoint endpoint, CancellationToken cancellationToken)
        {
            _startEntered.TrySetResult();
            if (BlockStart)
            {
                await _releaseStart.Task.WaitAsync(cancellationToken);
                BlockStart = false;
            }

            Starts.Add(endpoint);
            Events.Add($"start:{endpoint}");
            events.Enqueue($"host:start:{endpoint}");
        }

        public ValueTask StopAsync(CancellationToken cancellationToken)
        {
            Events.Add("stop");
            events.Enqueue("host:stop");
            return ValueTask.CompletedTask;
        }

        public void ReleaseStart() => _releaseStart.TrySetResult();
    }

    private sealed class FakePairingInvalidator : IPairingCodeInvalidator
    {
        public int Invalidations { get; private set; }

        public ValueTask InvalidateActiveCodesAsync(CancellationToken cancellationToken)
        {
            Invalidations++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class FakeAuthorizationAdministration(ConcurrentQueue<string> events)
        : IAuthorizationAdministration
    {
        public bool FailRevokeAll { get; set; }

        public ImmutableArray<AuthorizationMetadata> List() => [];

        public ValueTask<AuthorizationMutationResult> RevokeAsync(
            Guid authorizationId,
            CancellationToken cancellationToken = default) =>
            throw new NotImplementedException();

        public ValueTask<AuthorizationMutationResult> RevokeAllAsync(
            CancellationToken cancellationToken = default)
        {
            events.Enqueue("auth:revoke-all");
            return ValueTask.FromResult(
                NetworkTestAuthorizationResult.Create(!FailRevokeAll));
        }

        public ValueTask<AuthorizationMutationResult> RemoveStaleBindingsAsync(
            IReadOnlyCollection<IPAddress> activeHostIpv4Addresses,
            CancellationToken cancellationToken = default)
        {
            events.Enqueue(
                "auth:remove-stale:" + string.Join(",", activeHostIpv4Addresses));
            return ValueTask.FromResult(NetworkTestAuthorizationResult.Create(succeeded: true));
        }
    }

    private static class NetworkTestAuthorizationResult
    {
        public static AuthorizationMutationResult Create(bool succeeded)
        {
            var constructor = typeof(AuthorizationMutationResult).GetConstructors(
                System.Reflection.BindingFlags.Instance |
                System.Reflection.BindingFlags.NonPublic).Single();
            return (AuthorizationMutationResult)constructor.Invoke(
                [
                    succeeded ? AuthorizationFailure.None : AuthorizationFailure.PersistenceFailed,
                    new AuthorizationAdministrationSnapshot([]),
                ]);
        }
    }
}
