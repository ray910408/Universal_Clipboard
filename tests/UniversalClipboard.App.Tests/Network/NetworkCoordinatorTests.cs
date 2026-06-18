using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using FluentAssertions;
using UniversalClipboard.App.Network;
using UniversalClipboard.App.Web;
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
        var selectionRequired = await fixture.Coordinator.StartAsync();
        selectionRequired.Status.Should().Be(NetworkSharingStatus.SelectionRequired);
        selectionRequired.InterfaceOptions.Select(item => item.InterfaceId)
            .Should().Equal("eth", "wifi");

        fixture.Ports.Available = false;
        fixture.Ports.OwnerDiagnostic = "pid=42 name=other";
        var conflict = await fixture.Coordinator.SetSelectedInterfaceAsync("wifi");
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
    public async Task Running_same_endpoint_refresh_keeps_running_without_port_probe_or_restart()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];
        (await fixture.Coordinator.StartAsync()).Status.Should().Be(NetworkSharingStatus.Running);
        fixture.Ports.Available = false;
        fixture.Ports.OwnerDiagnostic = "self-listener";

        var state = await fixture.Coordinator.RefreshAsync();

        state.Status.Should().Be(NetworkSharingStatus.Running);
        state.SelectedAddress.Should().Be(IPAddress.Parse("192.168.1.5"));
        fixture.Ports.Checks.Should().ContainSingle();
        fixture.Host.Starts.Should().ContainSingle();
        fixture.Host.Events.Should().NotContain("stop");
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
    public async Task Startup_does_not_capture_non_pumping_synchronization_context()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];
        fixture.Authorization.CompleteRemoveStaleAsynchronously = true;
        var nonPumpingContext = new NonPumpingSynchronizationContext();
        var originalContext = SynchronizationContext.Current;
        Task<NetworkSharingState> start;

        SynchronizationContext.SetSynchronizationContext(nonPumpingContext);
        try
        {
            start = fixture.Coordinator.StartAsync();
        }
        finally
        {
            SynchronizationContext.SetSynchronizationContext(originalContext);
        }

        var state = await start.WaitAsync(TimeSpan.FromSeconds(5));

        state.Status.Should().Be(NetworkSharingStatus.Running);
        fixture.Host.Starts.Should().ContainSingle(
            endpoint => endpoint.Address.Equals(IPAddress.Parse("192.168.1.5")) &&
                        endpoint.Port == 43127);
        nonPumpingContext.Posts.Should().Be(0);
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
    public async Task Shutdown_during_host_start_keeps_final_state_shutdown_and_stops_late_start()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];
        fixture.Host.BlockStart = true;

        var start = fixture.Coordinator.StartAsync();
        await fixture.Host.StartEntered.WaitAsync(TimeSpan.FromSeconds(5));
        var shutdown = await fixture.Coordinator.ShutdownAsync();
        fixture.Host.ReleaseStart();
        var startResult = await start;

        shutdown.Status.Should().Be(NetworkSharingStatus.Shutdown);
        startResult.Status.Should().Be(NetworkSharingStatus.Shutdown);
        fixture.Coordinator.CurrentState.Status.Should().Be(NetworkSharingStatus.Shutdown);
        fixture.Host.Events.Should().Contain("stop");
    }

    [Fact]
    public async Task Host_bind_failure_after_successful_probe_reports_port_conflict()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];
        fixture.Host.StartException = new IOException("address already in use");

        var state = await fixture.Coordinator.StartAsync();

        state.Status.Should().Be(NetworkSharingStatus.PortConflict);
        state.PortDiagnostic.Should().Contain("address already in use");
        fixture.Coordinator.CurrentState.Status.Should().Be(NetworkSharingStatus.PortConflict);
        fixture.Host.Starts.Should().BeEmpty();
    }

    [Fact]
    public async Task Host_authorization_reset_failure_reports_persistence_failed()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];
        fixture.Host.StartException = new LocalWebHostAuthorizationResetException(
            AuthorizationFailure.PersistenceFailed);

        var state = await fixture.Coordinator.StartAsync();

        state.Status.Should().Be(NetworkSharingStatus.AuthorizationPersistenceFailed);
        fixture.Host.Starts.Should().BeEmpty();
    }

    [Fact]
    public async Task Diagnostic_model_exposes_url_profile_listening_and_unknown_firewall_status()
    {
        var fixture = new Fixture();
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];
        fixture.Firewall.Status = FirewallRuleStatus.Unknown;

        var state = await fixture.Coordinator.StartAsync();

        state.SelectedUrl.Should().Be("https://192.168.1.5:43127/");
        state.SelectedNetworkProfile.Should().Be(NetworkProfile.Private);
        state.IsPortListening.Should().BeTrue();
        state.FirewallRuleStatus.Should().Be(FirewallRuleStatus.Unknown);
    }

    [Fact]
    public void Firewall_query_reports_exact_rule_only_for_expected_private_local_subnet_rule()
    {
        var rules = new FakeFirewallRuleQuery
        {
            Rules =
            [
                new FirewallRuleSnapshot(
                    WindowsFirewallInspector.ExpectedRuleName,
                    WindowsFirewallInspector.ExpectedRuleName,
                    IsEnabled: true,
                    FirewallRuleAction.Allow,
                    FirewallRuleProtocol.Tcp,
                    LocalPort: 43127,
                    FirewallRuleProfile.Private,
                    FirewallRemoteAddressScope.LocalSubnet),
                new FirewallRuleSnapshot(
                    "Similar disabled",
                    "Similar disabled",
                    IsEnabled: false,
                    FirewallRuleAction.Allow,
                    FirewallRuleProtocol.Tcp,
                    LocalPort: 43127,
                    FirewallRuleProfile.Private,
                    FirewallRemoteAddressScope.LocalSubnet),
            ],
        };

        var inspector = new WindowsFirewallInspector(rules);

        inspector.Inspect(43127).Status.Should().Be(FirewallRuleStatus.ExactRuleFound);
        inspector.Inspect(43128).Status.Should().Be(FirewallRuleStatus.Unknown);
    }

    [Fact]
    public void Firewall_query_reflection_failure_reports_unknown()
    {
        var inspector = new WindowsFirewallInspector(
            new ThrowingFirewallRuleQuery(
                new TargetInvocationException(
                    new ArgumentException("firewall reflection failed"))));

        inspector.Inspect(43127).Status.Should().Be(FirewallRuleStatus.Unknown);
    }

    [Fact]
    public async Task Startup_reaches_running_when_firewall_rule_query_does_not_return()
    {
        var query = new BlockingFirewallRuleQuery();
        var fixture = new Fixture(
            new WindowsFirewallInspector(query, TimeSpan.FromMilliseconds(10)));
        fixture.Environment.Interfaces = [Iface("wifi", "192.168.1.5")];

        try
        {
            var start = fixture.Coordinator.StartAsync();
            await query.Entered.WaitAsync(TimeSpan.FromSeconds(5));
            var state = await start.WaitAsync(TimeSpan.FromSeconds(5));

            state.Status.Should().Be(NetworkSharingStatus.Running);
            state.FirewallRuleStatus.Should().Be(FirewallRuleStatus.Unknown);
            fixture.Host.Starts.Should().ContainSingle(
                endpoint => endpoint.Address.Equals(IPAddress.Parse("192.168.1.5")) &&
                            endpoint.Port == 43127);
            query.Invocations.Should().Be(1);
        }
        finally
        {
            query.Release();
        }
    }

    [Theory]
    [InlineData("unsafe-public", true, FirewallRuleAction.Allow, FirewallRuleProtocol.Tcp, 43127, FirewallRuleProfile.Public, FirewallRemoteAddressScope.LocalSubnet)]
    [InlineData("unsafe-any-remote", true, FirewallRuleAction.Allow, FirewallRuleProtocol.Tcp, 43127, FirewallRuleProfile.Private, FirewallRemoteAddressScope.Any)]
    [InlineData("wrong-name", true, FirewallRuleAction.Allow, FirewallRuleProtocol.Tcp, 43127, FirewallRuleProfile.Private, FirewallRemoteAddressScope.LocalSubnet)]
    [InlineData("disabled", false, FirewallRuleAction.Allow, FirewallRuleProtocol.Tcp, 43127, FirewallRuleProfile.Private, FirewallRemoteAddressScope.LocalSubnet)]
    [InlineData("wrong-action", true, FirewallRuleAction.Block, FirewallRuleProtocol.Tcp, 43127, FirewallRuleProfile.Private, FirewallRemoteAddressScope.LocalSubnet)]
    [InlineData("wrong-protocol", true, FirewallRuleAction.Allow, FirewallRuleProtocol.Udp, 43127, FirewallRuleProfile.Private, FirewallRemoteAddressScope.LocalSubnet)]
    [InlineData("wrong-port", true, FirewallRuleAction.Allow, FirewallRuleProtocol.Tcp, 43128, FirewallRuleProfile.Private, FirewallRemoteAddressScope.LocalSubnet)]
    public void Firewall_query_reports_unknown_for_non_exact_mobile_rule(
        string name,
        bool isEnabled,
        FirewallRuleAction action,
        FirewallRuleProtocol protocol,
        int port,
        FirewallRuleProfile profile,
        FirewallRemoteAddressScope remoteScope)
    {
        var rules = new FakeFirewallRuleQuery
        {
            Rules =
            [
                new FirewallRuleSnapshot(
                    name,
                    name,
                    isEnabled,
                    action,
                    protocol,
                    port,
                    profile,
                    remoteScope),
            ],
        };

        var inspector = new WindowsFirewallInspector(rules);

        inspector.Inspect(43127).Status.Should().Be(FirewallRuleStatus.Unknown);
    }

    [Fact]
    public void Firewall_rule_manager_creates_private_local_subnet_rule_when_missing()
    {
        var query = new FakeFirewallRuleQuery();
        var editor = new FakeFirewallRuleEditor();
        var manager = new WindowsFirewallRuleManager(query, editor);

        manager.EnsureRule(43127);

        editor.RemovedRuleNames.Should().BeEmpty();
        editor.AddedRules.Should().ContainSingle().Which.Should().Be(ExpectedFirewallDefinition());
    }

    [Fact]
    public void Firewall_rule_manager_reports_ready_only_for_single_exact_rule()
    {
        new WindowsFirewallRuleManager(
                new FakeFirewallRuleQuery { Rules = [ExpectedFirewallSnapshot()] },
                new FakeFirewallRuleEditor())
            .IsRuleReady(43127)
            .Should()
            .BeTrue();

        new WindowsFirewallRuleManager(
                new FakeFirewallRuleQuery
                {
                    Rules = [ExpectedFirewallSnapshot() with { DisplayName = "wrong-display" }],
                },
                new FakeFirewallRuleEditor())
            .IsRuleReady(43127)
            .Should()
            .BeFalse();

        new WindowsFirewallRuleManager(
                new FakeFirewallRuleQuery
                {
                    Rules = [ExpectedFirewallSnapshot() with { RemoteAddressScope = FirewallRemoteAddressScope.Any }],
                },
                new FakeFirewallRuleEditor())
            .IsRuleReady(43127)
            .Should()
            .BeFalse();

        new WindowsFirewallRuleManager(
                new FakeFirewallRuleQuery
                {
                    Rules =
                    [
                        ExpectedFirewallSnapshot(),
                        ExpectedFirewallSnapshot(),
                    ],
                },
                new FakeFirewallRuleEditor())
            .IsRuleReady(43127)
            .Should()
            .BeFalse();
    }

    [Fact]
    public void Firewall_rule_manager_reuses_exact_rule_without_writes()
    {
        var query = new FakeFirewallRuleQuery
        {
            Rules = [ExpectedFirewallSnapshot()],
        };
        var editor = new FakeFirewallRuleEditor();
        var manager = new WindowsFirewallRuleManager(query, editor);

        manager.EnsureRule(43127);

        editor.RemovedRuleNames.Should().BeEmpty();
        editor.AddedRules.Should().BeEmpty();
    }

    [Fact]
    public void Firewall_rule_manager_replaces_same_name_non_exact_rule()
    {
        var query = new FakeFirewallRuleQuery
        {
            Rules =
            [
                ExpectedFirewallSnapshot() with
                {
                    Profile = FirewallRuleProfile.Public,
                },
            ],
        };
        var editor = new FakeFirewallRuleEditor();
        var manager = new WindowsFirewallRuleManager(query, editor);

        manager.EnsureRule(43127);

        editor.RemovedRuleNames.Should().Equal(WindowsFirewallInspector.ExpectedRuleName);
        editor.AddedRules.Should().ContainSingle().Which.Should().Be(ExpectedFirewallDefinition());
    }

    [Fact]
    public void Firewall_rule_manager_replaces_duplicate_same_name_rules_even_when_one_is_exact()
    {
        var query = new FakeFirewallRuleQuery
        {
            Rules =
            [
                ExpectedFirewallSnapshot(),
                ExpectedFirewallSnapshot() with
                {
                    RemoteAddressScope = FirewallRemoteAddressScope.Any,
                },
            ],
        };
        var editor = new FakeFirewallRuleEditor();
        var manager = new WindowsFirewallRuleManager(query, editor);

        manager.EnsureRule(43127);

        editor.RemovedRuleNames.Should().Equal(
            WindowsFirewallInspector.ExpectedRuleName,
            WindowsFirewallInspector.ExpectedRuleName);
        editor.AddedRules.Should().ContainSingle().Which.Should().Be(ExpectedFirewallDefinition());
    }

    [Fact]
    public void Firewall_rule_manager_remove_deletes_all_rules_with_expected_name()
    {
        var query = new FakeFirewallRuleQuery
        {
            Rules =
            [
                ExpectedFirewallSnapshot(),
                ExpectedFirewallSnapshot() with { LocalPort = 43128 },
                ExpectedFirewallSnapshot() with
                {
                    Name = "GeneratedInternalName",
                    DisplayName = WindowsFirewallInspector.ExpectedRuleName,
                },
                new FirewallRuleSnapshot(
                    "Other",
                    "Other",
                    IsEnabled: true,
                    FirewallRuleAction.Allow,
                    FirewallRuleProtocol.Tcp,
                    LocalPort: 43127,
                    FirewallRuleProfile.Private,
                    FirewallRemoteAddressScope.LocalSubnet),
            ],
        };
        var editor = new FakeFirewallRuleEditor();
        var manager = new WindowsFirewallRuleManager(query, editor);

        manager.RemoveRule();

        editor.RemovedRuleNames.Should().Equal(
            WindowsFirewallInspector.ExpectedRuleName,
            WindowsFirewallInspector.ExpectedRuleName,
            "GeneratedInternalName");
        editor.AddedRules.Should().BeEmpty();
    }

    [Fact]
    public void Firewall_rule_manager_replaces_single_com_rule_with_multiple_ports_with_one_remove()
    {
        var query = new WindowsFirewallComRuleQuery(
            new FakeComFirewallRules(
                [
                    new ComFirewallRuleSnapshot(
                        WindowsFirewallInspector.ExpectedRuleName,
                        WindowsFirewallInspector.ExpectedRuleName,
                        Enabled: true,
                        Action: WindowsFirewallComRuleQuery.AllowAction,
                        Protocol: WindowsFirewallComRuleQuery.TcpProtocol,
                        LocalPorts: "43127,43128",
                        Profiles: WindowsFirewallComRuleQuery.PrivateProfile,
                        RemoteAddresses: "LocalSubnet"),
                ]));
        var editor = new FakeFirewallRuleEditor();
        var manager = new WindowsFirewallRuleManager(query, editor);

        manager.EnsureRule(43127);

        editor.RemovedRuleNames.Should().Equal(WindowsFirewallInspector.ExpectedRuleName);
        editor.AddedRules.Should().ContainSingle().Which.Should().Be(ExpectedFirewallDefinition());
    }

    [Fact]
    public void Com_firewall_rule_editor_writes_private_local_subnet_rule_and_releases_com_objects()
    {
        var bridge = new FakeWindowsFirewallComBridge([]);
        var editor = new WindowsFirewallComRuleEditor(bridge);

        editor.AddRule(ExpectedFirewallDefinition());

        var rule = bridge.AddedRules.Should().ContainSingle().Subject;
        rule.Properties.Should().Contain(new KeyValuePair<string, object>(
            "Name",
            WindowsFirewallInspector.ExpectedRuleName));
        rule.Properties.Should().Contain(new KeyValuePair<string, object>(
            "DisplayName",
            WindowsFirewallInspector.ExpectedRuleName));
        rule.Properties.Should().Contain(new KeyValuePair<string, object>("Enabled", true));
        rule.Properties.Should().Contain(new KeyValuePair<string, object>(
            "Direction",
            WindowsFirewallComRuleQuery.InboundDirection));
        rule.Properties.Should().Contain(new KeyValuePair<string, object>(
            "Action",
            WindowsFirewallComRuleQuery.AllowAction));
        rule.Properties.Should().Contain(new KeyValuePair<string, object>(
            "Protocol",
            WindowsFirewallComRuleQuery.TcpProtocol));
        rule.Properties.Should().Contain(new KeyValuePair<string, object>("LocalPorts", "43127"));
        rule.Properties.Should().Contain(new KeyValuePair<string, object>(
            "Profiles",
            WindowsFirewallComRuleQuery.PrivateProfile));
        rule.Properties.Should().Contain(new KeyValuePair<string, object>("RemoteAddresses", "LocalSubnet"));
        bridge.Released.Should().Equal(
            rule,
            bridge.RuleCollection,
            bridge.Policy);
    }

    [Fact]
    public void Com_firewall_rule_editor_removes_rule_by_expected_name_and_releases_com_objects()
    {
        var bridge = new FakeWindowsFirewallComBridge([]);
        var editor = new WindowsFirewallComRuleEditor(bridge);

        editor.RemoveRule(WindowsFirewallInspector.ExpectedRuleName);

        bridge.RemovedRuleNames.Should().Equal(WindowsFirewallInspector.ExpectedRuleName);
        bridge.Released.Should().Equal(bridge.RuleCollection, bridge.Policy);
    }

    [Fact]
    public void Network_interface_mapper_uses_injected_profile_strategy_and_requires_gateway_private_ipv4()
    {
        var mapper = new WindowsNetworkInterfaceMapper(
            adapter => adapter.Id == "wifi"
                ? NetworkProfile.Private
                : NetworkProfile.Public);

        var mapped = mapper.Map(
            new NetworkAdapterSnapshot(
                "wifi",
                "Wi-Fi",
                NetworkInterfaceKind.WiFi,
                NetworkOperationalStatus.Up,
                [IPAddress.Parse("192.168.1.10")],
                HasDefaultGateway: true));

        mapped.Profile.Should().Be(NetworkProfile.Private);
        NetworkInterfaceSelector.Select([mapped], retainedExplicitInterfaceId: null)
            .Status.Should().Be(NetworkSelectionStatus.AutoSelected);
    }

    [Fact]
    public void Tcp_port_probe_reports_listener_diagnostic_when_port_is_occupied()
    {
        var probe = new TcpPortProbe(
            new FakeTcpPortInspector
            {
                Listeners =
                [
                    new TcpPortOwnerSnapshot(IPAddress.Parse("192.168.1.5"), 43127, "pid unavailable"),
                ],
            });

        var result = probe.Check(IPAddress.Parse("192.168.1.5"), 43127);

        result.IsAvailable.Should().BeFalse();
        result.OwnerDiagnostic.Should().Contain("192.168.1.5:43127");
        result.OwnerDiagnostic.Should().Contain("pid unavailable");
    }

    [Fact]
    public void Com_firewall_rule_query_maps_expected_rule_fields_without_shelling_out()
    {
        var query = new WindowsFirewallComRuleQuery(
            new FakeComFirewallRules(
                [
                    new ComFirewallRuleSnapshot(
                        WindowsFirewallInspector.ExpectedRuleName,
                        WindowsFirewallInspector.ExpectedRuleName,
                        Enabled: true,
                        Action: 1,
                        Protocol: 6,
                        LocalPorts: "43127",
                        Profiles: WindowsFirewallComRuleQuery.PrivateProfile,
                        RemoteAddresses: "LocalSubnet"),
                ]));

        var rule = query.GetRules().Single();

        rule.Should().Be(new FirewallRuleSnapshot(
            WindowsFirewallInspector.ExpectedRuleName,
            WindowsFirewallInspector.ExpectedRuleName,
            IsEnabled: true,
            FirewallRuleAction.Allow,
            FirewallRuleProtocol.Tcp,
            LocalPort: 43127,
            FirewallRuleProfile.Private,
            FirewallRemoteAddressScope.LocalSubnet));
    }

    [Theory]
    [InlineData(WindowsFirewallComRuleQuery.PrivateProfile | WindowsFirewallComRuleQuery.PublicProfile)]
    [InlineData(WindowsFirewallComRuleQuery.AllProfiles)]
    public void Com_firewall_rule_query_does_not_treat_mixed_profile_masks_as_private(
        int profileMask)
    {
        var inspector = new WindowsFirewallInspector(
            new WindowsFirewallComRuleQuery(
                new FakeComFirewallRules(
                    [
                        new ComFirewallRuleSnapshot(
                            WindowsFirewallInspector.ExpectedRuleName,
                            WindowsFirewallInspector.ExpectedRuleName,
                            Enabled: true,
                            Action: 1,
                            Protocol: 6,
                            LocalPorts: "43127",
                            Profiles: profileMask,
                            RemoteAddresses: "LocalSubnet"),
                    ])));

        inspector.Inspect(43127).Status.Should().Be(FirewallRuleStatus.Unknown);
    }

    [Fact]
    public void Windows_firewall_com_rules_skip_bad_rules_and_release_all_com_objects()
    {
        var goodRule = new FakeRawComFirewallRule(
            WindowsFirewallInspector.ExpectedRuleName,
            WindowsFirewallInspector.ExpectedRuleName,
            Enabled: true,
            Action: 1,
            Protocol: 6,
            LocalPorts: "43127",
            Profiles: WindowsFirewallComRuleQuery.PrivateProfile,
            RemoteAddresses: "LocalSubnet");
        var badRule = new FakeRawComFirewallRule(
            "bad",
            "bad",
            Enabled: true,
            Action: 1,
            Protocol: 6,
            LocalPorts: "43127",
            Profiles: WindowsFirewallComRuleQuery.PrivateProfile,
            RemoteAddresses: "LocalSubnet")
        {
            ThrowOnPropertyRead = true,
        };
        var bridge = new FakeWindowsFirewallComBridge([goodRule, badRule]);

        var rules = new WindowsFirewallComRules(bridge).GetRules();

        rules.Should().ContainSingle(rule => rule.Name == WindowsFirewallInspector.ExpectedRuleName);
        bridge.Released.Should().Equal(
            goodRule,
            badRule,
            bridge.RuleCollection,
            bridge.Policy);
    }

    [Fact]
    public void Windows_network_environment_has_default_production_profile_resolver()
    {
        typeof(WindowsNetworkEnvironment)
            .GetConstructor(Type.EmptyTypes)
            .Should()
            .NotBeNull();

        var environment = new WindowsNetworkEnvironment();

        environment.Should().NotBeNull();
    }

    [Fact]
    public void Windows_network_profile_resolver_returns_unknown_when_adapter_mapping_is_missing()
    {
        var resolver = new WindowsNetworkProfileResolver(
            new FakeComNetworkList(
                [
                    new ComNetworkConnectionSnapshot(
                        AdapterId: "other-adapter",
                        Category: WindowsNetworkProfileResolver.PrivateCategory),
                ]));

        var profile = resolver.Resolve(
            new NetworkAdapterSnapshot(
                "wifi-adapter",
                "Wi-Fi",
                NetworkInterfaceKind.WiFi,
                NetworkOperationalStatus.Up,
                [IPAddress.Parse("192.168.1.10")],
                HasDefaultGateway: true));

        profile.Should().Be(NetworkProfile.Unknown);
    }

    [Fact]
    public void Windows_network_list_manager_skips_bad_connections_without_losing_good_profiles()
    {
        var goodConnection = new FakeRawNetworkConnection(
            "wifi-adapter",
            WindowsNetworkProfileResolver.PrivateCategory);
        var badConnection = new FakeRawNetworkConnection(
            "bad-adapter",
            WindowsNetworkProfileResolver.PublicCategory)
        {
            AdapterIdException = new TargetInvocationException(
                new ArgumentException("bad connection")),
        };
        var bridge = new FakeWindowsNetworkListComBridge([badConnection, goodConnection]);
        var resolver = new WindowsNetworkProfileResolver(new WindowsNetworkListManager(bridge));

        var profile = resolver.Resolve(
            new NetworkAdapterSnapshot(
                "wifi-adapter",
                "Wi-Fi",
                NetworkInterfaceKind.WiFi,
                NetworkOperationalStatus.Up,
                [IPAddress.Parse("192.168.8.216")],
                HasDefaultGateway: true));

        profile.Should().Be(NetworkProfile.Private);
        bridge.Released.Should().Contain(badConnection);
        bridge.Released.Should().Contain(goodConnection.Network);
        bridge.Released.Should().Contain(goodConnection);
        bridge.Released.Should().Contain(bridge.ConnectionCollection);
        bridge.Released.Should().Contain(bridge.Manager);
    }

    [Fact]
    public void Windows_network_list_manager_returns_empty_when_connection_enumeration_reflection_fails()
    {
        var bridge = new FakeWindowsNetworkListComBridge([])
        {
            GetConnectionsException = new TargetInvocationException(
                new ArgumentException("network list unavailable")),
        };

        var connections = new WindowsNetworkListManager(bridge).GetConnections();

        connections.Should().BeEmpty();
        bridge.Released.Should().Contain(bridge.Manager);
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

    private static FirewallRuleDefinition ExpectedFirewallDefinition() =>
        new(
            WindowsFirewallInspector.ExpectedRuleName,
            WindowsFirewallInspector.ExpectedRuleName,
            IsEnabled: true,
            FirewallRuleAction.Allow,
            FirewallRuleProtocol.Tcp,
            LocalPort: 43127,
            FirewallRuleProfile.Private,
            FirewallRemoteAddressScope.LocalSubnet);

    private static FirewallRuleSnapshot ExpectedFirewallSnapshot() =>
        new(
            WindowsFirewallInspector.ExpectedRuleName,
            WindowsFirewallInspector.ExpectedRuleName,
            IsEnabled: true,
            FirewallRuleAction.Allow,
            FirewallRuleProtocol.Tcp,
            LocalPort: 43127,
            FirewallRuleProfile.Private,
            FirewallRemoteAddressScope.LocalSubnet);

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

        public Fixture(IFirewallInspector? firewall = null)
        {
            Environment = new FakeNetworkEnvironment();
            Host = new FakeHostController(Events);
            Authorization = new FakeAuthorizationAdministration(Events);
            Coordinator = new NetworkCoordinator(
                Environment,
                Ports,
                firewall ?? Firewall,
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

        public List<IPEndPoint> Checks { get; } = [];

        public PortProbeResult Check(IPAddress address, int port)
        {
            Checks.Add(new IPEndPoint(address, port));
            return Available
                ? PortProbeResult.Available
                : PortProbeResult.Conflict(OwnerDiagnostic ?? "unknown");
        }
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

    private sealed class FakeFirewallRuleEditor : IFirewallRuleEditor
    {
        public List<FirewallRuleDefinition> AddedRules { get; } = [];

        public List<string> RemovedRuleNames { get; } = [];

        public void AddRule(FirewallRuleDefinition definition) => AddedRules.Add(definition);

        public void RemoveRule(string name) => RemovedRuleNames.Add(name);
    }

    private sealed class ThrowingFirewallRuleQuery(Exception exception) : IFirewallRuleQuery
    {
        public IReadOnlyList<FirewallRuleSnapshot> GetRules() => throw exception;
    }

    private sealed class BlockingFirewallRuleQuery : IFirewallRuleQuery
    {
        private readonly ManualResetEventSlim _release = new();
        private readonly TaskCompletionSource _entered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private int _invocations;

        public Task Entered => _entered.Task;

        public int Invocations => Volatile.Read(ref _invocations);

        public IReadOnlyList<FirewallRuleSnapshot> GetRules()
        {
            Interlocked.Increment(ref _invocations);
            _entered.TrySetResult();
            _release.Wait();
            return [];
        }

        public void Release() => _release.Set();
    }

    private sealed class NonPumpingSynchronizationContext : SynchronizationContext
    {
        private int _posts;

        public int Posts => Volatile.Read(ref _posts);

        public override void Post(SendOrPostCallback d, object? state) =>
            Interlocked.Increment(ref _posts);
    }

    private sealed class FakeTcpPortInspector : ITcpPortInspector
    {
        public IReadOnlyList<TcpPortOwnerSnapshot> Listeners { get; set; } = [];

        public IReadOnlyList<TcpPortOwnerSnapshot> GetActiveListeners() => Listeners;
    }

    private sealed class FakeComFirewallRules(
        IReadOnlyList<ComFirewallRuleSnapshot> rules) : IComFirewallRules
    {
        public IReadOnlyList<ComFirewallRuleSnapshot> GetRules() => rules;
    }

    private sealed class FakeWindowsFirewallComBridge : IWindowsFirewallComBridge
    {
        public FakeWindowsFirewallComBridge(IReadOnlyList<FakeRawComFirewallRule> rules)
        {
            RuleCollection = new FakeRawComFirewallRuleCollection(rules);
        }

        public object Policy { get; } = new();

        public FakeRawComFirewallRuleCollection RuleCollection { get; }

        public List<object> Released { get; } = [];

        public List<FakeCreatedFirewallRule> AddedRules { get; } = [];

        public List<string> RemovedRuleNames { get; } = [];

        public object? CreatePolicy() => Policy;

        public object? CreateRule() => new FakeCreatedFirewallRule();

        public object? GetRules(object policy) => RuleCollection;

        public object? GetProperty(object target, string name)
        {
            var rule = (FakeRawComFirewallRule)target;
            if (rule.ThrowOnPropertyRead)
            {
                throw new COMException("bad rule");
            }

            return name switch
            {
                "Name" => rule.Name,
                "DisplayName" => rule.DisplayName,
                "Enabled" => rule.Enabled,
                "Action" => rule.Action,
                "Protocol" => rule.Protocol,
                "LocalPorts" => rule.LocalPorts,
                "Profiles" => rule.Profiles,
                "RemoteAddresses" => rule.RemoteAddresses,
                _ => throw new ArgumentException("unknown property", nameof(name)),
            };
        }

        public void SetProperty(object target, string name, object value) =>
            ((FakeCreatedFirewallRule)target).Properties[name] = value;

        public void AddRule(object rules, object rule) =>
            AddedRules.Add((FakeCreatedFirewallRule)rule);

        public void RemoveRule(object rules, string name) => RemovedRuleNames.Add(name);

        public bool IsComObject(object target) => true;

        public void Release(object target) => Released.Add(target);
    }

    private sealed class FakeRawComFirewallRuleCollection(
        IReadOnlyList<FakeRawComFirewallRule> rules) : System.Collections.IEnumerable
    {
        public System.Collections.IEnumerator GetEnumerator() => rules.GetEnumerator();
    }

    private sealed record FakeRawComFirewallRule(
        string Name,
        string DisplayName,
        bool Enabled,
        int Action,
        int Protocol,
        string LocalPorts,
        int Profiles,
        string RemoteAddresses)
    {
        public bool ThrowOnPropertyRead { get; init; }
    }

    private sealed class FakeCreatedFirewallRule
    {
        public Dictionary<string, object> Properties { get; } = [];
    }

    private sealed class FakeComNetworkList(
        IReadOnlyList<ComNetworkConnectionSnapshot> connections) : IComNetworkList
    {
        public IReadOnlyList<ComNetworkConnectionSnapshot> GetConnections() => connections;
    }

    private sealed class FakeWindowsNetworkListComBridge(
        IReadOnlyList<FakeRawNetworkConnection> connections) : IWindowsNetworkListComBridge
    {
        public object Manager { get; } = new();

        public FakeRawNetworkConnectionCollection ConnectionCollection { get; } = new(connections);

        public List<object> Released { get; } = [];

        public Exception? GetConnectionsException { get; init; }

        public object? CreateManager(Guid clsid) => Manager;

        public object? GetNetworkConnections(object manager)
        {
            if (GetConnectionsException is not null)
            {
                throw GetConnectionsException;
            }

            return ConnectionCollection;
        }

        public object? GetAdapterId(object connection)
        {
            var typed = (FakeRawNetworkConnection)connection;
            if (typed.AdapterIdException is not null)
            {
                throw typed.AdapterIdException;
            }

            return typed.AdapterId;
        }

        public object? GetNetwork(object connection) =>
            ((FakeRawNetworkConnection)connection).Network;

        public object? GetCategory(object network) =>
            ((FakeRawNetwork)network).Category;

        public bool IsComObject(object target) => true;

        public void Release(object target) => Released.Add(target);
    }

    private sealed class FakeRawNetworkConnectionCollection(
        IReadOnlyList<FakeRawNetworkConnection> connections) : System.Collections.IEnumerable
    {
        public System.Collections.IEnumerator GetEnumerator() => connections.GetEnumerator();
    }

    private sealed record FakeRawNetworkConnection(
        string AdapterId,
        int Category)
    {
        public FakeRawNetwork Network { get; } = new(Category);

        public Exception? AdapterIdException { get; init; }
    }

    private sealed record FakeRawNetwork(int Category);

    private sealed class FakeHostController(ConcurrentQueue<string> events) : ILocalWebHostController
    {
        private readonly TaskCompletionSource _startEntered =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseStart =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public bool BlockStart { get; set; }

        public Exception? StartException { get; set; }

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

            if (StartException is not null)
            {
                throw StartException;
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

        public bool CompleteRemoveStaleAsynchronously { get; set; }

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
            var eventText = "auth:remove-stale:" + string.Join(",", activeHostIpv4Addresses);
            if (CompleteRemoveStaleAsynchronously)
            {
                return new ValueTask<AuthorizationMutationResult>(
                    Task.Run(
                        () =>
                        {
                            events.Enqueue(eventText);
                            return NetworkTestAuthorizationResult.Create(succeeded: true);
                        },
                        cancellationToken));
            }

            events.Enqueue(eventText);
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
