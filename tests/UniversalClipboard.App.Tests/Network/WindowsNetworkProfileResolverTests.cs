using System.Net;
using FluentAssertions;
using UniversalClipboard.App.Network;

namespace UniversalClipboard.App.Tests.Network;

public sealed class WindowsNetworkProfileResolverTests
{
    [Fact]
    public void Resolver_maps_private_profile_when_nlm_adapter_id_uses_com_out_parameter_shape()
    {
        var adapterId = Guid.Parse("11223344-5566-7788-99aa-bbccddeeff00");
        var resolver = new WindowsNetworkProfileResolver(
            new WindowsNetworkListManager(
                new ReflectionBackedNetworkListComBridge(
                    [
                        new OutParameterNetworkConnection(
                            adapterId,
                            WindowsNetworkProfileResolver.PrivateCategory),
                    ])),
            WindowsConnectionProfileProvider.Unknown);

        var profile = resolver.Resolve(Adapter(id: adapterId.ToString("B"), name: "Wi-Fi"));

        profile.Should().Be(NetworkProfile.Private);
    }

    [Fact]
    public void Resolver_keeps_public_out_parameter_nlm_result_without_private_fallback_override()
    {
        var adapterId = Guid.Parse("11223344-5566-7788-99aa-bbccddeeff00");
        var resolver = new WindowsNetworkProfileResolver(
            new WindowsNetworkListManager(
                new ReflectionBackedNetworkListComBridge(
                    [
                        new OutParameterNetworkConnection(
                            adapterId,
                            WindowsNetworkProfileResolver.PublicCategory),
                    ])),
            new WindowsConnectionProfileProvider(_ => NetworkProfile.Private));

        var profile = resolver.Resolve(Adapter(id: adapterId.ToString("B"), name: "Wi-Fi"));

        profile.Should().Be(NetworkProfile.Public);
    }

    [Fact]
    public void Netsh_parser_maps_connected_wifi_alias_to_private_firewall_profile()
    {
        var profiles = NetshWindowsConnectionProfileParser.Parse(
            """
            There is 1 interface on the system:

                Name                   : Wi-Fi
                State                  : connected
                SSID                   : JOHNS_5G
                BSSID                  : 11:22:33:44:55:66
            """,
            """
            Private Profile:
            ----------------------------------------------------------------------
            JOHNS_5G 2

            Public Profile:
            ----------------------------------------------------------------------
            """);

        profiles["Wi-Fi"].Should().Be(NetworkProfile.Private);
    }

    [Fact]
    public void Netsh_parser_maps_traditional_chinese_connected_wifi_alias_to_private_firewall_profile()
    {
        var profiles = NetshWindowsConnectionProfileParser.Parse(
            """
            系統上有 1 個介面:

                名稱                   : Wi-Fi
                狀態                  : 連線
                SSID                   : JOHNS_5G
                設定檔                 : JOHNS_5G
            """,
            """
            私人設定檔:
            ----------------------------------------------------------------------
            JOHNS_5G 2
            Radmin VPN

            公用設定檔:
            ----------------------------------------------------------------------
            確定。
            """);

        profiles["Wi-Fi"].Should().Be(NetworkProfile.Private);
    }

    [Fact]
    public void Netsh_parser_maps_connected_wifi_alias_to_public_firewall_profile()
    {
        var profiles = NetshWindowsConnectionProfileParser.Parse(
            """
            Name                   : Wi-Fi
            State                  : connected
            SSID                   : Coffee Shop
            """,
            """
            Private Profile:
            ----------------------------------------------------------------------

            Public Profile:
            ----------------------------------------------------------------------
            Coffee Shop
            """);

        profiles["Wi-Fi"].Should().Be(NetworkProfile.Public);
    }

    [Fact]
    public void Netsh_parser_preserves_public_when_firewall_profile_lists_conflicting_network_name()
    {
        var profiles = NetshWindowsConnectionProfileParser.Parse(
            """
            Name                   : Wi-Fi
            State                  : connected
            SSID                   : Ambiguous
            """,
            """
            Private Profile:
            ----------------------------------------------------------------------
            Ambiguous

            Public Profile:
            ----------------------------------------------------------------------
            Ambiguous
            """);

        profiles["Wi-Fi"].Should().Be(NetworkProfile.Public);
    }

    [Theory]
    [InlineData("Ok.")]
    [InlineData("確定。")]
    public void Netsh_parser_does_not_treat_terminal_status_lines_as_network_names(
        string terminalStatus)
    {
        var profiles = NetshWindowsConnectionProfileParser.Parse(
            $"""
            Name                   : Wi-Fi
            State                  : connected
            SSID                   : {terminalStatus}
            """,
            $"""
            Public Profile:
            ----------------------------------------------------------------------
            {terminalStatus}
            """);

        profiles.Should().NotContainKey("Wi-Fi");
    }

    [Fact]
    public void Netsh_provider_fails_closed_when_command_fails()
    {
        var provider = new NetshWindowsConnectionProfileProvider(
            new FakeNetshConnectionProfileCommand(
                new NetshWindowsConnectionProfileCommandResult(
                    Succeeded: false,
                    WlanInterfacesOutput:
                        """
                        Name                   : Wi-Fi
                        State                  : connected
                        SSID                   : JOHNS_5G 2
                        """,
                    FirewallProfilesOutput:
                        """
                        Private Profile:
                        JOHNS_5G 2
                        """)),
            TimeProvider.System);

        provider.Resolve("Wi-Fi").Should().Be(NetworkProfile.Unknown);
    }

    [Fact]
    public void Composite_profile_provider_keeps_public_result_when_another_source_reports_private()
    {
        var provider = new FailClosedWindowsConnectionProfileProvider(
            new WindowsConnectionProfileProvider(_ => NetworkProfile.Private),
            new WindowsConnectionProfileProvider(_ => NetworkProfile.Public));

        provider.Resolve("Wi-Fi").Should().Be(NetworkProfile.Public);
    }

    [Fact]
    public void Resolver_uses_alias_fallback_when_com_adapter_mapping_is_unknown()
    {
        var resolver = new WindowsNetworkProfileResolver(
            new FakeComNetworkList([]),
            new WindowsConnectionProfileProvider(alias =>
                string.Equals(alias, "Wi-Fi", StringComparison.Ordinal)
                    ? NetworkProfile.Private
                    : NetworkProfile.Unknown));

        var profile = resolver.Resolve(Adapter(id: "wifi-guid", name: "Wi-Fi"));

        profile.Should().Be(NetworkProfile.Private);
    }

    [Fact]
    public void Resolver_keeps_public_com_result_without_private_fallback_override()
    {
        var resolver = new WindowsNetworkProfileResolver(
            new FakeComNetworkList(
                [
                    new ComNetworkConnectionSnapshot(
                        "wifi-guid",
                        WindowsNetworkProfileResolver.PublicCategory),
                ]),
            new WindowsConnectionProfileProvider(_ => NetworkProfile.Private));

        var profile = resolver.Resolve(Adapter(id: "wifi-guid", name: "Wi-Fi"));

        profile.Should().Be(NetworkProfile.Public);
    }

    [Theory]
    [InlineData(
        """
        [{"InterfaceAlias":"Wi-Fi","NetworkCategory":"Private"}]
        """,
        "Wi-Fi",
        NetworkProfile.Private)]
    [InlineData(
        """
        [{"InterfaceAlias":"Wi-Fi","NetworkCategory":"Public"}]
        """,
        "Wi-Fi",
        NetworkProfile.Public)]
    [InlineData(
        """
        {"InterfaceAlias":"Wi-Fi","NetworkCategory":1}
        """,
        "wi-fi",
        NetworkProfile.Private)]
    [InlineData(
        """
        [{"InterfaceAlias":"Wi-Fi","NetworkCategory":0}]
        """,
        "Wi-Fi",
        NetworkProfile.Public)]
    public void Parser_maps_exact_interface_alias_to_private_or_public(
        string json,
        string alias,
        NetworkProfile expectedProfile)
    {
        var profiles = WindowsConnectionProfileParser.Parse(json);

        profiles.TryGetValue(alias, out var profile).Should().BeTrue();
        profile.Should().Be(expectedProfile);
    }

    [Theory]
    [InlineData("")]
    [InlineData("not json")]
    [InlineData("""[{"InterfaceAlias":"Ethernet","NetworkCategory":"Private"}]""")]
    [InlineData("""[{"InterfaceAlias":"Wi-Fi","NetworkCategory":"DomainAuthenticated"}]""")]
    [InlineData("""[{"InterfaceAlias":"Wi-Fi","NetworkCategory":2}]""")]
    [InlineData("""[{"InterfaceAlias":"Wi-Fi"}]""")]
    public void Parser_fails_closed_for_unparseable_missing_or_unknown_profiles(string json)
    {
        var profiles = WindowsConnectionProfileParser.Parse(json);

        var found = profiles.TryGetValue("Wi-Fi", out var resolvedProfile);
        var profile = found ? resolvedProfile : NetworkProfile.Unknown;

        found.Should().BeFalse();
        profile.Should().Be(NetworkProfile.Unknown);
    }

    [Fact]
    public void Parser_fails_closed_for_conflicting_duplicate_aliases()
    {
        var profiles = WindowsConnectionProfileParser.Parse(
            """
            [
              {"InterfaceAlias":"Wi-Fi","NetworkCategory":"Private"},
              {"InterfaceAlias":"wi-fi","NetworkCategory":"Public"}
            ]
            """);

        profiles["Wi-Fi"].Should().Be(NetworkProfile.Unknown);
    }

    [Fact]
    public void PowerShell_provider_fails_closed_when_command_fails()
    {
        var provider = new PowerShellWindowsConnectionProfileProvider(
            new FakeConnectionProfileCommand(
                new WindowsConnectionProfileCommandResult(
                    Succeeded: false,
                    StandardOutput:
                        """[{"InterfaceAlias":"Wi-Fi","NetworkCategory":"Private"}]""")),
            TimeProvider.System);

        provider.Resolve("Wi-Fi").Should().Be(NetworkProfile.Unknown);
    }

    [Fact]
    public void PowerShell_provider_uses_timeout_with_headroom_for_slow_windows_profile_queries()
    {
        var command = new FakeConnectionProfileCommand(
            new WindowsConnectionProfileCommandResult(
                Succeeded: true,
                StandardOutput:
                    """[{"InterfaceAlias":"Wi-Fi","NetworkCategory":1}]"""));
        var provider = new PowerShellWindowsConnectionProfileProvider(command, TimeProvider.System);

        provider.Resolve("Wi-Fi").Should().Be(NetworkProfile.Private);

        command.Timeouts.Should().ContainSingle();
        command.Timeouts.Single().Should().BeGreaterThanOrEqualTo(TimeSpan.FromSeconds(5));
    }

    private static NetworkAdapterSnapshot Adapter(string id, string name) =>
        new(
            id,
            name,
            NetworkInterfaceKind.WiFi,
            NetworkOperationalStatus.Up,
            [IPAddress.Parse("192.168.8.216")],
            HasDefaultGateway: true);

    private sealed class FakeComNetworkList(
        IReadOnlyList<ComNetworkConnectionSnapshot> connections) : IComNetworkList
    {
        public IReadOnlyList<ComNetworkConnectionSnapshot> GetConnections() => connections;
    }

    private sealed class FakeConnectionProfileCommand(
        WindowsConnectionProfileCommandResult result) : IWindowsConnectionProfileCommand
    {
        public List<TimeSpan> Timeouts { get; } = [];

        public WindowsConnectionProfileCommandResult Query(TimeSpan timeout)
        {
            Timeouts.Add(timeout);
            return result;
        }
    }

    private sealed class FakeNetshConnectionProfileCommand(
        NetshWindowsConnectionProfileCommandResult result) : INetshWindowsConnectionProfileCommand
    {
        public NetshWindowsConnectionProfileCommandResult Query(TimeSpan timeout) => result;
    }

    private sealed class ReflectionBackedNetworkListComBridge(
        IReadOnlyList<OutParameterNetworkConnection> connections) : IWindowsNetworkListComBridge
    {
        private readonly ReflectionWindowsNetworkListComBridge _reflectionBridge = new();

        public object Manager { get; } = new();

        public OutParameterNetworkConnectionCollection ConnectionCollection { get; } =
            new(connections);

        public object? CreateManager(Guid clsid) => Manager;

        public object? GetNetworkConnections(object manager) => ConnectionCollection;

        public object? GetAdapterId(object connection) =>
            _reflectionBridge.GetAdapterId(connection);

        public object? GetNetwork(object connection) =>
            _reflectionBridge.GetNetwork(connection);

        public object? GetCategory(object network) =>
            _reflectionBridge.GetCategory(network);

        public bool IsComObject(object target) => true;

        public void Release(object target)
        {
        }
    }

    private sealed class OutParameterNetworkConnectionCollection(
        IReadOnlyList<OutParameterNetworkConnection> connections) : System.Collections.IEnumerable
    {
        public System.Collections.IEnumerator GetEnumerator() => connections.GetEnumerator();
    }

    private sealed class OutParameterNetworkConnection(Guid adapterId, int category)
    {
        public OutParameterNetwork Network { get; } = new(category);

        public void GetAdapterId(out Guid result) => result = adapterId;

        public void GetNetwork(out OutParameterNetwork result) => result = Network;
    }

    private sealed class OutParameterNetwork(int category)
    {
        public void GetCategory(out int result) => result = category;
    }
}
