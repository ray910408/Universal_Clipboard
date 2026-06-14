using System.Net;
using FluentAssertions;
using UniversalClipboard.App.Network;

namespace UniversalClipboard.App.Tests.Network;

public sealed class NetworkInterfaceSelectorTests
{
    [Fact]
    public void No_eligible_interface_reports_no_eligible_interface()
    {
        var result = NetworkInterfaceSelector.Select(
            [
                Iface("loop", NetworkInterfaceKind.Loopback, IPAddress.Loopback),
                Iface("tun", NetworkInterfaceKind.Tunnel, IPAddress.Parse("10.1.1.20")),
                Iface("nogw", NetworkInterfaceKind.Ethernet, IPAddress.Parse("192.168.1.20"), hasGateway: false),
                Iface("public", NetworkInterfaceKind.WiFi, IPAddress.Parse("8.8.8.8")),
            ],
            retainedExplicitInterfaceId: null);

        result.Status.Should().Be(NetworkSelectionStatus.NoEligibleInterface);
        result.EligibleInterfaces.Should().BeEmpty();
    }

    [Fact]
    public void One_eligible_private_ethernet_or_wifi_with_default_gateway_auto_selects()
    {
        var selected = NetworkInterfaceSelector.Select(
            [Iface("wifi", NetworkInterfaceKind.WiFi, IPAddress.Parse("192.168.50.5"))],
            retainedExplicitInterfaceId: null);

        selected.Status.Should().Be(NetworkSelectionStatus.AutoSelected);
        selected.Selected!.Id.Should().Be("wifi");
        selected.SelectedAddress.Should().Be(IPAddress.Parse("192.168.50.5"));
    }

    [Fact]
    public void Multiple_eligible_interfaces_require_selection_unless_retained_private_selection_survives()
    {
        var interfaces = new[]
        {
            Iface("eth", NetworkInterfaceKind.Ethernet, IPAddress.Parse("10.0.0.5")),
            Iface("wifi", NetworkInterfaceKind.WiFi, IPAddress.Parse("192.168.1.5")),
        };

        NetworkInterfaceSelector.Select(interfaces, retainedExplicitInterfaceId: null)
            .Status.Should().Be(NetworkSelectionStatus.SelectionRequired);

        var retained = NetworkInterfaceSelector.Select(
            interfaces,
            retainedExplicitInterfaceId: "wifi");

        retained.Status.Should().Be(NetworkSelectionStatus.RetainedExplicitSelection);
        retained.Selected!.Id.Should().Be("wifi");
        retained.SelectedAddress.Should().Be(IPAddress.Parse("192.168.1.5"));
    }

    [Fact]
    public void Retained_selection_is_rejected_when_interface_becomes_public()
    {
        var result = NetworkInterfaceSelector.Select(
            [
                Iface(
                    "wifi",
                    NetworkInterfaceKind.WiFi,
                    IPAddress.Parse("192.168.1.5"),
                    profile: NetworkProfile.Public),
                Iface("eth", NetworkInterfaceKind.Ethernet, IPAddress.Parse("10.0.0.5")),
            ],
            retainedExplicitInterfaceId: "wifi");

        result.Status.Should().Be(NetworkSelectionStatus.AutoSelected);
        result.Selected!.Id.Should().Be("eth");
    }

    private static NetworkInterfaceState Iface(
        string id,
        NetworkInterfaceKind kind,
        IPAddress address,
        bool hasGateway = true,
        NetworkProfile profile = NetworkProfile.Private) =>
        new(
            id,
            id,
            kind,
            NetworkOperationalStatus.Up,
            profile,
            [address],
            hasGateway);
}
