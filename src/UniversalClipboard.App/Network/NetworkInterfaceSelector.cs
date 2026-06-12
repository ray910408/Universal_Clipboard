using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;

namespace UniversalClipboard.App.Network;

public enum NetworkInterfaceKind
{
    Ethernet,
    WiFi,
    Loopback,
    Tunnel,
    Other,
}

public enum NetworkOperationalStatus
{
    Up,
    Down,
}

public enum NetworkProfile
{
    Private,
    Public,
    Unknown,
}

public sealed record NetworkInterfaceState(
    string Id,
    string Name,
    NetworkInterfaceKind Kind,
    NetworkOperationalStatus OperationalStatus,
    NetworkProfile Profile,
    IReadOnlyList<IPAddress> Ipv4Addresses,
    bool HasDefaultGateway);

public enum NetworkSelectionStatus
{
    NoEligibleInterface,
    AutoSelected,
    RetainedExplicitSelection,
    SelectionRequired,
}

public sealed record NetworkSelectionResult(
    NetworkSelectionStatus Status,
    ImmutableArray<NetworkInterfaceState> EligibleInterfaces,
    NetworkInterfaceState? Selected,
    IPAddress? SelectedAddress);

public static class NetworkInterfaceSelector
{
    public static NetworkSelectionResult Select(
        IReadOnlyList<NetworkInterfaceState> interfaces,
        string? retainedExplicitInterfaceId)
    {
        ArgumentNullException.ThrowIfNull(interfaces);
        var eligible = interfaces
            .Where(IsEligiblePrivateInterface)
            .ToImmutableArray();

        if (eligible.IsEmpty)
        {
            return new NetworkSelectionResult(
                NetworkSelectionStatus.NoEligibleInterface,
                eligible,
                null,
                null);
        }

        if (!string.IsNullOrWhiteSpace(retainedExplicitInterfaceId))
        {
            var retained = eligible.FirstOrDefault(
                item => string.Equals(
                    item.Id,
                    retainedExplicitInterfaceId,
                    StringComparison.Ordinal));
            if (retained is not null)
            {
                return Selected(
                    NetworkSelectionStatus.RetainedExplicitSelection,
                    eligible,
                    retained);
            }
        }

        return eligible.Length == 1
            ? Selected(NetworkSelectionStatus.AutoSelected, eligible, eligible[0])
            : new NetworkSelectionResult(
                NetworkSelectionStatus.SelectionRequired,
                eligible,
                null,
                null);
    }

    internal static bool IsEligiblePrivateInterface(NetworkInterfaceState item) =>
        IsUsableLanInterface(item) &&
        item.Profile == NetworkProfile.Private &&
        item.Ipv4Addresses.Any(IsPrivateIpv4);

    internal static bool IsUsableLanInterface(NetworkInterfaceState item) =>
        item.OperationalStatus == NetworkOperationalStatus.Up &&
        item.HasDefaultGateway &&
        item.Kind is NetworkInterfaceKind.Ethernet or NetworkInterfaceKind.WiFi;

    internal static bool IsPrivateIpv4(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork ||
            IPAddress.IsLoopback(address))
        {
            return false;
        }

        var bytes = address.GetAddressBytes();
        return bytes[0] == 10 ||
            bytes[0] == 192 && bytes[1] == 168 ||
            bytes[0] == 172 && bytes[1] is >= 16 and <= 31;
    }

    internal static IPAddress FirstPrivateIpv4(NetworkInterfaceState item) =>
        item.Ipv4Addresses.First(IsPrivateIpv4);

    private static NetworkSelectionResult Selected(
        NetworkSelectionStatus status,
        ImmutableArray<NetworkInterfaceState> eligible,
        NetworkInterfaceState selected) =>
        new(status, eligible, selected, FirstPrivateIpv4(selected));
}
