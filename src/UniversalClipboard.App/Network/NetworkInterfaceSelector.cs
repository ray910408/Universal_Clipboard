using System.Collections.Immutable;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

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

public sealed record NetworkAdapterSnapshot(
    string Id,
    string Name,
    NetworkInterfaceKind Kind,
    NetworkOperationalStatus OperationalStatus,
    IReadOnlyList<IPAddress> Ipv4Addresses,
    bool HasDefaultGateway);

public sealed class WindowsNetworkInterfaceMapper(Func<NetworkAdapterSnapshot, NetworkProfile> profileResolver)
{
    public NetworkInterfaceState Map(NetworkAdapterSnapshot adapter) =>
        new(
            adapter.Id,
            adapter.Name,
            adapter.Kind,
            adapter.OperationalStatus,
            profileResolver(adapter),
            adapter.Ipv4Addresses,
            adapter.HasDefaultGateway);
}

public sealed record ComNetworkConnectionSnapshot(string AdapterId, int Category);

public interface IComNetworkList
{
    IReadOnlyList<ComNetworkConnectionSnapshot> GetConnections();
}

public sealed class WindowsNetworkProfileResolver(IComNetworkList networkList)
{
    public const int PublicCategory = 0;
    public const int PrivateCategory = 1;
    public const int DomainAuthenticatedCategory = 2;

    public WindowsNetworkProfileResolver()
        : this(new WindowsNetworkListManager())
    {
    }

    public NetworkProfile Resolve(NetworkAdapterSnapshot adapter)
    {
        var adapterId = NormalizeAdapterId(adapter.Id);
        ComNetworkConnectionSnapshot? connection;
        try
        {
            connection = networkList.GetConnections().FirstOrDefault(item =>
                string.Equals(
                    NormalizeAdapterId(item.AdapterId),
                    adapterId,
                    StringComparison.OrdinalIgnoreCase));
        }
        catch (COMException)
        {
            return NetworkProfile.Unknown;
        }
        catch (ArgumentException)
        {
            return NetworkProfile.Unknown;
        }

        return connection?.Category switch
        {
            PrivateCategory => NetworkProfile.Private,
            PublicCategory => NetworkProfile.Public,
            _ => NetworkProfile.Unknown,
        };
    }

    private static string NormalizeAdapterId(string adapterId) =>
        adapterId.Trim().Trim('{', '}');
}

public sealed class WindowsNetworkListManager : IComNetworkList
{
    private static readonly Guid NetworkListManagerClsid =
        Guid.Parse("DCB00C01-570F-4A9B-8D69-199FDBA5723B");

    public IReadOnlyList<ComNetworkConnectionSnapshot> GetConnections()
    {
        var managerType = Type.GetTypeFromCLSID(NetworkListManagerClsid);
        if (managerType is null)
        {
            return [];
        }

        object? manager = null;
        try
        {
            manager = Activator.CreateInstance(managerType);
            if (manager is null)
            {
                return [];
            }

            var connections = Invoke(manager, "GetNetworkConnections");
            if (connections is not System.Collections.IEnumerable enumerable)
            {
                return [];
            }

            var snapshots = new List<ComNetworkConnectionSnapshot>();
            foreach (var connection in enumerable)
            {
                object? network = null;
                try
                {
                    var adapterId = Invoke(connection, "GetAdapterId")?.ToString();
                    network = Invoke(connection, "GetNetwork");
                    if (network is null)
                    {
                        continue;
                    }

                    var category = Invoke(network, "GetCategory");
                    if (adapterId is not null && category is int typedCategory)
                    {
                        snapshots.Add(new ComNetworkConnectionSnapshot(adapterId, typedCategory));
                    }
                }
                finally
                {
                    if (network is not null && Marshal.IsComObject(network))
                    {
                        Marshal.ReleaseComObject(network);
                    }

                    if (Marshal.IsComObject(connection))
                    {
                        Marshal.ReleaseComObject(connection);
                    }
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
        catch (ArgumentException)
        {
            return [];
        }
        finally
        {
            if (manager is not null && Marshal.IsComObject(manager))
            {
                Marshal.ReleaseComObject(manager);
            }
        }
    }

    private static object? Invoke(object target, string method) =>
        target.GetType().InvokeMember(
            method,
            System.Reflection.BindingFlags.InvokeMethod,
            null,
            target,
            null);
}

public sealed class WindowsNetworkEnvironment : INetworkEnvironment
{
    private readonly WindowsNetworkInterfaceMapper _mapper;

    public WindowsNetworkEnvironment()
        : this(new WindowsNetworkProfileResolver().Resolve)
    {
    }

    public WindowsNetworkEnvironment(Func<NetworkAdapterSnapshot, NetworkProfile> profileResolver)
    {
        _mapper = new WindowsNetworkInterfaceMapper(profileResolver);
    }

    public ValueTask<IReadOnlyList<NetworkInterfaceState>> GetInterfacesAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            var interfaces = NetworkInterface.GetAllNetworkInterfaces()
                .Select(TryToSnapshot)
                .Where(snapshot => snapshot is not null)
                .Cast<NetworkAdapterSnapshot>()
                .Select(_mapper.Map)
                .ToArray();
            return ValueTask.FromResult<IReadOnlyList<NetworkInterfaceState>>(interfaces);
        }
        catch (NetworkInformationException)
        {
            return ValueTask.FromResult<IReadOnlyList<NetworkInterfaceState>>([]);
        }
        catch (ArgumentException)
        {
            return ValueTask.FromResult<IReadOnlyList<NetworkInterfaceState>>([]);
        }
    }

    private static NetworkAdapterSnapshot? TryToSnapshot(NetworkInterface networkInterface)
    {
        try
        {
            return ToSnapshot(networkInterface);
        }
        catch (NetworkInformationException)
        {
            return null;
        }
        catch (ArgumentException)
        {
            return null;
        }
    }

    private static NetworkAdapterSnapshot ToSnapshot(NetworkInterface networkInterface)
    {
        var properties = networkInterface.GetIPProperties();
        return new NetworkAdapterSnapshot(
            networkInterface.Id,
            networkInterface.Name,
            ToKind(networkInterface.NetworkInterfaceType),
            networkInterface.OperationalStatus == OperationalStatus.Up
                ? NetworkOperationalStatus.Up
                : NetworkOperationalStatus.Down,
            properties.UnicastAddresses
                .Where(address => address.Address.AddressFamily == AddressFamily.InterNetwork)
                .Select(address => address.Address)
                .ToArray(),
            properties.GatewayAddresses.Any(address =>
                address.Address.AddressFamily == AddressFamily.InterNetwork &&
                !IPAddress.Any.Equals(address.Address)));
    }

    private static NetworkInterfaceKind ToKind(NetworkInterfaceType type) =>
        type switch
        {
            NetworkInterfaceType.Ethernet => NetworkInterfaceKind.Ethernet,
            NetworkInterfaceType.Wireless80211 => NetworkInterfaceKind.WiFi,
            NetworkInterfaceType.Loopback => NetworkInterfaceKind.Loopback,
            NetworkInterfaceType.Tunnel => NetworkInterfaceKind.Tunnel,
            _ => NetworkInterfaceKind.Other,
        };
}

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
