using System.Collections.Immutable;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;

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

public sealed class WindowsNetworkProfileResolver
{
    public const int PublicCategory = 0;
    public const int PrivateCategory = 1;
    public const int DomainAuthenticatedCategory = 2;

    private readonly IComNetworkList _networkList;
    private readonly IWindowsConnectionProfileProvider _fallbackProfileProvider;

    public WindowsNetworkProfileResolver()
        : this(
            new WindowsNetworkListManager(),
            new FailClosedWindowsConnectionProfileProvider(
                new NetshWindowsConnectionProfileProvider(),
                new PowerShellWindowsConnectionProfileProvider()))
    {
    }

    public WindowsNetworkProfileResolver(IComNetworkList networkList)
        : this(networkList, WindowsConnectionProfileProvider.Unknown)
    {
    }

    internal WindowsNetworkProfileResolver(
        IComNetworkList networkList,
        IWindowsConnectionProfileProvider fallbackProfileProvider)
    {
        _networkList = networkList;
        _fallbackProfileProvider = fallbackProfileProvider;
    }

    public NetworkProfile Resolve(NetworkAdapterSnapshot adapter)
    {
        var profile = ResolveFromNetworkListManager(adapter);
        return profile == NetworkProfile.Unknown
            ? _fallbackProfileProvider.Resolve(adapter.Name)
            : profile;
    }

    private NetworkProfile ResolveFromNetworkListManager(NetworkAdapterSnapshot adapter)
    {
        var adapterId = NormalizeAdapterId(adapter.Id);
        ComNetworkConnectionSnapshot? connection;
        try
        {
            connection = _networkList.GetConnections().FirstOrDefault(item =>
                string.Equals(
                    NormalizeAdapterId(item.AdapterId),
                    adapterId,
                    StringComparison.OrdinalIgnoreCase));
        }
        catch (COMException)
        {
            return NetworkProfile.Unknown;
        }
        catch (TargetInvocationException)
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

internal interface IWindowsConnectionProfileProvider
{
    NetworkProfile Resolve(string interfaceAlias);
}

internal sealed class WindowsConnectionProfileProvider(
    Func<string, NetworkProfile> resolve) : IWindowsConnectionProfileProvider
{
    public static IWindowsConnectionProfileProvider Unknown { get; } =
        new WindowsConnectionProfileProvider(_ => NetworkProfile.Unknown);

    public NetworkProfile Resolve(string interfaceAlias) => resolve(interfaceAlias);
}

internal sealed class FailClosedWindowsConnectionProfileProvider(
    params IWindowsConnectionProfileProvider[] providers) : IWindowsConnectionProfileProvider
{
    public NetworkProfile Resolve(string interfaceAlias)
    {
        var sawPrivate = false;
        foreach (var provider in providers)
        {
            var profile = provider.Resolve(interfaceAlias);
            if (profile == NetworkProfile.Public)
            {
                return NetworkProfile.Public;
            }

            sawPrivate |= profile == NetworkProfile.Private;
        }

        return sawPrivate ? NetworkProfile.Private : NetworkProfile.Unknown;
    }
}

internal sealed class NetshWindowsConnectionProfileProvider : IWindowsConnectionProfileProvider
{
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(2);

    private readonly INetshWindowsConnectionProfileCommand _command;
    private readonly TimeProvider _timeProvider;
    private readonly object _gate = new();
    private IReadOnlyDictionary<string, NetworkProfile>? _cachedProfiles;
    private DateTimeOffset _cacheExpiresAt;

    public NetshWindowsConnectionProfileProvider()
        : this(new NetshWindowsConnectionProfileCommand(), TimeProvider.System)
    {
    }

    internal NetshWindowsConnectionProfileProvider(
        INetshWindowsConnectionProfileCommand command,
        TimeProvider timeProvider)
    {
        _command = command;
        _timeProvider = timeProvider;
    }

    public NetworkProfile Resolve(string interfaceAlias)
    {
        if (string.IsNullOrWhiteSpace(interfaceAlias))
        {
            return NetworkProfile.Unknown;
        }

        var profiles = GetProfiles();
        return profiles.TryGetValue(interfaceAlias.Trim(), out var profile)
            ? profile
            : NetworkProfile.Unknown;
    }

    private IReadOnlyDictionary<string, NetworkProfile> GetProfiles()
    {
        var now = _timeProvider.GetUtcNow();
        lock (_gate)
        {
            if (_cachedProfiles is not null && now < _cacheExpiresAt)
            {
                return _cachedProfiles;
            }

            var result = _command.Query(QueryTimeout);
            _cachedProfiles = result.Succeeded
                ? NetshWindowsConnectionProfileParser.Parse(
                    result.WlanInterfacesOutput,
                    result.FirewallProfilesOutput)
                : WindowsConnectionProfileParser.EmptyProfiles;
            _cacheExpiresAt = now.Add(CacheDuration);
            return _cachedProfiles;
        }
    }
}

internal sealed record NetshWindowsConnectionProfileCommandResult(
    bool Succeeded,
    string WlanInterfacesOutput,
    string FirewallProfilesOutput);

internal interface INetshWindowsConnectionProfileCommand
{
    NetshWindowsConnectionProfileCommandResult Query(TimeSpan timeout);
}

internal sealed class NetshWindowsConnectionProfileCommand : INetshWindowsConnectionProfileCommand
{
    public NetshWindowsConnectionProfileCommandResult Query(TimeSpan timeout)
    {
        var wlan = RunNetsh(timeout, "wlan", "show", "interfaces");
        if (!wlan.Succeeded)
        {
            return new NetshWindowsConnectionProfileCommandResult(false, string.Empty, string.Empty);
        }

        var firewall = RunNetsh(timeout, "advfirewall", "monitor", "show", "currentprofile");
        return new NetshWindowsConnectionProfileCommandResult(
            firewall.Succeeded,
            wlan.StandardOutput,
            firewall.StandardOutput);
    }

    private static WindowsConnectionProfileCommandResult RunNetsh(
        TimeSpan timeout,
        params string[] arguments)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = CreateStartInfo(arguments),
            };

            if (!process.Start())
            {
                return new WindowsConnectionProfileCommandResult(false, string.Empty);
            }

            process.ErrorDataReceived += (_, _) => { };
            process.BeginErrorReadLine();
            if (!process.WaitForExit((int)timeout.TotalMilliseconds))
            {
                TryKill(process);
                return new WindowsConnectionProfileCommandResult(false, string.Empty);
            }

            var standardOutput = process.StandardOutput.ReadToEnd();
            return new WindowsConnectionProfileCommandResult(
                process.ExitCode == 0,
                standardOutput);
        }
        catch (InvalidOperationException)
        {
            return new WindowsConnectionProfileCommandResult(false, string.Empty);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return new WindowsConnectionProfileCommandResult(false, string.Empty);
        }
    }

    private static ProcessStartInfo CreateStartInfo(string[] arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "netsh.exe",
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        foreach (var argument in arguments)
        {
            startInfo.ArgumentList.Add(argument);
        }

        return startInfo;
    }

    private static void TryKill(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }
}

internal static class NetshWindowsConnectionProfileParser
{
    public static IReadOnlyDictionary<string, NetworkProfile> Parse(
        string wlanInterfacesOutput,
        string firewallProfilesOutput)
    {
        var ssidsByAlias = ParseConnectedWifiSsids(wlanInterfacesOutput);
        var profilesByNetworkName = ParseFirewallProfiles(firewallProfilesOutput);
        var profiles = new Dictionary<string, NetworkProfile>(StringComparer.OrdinalIgnoreCase);

        foreach (var (alias, ssid) in ssidsByAlias)
        {
            if (!profilesByNetworkName.TryGetValue(ssid, out var profile))
            {
                continue;
            }

            AddProfile(profiles, alias, profile);
        }

        return profiles;
    }

    private static Dictionary<string, string> ParseConnectedWifiSsids(string output)
    {
        var interfaces = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        string? currentAlias = null;
        string? currentSsid = null;
        var isConnected = false;

        foreach (var rawLine in ReadLines(output))
        {
            var line = rawLine.Trim();
            if (TryReadValue(line, ["Name", "名稱"], out var name))
            {
                AddCurrent();
                currentAlias = name;
                currentSsid = null;
                isConnected = false;
                continue;
            }

            if (TryReadValue(line, ["State", "狀態"], out var state))
            {
                isConnected = IsConnectedState(state);
                continue;
            }

            if (TryReadValue(line, ["SSID"], out var ssid) &&
                !line.StartsWith("BSSID", StringComparison.OrdinalIgnoreCase))
            {
                currentSsid = ssid;
            }
        }

        AddCurrent();
        return interfaces;

        void AddCurrent()
        {
            if (isConnected &&
                !string.IsNullOrWhiteSpace(currentAlias) &&
                !string.IsNullOrWhiteSpace(currentSsid))
            {
                interfaces[currentAlias.Trim()] = currentSsid.Trim();
            }
        }
    }

    private static Dictionary<string, NetworkProfile> ParseFirewallProfiles(string output)
    {
        var profiles = new Dictionary<string, NetworkProfile>(StringComparer.OrdinalIgnoreCase);
        var currentProfile = NetworkProfile.Unknown;

        foreach (var rawLine in ReadLines(output))
        {
            var line = rawLine.Trim();
            if (line.Length == 0 ||
                line.All(character => character == '-') ||
                IsTerminalStatusLine(line))
            {
                continue;
            }

            if (IsProfileHeader(line))
            {
                currentProfile = ParseProfileHeader(line);
                continue;
            }

            if (currentProfile != NetworkProfile.Unknown)
            {
                AddProfile(profiles, line, currentProfile);
                var normalizedProfileName = TrimWindowsNetworkProfileSuffix(line);
                if (!string.Equals(normalizedProfileName, line, StringComparison.Ordinal))
                {
                    AddProfile(profiles, normalizedProfileName, currentProfile);
                }
            }
        }

        return profiles;
    }

    private static void AddProfile(
        Dictionary<string, NetworkProfile> profiles,
        string key,
        NetworkProfile profile)
    {
        if (profiles.TryGetValue(key, out var existing))
        {
            profiles[key] = existing == NetworkProfile.Public || profile == NetworkProfile.Public
                ? NetworkProfile.Public
                : existing == profile
                    ? profile
                    : NetworkProfile.Unknown;
            return;
        }

        profiles[key] = profile;
    }

    private static string TrimWindowsNetworkProfileSuffix(string networkName)
    {
        var separator = networkName.LastIndexOf(' ');
        if (separator <= 0 ||
            separator == networkName.Length - 1)
        {
            return networkName;
        }

        return networkName[(separator + 1)..].All(char.IsDigit)
            ? networkName[..separator]
            : networkName;
    }

    private static NetworkProfile ParseProfileHeader(string header)
    {
        if (header.StartsWith("Private Profile", StringComparison.OrdinalIgnoreCase) ||
            header.StartsWith("私人設定檔", StringComparison.OrdinalIgnoreCase))
        {
            return NetworkProfile.Private;
        }

        return header.StartsWith("Public Profile", StringComparison.OrdinalIgnoreCase) ||
            header.StartsWith("公用設定檔", StringComparison.OrdinalIgnoreCase)
            ? NetworkProfile.Public
            : NetworkProfile.Unknown;
    }

    private static bool IsProfileHeader(string line) =>
        line.EndsWith("Profile:", StringComparison.OrdinalIgnoreCase) ||
        line.EndsWith("設定檔:", StringComparison.OrdinalIgnoreCase);

    private static bool IsConnectedState(string state) =>
        string.Equals(state, "connected", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(state, "連線", StringComparison.OrdinalIgnoreCase);

    private static bool IsTerminalStatusLine(string line) =>
        string.Equals(line, "Ok.", StringComparison.OrdinalIgnoreCase) ||
        string.Equals(line, "確定。", StringComparison.OrdinalIgnoreCase);

    private static bool TryReadValue(string line, IReadOnlyCollection<string> keys, out string value)
    {
        value = string.Empty;
        var separator = line.IndexOf(':', StringComparison.Ordinal);
        if (separator < 0 ||
            !keys.Contains(line[..separator].Trim(), StringComparer.OrdinalIgnoreCase))
        {
            return false;
        }

        value = line[(separator + 1)..].Trim();
        return value.Length > 0;
    }

    private static IEnumerable<string> ReadLines(string output)
    {
        using var reader = new StringReader(output);
        while (reader.ReadLine() is { } line)
        {
            yield return line;
        }
    }
}

internal sealed class PowerShellWindowsConnectionProfileProvider : IWindowsConnectionProfileProvider
{
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(8);
    private static readonly TimeSpan CacheDuration = TimeSpan.FromSeconds(2);

    private readonly IWindowsConnectionProfileCommand _command;
    private readonly TimeProvider _timeProvider;
    private readonly object _gate = new();
    private IReadOnlyDictionary<string, NetworkProfile>? _cachedProfiles;
    private DateTimeOffset _cacheExpiresAt;

    public PowerShellWindowsConnectionProfileProvider()
        : this(new PowerShellWindowsConnectionProfileCommand(), TimeProvider.System)
    {
    }

    internal PowerShellWindowsConnectionProfileProvider(
        IWindowsConnectionProfileCommand command,
        TimeProvider timeProvider)
    {
        _command = command;
        _timeProvider = timeProvider;
    }

    public NetworkProfile Resolve(string interfaceAlias)
    {
        if (string.IsNullOrWhiteSpace(interfaceAlias))
        {
            return NetworkProfile.Unknown;
        }

        var profiles = GetProfiles();
        return profiles.TryGetValue(interfaceAlias.Trim(), out var profile)
            ? profile
            : NetworkProfile.Unknown;
    }

    private IReadOnlyDictionary<string, NetworkProfile> GetProfiles()
    {
        var now = _timeProvider.GetUtcNow();
        lock (_gate)
        {
            if (_cachedProfiles is not null && now < _cacheExpiresAt)
            {
                return _cachedProfiles;
            }

            var result = _command.Query(QueryTimeout);
            _cachedProfiles = result.Succeeded
                ? WindowsConnectionProfileParser.Parse(result.StandardOutput)
                : WindowsConnectionProfileParser.EmptyProfiles;
            _cacheExpiresAt = now.Add(CacheDuration);
            return _cachedProfiles;
        }
    }
}

internal sealed record WindowsConnectionProfileCommandResult(
    bool Succeeded,
    string StandardOutput);

internal interface IWindowsConnectionProfileCommand
{
    WindowsConnectionProfileCommandResult Query(TimeSpan timeout);
}

internal sealed class PowerShellWindowsConnectionProfileCommand : IWindowsConnectionProfileCommand
{
    public WindowsConnectionProfileCommandResult Query(TimeSpan timeout)
    {
        try
        {
            using var process = new Process
            {
                StartInfo = CreateStartInfo(),
            };

            if (!process.Start())
            {
                return new WindowsConnectionProfileCommandResult(false, string.Empty);
            }

            process.ErrorDataReceived += (_, _) => { };
            process.BeginErrorReadLine();
            if (!process.WaitForExit((int)timeout.TotalMilliseconds))
            {
                TryKill(process);
                return new WindowsConnectionProfileCommandResult(false, string.Empty);
            }

            var standardOutput = process.StandardOutput.ReadToEnd();
            return new WindowsConnectionProfileCommandResult(
                process.ExitCode == 0,
                standardOutput);
        }
        catch (InvalidOperationException)
        {
            return new WindowsConnectionProfileCommandResult(false, string.Empty);
        }
        catch (System.ComponentModel.Win32Exception)
        {
            return new WindowsConnectionProfileCommandResult(false, string.Empty);
        }
    }

    private static ProcessStartInfo CreateStartInfo()
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "powershell.exe",
            RedirectStandardError = true,
            RedirectStandardOutput = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        startInfo.ArgumentList.Add("-NoProfile");
        startInfo.ArgumentList.Add("-NonInteractive");
        startInfo.ArgumentList.Add("-Command");
        startInfo.ArgumentList.Add(
            "Get-NetConnectionProfile | " +
            "Select-Object -Property InterfaceAlias,NetworkCategory | " +
            "ConvertTo-Json -Compress");
        return startInfo;
    }

    private static void TryKill(Process process)
    {
        try
        {
            process.Kill(entireProcessTree: true);
        }
        catch (InvalidOperationException)
        {
        }
        catch (System.ComponentModel.Win32Exception)
        {
        }
    }
}

internal static class WindowsConnectionProfileParser
{
    public static IReadOnlyDictionary<string, NetworkProfile> EmptyProfiles { get; } =
        new Dictionary<string, NetworkProfile>(StringComparer.OrdinalIgnoreCase);

    public static IReadOnlyDictionary<string, NetworkProfile> Parse(string json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return EmptyProfiles;
        }

        try
        {
            using var document = JsonDocument.Parse(json);
            var profiles = new Dictionary<string, NetworkProfile>(StringComparer.OrdinalIgnoreCase);
            if (document.RootElement.ValueKind == JsonValueKind.Array)
            {
                foreach (var element in document.RootElement.EnumerateArray())
                {
                    AddProfile(profiles, element);
                }
            }
            else if (document.RootElement.ValueKind == JsonValueKind.Object)
            {
                AddProfile(profiles, document.RootElement);
            }

            return profiles;
        }
        catch (JsonException)
        {
            return EmptyProfiles;
        }
    }

    private static void AddProfile(
        Dictionary<string, NetworkProfile> profiles,
        JsonElement element)
    {
        if (element.ValueKind != JsonValueKind.Object ||
            !element.TryGetProperty("InterfaceAlias", out var aliasElement) ||
            !element.TryGetProperty("NetworkCategory", out var categoryElement))
        {
            return;
        }

        var alias = aliasElement.GetString();
        var profile = ParseCategory(categoryElement);
        if (string.IsNullOrWhiteSpace(alias) || profile == NetworkProfile.Unknown)
        {
            return;
        }

        var trimmedAlias = alias.Trim();
        if (profiles.TryGetValue(trimmedAlias, out var existing))
        {
            if (existing != profile)
            {
                profiles[trimmedAlias] = NetworkProfile.Unknown;
            }

            return;
        }

        profiles[trimmedAlias] = profile;
    }

    private static NetworkProfile ParseCategory(JsonElement categoryElement) =>
        categoryElement.ValueKind switch
        {
            JsonValueKind.Number when categoryElement.TryGetInt32(out var category) =>
                ParseCategory(category),
            JsonValueKind.String => ParseCategory(categoryElement.GetString()),
            _ => NetworkProfile.Unknown,
        };

    private static NetworkProfile ParseCategory(string? category)
    {
        if (string.IsNullOrWhiteSpace(category))
        {
            return NetworkProfile.Unknown;
        }

        return int.TryParse(category, out var numericCategory)
            ? ParseCategory(numericCategory)
            : ParseCategoryName(category.Trim());
    }

    private static NetworkProfile ParseCategoryName(string category) =>
        string.Equals(category, "Private", StringComparison.OrdinalIgnoreCase)
            ? NetworkProfile.Private
            : string.Equals(category, "Public", StringComparison.OrdinalIgnoreCase)
                ? NetworkProfile.Public
                : NetworkProfile.Unknown;

    private static NetworkProfile ParseCategory(int category) =>
        category switch
        {
            WindowsNetworkProfileResolver.PrivateCategory => NetworkProfile.Private,
            WindowsNetworkProfileResolver.PublicCategory => NetworkProfile.Public,
            _ => NetworkProfile.Unknown,
        };
}

public sealed class WindowsNetworkListManager : IComNetworkList
{
    private static readonly Guid NetworkListManagerClsid =
        Guid.Parse("DCB00C01-570F-4A9B-8D69-199FDBA5723B");

    private readonly IWindowsNetworkListComBridge _bridge;

    public WindowsNetworkListManager()
        : this(new ReflectionWindowsNetworkListComBridge())
    {
    }

    internal WindowsNetworkListManager(IWindowsNetworkListComBridge bridge)
    {
        _bridge = bridge;
    }

    public IReadOnlyList<ComNetworkConnectionSnapshot> GetConnections()
    {
        object? manager = null;
        object? connections = null;
        try
        {
            manager = _bridge.CreateManager(NetworkListManagerClsid);
            if (manager is null)
            {
                return [];
            }

            connections = _bridge.GetNetworkConnections(manager);
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
                    var adapterId = _bridge.GetAdapterId(connection)?.ToString();
                    network = _bridge.GetNetwork(connection);
                    if (network is null)
                    {
                        continue;
                    }

                    var category = _bridge.GetCategory(network);
                    if (!string.IsNullOrWhiteSpace(adapterId) && category is int typedCategory)
                    {
                        snapshots.Add(new ComNetworkConnectionSnapshot(adapterId, typedCategory));
                    }
                }
                catch (COMException)
                {
                }
                catch (UnauthorizedAccessException)
                {
                }
                catch (TargetInvocationException)
                {
                }
                catch (TargetParameterCountException)
                {
                }
                catch (ArgumentException)
                {
                }
                catch (MissingMethodException)
                {
                }
                finally
                {
                    if (network is not null && _bridge.IsComObject(network))
                    {
                        _bridge.Release(network);
                    }

                    if (_bridge.IsComObject(connection))
                    {
                        _bridge.Release(connection);
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
        catch (TargetInvocationException)
        {
            return [];
        }
        catch (TargetParameterCountException)
        {
            return [];
        }
        catch (ArgumentException)
        {
            return [];
        }
        catch (MissingMethodException)
        {
            return [];
        }
        finally
        {
            if (connections is not null && _bridge.IsComObject(connections))
            {
                _bridge.Release(connections);
            }

            if (manager is not null && _bridge.IsComObject(manager))
            {
                _bridge.Release(manager);
            }
        }
    }
}

internal interface IWindowsNetworkListComBridge
{
    object? CreateManager(Guid clsid);

    object? GetNetworkConnections(object manager);

    object? GetAdapterId(object connection);

    object? GetNetwork(object connection);

    object? GetCategory(object network);

    bool IsComObject(object target);

    void Release(object target);
}

internal sealed class ReflectionWindowsNetworkListComBridge : IWindowsNetworkListComBridge
{
    public object? CreateManager(Guid clsid)
    {
        var managerType = Type.GetTypeFromCLSID(clsid);
        return managerType is null ? null : Activator.CreateInstance(managerType);
    }

    public object? GetNetworkConnections(object manager) =>
        Invoke(manager, "GetNetworkConnections");

    public object? GetAdapterId(object connection) =>
        Invoke(connection, "GetAdapterId");

    public object? GetNetwork(object connection) =>
        Invoke(connection, "GetNetwork");

    public object? GetCategory(object network) =>
        Invoke(network, "GetCategory");

    public bool IsComObject(object target) => Marshal.IsComObject(target);

    public void Release(object target) => Marshal.ReleaseComObject(target);

    private static object? Invoke(object target, string method)
    {
        try
        {
            return InvokeNoArgs(target, method);
        }
        catch (TargetParameterCountException)
        {
            return InvokeSingleOutArgument(target, method);
        }
        catch (TargetInvocationException exception)
            when (exception.InnerException is TargetParameterCountException or
                ArgumentException or
                MissingMethodException)
        {
            return InvokeSingleOutArgument(target, method);
        }
        catch (ArgumentException)
        {
            return InvokeSingleOutArgument(target, method);
        }
        catch (MissingMethodException)
        {
            return InvokeSingleOutArgument(target, method);
        }
    }

    private static object? InvokeNoArgs(object target, string method) =>
        target.GetType().InvokeMember(
            method,
            BindingFlags.InvokeMethod,
            null,
            target,
            null);

    private static object? InvokeSingleOutArgument(object target, string method)
    {
        object?[] args = [null];
        var modifier = new ParameterModifier(1);
        modifier[0] = true;

        var result = target.GetType().InvokeMember(
            method,
            BindingFlags.InvokeMethod,
            null,
            target,
            args,
            [modifier],
            null,
            null);

        return result ?? args[0];
    }
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
