using System.IO;
using System.Text.Json;

namespace UniversalClipboard.App.Network;

// IsTailscale lets a restart tell a saved tailnet choice that is not up yet from a LAN
// choice that is gone: only a LAN choice may fall back to another interface.
public sealed record NetworkInterfaceChoice(string InterfaceId, bool IsTailscale);

// Unlike the DPAPI stores this is plain JSON: an adapter ID is not secret (any local
// process can enumerate it), and a lost or corrupt file only means picking again.
public sealed class NetworkInterfaceChoiceStore(string? path = null)
{
    private readonly string _path = path ?? DefaultPath;

    public static string DefaultPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "UniversalClipboard",
            "network-interface.v1.json");

    public NetworkInterfaceChoice? Load()
    {
        try
        {
            if (!File.Exists(_path))
            {
                return null;
            }

            var choice = JsonSerializer.Deserialize<NetworkInterfaceChoice>(File.ReadAllBytes(_path));
            return string.IsNullOrWhiteSpace(choice?.InterfaceId) ? null : choice;
        }
        catch (Exception exception) when (
            exception is JsonException or IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    // Best-effort: failing to save only means picking the interface again after a restart.
    public void Save(NetworkInterfaceChoice choice)
    {
        var temporaryPath = _path + ".tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
            File.WriteAllBytes(temporaryPath, JsonSerializer.SerializeToUtf8Bytes(choice));
            File.Move(temporaryPath, _path, overwrite: true);
        }
        catch (Exception exception) when (
            exception is IOException or UnauthorizedAccessException)
        {
        }
    }
}
