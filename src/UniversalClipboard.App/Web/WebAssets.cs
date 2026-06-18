using System.Reflection;

namespace UniversalClipboard.App.Web;

internal static class WebAssets
{
    private const string ResourceRoot = "UniversalClipboard.App.wwwroot";

    public static (string ContentType, byte[] Bytes)? Get(string path)
    {
        var fileName = path switch
        {
            "/" or "/pair" => "index.html",
            "/app.css" => "app.css",
            "/app.js" => "app.js",
            _ => null,
        };
        if (fileName is null)
        {
            return null;
        }

        var assembly = typeof(WebAssets).Assembly;
        var resourceName = $"{ResourceRoot}.{fileName}";
        using var stream = assembly.GetManifestResourceStream(resourceName)
            ?? throw new InvalidOperationException($"Missing embedded web asset {fileName}.");
        using var memory = new MemoryStream();
        stream.CopyTo(memory);
        var contentType = Path.GetExtension(fileName) switch
        {
            ".html" => "text/html; charset=utf-8",
            ".css" => "text/css; charset=utf-8",
            ".js" => "text/javascript; charset=utf-8",
            _ => "application/octet-stream",
        };
        return (contentType, memory.ToArray());
    }
}
