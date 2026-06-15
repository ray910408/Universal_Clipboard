using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using FluentAssertions;
using UniversalClipboard.App.Web;

namespace UniversalClipboard.App.Tests.Web;

public sealed partial class MobileAssetsTests
{
    [Fact]
    public void Browser_contract_drives_polling_clearing_pairing_and_copy_states()
    {
        var script = ReadAsset("/app.js");
        using var contract = ReadContract(script);
        var root = contract.RootElement;

        root.GetProperty("pollIntervalMs").GetInt32().Should().Be(1_000);
        root.GetProperty("maxItems").GetInt32().Should().Be(3);
        root.GetProperty("clearOn").EnumerateArray()
            .Select(value => value.GetString())
            .Should().BeEquivalentTo(
                "hidden",
                "pagehide",
                "unauthorized",
                "pairing",
                "pageshow");
        root.GetProperty("pairing").GetProperty("fragmentKey").GetString().Should().Be("code");
        root.GetProperty("pairing").GetProperty("cleanPath").GetString().Should().Be("/pair");
        root.GetProperty("pairing").GetProperty("cleanupBeforePost").GetBoolean().Should().BeTrue();
        root.GetProperty("pairing").GetProperty("clearVariableFinally").GetBoolean()
            .Should().BeTrue();
        root.GetProperty("copy").GetProperty("confirmed").GetString().Should().Be("Copied");
        root.GetProperty("copy").GetProperty("fallback").GetString().Should().Be(
            "Copy requested - verify, or long-press and choose Copy");
        root.GetProperty("incoming").GetProperty("endpoint").GetString()
            .Should().Be("/clip-api/incoming-text");
        root.GetProperty("incoming").GetProperty("storageKey").GetString()
            .Should().Be("uc.permission");
        root.GetProperty("incoming").GetProperty("readPermissions").EnumerateArray()
            .Select(value => value.GetString())
            .Should().Equal("read", "readWrite");
        root.GetProperty("incoming").GetProperty("writePermissions").EnumerateArray()
            .Select(value => value.GetString())
            .Should().Equal("write", "readWrite");
        root.GetProperty("incoming").GetProperty("disabled").GetString()
            .Should().Contain("Write enabled");
        root.GetProperty("incoming").GetProperty("queued").GetString()
            .Should().Be("Pending in Windows tray.");
    }

    [Fact]
    public void Browser_contract_maps_sensitive_lifecycle_events_to_explicit_state_actions()
    {
        using var contract = ReadContract(ReadAsset("/app.js"));
        var transitions = contract.RootElement.GetProperty("transitions");

        ReadActions(transitions, "hidden").Should().Equal(
            "stopPolling",
            "clearClipboardDom",
            "resetIdentity");
        ReadActions(transitions, "pagehide").Should().Equal(
            "stopPolling",
            "clearClipboardDom",
            "resetIdentity");
        ReadActions(transitions, "unauthorized").Should().Equal(
            "stopPolling",
            "clearClipboardDom",
            "resetIdentity",
            "showPairing");
        ReadActions(transitions, "pairing").Should().Equal(
            "stopPolling",
            "clearClipboardDom",
            "resetIdentity",
            "showLoading");
        ReadActions(transitions, "pageshow").Should().Equal(
            "stopPolling",
            "clearClipboardDom",
            "resetIdentity",
            "showLoading",
            "pollFull");
        ReadActions(transitions, "error").Should().Equal(
            "clearClipboardDom",
            "resetIdentity",
            "showError");
    }

    [Fact]
    public void Pageshow_is_the_single_initial_and_bfcache_refresh_trigger()
    {
        var script = ReadAsset("/app.js");
        using var contract = ReadContract(script);

        contract.RootElement.GetProperty("bootstrapEvent").GetString().Should().Be("pageshow");
        Regex.Matches(
                script,
                "addEventListener\\(CONTRACT\\.bootstrapEvent",
                RegexOptions.CultureInvariant)
            .Should().HaveCount(1);
        script.Should().NotContain("addEventListener(\"DOMContentLoaded\"");
    }

    [Fact]
    public void Lifecycle_interpreter_implements_every_declared_contract_action()
    {
        var script = ReadAsset("/app.js");
        using var contract = ReadContract(script);
        var interpreter = ExtractFunction(script, "applyLifecycleTransition");
        var actions = contract.RootElement.GetProperty("transitions")
            .EnumerateObject()
            .SelectMany(transition => transition.Value.EnumerateArray())
            .Select(action => action.GetString()!)
            .Distinct(StringComparer.Ordinal);

        foreach (var action in actions)
        {
            interpreter.Should().Contain($"case \"{action}\":");
        }
    }

    [Theory]
    [InlineData("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcY", true)]
    [InlineData("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhc=", false)]
    [InlineData("short", false)]
    [InlineData("AQIDBAUGBwgJCgsMDQ4PEBESExQVFhc!", false)]
    public void Pairing_code_pattern_accepts_only_canonical_base64url(string code, bool expected)
    {
        using var contract = ReadContract(ReadAsset("/app.js"));
        var pattern = contract.RootElement.GetProperty("pairing")
            .GetProperty("codePattern").GetString();

        Regex.IsMatch(code, pattern!, RegexOptions.CultureInvariant).Should().Be(expected);
    }

    [Fact]
    public void Pairing_flow_cleans_fragment_before_post_and_clears_mutable_code_in_finally()
    {
        var function = ExtractFunction(ReadAsset("/app.js"), "exchangePairingFragment");

        Regex.Matches(
                function,
                @"\bpostPairingCode\(",
                RegexOptions.CultureInvariant)
            .Should().HaveCount(1);
        function.IndexOf("pattern.test", StringComparison.Ordinal)
            .Should().BeLessThan(function.IndexOf("history.replaceState", StringComparison.Ordinal));
        function.IndexOf("history.replaceState", StringComparison.Ordinal)
            .Should().BeLessThan(function.IndexOf("postPairingCode", StringComparison.Ordinal));
        function.Should().Contain("finally");
        function.Should().MatchRegex(@"finally\s*\{[^}]*pairingCode\s*=\s*""""");
        function.Should().Contain("URLSearchParams");
    }

    [Fact]
    public void Pairing_post_sends_device_and_browser_metadata_without_permission_escalation()
    {
        var script = ReadAsset("/app.js");
        var function = ExtractFunction(script, "postPairingCode");

        function.Should().Contain("deviceName");
        function.Should().Contain("browserName");
        function.Should().NotContain("permission");
        script.Should().Contain("function detectDeviceName()");
        script.Should().Contain("function detectBrowserName()");
    }

    [Fact]
    public void Send_to_windows_flow_requires_write_permission_and_posts_authenticated_json()
    {
        var script = ReadAsset("/app.js");
        using var contract = ReadContract(script);
        var sendFunction = ExtractFunction(script, "sendIncomingText");
        var permissionFunction = ExtractFunction(script, "canSendToWindows");
        var readPermissionFunction = ExtractFunction(script, "canReadFromWindows");
        var pollFunction = ExtractFunction(script, "pollClips");

        contract.RootElement.GetProperty("incoming").GetProperty("endpoint").GetString()
            .Should().Be("/clip-api/incoming-text");
        permissionFunction.Should().Contain("CONTRACT.incoming.writePermissions.includes");
        readPermissionFunction.Should().Contain("permission === null");
        readPermissionFunction.Should().Contain("CONTRACT.incoming.readPermissions.includes");
        pollFunction.Should().Contain("!canReadFromWindows");
        pollFunction.Should().Contain("renderItems([]);");
        pollFunction.Should().Contain("response.status === 403");
        sendFunction.Should().Contain("CONTRACT.incoming.endpoint");
        sendFunction.Should().Contain("\"Content-Type\": \"application/json\"");
        sendFunction.Should().Contain("...sessionHeaders()");
        sendFunction.Should().Contain("response.status === 401");
        sendFunction.Should().Contain("response.status === 403");
        sendFunction.Should().NotContain("innerHTML");
    }

    [Fact]
    public void Rendering_and_copy_paths_do_not_claim_unconfirmed_success()
    {
        var script = ReadAsset("/app.js");
        var copyFunction = ExtractFunction(script, "copySelectedText");
        var renderFunction = ExtractFunction(script, "renderItems");

        script.Should().NotContain("innerHTML");
        script.Should().NotContain("setInterval");
        renderFunction.Should().Contain(".textContent");
        copyFunction.IndexOf("await navigator.clipboard.writeText", StringComparison.Ordinal)
            .Should().BeLessThan(
                copyFunction.IndexOf("CONTRACT.copy.confirmed", StringComparison.Ordinal));
        copyFunction.Should().Contain("selectFallbackText");
        copyFunction.Should().Contain("CONTRACT.copy.fallback");
        copyFunction.Should().NotContain("execCommand(\"copy\") ?");
    }

    [Fact]
    public void Polling_only_clears_the_controller_owned_by_that_request()
    {
        var function = ExtractFunction(ReadAsset("/app.js"), "pollClips");

        function.Should().Contain("const requestController = new AbortController()");
        function.Should().Contain("signal: requestController.signal");
        function.Should().Contain("if (activeRequest === requestController)");
    }

    [Fact]
    public void Html_has_semantic_states_http_warning_and_only_local_resources()
    {
        var html = ReadAsset("/");

        foreach (var state in new[] { "pairing", "loading", "empty", "error", "items" })
        {
            html.Should().Contain($"data-state=\"{state}\"");
        }

        html.Should().Contain("HTTP");
        html.Should().Contain("<textarea");
        html.Should().Contain("readonly");
        html.Should().Contain("id=\"incoming-text\"");
        html.Should().Contain("id=\"incoming-send\"");
        html.Should().Contain("Send to Windows");
        var resourceTargets = ResourceReferenceRegex().Matches(html)
            .Select(match => match.Groups["target"].Value)
            .ToArray();
        resourceTargets.Should().NotBeEmpty();
        resourceTargets.Should().OnlyContain(
            target => target.StartsWith("/", StringComparison.Ordinal));
        html.Should().NotContain("https://");
        html.Should().NotContain("http://");
    }

    private static string ReadAsset(string path)
    {
        var asset = WebAssets.Get(path);
        asset.Should().NotBeNull();
        return Encoding.UTF8.GetString(asset!.Value.Bytes);
    }

    private static JsonDocument ReadContract(string script)
    {
        const string startMarker = "/* app-contract:start */";
        const string endMarker = "/* app-contract:end */";
        var start = script.IndexOf(startMarker, StringComparison.Ordinal);
        var end = script.IndexOf(endMarker, StringComparison.Ordinal);
        start.Should().BeGreaterThanOrEqualTo(0);
        end.Should().BeGreaterThan(start);
        var jsonStart = start + startMarker.Length;
        return JsonDocument.Parse(script[jsonStart..end].Trim());
    }

    private static string[] ReadActions(JsonElement transitions, string eventName) =>
        transitions.GetProperty(eventName)
            .EnumerateArray()
            .Select(action => action.GetString()!)
            .ToArray();

    private static string ExtractFunction(string script, string name)
    {
        var signature = $"function {name}";
        var start = script.IndexOf(signature, StringComparison.Ordinal);
        start.Should().BeGreaterThanOrEqualTo(0);
        var brace = script.IndexOf('{', start);
        brace.Should().BeGreaterThan(start);
        var depth = 0;
        var quote = '\0';
        var escaped = false;

        for (var index = brace; index < script.Length; index++)
        {
            var character = script[index];
            if (quote != '\0')
            {
                if (escaped)
                {
                    escaped = false;
                }
                else if (character == '\\')
                {
                    escaped = true;
                }
                else if (character == quote)
                {
                    quote = '\0';
                }

                continue;
            }

            if (character is '\'' or '"' or '`')
            {
                quote = character;
            }
            else if (character == '{')
            {
                depth++;
            }
            else if (character == '}' && --depth == 0)
            {
                return script[start..(index + 1)];
            }
        }

        throw new InvalidDataException($"Function {name} is not balanced.");
    }

    [GeneratedRegex("(?:src|href)=\"(?<target>[^\"]+)\"", RegexOptions.CultureInvariant)]
    private static partial Regex ResourceReferenceRegex();
}
