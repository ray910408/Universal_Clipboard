using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Drawing;
using System.Drawing.Imaging;
using System.Net;
using System.Text;
using System.Windows.Forms;
using FluentAssertions;
using UniversalClipboard.App;
using UniversalClipboard.App.App;
using UniversalClipboard.App.Clipboard;
using UniversalClipboard.App.Network;
using UniversalClipboard.App.Ui;
using UniversalClipboard.App.Web;
using UniversalClipboard.Core.Authorization;
using UniversalClipboard.Core.Clipboard;

namespace UniversalClipboard.App.Tests.App;

public sealed class ApplicationCompositionTests
{
    [Fact]
    public async Task Sharing_state_url_default_duration_qr_and_firewall_are_presented()
    {
        var fixture = new Fixture();
        fixture.Sharing.State = RunningState(
            "https://192.168.1.5:43127/",
            FirewallRuleStatus.Unknown);

        await fixture.Context.StartSharingAsync();
        fixture.Context.CreatePairingCode();

        fixture.Window.State.ServiceStatus.Should().Be("Running");
        fixture.Window.State.SelectedUrl.Should().Be("https://192.168.1.5:43127/");
        fixture.Window.State.SelectedDuration.Should().Be(AuthorizationDuration.FiveHours);
        fixture.Window.State.FirewallStatus.Should().Be("Unknown - test from iPhone");
        fixture.Window.State.NetworkProfile.Should().Be("Private");
        fixture.Window.State.PortListeningStatus.Should().Be("Listening on TCP 43127");
        fixture.Window.State.FirewallSetupHelp.Should().Be("docs/firewall-setup.md");
        fixture.Window.State.Pairing.Should().NotBeNull();
        fixture.Window.State.Pairing!.PairingUrl.Should().Be(
            "https://192.168.1.5:43127/pair#code=pair-code");
        fixture.Qr.Payloads.Should().Equal(fixture.Window.State.Pairing.PairingUrl);
        fixture.Window.State.Pairing.QrCodePng.Should().Equal(
            Encoding.UTF8.GetBytes("qr:https://192.168.1.5:43127/pair#code=pair-code"));
    }

    [Fact]
    public void Paired_browser_rows_have_stable_unique_suffixes()
    {
        var first = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var second = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var fixture = new Fixture();
        fixture.Authorizations.Authorizations =
        [
            Metadata(first, "Safari"),
            Metadata(second, "Safari"),
        ];

        fixture.Context.RefreshView();

        fixture.Window.State.PairedBrowsers.Select(row => row.AuthorizationIdSuffix)
            .Should().Equal("ERERERER", "IiIiIiIi");
        fixture.Window.State.PairedBrowsers[0].DisplayName.Should().Contain("Id: ERERERER");
        fixture.Window.State.PairedBrowsers[1].DisplayName.Should().Contain("Id: IiIiIiIi");
    }

    [Fact]
    public void Paired_browser_suffixes_extend_until_they_are_unique()
    {
        var first = Guid.Parse("aaaaaaaa-bbbb-1111-1111-111111111111");
        var second = Guid.Parse("aaaaaaaa-bbbb-2222-2222-222222222222");
        var fixture = new Fixture();
        fixture.Authorizations.Authorizations =
        [
            Metadata(first, "Safari"),
            Metadata(second, "Safari"),
        ];

        fixture.Context.RefreshView();

        fixture.Window.State.PairedBrowsers.Select(row => row.AuthorizationIdSuffix)
            .Should().OnlyContain(suffix => suffix.Length == 12);
        fixture.Window.State.PairedBrowsers.Select(row => row.AuthorizationIdSuffix)
            .Should().OnlyHaveUniqueItems();
    }

    [Fact]
    public void Permanent_authorizations_are_shown_as_until_revoked_with_created_time()
    {
        var authorizationId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var fixture = new Fixture();
        fixture.Authorizations.Authorizations =
        [
            Metadata(authorizationId, "Safari", permanent: true),
        ];

        fixture.Context.RefreshView();

        var row = fixture.Window.State.PairedBrowsers.Single();
        row.Label.Should().Be("Safari");
        row.CreatedAtUtc.Should().Be(
            new DateTimeOffset(2026, 6, 12, 0, 0, 0, TimeSpan.Zero));
        row.Expiry.Should().Be("Until revoked");
        row.DisplayName.Should().Contain("Until revoked");
    }

    [Fact]
    public void Startup_registers_clipboard_listener_after_async_sharing_has_started_without_pumped_context()
    {
        var events = new ConcurrentQueue<string>();
        var synchronizationContext = new NonPumpingSynchronizationContext();
        Exception? exception = null;
        object? monitor = null;
        RecordingTrayWindow? window = null;
        var callerThreadId = -1;
        var refreshThreadId = -1;
        var registerThreadId = -1;

        var thread = new Thread(() =>
        {
            try
            {
                SynchronizationContext.SetSynchronizationContext(synchronizationContext);
                callerThreadId = Environment.CurrentManagedThreadId;
                var fixture = new Fixture();
                fixture.Sharing.State = RunningState(
                    "https://192.168.1.5:43127/",
                    FirewallRuleStatus.Unknown);
                fixture.Sharing.CompleteStartAsynchronously = true;
                fixture.Sharing.StartEntered = () => events.Enqueue("sharing:start");
                fixture.Sharing.StartCompleted = () => events.Enqueue("sharing:started");

                monitor = Program.StartSharingThenRegisterClipboard(
                    fixture.Sharing,
                    () =>
                    {
                        refreshThreadId = Environment.CurrentManagedThreadId;
                        events.Enqueue("refresh");
                        fixture.Context.RefreshView();
                    },
                    () =>
                    {
                        registerThreadId = Environment.CurrentManagedThreadId;
                        events.Enqueue("clipboard:register");
                        return new object();
                    });
                window = fixture.Window;
            }
            catch (Exception caught)
            {
                exception = caught;
            }
        });
        thread.IsBackground = true;
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();

        thread.Join(TimeSpan.FromSeconds(5)).Should().BeTrue(
            "startup sharing must not wait for a pre-message-loop WinForms context to pump");
        exception.Should().BeNull();
        monitor.Should().NotBeNull();
        synchronizationContext.PostCount.Should().Be(0);
        events.Should().Equal(
            "sharing:start",
            "sharing:started",
            "refresh",
            "clipboard:register");
        refreshThreadId.Should().Be(callerThreadId);
        registerThreadId.Should().Be(callerThreadId);
        window!.State.ServiceStatus.Should().Be("Running");
    }

    [Fact]
    public async Task Tray_exit_unregisters_clipboard_listener_before_shutdown_clears_content()
    {
        var fixture = new Fixture();
        fixture.Context.OnClipboardText("shared item");
        DisposableProbe? monitor = new(() => fixture.Sharing.Events.Enqueue("monitor:dispose"));

        await Program.ShutdownFromTrayAsync(
            () => monitor,
            value => monitor = value,
            () => fixture.Context);

        monitor.Should().BeNull();
        fixture.Sharing.Events.Should().ContainInOrder(
            "monitor:dispose",
            "sharing:shutdown",
            "clipboard:clear");
        fixture.Clipboard.ClearCount.Should().Be(1);
    }

    [Fact]
    public void Secondary_pipe_failure_exits_without_blocking_error_reporter()
    {
        var reports = new List<string>();
        var result = new SingleInstanceCoordinatorResult(
            SingleInstanceRole.SecondaryPipeUnavailable,
            null,
            null,
            "Existing Universal Clipboard instance did not accept ShowTray within 2 seconds.");

        var shouldContinue = Program.ShouldContinueStartupAfterSingleInstanceResult(
            result,
            reports.Add);

        shouldContinue.Should().BeFalse();
        reports.Should().BeEmpty();
    }

    [Fact]
    public void Program_shutdown_disposes_tray_resources()
    {
        var disposed = new List<string>();

        Program.DisposeTrayWindow(new DisposableProbe(() => disposed.Add("tray:dispose")));

        disposed.Should().Equal("tray:dispose");
    }

    [Fact]
    public void Tray_window_names_paired_devices_permission_and_incoming_lists()
    {
        using var window = new TrayWindow();

        window.Controls.OfType<Label>()
            .Select(label => label.Text)
            .Should()
            .Contain(
                "Paired devices",
                "Permission",
                "Pending incoming text");
    }

    [Fact]
    public void Tray_window_keeps_pending_actions_separate_from_global_commands()
    {
        using var window = new TrayWindow();
        var pendingActions = Buttons(
            window,
            "Allow once",
            "Discard",
            "Apply to Windows Clipboard",
            "Discard incoming");
        var globalCommands = Buttons(
            window,
            "Start",
            "Stop",
            "Pair",
            "Revoke",
            "Revoke all",
            "Exit");

        foreach (var pendingAction in pendingActions)
        {
            foreach (var globalCommand in globalCommands)
            {
                pendingAction.Bounds.IntersectsWith(globalCommand.Bounds)
                    .Should()
                    .BeFalse($"{pendingAction.Text} should not overlap {globalCommand.Text}");
            }
        }

        foreach (var button in pendingActions.Concat(globalCommands))
        {
            button.Bottom
                .Should()
                .BeLessThanOrEqualTo(window.ClientSize.Height, $"{button.Text} should stay inside the tray window");
        }
    }

    [Fact]
    public void Tray_window_dispose_hides_notify_icon()
    {
        var window = new TrayWindow();

        window.Dispose();

        window.IsNotifyIconVisibleForTests.Should().BeFalse();
    }

    [Fact]
    public void Tray_window_incoming_command_events_are_not_noop()
    {
        using var window = new TrayWindow();
        var incomingId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var applied = new List<Guid>();
        var discarded = new List<Guid>();

        window.ApplyIncomingRequested += (_, id) => applied.Add(id);
        window.DiscardIncomingRequested += (_, id) => discarded.Add(id);

        window.RaiseApplyIncoming(incomingId);
        window.RaiseDiscardIncoming(incomingId);

        applied.Should().Equal(incomingId);
        discarded.Should().Equal(incomingId);
    }


    [Fact]
    public void Tray_window_rendering_interface_options_does_not_select_an_interface()
    {
        using var window = new TrayWindow();
        var selected = new List<string>();
        window.InterfaceSelected += (_, interfaceId) => selected.Add(interfaceId);
        var state = TrayViewState.Empty with
        {
            ServiceStatus = "Select interface",
            InterfaceOptions =
            [
                new NetworkInterfaceOptionRow("wifi", "Wi-Fi - 192.168.1.5"),
                new NetworkInterfaceOptionRow("eth", "Ethernet - 10.0.0.5"),
            ],
        };

        window.Render(state);

        selected.Should().BeEmpty();
    }

    [Fact]
    public void Tray_window_clones_qr_image_for_stable_rendering()
    {
        using var window = new TrayWindow();
        var state = TrayViewState.Empty with
        {
            Pairing = new PairingViewState(
                "https://192.168.1.5:43127/pair#code=pair-code",
                CreatePngBytes(),
                DateTimeOffset.UtcNow.AddMinutes(2)),
        };

        window.Render(state);

        var image = window.Controls.OfType<PictureBox>().Single().Image;
        image.Should().NotBeNull();
        using var saved = new MemoryStream();
        image!.Save(saved, ImageFormat.Png);
        saved.Length.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task Tray_command_failures_are_reported_without_escaping_event_handler()
    {
        var fixture = new Fixture();
        fixture.Sharing.ThrowStart = true;

        fixture.Window.RaiseStartSharingRequested();
        await WaitUntilAsync(() => fixture.Notifications.Items.Count == 1);

        fixture.Notifications.Items.Single().Title.Should().Be(
            "Universal Clipboard command failed");
        fixture.Notifications.Items.Single().Body.Should().NotContain("boom");
        fixture.Window.ShowCount.Should().Be(1);
    }

    [Fact]
    public async Task Local_host_controller_does_not_dispose_host_after_incomplete_stop()
    {
        var host = new RecordingLocalWebHostInstance(LocalWebHostStopResult.Incomplete);
        await using var controller = new LocalWebHostController(
            new UnsupportedAuthorizationService(),
            () => new ClipboardSnapshot(
                Guid.NewGuid(),
                0,
                ImmutableArray<ClipboardItem>.Empty),
            () => AuthorizationDuration.FiveHours,
            hostFactory: _ => host);

        await controller.StartAsync(
            new IPEndPoint(IPAddress.Parse("192.168.1.5"), 43127),
            CancellationToken.None);
        var stop = async () => await controller.StopAsync(CancellationToken.None);

        await stop.Should().ThrowAsync<LocalWebHostShutdownIncompleteException>();
        host.StopCount.Should().Be(1);
        host.DisposeCount.Should().Be(0);
    }

    [Fact]
    public async Task Revoke_one_and_all_wait_for_durable_authorization_results()
    {
        var first = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var second = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var fixture = new Fixture();
        fixture.Authorizations.Authorizations =
        [
            Metadata(first, "Safari"),
            Metadata(second, "Chrome"),
        ];
        fixture.Authorizations.BlockRevoke = true;
        fixture.Context.RefreshView();

        var revokeOne = fixture.Context.RevokeAsync(first);
        await fixture.Authorizations.RevokeEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Window.State.PairedBrowsers.Should().HaveCount(2);
        fixture.Authorizations.CompleteRevoke();
        await revokeOne.WaitAsync(TimeSpan.FromSeconds(5));
        fixture.Window.State.PairedBrowsers.Should().ContainSingle()
            .Which.AuthorizationId.Should().Be(second);

        fixture.Authorizations.BlockRevokeAll = true;
        var revokeAll = fixture.Context.RevokeAllAsync();
        await fixture.Authorizations.RevokeAllEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Window.State.PairedBrowsers.Should().ContainSingle();
        fixture.Authorizations.CompleteRevokeAll();
        await revokeAll.WaitAsync(TimeSpan.FromSeconds(5));
        fixture.Window.State.PairedBrowsers.Should().BeEmpty();
    }

    [Fact]
    public void Clipboard_notifications_never_disclose_sensitive_or_rejected_content()
    {
        var fixture = new Fixture();
        var sensitive = "GitHub token ghp_abcdefghijklmnopqrstuvwxyz0123456789AB";
        var overLimit = new string('x', StrictUtf8TextValidator.MaxUtf8Bytes + 1);
        var invalidUtf16 = "\ud800secret";

        fixture.Context.OnClipboardText(sensitive);
        fixture.Context.OnClipboardText(overLimit);
        fixture.Context.OnClipboardText(invalidUtf16);

        fixture.Notifications.Items.Should().HaveCount(3);
        fixture.Notifications.Items[0].Title.Should().Be("Possible sensitive content detected");
        fixture.Notifications.Items[0].Body.Should().Contain("GitHub token");
        fixture.Notifications.Items[0].Body.Should().Contain("[masked");
        fixture.Notifications.Items[0].Body.Should().NotContain(sensitive);
        fixture.Notifications.Items.Select(item => item.Body).Should().NotContain(body =>
            body.Contains(overLimit, StringComparison.Ordinal) ||
            body.Contains("secret", StringComparison.Ordinal));
    }

    [Fact]
    public void Exhausted_clipboard_retries_increment_content_free_diagnostics()
    {
        var fixture = new Fixture();

        fixture.Context.OnClipboardReadExhausted(new ClipboardReadDiagnostic(4));
        fixture.Context.OnClipboardReadExhausted(new ClipboardReadDiagnostic(4));

        fixture.Window.State.ClipboardRetryExhaustionCount.Should().Be(2);
        fixture.Notifications.Items.Select(item => item.Body)
            .Should().OnlyContain(body => !body.Contains("clipboard", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void Allow_discard_and_withdraw_update_presented_clipboard_state()
    {
        var fixture = new Fixture();
        fixture.Context.OnClipboardText("shared item");
        fixture.Context.OnClipboardText("GitHub token ghp_abcdefghijklmnopqrstuvwxyz0123456789AB");
        fixture.Context.OnClipboardText("AWS key AKIAIOSFODNN7EXAMPLE");

        var sharedId = fixture.Window.State.SharedItems.Single().ItemId;
        var pendingIds = fixture.Window.State.PendingSensitiveItems.Select(item => item.ItemId).ToArray();

        fixture.Context.AllowPending(pendingIds[0]);
        fixture.Context.DiscardPending(pendingIds[1]);
        fixture.Context.WithdrawShared(sharedId);

        fixture.Window.State.SharedItems.Should().ContainSingle()
            .Which.ItemId.Should().Be(pendingIds[0]);
        fixture.Window.State.PendingSensitiveItems.Should().BeEmpty();
    }

    [Fact]
    public void Paired_device_rows_display_metadata_last_access_expiry_and_permissions()
    {
        var authorizationId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var fixture = new Fixture();
        fixture.Authorizations.Authorizations =
        [
            Metadata(
                authorizationId,
                "iPhone Safari",
                deviceName: "Kenneth's iPhone",
                browserName: "Safari",
                lastAccessedAtUtc: new DateTimeOffset(2026, 6, 12, 1, 5, 0, TimeSpan.Zero),
                permissions: AuthorizationPermissions.ReadWrite),
        ];

        fixture.Context.RefreshView();

        var row = fixture.Window.State.PairedBrowsers.Should().ContainSingle().Subject;
        row.DeviceName.Should().Be("Kenneth's iPhone");
        row.BrowserName.Should().Be("Safari");
        row.Created.Should().Be("2026-06-12 00:00 UTC");
        row.LastAccessed.Should().Be("2026-06-12 01:05 UTC");
        row.Expiry.Should().Be("2026-06-12 05:00 UTC");
        row.Permissions.Should().Be("Read / Write");
        row.DisplayName.Should().Contain("Device: Kenneth's iPhone");
        row.DisplayName.Should().Contain("Browser: Safari");
        row.DisplayName.Should().Contain("Last access: 2026-06-12 01:05 UTC");
    }

    [Fact]
    public void Paired_device_rows_show_never_for_missing_last_access()
    {
        var fixture = new Fixture();
        fixture.Authorizations.Authorizations =
        [
            Metadata(Guid.Parse("11111111-1111-1111-1111-111111111111"), "Legacy Safari"),
        ];

        fixture.Context.RefreshView();

        fixture.Window.State.PairedBrowsers.Single().LastAccessed.Should().Be("Never");
    }

    [Fact]
    public void Incoming_text_appears_as_masked_pending_row_and_content_free_notification()
    {
        var authorizationId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var fixture = new Fixture();
        fixture.Authorizations.Authorizations =
        [
            Metadata(
                authorizationId,
                "Safari",
                deviceName: "Kenneth's iPhone",
                browserName: "Safari",
                permissions: AuthorizationPermissions.Write),
        ];

        var item = fixture.Context.EnqueueIncomingText(
            authorizationId,
            "Kenneth's iPhone",
            "Safari",
            "secret from phone");

        var row = fixture.Window.State.PendingIncomingItems.Should().ContainSingle().Subject;
        row.ItemId.Should().Be(item.IncomingId);
        row.AuthorizationId.Should().Be(authorizationId);
        row.DisplayName.Should().Contain("Kenneth's iPhone");
        row.DisplayName.Should().Contain("Safari");
        row.MaskedPreview.Should().Be("[masked 17 chars]");
        row.MaskedPreview.Should().NotContain("secret from phone");
        fixture.Notifications.Items.Should().ContainSingle()
            .Which.Title.Should().Be("Pending incoming text");
        fixture.Notifications.Items.Single().Body.Should().NotContain("secret from phone");
    }

    [Fact]
    public void Apply_incoming_writes_exact_text_and_clears_item()
    {
        var fixture = new Fixture();
        var item = fixture.Context.EnqueueIncomingText(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "Phone",
            "Safari",
            "exact incoming text");

        fixture.Context.ApplyIncoming(item.IncomingId);

        fixture.IncomingClipboard.Writes.Should().Equal("exact incoming text");
        fixture.Window.State.PendingIncomingItems.Should().BeEmpty();
    }

    [Fact]
    public void Apply_incoming_does_not_republish_the_same_clipboard_event_to_iphone()
    {
        var fixture = new Fixture();
        var item = fixture.Context.EnqueueIncomingText(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "Phone",
            "Safari",
            "incoming roundtrip");

        fixture.Context.ApplyIncoming(item.IncomingId);
        fixture.Context.OnClipboardText("incoming roundtrip");

        fixture.Window.State.SharedItems.Should().BeEmpty();
        fixture.Context.OnClipboardText("user copied later");
        fixture.Window.State.SharedItems.Should().ContainSingle()
            .Which.Preview.Should().Be("user copied later");
    }

    [Fact]
    public void Apply_incoming_suppresses_clipboard_event_that_arrives_during_windows_write()
    {
        // Regression: ISSUE-001 - Apply to Windows echoed incoming phone text back to the phone.
        // Found by /qa on 2026-06-15.
        // Report: user-reported phone QA in this thread.
        var fixture = new Fixture();
        var item = fixture.Context.EnqueueIncomingText(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "Phone",
            "Safari",
            "incoming reentrant");
        fixture.IncomingClipboard.OnSetText = text => fixture.Context.OnClipboardText(text);

        fixture.Context.ApplyIncoming(item.IncomingId);

        fixture.Window.State.SharedItems.Should().BeEmpty();
        fixture.Window.State.PendingIncomingItems.Should().BeEmpty();
        fixture.IncomingClipboard.Writes.Should().Equal("incoming reentrant");
    }

    [Fact]
    public void Apply_incoming_suppresses_repeated_clipboard_echo_events_in_window()
    {
        var fixture = new Fixture();
        var item = fixture.Context.EnqueueIncomingText(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "Phone",
            "Safari",
            "repeated echo");

        fixture.Context.ApplyIncoming(item.IncomingId);
        fixture.Context.OnClipboardText("repeated echo");
        fixture.Context.OnClipboardText("repeated echo");

        fixture.Window.State.SharedItems.Should().BeEmpty();
    }

    [Fact]
    public void Apply_incoming_stale_suppression_does_not_block_same_text_later()
    {
        var fixture = new Fixture();
        var item = fixture.Context.EnqueueIncomingText(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "Phone",
            "Safari",
            "same text later");

        fixture.Context.ApplyIncoming(item.IncomingId);
        fixture.Clock.Advance(
            ClipboardApplicationContext.ClipboardApplyEchoSuppressionWindow + TimeSpan.FromMilliseconds(1));
        fixture.Context.OnClipboardText("same text later");

        fixture.Window.State.SharedItems.Should().ContainSingle()
            .Which.Preview.Should().Be("same text later");
    }

    [Fact]
    public void Apply_incoming_preserves_item_when_windows_clipboard_write_fails()
    {
        var fixture = new Fixture();
        var item = fixture.Context.EnqueueIncomingText(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "Phone",
            "Safari",
            "retry later");
        fixture.IncomingClipboard.ThrowOnSetText = true;

        var act = () => fixture.Context.ApplyIncoming(item.IncomingId);

        act.Should().Throw<InvalidOperationException>();
        fixture.IncomingClipboard.Writes.Should().BeEmpty();
        fixture.Window.State.PendingIncomingItems.Should().ContainSingle()
            .Which.ItemId.Should().Be(item.IncomingId);
    }

    [Fact]
    public void Discard_incoming_clears_without_writing()
    {
        var fixture = new Fixture();
        var item = fixture.Context.EnqueueIncomingText(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "Phone",
            "Safari",
            "do not write");

        fixture.Context.DiscardIncoming(item.IncomingId);

        fixture.IncomingClipboard.Writes.Should().BeEmpty();
        fixture.Window.State.PendingIncomingItems.Should().BeEmpty();
    }

    [Fact]
    public async Task Revoke_one_clears_only_matching_incoming_items()
    {
        var first = Guid.Parse("11111111-1111-1111-1111-111111111111");
        var second = Guid.Parse("22222222-2222-2222-2222-222222222222");
        var fixture = new Fixture();
        fixture.Context.EnqueueIncomingText(first, "Phone", "Safari", "first");
        fixture.Context.EnqueueIncomingText(second, "Tablet", "Chrome", "second");

        await fixture.Context.RevokeAsync(first);

        fixture.Window.State.PendingIncomingItems.Should().ContainSingle()
            .Which.AuthorizationId.Should().Be(second);
    }

    [Fact]
    public async Task Revoke_all_and_shutdown_clear_all_incoming_items()
    {
        var fixture = new Fixture();
        fixture.Context.EnqueueIncomingText(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "Phone",
            "Safari",
            "first");

        await fixture.Context.RevokeAllAsync();

        fixture.Window.State.PendingIncomingItems.Should().BeEmpty();

        fixture.Context.EnqueueIncomingText(
            Guid.Parse("22222222-2222-2222-2222-222222222222"),
            "Tablet",
            "Chrome",
            "second");
        await fixture.Context.ShutdownAsync();

        fixture.Window.State.PendingIncomingItems.Should().BeEmpty();
    }

    [Fact]
    public void Stale_apply_or_discard_after_cleanup_does_not_write()
    {
        var fixture = new Fixture();
        var item = fixture.Context.EnqueueIncomingText(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "Phone",
            "Safari",
            "stale");

        fixture.Context.ClearIncomingForAuthorization(item.AuthorizationId);
        fixture.Context.ApplyIncoming(item.IncomingId);
        fixture.Context.DiscardIncoming(item.IncomingId);

        fixture.IncomingClipboard.Writes.Should().BeEmpty();
    }

    [Fact]
    public void Public_profile_status_displays_blocking_warning()
    {
        var fixture = new Fixture();
        fixture.Sharing.State = new NetworkSharingState(
            NetworkSharingStatus.PublicProfileBlocked,
            null,
            null,
            null,
            NetworkProfile.Public,
            43127,
            IsPortListening: false,
            FirewallRuleStatus.Unknown,
            null);

        fixture.Context.RefreshView();

        fixture.Window.State.ServiceStatus.Should().Be("Blocked");
        fixture.Window.State.BlockingWarning.Should().Be(
            "Windows reports this network as Public. Switch it to Private before sharing.");
    }

    [Fact]
    public void Permanent_duration_displays_high_risk_warning()
    {
        var fixture = new Fixture();

        fixture.Context.SetAuthorizationDuration(AuthorizationDuration.Permanent);

        fixture.Window.State.SelectedDuration.Should().Be(AuthorizationDuration.Permanent);
        fixture.Window.State.BlockingWarning.Should().Be(
            "Permanent pairing is high risk. Revoke it when you no longer need this browser.");
    }

    [Fact]
    public void Pairing_permission_defaults_to_read_only()
    {
        var fixture = new Fixture();

        fixture.Context.ViewState.SelectedPermissions.Should().Be(AuthorizationPermissions.Read);
        fixture.Context.ViewState.PermissionOptions.Select(item => item.DisplayName)
            .Should().Equal("Read only", "Write only", "Read + Write");
    }

    [Fact]
    public void Pairing_code_is_created_with_selected_permissions()
    {
        var fixture = new Fixture();
        fixture.Sharing.State = RunningState(
            "https://192.168.1.5:43127/",
            FirewallRuleStatus.Unknown);

        fixture.Context.CreatePairingCode();
        fixture.PairingCodes.LastPermissions.Should().Be(AuthorizationPermissions.Read);

        fixture.Context.SetAuthorizationPermissions(AuthorizationPermissions.ReadWrite);
        fixture.Context.CreatePairingCode();

        fixture.Context.ViewState.SelectedPermissions.Should().Be(AuthorizationPermissions.ReadWrite);
        fixture.PairingCodes.LastPermissions.Should().Be(AuthorizationPermissions.ReadWrite);
    }

    [Fact]
    public void Changing_pairing_permissions_invalidates_existing_pairing_code()
    {
        var fixture = new Fixture();
        fixture.Sharing.State = RunningState(
            "https://192.168.1.5:43127/",
            FirewallRuleStatus.Unknown);
        fixture.Context.SetAuthorizationPermissions(AuthorizationPermissions.ReadWrite);
        fixture.Context.CreatePairingCode();

        fixture.Context.SetAuthorizationPermissions(AuthorizationPermissions.Read);

        fixture.PairingCodes.InvalidateCount.Should().Be(2);
        fixture.Context.ViewState.Pairing.Should().BeNull();
    }

    [Fact]
    public void Pairing_code_is_created_with_selected_duration()
    {
        var fixture = new Fixture();
        fixture.Sharing.State = RunningState(
            "https://192.168.1.5:43127/",
            FirewallRuleStatus.Unknown);

        fixture.Context.SetAuthorizationDuration(AuthorizationDuration.OneWeek);
        fixture.Context.CreatePairingCode();

        fixture.PairingCodes.LastDuration.Should().Be(AuthorizationDuration.OneWeek);
    }

    [Fact]
    public async Task Selection_required_state_displays_interface_options_and_forwards_selection()
    {
        var fixture = new Fixture();
        fixture.Sharing.State = new NetworkSharingState(
            NetworkSharingStatus.SelectionRequired,
            null,
            null,
            null,
            null,
            43127,
            IsPortListening: false,
            FirewallRuleStatus.Unknown,
            null,
            ImmutableArray.Create(
                new NetworkInterfaceSelectionOption(
                    "wifi",
                    "Wi-Fi",
                    IPAddress.Parse("192.168.1.5")),
                new NetworkInterfaceSelectionOption(
                    "eth",
                    "Ethernet",
                    IPAddress.Parse("10.0.0.5"))));

        fixture.Context.RefreshView();
        await fixture.Context.SelectInterfaceAsync("eth");

        fixture.Window.State.ServiceStatus.Should().Be("Select interface");
        fixture.Window.State.InterfaceOptions.Select(item => item.DisplayName)
            .Should().Equal("Wi-Fi - 192.168.1.5", "Ethernet - 10.0.0.5");
        fixture.Sharing.SelectedInterfaces.Should().Equal("eth");
    }

    [Fact]
    public async Task Shutdown_drains_sharing_before_clearing_clipboard_content()
    {
        var fixture = new Fixture();
        fixture.Context.OnClipboardText("shared item");
        fixture.Sharing.BlockShutdown = true;

        var shutdown = fixture.Context.ShutdownAsync();
        await fixture.Sharing.ShutdownEntered.Task.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Clipboard.ClearCount.Should().Be(0);
        fixture.Sharing.ReleaseShutdown();
        await shutdown.WaitAsync(TimeSpan.FromSeconds(5));

        fixture.Sharing.Events.Should().ContainInOrder("sharing:shutdown", "clipboard:clear");
        fixture.Clipboard.ClearCount.Should().Be(1);
    }

    [Fact]
    public async Task Shutdown_records_diagnostic_without_clearing_when_handlers_do_not_exit()
    {
        var fixture = new Fixture();
        fixture.Context.OnClipboardText("shared item");
        fixture.Context.EnqueueIncomingText(
            Guid.Parse("11111111-1111-1111-1111-111111111111"),
            "Phone",
            "Safari",
            "incoming should clear");
        fixture.Sharing.ThrowIncompleteShutdown = true;

        await fixture.Context.ShutdownAsync();

        fixture.Clipboard.ClearCount.Should().Be(0);
        fixture.Window.State.PendingIncomingItems.Should().BeEmpty();
        fixture.Notifications.Items.Should().Contain(notification =>
            notification.Title == "Sharing did not stop cleanly" &&
            !notification.Body.Contains("shared item", StringComparison.Ordinal));
    }

    [Fact]
    public void Production_shutdown_contract_uses_five_second_drain_and_two_second_cancel_join()
    {
        ClipboardApplicationContext.ShutdownTimeouts.Should().Be(LocalWebHostTimeouts.Production);
        ClipboardApplicationContext.ShutdownTimeouts.Drain.Should().Be(TimeSpan.FromSeconds(5));
        ClipboardApplicationContext.ShutdownTimeouts.CancelJoin.Should().Be(TimeSpan.FromSeconds(2));
    }

    private static NetworkSharingState RunningState(
        string url,
        FirewallRuleStatus firewallRuleStatus) =>
        new(
            NetworkSharingStatus.Running,
            "wifi",
            IPAddress.Parse("192.168.1.5"),
            url,
            NetworkProfile.Private,
            43127,
            IsPortListening: true,
            firewallRuleStatus,
            null);

    private static Button[] Buttons(Form window, params string[] texts)
    {
        return texts
            .Select(text => window.Controls.OfType<Button>().Single(button => button.Text == text))
            .ToArray();
    }

    private static AuthorizationMetadata Metadata(
        Guid id,
        string label,
        DateTimeOffset? expiresAtUtc = null,
        bool permanent = false,
        string? deviceName = null,
        string? browserName = null,
        DateTimeOffset? lastAccessedAtUtc = null,
        AuthorizationPermissions permissions = AuthorizationPermissions.Read) =>
        new(
            id,
            label,
            new DateTimeOffset(2026, 6, 12, 0, 0, 0, TimeSpan.Zero),
            IPAddress.Parse("192.168.1.5"),
            permanent
                ? null
                : expiresAtUtc ?? new DateTimeOffset(2026, 6, 12, 5, 0, 0, TimeSpan.Zero),
            deviceName,
            browserName,
            lastAccessedAtUtc,
            permissions);

    private static byte[] CreatePngBytes()
    {
        using var bitmap = new Bitmap(1, 1);
        using var stream = new MemoryStream();
        bitmap.Save(stream, ImageFormat.Png);
        return stream.ToArray();
    }

    private static async Task WaitUntilAsync(Func<bool> condition)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!condition())
        {
            await Task.Delay(10, timeout.Token);
        }
    }

    private sealed class Fixture
    {
        public RecordingTrayWindow Window { get; } = new();

        public RecordingTrayNotifier Notifications { get; } = new();

        public FakeSharingController Sharing { get; } = new();

        public FakePairingCodeProvider PairingCodes { get; } = new();

        public FakeAuthorizationAdministration Authorizations { get; } = new();

        public RecordingClipboardContentStore Clipboard { get; }

        public RecordingWindowsClipboardWriter IncomingClipboard { get; } = new();

        public RecordingQrCodeRenderer Qr { get; } = new();

        public FixedTimeProvider Clock { get; } =
            new(new DateTimeOffset(2026, 6, 12, 0, 0, 0, TimeSpan.Zero));

        public ClipboardApplicationContext Context { get; }

        public Fixture()
        {
            Clipboard = new RecordingClipboardContentStore(Sharing.Events);
            Context = new ClipboardApplicationContext(
                new ClipboardApplicationServices(
                    Window,
                    Notifications,
                    Sharing,
                    PairingCodes,
                    Authorizations,
                    Clipboard,
                    IncomingClipboard,
                    Qr,
                    Clock));
        }
    }

    private sealed class RecordingTrayWindow : ITrayWindow, ITrayCommandSource
    {
        private EventHandler? _startSharingRequested;

        public TrayViewState State { get; private set; } = TrayViewState.Empty;

        public int ShowCount { get; private set; }

        public event EventHandler? StartSharingRequested
        {
            add => _startSharingRequested += value;
            remove => _startSharingRequested -= value;
        }

        public event EventHandler? StopSharingRequested
        {
            add { }
            remove { }
        }

        public event EventHandler? ExitRequested
        {
            add { }
            remove { }
        }

        public event EventHandler? PairingCodeRequested
        {
            add { }
            remove { }
        }

        public event EventHandler<AuthorizationDuration>? AuthorizationDurationChanged
        {
            add { }
            remove { }
        }

        public event EventHandler<AuthorizationPermissions>? AuthorizationPermissionsChanged
        {
            add { }
            remove { }
        }

        public event EventHandler<Guid>? RevokeAuthorizationRequested
        {
            add { }
            remove { }
        }

        public event EventHandler? RevokeAllAuthorizationsRequested
        {
            add { }
            remove { }
        }

        public event EventHandler<Guid>? AllowPendingRequested
        {
            add { }
            remove { }
        }

        public event EventHandler<Guid>? DiscardPendingRequested
        {
            add { }
            remove { }
        }

        public event EventHandler<Guid>? WithdrawSharedRequested
        {
            add { }
            remove { }
        }

        public event EventHandler<Guid>? ApplyIncomingRequested
        {
            add { }
            remove { }
        }

        public event EventHandler<Guid>? DiscardIncomingRequested
        {
            add { }
            remove { }
        }

        public event EventHandler<string>? InterfaceSelected
        {
            add { }
            remove { }
        }

        public void Render(TrayViewState state) => State = state;

        public void ShowTray() => ShowCount++;

        public void RaiseStartSharingRequested() =>
            _startSharingRequested?.Invoke(this, EventArgs.Empty);
    }

    private sealed class RecordingTrayNotifier : ITrayNotifier
    {
        public List<TrayNotification> Items { get; } = [];

        public void Notify(TrayNotification notification) => Items.Add(notification);
    }

    private sealed class RecordingQrCodeRenderer : IQrCodeRenderer
    {
        public List<string> Payloads { get; } = [];

        public byte[] RenderPng(string payload)
        {
            Payloads.Add(payload);
            return Encoding.UTF8.GetBytes("qr:" + payload);
        }
    }

    private sealed class FakePairingCodeProvider : IPairingCodeProvider
    {
        public AuthorizationDuration? LastDuration { get; private set; }

        public AuthorizationPermissions? LastPermissions { get; private set; }

        public int InvalidateCount { get; private set; }

        public PairingCodeSnapshot Create(
            AuthorizationDuration duration,
            AuthorizationPermissions permissions)
        {
            LastDuration = duration;
            LastPermissions = permissions;
            return
            new(
                "pair-code",
                new DateTimeOffset(2026, 6, 12, 0, 2, 0, TimeSpan.Zero),
                permissions);
        }

        public void Invalidate() => InvalidateCount++;
    }

    private sealed class FakeSharingController : ISharingController
    {
        private readonly TaskCompletionSource _releaseShutdown =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ConcurrentQueue<string> Events { get; } = new();

        public NetworkSharingState State { get; set; } = NetworkSharingState.Initial;

        public List<string> SelectedInterfaces { get; } = [];

        public bool BlockShutdown { get; set; }

        public bool ThrowIncompleteShutdown { get; set; }

        public bool ThrowStart { get; set; }

        public bool CompleteStartAsynchronously { get; set; }

        public Action? StartEntered { get; set; }

        public Action? StartCompleted { get; set; }

        public TaskCompletionSource ShutdownEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public NetworkSharingState CurrentState => State;

        public Task<NetworkSharingState> StartAsync(CancellationToken cancellationToken = default)
        {
            StartEntered?.Invoke();
            if (ThrowStart)
            {
                throw new InvalidOperationException("boom");
            }

            if (CompleteStartAsynchronously)
            {
                return CompleteStartAsync(cancellationToken);
            }

            StartCompleted?.Invoke();
            return Task.FromResult(State);
        }

        private async Task<NetworkSharingState> CompleteStartAsync(
            CancellationToken cancellationToken)
        {
            await Task.Delay(10, cancellationToken).ConfigureAwait(false);
            StartCompleted?.Invoke();
            return State;
        }

        public async Task<NetworkSharingState> ShutdownAsync(CancellationToken cancellationToken = default)
        {
            Events.Enqueue("sharing:shutdown");
            ShutdownEntered.TrySetResult();
            if (BlockShutdown)
            {
                await _releaseShutdown.Task.WaitAsync(cancellationToken);
            }

            if (ThrowIncompleteShutdown)
            {
                throw new LocalWebHostShutdownIncompleteException();
            }

            State = NetworkSharingState.Initial;
            return State;
        }

        public Task<NetworkSharingState> SetSelectedInterfaceAsync(
            string interfaceId,
            CancellationToken cancellationToken = default)
        {
            SelectedInterfaces.Add(interfaceId);
            return Task.FromResult(State);
        }

        public Task<NetworkSharingState> RefreshAsync(CancellationToken cancellationToken = default) =>
            Task.FromResult(State);

        public void ReleaseShutdown() => _releaseShutdown.TrySetResult();
    }

    private sealed class FakeAuthorizationAdministration : IAuthorizationAdministration
    {
        private readonly TaskCompletionSource _releaseRevoke =
            new(TaskCreationOptions.RunContinuationsAsynchronously);
        private readonly TaskCompletionSource _releaseRevokeAll =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ImmutableArray<AuthorizationMetadata> Authorizations { get; set; } = [];

        public bool BlockRevoke { get; set; }

        public bool BlockRevokeAll { get; set; }

        public TaskCompletionSource RevokeEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource RevokeAllEntered { get; } =
            new(TaskCreationOptions.RunContinuationsAsynchronously);

        public ImmutableArray<AuthorizationMetadata> List() => Authorizations;

        public async ValueTask<AuthorizationMutationResult> RevokeAsync(
            Guid authorizationId,
            CancellationToken cancellationToken = default)
        {
            RevokeEntered.TrySetResult();
            if (BlockRevoke)
            {
                await _releaseRevoke.Task.WaitAsync(cancellationToken);
            }

            Authorizations = Authorizations
                .Where(item => item.Id != authorizationId)
                .ToImmutableArray();
            return MutationResult(AuthorizationFailure.None, Authorizations);
        }

        public async ValueTask<AuthorizationMutationResult> RevokeAllAsync(
            CancellationToken cancellationToken = default)
        {
            RevokeAllEntered.TrySetResult();
            if (BlockRevokeAll)
            {
                await _releaseRevokeAll.Task.WaitAsync(cancellationToken);
            }

            Authorizations = [];
            return MutationResult(AuthorizationFailure.None, Authorizations);
        }

        public ValueTask<AuthorizationMutationResult> RemoveStaleBindingsAsync(
            IReadOnlyCollection<IPAddress> activeHostIpv4Addresses,
            CancellationToken cancellationToken = default) =>
            ValueTask.FromResult(MutationResult(AuthorizationFailure.None, Authorizations));

        public void CompleteRevoke() => _releaseRevoke.TrySetResult();

        public void CompleteRevokeAll() => _releaseRevokeAll.TrySetResult();
    }

    private sealed class RecordingClipboardContentStore(ConcurrentQueue<string>? events = null)
        : IClipboardContentStore
    {
        private readonly ClipboardPipelineContentStore _inner = new();
        private readonly ConcurrentQueue<string> _events = events ?? new ConcurrentQueue<string>();

        public ClipboardSnapshot HistorySnapshot => _inner.HistorySnapshot;

        public PendingApprovalSnapshot PendingSnapshot => _inner.PendingSnapshot;

        public IReadOnlyList<PendingClipboardViewItem> PendingItems => _inner.PendingItems;

        public int ClearCount { get; private set; }

        public ClipboardCaptureResult CaptureText(string text) => _inner.CaptureText(text);

        public PipelineAllowResult Allow(Guid id) => _inner.Allow(id);

        public PendingTakeResult Discard(Guid id) => _inner.Discard(id);

        public HistoryWithdrawResult Withdraw(Guid id) => _inner.Withdraw(id);

        public void Clear()
        {
            ClearCount++;
            _events.Enqueue("clipboard:clear");
            _inner.Clear();
        }
    }

    private sealed class RecordingWindowsClipboardWriter : IWindowsClipboardWriter
    {
        public List<string> Writes { get; } = [];

        public Action<string>? OnSetText { get; set; }

        public bool ThrowOnSetText { get; set; }

        public void SetText(string text)
        {
            if (ThrowOnSetText)
            {
                throw new InvalidOperationException("clipboard busy");
            }

            OnSetText?.Invoke(text);
            Writes.Add(text);
        }
    }

    private static AuthorizationMutationResult MutationResult(
        AuthorizationFailure failure,
        ImmutableArray<AuthorizationMetadata> authorizations)
    {
        var constructor = typeof(AuthorizationMutationResult).GetConstructors(
            System.Reflection.BindingFlags.Instance |
            System.Reflection.BindingFlags.NonPublic).Single();
        return (AuthorizationMutationResult)constructor.Invoke(
            [failure, new AuthorizationAdministrationSnapshot(authorizations)]);
    }

    private sealed class FixedTimeProvider(DateTimeOffset utcNow) : TimeProvider
    {
        private DateTimeOffset _utcNow = utcNow;

        public override DateTimeOffset GetUtcNow() => _utcNow;

        public void Advance(TimeSpan duration) => _utcNow += duration;
    }

    private sealed class DisposableProbe(Action onDispose) : IDisposable
    {
        public void Dispose() => onDispose();
    }

    private sealed class NonPumpingSynchronizationContext : SynchronizationContext
    {
        public int PostCount { get; private set; }

        public override void Post(SendOrPostCallback d, object? state)
        {
            ArgumentNullException.ThrowIfNull(d);
            PostCount++;
        }

        public override void Send(SendOrPostCallback d, object? state)
        {
            ArgumentNullException.ThrowIfNull(d);
            PostCount++;
        }
    }

    private sealed class RecordingLocalWebHostInstance(LocalWebHostStopResult stopResult)
        : ILocalWebHostInstance
    {
        public int StopCount { get; private set; }

        public int DisposeCount { get; private set; }

        public Task StartAsync(CancellationToken cancellationToken = default) =>
            Task.CompletedTask;

        public Task<LocalWebHostStopResult> StopAsync(
            CancellationToken cancellationToken = default)
        {
            StopCount++;
            return Task.FromResult(stopResult);
        }

        public ValueTask DisposeAsync()
        {
            DisposeCount++;
            return ValueTask.CompletedTask;
        }
    }

    private sealed class UnsupportedAuthorizationService : IAuthorizationService
    {
        public ValueTask<ExchangeAuthorizationResult> ExchangeAsync(
            ExchangeAuthorizationRequest request,
            CancellationToken cancellationToken = default) =>
            throw new NotSupportedException();

        public AcquireLeaseResult AcquireLease(AcquireLeaseRequest request) =>
            throw new NotSupportedException();
    }
}
