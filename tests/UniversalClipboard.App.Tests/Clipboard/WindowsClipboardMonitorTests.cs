using FluentAssertions;
using System.Windows.Forms;
using UniversalClipboard.App.Clipboard;

namespace UniversalClipboard.App.Tests.Clipboard;

public sealed class WindowsClipboardMonitorTests
{
    [Fact]
    public async Task Clipboard_update_on_sta_reads_unicode_text_without_logging_content()
    {
        await StaThreadFixture.RunAsync(() =>
        {
            var reader = new FakeClipboardReader();
            reader.Results.Enqueue(ClipboardReadResult.Text("hello from clipboard"));
            var sink = new FakeClipboardSink();
            var native = new FakeNativeClipboardListener();
            var scheduler = new InlineStaScheduler();

            using var monitor = new WindowsClipboardMonitor(reader, sink, native, scheduler);
            monitor.HandleClipboardUpdate();

            sink.Texts.Should().Equal("hello from clipboard");
            sink.Diagnostics.Should().BeEmpty();
            native.RegisteredHandles.Should().ContainSingle(handle => handle != IntPtr.Zero);
        });
    }

    [Fact]
    public async Task Busy_clipboard_retries_on_sta_scheduler_at_25_50_100_ms()
    {
        await StaThreadFixture.RunAsync(() =>
        {
            var reader = new FakeClipboardReader();
            reader.Results.Enqueue(ClipboardReadResult.Busy());
            reader.Results.Enqueue(ClipboardReadResult.Busy());
            reader.Results.Enqueue(ClipboardReadResult.Busy());
            reader.Results.Enqueue(ClipboardReadResult.Text("eventual"));
            var sink = new FakeClipboardSink();
            var scheduler = new InlineStaScheduler { AutoRunDelayed = false };

            using var monitor = new WindowsClipboardMonitor(
                reader,
                sink,
                new FakeNativeClipboardListener(),
                scheduler);

            monitor.HandleClipboardUpdate();
            scheduler.Delays.Should().Equal(TimeSpan.FromMilliseconds(25));

            scheduler.RunDelayed();

            scheduler.Delays.Should().Equal(
                TimeSpan.FromMilliseconds(25),
                TimeSpan.FromMilliseconds(50),
                TimeSpan.FromMilliseconds(100));
            sink.Texts.Should().Equal("eventual");
            reader.ReadThreadIds.Should().OnlyContain(id => id == Environment.CurrentManagedThreadId);
        });
    }

    [Fact]
    public async Task Exhausted_busy_retries_emit_content_free_diagnostic_count()
    {
        await StaThreadFixture.RunAsync(() =>
        {
            var reader = new FakeClipboardReader();
            for (var attempt = 0; attempt < 4; attempt++)
            {
                reader.Results.Enqueue(ClipboardReadResult.Busy());
            }

            var sink = new FakeClipboardSink();
            var scheduler = new InlineStaScheduler();

            using var monitor = new WindowsClipboardMonitor(
                reader,
                sink,
                new FakeNativeClipboardListener(),
                scheduler);

            monitor.HandleClipboardUpdate();

            sink.Texts.Should().BeEmpty();
            sink.Diagnostics.Should().Equal(new ClipboardReadDiagnostic(4));
        });
    }

    [Fact]
    public async Task Dispose_cancels_pending_busy_retry_callbacks()
    {
        await StaThreadFixture.RunAsync(() =>
        {
            var reader = new FakeClipboardReader();
            reader.Results.Enqueue(ClipboardReadResult.Busy());
            reader.Results.Enqueue(ClipboardReadResult.Text("late"));
            var sink = new FakeClipboardSink();
            var scheduler = new InlineStaScheduler { AutoRunDelayed = false };
            var monitor = new WindowsClipboardMonitor(
                reader,
                sink,
                new FakeNativeClipboardListener(),
                scheduler);

            monitor.HandleClipboardUpdate();
            monitor.Dispose();
            scheduler.RunDelayed();

            reader.ReadThreadIds.Should().HaveCount(1);
            sink.Texts.Should().BeEmpty();
            sink.Diagnostics.Should().BeEmpty();
        });
    }

    [Fact]
    public async Task Dispose_unregisters_listener()
    {
        await StaThreadFixture.RunAsync(() =>
        {
            var native = new FakeNativeClipboardListener();
            var scheduler = new InlineStaScheduler();
            var monitor = new WindowsClipboardMonitor(
                new FakeClipboardReader(),
                new FakeClipboardSink(),
                native,
                scheduler);
            var handle = native.RegisteredHandles.Single();

            monitor.Dispose();

            native.UnregisteredHandles.Should().Equal(handle);
        });
    }

    [Fact]
    public async Task Construction_requires_sta_scheduler_access()
    {
        await StaThreadFixture.RunAsync(() =>
        {
            var act = () => new WindowsClipboardMonitor(
                new FakeClipboardReader(),
                new FakeClipboardSink(),
                new FakeNativeClipboardListener(),
                new InlineStaScheduler { HasAccess = false });

            act.Should().Throw<InvalidOperationException>()
                .WithMessage("*STA*");
        });
    }

    private sealed class FakeClipboardReader : IClipboardReader
    {
        public Queue<ClipboardReadResult> Results { get; } = [];

        public List<int> ReadThreadIds { get; } = [];

        public ClipboardReadResult ReadUnicodeText()
        {
            ReadThreadIds.Add(Environment.CurrentManagedThreadId);
            return Results.Count == 0 ? ClipboardReadResult.Empty() : Results.Dequeue();
        }
    }

    private sealed class FakeClipboardSink : IClipboardNotificationSink
    {
        public List<string> Texts { get; } = [];

        public List<ClipboardReadDiagnostic> Diagnostics { get; } = [];

        public void OnClipboardText(string text) => Texts.Add(text);

        public void OnClipboardReadExhausted(ClipboardReadDiagnostic diagnostic) =>
            Diagnostics.Add(diagnostic);
    }

    private sealed class FakeNativeClipboardListener : IClipboardNativeListener
    {
        public List<IntPtr> RegisteredHandles { get; } = [];

        public List<IntPtr> UnregisteredHandles { get; } = [];

        public bool Add(IntPtr windowHandle)
        {
            RegisteredHandles.Add(windowHandle);
            return true;
        }

        public bool Remove(IntPtr windowHandle)
        {
            UnregisteredHandles.Add(windowHandle);
            return true;
        }
    }

    private sealed class InlineStaScheduler : IStaScheduler
    {
        private readonly Queue<Action> _delayed = [];

        public bool HasAccess { get; set; } = true;

        public bool AutoRunDelayed { get; set; } = true;

        public List<TimeSpan> Delays { get; } = [];

        public bool CheckAccess() => HasAccess;

        public void Post(Action action) => action();

        public void PostDelayed(TimeSpan delay, Action action)
        {
            Delays.Add(delay);
            if (AutoRunDelayed)
            {
                action();
            }
            else
            {
                _delayed.Enqueue(action);
            }
        }

        public void RunDelayed()
        {
            while (_delayed.Count > 0)
            {
                _delayed.Dequeue()();
            }
        }
    }

    private static class StaThreadFixture
    {
        public static Task RunAsync(Action action)
        {
            var completion = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var thread = new Thread(() =>
            {
                using var control = new Control();
                control.CreateControl();
                control.BeginInvoke(new Action(() =>
                {
                    try
                    {
                        action();
                        completion.SetResult();
                    }
                    catch (Exception exception)
                    {
                        completion.SetException(exception);
                    }
                    finally
                    {
                        Application.ExitThread();
                    }
                }));
                Application.Run();
            });
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            return completion.Task.WaitAsync(TimeSpan.FromSeconds(5));
        }
    }
}
