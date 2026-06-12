using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace UniversalClipboard.App.Clipboard;

public interface IClipboardReader
{
    ClipboardReadResult ReadUnicodeText();
}

public interface IClipboardNotificationSink
{
    void OnClipboardText(string text);

    void OnClipboardReadExhausted(ClipboardReadDiagnostic diagnostic);
}

public interface IClipboardNativeListener
{
    bool Add(IntPtr windowHandle);

    bool Remove(IntPtr windowHandle);
}

public interface IStaScheduler
{
    bool CheckAccess();

    void Post(Action action);

    void PostDelayed(TimeSpan delay, Action action);
}

public enum ClipboardReadStatus
{
    Empty,
    Text,
    Busy,
}

public sealed record ClipboardReadResult(ClipboardReadStatus Status, string? Value)
{
    public static ClipboardReadResult Empty() => new(ClipboardReadStatus.Empty, null);

    public static ClipboardReadResult Text(string text) => new(ClipboardReadStatus.Text, text);

    public static ClipboardReadResult Busy() => new(ClipboardReadStatus.Busy, null);
}

public sealed record ClipboardReadDiagnostic(int AttemptCount);

public sealed class WindowsClipboardMonitor : NativeWindow, IDisposable
{
    internal const int WmClipboardUpdate = 0x031D;
    private static readonly TimeSpan[] BusyRetryDelays =
    [
        TimeSpan.FromMilliseconds(25),
        TimeSpan.FromMilliseconds(50),
        TimeSpan.FromMilliseconds(100),
    ];

    private readonly IClipboardReader _reader;
    private readonly IClipboardNotificationSink _sink;
    private readonly IClipboardNativeListener _nativeListener;
    private readonly IStaScheduler _scheduler;
    private bool _disposed;

    public WindowsClipboardMonitor(
        IClipboardReader reader,
        IClipboardNotificationSink sink,
        IClipboardNativeListener nativeListener,
        IStaScheduler scheduler)
    {
        ArgumentNullException.ThrowIfNull(reader);
        ArgumentNullException.ThrowIfNull(sink);
        ArgumentNullException.ThrowIfNull(nativeListener);
        ArgumentNullException.ThrowIfNull(scheduler);
        if (!scheduler.CheckAccess() || Thread.CurrentThread.GetApartmentState() != ApartmentState.STA)
        {
            throw new InvalidOperationException(
                "Windows clipboard monitoring must be created on its STA scheduler thread.");
        }

        _reader = reader;
        _sink = sink;
        _nativeListener = nativeListener;
        _scheduler = scheduler;
        CreateHandle(new CreateParams());
        if (!_nativeListener.Add(Handle))
        {
            DestroyHandle();
            throw new InvalidOperationException("Failed to register clipboard listener.");
        }
    }

    internal void HandleClipboardUpdate()
    {
        if (_disposed)
        {
            return;
        }

        if (_scheduler.CheckAccess())
        {
            ReadAttempt(0);
        }
        else
        {
            _scheduler.Post(() => ReadAttempt(0));
        }
    }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == WmClipboardUpdate)
        {
            HandleClipboardUpdate();
            return;
        }

        base.WndProc(ref m);
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        if (Handle != IntPtr.Zero)
        {
            _nativeListener.Remove(Handle);
            DestroyHandle();
        }

        GC.SuppressFinalize(this);
    }

    private void ReadAttempt(int busyCount)
    {
        if (_disposed)
        {
            return;
        }

        var result = _reader.ReadUnicodeText();
        if (_disposed)
        {
            return;
        }

        switch (result.Status)
        {
            case ClipboardReadStatus.Text:
                _sink.OnClipboardText(result.Value ?? string.Empty);
                break;
            case ClipboardReadStatus.Busy:
                if (busyCount < BusyRetryDelays.Length)
                {
                    var nextBusyCount = busyCount + 1;
                    _scheduler.PostDelayed(
                        BusyRetryDelays[busyCount],
                        () =>
                        {
                            if (!_disposed)
                            {
                                ReadAttempt(nextBusyCount);
                            }
                        });
                }
                else
                {
                    _sink.OnClipboardReadExhausted(new ClipboardReadDiagnostic(busyCount + 1));
                }

                break;
        }
    }
}

public sealed class WindowsClipboardReader : IClipboardReader
{
    public ClipboardReadResult ReadUnicodeText()
    {
        try
        {
            return System.Windows.Forms.Clipboard.ContainsText(TextDataFormat.UnicodeText)
                ? ClipboardReadResult.Text(
                    System.Windows.Forms.Clipboard.GetText(TextDataFormat.UnicodeText))
                : ClipboardReadResult.Empty();
        }
        catch (ExternalException)
        {
            return ClipboardReadResult.Busy();
        }
    }
}

public sealed class WindowsClipboardNativeListener : IClipboardNativeListener
{
    public bool Add(IntPtr windowHandle) => AddClipboardFormatListener(windowHandle);

    public bool Remove(IntPtr windowHandle) => RemoveClipboardFormatListener(windowHandle);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool AddClipboardFormatListener(IntPtr hwnd);

    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool RemoveClipboardFormatListener(IntPtr hwnd);
}
