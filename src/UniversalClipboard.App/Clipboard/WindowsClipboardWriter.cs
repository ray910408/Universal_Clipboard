using System.Windows.Forms;
using UniversalClipboard.App.App;

namespace UniversalClipboard.App.Clipboard;

public sealed class WindowsClipboardWriter(IStaScheduler scheduler) : IWindowsClipboardWriter
{
    public void SetText(string text)
    {
        ArgumentNullException.ThrowIfNull(text);
        if (scheduler.CheckAccess())
        {
            global::System.Windows.Forms.Clipboard.SetText(text, TextDataFormat.UnicodeText);
            return;
        }

        scheduler.Post(() => global::System.Windows.Forms.Clipboard.SetText(text, TextDataFormat.UnicodeText));
    }
}
