using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using CCP.Windows.Ui;

namespace CCP.Windows;

public partial class App : Application
{
    [DllImport("user32.dll")]
    private static extern bool SetProcessDpiAwarenessContext(IntPtr value);

    protected override void OnStartup(StartupEventArgs e)
    {
        // Per-monitor v2 DPI awareness so text stays crisp on 125%/150% displays.
        // -4 = DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2.
        try { SetProcessDpiAwarenessContext((IntPtr)(-4)); } catch { /* best effort on older Windows */ }

        // Force ClearType-friendly text defaults for every window.
        TextOptions.TextFormattingModeProperty.OverrideMetadata(
            typeof(TextElement),
            new FrameworkPropertyMetadata(TextFormattingMode.Display));
        TextOptions.TextRenderingModeProperty.OverrideMetadata(
            typeof(TextElement),
            new FrameworkPropertyMetadata(TextRenderingMode.ClearType));

        base.OnStartup(e);
    }
}
