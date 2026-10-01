using System.Windows;
using System.Windows.Automation;
using System.Windows.Controls;
using System.Windows.Media;

namespace CCP.Windows.Ui;

/// <summary>
/// Modeless window shown while an outgoing pairing waits for the other
/// device's user to compare codes and approve.
/// </summary>
public sealed class PairCodeWindow : Window
{
    public event Action? CancelRequested;

    public PairCodeWindow(Window owner, string peerName, string code)
    {
        Owner = owner;
        Title = "CCP pairing";
        SizeToContent = SizeToContent.WidthAndHeight;
        ResizeMode = ResizeMode.NoResize;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        ShowInTaskbar = false;

        var formatted = code.Length == 6 ? $"{code[..3]} {code[3..]}" : code;
        var codeText = new TextBlock
        {
            Text = formatted,
            FontSize = 40,
            FontWeight = FontWeights.Bold,
            FontFamily = new FontFamily("Consolas"),
            HorizontalAlignment = HorizontalAlignment.Center,
            Margin = new Thickness(0, 12, 0, 12),
        };
        AutomationProperties.SetName(codeText, $"Pairing code {string.Join(' ', code.ToCharArray())}");

        var cancel = new Button
        {
            Content = "Cancel",
            Padding = new Thickness(16, 4, 16, 4),
            HorizontalAlignment = HorizontalAlignment.Right,
            IsCancel = true,
        };
        cancel.Click += (_, _) =>
        {
            CancelRequested?.Invoke();
            Close();
        };

        Content = new StackPanel
        {
            Margin = new Thickness(24),
            MinWidth = 320,
            Children =
            {
                new TextBlock { Text = $"Pairing with {peerName}", FontSize = 16, FontWeight = FontWeights.SemiBold },
                codeText,
                new TextBlock
                {
                    Text = $"Check that {peerName} shows the same code, then approve it there.",
                    TextWrapping = TextWrapping.Wrap,
                    MaxWidth = 320,
                    Margin = new Thickness(0, 0, 0, 16),
                },
                cancel,
            },
        };
    }
}
