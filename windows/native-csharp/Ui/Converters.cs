using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;

namespace CCP.Windows.Ui;

public sealed class StateToBrushConverter : IValueConverter
{
    public Brush? Disconnected { get; set; }
    public Brush? Connecting   { get; set; }
    public Brush? Connected    { get; set; }
    public Brush? Ready        { get; set; }
    public Brush? Error        { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value switch
        {
            CloudConnectionState.Connecting => Connecting ?? Disconnected ?? Brushes.Gray,
            CloudConnectionState.Connected  => Connected  ?? Disconnected ?? Brushes.Gray,
            CloudConnectionState.Ready      => Ready      ?? Connected  ?? Disconnected ?? Brushes.Gray,
            CloudConnectionState.Error      => Error      ?? Disconnected ?? Brushes.Gray,
            _                               => Disconnected ?? Brushes.Gray,
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class StateToLabelConverter : IValueConverter
{
    public string Disconnected { get; set; } = "Offline";
    public string Connecting   { get; set; } = "Connecting…";
    public string Connected    { get; set; } = "Connected";
    public string Ready        { get; set; } = "Relay ready";
    public string Error        { get; set; } = "Error";

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        return value switch
        {
            CloudConnectionState.Connecting => Connecting,
            CloudConnectionState.Connected  => Connected,
            CloudConnectionState.Ready      => Ready,
            CloudConnectionState.Error      => Error,
            _                               => Disconnected,
        };
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public bool Invert { get; set; }

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var b = value is bool x && x;
        if (Invert) b = !b;
        return b ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => value is Visibility v && v == Visibility.Visible;
}

public sealed class CountToVisibilityConverter : IValueConverter
{
    public int Threshold { get; set; } = 0;

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        var count = value switch
        {
            int i => i,
            System.Collections.ICollection c => c.Count,
            _ => 0,
        };
        return count > Threshold ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture)
        => throw new NotSupportedException();
}
