using System.Net;
using System.Windows.Media;

namespace CCP.Windows.Models;

public sealed record PeerView
{
    public required string DeviceId { get; init; }
    public required string DeviceName { get; init; }
    public required string Platform { get; init; }
    public required IPAddress Address { get; init; }
    public required int TcpPort { get; init; }
    public required bool Trusted { get; init; }
    public required DateTime LastSeen { get; init; }

    public string EndpointLabel => $"{Platform}  {Address}:{TcpPort}  {(Trusted ? "trusted" : "new")}";
    public string PlatformInitial => string.IsNullOrWhiteSpace(Platform) ? "?" : Platform[..1].ToUpperInvariant();
    public Brush BadgeBrush => Trusted ? new SolidColorBrush(Color.FromRgb(47, 143, 107)) : new SolidColorBrush(Color.FromRgb(100, 116, 139));
}
