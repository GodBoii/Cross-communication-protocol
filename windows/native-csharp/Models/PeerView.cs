using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Windows.Media;

namespace CCP.Windows.Models;

public sealed record PeerRoute
{
    public required string Transport { get; init; }
    public required string Host { get; init; }
    public required int Port { get; init; }

    public string Label => $"{Transport} {Host}:{Port}";
}

public sealed record PeerView
{
    public required string DeviceId { get; init; }
    public required string DeviceName { get; init; }
    public required string Platform { get; init; }
    public required IPAddress Address { get; init; }
    public required int TcpPort { get; init; }
    public required bool Trusted { get; init; }
    public required DateTime LastSeen { get; init; }
    public IReadOnlyList<string> AvailableTransports { get; init; } = [];
    public IReadOnlyList<PeerRoute> Routes { get; init; } = [];

    public string EndpointLabel => $"{Platform}  {PrimaryRouteLabel}  {(Trusted ? "trusted" : "new")}";
    public string PrimaryRouteLabel => Routes.FirstOrDefault()?.Label ?? $"{Address}:{TcpPort}";
    public string TransportSummary => AvailableTransports.Count == 0 ? "direct tcp" : string.Join(" | ", AvailableTransports);
    public string PlatformInitial => string.IsNullOrWhiteSpace(Platform) ? "?" : Platform[..1].ToUpperInvariant();
    public Brush BadgeBrush => Trusted ? new SolidColorBrush(Color.FromRgb(245, 245, 245)) : new SolidColorBrush(Color.FromRgb(99, 99, 99));
}
