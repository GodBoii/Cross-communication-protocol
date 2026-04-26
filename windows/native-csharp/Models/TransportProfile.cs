namespace CCP.Windows.Models;

public sealed record TransportStatus(
    bool Available,
    bool Connected,
    string Detail);
