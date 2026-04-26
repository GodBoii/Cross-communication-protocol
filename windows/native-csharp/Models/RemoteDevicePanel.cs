using System.Collections.Generic;

namespace CCP.Windows.Models;

public sealed record RemoteFactView(string Label, string Value);

public sealed record RemoteContentItem(string Name, string Subtitle, string Type);

public sealed record RemoteDevicePanel(
    string Title,
    string Subtitle,
    string Battery,
    string Storage,
    string NotificationAccess,
    string GalleryAccess,
    IReadOnlyList<RemoteFactView> Settings,
    IReadOnlyList<RemoteContentItem> Gallery,
    IReadOnlyList<RemoteContentItem> Files,
    IReadOnlyList<RemoteContentItem> Notifications)
{
    public static RemoteDevicePanel Empty(string deviceName, string platform)
    {
        return new RemoteDevicePanel(
            Title: deviceName,
            Subtitle: platform,
            Battery: "Unknown",
            Storage: "Unknown",
            NotificationAccess: "Unavailable",
            GalleryAccess: "Unavailable",
            Settings: [],
            Gallery: [],
            Files: [],
            Notifications: []);
    }
}

