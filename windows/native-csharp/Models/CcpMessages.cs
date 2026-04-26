using System.Text.Json.Serialization;

namespace CCP.Windows.Models;

public sealed record SenderInfo(
    [property: JsonPropertyName("device_id")] string DeviceId,
    [property: JsonPropertyName("device_name")] string DeviceName,
    [property: JsonPropertyName("platform")] string Platform);

public sealed record CcpMessage(
    [property: JsonPropertyName("protocol")] string Protocol,
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("type")] string Type,
    [property: JsonPropertyName("sender")] SenderInfo Sender,
    [property: JsonPropertyName("payload")] Dictionary<string, object?> Payload,
    [property: JsonPropertyName("timestamp")] long Timestamp);

