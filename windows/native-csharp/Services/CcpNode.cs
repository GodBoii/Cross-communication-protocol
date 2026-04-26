using CCP.Windows.Models;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Linq;
using System.Windows;

namespace CCP.Windows.Services;

public sealed class CcpNode : IDisposable
{
    private const string Protocol = "ccp.v0";
    private const int UdpPort = 47827;
    private const int TcpPort = 47828;
    private const int ChunkSize = 64 * 1024;

    private readonly ConfigStore _config = new();
    private readonly ConcurrentDictionary<string, PeerView> _peers = new();
    private readonly Action<IReadOnlyList<PeerView>> _onPeers;
    private readonly Action<string> _onEvent;
    private readonly Func<string, string, bool> _confirm;
    private readonly CancellationTokenSource _stop = new();

    public CcpNode(Action<IReadOnlyList<PeerView>> onPeers, Action<string> onEvent, Func<string, string, bool> confirm)
    {
        _onPeers = onPeers;
        _onEvent = onEvent;
        _confirm = confirm;
    }

    public Task StartAsync()
    {
        _ = Task.Run(() => BroadcastLoopAsync(_stop.Token));
        _ = Task.Run(() => ListenDiscoveryAsync(_stop.Token));
        _ = Task.Run(() => ListenTcpAsync(_stop.Token));
        _onEvent($"Native Windows node started as {_config.DeviceName}");
        return Task.CompletedTask;
    }

    public void BroadcastNow()
    {
        _ = Task.Run(() => SendDiscoveryAsync());
        _onEvent("Discovery broadcast sent");
    }

    public async Task PairAsync(PeerView peer)
    {
        var code = Random.Shared.Next(0, 999999).ToString("000000");
        _onEvent($"Pair request sent to {peer.DeviceName}. Code {code}");
        var response = await SendSingleAsync(peer, Envelope("pair.request", new()
        {
            ["pair_code"] = code,
            ["public_key"] = "reserved-for-v1"
        }));
        if (response is not null && response.Payload.TryGetValue("accepted", out var accepted) && AsBool(accepted))
        {
            _config.Trust(new SenderInfo(peer.DeviceId, peer.DeviceName, peer.Platform));
            UpsertPeer(peer with { Trusted = true, LastSeen = DateTime.Now });
            _onEvent($"Paired with {peer.DeviceName}");
        }
        else
        {
            _onEvent($"Pairing rejected by {peer.DeviceName}");
        }
    }

    public async Task SendFileAsync(PeerView peer, string path)
    {
        if (!peer.Trusted)
        {
            _onEvent("Pair with the device before sending files.");
            return;
        }
        var file = new FileInfo(path);
        var transferId = Guid.NewGuid().ToString();
        var fullHash = await Sha256FileAsync(path);
        var totalChunks = (int)((file.Length + ChunkSize - 1) / ChunkSize);

        using var socket = new TcpClient();
        await socket.ConnectAsync(peer.Address, peer.TcpPort);
        await using var stream = socket.GetStream();
        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        await using var writer = new StreamWriter(stream, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };

        await WriteAsync(writer, Envelope("file.offer", new()
        {
            ["transfer_id"] = transferId,
            ["filename"] = file.Name,
            ["size"] = file.Length,
            ["sha256"] = fullHash,
            ["chunk_size"] = ChunkSize,
            ["total_chunks"] = totalChunks
        }));

        var offerResponse = await ReadAsync(reader);
        if (offerResponse is null || !AsBool(offerResponse.Payload.GetValueOrDefault("accepted")))
        {
            _onEvent($"{peer.DeviceName} rejected {file.Name}");
            return;
        }

        var buffer = new byte[ChunkSize];
        long sent = 0;
        await using var input = File.OpenRead(path);
        for (var index = 0; ; index++)
        {
            var read = await input.ReadAsync(buffer);
            if (read == 0) break;
            var chunk = buffer.AsSpan(0, read).ToArray();
            await WriteAsync(writer, Envelope("file.chunk", new()
            {
                ["transfer_id"] = transferId,
                ["index"] = index,
                ["sha256"] = Sha256Bytes(chunk),
                ["data_b64"] = Convert.ToBase64String(chunk)
            }));
            sent += read;
            _onEvent($"Sending {file.Name}: {sent} / {file.Length} bytes");
        }

        await WriteAsync(writer, Envelope("file.complete", new()
        {
            ["transfer_id"] = transferId,
            ["sha256"] = fullHash
        }));

        var complete = await ReadAsync(reader);
        _onEvent(complete is not null && AsBool(complete.Payload.GetValueOrDefault("ok"))
            ? $"Sent and verified {file.Name}"
            : $"Receiver verification failed for {file.Name}");
    }

    public async Task<RemoteDevicePanel> GetPeerPanelAsync(PeerView peer)
    {
        if (!peer.Trusted)
        {
            return RemoteDevicePanel.Empty(peer.DeviceName, peer.Platform);
        }

        var snapshot = await RequestPayloadAsync(peer, "device.snapshot.request");
        var gallery = await RequestPayloadAsync(peer, "gallery.list.request");
        var files = await RequestPayloadAsync(peer, "files.list.request");
        var notifications = await RequestPayloadAsync(peer, "notifications.list.request");

        return new RemoteDevicePanel(
            Title: AsString(snapshot?.GetValueOrDefault("device_title")) ?? peer.DeviceName,
            Subtitle: AsString(snapshot?.GetValueOrDefault("device_subtitle")) ?? peer.Platform,
            Battery: AsString(snapshot?.GetValueOrDefault("battery")) ?? "Unknown",
            Storage: AsString(snapshot?.GetValueOrDefault("storage")) ?? "Unknown",
            NotificationAccess: AsString(snapshot?.GetValueOrDefault("notification_access")) ?? "Unknown",
            GalleryAccess: AsString(snapshot?.GetValueOrDefault("gallery_access")) ?? "Unknown",
            Settings: ParseFacts(snapshot?.GetValueOrDefault("settings")),
            Gallery: ParseItems(gallery?.GetValueOrDefault("items"), "gallery"),
            Files: ParseItems(files?.GetValueOrDefault("items"), "file"),
            Notifications: ParseNotifications(notifications)
        );
    }

    private async Task BroadcastLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            await SendDiscoveryAsync();
            await Task.Delay(TimeSpan.FromSeconds(3), token).ContinueWith(_ => { });
        }
    }

    private async Task SendDiscoveryAsync()
    {
        using var udp = new UdpClient { EnableBroadcast = true };
        var packet = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["protocol"] = Protocol,
            ["type"] = "discovery",
            ["device_id"] = _config.DeviceId,
            ["device_name"] = _config.DeviceName,
            ["platform"] = "windows",
            ["tcp_port"] = TcpPort,
            ["capabilities"] = new[] { "pairing", "file.transfer", "native.windows" },
            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        });
        var bytes = Encoding.UTF8.GetBytes(packet);
        await udp.SendAsync(bytes, new IPEndPoint(IPAddress.Broadcast, UdpPort));
    }

    private async Task ListenDiscoveryAsync(CancellationToken token)
    {
        using var udp = new UdpClient(UdpPort) { EnableBroadcast = true };
        while (!token.IsCancellationRequested)
        {
            var result = await udp.ReceiveAsync(token);
            var doc = JsonDocument.Parse(result.Buffer).RootElement;
            if (doc.GetProperty("protocol").GetString() != Protocol) continue;
            var deviceId = doc.GetProperty("device_id").GetString() ?? "";
            if (deviceId == _config.DeviceId) continue;
            UpsertPeer(new PeerView
            {
                DeviceId = deviceId,
                DeviceName = doc.GetProperty("device_name").GetString() ?? "Unknown",
                Platform = doc.GetProperty("platform").GetString() ?? "unknown",
                Address = result.RemoteEndPoint.Address,
                TcpPort = doc.GetProperty("tcp_port").GetInt32(),
                Trusted = _config.IsTrusted(deviceId),
                LastSeen = DateTime.Now
            });
        }
    }

    private async Task ListenTcpAsync(CancellationToken token)
    {
        var listener = new TcpListener(IPAddress.Any, TcpPort);
        listener.Start();
        _onEvent($"TCP listener active on {TcpPort}");
        while (!token.IsCancellationRequested)
        {
            var client = await listener.AcceptTcpClientAsync(token);
            _ = Task.Run(() => HandleClientAsync(client, token), token);
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken token)
    {
        using var socket = client;
        await using var stream = socket.GetStream();
        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        await using var writer = new StreamWriter(stream, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };
        FileStream? output = null;
        string? target = null;
        string? expectedHash = null;

        try
        {
            while (!token.IsCancellationRequested)
            {
                var message = await ReadAsync(reader);
                if (message is null) break;
                switch (message.Type)
                {
                    case "pair.request":
                        var code = AsString(message.Payload.GetValueOrDefault("pair_code")) ?? "??????";
                        var accepted = _confirm("CCP Pairing Request", $"Pair with {message.Sender.DeviceName} ({message.Sender.Platform})?\nPair code: {code}");
                        if (accepted) _config.Trust(message.Sender);
                        await WriteAsync(writer, Envelope("pair.response", new() { ["accepted"] = accepted, ["reason"] = accepted ? null : "rejected" }));
                        _onEvent(accepted ? $"Trusted {message.Sender.DeviceName}" : $"Rejected pair request from {message.Sender.DeviceName}");
                        break;

                    case "file.offer":
                        if (!_config.IsTrusted(message.Sender.DeviceId))
                        {
                            await WriteAsync(writer, Envelope("file.offer.response", new()
                            {
                                ["transfer_id"] = message.Payload.GetValueOrDefault("transfer_id"),
                                ["accepted"] = false,
                                ["resume_from"] = 0,
                                ["reason"] = "peer is not paired"
                            }));
                            break;
                        }
                        var filename = SafeFilename(AsString(message.Payload.GetValueOrDefault("filename")) ?? "received-file");
                        var inbox = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "CCP-Inbox");
                        Directory.CreateDirectory(inbox);
                        target = UniquePath(Path.Combine(inbox, filename));
                        expectedHash = AsString(message.Payload.GetValueOrDefault("sha256"));
                        var allow = _confirm("Incoming File", $"Accept {filename} from {message.Sender.DeviceName}?");
                        await WriteAsync(writer, Envelope("file.offer.response", new()
                        {
                            ["transfer_id"] = message.Payload.GetValueOrDefault("transfer_id"),
                            ["accepted"] = allow,
                            ["resume_from"] = 0,
                            ["reason"] = allow ? null : "rejected"
                        }));
                        if (allow)
                        {
                            output = File.Create(target);
                            _onEvent($"Receiving {filename}");
                        }
                        break;

                    case "file.chunk":
                        if (output is null) break;
                        var raw = Convert.FromBase64String(AsString(message.Payload.GetValueOrDefault("data_b64")) ?? "");
                        if (Sha256Bytes(raw) != AsString(message.Payload.GetValueOrDefault("sha256"))) throw new InvalidDataException("Chunk checksum mismatch");
                        await output.WriteAsync(raw, token);
                        _onEvent($"Received chunk {message.Payload.GetValueOrDefault("index")}");
                        break;

                    case "file.complete":
                        if (output is null || target is null) break;
                        await output.DisposeAsync();
                        output = null;
                        var actual = await Sha256FileAsync(target);
                        var ok = actual == expectedHash && actual == AsString(message.Payload.GetValueOrDefault("sha256"));
                        await WriteAsync(writer, Envelope("file.complete.response", new()
                        {
                            ["transfer_id"] = message.Payload.GetValueOrDefault("transfer_id"),
                            ["ok"] = ok,
                            ["sha256"] = actual
                        }));
                        _onEvent(ok ? $"Received and verified {target}" : $"Checksum failed for {target}");
                        break;

                    case "device.snapshot.request":
                        await WriteAsync(writer, Envelope("device.snapshot.response", BuildLocalSnapshotPayload()));
                        break;

                    case "gallery.list.request":
                        await WriteAsync(writer, Envelope("gallery.list.response", BuildDirectoryPayload(
                            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)),
                            "gallery")));
                        break;

                    case "files.list.request":
                        await WriteAsync(writer, Envelope("files.list.response", BuildDirectoryPayload(
                            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"),
                            "file")));
                        break;

                    case "notifications.list.request":
                        await WriteAsync(writer, Envelope("notifications.list.response", new()
                        {
                            ["permission_granted"] = false,
                            ["items"] = Array.Empty<object>()
                        }));
                        break;
                }
            }
        }
        finally
        {
            if (output is not null) await output.DisposeAsync();
        }
    }

    private async Task<CcpMessage?> SendSingleAsync(PeerView peer, CcpMessage message)
    {
        using var client = new TcpClient();
        await client.ConnectAsync(peer.Address, peer.TcpPort);
        await using var stream = client.GetStream();
        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        await using var writer = new StreamWriter(stream, Encoding.UTF8, leaveOpen: true) { AutoFlush = true };
        await WriteAsync(writer, message);
        return await ReadAsync(reader);
    }

    private async Task<Dictionary<string, object?>?> RequestPayloadAsync(PeerView peer, string messageType)
    {
        var response = await SendSingleAsync(peer, Envelope(messageType, new()));
        return response?.Payload;
    }

    private CcpMessage Envelope(string type, Dictionary<string, object?> payload)
    {
        return new CcpMessage(Protocol, Guid.NewGuid().ToString(), type, _config.Sender, payload, DateTimeOffset.UtcNow.ToUnixTimeSeconds());
    }

    private static async Task WriteAsync(StreamWriter writer, CcpMessage message)
    {
        await writer.WriteLineAsync(JsonSerializer.Serialize(message));
    }

    private static async Task<CcpMessage?> ReadAsync(StreamReader reader)
    {
        var line = await reader.ReadLineAsync();
        return string.IsNullOrWhiteSpace(line) ? null : JsonSerializer.Deserialize<CcpMessage>(line);
    }

    private void UpsertPeer(PeerView peer)
    {
        _peers[peer.DeviceId] = peer;
        _onPeers(_peers.Values.OrderByDescending(p => p.LastSeen).ToList());
    }

    private static bool AsBool(object? value)
    {
        return value switch
        {
            bool b => b,
            JsonElement e when e.ValueKind is JsonValueKind.True => true,
            JsonElement e when e.ValueKind is JsonValueKind.False => false,
            string s => bool.TryParse(s, out var b) && b,
            _ => false
        };
    }

    private static string? AsString(object? value)
    {
        return value switch
        {
            null => null,
            string s => s,
            JsonElement e when e.ValueKind == JsonValueKind.String => e.GetString(),
            JsonElement e => e.ToString(),
            _ => Convert.ToString(value)
        };
    }

    private static IReadOnlyList<RemoteFactView> ParseFacts(object? value)
    {
        var result = new List<RemoteFactView>();
        if (value is not JsonElement element || element.ValueKind != JsonValueKind.Array)
        {
            return result;
        }

        foreach (var item in element.EnumerateArray())
        {
            result.Add(new RemoteFactView(
                item.GetProperty("label").GetString() ?? "Setting",
                item.GetProperty("value").GetString() ?? "Unknown"));
        }
        return result;
    }

    private static IReadOnlyList<RemoteContentItem> ParseItems(object? value, string fallbackType)
    {
        var result = new List<RemoteContentItem>();
        if (value is not JsonElement element || element.ValueKind != JsonValueKind.Array)
        {
            return result;
        }

        foreach (var item in element.EnumerateArray())
        {
            var subtitle = item.TryGetProperty("location", out var location)
                ? location.GetString()
                : item.TryGetProperty("mime_type", out var mimeType)
                    ? mimeType.GetString()
                    : item.TryGetProperty("size", out var size)
                        ? size.ToString()
                        : fallbackType;

            result.Add(new RemoteContentItem(
                item.TryGetProperty("name", out var name) ? name.GetString() ?? "Untitled" : "Untitled",
                subtitle ?? fallbackType,
                item.TryGetProperty("type", out var type) ? type.GetString() ?? fallbackType : fallbackType));
        }
        return result;
    }

    private static IReadOnlyList<RemoteContentItem> ParseNotifications(Dictionary<string, object?>? payload)
    {
        var result = new List<RemoteContentItem>();
        if (payload?.TryGetValue("items", out var itemsValue) != true || itemsValue is not JsonElement element || element.ValueKind != JsonValueKind.Array)
        {
            return result;
        }

        foreach (var item in element.EnumerateArray())
        {
            result.Add(new RemoteContentItem(
                item.TryGetProperty("title", out var title) ? title.GetString() ?? "Notification" : "Notification",
                item.TryGetProperty("text", out var text) ? text.GetString() ?? "" : "",
                "notification"));
        }
        return result;
    }

    private static string Sha256Bytes(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();

    private static async Task<string> Sha256FileAsync(string path)
    {
        await using var stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();
    }

    private static string SafeFilename(string filename)
    {
        foreach (var c in Path.GetInvalidFileNameChars()) filename = filename.Replace(c, '_');
        return string.IsNullOrWhiteSpace(filename) ? "received-file" : filename;
    }

    private static string UniquePath(string path)
    {
        if (!File.Exists(path)) return path;
        var dir = Path.GetDirectoryName(path)!;
        var name = Path.GetFileNameWithoutExtension(path);
        var ext = Path.GetExtension(path);
        for (var i = 1; ; i++)
        {
            var candidate = Path.Combine(dir, $"{name}-{i}{ext}");
            if (!File.Exists(candidate)) return candidate;
        }
    }

    private Dictionary<string, object?> BuildLocalSnapshotPayload()
    {
        var settings = new List<Dictionary<string, string>>
        {
            new() { ["label"] = "Operating system", ["value"] = Environment.OSVersion.VersionString },
            new() { ["label"] = "Machine name", ["value"] = Environment.MachineName },
            new() { ["label"] = "User", ["value"] = Environment.UserName },
            new() { ["label"] = "Power", ["value"] = SystemParameters.PowerLineStatus.ToString() }
        };

        var drive = new DriveInfo(Path.GetPathRoot(Environment.SystemDirectory)!);
        var storage = drive.IsReady
            ? $"{FormatBytes(drive.TotalSize - drive.AvailableFreeSpace)} used / {FormatBytes(drive.TotalSize)}"
            : "Unavailable";

        return new Dictionary<string, object?>
        {
            ["device_title"] = _config.DeviceName,
            ["device_subtitle"] = "Windows desktop",
            ["battery"] = SystemParameters.PowerLineStatus == PowerLineStatus.Online ? "AC power" : "Portable",
            ["storage"] = storage,
            ["notification_access"] = "Not connected",
            ["gallery_access"] = "Granted",
            ["settings"] = settings
        };
    }

    private static Dictionary<string, object?> BuildDirectoryPayload(string directoryPath, string type)
    {
        var items = Directory.Exists(directoryPath)
            ? Directory.GetFiles(directoryPath)
                .Select(path => new FileInfo(path))
                .OrderByDescending(file => file.LastWriteTimeUtc)
                .Take(18)
                .Select(file => new Dictionary<string, object?>
                {
                    ["name"] = file.Name,
                    ["location"] = file.DirectoryName ?? directoryPath,
                    ["size"] = file.Length,
                    ["type"] = type
                })
                .Cast<object>()
                .ToArray()
            : Array.Empty<object>();

        return new Dictionary<string, object?> { ["items"] = items };
    }

    private static string FormatBytes(long value)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var size = (double)value;
        var order = 0;
        while (size >= 1024 && order < units.Length - 1)
        {
            order++;
            size /= 1024;
        }
        return $"{size:0.#} {units[order]}";
    }

    public void Dispose()
    {
        _stop.Cancel();
        _stop.Dispose();
    }
}
