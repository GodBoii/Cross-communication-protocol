using CCP.Windows.Models;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

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

    public void Dispose()
    {
        _stop.Cancel();
        _stop.Dispose();
    }
}
