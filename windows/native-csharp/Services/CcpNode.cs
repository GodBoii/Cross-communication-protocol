using CCP.Windows.Models;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Windows;

namespace CCP.Windows.Services;

public sealed class CcpNode : IDisposable
{
    private const string Protocol = "ccp.v0";
    private const int UdpPort = 47827;
    private const int TcpPort = 47828;
    private const int ChunkSize = 64 * 1024;
    private const int StalePeerSeconds = 20;
    private const int ConnectTimeoutMs = 2500;

    private readonly ConfigStore _config = new();
    private readonly ConcurrentDictionary<string, PeerView> _peers = new();
    private readonly ConcurrentDictionary<string, string?> _preferredTransports = new();
    private readonly Action<IReadOnlyList<PeerView>> _onPeers;
    private readonly Action<string> _onEvent;
    private readonly Func<string, string, bool> _confirm;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<string, CloudIncomingTransfer> _cloudIncomingTransfers = new();

    // ── Cloud mode state ──────────────────────────────────────────────────
    private bool _cloudModeEnabled;
    public bool IsCloudModeEnabled => _cloudModeEnabled;

    // ── Convex cloud bridge ────────────────────────────────────────────────
    public ConvexService Convex { get; }

    public CcpNode(Action<IReadOnlyList<PeerView>> onPeers, Action<string> onEvent, Func<string, string, bool> confirm)
    {
        _onPeers = onPeers;
        _onEvent = onEvent;
        _confirm = confirm;

        Convex = new ConvexService(_config.DeviceId, _config.DeviceName, _config.PrivateKey);
        Convex.SetLogger(msg => _onEvent(msg));
        Convex.OnMessageReceived += HandleCloudMessage;
    }

    public Task StartAsync()
    {
        _ = Task.Run(() => BroadcastLoopAsync(_stop.Token));
        _ = Task.Run(() => ListenDiscoveryAsync(_stop.Token));
        _ = Task.Run(() => ListenTcpAsync(_stop.Token));
        Convex.Start();
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
            // Include our public key so the peer can complete ECDH immediately
            ["public_key"] = Convex.PublicKeyB64,
        }));
        if (response is not null && response.Payload.TryGetValue("accepted", out var accepted) && AsBool(accepted))
        {
            _config.Trust(new SenderInfo(peer.DeviceId, peer.DeviceName, peer.Platform));
            UpsertPeer(peer with { Trusted = true, LastSeen = DateTime.Now });
            _onEvent($"Paired with {peer.DeviceName}");
            // Trigger cloud key exchange in background
            _ = Task.Run(() => DeferredKeyExchangeAsync(peer.DeviceId));
        }
        else
        {
            _onEvent($"Pairing rejected by {peer.DeviceName}");
        }
    }

    private async Task DeferredKeyExchangeAsync(string peerDeviceId)
    {
        for (int attempt = 0; attempt < 5; attempt++)
        {
            await Task.Delay(1000 * (1 << attempt));
            var pubKey = await Convex.GetPeerPublicKeyAsync(peerDeviceId);
            if (pubKey is not null)
            {
                var fp = await Convex.CompleteKeyExchangeAsync(peerDeviceId, pubKey, "wifi");
                _onEvent($"Cloud key exchange OK for {peerDeviceId[..8]}… (fp: {fp[..12]}…)");
                return;
            }
        }
        _onEvent($"Key exchange failed for {peerDeviceId[..8]}… after 5 attempts");
    }

    public async Task SendFileAsync(PeerView peer, string path)
    {
        if (!peer.Trusted)
        {
            _onEvent("Pair with the device before sending files.");
            return;
        }

        if (peer.IsCloudPeer)
        {
            await SendFileViaCloudAsync(peer, path);
            return;
        }

        var file = new FileInfo(path);
        var transferId = Guid.NewGuid().ToString();
        var fullHash = await Sha256FileAsync(path);
        var totalChunks = (int)((file.Length + ChunkSize - 1) / ChunkSize);

        using var socket = await ConnectPeerAsync(peer);
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

        // Cloud peers use cloud relay, local peers use direct TCP
        if (peer.IsCloudPeer)
        {
            return await GetPeerPanelViaCloudAsync(peer);
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
            Notifications: ParseNotifications(notifications));
    }

    // ── Cloud-based operations ─────────────────────────────────────────────

    /// <summary>
    /// Fetch the device panel data entirely through the Convex cloud relay.
    /// Used when the peer is only reachable via Long Distance mode.
    /// </summary>
    private async Task<RemoteDevicePanel> GetPeerPanelViaCloudAsync(PeerView peer)
    {
        _onEvent($"☁ Loading panel for {peer.DeviceName} via cloud relay…");

        var snapshot = await Convex.SendCloudRequestAsync(peer.DeviceId, "device.snapshot.request", timeoutMs: 20_000);
        var gallery = await Convex.SendCloudRequestAsync(peer.DeviceId, "gallery.list.request", timeoutMs: 20_000);
        var files = await Convex.SendCloudRequestAsync(peer.DeviceId, "files.list.request", timeoutMs: 20_000);
        var notifications = await Convex.SendCloudRequestAsync(peer.DeviceId, "notifications.list.request", timeoutMs: 20_000);

        return new RemoteDevicePanel(
            Title: snapshot?["device_title"]?.GetValue<string>() ?? peer.DeviceName,
            Subtitle: snapshot?["device_subtitle"]?.GetValue<string>() ?? peer.Platform,
            Battery: snapshot?["battery"]?.GetValue<string>() ?? "Unknown",
            Storage: snapshot?["storage"]?.GetValue<string>() ?? "Unknown",
            NotificationAccess: snapshot?["notification_access"]?.GetValue<string>() ?? "Unknown",
            GalleryAccess: snapshot?["gallery_access"]?.GetValue<string>() ?? "Unknown",
            Settings: ParseJsonNodeFacts(snapshot?["settings"]),
            Gallery: ParseJsonNodeItems(gallery?["items"], "gallery"),
            Files: ParseJsonNodeItems(files?["items"], "file"),
            Notifications: ParseJsonNodeNotifications(notifications));
    }

    /// <summary>
    /// Toggle Long Distance (cloud) mode. When enabled, loads all paired peers
    /// from Convex and adds them to the peer list as cloud peers.
    /// </summary>
    public async Task ToggleCloudModeAsync()
    {
        _cloudModeEnabled = !_cloudModeEnabled;

        if (_cloudModeEnabled)
        {
            _onEvent("☁ Long Distance mode enabled — loading cloud peers…");
            await LoadCloudPeersAsync();
        }
        else
        {
            _onEvent("☁ Long Distance mode disabled");
            // Remove cloud peers from the peer list
            foreach (var entry in _peers.ToArray())
            {
                if (entry.Value.IsCloudPeer && _peers.TryRemove(entry.Key, out _)) { }
            }
            PublishPeers();
        }
    }

    /// <summary>
    /// Load all paired peers from Convex sessions, check their online status,
    /// and add them to the peer list as cloud peers.
    /// </summary>
    public async Task LoadCloudPeersAsync()
    {
        try
        {
            var pairedPeers = await Convex.ListPairedPeersAsync();
            var loaded = 0;

            foreach (var (deviceId, fingerprint, pairedVia, online) in pairedPeers)
            {
                // Skip if already visible as a local peer
                if (_peers.TryGetValue(deviceId, out var existing) && !existing.IsCloudPeer)
                    continue;

                // Fetch device info from Convex
                var info = await Convex.GetPeerDeviceInfoAsync(deviceId);
                var name = info?.Name ?? $"Cloud device {deviceId[..8]}…";
                var platform = info?.Platform ?? "unknown";

                // Ensure we have the session key loaded
                await Convex.LoadSessionFromCloudAsync(deviceId);

                UpsertPeer(new PeerView
                {
                    DeviceId = deviceId,
                    DeviceName = name,
                    Platform = platform,
                    Address = IPAddress.Loopback,  // dummy — not used for cloud peers
                    TcpPort = 0,
                    Trusted = true,  // paired peers are trusted
                    LastSeen = DateTime.Now,
                    AvailableTransports = ["cloud"],
                    Routes = [],
                    IsCloudPeer = true,
                    CloudOnline = online,
                });
                loaded++;
            }

            _onEvent(loaded > 0
                ? $"☁ Found {loaded} cloud peer(s)"
                : "☁ No paired peers found in cloud");
        }
        catch (Exception ex)
        {
            _onEvent($"☁ Failed to load cloud peers: {ex.Message}");
        }
    }

    public string GetPreferredTransport(string deviceId)
    {
        return _preferredTransports.TryGetValue(deviceId, out var value) && !string.IsNullOrWhiteSpace(value)
            ? value
            : "auto";
    }

    public void SetPreferredTransport(string deviceId, string? transport)
    {
        if (string.IsNullOrWhiteSpace(transport) || string.Equals(transport, "auto", StringComparison.OrdinalIgnoreCase))
        {
            _preferredTransports.TryRemove(deviceId, out _);
            return;
        }

        _preferredTransports[deviceId] = transport;
    }

    public async Task<bool> RequestRemoteActionAsync(PeerView peer, string action, Dictionary<string, object?>? args = null)
    {
        // Cloud peers: route through cloud relay
        if (peer.IsCloudPeer)
        {
            return await RequestRemoteActionViaCloudAsync(peer, action, args);
        }

        var payload = new Dictionary<string, object?>
        {
            ["action"] = action,
            ["args"] = args ?? new Dictionary<string, object?>()
        };

        var response = await SendSingleAsync(peer, Envelope("remote.action.request", payload));
        if (response is null)
        {
            _onEvent($"No response for remote action {action}");
            return false;
        }

        var ok = AsBool(response.Payload.GetValueOrDefault("ok"));
        var message = AsString(response.Payload.GetValueOrDefault("message"));
        _onEvent(ok
            ? $"Remote action completed: {message ?? action}"
            : $"Remote action failed: {message ?? action}");
        return ok;
    }

    private async Task<bool> RequestRemoteActionViaCloudAsync(PeerView peer, string action, Dictionary<string, object?>? args = null)
    {
        _onEvent($"☁ Sending remote action {action} to {peer.DeviceName} via cloud…");
        var payload = new JsonObject
        {
            ["action"] = action,
            ["args"] = JsonSerializer.SerializeToNode(args ?? new Dictionary<string, object?>()),
        };

        var response = await Convex.SendCloudRequestAsync(peer.DeviceId, "remote.action.request", payload, timeoutMs: 20_000);
        if (response is null)
        {
            _onEvent($"☁ No cloud response for remote action {action}");
            return false;
        }

        var ok = response["ok"]?.GetValue<bool>() ?? false;
        var message = response["message"]?.GetValue<string>();
        _onEvent(ok
            ? $"☁ Remote action completed: {message ?? action}"
            : $"☁ Remote action failed: {message ?? action}");
        return ok;
    }

    private async Task SendFileViaCloudAsync(PeerView peer, string path)
    {
        var file = new FileInfo(path);
        var transferId = Guid.NewGuid().ToString();
        var fullHash = await Sha256FileAsync(path);
        var totalChunks = (int)((file.Length + ChunkSize - 1) / ChunkSize);

        _onEvent($"☁ Offering {file.Name} to {peer.DeviceName} via cloud relay…");
        var offer = await Convex.SendCloudRequestAsync(peer.DeviceId, "file.offer", new JsonObject
        {
            ["transfer_id"] = transferId,
            ["filename"] = file.Name,
            ["size"] = file.Length,
            ["sha256"] = fullHash,
            ["chunk_size"] = ChunkSize,
            ["total_chunks"] = totalChunks,
        }, timeoutMs: 30_000);

        if (offer is null || offer["accepted"]?.GetValue<bool>() != true)
        {
            var reason = offer?["reason"]?.GetValue<string>();
            _onEvent($"{peer.DeviceName} rejected {file.Name}{(string.IsNullOrWhiteSpace(reason) ? "" : $": {reason}")}");
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
            var ok = await Convex.PushMessageAsync(peer.DeviceId, "file.chunk", new JsonObject
            {
                ["transfer_id"] = transferId,
                ["index"] = index,
                ["sha256"] = Sha256Bytes(chunk),
                ["data_b64"] = Convert.ToBase64String(chunk),
            }, ttlMs: 10 * 60 * 1000);

            if (!ok)
            {
                _onEvent($"☁ Cloud send failed while sending chunk {index} of {file.Name}");
                return;
            }

            sent += read;
            _onEvent($"☁ Sending {file.Name}: {sent} / {file.Length} bytes");
        }

        var complete = await Convex.SendCloudRequestAsync(peer.DeviceId, "file.complete", new JsonObject
        {
            ["transfer_id"] = transferId,
            ["sha256"] = fullHash,
        }, timeoutMs: 30_000);

        _onEvent(complete?["ok"]?.GetValue<bool>() == true
            ? $"☁ Sent and verified {file.Name}"
            : $"☁ Receiver verification failed for {file.Name}");
    }

    private async Task BroadcastLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            await SendDiscoveryAsync();
            PruneStalePeers();
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
            ["capabilities"] = new[] { "pairing", "file.transfer", "device.snapshot", "gallery.list", "files.list", "notifications.list", "native.windows" },
            ["transports"] = BuildTransportPayload(),
            ["endpoints"] = BuildEndpointPayload(),
            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds()
        });
        var bytes = Encoding.UTF8.GetBytes(packet);
        foreach (var target in GetBroadcastTargets())
        {
            try
            {
                await udp.SendAsync(bytes, new IPEndPoint(target, UdpPort));
            }
            catch (SocketException ex)
            {
                _onEvent($"Discovery send failed on {target}: {ex.Message}");
            }
        }
    }

    private static IReadOnlyList<IPAddress> GetBroadcastTargets()
    {
        var targets = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            IPAddress.Broadcast.ToString()
        };

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces().Where(nic => nic.OperationalStatus == OperationalStatus.Up))
        {
            foreach (var address in nic.GetIPProperties().UnicastAddresses)
            {
                if (address.Address.AddressFamily != AddressFamily.InterNetwork ||
                    IPAddress.IsLoopback(address.Address) ||
                    address.IPv4Mask is null)
                {
                    continue;
                }

                var ip = address.Address.GetAddressBytes();
                var mask = address.IPv4Mask.GetAddressBytes();
                var broadcast = new byte[4];
                for (var i = 0; i < broadcast.Length; i++)
                {
                    broadcast[i] = (byte)(ip[i] | ~mask[i]);
                }
                targets.Add(new IPAddress(broadcast).ToString());
            }
        }

        return targets.Select(IPAddress.Parse).ToList();
    }

    private async Task ListenDiscoveryAsync(CancellationToken token)
    {
        using var udp = new UdpClient { EnableBroadcast = true };
        udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, UdpPort));
        try
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    var result = await udp.ReceiveAsync(token);
                    var doc = JsonDocument.Parse(result.Buffer).RootElement;
                    if (!doc.TryGetProperty("protocol", out var protocol) || protocol.GetString() != Protocol) continue;
                    var deviceId = doc.GetProperty("device_id").GetString() ?? "";
                    if (deviceId == _config.DeviceId) continue;

                    var routes = ParseRoutes(doc, result.RemoteEndPoint.Address);
                    UpsertPeer(new PeerView
                    {
                        DeviceId = deviceId,
                        DeviceName = doc.GetProperty("device_name").GetString() ?? "Unknown",
                        Platform = doc.GetProperty("platform").GetString() ?? "unknown",
                        Address = result.RemoteEndPoint.Address,
                        TcpPort = doc.GetProperty("tcp_port").GetInt32(),
                        Trusted = _config.IsTrusted(deviceId),
                        LastSeen = DateTime.Now,
                        AvailableTransports = ParseTransportModes(doc),
                        Routes = routes
                    });
                }
                catch (JsonException ex)
                {
                    _onEvent($"Ignored malformed discovery packet: {ex.Message}");
                }
                catch (SocketException ex)
                {
                    _onEvent($"Discovery receive failed: {ex.Message}");
                    await Task.Delay(1000, token).ContinueWith(_ => { });
                }
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private async Task ListenTcpAsync(CancellationToken token)
    {
        var listener = new TcpListener(IPAddress.Any, TcpPort);
        listener.Start();
        _onEvent($"TCP listener active on {TcpPort}");
        try
        {
            while (!token.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(token);
                _ = Task.Run(() => HandleClientAsync(client, token), token);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    private async Task HandleClientAsync(TcpClient client, CancellationToken token)
    {
        using var socket = client;
        socket.NoDelay = true;
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
                        if (accepted)
                        {
                            _config.Trust(message.Sender);
                            // Key exchange: use public key from pair packet if present
                            var peerPubKey = AsString(message.Payload.GetValueOrDefault("public_key"));
                            if (!string.IsNullOrEmpty(peerPubKey) && peerPubKey != "reserved-for-v1")
                            {
                                _ = Task.Run(async () =>
                                {
                                    var fp = await Convex.CompleteKeyExchangeAsync(message.Sender.DeviceId, peerPubKey, "wifi");
                                    _onEvent($"Cloud key exchange with {message.Sender.DeviceName} complete (fp: {fp[..12]}…)");
                                });
                            }
                            else
                            {
                                _ = Task.Run(() => DeferredKeyExchangeAsync(message.Sender.DeviceId));
                            }
                        }
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

                    case "remote.action.request":
                        await WriteAsync(writer, Envelope("remote.action.response", new()
                        {
                            ["ok"] = false,
                            ["message"] = "Remote actions are not implemented on Windows yet."
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
        using var client = await ConnectPeerAsync(peer);
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

    private async Task<TcpClient> ConnectPeerAsync(PeerView peer)
    {
        Exception? lastError = null;
        foreach (var route in RankRoutes(peer))
        {
            try
            {
                var client = new TcpClient { NoDelay = true };
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                connectCts.CancelAfter(ConnectTimeoutMs);
                await client.ConnectAsync(route.Host, route.Port, connectCts.Token);
                _onEvent($"Connected to {peer.DeviceName} via {route.Transport}");
                return client;
            }
            catch (Exception ex)
            {
                lastError = ex;
            }
        }

        throw new IOException($"Could not connect to {peer.DeviceName}. {lastError?.Message}", lastError);
    }

    private IEnumerable<PeerRoute> RankRoutes(PeerView peer)
    {
        var routes = peer.Routes.Count > 0
            ? peer.Routes
            : [new PeerRoute { Transport = "direct", Host = peer.Address.ToString(), Port = peer.TcpPort }];

        var priority = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        {
            ["usb"] = 0,
            ["wifi"] = 1,
            ["lan"] = 2,
            ["bluetooth"] = 3,
            ["cloud"] = 4,
            ["direct"] = 5
        };

        var preferred = _preferredTransports.TryGetValue(peer.DeviceId, out var transport) ? transport : null;

        return routes
            .GroupBy(route => $"{route.Transport}|{route.Host}|{route.Port}", StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .OrderBy(route => !string.IsNullOrWhiteSpace(preferred) && route.Transport.Equals(preferred, StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .ThenBy(route => priority.TryGetValue(route.Transport, out var rank) ? rank : 99);
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
        PublishPeers();
    }

    private void PruneStalePeers()
    {
        var cutoff = DateTime.Now.AddSeconds(-StalePeerSeconds);
        var removed = false;
        foreach (var entry in _peers.ToArray())
        {
            if (entry.Value.LastSeen < cutoff && _peers.TryRemove(entry.Key, out _))
            {
                removed = true;
            }
        }

        if (removed)
        {
            PublishPeers();
        }
    }

    private void PublishPeers()
    {
        _onPeers(_peers.Values.OrderByDescending(p => p.LastSeen).ToList());
    }

    private Dictionary<string, object?> BuildTransportPayload()
    {
        return DetectTransportStatus()
            .ToDictionary(
                item => item.Key,
                item => (object?)new Dictionary<string, object?>
                {
                    ["available"] = item.Value.Available,
                    ["connected"] = item.Value.Connected,
                    ["detail"] = item.Value.Detail
                },
                StringComparer.OrdinalIgnoreCase);
    }

    private object[] BuildEndpointPayload()
    {
        return DetectAdvertisedRoutes()
            .Select(route => new Dictionary<string, object?>
            {
                ["transport"] = route.Transport,
                ["host"] = route.Host,
                ["port"] = route.Port
            })
            .Cast<object>()
            .ToArray();
    }

    private Dictionary<string, TransportStatus> DetectTransportStatus()
    {
        var adapters = NetworkInterface.GetAllNetworkInterfaces()
            .Where(nic => nic.OperationalStatus == OperationalStatus.Up)
            .ToList();

        var wifi = adapters.Where(nic => nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211).ToList();
        var ethernet = adapters.Where(nic =>
            nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
            nic.NetworkInterfaceType == NetworkInterfaceType.GigabitEthernet ||
            nic.NetworkInterfaceType == NetworkInterfaceType.FastEthernetFx ||
            nic.NetworkInterfaceType == NetworkInterfaceType.FastEthernetT).ToList();
        var usb = adapters.Where(IsUsbInterface).ToList();
        var bluetooth = adapters.Where(IsBluetoothInterface).ToList();
        var cloudAvailable = adapters.Any(HasUsableIpv4Address);

        return new Dictionary<string, TransportStatus>(StringComparer.OrdinalIgnoreCase)
        {
            ["wifi"] = new(wifi.Count > 0, wifi.Any(HasUsableIpv4Address), DescribeAdapters(wifi)),
            ["lan"] = new(ethernet.Count > 0, ethernet.Any(HasUsableIpv4Address), DescribeAdapters(ethernet)),
            ["usb"] = new(usb.Count > 0, usb.Any(HasUsableIpv4Address), DescribeAdapters(usb)),
            ["bluetooth"] = new(bluetooth.Count > 0, bluetooth.Any(HasUsableIpv4Address), DescribeAdapters(bluetooth)),
            ["cloud"] = new(cloudAvailable, NetworkInterface.GetIsNetworkAvailable(), cloudAvailable ? "Internet-capable network present" : "No routable network")
        };
    }

    private IReadOnlyList<PeerRoute> DetectAdvertisedRoutes()
    {
        var routes = new List<PeerRoute>();
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces().Where(nic => nic.OperationalStatus == OperationalStatus.Up))
        {
            var transport = ClassifyTransport(nic);
            foreach (var address in nic.GetIPProperties().UnicastAddresses)
            {
                if (address.Address.AddressFamily != AddressFamily.InterNetwork || IPAddress.IsLoopback(address.Address))
                {
                    continue;
                }

                routes.Add(new PeerRoute
                {
                    Transport = transport,
                    Host = address.Address.ToString(),
                    Port = TcpPort
                });
            }
        }

        return routes
            .GroupBy(route => $"{route.Transport}|{route.Host}|{route.Port}", StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();
    }

    private static IReadOnlyList<string> ParseTransportModes(JsonElement doc)
    {
        if (!doc.TryGetProperty("transports", out var transports) || transports.ValueKind != JsonValueKind.Object)
        {
            return [];
        }

        return transports.EnumerateObject()
            .Where(item =>
                item.Value.ValueKind == JsonValueKind.Object &&
                item.Value.TryGetProperty("available", out var available) &&
                available.ValueKind == JsonValueKind.True)
            .Select(item => item.Name)
            .ToList();
    }

    private static IReadOnlyList<PeerRoute> ParseRoutes(JsonElement doc, IPAddress fallbackAddress)
    {
        var routes = new List<PeerRoute>();
        var fallbackPort = doc.TryGetProperty("tcp_port", out var portElement) ? portElement.GetInt32() : TcpPort;

        if (doc.TryGetProperty("endpoints", out var endpoints) && endpoints.ValueKind == JsonValueKind.Array)
        {
            foreach (var endpoint in endpoints.EnumerateArray())
            {
                var host = endpoint.TryGetProperty("host", out var hostElement) ? hostElement.GetString() : null;
                var transport = endpoint.TryGetProperty("transport", out var transportElement) ? transportElement.GetString() : null;
                var port = endpoint.TryGetProperty("port", out var endpointPortElement) ? endpointPortElement.GetInt32() : fallbackPort;
                if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(transport))
                {
                    continue;
                }

                routes.Add(new PeerRoute
                {
                    Transport = transport,
                    Host = host,
                    Port = port
                });
            }
        }

        if (routes.Count == 0)
        {
            routes.Add(new PeerRoute
            {
                Transport = "direct",
                Host = fallbackAddress.ToString(),
                Port = fallbackPort
            });
        }

        return routes;
    }

    private static bool HasUsableIpv4Address(NetworkInterface nic)
    {
        return nic.GetIPProperties().UnicastAddresses.Any(address =>
            address.Address.AddressFamily == AddressFamily.InterNetwork &&
            !IPAddress.IsLoopback(address.Address));
    }

    private static bool IsUsbInterface(NetworkInterface nic)
    {
        var text = $"{nic.Name} {nic.Description}";
        return text.Contains("usb", StringComparison.OrdinalIgnoreCase) ||
               text.Contains("rndis", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsBluetoothInterface(NetworkInterface nic)
    {
        var text = $"{nic.Name} {nic.Description}";
        return text.Contains("bluetooth", StringComparison.OrdinalIgnoreCase) ||
               nic.NetworkInterfaceType == NetworkInterfaceType.Ppp;
    }

    private static string ClassifyTransport(NetworkInterface nic)
    {
        if (IsUsbInterface(nic)) return "usb";
        if (nic.NetworkInterfaceType == NetworkInterfaceType.Wireless80211) return "wifi";
        if (IsBluetoothInterface(nic)) return "bluetooth";
        if (nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet ||
            nic.NetworkInterfaceType == NetworkInterfaceType.GigabitEthernet ||
            nic.NetworkInterfaceType == NetworkInterfaceType.FastEthernetFx ||
            nic.NetworkInterfaceType == NetworkInterfaceType.FastEthernetT)
        {
            return "lan";
        }
        return "cloud";
    }

    private static string DescribeAdapters(IReadOnlyCollection<NetworkInterface> adapters)
    {
        return adapters.Count == 0 ? "Unavailable" : string.Join(", ", adapters.Take(2).Select(adapter => adapter.Name));
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
        var transports = DetectTransportStatus();
        var settings = new List<Dictionary<string, string>>
        {
            new() { ["label"] = "Operating system", ["value"] = Environment.OSVersion.VersionString },
            new() { ["label"] = "Machine name", ["value"] = Environment.MachineName },
            new() { ["label"] = "User", ["value"] = Environment.UserName },
            new() { ["label"] = "Power", ["value"] = SystemParameters.PowerLineStatus.ToString() },
            new() { ["label"] = "Routes", ["value"] = string.Join(", ", DetectAdvertisedRoutes().Select(route => route.Transport).Distinct()) },
            new() { ["label"] = "Wi-Fi", ["value"] = FormatTransport(transports, "wifi") },
            new() { ["label"] = "LAN", ["value"] = FormatTransport(transports, "lan") },
            new() { ["label"] = "USB", ["value"] = FormatTransport(transports, "usb") },
            new() { ["label"] = "Bluetooth", ["value"] = FormatTransport(transports, "bluetooth") },
            new() { ["label"] = "Cloud", ["value"] = FormatTransport(transports, "cloud") }
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

    private static string FormatTransport(IReadOnlyDictionary<string, TransportStatus> transports, string key)
    {
        return transports.TryGetValue(key, out var status)
            ? status.Connected ? $"Connected ({status.Detail})" : status.Available ? $"Available ({status.Detail})" : status.Detail
            : "Unknown";
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

    private void HandleCloudMessage(string senderId, string msgType, JsonObject payload)
    {
        var senderShort = senderId[..Math.Min(8, senderId.Length)];
        var requestId = payload["request_id"]?.GetValue<string>();

        switch (msgType)
        {
            case "device.snapshot.request":
            {
                _onEvent($"[Cloud] Snapshot request from {senderShort}…");
                _ = Task.Run(async () =>
                {
                    var dict = BuildLocalSnapshotPayload();
                    var response = JsonNode.Parse(JsonSerializer.Serialize(dict))!.AsObject();
                    if (requestId is not null) response["request_id"] = requestId;
                    await Convex.PushMessageAsync(senderId, "device.snapshot.response", response);
                });
                break;
            }

            case "gallery.list.request":
            {
                _onEvent($"[Cloud] Gallery request from {senderShort}…");
                _ = Task.Run(async () =>
                {
                    var dict = BuildDirectoryPayload(
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)), "gallery");
                    var response = JsonNode.Parse(JsonSerializer.Serialize(dict))!.AsObject();
                    if (requestId is not null) response["request_id"] = requestId;
                    await Convex.PushMessageAsync(senderId, "gallery.list.response", response);
                });
                break;
            }

            case "files.list.request":
            {
                _onEvent($"[Cloud] Files request from {senderShort}…");
                _ = Task.Run(async () =>
                {
                    var dict = BuildDirectoryPayload(
                        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"), "file");
                    var response = JsonNode.Parse(JsonSerializer.Serialize(dict))!.AsObject();
                    if (requestId is not null) response["request_id"] = requestId;
                    await Convex.PushMessageAsync(senderId, "files.list.response", response);
                });
                break;
            }

            case "notifications.list.request":
            {
                _onEvent($"[Cloud] Notifications request from {senderShort}…");
                _ = Task.Run(async () =>
                {
                    var dict = new Dictionary<string, object?>
                    {
                        ["permission_granted"] = false,
                        ["items"] = Array.Empty<object>()
                    };
                    var response = JsonNode.Parse(JsonSerializer.Serialize(dict))!.AsObject();
                    if (requestId is not null) response["request_id"] = requestId;
                    await Convex.PushMessageAsync(senderId, "notifications.list.response", response);
                });
                break;
            }

            case "remote.action.request":
            {
                var action = payload["action"]?.GetValue<string>() ?? "";
                _onEvent($"[Cloud] Remote action from {senderShort}…: {action}");
                _ = Task.Run(async () =>
                {
                    // Windows doesn't fully support remote actions yet,
                    // but we acknowledge the request properly
                    var response = new JsonObject
                    {
                        ["ok"] = false,
                        ["message"] = "Remote actions are not fully implemented on Windows yet.",
                        ["action"] = action,
                    };
                    if (requestId is not null) response["request_id"] = requestId;
                    await Convex.PushMessageAsync(senderId, "remote.action.response", response);
                });
                break;
            }

            case "file.offer":
            {
                var filename = payload["filename"]?.GetValue<string>() ?? "?";
                _onEvent($"[Cloud] File offer from {senderShort}…: {filename}");
                _ = Task.Run(async () =>
                {
                    var transferId = payload["transfer_id"]?.GetValue<string>() ?? Guid.NewGuid().ToString();
                    var response = new JsonObject
                    {
                        ["transfer_id"] = transferId,
                        ["accepted"] = false,
                        ["resume_from"] = 0,
                    };
                    if (requestId is not null) response["request_id"] = requestId;

                    if (!_config.IsTrusted(senderId))
                    {
                        response["reason"] = "peer is not paired";
                        await Convex.PushMessageAsync(senderId, "file.offer.response", response);
                        return;
                    }

                    var safeName = SafeFilename(filename);
                    var allow = _confirm("Incoming Cloud File", $"Accept {safeName} from {senderShort} via cloud relay?");
                    if (!allow)
                    {
                        response["reason"] = "rejected";
                        await Convex.PushMessageAsync(senderId, "file.offer.response", response);
                        return;
                    }

                    var inbox = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "CCP-Inbox");
                    Directory.CreateDirectory(inbox);
                    var targetPath = UniquePath(Path.Combine(inbox, safeName));
                    var output = File.Create(targetPath);
                    var key = $"{senderId}|{transferId}";
                    _cloudIncomingTransfers[key] = new CloudIncomingTransfer(
                        TargetPath: targetPath,
                        ExpectedHash: payload["sha256"]?.GetValue<string>() ?? "",
                        Output: output);

                    response["accepted"] = true;
                    response["reason"] = null;
                    await Convex.PushMessageAsync(senderId, "file.offer.response", response);
                    _onEvent($"[Cloud] Receiving {safeName}");
                });
                break;
            }

            case "file.chunk":
            {
                var transferId = payload["transfer_id"]?.GetValue<string>() ?? "";
                var key = $"{senderId}|{transferId}";
                if (!_cloudIncomingTransfers.TryGetValue(key, out var transfer)) break;

                var raw = Convert.FromBase64String(payload["data_b64"]?.GetValue<string>() ?? "");
                if (Sha256Bytes(raw) != payload["sha256"]?.GetValue<string>())
                {
                    _onEvent($"[Cloud] Chunk checksum failed for {Path.GetFileName(transfer.TargetPath)}");
                    break;
                }

                transfer.Lock.Wait();
                try
                {
                    transfer.Output.Write(raw);
                    _onEvent($"[Cloud] Received chunk {payload["index"]?.ToString() ?? "?"}");
                }
                finally
                {
                    transfer.Lock.Release();
                }
                break;
            }

            case "file.complete":
            {
                _ = Task.Run(async () =>
                {
                    var transferId = payload["transfer_id"]?.GetValue<string>() ?? "";
                    var key = $"{senderId}|{transferId}";
                    var response = new JsonObject
                    {
                        ["transfer_id"] = transferId,
                        ["ok"] = false,
                    };
                    if (requestId is not null) response["request_id"] = requestId;

                    if (_cloudIncomingTransfers.TryRemove(key, out var transfer))
                    {
                        await transfer.Lock.WaitAsync();
                        try
                        {
                            await transfer.Output.DisposeAsync();
                            var actual = await Sha256FileAsync(transfer.TargetPath);
                            var expected = payload["sha256"]?.GetValue<string>() ?? transfer.ExpectedHash;
                            var ok = actual == expected && actual == transfer.ExpectedHash;
                            response["ok"] = ok;
                            response["sha256"] = actual;
                            _onEvent(ok
                                ? $"[Cloud] Received and verified {transfer.TargetPath}"
                                : $"[Cloud] Checksum failed for {transfer.TargetPath}");
                        }
                        finally
                        {
                            transfer.Lock.Release();
                            transfer.Lock.Dispose();
                        }
                    }

                    await Convex.PushMessageAsync(senderId, "file.complete.response", response);
                });
                break;
            }

            case "clipboard.sync":
            {
                _onEvent($"[Cloud] Clipboard sync from {senderShort}…");
                break;
            }

            case "notification.push":
            {
                var title = payload["title"]?.GetValue<string>() ?? "Notification";
                _onEvent($"[Cloud] Notification from {senderShort}…: {title}");
                break;
            }

            default:
                _onEvent($"[Cloud] {msgType} from {senderShort}…");
                break;
        }
    }

    // ── JsonNode-based parsers for cloud responses ─────────────────────────

    private static IReadOnlyList<RemoteFactView> ParseJsonNodeFacts(JsonNode? node)
    {
        var result = new List<RemoteFactView>();
        if (node is not JsonArray array) return result;
        foreach (var item in array)
        {
            if (item is not JsonObject obj) continue;
            result.Add(new RemoteFactView(
                obj["label"]?.GetValue<string>() ?? "Setting",
                obj["value"]?.GetValue<string>() ?? "Unknown"));
        }
        return result;
    }

    private static IReadOnlyList<RemoteContentItem> ParseJsonNodeItems(JsonNode? node, string fallbackType)
    {
        var result = new List<RemoteContentItem>();
        if (node is not JsonArray array) return result;
        foreach (var item in array)
        {
            if (item is not JsonObject obj) continue;
            var subtitle = obj["location"]?.GetValue<string>()
                ?? obj["mime_type"]?.GetValue<string>()
                ?? obj["size"]?.ToString()
                ?? fallbackType;
            result.Add(new RemoteContentItem(
                obj["name"]?.GetValue<string>() ?? "Untitled",
                subtitle,
                obj["type"]?.GetValue<string>() ?? fallbackType));
        }
        return result;
    }

    private static IReadOnlyList<RemoteContentItem> ParseJsonNodeNotifications(JsonObject? payload)
    {
        var result = new List<RemoteContentItem>();
        if (payload?["items"] is not JsonArray array) return result;
        foreach (var item in array)
        {
            if (item is not JsonObject obj) continue;
            result.Add(new RemoteContentItem(
                obj["title"]?.GetValue<string>() ?? "Notification",
                obj["text"]?.GetValue<string>() ?? "",
                "notification"));
        }
        return result;
    }

    public void Dispose()
    {
        _stop.Cancel();
        foreach (var transfer in _cloudIncomingTransfers.Values)
        {
            transfer.Output.Dispose();
            transfer.Lock.Dispose();
        }
        _stop.Dispose();
        _ = Convex.StopAsync();
        Convex.Dispose();
    }

    private sealed record CloudIncomingTransfer(
        string TargetPath,
        string ExpectedHash,
        FileStream Output)
    {
        public SemaphoreSlim Lock { get; } = new(1, 1);
    }
}
