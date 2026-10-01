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
    private const string Protocol = CcpWire.Protocol;
    private const int UdpPort = CcpWire.UdpPort;
    private const int TcpPort = CcpWire.TcpPort;
    private const int ChunkSize = CcpWire.ChunkSize;
    private const int StalePeerSeconds = 20;
    private const int ConnectTimeoutMs = 2500;
    private const int MaxCloudTransfers = 4;
    private static readonly TimeSpan PromptTimeout = TimeSpan.FromSeconds(60);
    private static readonly string[] PanelRequests =
        ["device.snapshot.request", "gallery.list.request", "files.list.request", "notifications.list.request"];

    private readonly ConfigStore _config = new();
    private readonly ConcurrentDictionary<string, PeerView> _peers = new();
    private readonly ConcurrentDictionary<string, string?> _preferredTransports = new();
    private readonly Action<IReadOnlyList<PeerView>> _onPeers;
    private readonly Action<string> _onEvent;
    private readonly Func<string, string, bool> _confirm;
    private readonly Action<string, string?> _onOutgoingPairCode;
    private readonly CancellationTokenSource _stop = new();
    private readonly ConcurrentDictionary<string, IncomingTransfer> _cloudIncomingTransfers = new();
    private readonly ConcurrentDictionary<string, DateTime> _lastSessionSync = new();
    private readonly SemaphoreSlim _connectionSlots = new(CcpWire.MaxConcurrentConnections, CcpWire.MaxConcurrentConnections);
    private int _pairingBusy;
    private TcpClient? _outgoingPairClient;

    private static string InboxDirectory =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads", "CCP-Inbox");

    // ── Cloud mode state ──────────────────────────────────────────────────
    private bool _cloudModeEnabled;
    public bool IsCloudModeEnabled => _cloudModeEnabled;

    // ── Convex cloud bridge ────────────────────────────────────────────────
    public ConvexService Convex { get; }

    /// <param name="onOutgoingPairCode">Called with (peer name, code) while an outgoing pairing awaits approval, and (name, null) when it ends.</param>
    public CcpNode(
        Action<IReadOnlyList<PeerView>> onPeers,
        Action<string> onEvent,
        Func<string, string, bool> confirm,
        Action<string, string?>? onOutgoingPairCode = null)
    {
        _onPeers = onPeers;
        _onEvent = onEvent;
        _confirm = confirm;
        _onOutgoingPairCode = onOutgoingPairCode ?? ((_, _) => { });

        Convex = new ConvexService(_config.DeviceId, _config.DeviceName, _config.CloudAuthToken, _config.PairSecret);
        Convex.SetLogger(msg => _onEvent(msg));
        Convex.OnMessageReceived += HandleCloudMessage;
    }

    private JsonObject SenderNode => new()
    {
        ["device_id"] = _config.DeviceId,
        ["device_name"] = _config.DeviceName,
        ["platform"] = "windows",
    };

    public Task StartAsync()
    {
        _ = Task.Run(() => RunResilientAsync("Discovery broadcast", BroadcastLoopAsync));
        _ = Task.Run(() => RunResilientAsync("UDP discovery listener", ListenDiscoveryAsync));
        _ = Task.Run(() => RunResilientAsync("TCP listener", ListenTcpAsync));
        _ = Task.Run(() => RunResilientAsync("Cloud peer sync", CloudPeerLoopAsync));
        _ = Task.Run(CleanupInbox);
        Convex.Start(typeof(CcpNode).Assembly.GetName().Version?.ToString(3) ?? "0.3.0");
        _onEvent($"Native Windows node started as {_config.DeviceName}");
        return Task.CompletedTask;
    }

    /// <summary>Restarts a background loop with backoff if it crashes (e.g. port briefly in use).</summary>
    private async Task RunResilientAsync(string name, Func<CancellationToken, Task> loop)
    {
        var backoff = TimeSpan.FromSeconds(1);
        while (!_stop.IsCancellationRequested)
        {
            try
            {
                await loop(_stop.Token);
                return;
            }
            catch (OperationCanceledException) when (_stop.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                _onEvent($"{name} failed: {ex.Message}; retrying in {backoff.TotalSeconds:0}s");
                try { await Task.Delay(backoff, _stop.Token); } catch (OperationCanceledException) { return; }
                backoff = TimeSpan.FromSeconds(Math.Min(backoff.TotalSeconds * 2, 30));
            }
        }
    }

    public void BroadcastNow()
    {
        _ = Task.Run(async () =>
        {
            try { await SendDiscoveryAsync(); }
            catch (Exception ex) { _onEvent($"Discovery broadcast failed: {ex.Message}"); }
        });
        _onEvent("Discovery broadcast sent");
    }

    /// <summary>Runs a user-initiated operation, reporting failures instead of letting them escape.</summary>
    private async Task<T?> GuardAsync<T>(string label, Func<Task<T?>> work)
    {
        try
        {
            return await work();
        }
        catch (Exception ex) when (ex is not OperationCanceledException || !_stop.IsCancellationRequested)
        {
            _onEvent($"{label} failed: {ex.Message}");
            return default;
        }
    }

    // ── Pairing ────────────────────────────────────────────────────────────

    /// <summary>
    /// v1 pairing: ECDH with a commitment; both screens show the same 6-digit
    /// code and the other device's user approves only if they match.
    /// </summary>
    public Task PairAsync(PeerView peer) => GuardAsync<object>($"Pairing with {peer.DeviceName}", async () =>
    {
        if (peer.IsCloudPeer)
        {
            _onEvent($"Pair with {peer.DeviceName} on the same network first.");
            return null;
        }

        using var client = await ConnectPeerAsync(peer);
        _outgoingPairClient = client;
        try
        {
            await RunInitiatorPairingAsync(client, peer);
        }
        finally
        {
            _outgoingPairClient = null;
            _onOutgoingPairCode(peer.DeviceName, null);
        }
        return null;
    });

    public void CancelOutgoingPair()
    {
        try { _outgoingPairClient?.Close(); } catch (ObjectDisposedException) { }
    }

    private async Task RunInitiatorPairingAsync(TcpClient client, PeerView peer)
    {
        var stream = client.GetStream();
        var reader = new BoundedLineReader(stream);
        var writer = new LineWriter(stream);
        using var initiator = new PairingInitiator(_config.DeviceId);
        await writer.WriteLineAsync(Envelope("pair.request", initiator.RequestPayload()).ToJsonString());

        var challenge = CcpWire.ParseObject(await CcpWire.ReadLineWithTimeoutAsync(reader, _stop.Token)
            ?? throw new EndOfStreamException("Connection closed during pairing"));
        if (CcpWire.Type(challenge) == "pair.response")
        {
            _onEvent($"{peer.DeviceName} refused pairing: {CcpWire.Str(CcpWire.Payload(challenge)["reason"])}");
            return;
        }
        if (CcpWire.Type(challenge) != "pair.challenge") throw new InvalidDataException("Unexpected pairing message");
        if (CcpWire.SenderId(challenge) != peer.DeviceId) throw new InvalidDataException("Peer identity changed during pairing");

        var result = initiator.OnChallenge(peer.DeviceId, CcpWire.Payload(challenge));
        await writer.WriteLineAsync(Envelope("pair.reveal", initiator.RevealPayload()).ToJsonString());
        _onOutgoingPairCode(peer.DeviceName, result.Sas);
        _onEvent($"Check that {peer.DeviceName} shows code {result.Sas}");

        var response = CcpWire.ParseObject(await CcpWire.ReadLineWithTimeoutAsync(reader, _stop.Token)
            ?? throw new EndOfStreamException("Connection closed before approval"));
        var payload = CcpWire.Payload(response);
        if (CcpWire.Type(response) != "pair.response" || !CcpWire.Bool(payload["accepted"]))
        {
            _onEvent($"Pairing rejected by {peer.DeviceName}: {CcpWire.Str(payload["reason"], "rejected")}");
            return;
        }
        if (!result.VerifyResponderConfirm(CcpWire.Str(payload["confirm"])))
        {
            throw new CryptographicException("Key confirmation failed; pairing aborted");
        }

        _config.Trust(new SenderInfo(peer.DeviceId, peer.DeviceName, peer.Platform), result.PairSecret);
        UpsertPeer(peer with { Trusted = true, LastSeen = DateTime.Now });
        _onEvent($"Paired with {peer.DeviceName}");
        _ = Task.Run(() => EstablishCloudSessionAsync(peer.DeviceId, result.PairSecret));
    }

    private async Task HandlePairRequestAsync(TcpClient client, BoundedLineReader reader, LineWriter writer, JsonObject request, CancellationToken token)
    {
        var sender = request["sender"] as JsonObject ?? new JsonObject();
        var peerId = CcpWire.Str(sender["device_id"]);
        var peerName = Truncate(CcpWire.Str(sender["device_name"], "Unknown"), 64);
        var peerPlatform = Truncate(CcpWire.Str(sender["platform"], "unknown"), 16);
        Task Refuse(string reason) => writer.WriteLineAsync(Envelope("pair.response", new JsonObject
        {
            ["accepted"] = false,
            ["reason"] = reason,
        }).ToJsonString(), token);

        if (!CcpIdentity.IsValidDeviceId(peerId) || peerId == _config.DeviceId)
        {
            await Refuse("invalid_device_id");
            return;
        }
        // One prompt at a time; this also rate-limits prompt spam from the LAN.
        if (Interlocked.CompareExchange(ref _pairingBusy, 1, 0) != 0)
        {
            await Refuse("busy");
            return;
        }

        try
        {
            PairingResponder responder;
            try
            {
                responder = new PairingResponder(_config.DeviceId, peerId, CcpWire.Payload(request));
            }
            catch (PairingException ex)
            {
                await Refuse(ex.Message);
                return;
            }
            using (responder)
            {
                await writer.WriteLineAsync(Envelope("pair.challenge", responder.ChallengePayload()).ToJsonString(), token);
                var line = await CcpWire.ReadLineWithTimeoutAsync(reader, token);
                if (line is null) return;
                var reveal = CcpWire.ParseObject(line);
                if (CcpWire.Type(reveal) != "pair.reveal")
                {
                    await Refuse("protocol_error");
                    return;
                }

                CcpPairing.Result result;
                try
                {
                    result = responder.OnReveal(CcpWire.Payload(reveal));
                }
                catch (PairingException ex)
                {
                    _onEvent($"Pairing from {peerName} failed: {ex.Message}");
                    await Refuse(ex.Message);
                    return;
                }

                var warning = _config.IsTrusted(peerId)
                    ? "\n\nThis device is already paired. Approving replaces its keys; choose No if you didn't start this."
                    : "";
                var code = $"{result.Sas[..3]} {result.Sas[3..]}";
                var accepted = await PromptAsync("CCP pairing request",
                    $"Pair with {peerName} ({peerPlatform})?\n\nCode: {code}\n\nChoose Yes only if {peerName} shows exactly this code.{warning}");
                if (!accepted)
                {
                    _onEvent($"Rejected pairing from {peerName}");
                    await Refuse("rejected");
                    return;
                }

                _config.Trust(new SenderInfo(peerId, peerName, peerPlatform), result.PairSecret);
                await writer.WriteLineAsync(Envelope("pair.response", new JsonObject
                {
                    ["accepted"] = true,
                    ["confirm"] = CcpCrypto.B64(result.ResponderConfirm()),
                }).ToJsonString(), token);

                var address = (client.Client.RemoteEndPoint as IPEndPoint)?.Address ?? IPAddress.Loopback;
                UpsertPeer(new PeerView
                {
                    DeviceId = peerId,
                    DeviceName = peerName,
                    Platform = peerPlatform,
                    Address = address,
                    TcpPort = TcpPort,
                    Trusted = true,
                    LastSeen = DateTime.Now,
                });
                _onEvent($"Paired with {peerName}");
                _ = Task.Run(() => EstablishCloudSessionAsync(peerId, result.PairSecret));
            }
        }
        finally
        {
            Interlocked.Exchange(ref _pairingBusy, 0);
        }
    }

    /// <summary>Shows a Yes/No prompt; treats no answer within 60 s as No.</summary>
    private async Task<bool> PromptAsync(string title, string message)
    {
        var decision = Task.Run(() => _confirm(title, message));
        var finished = await Task.WhenAny(decision, Task.Delay(PromptTimeout, _stop.Token).ContinueWith(_ => { }));
        return finished == decision && decision.Result;
    }

    /// <summary>Registers the pairing with the cloud relay so Long Distance works later.</summary>
    private async Task EstablishCloudSessionAsync(string peerDeviceId, byte[] pairSecret)
    {
        for (var attempt = 0; attempt < 4; attempt++)
        {
            if (await Convex.StoreSessionAsync(peerDeviceId, pairSecret))
            {
                _onEvent($"Long Distance ready for {Short(peerDeviceId)}…");
                return;
            }
            try { await Task.Delay(5000 * (1 << attempt), _stop.Token); } catch (OperationCanceledException) { return; }
        }
        _onEvent($"Long Distance setup for {Short(peerDeviceId)}… deferred; will retry in the background");
    }

    /// <summary>Opens an authenticated, encrypted session with a paired LAN peer.</summary>
    private async Task<SecureConnection> OpenSecureSessionAsync(PeerView peer)
    {
        var secret = _config.PairSecret(peer.DeviceId)
            ?? throw new InvalidOperationException($"Not paired with {peer.DeviceName}; pair again");
        var client = await ConnectPeerAsync(peer);
        try
        {
            return await LanHandshake.ClientAsync(client, SenderNode, peer.DeviceId, secret, _stop.Token);
        }
        catch (SessionRefusedException ex) when (ex.Reason == "not_paired")
        {
            client.Dispose();
            throw new InvalidOperationException($"{peer.DeviceName} no longer trusts this device; pair again");
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    // ── File transfer ──────────────────────────────────────────────────────

    public Task SendFileAsync(PeerView peer, string path) => GuardAsync<object>($"Sending file to {peer.DeviceName}", async () =>
    {
        if (!peer.Trusted)
        {
            _onEvent("Pair with the device before sending files.");
            return null;
        }
        if (peer.IsCloudPeer)
        {
            await SendFileViaCloudAsync(peer, path);
            return null;
        }

        var file = new FileInfo(path);
        if (file.Length > TransferLimits.MaxLanFileBytes)
        {
            _onEvent($"{file.Name} is larger than {TransferLimits.MaxLanFileBytes / (1024 * 1024)} MB");
            return null;
        }
        var transferId = Guid.NewGuid().ToString();
        var fullHash = await Sha256FileAsync(path);

        using var conn = await OpenSecureSessionAsync(peer);
        var offer = await conn.RequestAsync(Envelope("file.offer", new JsonObject
        {
            ["transfer_id"] = transferId,
            ["filename"] = file.Name,
            ["size"] = file.Length,
            ["sha256"] = fullHash,
            ["chunk_size"] = ChunkSize,
            ["total_chunks"] = TransferLimits.ChunkCount(file.Length, ChunkSize),
        }), _stop.Token);
        var offerPayload = CcpWire.Payload(offer);
        if (!CcpWire.Bool(offerPayload["accepted"]))
        {
            _onEvent($"{peer.DeviceName} rejected {file.Name}: {CcpWire.Str(offerPayload["reason"], "rejected")}");
            return null;
        }

        var progress = new ProgressReporter(file.Length, percent => _onEvent($"Sending {file.Name}: {percent}%"));
        long sent = 0;
        var index = 0;
        await foreach (var chunk in ReadChunksAsync(path))
        {
            await conn.SendAsync(Envelope("file.chunk", new JsonObject
            {
                ["transfer_id"] = transferId,
                ["index"] = index++,
                ["sha256"] = Sha256Bytes(chunk),
                ["data_b64"] = Convert.ToBase64String(chunk),
            }), _stop.Token);
            sent += chunk.Length;
            progress.Update(sent);
        }

        var complete = await conn.RequestAsync(Envelope("file.complete", new JsonObject
        {
            ["transfer_id"] = transferId,
            ["sha256"] = fullHash,
        }), _stop.Token);
        _onEvent(CcpWire.Bool(CcpWire.Payload(complete)["ok"])
            ? $"Sent and verified {file.Name}"
            : $"{peer.DeviceName} could not verify {file.Name}");
        return null;
    });

    /// <summary>Reads whole ChunkSize pieces so the chunk count always matches the offer.</summary>
    private static async IAsyncEnumerable<byte[]> ReadChunksAsync(string path)
    {
        var buffer = new byte[ChunkSize];
        await using var input = File.OpenRead(path);
        while (true)
        {
            var filled = 0;
            while (filled < buffer.Length)
            {
                var read = await input.ReadAsync(buffer.AsMemory(filled));
                if (read == 0) break;
                filled += read;
            }
            if (filled == 0) yield break;
            yield return buffer[..filled];
            if (filled < buffer.Length) yield break;
        }
    }

    private async Task SendFileViaCloudAsync(PeerView peer, string path)
    {
        var file = new FileInfo(path);
        if (file.Length > TransferLimits.MaxCloudFileBytes)
        {
            _onEvent($"{file.Name} is too large for Long Distance (limit {TransferLimits.MaxCloudFileBytes / (1024 * 1024)} MB)");
            return;
        }
        var transferId = Guid.NewGuid().ToString();
        var fullHash = await Sha256FileAsync(path);

        _onEvent($"☁ Offering {file.Name} to {peer.DeviceName} via cloud relay…");
        var offer = await Convex.SendCloudRequestAsync(peer.DeviceId, "file.offer", new JsonObject
        {
            ["transfer_id"] = transferId,
            ["filename"] = file.Name,
            ["size"] = file.Length,
            ["sha256"] = fullHash,
            ["chunk_size"] = ChunkSize,
            ["total_chunks"] = TransferLimits.ChunkCount(file.Length, ChunkSize),
        }, timeoutMs: 75_000); // allows for the receiver's accept prompt

        if (offer is null || !CcpWire.Bool(offer["accepted"]))
        {
            _onEvent($"{peer.DeviceName} rejected {file.Name}: {(offer is null ? "no response" : CcpWire.Str(offer["reason"], "rejected"))}");
            return;
        }

        var progress = new ProgressReporter(file.Length, percent => _onEvent($"☁ Sending {file.Name}: {percent}%"));
        long sent = 0;
        var index = 0;
        await foreach (var chunk in ReadChunksAsync(path))
        {
            var ok = await Convex.PushMessageAsync(peer.DeviceId, "file.chunk", new JsonObject
            {
                ["transfer_id"] = transferId,
                ["index"] = index,
                ["sha256"] = Sha256Bytes(chunk),
                ["data_b64"] = Convert.ToBase64String(chunk),
            }, ttlMs: 10 * 60 * 1000);
            if (!ok)
            {
                _onEvent($"☁ Cloud send failed at chunk {index} of {file.Name}");
                return;
            }
            index++;
            sent += chunk.Length;
            progress.Update(sent);
        }

        var complete = await Convex.SendCloudRequestAsync(peer.DeviceId, "file.complete", new JsonObject
        {
            ["transfer_id"] = transferId,
            ["sha256"] = fullHash,
        }, timeoutMs: 60_000);
        _onEvent(CcpWire.Bool(complete?["ok"])
            ? $"☁ Sent and verified {file.Name}"
            : $"☁ Receiver could not verify {file.Name}");
    }

    /// <summary>Verifies a completed transfer and moves it into the inbox.</summary>
    private bool FinishIncoming(IncomingTransfer transfer)
    {
        try
        {
            if (!transfer.Finish())
            {
                _onEvent($"Checksum failed for {transfer.DisplayName}; discarded");
                transfer.Discard();
                return false;
            }
            var saved = transfer.MoveTo(InboxDirectory);
            transfer.Dispose();
            _onEvent($"Received {transfer.DisplayName} → {saved}");
            return true;
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            _onEvent($"Saving {transfer.DisplayName} failed: {ex.Message}");
            transfer.Discard();
            return false;
        }
    }

    private static bool HasSpaceFor(long size)
    {
        try
        {
            Directory.CreateDirectory(InboxDirectory);
            var drive = new DriveInfo(Path.GetPathRoot(Path.GetFullPath(InboxDirectory))!);
            return drive.AvailableFreeSpace > size + 64L * 1024 * 1024;
        }
        catch (Exception ex) when (ex is IOException or ArgumentException or UnauthorizedAccessException)
        {
            return false;
        }
    }

    /// <summary>Removes partial files left behind by a crash.</summary>
    private static void CleanupInbox()
    {
        try
        {
            if (!Directory.Exists(InboxDirectory)) return;
            var cutoff = DateTime.UtcNow.AddHours(-1);
            foreach (var part in Directory.EnumerateFiles(InboxDirectory, "*.part"))
            {
                if (File.GetLastWriteTimeUtc(part) < cutoff) File.Delete(part);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
        }
    }

    // ── Remote panel ───────────────────────────────────────────────────────

    public async Task<RemoteDevicePanel> GetPeerPanelAsync(PeerView peer)
    {
        if (!peer.Trusted) return RemoteDevicePanel.Empty(peer.DeviceName, peer.Platform);

        var responses = await GuardAsync<JsonObject?[]>($"Loading panel for {peer.DeviceName}", async () =>
        {
            if (peer.IsCloudPeer)
            {
                _onEvent($"☁ Loading panel for {peer.DeviceName} via cloud relay…");
                // Requests go out together so the panel costs one relay round trip, not four.
                return await Task.WhenAll(PanelRequests.Select(type =>
                    Convex.SendCloudRequestAsync(peer.DeviceId, type, timeoutMs: 25_000)));
            }

            using var conn = await OpenSecureSessionAsync(peer);
            var results = new JsonObject?[PanelRequests.Length];
            for (var i = 0; i < PanelRequests.Length; i++)
            {
                results[i] = CcpWire.Payload(await conn.RequestAsync(Envelope(PanelRequests[i], new JsonObject()), _stop.Token));
            }
            return results;
        });

        return responses is null
            ? RemoteDevicePanel.Empty(peer.DeviceName, peer.Platform)
            : BuildPanel(peer, responses[0], responses[1], responses[2], responses[3]);
    }

    private static RemoteDevicePanel BuildPanel(PeerView peer, JsonObject? snapshot, JsonObject? gallery, JsonObject? files, JsonObject? notifications) => new(
        Title: NonEmpty(CcpWire.Str(snapshot?["device_title"]), peer.DeviceName),
        Subtitle: NonEmpty(CcpWire.Str(snapshot?["device_subtitle"]), peer.Platform),
        Battery: CcpWire.Str(snapshot?["battery"], "Unknown"),
        Storage: CcpWire.Str(snapshot?["storage"], "Unknown"),
        NotificationAccess: CcpWire.Str(snapshot?["notification_access"], "Unknown"),
        GalleryAccess: CcpWire.Str(snapshot?["gallery_access"], "Unknown"),
        Settings: ParseJsonNodeFacts(snapshot?["settings"]),
        Gallery: ParseJsonNodeItems(gallery?["items"], "gallery"),
        Files: ParseJsonNodeItems(files?["items"], "file"),
        Notifications: ParseJsonNodeNotifications(notifications));

    private static string NonEmpty(string value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value;

    /// <summary>
    /// Toggle Long Distance (cloud) mode. When enabled, paired peers known to
    /// Convex appear in the peer list as cloud peers.
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
            foreach (var entry in _peers.ToArray())
            {
                if (entry.Value.IsCloudPeer) _peers.TryRemove(entry.Key, out _);
            }
            PublishPeers();
        }
    }

    private async Task CloudPeerLoopAsync(CancellationToken token)
    {
        await Task.Delay(TimeSpan.FromSeconds(3), token);
        while (!token.IsCancellationRequested)
        {
            await SyncCloudSessionsAsync();
            if (_cloudModeEnabled) await LoadCloudPeersAsync(quiet: true);
            PruneStaleCloudTransfers();
            await Task.Delay(TimeSpan.FromSeconds(15), token);
        }
    }

    /// <summary>Re-publishes local pairings the relay doesn't know about (e.g. pairing happened offline).</summary>
    private async Task SyncCloudSessionsAsync()
    {
        var cloudIds = await Convex.ListPairedPeerIdsAsync();
        if (cloudIds is null) return;
        var known = cloudIds.ToHashSet();
        foreach (var peerId in _config.TrustedPeerIds())
        {
            if (known.Contains(peerId)) continue;
            if (_lastSessionSync.TryGetValue(peerId, out var last) && DateTime.UtcNow - last < TimeSpan.FromMinutes(5)) continue;
            _lastSessionSync[peerId] = DateTime.UtcNow;
            if (_config.PairSecret(peerId) is { } secret) await Convex.StoreSessionAsync(peerId, secret);
        }
    }

    /// <summary>Adds paired peers from Convex sessions to the peer list as cloud peers.</summary>
    public async Task LoadCloudPeersAsync(bool quiet = false)
    {
        var peerIds = await Convex.ListPairedPeerIdsAsync();
        if (peerIds is null)
        {
            if (!quiet) _onEvent("☁ Could not reach the cloud relay");
            return;
        }

        var loaded = 0;
        foreach (var deviceId in peerIds)
        {
            if (!_config.IsTrusted(deviceId)) continue; // paired before v1 or only from the other side: needs re-pairing
            if (_peers.TryGetValue(deviceId, out var existing) && !existing.IsCloudPeer) continue;

            var info = await Convex.GetPeerDeviceInfoAsync(deviceId);
            var local = _config.PeerInfo(deviceId);
            UpsertPeer(new PeerView
            {
                DeviceId = deviceId,
                DeviceName = info?.Name ?? local?.DeviceName ?? $"Cloud device {Short(deviceId)}…",
                Platform = info?.Platform ?? local?.Platform ?? "unknown",
                Address = IPAddress.Loopback, // not used for cloud peers
                TcpPort = 0,
                Trusted = true,
                LastSeen = DateTime.Now,
                AvailableTransports = ["cloud"],
                Routes = [],
                IsCloudPeer = true,
                CloudOnline = await Convex.GetPeerOnlineAsync(deviceId),
            });
            loaded++;
        }

        // Drop cloud peers whose sessions were revoked.
        var current = peerIds.ToHashSet();
        foreach (var entry in _peers.ToArray())
        {
            if (entry.Value.IsCloudPeer && (!current.Contains(entry.Key) || !_config.IsTrusted(entry.Key)))
            {
                _peers.TryRemove(entry.Key, out _);
            }
        }
        PublishPeers();

        if (!quiet) _onEvent(loaded > 0 ? $"☁ Found {loaded} cloud peer(s)" : "☁ No paired peers found in cloud");
    }

    private void PruneStaleCloudTransfers()
    {
        var cutoff = DateTime.UtcNow - TransferLimits.IdleTimeout;
        foreach (var entry in _cloudIncomingTransfers.ToArray())
        {
            if (entry.Value.LastActivity < cutoff && _cloudIncomingTransfers.TryRemove(entry.Key, out var stale))
            {
                stale.Discard();
                _onEvent($"[Cloud] Abandoned stalled transfer of {stale.DisplayName}");
            }
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
        var payload = new JsonObject
        {
            ["action"] = action,
            ["args"] = JsonSerializer.SerializeToNode(args ?? new Dictionary<string, object?>()),
        };

        var response = await GuardAsync($"Remote action {action}", async () =>
        {
            if (peer.IsCloudPeer)
            {
                _onEvent($"☁ Sending remote action {action} to {peer.DeviceName} via cloud…");
                return await Convex.SendCloudRequestAsync(peer.DeviceId, "remote.action.request", payload, timeoutMs: 25_000);
            }
            using var conn = await OpenSecureSessionAsync(peer);
            return CcpWire.Payload(await conn.RequestAsync(Envelope("remote.action.request", payload), _stop.Token));
        });

        if (response is null)
        {
            _onEvent($"No response for remote action {action}");
            return false;
        }
        var ok = CcpWire.Bool(response["ok"]);
        var message = NonEmpty(CcpWire.Str(response["message"]), action);
        _onEvent(ok ? $"Remote action completed: {message}" : $"Remote action failed: {message}");
        return ok;
    }

    // ── Discovery ──────────────────────────────────────────────────────────

    private async Task BroadcastLoopAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                await SendDiscoveryAsync();
            }
            catch (Exception ex) when (ex is SocketException or IOException)
            {
                _onEvent($"Discovery broadcast failed: {ex.Message}");
            }
            PruneStalePeers();
            await Task.Delay(TimeSpan.FromSeconds(3), token);
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
            ["capabilities"] = new[] { "pairing", "file.transfer", "device.snapshot", "gallery.list", "files.list", "native.windows" },
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
            catch (SocketException)
            {
                // Some adapters (VPNs, disconnected NICs) reject broadcasts; others still work.
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
        while (!token.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await udp.ReceiveAsync(token);
            }
            catch (SocketException)
            {
                // e.g. ICMP port unreachable surfaced on Windows; keep listening.
                await Task.Delay(500, token);
                continue;
            }

            try
            {
                using var json = JsonDocument.Parse(result.Buffer);
                var doc = json.RootElement;
                if (!doc.TryGetProperty("protocol", out var protocol) || protocol.GetString() != Protocol) continue;
                var deviceId = doc.TryGetProperty("device_id", out var id) ? id.GetString() ?? "" : "";
                if (deviceId == _config.DeviceId || !CcpIdentity.IsValidDeviceId(deviceId)) continue;
                var tcpPort = doc.TryGetProperty("tcp_port", out var port) && port.TryGetInt32(out var p) && p is > 0 and < 65536 ? p : TcpPort;

                UpsertPeer(new PeerView
                {
                    DeviceId = deviceId,
                    DeviceName = Truncate(doc.TryGetProperty("device_name", out var name) ? name.GetString() : null, 64),
                    Platform = Truncate(doc.TryGetProperty("platform", out var platform) ? platform.GetString() : null, 16),
                    Address = result.RemoteEndPoint.Address,
                    TcpPort = tcpPort,
                    Trusted = _config.IsTrusted(deviceId),
                    LastSeen = DateTime.Now,
                    AvailableTransports = ParseTransportModes(doc),
                    Routes = ParseRoutes(doc, result.RemoteEndPoint.Address)
                });
            }
            catch (Exception ex) when (ex is JsonException or InvalidOperationException or KeyNotFoundException or FormatException)
            {
                // Malformed packets are expected on a shared LAN; drop them quietly.
            }
        }
    }

    // ── LAN server ─────────────────────────────────────────────────────────

    private async Task ListenTcpAsync(CancellationToken token)
    {
        var listener = new TcpListener(IPAddress.Any, TcpPort);
        listener.Server.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        listener.Start();
        _onEvent($"TCP listener active on {TcpPort}");
        try
        {
            while (!token.IsCancellationRequested)
            {
                var client = await listener.AcceptTcpClientAsync(token);
                if (!_connectionSlots.Wait(0))
                {
                    // Too many concurrent peers: refuse rather than queue unbounded work.
                    client.Dispose();
                    continue;
                }
                _ = Task.Run(async () =>
                {
                    try
                    {
                        await HandleClientAsync(client, token);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException || !token.IsCancellationRequested)
                    {
                        _onEvent($"Connection from {client.Client.RemoteEndPoint} closed: {ex.Message}");
                    }
                    finally
                    {
                        client.Dispose();
                        _connectionSlots.Release();
                    }
                }, token);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    /// <summary>
    /// Every inbound connection starts with a plain-text frame: either a
    /// pairing attempt or a session.hello that upgrades to an encrypted,
    /// authenticated session. Nothing else is served in clear.
    /// </summary>
    private async Task HandleClientAsync(TcpClient client, CancellationToken token)
    {
        client.NoDelay = true;
        var stream = client.GetStream();
        var reader = new BoundedLineReader(stream);
        var writer = new LineWriter(stream);
        var line = await CcpWire.ReadLineWithTimeoutAsync(reader, token);
        if (line is null) return;
        var first = CcpWire.ParseObject(line);

        switch (CcpWire.Type(first))
        {
            case "pair.request":
                await HandlePairRequestAsync(client, reader, writer, first, token);
                break;
            case "session.hello":
                var conn = await LanHandshake.ServerAsync(client, reader, writer, SenderNode, first, _config.PairSecret, token);
                if (conn is not null) await ServeSecureSessionAsync(conn, token);
                break;
            default:
                await writer.WriteLineAsync(Envelope("session.error", new JsonObject { ["reason"] = "secure_session_required" }).ToJsonString(), token);
                break;
        }
    }

    /// <summary>Serves requests on an authenticated session. The peer id comes from the handshake, never from message bodies.</summary>
    private async Task ServeSecureSessionAsync(SecureConnection conn, CancellationToken token)
    {
        IncomingTransfer? transfer = null;
        try
        {
            while (!token.IsCancellationRequested)
            {
                JsonObject? message;
                try
                {
                    message = await conn.ReceiveAsync(token);
                }
                catch (CryptographicException)
                {
                    _onEvent($"Rejected an unauthenticated frame claiming to be {Short(conn.PeerId)}…");
                    await conn.SendPlainErrorAsync(SenderNode, "bad_frame");
                    return;
                }
                if (message is null || !_config.IsTrusted(conn.PeerId)) return;

                var payload = CcpWire.Payload(message);
                var type = CcpWire.Type(message);
                switch (type)
                {
                    case "file.offer":
                    {
                        transfer?.Discard();
                        transfer = null;
                        var name = TransferLimits.SafeFilename(CcpWire.Str(payload["filename"]));
                        var reason = IncomingTransfer.ValidateOffer(payload)
                            ?? (HasSpaceFor(CcpWire.Long(payload["size"])) ? null : "insufficient_storage");
                        if (reason is null && !await PromptAsync("Incoming file",
                                $"Accept {name} ({FormatBytes(CcpWire.Long(payload["size"]))}) from {PeerName(conn.PeerId)}?"))
                        {
                            reason = "rejected";
                        }
                        if (reason is null)
                        {
                            transfer = IncomingTransfer.Create(InboxDirectory, payload);
                            _onEvent($"Receiving {transfer.DisplayName} from {PeerName(conn.PeerId)}");
                        }
                        await conn.SendAsync(Envelope("file.offer.response", new JsonObject
                        {
                            ["transfer_id"] = CcpWire.Str(payload["transfer_id"]),
                            ["accepted"] = reason is null,
                            ["resume_from"] = 0,
                            ["reason"] = reason,
                        }), token);
                        break;
                    }

                    case "file.chunk":
                    {
                        var active = transfer ?? throw new InvalidDataException("Chunk without an accepted offer");
                        if (CcpWire.Str(payload["transfer_id"]) != active.TransferId) throw new InvalidDataException("Chunk for an unknown transfer");
                        active.Append(
                            (int)CcpWire.Long(payload["index"]),
                            Convert.FromBase64String(CcpWire.Str(payload["data_b64"])),
                            CcpWire.Str(payload["sha256"]));
                        break;
                    }

                    case "file.complete":
                    {
                        var active = transfer;
                        transfer = null;
                        var ok = active is not null &&
                                 CcpWire.Str(payload["transfer_id"]) == active.TransferId &&
                                 FinishIncoming(active);
                        if (!ok) active?.Discard();
                        await conn.SendAsync(Envelope("file.complete.response", new JsonObject
                        {
                            ["transfer_id"] = CcpWire.Str(payload["transfer_id"]),
                            ["ok"] = ok,
                        }), token);
                        break;
                    }

                    default:
                        await conn.SendAsync(Envelope(ResponseTypeFor(type), HandleCapabilityRequest(type, payload)), token);
                        break;
                }
            }
        }
        finally
        {
            transfer?.Discard();
        }
    }

    /// <summary>Requests answered identically over the LAN and the cloud relay.</summary>
    private JsonObject HandleCapabilityRequest(string type, JsonObject payload) => type switch
    {
        "device.snapshot.request" => ToJsonObject(BuildLocalSnapshotPayload()),
        "gallery.list.request" => ToJsonObject(BuildDirectoryPayload(
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures), "gallery")),
        "files.list.request" => ToJsonObject(BuildDirectoryPayload(
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), "Downloads"), "file")),
        "notifications.list.request" => new JsonObject { ["permission_granted"] = false, ["items"] = new JsonArray() },
        "remote.action.request" => new JsonObject
        {
            ["ok"] = false,
            ["message"] = "Remote actions are not supported on Windows yet.",
            ["action"] = CcpWire.Str(payload["action"]),
        },
        _ => new JsonObject { ["ok"] = false, ["error"] = "unsupported_request" },
    };

    private static JsonObject ToJsonObject(Dictionary<string, object?> value) =>
        JsonSerializer.SerializeToNode(value) as JsonObject ?? new JsonObject();

    private string PeerName(string deviceId) =>
        _config.PeerInfo(deviceId)?.DeviceName ?? Short(deviceId);

    private async Task<TcpClient> ConnectPeerAsync(PeerView peer)
    {
        Exception? lastError = null;
        foreach (var route in RankRoutes(peer))
        {
            var client = new TcpClient { NoDelay = true };
            try
            {
                using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(_stop.Token);
                connectCts.CancelAfter(ConnectTimeoutMs);
                await client.ConnectAsync(route.Host, route.Port, connectCts.Token);
                _onEvent($"Connected to {peer.DeviceName} via {route.Transport}");
                return client;
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException or IOException)
            {
                client.Dispose();
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

    private JsonObject Envelope(string type, JsonObject payload) => CcpWire.Envelope(type, SenderNode, payload);

    private static string Truncate(string? value, int max) =>
        string.IsNullOrWhiteSpace(value) ? "Unknown" : value.Length <= max ? value : value[..max];

    private static string Short(string value, int length = 8) => value[..Math.Min(length, value.Length)];

    private static string Sha256Bytes(byte[] bytes) => CcpCrypto.Hex(CcpCrypto.Sha256(bytes));

    private static async Task<string> Sha256FileAsync(string path)
    {
        await using var stream = File.OpenRead(path);
        return Convert.ToHexString(await SHA256.HashDataAsync(stream)).ToLowerInvariant();
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

    /// <summary>Handles a cloud relay message (already decrypted and authenticated by ConvexService).</summary>
    private void HandleCloudMessage(string senderId, string msgType, JsonObject payload)
    {
        var senderShort = Short(senderId);
        var requestId = CcpWire.Str(payload["request_id"]);

        if (RequiresTrustedPeer(msgType) && !_config.IsTrusted(senderId))
        {
            _onEvent($"[Cloud] Rejected {msgType} from unpaired device {senderShort}");
            _ = Task.Run(() => SendCloudRejectionAsync(senderId, msgType, requestId));
            return;
        }

        JsonObject WithRequestId(JsonObject response)
        {
            if (requestId.Length > 0) response["request_id"] = requestId;
            return response;
        }

        switch (msgType)
        {
            case "device.snapshot.request":
            case "gallery.list.request":
            case "files.list.request":
            case "notifications.list.request":
            case "remote.action.request":
                _onEvent($"[Cloud] {msgType} from {senderShort}…");
                _ = Task.Run(() => Convex.PushMessageAsync(senderId, ResponseTypeFor(msgType),
                    WithRequestId(HandleCapabilityRequest(msgType, payload))));
                break;

            case "file.offer":
                _ = Task.Run(async () =>
                {
                    var transferId = CcpWire.Str(payload["transfer_id"]);
                    var key = $"{senderId}|{transferId}";
                    var name = TransferLimits.SafeFilename(CcpWire.Str(payload["filename"]));
                    var reason = IncomingTransfer.ValidateOffer(payload, TransferLimits.MaxCloudFileBytes)
                        ?? (_cloudIncomingTransfers.Count >= MaxCloudTransfers ? "too_many_transfers" : null)
                        ?? (HasSpaceFor(CcpWire.Long(payload["size"])) ? null : "insufficient_storage");
                    if (reason is null && !await PromptAsync("Incoming cloud file",
                            $"Accept {name} ({FormatBytes(CcpWire.Long(payload["size"]))}) from {PeerName(senderId)} via the cloud relay?"))
                    {
                        reason = "rejected";
                    }
                    if (reason is null)
                    {
                        if (_cloudIncomingTransfers.TryRemove(key, out var previous)) previous.Discard();
                        _cloudIncomingTransfers[key] = IncomingTransfer.Create(InboxDirectory, payload);
                        _onEvent($"[Cloud] Receiving {name} from {PeerName(senderId)}");
                    }
                    await Convex.PushMessageAsync(senderId, "file.offer.response", WithRequestId(new JsonObject
                    {
                        ["transfer_id"] = transferId,
                        ["accepted"] = reason is null,
                        ["resume_from"] = 0,
                        ["reason"] = reason,
                    }));
                });
                break;

            case "file.chunk":
            {
                // Chunks arrive in relay order on the poll loop, so they're applied sequentially here.
                var key = $"{senderId}|{CcpWire.Str(payload["transfer_id"])}";
                if (!_cloudIncomingTransfers.TryGetValue(key, out var transfer)) break;
                try
                {
                    transfer.Append(
                        (int)CcpWire.Long(payload["index"]),
                        Convert.FromBase64String(CcpWire.Str(payload["data_b64"])),
                        CcpWire.Str(payload["sha256"]));
                }
                catch (Exception ex) when (ex is InvalidDataException or FormatException or IOException)
                {
                    _cloudIncomingTransfers.TryRemove(key, out _);
                    transfer.Discard();
                    _onEvent($"[Cloud] Transfer of {transfer.DisplayName} aborted: {ex.Message}");
                }
                break;
            }

            case "file.complete":
            {
                var transferId = CcpWire.Str(payload["transfer_id"]);
                var ok = _cloudIncomingTransfers.TryRemove($"{senderId}|{transferId}", out var transfer) && FinishIncoming(transfer);
                _ = Task.Run(() => Convex.PushMessageAsync(senderId, "file.complete.response", WithRequestId(new JsonObject
                {
                    ["transfer_id"] = transferId,
                    ["ok"] = ok,
                })));
                break;
            }

            case "clipboard.sync":
                _onEvent($"[Cloud] Clipboard sync from {senderShort}…");
                break;

            case "notification.push":
                _onEvent($"[Cloud] Notification from {senderShort}…: {CcpWire.Str(payload["title"], "Notification")}");
                break;

            case "heartbeat":
                break;

            default:
                _onEvent($"[Cloud] Ignored {msgType} from {senderShort}…");
                break;
        }
    }

    private static bool RequiresTrustedPeer(string msgType) => msgType is
        "device.snapshot.request" or
        "gallery.list.request" or
        "files.list.request" or
        "notifications.list.request" or
        "remote.action.request" or
        "file.offer" or
        "file.chunk" or
        "file.complete" or
        "clipboard.sync" or
        "notification.push";

    private static string ResponseTypeFor(string msgType) => msgType switch
    {
        "device.snapshot.request" => "device.snapshot.response",
        "gallery.list.request" => "gallery.list.response",
        "files.list.request" => "files.list.response",
        "notifications.list.request" => "notifications.list.response",
        "remote.action.request" => "remote.action.response",
        "file.offer" => "file.offer.response",
        "file.complete" => "file.complete.response",
        _ => $"{msgType}.response",
    };

    private async Task SendCloudRejectionAsync(string peerDeviceId, string msgType, string requestId)
    {
        var response = new JsonObject
        {
            ["ok"] = false,
            ["accepted"] = false,
            ["message"] = "peer is not paired",
            ["reason"] = "peer is not paired",
        };
        if (requestId.Length > 0) response["request_id"] = requestId;
        await Convex.PushMessageAsync(peerDeviceId, ResponseTypeFor(msgType), response);
    }

    // ── Response parsers (tolerant of missing or mistyped fields) ──────────

    private static IReadOnlyList<RemoteFactView> ParseJsonNodeFacts(JsonNode? node) =>
        (node as JsonArray)?.OfType<JsonObject>()
            .Select(obj => new RemoteFactView(CcpWire.Str(obj["label"], "Setting"), CcpWire.Str(obj["value"], "Unknown")))
            .ToList() ?? [];

    private static IReadOnlyList<RemoteContentItem> ParseJsonNodeItems(JsonNode? node, string fallbackType) =>
        (node as JsonArray)?.OfType<JsonObject>()
            .Select(obj => new RemoteContentItem(
                CcpWire.Str(obj["name"], "Untitled"),
                NonEmpty(CcpWire.Str(obj["location"]), NonEmpty(CcpWire.Str(obj["mime_type"]), NonEmpty(CcpWire.Str(obj["size"]), fallbackType))),
                CcpWire.Str(obj["type"], fallbackType)))
            .ToList() ?? [];

    private static IReadOnlyList<RemoteContentItem> ParseJsonNodeNotifications(JsonObject? payload) =>
        (payload?["items"] as JsonArray)?.OfType<JsonObject>()
            .Select(obj => new RemoteContentItem(CcpWire.Str(obj["title"], "Notification"), CcpWire.Str(obj["text"]), "notification"))
            .ToList() ?? [];

    public void Dispose()
    {
        _stop.Cancel();
        foreach (var transfer in _cloudIncomingTransfers.Values) transfer.Discard();
        _cloudIncomingTransfers.Clear();
        try { Convex.StopAsync().Wait(TimeSpan.FromSeconds(3)); } catch (AggregateException) { }
        Convex.Dispose();
        _stop.Dispose();
        _connectionSlots.Dispose();
    }
}
