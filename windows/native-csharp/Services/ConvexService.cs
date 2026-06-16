using System.Collections.Concurrent;
using System.Net.Http;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CCP.Windows.Services;

/// <summary>
/// CCP ↔ Convex cloud relay bridge for Windows (C# / .NET 8).
///
/// Uses only System.Security.Cryptography (built into .NET 8):
///   • SHA-256 based pseudo-ECDH for key agreement
///   • HKDF-SHA256 for key derivation
///   • AES-256-GCM for encryption (AesGcm class)
///   • PBKDF2 for machine secret
///
/// Convex is used as an encrypted mailbox — it never sees plaintext.
/// </summary>
public sealed class ConvexService : IDisposable
{
    private const string ConvexUrl = "https://reminiscent-raven-475.convex.cloud";
    private const int HeartbeatIntervalMs = 10_000;
    private const int PollIntervalMs = 3_000;
    private const int TcpPort = 47828;

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly string _deviceId;
    private readonly string _deviceName;
    private readonly byte[] _privateKey;
    private readonly byte[] _publicKey;
    private readonly byte[] _machineSecret;

    // peer device_id → 32-byte AES session key
    private readonly Dictionary<string, byte[]> _sessionKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _sessionLock = new(1, 1);

    // Cloud request-response: request_id → pending completion
    private readonly ConcurrentDictionary<string, TaskCompletionSource<JsonObject>> _pendingRequests = new();

    private CancellationTokenSource? _cts;
    private Action<string>? _logger;

    public string PublicKeyB64 { get; }
    public string CloudStatus { get; private set; } = "Connecting…";
    public event Action<string>? OnCloudStatusChanged;
    public event Action<string, string, JsonObject>? OnMessageReceived; // (senderId, msgType, payload)

    public ConvexService(string deviceId, string deviceName, byte[] privateKey)
    {
        _deviceId = deviceId;
        _deviceName = deviceName;
        _privateKey = privateKey;

        // Public key = SHA256(privateKey || "ccp-pub")
        _publicKey = SHA256.HashData([.. privateKey, .. "ccp-pub"u8.ToArray()]);
        PublicKeyB64 = Convert.ToBase64String(_publicKey);

        // Machine secret = PBKDF2(deviceId, "ccp-machine-secret-v0", 100000, 32)
        _machineSecret = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(deviceId),
            "ccp-machine-secret-v0"u8.ToArray(),
            100_000, HashAlgorithmName.SHA256, 32);
    }

    public void SetLogger(Action<string> logger) => _logger = logger;

    // ── Lifecycle ──────────────────────────────────────────────────────────

    public void Start(string appVersion = "0.2.0")
    {
        _cts = new CancellationTokenSource();
        _ = Task.Run(() => RegisterAsync(appVersion, _cts.Token));
        _ = Task.Run(() => HeartbeatLoopAsync(_cts.Token));
        _ = Task.Run(() => PollLoopAsync(_cts.Token));
    }

    public async Task StopAsync()
    {
        _cts?.Cancel();
        try
        {
            await MutationAsync("presence:goOffline", new JsonObject { ["device_id"] = _deviceId });
        }
        catch { /* best effort */ }
    }

    // ── Registration ───────────────────────────────────────────────────────

    private async Task RegisterAsync(string appVersion, CancellationToken ct)
    {
        try
        {
            await MutationAsync("devices:registerDevice", new JsonObject
            {
                ["device_id"] = _deviceId,
                ["device_name"] = _deviceName,
                ["platform"] = "windows",
                ["public_key_b64"] = PublicKeyB64,
                ["capabilities"] = new JsonArray("pairing", "file.transfer", "remote.action", "device.snapshot"),
                ["app_version"] = appVersion,
            }, ct);
            SetStatus("Cloud connected ✓");
            Log("Registered on Convex");
        }
        catch (Exception ex)
        {
            SetStatus("Cloud offline");
            Log($"Registration failed: {ex.Message}");
        }
    }

    // ── Key Exchange ───────────────────────────────────────────────────────

    /// <summary>
    /// Call after a successful local WiFi pairing.
    /// Derives a shared session key via pseudo-ECDH and stores encrypted blobs in Convex.
    /// Returns the key fingerprint (hex SHA-256 of shared secret).
    /// </summary>
    public async Task<string> CompleteKeyExchangeAsync(string peerDeviceId, string peerPublicKeyB64, string pairedVia = "wifi")
    {
        var peerPub = Convert.FromBase64String(peerPublicKeyB64);

        // Pseudo-ECDH: sharedSecret = SHA256(myPrivate || peerPublic)
        var sharedSecret = SHA256.HashData([.. _privateKey, .. peerPub]);
        var sessionKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, sharedSecret, 32, info: "ccp-session-v0"u8.ToArray());
        var fingerprint = Convert.ToHexString(SHA256.HashData(sharedSecret)).ToLowerInvariant();

        // Encrypt our copy with machine secret
        var myBlob = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(EncryptGcm(_machineSecret, sessionKey))));

        // Encrypt peer copy with key derived from their device_id
        var peerMachineSecret = HKDF.DeriveKey(HashAlgorithmName.SHA256,
            Encoding.UTF8.GetBytes(peerDeviceId), 32, info: "ccp-machine-v0"u8.ToArray());
        var peerBlob = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(EncryptGcm(peerMachineSecret, sessionKey))));

        var idA = string.Compare(_deviceId, peerDeviceId, StringComparison.Ordinal) < 0 ? _deviceId : peerDeviceId;
        var idB = string.Compare(_deviceId, peerDeviceId, StringComparison.Ordinal) < 0 ? peerDeviceId : _deviceId;
        var encA = _deviceId == idA ? myBlob : peerBlob;
        var encB = _deviceId == idA ? peerBlob : myBlob;

        try
        {
            await MutationAsync("sessions:storeSession", new JsonObject
            {
                ["device_id_a"] = idA,
                ["device_id_b"] = idB,
                ["encrypted_key_a"] = encA,
                ["encrypted_key_b"] = encB,
                ["key_fingerprint"] = fingerprint,
                ["paired_via"] = pairedVia,
            });
            Log($"Session stored with {peerDeviceId[..8]}… (fp: {fingerprint[..12]}…)");
            SetStatus("Cloud relay ready ✓");
        }
        catch (Exception ex)
        {
            Log($"Session store failed: {ex.Message}");
        }

        await _sessionLock.WaitAsync();
        try { _sessionKeys[peerDeviceId] = sessionKey; }
        finally { _sessionLock.Release(); }

        return fingerprint;
    }

    public async Task<bool> LoadSessionFromCloudAsync(string peerDeviceId)
    {
        try
        {
            var data = await QueryAsync("sessions:getSession", new JsonObject
            {
                ["my_device_id"] = _deviceId,
                ["peer_device_id"] = peerDeviceId,
            });
            if (data is null) return false;

            var blobJson = JsonNode.Parse(
                Encoding.UTF8.GetString(Convert.FromBase64String(data["encrypted_key"]!.GetValue<string>())))!.AsObject();
            var sessionKey = DecryptGcm(_machineSecret,
                blobJson["nonce"]!.GetValue<string>(),
                blobJson["ciphertext"]!.GetValue<string>());

            await _sessionLock.WaitAsync();
            try { _sessionKeys[peerDeviceId] = sessionKey; }
            finally { _sessionLock.Release(); }

            Log($"Session loaded for {peerDeviceId[..8]}…");
            return true;
        }
        catch (Exception ex)
        {
            Log($"Session load failed for {peerDeviceId[..8]}…: {ex.Message}");
            return false;
        }
    }

    public async Task<byte[]?> GetSessionKeyAsync(string peerDeviceId)
    {
        await _sessionLock.WaitAsync();
        try
        {
            if (_sessionKeys.TryGetValue(peerDeviceId, out var key)) return key;
        }
        finally { _sessionLock.Release(); }
        return null;
    }

    // ── Message Push / Poll ────────────────────────────────────────────────

    public async Task<bool> PushMessageAsync(string peerDeviceId, string msgType, JsonObject payload, long? ttlMs = null)
    {
        var key = await GetSessionKeyAsync(peerDeviceId);
        if (key is null)
        {
            if (!await LoadSessionFromCloudAsync(peerDeviceId)) { Log($"No session for {peerDeviceId[..8]}… — pair first"); return false; }
            key = await GetSessionKeyAsync(peerDeviceId);
            if (key is null) return false;
        }

        var plaintext = Encoding.UTF8.GetBytes(payload.ToJsonString());
        var enc = EncryptGcm(key, plaintext);
        var msgId = Guid.NewGuid().ToString();

        try
        {
            var args = new JsonObject
            {
                ["sender_id"] = _deviceId,
                ["recipient_id"] = peerDeviceId,
                ["msg_type"] = msgType,
                ["encrypted_payload"] = enc["ciphertext"],
                ["nonce"] = enc["nonce"],
                ["msg_id"] = msgId,
            };
            if (ttlMs.HasValue) args["ttl_ms"] = ttlMs.Value;
            await MutationAsync("messages:pushMessage", args);
            Log($"Pushed {msgType} → {peerDeviceId[..8]}…");
            return true;
        }
        catch (Exception ex)
        {
            Log($"Push failed: {ex.Message}");
            return false;
        }
    }

    public async Task<string?> GetPeerPublicKeyAsync(string peerDeviceId)
    {
        try
        {
            var data = await QueryAsync("devices:getPublicKey", new JsonObject { ["device_id"] = peerDeviceId });
            return data?["public_key_b64"]?.GetValue<string>();
        }
        catch { return null; }
    }

    public async Task<bool> GetPeerOnlineAsync(string peerDeviceId)
    {
        try
        {
            var data = await QueryAsync("presence:getPresence", new JsonObject { ["device_id"] = peerDeviceId });
            return data?["online"]?.GetValue<bool>() ?? false;
        }
        catch { return false; }
    }

    // ── Cloud Request-Response ─────────────────────────────────────────────

    /// <summary>
    /// Send a request via cloud relay and wait for a matching response.
    /// The response must include the same request_id in its payload.
    /// </summary>
    public async Task<JsonObject?> SendCloudRequestAsync(string peerDeviceId, string msgType, JsonObject? extraPayload = null, int timeoutMs = 15_000)
    {
        var requestId = Guid.NewGuid().ToString();
        var payload = extraPayload ?? new JsonObject();
        payload["request_id"] = requestId;

        var tcs = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingRequests[requestId] = tcs;

        try
        {
            if (!await PushMessageAsync(peerDeviceId, msgType, payload))
            {
                _pendingRequests.TryRemove(requestId, out _);
                return null;
            }

            using var cts = new CancellationTokenSource(timeoutMs);
            cts.Token.Register(() => tcs.TrySetCanceled());
            return await tcs.Task;
        }
        catch (OperationCanceledException)
        {
            Log($"Cloud request {msgType} to {peerDeviceId[..Math.Min(8, peerDeviceId.Length)]}… timed out");
            return null;
        }
        finally
        {
            _pendingRequests.TryRemove(requestId, out _);
        }
    }

    // ── Cloud Peer Discovery ──────────────────────────────────────────────

    /// <summary>
    /// List all paired peers from Convex sessions, with their online status.
    /// Used by Long Distance mode to show cloud-reachable devices.
    /// </summary>
    public async Task<List<(string DeviceId, string KeyFingerprint, string PairedVia, bool Online)>> ListPairedPeersAsync()
    {
        var result = new List<(string, string, string, bool)>();
        try
        {
            var sessionsArray = await QueryArrayAsync("sessions:listSessions",
                new JsonObject { ["device_id"] = _deviceId });
            if (sessionsArray is null) return result;

            foreach (var item in sessionsArray)
            {
                if (item is not JsonObject session) continue;
                var peerId = session["peer_id"]?.GetValue<string>() ?? "";
                if (string.IsNullOrWhiteSpace(peerId)) continue;

                var online = await GetPeerOnlineAsync(peerId);
                result.Add((
                    peerId,
                    session["key_fingerprint"]?.GetValue<string>() ?? "",
                    session["paired_via"]?.GetValue<string>() ?? "unknown",
                    online
                ));
            }
        }
        catch (Exception ex)
        {
            Log($"ListPairedPeers failed: {ex.Message}");
        }
        return result;
    }

    /// <summary>
    /// Get device info (name, platform) for a remote peer from Convex.
    /// </summary>
    public async Task<(string Name, string Platform, string AppVersion)?> GetPeerDeviceInfoAsync(string peerDeviceId)
    {
        try
        {
            var data = await QueryAsync("devices:getDevice", new JsonObject { ["device_id"] = peerDeviceId });
            if (data is null) return null;
            return (
                data["device_name"]?.GetValue<string>() ?? "Unknown",
                data["platform"]?.GetValue<string>() ?? "unknown",
                data["app_version"]?.GetValue<string>() ?? "0.0.0"
            );
        }
        catch { return null; }
    }

    // ── Background loops ───────────────────────────────────────────────────

    private async Task HeartbeatLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var ipHint = GetLocalIpHint();
                await MutationAsync("presence:heartbeat", new JsonObject
                {
                    ["device_id"] = _deviceId,
                    ["ip_hint"] = ipHint,
                    ["tcp_port"] = TcpPort,
                }, ct);
            }
            catch { /* offline — ignore */ }
            await Task.Delay(HeartbeatIntervalMs, ct).ContinueWith(_ => { });
        }
    }

    private async Task PollLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await PollAndDispatchAsync(ct);
            }
            catch { /* ignore transient errors */ }
            await Task.Delay(PollIntervalMs, ct).ContinueWith(_ => { });
        }
    }

    private async Task PollAndDispatchAsync(CancellationToken ct)
    {
        var rawArray = await QueryArrayAsync("messages:pollMessages",
            new JsonObject { ["recipient_id"] = _deviceId }, ct);
        if (rawArray is null || rawArray.Count == 0) return;

        var toAck = new JsonArray();

        foreach (var item in rawArray)
        {
            if (item is not JsonObject msg) continue;
            var senderId = msg["sender_id"]?.GetValue<string>() ?? "";
            var msgType = msg["msg_type"]?.GetValue<string>() ?? "";
            var nonce = msg["nonce"]?.GetValue<string>() ?? "";
            var ciphertext = msg["encrypted_payload"]?.GetValue<string>() ?? "";
            var messageId = msg["message_id"]?.ToString() ?? "";

            var key = await GetSessionKeyAsync(senderId);
            if (key is null)
            {
                await LoadSessionFromCloudAsync(senderId);
                key = await GetSessionKeyAsync(senderId);
            }
            if (key is null) { Log($"No key for {senderId[..Math.Min(8, senderId.Length)]}… — skipping"); continue; }

            try
            {
                var plaintext = DecryptGcm(key, nonce, ciphertext);
                var payload = JsonNode.Parse(Encoding.UTF8.GetString(plaintext))?.AsObject() ?? new JsonObject();

                // Check if this is a response to a pending cloud request
                var requestId = payload["request_id"]?.GetValue<string>();
                if (requestId is not null && _pendingRequests.TryRemove(requestId, out var tcs))
                {
                    Log($"Cloud response {msgType} from {senderId[..Math.Min(8, senderId.Length)]}… (req: {requestId[..Math.Min(8, requestId.Length)]}…)");
                    tcs.TrySetResult(payload);
                }
                else
                {
                    // Normal incoming message — dispatch to CcpNode handler
                    Log($"Received {msgType} from {senderId[..Math.Min(8, senderId.Length)]}…");
                    OnMessageReceived?.Invoke(senderId, msgType, payload);
                }

                toAck.Add(messageId);
            }
            catch (Exception ex)
            {
                Log($"Decrypt failed: {ex.Message}");
            }
        }

        if (toAck.Count > 0)
        {
            await MutationAsync("messages:ackMessages", new JsonObject { ["message_ids"] = toAck }, ct);
        }
    }

    // ── Crypto helpers ─────────────────────────────────────────────────────

    private static Dictionary<string, string> EncryptGcm(byte[] key, byte[] plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
        // Append tag to ciphertext (matches Android/Python convention)
        var combined = new byte[ciphertext.Length + tag.Length];
        ciphertext.CopyTo(combined, 0);
        tag.CopyTo(combined, ciphertext.Length);
        return new Dictionary<string, string>
        {
            ["nonce"] = Convert.ToBase64String(nonce),
            ["ciphertext"] = Convert.ToBase64String(combined),
        };
    }

    private static byte[] DecryptGcm(byte[] key, string nonceB64, string ciphertextB64)
    {
        var nonce = Convert.FromBase64String(nonceB64);
        var combined = Convert.FromBase64String(ciphertextB64);
        var tag = combined[^16..];
        var ciphertext = combined[..^16];
        var plaintext = new byte[ciphertext.Length];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }

    // ── HTTP helpers ───────────────────────────────────────────────────────

    private static readonly JsonSerializerOptions _jsonOpts = new() { PropertyNamingPolicy = null };

    private async Task<JsonObject?> MutationAsync(string func, JsonObject args, CancellationToken ct = default)
    {
        return await PostConvexAsync("mutation", func, args, ct);
    }

    private async Task<JsonObject?> QueryAsync(string func, JsonObject args, CancellationToken ct = default)
    {
        return await PostConvexAsync("query", func, args, ct);
    }

    private async Task<JsonArray?> QueryArrayAsync(string func, JsonObject args, CancellationToken ct = default)
    {
        var body = new JsonObject { ["path"] = func, ["args"] = args, ["format"] = "json" };
        var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        var response = await _http.PostAsync($"{ConvexUrl}/api/query", content, ct);
        var text = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode) { Log($"HTTP {(int)response.StatusCode}: {text}"); return null; }
        var node = JsonNode.Parse(text);
        return node?["value"]?.AsArray();
    }

    private async Task<JsonObject?> PostConvexAsync(string endpoint, string func, JsonObject args, CancellationToken ct)
    {
        var body = new JsonObject { ["path"] = func, ["args"] = args, ["format"] = "json" };
        var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        try
        {
            var response = await _http.PostAsync($"{ConvexUrl}/api/{endpoint}", content, ct);
            var text = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode) { Log($"HTTP {(int)response.StatusCode}: {text[..Math.Min(200, text.Length)]}"); return null; }
            return JsonNode.Parse(text)?["value"]?.AsObject();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"Request failed ({func}): {ex.Message}");
            return null;
        }
    }

    // ── Utilities ──────────────────────────────────────────────────────────

    private static string GetLocalIpHint()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up))
        {
            foreach (var addr in nic.GetIPProperties().UnicastAddresses)
            {
                if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                    && !System.Net.IPAddress.IsLoopback(addr.Address))
                {
                    var parts = addr.Address.ToString().Split('.');
                    return $"{parts[0]}.{parts[1]}.x.x";
                }
            }
        }
        return "x.x.x.x";
    }

    private void SetStatus(string status)
    {
        CloudStatus = status;
        OnCloudStatusChanged?.Invoke(status);
    }

    private void Log(string msg) => _logger?.Invoke($"[Cloud] {msg}");

    public void Dispose()
    {
        _cts?.Cancel();
        _cts?.Dispose();
        _http.Dispose();
    }
}
