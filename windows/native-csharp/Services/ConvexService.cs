using System.Collections.Concurrent;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace CCP.Windows.Services;

public sealed class ConvexService : IDisposable
{
    private const string ConvexUrl = "https://reminiscent-raven-475.convex.cloud";
    private const int HeartbeatIntervalMs = 10_000;
    private const int PollIntervalMs = 3_000;
    private const int TcpPort = 47828;

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly string _deviceId;
    private readonly string _deviceName;
    private readonly byte[] _publicKey;
    private readonly string _cloudAuthToken;
    private readonly string _cloudAuthTokenHash;
    private readonly Dictionary<string, byte[]> _sessionKeys = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _sessionLock = new(1, 1);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<JsonObject>> _pendingRequests = new();

    private CancellationTokenSource? _cts;
    private Action<string>? _logger;

    public string PublicKeyB64 { get; }
    public string CloudStatus { get; private set; } = "Connecting...";
    public event Action<string>? OnCloudStatusChanged;
    public event Action<string, string, JsonObject>? OnMessageReceived;

    public ConvexService(string deviceId, string deviceName, byte[] privateKey, string cloudAuthToken)
    {
        _deviceId = deviceId;
        _deviceName = deviceName;
        _cloudAuthToken = cloudAuthToken;
        _cloudAuthTokenHash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(cloudAuthToken))).ToLowerInvariant();
        _publicKey = SHA256.HashData([.. privateKey, .. "ccp-pub"u8.ToArray()]);
        PublicKeyB64 = Convert.ToBase64String(_publicKey);
    }

    public void SetLogger(Action<string> logger) => _logger = logger;

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
            await MutationAsync("presence:goOffline", AuthArgs(new JsonObject { ["device_id"] = _deviceId }));
        }
        catch
        {
        }
    }

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
                ["auth_token_hash"] = _cloudAuthTokenHash,
            }, ct);
            SetStatus("Cloud connected");
            Log("Registered on Convex");
        }
        catch (Exception ex)
        {
            SetStatus("Cloud offline");
            Log($"Registration failed: {ex.Message}");
        }
    }

    public async Task<string> CompleteKeyExchangeAsync(
        string peerDeviceId,
        string peerPublicKeyB64,
        string? pairSecretB64,
        string pairedVia = "wifi")
    {
        if (string.IsNullOrWhiteSpace(pairSecretB64))
        {
            Log($"No pair secret for {Short(peerDeviceId)}; re-pair before using cloud relay");
            return "";
        }

        var pairSecret = Convert.FromBase64String(pairSecretB64);
        var idA = string.Compare(_deviceId, peerDeviceId, StringComparison.Ordinal) < 0 ? _deviceId : peerDeviceId;
        var idB = string.Compare(_deviceId, peerDeviceId, StringComparison.Ordinal) < 0 ? peerDeviceId : _deviceId;
        var context = Encoding.UTF8.GetBytes($"{idA}|{idB}");
        var sessionInput = new byte[pairSecret.Length + context.Length];
        Buffer.BlockCopy(pairSecret, 0, sessionInput, 0, pairSecret.Length);
        Buffer.BlockCopy(context, 0, sessionInput, pairSecret.Length, context.Length);

        var sessionKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, sessionInput, 32, info: "ccp-session-v1"u8.ToArray());
        var wrapKey = HKDF.DeriveKey(HashAlgorithmName.SHA256, pairSecret, 32, info: "ccp-session-wrap-v1"u8.ToArray());
        var fingerprint = Convert.ToHexString(SHA256.HashData(sessionKey)).ToLowerInvariant();
        var encryptedBlob = Convert.ToBase64String(Encoding.UTF8.GetBytes(
            JsonSerializer.Serialize(EncryptGcm(wrapKey, sessionKey))));

        try
        {
            await MutationAsync("sessions:storeSession", AuthArgs(new JsonObject
            {
                ["device_id_a"] = idA,
                ["device_id_b"] = idB,
                ["encrypted_key_a"] = encryptedBlob,
                ["encrypted_key_b"] = encryptedBlob,
                ["key_fingerprint"] = fingerprint,
                ["paired_via"] = pairedVia,
                ["caller_device_id"] = _deviceId,
            }));
            Log($"Session stored with {Short(peerDeviceId)} (fp: {Short(fingerprint, 12)})");
            SetStatus("Cloud relay ready");
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

    public async Task<bool> LoadSessionFromCloudAsync(string peerDeviceId, string? pairSecretB64)
    {
        if (string.IsNullOrWhiteSpace(pairSecretB64))
        {
            Log($"No pair secret for {Short(peerDeviceId)}; re-pair before using cloud relay");
            return false;
        }

        try
        {
            var data = await QueryAsync("sessions:getSession", AuthArgs(new JsonObject
            {
                ["my_device_id"] = _deviceId,
                ["peer_device_id"] = peerDeviceId,
            }));
            if (data is null) return false;

            var wrapKey = HKDF.DeriveKey(HashAlgorithmName.SHA256,
                Convert.FromBase64String(pairSecretB64), 32, info: "ccp-session-wrap-v1"u8.ToArray());
            var blobJson = JsonNode.Parse(
                Encoding.UTF8.GetString(Convert.FromBase64String(data["encrypted_key"]!.GetValue<string>())))!.AsObject();
            var sessionKey = DecryptGcm(wrapKey,
                blobJson["nonce"]!.GetValue<string>(),
                blobJson["ciphertext"]!.GetValue<string>());

            await _sessionLock.WaitAsync();
            try { _sessionKeys[peerDeviceId] = sessionKey; }
            finally { _sessionLock.Release(); }

            Log($"Session loaded for {Short(peerDeviceId)}");
            return true;
        }
        catch (Exception ex)
        {
            Log($"Session load failed for {Short(peerDeviceId)}: {ex.Message}");
            return false;
        }
    }

    public async Task<bool> EnsureSessionKeyAsync(string peerDeviceId, string? pairSecretB64)
    {
        if (await GetSessionKeyAsync(peerDeviceId) is not null) return true;
        return await LoadSessionFromCloudAsync(peerDeviceId, pairSecretB64);
    }

    public async Task<byte[]?> GetSessionKeyAsync(string peerDeviceId)
    {
        await _sessionLock.WaitAsync();
        try
        {
            return _sessionKeys.TryGetValue(peerDeviceId, out var key) ? key : null;
        }
        finally { _sessionLock.Release(); }
    }

    public async Task<bool> PushMessageAsync(string peerDeviceId, string msgType, JsonObject payload, long? ttlMs = null)
    {
        var key = await GetSessionKeyAsync(peerDeviceId);
        if (key is null)
        {
            Log($"No session for {Short(peerDeviceId)}; pair first");
            return false;
        }

        var enc = EncryptGcm(key, Encoding.UTF8.GetBytes(payload.ToJsonString()));
        var args = AuthArgs(new JsonObject
        {
            ["sender_id"] = _deviceId,
            ["recipient_id"] = peerDeviceId,
            ["msg_type"] = msgType,
            ["encrypted_payload"] = enc["ciphertext"],
            ["nonce"] = enc["nonce"],
            ["msg_id"] = Guid.NewGuid().ToString(),
        });
        if (ttlMs.HasValue) args["ttl_ms"] = ttlMs.Value;

        try
        {
            await MutationAsync("messages:pushMessage", args);
            Log($"Pushed {msgType} to {Short(peerDeviceId)}");
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
            var data = await QueryAsync("devices:getPublicKey", AuthArgs(new JsonObject
            {
                ["requester_device_id"] = _deviceId,
                ["device_id"] = peerDeviceId,
            }));
            return data?["public_key_b64"]?.GetValue<string>();
        }
        catch { return null; }
    }

    public async Task<bool> GetPeerOnlineAsync(string peerDeviceId)
    {
        try
        {
            var data = await QueryAsync("presence:getPresence", AuthArgs(new JsonObject
            {
                ["requester_device_id"] = _deviceId,
                ["device_id"] = peerDeviceId,
            }));
            return data?["online"]?.GetValue<bool>() ?? false;
        }
        catch { return false; }
    }

    public async Task<JsonObject?> SendCloudRequestAsync(
        string peerDeviceId,
        string msgType,
        JsonObject? extraPayload = null,
        int timeoutMs = 15_000)
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
            using var registration = cts.Token.Register(() => tcs.TrySetCanceled());
            return await tcs.Task;
        }
        catch (OperationCanceledException)
        {
            Log($"Cloud request {msgType} to {Short(peerDeviceId)} timed out");
            return null;
        }
        finally
        {
            _pendingRequests.TryRemove(requestId, out _);
        }
    }

    public async Task<List<(string DeviceId, string KeyFingerprint, string PairedVia, bool Online)>> ListPairedPeersAsync()
    {
        var result = new List<(string, string, string, bool)>();
        try
        {
            var sessionsArray = await QueryArrayAsync("sessions:listSessions", AuthArgs(new JsonObject
            {
                ["device_id"] = _deviceId,
            }));
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

    public async Task<(string Name, string Platform, string AppVersion)?> GetPeerDeviceInfoAsync(string peerDeviceId)
    {
        try
        {
            var data = await QueryAsync("devices:getDevice", AuthArgs(new JsonObject
            {
                ["requester_device_id"] = _deviceId,
                ["device_id"] = peerDeviceId,
            }));
            if (data is null) return null;
            return (
                data["device_name"]?.GetValue<string>() ?? "Unknown",
                data["platform"]?.GetValue<string>() ?? "unknown",
                data["app_version"]?.GetValue<string>() ?? "0.0.0"
            );
        }
        catch { return null; }
    }

    private async Task HeartbeatLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await MutationAsync("presence:heartbeat", AuthArgs(new JsonObject
                {
                    ["device_id"] = _deviceId,
                    ["ip_hint"] = GetLocalIpHint(),
                    ["tcp_port"] = TcpPort,
                }), ct);
            }
            catch
            {
            }
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
            catch
            {
            }
            await Task.Delay(PollIntervalMs, ct).ContinueWith(_ => { });
        }
    }

    private async Task PollAndDispatchAsync(CancellationToken ct)
    {
        var rawArray = await QueryArrayAsync("messages:pollMessages", AuthArgs(new JsonObject
        {
            ["recipient_id"] = _deviceId,
        }), ct);
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
                Log($"No key for {Short(senderId)}; skipping cloud message");
                continue;
            }

            try
            {
                var plaintext = DecryptGcm(key, nonce, ciphertext);
                var payload = JsonNode.Parse(Encoding.UTF8.GetString(plaintext))?.AsObject() ?? new JsonObject();
                var requestId = payload["request_id"]?.GetValue<string>();
                if (requestId is not null && _pendingRequests.TryRemove(requestId, out var tcs))
                {
                    Log($"Cloud response {msgType} from {Short(senderId)}");
                    tcs.TrySetResult(payload);
                }
                else
                {
                    Log($"Received {msgType} from {Short(senderId)}");
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
            await MutationAsync("messages:ackMessages", AuthArgs(new JsonObject
            {
                ["recipient_id"] = _deviceId,
                ["message_ids"] = toAck,
            }), ct);
        }
    }

    private static Dictionary<string, string> EncryptGcm(byte[] key, byte[] plaintext)
    {
        var nonce = RandomNumberGenerator.GetBytes(12);
        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);
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

    private JsonObject AuthArgs(JsonObject args)
    {
        args["auth_token"] = _cloudAuthToken;
        return args;
    }

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
        if (!response.IsSuccessStatusCode)
        {
            Log($"HTTP {(int)response.StatusCode}: {text}");
            return null;
        }
        return JsonNode.Parse(text)?["value"]?.AsArray();
    }

    private async Task<JsonObject?> PostConvexAsync(string endpoint, string func, JsonObject args, CancellationToken ct)
    {
        var body = new JsonObject { ["path"] = func, ["args"] = args, ["format"] = "json" };
        var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        try
        {
            var response = await _http.PostAsync($"{ConvexUrl}/api/{endpoint}", content, ct);
            var text = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
            {
                Log($"HTTP {(int)response.StatusCode}: {text[..Math.Min(200, text.Length)]}");
                return null;
            }
            return JsonNode.Parse(text)?["value"]?.AsObject();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            Log($"Request failed ({func}): {ex.Message}");
            return null;
        }
    }

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

    private static string Short(string value, int length = 8) =>
        value[..Math.Min(length, value.Length)];

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
