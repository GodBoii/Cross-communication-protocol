using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Net.NetworkInformation;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;

namespace CCP.Windows.Services;

/// <summary>Convex rejected a call (auth failure, validation error, ...).</summary>
public sealed class ConvexException(string message) : IOException(message);

/// <summary>
/// Windows ↔ Convex cloud relay ("Long Distance"), wire-compatible with the
/// Android ConvexBridge.
///
///  • Every call is authenticated with the device's cloud auth token; the
///    device id is bound to that token.
///  • Payloads are AES-256-GCM encrypted with a key both peers derive locally
///    from their pair secret; sender/recipient/type/msg_id are bound as AAD.
///  • Messages are acked only after they've been handled; replays are rejected.
///  • Polling backs off while idle and wakes immediately for outgoing requests.
/// </summary>
public sealed partial class ConvexService : IDisposable
{
    public const string DefaultConvexUrl = "https://reminiscent-raven-475.convex.cloud";
    private static readonly TimeSpan HeartbeatInterval = TimeSpan.FromSeconds(15);
    private static readonly TimeSpan PollActive = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan PollIdleMax = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ActiveWindow = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan MaxMessageAge = TimeSpan.FromDays(8);
    private const int PollBatch = 20;
    private const int MaxEncryptedPayloadChars = 512 * 1024;
    private static readonly byte[] WrapAad = "ccp-cloud-wrap-v1"u8.ToArray();

    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(15) };
    private readonly string _convexUrl;
    private readonly string _deviceId;
    private readonly string _deviceName;
    private readonly string _cloudAuthToken;
    private readonly Func<string, byte[]?> _pairSecretFor;
    private readonly ConcurrentDictionary<string, PendingRequest> _pendingRequests = new();
    private readonly ReplayGuard _replayGuard;
    private readonly SemaphoreSlim _wake = new(0, 1);

    private CancellationTokenSource? _cts;
    private Action<string>? _logger;
    private DateTime _lastActivity = DateTime.MinValue;

    public string CloudStatus { get; private set; } = "Connecting...";
    public event Action<string>? OnCloudStatusChanged;
    public event Action<string, string, JsonObject>? OnMessageReceived;

    private sealed record PendingRequest(string PeerId, TaskCompletionSource<JsonObject> Completion);

    public ConvexService(string deviceId, string deviceName, string cloudAuthToken, Func<string, byte[]?> pairSecretFor, string? convexUrl = null)
    {
        _convexUrl = (convexUrl ?? Environment.GetEnvironmentVariable("CCP_CONVEX_URL") ?? DefaultConvexUrl).TrimEnd('/');
        if (!_convexUrl.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            throw new ArgumentException("Convex URL must use HTTPS", nameof(convexUrl));
        }
        _deviceId = deviceId;
        _deviceName = deviceName;
        _cloudAuthToken = cloudAuthToken;
        _pairSecretFor = pairSecretFor;
        _replayGuard = new ReplayGuard(Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "CCP", "seen-msg-ids.json"));
    }

    public void SetLogger(Action<string> logger) => _logger = logger;

    public void Start(string appVersion)
    {
        if (_cts is not null) return;
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        _ = Task.Run(() => RegisterLoopAsync(appVersion, ct), ct);
        _ = Task.Run(() => HeartbeatLoopAsync(ct), ct);
        _ = Task.Run(() => PollLoopAsync(ct), ct);
    }

    public async Task StopAsync()
    {
        _cts?.Cancel();
        foreach (var pending in _pendingRequests.Values) pending.Completion.TrySetCanceled();
        _pendingRequests.Clear();
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(3));
            await CallAsync("mutation", "presence:goOffline", Auth(new JsonObject { ["device_id"] = _deviceId }), timeout.Token);
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException or OperationCanceledException)
        {
            // Presence expires on its own after 30 s.
        }
    }

    // ── Sessions ────────────────────────────────────────────────────────────

    /// <summary>
    /// Records the pairing in Convex so the relay carries messages between the
    /// two devices. The stored blob is the cloud key wrapped under a key only
    /// the peers can derive.
    /// </summary>
    public async Task<bool> StoreSessionAsync(string peerDeviceId, byte[] pairSecret, string pairedVia = "wifi")
    {
        var (idA, idB) = string.CompareOrdinal(_deviceId, peerDeviceId) < 0 ? (_deviceId, peerDeviceId) : (peerDeviceId, _deviceId);
        var cloudKey = CcpCloudKeys.CloudKey(pairSecret, _deviceId, peerDeviceId);
        var wrapKey = CcpCloudKeys.WrapKey(pairSecret, _deviceId, peerDeviceId);
        var nonce = CcpCrypto.RandomBytes(12);
        var blob = new JsonObject
        {
            ["v"] = 1,
            ["nonce"] = CcpCrypto.B64(nonce),
            ["ciphertext"] = CcpCrypto.B64(CcpCrypto.Seal(wrapKey, nonce, WrapAad, cloudKey)),
        }.ToJsonString();
        var fingerprint = CcpCloudKeys.Fingerprint(cloudKey);
        try
        {
            await CallAsync("mutation", "sessions:storeSession", Auth(new JsonObject
            {
                ["device_id_a"] = idA,
                ["device_id_b"] = idB,
                ["caller_device_id"] = _deviceId,
                ["encrypted_key_a"] = blob,
                ["encrypted_key_b"] = blob,
                ["key_fingerprint"] = fingerprint,
                ["paired_via"] = pairedVia,
            }));
            Log($"Session stored with {Short(peerDeviceId)} (fp {Short(fingerprint, 12)})");
            SetStatus("Cloud relay ready");
            return true;
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException or TaskCanceledException)
        {
            Log($"Session store failed: {ex.Message}");
            return false;
        }
    }

    private byte[]? KeyFor(string peerDeviceId) =>
        _pairSecretFor(peerDeviceId) is { } secret ? CcpCloudKeys.CloudKey(secret, _deviceId, peerDeviceId) : null;

    // ── Messages ────────────────────────────────────────────────────────────

    public async Task<bool> PushMessageAsync(string peerDeviceId, string msgType, JsonObject payload, long? ttlMs = null)
    {
        var key = KeyFor(peerDeviceId);
        if (key is null)
        {
            Log($"Not paired with {Short(peerDeviceId)}; pair first");
            return false;
        }

        var msgId = Guid.NewGuid().ToString();
        var plaintext = Encoding.UTF8.GetBytes(new JsonObject
        {
            ["v"] = 1,
            ["sent_at"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            ["body"] = payload.DeepClone(),
        }.ToJsonString());
        var nonce = CcpCrypto.RandomBytes(12);
        var aad = CcpCloudKeys.MessageAad(_deviceId, peerDeviceId, msgType, msgId);
        var encoded = CcpCrypto.B64(CcpCrypto.Seal(key, nonce, aad, plaintext));
        if (encoded.Length > MaxEncryptedPayloadChars)
        {
            Log($"{msgType} is too large for the relay");
            return false;
        }

        var args = Auth(new JsonObject
        {
            ["sender_id"] = _deviceId,
            ["recipient_id"] = peerDeviceId,
            ["msg_type"] = msgType,
            ["encrypted_payload"] = encoded,
            ["nonce"] = CcpCrypto.B64(nonce),
            ["msg_id"] = msgId,
        });
        if (ttlMs.HasValue) args["ttl_ms"] = ttlMs.Value;

        // Retrying is safe: Convex de-duplicates by (sender, msg_id).
        for (var attempt = 0; attempt < 3; attempt++)
        {
            try
            {
                await CallAsync("mutation", "messages:pushMessage", args);
                MarkActive();
                return true;
            }
            catch (ConvexException ex)
            {
                Log($"Relay rejected {msgType}: {ex.Message}");
                return false;
            }
            catch (Exception ex) when (ex is IOException or HttpRequestException or TaskCanceledException)
            {
                if (attempt == 2)
                {
                    Log($"Push {msgType} failed: {ex.Message}");
                    return false;
                }
                await Task.Delay(1000 * (attempt + 1));
            }
        }
        return false;
    }

    public async Task<JsonObject?> SendCloudRequestAsync(
        string peerDeviceId,
        string msgType,
        JsonObject? extraPayload = null,
        int timeoutMs = 20_000)
    {
        var requestId = Guid.NewGuid().ToString();
        var payload = extraPayload ?? new JsonObject();
        payload["request_id"] = requestId;

        var tcs = new TaskCompletionSource<JsonObject>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pendingRequests[requestId] = new PendingRequest(peerDeviceId, tcs);
        MarkActive();
        try
        {
            if (!await PushMessageAsync(peerDeviceId, msgType, payload)) return null;
            var finished = await Task.WhenAny(tcs.Task, Task.Delay(timeoutMs));
            if (finished == tcs.Task && tcs.Task.IsCompletedSuccessfully) return tcs.Task.Result;
            Log($"Cloud request {msgType} to {Short(peerDeviceId)} timed out");
            return null;
        }
        finally
        {
            _pendingRequests.TryRemove(requestId, out _);
        }
    }

    // ── Peer metadata ──────────────────────────────────────────────────────

    public async Task<IReadOnlyList<string>?> ListPairedPeerIdsAsync()
    {
        var sessions = await SafeQueryAsync("sessions:listSessions", Auth(new JsonObject { ["device_id"] = _deviceId })) as JsonArray;
        if (sessions is null) return null;
        return sessions.OfType<JsonObject>()
            .Select(s => CcpWire.Str(s["peer_id"]))
            .Where(CcpIdentity.IsValidDeviceId)
            .Distinct()
            .ToList();
    }

    public async Task<bool> GetPeerOnlineAsync(string peerDeviceId)
    {
        var data = await SafeQueryAsync("presence:getPresence", Auth(new JsonObject
        {
            ["requester_device_id"] = _deviceId,
            ["device_id"] = peerDeviceId,
        })) as JsonObject;
        return CcpWire.Bool(data?["online"]);
    }

    public async Task<(string Name, string Platform)?> GetPeerDeviceInfoAsync(string peerDeviceId)
    {
        if (await SafeQueryAsync("devices:getDevice", Auth(new JsonObject
            {
                ["requester_device_id"] = _deviceId,
                ["device_id"] = peerDeviceId,
            })) is not JsonObject data)
        {
            return null;
        }
        return (CcpWire.Str(data["device_name"], "Unknown"), CcpWire.Str(data["platform"], "unknown"));
    }

    private async Task<JsonNode?> SafeQueryAsync(string path, JsonObject args)
    {
        try
        {
            return await CallAsync("query", path, args);
        }
        catch (Exception ex) when (ex is IOException or HttpRequestException or TaskCanceledException)
        {
            Log($"{path} failed: {ex.Message}");
            return null;
        }
    }

    // ── Background loops ────────────────────────────────────────────────────

    private async Task RegisterLoopAsync(string appVersion, CancellationToken ct)
    {
        var backoff = TimeSpan.FromSeconds(5);
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await CallAsync("mutation", "devices:registerDevice", new JsonObject
                {
                    ["device_id"] = _deviceId,
                    ["device_name"] = _deviceName.Length > 64 ? _deviceName[..64] : _deviceName,
                    ["platform"] = "windows",
                    ["public_key_b64"] = "",
                    ["capabilities"] = new JsonArray("pairing", "file.transfer", "device.snapshot", "gallery.list", "files.list"),
                    ["app_version"] = appVersion,
                    ["auth_token"] = _cloudAuthToken,
                }, ct);
                SetStatus("Cloud connected");
                Log("Registered on Convex");
                return;
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex) when (ex is IOException or HttpRequestException or TaskCanceledException)
            {
                SetStatus("Cloud offline");
                Log($"Registration failed: {ex.Message}");
            }
            await DelayAsync(backoff, ct);
            backoff = TimeSpan.FromSeconds(Math.Min(backoff.TotalSeconds * 2, 300));
        }
    }

    private async Task HeartbeatLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await CallAsync("mutation", "presence:heartbeat", Auth(new JsonObject
                {
                    ["device_id"] = _deviceId,
                    ["ip_hint"] = GetLocalIpHint(),
                    ["tcp_port"] = CcpWire.TcpPort,
                }), ct);
            }
            catch (Exception ex) when (ex is IOException or HttpRequestException or TaskCanceledException)
            {
                // The registration loop reports connectivity; a missed beat just shows us offline.
            }
            await DelayAsync(HeartbeatInterval, ct);
        }
    }

    private async Task PollLoopAsync(CancellationToken ct)
    {
        var interval = PollActive;
        while (!ct.IsCancellationRequested)
        {
            var count = 0;
            try
            {
                count = await PollOnceAsync(ct);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex) when (ex is IOException or HttpRequestException or TaskCanceledException or JsonException)
            {
                Log($"Poll failed: {ex.Message}");
            }
            if (count >= PollBatch) continue; // drain a backlog immediately

            var active = count > 0 || !_pendingRequests.IsEmpty || DateTime.UtcNow - _lastActivity < ActiveWindow;
            interval = active ? PollActive : TimeSpan.FromMilliseconds(Math.Min(interval.TotalMilliseconds * 2, PollIdleMax.TotalMilliseconds));
            try
            {
                await _wake.WaitAsync(interval, ct);
            }
            catch (OperationCanceledException)
            {
                return;
            }
        }
    }

    /// <summary>Polls one batch, handles each message, then acks the batch.</summary>
    private async Task<int> PollOnceAsync(CancellationToken ct)
    {
        if (await CallAsync("query", "messages:pollMessages", Auth(new JsonObject
            {
                ["recipient_id"] = _deviceId,
                ["limit"] = PollBatch,
            }), ct) is not JsonArray raw || raw.Count == 0)
        {
            return 0;
        }

        var toAck = new JsonArray();
        foreach (var msg in raw.OfType<JsonObject>())
        {
            try
            {
                Dispatch(msg);
            }
            catch (Exception ex)
            {
                // Undecryptable, replayed or failing messages are dropped, not redelivered forever.
                Log($"Dropped {CcpWire.Str(msg["msg_type"])} from {Short(CcpWire.Str(msg["sender_id"]))}: {ex.Message}");
            }
            var messageId = CcpWire.Str(msg["message_id"]);
            if (messageId.Length > 0) toAck.Add(messageId);
        }

        if (toAck.Count > 0)
        {
            await CallAsync("mutation", "messages:ackMessages", Auth(new JsonObject
            {
                ["recipient_id"] = _deviceId,
                ["message_ids"] = toAck,
            }), ct);
            _replayGuard.Persist();
        }
        return raw.Count;
    }

    private void Dispatch(JsonObject msg)
    {
        var senderId = CcpWire.Str(msg["sender_id"]);
        var msgType = CcpWire.Str(msg["msg_type"]);
        var msgId = CcpWire.Str(msg["msg_id"]);
        var key = KeyFor(senderId) ?? throw new InvalidOperationException("sender is not paired");
        var aad = CcpCloudKeys.MessageAad(senderId, _deviceId, msgType, msgId);
        var plain = CcpCrypto.Open(key, CcpCrypto.UnB64(CcpWire.Str(msg["nonce"])), aad, CcpCrypto.UnB64(CcpWire.Str(msg["encrypted_payload"])));
        var envelope = CcpWire.ParseObject(Encoding.UTF8.GetString(plain));

        var sentAt = DateTimeOffset.FromUnixTimeMilliseconds(CcpWire.Long(envelope["sent_at"], 0));
        if ((DateTimeOffset.UtcNow - sentAt).Duration() > MaxMessageAge) throw new InvalidOperationException("message too old");
        if (!_replayGuard.FirstSeen($"{senderId}|{msgId}")) throw new InvalidOperationException("replayed message");

        var payload = envelope["body"] as JsonObject ?? new JsonObject();
        MarkActive();

        var requestId = CcpWire.Str(payload["request_id"]);
        if (requestId.Length > 0 && msgType.EndsWith(".response", StringComparison.Ordinal) &&
            _pendingRequests.TryGetValue(requestId, out var pending) && pending.PeerId == senderId)
        {
            _pendingRequests.TryRemove(requestId, out _);
            pending.Completion.TrySetResult(payload);
            return;
        }
        OnMessageReceived?.Invoke(senderId, msgType, payload);
    }

    private void MarkActive()
    {
        _lastActivity = DateTime.UtcNow;
        if (_wake.CurrentCount == 0)
        {
            try { _wake.Release(); } catch (SemaphoreFullException) { }
        }
    }

    // ── HTTP ────────────────────────────────────────────────────────────────

    private JsonObject Auth(JsonObject args)
    {
        args["auth_token"] = _cloudAuthToken;
        return args;
    }

    /// <summary>
    /// Calls a Convex function over the HTTP API. Convex reports function
    /// errors as HTTP 200 with status "error"; both become <see cref="ConvexException"/>.
    /// </summary>
    private async Task<JsonNode?> CallAsync(string kind, string path, JsonObject args, CancellationToken ct = default)
    {
        var body = new JsonObject { ["path"] = path, ["args"] = args, ["format"] = "json" };
        using var content = new StringContent(body.ToJsonString(), Encoding.UTF8, "application/json");
        using var response = await _http.PostAsync($"{_convexUrl}/api/{kind}", content, ct);
        var text = await response.Content.ReadAsStringAsync(ct);
        JsonObject? json = null;
        try { json = JsonNode.Parse(text) as JsonObject; } catch (JsonException) { }
        if (!response.IsSuccessStatusCode || CcpWire.Str(json?["status"]) == "error")
        {
            throw new ConvexException(SummarizeError(CcpWire.Str(json?["errorMessage"]), (int)response.StatusCode));
        }
        return json?["value"];
    }

    /// <summary>Extracts "auth_failed" from Convex's "...Uncaught Error: auth_failed\n at ..." messages.</summary>
    public static string SummarizeError(string? message, int httpCode)
    {
        if (string.IsNullOrWhiteSpace(message)) return $"HTTP {httpCode}";
        var match = UncaughtError().Match(message);
        var summary = match.Success ? match.Groups[1].Value.Trim() : message.Split('\n')[0];
        return summary.Length > 200 ? summary[..200] : summary;
    }

    [GeneratedRegex(@"Uncaught Error: ([^\n]+)")]
    private static partial Regex UncaughtError();

    private static string GetLocalIpHint()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces().Where(n => n.OperationalStatus == OperationalStatus.Up))
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

    private static async Task DelayAsync(TimeSpan delay, CancellationToken ct)
    {
        try { await Task.Delay(delay, ct); } catch (OperationCanceledException) { }
    }

    private static string Short(string value, int length = 8) => value[..Math.Min(length, value.Length)];

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
        _wake.Dispose();
    }

    /// <summary>Persisted set of recently seen relay message ids (bounded).</summary>
    private sealed class ReplayGuard
    {
        private const int MaxEntries = 2000;
        private readonly string _path;
        private readonly LinkedList<string> _order = new();
        private readonly HashSet<string> _seen = [];
        private readonly object _lock = new();
        private bool _dirty;

        public ReplayGuard(string path)
        {
            _path = path;
            try
            {
                if (File.Exists(path) && JsonSerializer.Deserialize<List<string>>(File.ReadAllText(path)) is { } ids)
                {
                    foreach (var id in ids) Add(id);
                }
            }
            catch (Exception ex) when (ex is IOException or JsonException)
            {
                // A lost replay cache only weakens replay protection until refilled.
            }
        }

        public bool FirstSeen(string id)
        {
            lock (_lock)
            {
                if (_seen.Contains(id)) return false;
                Add(id);
                _dirty = true;
                return true;
            }
        }

        public void Persist()
        {
            lock (_lock)
            {
                if (!_dirty) return;
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
                    var temp = _path + ".tmp";
                    File.WriteAllText(temp, JsonSerializer.Serialize(_order.ToList()));
                    File.Move(temp, _path, overwrite: true);
                    _dirty = false;
                }
                catch (IOException)
                {
                    // Retry on the next batch.
                }
            }
        }

        private void Add(string id)
        {
            if (!_seen.Add(id)) return;
            _order.AddLast(id);
            while (_order.Count > MaxEntries)
            {
                _seen.Remove(_order.First!.Value);
                _order.RemoveFirst();
            }
        }
    }
}
