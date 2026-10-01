using System.IO;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace CCP.Windows.Services;

/// <summary>Wire constants and envelope helpers shared by every CCP v1 message.</summary>
public static class CcpWire
{
    /// <summary>v1: ECDH pairing and encrypted LAN sessions; not wire-compatible with v0.</summary>
    public const string Protocol = "ccp.v1";
    public const int UdpPort = 47827;
    public const int TcpPort = 47828;
    public const int ChunkSize = 64 * 1024;
    public const int SessionNonceBytes = 16;
    public const int MaxConcurrentConnections = 16;
    /// <summary>Idle read timeout; longer than the 60 s pairing prompt.</summary>
    public static readonly TimeSpan IdleTimeout = TimeSpan.FromSeconds(90);

    public static JsonObject Envelope(string type, JsonObject sender, JsonObject payload) => new()
    {
        ["protocol"] = Protocol,
        ["id"] = Guid.NewGuid().ToString(),
        ["type"] = type,
        ["sender"] = sender.DeepClone(),
        ["payload"] = payload,
        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
    };

    public static string Type(JsonObject message) => Str(message["type"]);

    public static JsonObject Payload(JsonObject message) => message["payload"] as JsonObject ?? new JsonObject();

    public static string SenderId(JsonObject message) => Str((message["sender"] as JsonObject)?["device_id"]);

    /// <summary>Reads any JSON scalar as a string without throwing on type mismatches.</summary>
    public static string Str(JsonNode? node, string fallback = "")
    {
        if (node is not JsonValue value) return fallback;
        if (value.TryGetValue<string>(out var s)) return s;
        return value.ToJsonString().Trim('"');
    }

    public static bool Bool(JsonNode? node) => node is JsonValue v && v.TryGetValue<bool>(out var b) && b;

    public static long Long(JsonNode? node, long fallback = -1)
    {
        if (node is not JsonValue v) return fallback;
        if (v.TryGetValue<long>(out var l)) return l;
        if (v.TryGetValue<int>(out var i)) return i;
        if (v.TryGetValue<double>(out var d) && d == Math.Floor(d) && Math.Abs(d) < 9e15) return (long)d;
        return fallback;
    }

    public static JsonObject ParseObject(string line) =>
        JsonNode.Parse(line) as JsonObject ?? throw new InvalidDataException("Expected a JSON object");

    public static async Task<string?> ReadLineWithTimeoutAsync(BoundedLineReader reader, CancellationToken ct)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(IdleTimeout);
        try
        {
            return await reader.ReadLineAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            throw new TimeoutException("Peer went silent");
        }
    }
}

/// <summary>The peer refused or could not authenticate the session.</summary>
public sealed class SessionRefusedException(string reason) : IOException($"Peer refused session: {reason}")
{
    public string Reason { get; } = reason;
}

/// <summary>
/// An authenticated, encrypted LAN session with a paired peer. Every frame is
/// {"sealed": base64(AES-GCM)} keyed from the pair secret, so a device that
/// copies a paired peer's broadcast id can neither read nor forge traffic.
/// </summary>
public sealed class SecureConnection(TcpClient client, BoundedLineReader reader, LineWriter writer, SecureChannel channel, string peerId)
    : IDisposable
{
    public string PeerId { get; } = peerId;

    public Task SendAsync(JsonObject message, CancellationToken ct = default) =>
        writer.WriteLineAsync(new JsonObject { ["sealed"] = channel.Seal(message.ToJsonString()) }.ToJsonString(), ct);

    /// <summary>
    /// Next authenticated message, or null when the peer closes. Throws
    /// <see cref="CryptographicException"/> for forged/replayed frames and
    /// <see cref="SessionRefusedException"/> for a plain-text refusal.
    /// </summary>
    public async Task<JsonObject?> ReceiveAsync(CancellationToken ct = default)
    {
        var line = await CcpWire.ReadLineWithTimeoutAsync(reader, ct).ConfigureAwait(false);
        if (line is null) return null;
        var frame = CcpWire.ParseObject(line);
        var sealedText = CcpWire.Str(frame["sealed"]);
        if (sealedText.Length == 0)
        {
            var reason = CcpWire.Str(CcpWire.Payload(frame)["reason"]);
            throw new SessionRefusedException(reason.Length > 0 ? reason : "unsealed_frame");
        }
        return CcpWire.ParseObject(channel.Open(sealedText));
    }

    public async Task<JsonObject> RequestAsync(JsonObject message, CancellationToken ct = default)
    {
        await SendAsync(message, ct).ConfigureAwait(false);
        return await ReceiveAsync(ct).ConfigureAwait(false) ?? throw new EndOfStreamException("Connection closed by peer");
    }

    /// <summary>Plain-text refusal for a peer whose frames failed to authenticate; reveals nothing secret.</summary>
    public async Task SendPlainErrorAsync(JsonObject self, string reason)
    {
        try
        {
            await writer.WriteLineAsync(CcpWire.Envelope("session.error", self, new JsonObject { ["reason"] = reason }).ToJsonString())
                .ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Best effort: the connection is being torn down anyway.
        }
    }

    public void Dispose() => client.Dispose();
}

/// <summary>session.hello / session.hello.response exchange that precedes every secure LAN session.</summary>
public static class LanHandshake
{
    public static async Task<SecureConnection> ClientAsync(TcpClient client, JsonObject self, string peerId, byte[] pairSecret, CancellationToken ct = default)
    {
        var stream = client.GetStream();
        var reader = new BoundedLineReader(stream);
        var writer = new LineWriter(stream);
        var clientNonce = CcpCrypto.RandomBytes(CcpWire.SessionNonceBytes);
        await writer.WriteLineAsync(CcpWire.Envelope("session.hello", self, new JsonObject
        {
            ["version"] = 1,
            ["nonce"] = CcpCrypto.B64(clientNonce),
        }).ToJsonString(), ct).ConfigureAwait(false);

        var line = await CcpWire.ReadLineWithTimeoutAsync(reader, ct).ConfigureAwait(false)
            ?? throw new EndOfStreamException("Connection closed during handshake");
        var response = CcpWire.ParseObject(line);
        var payload = CcpWire.Payload(response);
        if (CcpWire.Type(response) != "session.hello.response" || !CcpWire.Bool(payload["ok"]))
        {
            var reason = CcpWire.Str(payload["reason"]);
            throw new SessionRefusedException(reason.Length > 0 ? reason : "handshake_failed");
        }
        if (CcpWire.SenderId(response) != peerId) throw new SessionRefusedException("unexpected_peer");

        byte[] serverNonce;
        try { serverNonce = CcpCrypto.UnB64(CcpWire.Str(payload["nonce"])); }
        catch (FormatException) { throw new SessionRefusedException("bad_nonce"); }
        if (serverNonce.Length != CcpWire.SessionNonceBytes) throw new SessionRefusedException("bad_nonce");

        var selfId = CcpWire.Str(self["device_id"]);
        return new SecureConnection(client, reader, writer,
            SecureChannel.ForClient(pairSecret, selfId, peerId, clientNonce, serverNonce), peerId);
    }

    /// <summary>Answers a session.hello; returns null after refusing unpaired or malformed callers.</summary>
    public static async Task<SecureConnection?> ServerAsync(
        TcpClient client, BoundedLineReader reader, LineWriter writer, JsonObject self, JsonObject hello,
        Func<string, byte[]?> secretFor, CancellationToken ct = default)
    {
        var peerId = CcpWire.SenderId(hello);
        var secret = CcpIdentity.IsValidDeviceId(peerId) ? secretFor(peerId) : null;
        byte[]? clientNonce = null;
        try { clientNonce = CcpCrypto.UnB64(CcpWire.Str(CcpWire.Payload(hello)["nonce"])); }
        catch (FormatException) { }

        string? refusal = secret is null ? "not_paired"
            : clientNonce is not { Length: CcpWire.SessionNonceBytes } ? "bad_hello"
            : null;
        if (refusal is not null || secret is null || clientNonce is null)
        {
            await writer.WriteLineAsync(CcpWire.Envelope("session.hello.response", self, new JsonObject
            {
                ["ok"] = false,
                ["reason"] = refusal ?? "bad_hello",
            }).ToJsonString(), ct).ConfigureAwait(false);
            return null;
        }

        var serverNonce = CcpCrypto.RandomBytes(CcpWire.SessionNonceBytes);
        await writer.WriteLineAsync(CcpWire.Envelope("session.hello.response", self, new JsonObject
        {
            ["ok"] = true,
            ["version"] = 1,
            ["nonce"] = CcpCrypto.B64(serverNonce),
        }).ToJsonString(), ct).ConfigureAwait(false);

        var selfId = CcpWire.Str(self["device_id"]);
        return new SecureConnection(client, reader, writer,
            SecureChannel.ForServer(secret, peerId, selfId, clientNonce, serverNonce), peerId);
    }
}
