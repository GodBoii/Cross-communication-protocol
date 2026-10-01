using System.Security.Cryptography;
using System.Text.Json.Nodes;

namespace CCP.Windows.Services;

/// <summary>Validation failure during pairing; <see cref="Exception.Message"/> is the reason code sent to the peer.</summary>
public sealed class PairingException(string reason) : Exception(reason);

internal static class PairingFields
{
    private const int MaxPublicKeyB64 = 256;

    public static byte[] PublicKey(JsonObject payload)
    {
        var text = CcpWire.Str(payload["ephemeral_pub"]);
        if (text.Length == 0 || text.Length > MaxPublicKeyB64) throw new PairingException("invalid_ephemeral_pub");
        try { return CcpCrypto.UnB64(text); }
        catch (FormatException) { throw new PairingException("invalid_ephemeral_pub"); }
    }

    public static byte[] Nonce(JsonObject payload)
    {
        try
        {
            var nonce = CcpCrypto.UnB64(CcpWire.Str(payload["nonce"]));
            if (nonce.Length != CcpWire.SessionNonceBytes) throw new PairingException("invalid_nonce");
            return nonce;
        }
        catch (FormatException)
        {
            throw new PairingException("invalid_nonce");
        }
    }

    public static byte[] Agree(ECDiffieHellman key, byte[] peerPublicKey)
    {
        try { return CcpCrypto.Ecdh(key, peerPublicKey); }
        catch (CryptographicException) { throw new PairingException("invalid_ephemeral_pub"); }
    }
}

/// <summary>Initiator side of v1 pairing (see CcpPairing). The P-256 key lives only for this attempt.</summary>
public sealed class PairingInitiator(string selfId) : IDisposable
{
    private readonly ECDiffieHellman _key = CcpCrypto.GenerateEcKey();
    private readonly byte[] _nonce = CcpCrypto.RandomBytes(CcpWire.SessionNonceBytes);
    private byte[] PublicKey => CcpCrypto.EncodePublicKey(_key);

    public JsonObject RequestPayload() => new()
    {
        ["version"] = CcpPairing.Version,
        ["commitment"] = CcpPairing.Commitment(PublicKey, _nonce),
    };

    public JsonObject RevealPayload() => new()
    {
        ["ephemeral_pub"] = CcpCrypto.B64(PublicKey),
        ["nonce"] = CcpCrypto.B64(_nonce),
    };

    public CcpPairing.Result OnChallenge(string responderId, JsonObject payload)
    {
        var peerPublicKey = PairingFields.PublicKey(payload);
        var peerNonce = PairingFields.Nonce(payload);
        var shared = PairingFields.Agree(_key, peerPublicKey);
        return CcpPairing.Derive(shared, selfId, responderId, PublicKey, peerPublicKey, _nonce, peerNonce);
    }

    public void Dispose() => _key.Dispose();
}

/// <summary>
/// Responder side of v1 pairing. The constructor validates pair.request;
/// <see cref="OnReveal"/> checks the commitment before deriving anything.
/// </summary>
public sealed class PairingResponder : IDisposable
{
    private readonly string _selfId;
    private readonly string _initiatorId;
    private readonly string _commitment;
    private readonly ECDiffieHellman _key = CcpCrypto.GenerateEcKey();
    private readonly byte[] _nonce = CcpCrypto.RandomBytes(CcpWire.SessionNonceBytes);

    public PairingResponder(string selfId, string initiatorId, JsonObject request)
    {
        _selfId = selfId;
        _initiatorId = initiatorId;
        if (CcpWire.Long(request["version"], 0) != CcpPairing.Version) throw new PairingException("unsupported_pairing_version");
        _commitment = CcpWire.Str(request["commitment"]).ToLowerInvariant();
        if (!CcpIdentity.IsValidDeviceId(_commitment)) throw new PairingException("invalid_commitment"); // same 64-hex shape
    }

    private byte[] PublicKey => CcpCrypto.EncodePublicKey(_key);

    public JsonObject ChallengePayload() => new()
    {
        ["ephemeral_pub"] = CcpCrypto.B64(PublicKey),
        ["nonce"] = CcpCrypto.B64(_nonce),
    };

    public CcpPairing.Result OnReveal(JsonObject payload)
    {
        var peerPublicKey = PairingFields.PublicKey(payload);
        var peerNonce = PairingFields.Nonce(payload);
        if (!CcpPairing.VerifyCommitment(_commitment, peerPublicKey, peerNonce)) throw new PairingException("commitment_mismatch");
        var shared = PairingFields.Agree(_key, peerPublicKey);
        return CcpPairing.Derive(shared, _initiatorId, _selfId, peerPublicKey, PublicKey, peerNonce, _nonce);
    }

    public void Dispose() => _key.Dispose();
}
