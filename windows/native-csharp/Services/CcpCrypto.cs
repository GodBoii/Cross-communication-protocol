using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace CCP.Windows.Services;

/// <summary>
/// CCP v1 cryptography, byte-compatible with the Android client
/// (CcpCrypto.kt) and verified against shared/test-vectors/ccp-crypto-v1.json.
/// This file has no WPF dependencies so the test project can link it directly.
/// </summary>
public static class CcpCrypto
{
    public static byte[] RandomBytes(int length) => RandomNumberGenerator.GetBytes(length);

    public static string B64(byte[] bytes) => Convert.ToBase64String(bytes);

    public static byte[] UnB64(string text) => Convert.FromBase64String(text);

    public static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    public static byte[] UnHex(string text) => Convert.FromHexString(text);

    public static byte[] Sha256(byte[] data) => SHA256.HashData(data);

    public static byte[] Sha256(string text) => SHA256.HashData(Encoding.UTF8.GetBytes(text));

    public static byte[] HmacSha256(byte[] key, byte[] data) => HMACSHA256.HashData(key, data);

    /// <summary>RFC 5869 HKDF-SHA256. An empty salt is equivalent to 32 zero bytes.</summary>
    public static byte[] Hkdf(byte[] ikm, byte[] salt, string info, int length) =>
        HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm, length,
            salt.Length == 0 ? new byte[32] : salt, Encoding.UTF8.GetBytes(info));

    public static bool ConstantTimeEquals(byte[] a, byte[] b) => CryptographicOperations.FixedTimeEquals(a, b);

    /// <summary>AES-256-GCM; returns ciphertext || 16-byte tag.</summary>
    public static byte[] Seal(byte[] key, byte[] nonce, byte[] aad, byte[] plaintext)
    {
        var output = new byte[plaintext.Length + 16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, output.AsSpan(0, plaintext.Length), output.AsSpan(plaintext.Length), aad);
        return output;
    }

    /// <summary>Throws <see cref="CryptographicException"/> if authentication fails.</summary>
    public static byte[] Open(byte[] key, byte[] nonce, byte[] aad, byte[] sealedData)
    {
        if (sealedData.Length < 16) throw new CryptographicException("sealed data too short");
        var plaintext = new byte[sealedData.Length - 16];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, sealedData.AsSpan(0, plaintext.Length), sealedData.AsSpan(plaintext.Length), plaintext, aad);
        return plaintext;
    }

    public static ECDiffieHellman GenerateEcKey() => ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);

    /// <summary>X.509 SubjectPublicKeyInfo DER.</summary>
    public static byte[] EncodePublicKey(ECDiffieHellman key) => key.ExportSubjectPublicKeyInfo();

    public static ECDiffieHellman ImportPrivateKey(byte[] pkcs8)
    {
        var key = ECDiffieHellman.Create();
        key.ImportPkcs8PrivateKey(pkcs8, out _);
        return key;
    }

    /// <summary>Raw shared secret (affine x-coordinate, 32 bytes).</summary>
    public static byte[] Ecdh(ECDiffieHellman privateKey, byte[] peerSpki)
    {
        using var peer = ECDiffieHellman.Create();
        peer.ImportSubjectPublicKeyInfo(peerSpki, out _);
        if (peer.KeySize != 256) throw new CryptographicException("peer key is not P-256");
        return privateKey.DeriveRawSecretAgreement(peer.PublicKey);
    }
}

/// <summary>Numeric-comparison pairing with commitment. See CcpPairing in CcpCrypto.kt.</summary>
public static class CcpPairing
{
    public const int Version = 1;

    public sealed record Result(byte[] PairSecret, string Sas, byte[] ConfirmKey, byte[] TranscriptHash)
    {
        public byte[] ResponderConfirm() => CcpCrypto.HmacSha256(ConfirmKey, "responder"u8.ToArray());

        public bool VerifyResponderConfirm(string? confirmB64)
        {
            if (string.IsNullOrWhiteSpace(confirmB64)) return false;
            try
            {
                return CcpCrypto.ConstantTimeEquals(CcpCrypto.UnB64(confirmB64), ResponderConfirm());
            }
            catch (FormatException)
            {
                return false;
            }
        }
    }

    public static string Commitment(byte[] initiatorPub, byte[] initiatorNonce) =>
        CcpCrypto.Hex(CcpCrypto.Sha256($"ccp-pair-commit-v1|{CcpCrypto.B64(initiatorPub)}|{CcpCrypto.B64(initiatorNonce)}"));

    public static bool VerifyCommitment(string commitmentHex, byte[] initiatorPub, byte[] initiatorNonce) =>
        CcpCrypto.ConstantTimeEquals(
            Encoding.ASCII.GetBytes(commitmentHex.ToLowerInvariant()),
            Encoding.ASCII.GetBytes(Commitment(initiatorPub, initiatorNonce)));

    public static Result Derive(
        byte[] sharedSecret,
        string initiatorId,
        string responderId,
        byte[] initiatorPub,
        byte[] responderPub,
        byte[] initiatorNonce,
        byte[] responderNonce)
    {
        var transcript = CcpCrypto.Sha256(
            $"ccp-pair-v1|{initiatorId}|{responderId}|" +
            $"{CcpCrypto.B64(initiatorPub)}|{CcpCrypto.B64(responderPub)}|" +
            $"{CcpCrypto.B64(initiatorNonce)}|{CcpCrypto.B64(responderNonce)}");
        var pairSecret = CcpCrypto.Hkdf(sharedSecret, transcript, "ccp-pair-secret-v1", 32);
        var sasValue = BinaryPrimitives.ReadUInt32BigEndian(CcpCrypto.Hkdf(sharedSecret, transcript, "ccp-pair-sas-v1", 4)) % 1_000_000u;
        var confirmKey = CcpCrypto.Hkdf(sharedSecret, transcript, "ccp-pair-confirm-v1", 32);
        return new Result(pairSecret, sasValue.ToString("D6"), confirmKey, transcript);
    }
}

/// <summary>Encrypted, authenticated, replay-protected LAN framing. See SecureChannel in CcpCrypto.kt.</summary>
public sealed class SecureChannel
{
    private readonly byte[] _sendKey;
    private readonly byte[] _receiveKey;
    private readonly string _sendLabel;
    private readonly string _receiveLabel;
    private readonly object _sendLock = new();
    private readonly object _receiveLock = new();
    private long _sendCounter;
    private long _receiveCounter;

    private SecureChannel(byte[] sendKey, byte[] receiveKey, string sendLabel, string receiveLabel)
    {
        _sendKey = sendKey;
        _receiveKey = receiveKey;
        _sendLabel = sendLabel;
        _receiveLabel = receiveLabel;
    }

    public string Seal(string plaintext)
    {
        lock (_sendLock)
        {
            var counter = _sendCounter++;
            return CcpCrypto.B64(CcpCrypto.Seal(_sendKey, Nonce(counter), Aad(_sendLabel, counter), Encoding.UTF8.GetBytes(plaintext)));
        }
    }

    /// <summary>Throws if the frame was forged, replayed or reordered.</summary>
    public string Open(string sealedB64)
    {
        lock (_receiveLock)
        {
            var counter = _receiveCounter;
            var plain = CcpCrypto.Open(_receiveKey, Nonce(counter), Aad(_receiveLabel, counter), CcpCrypto.UnB64(sealedB64));
            _receiveCounter++;
            return Encoding.UTF8.GetString(plain);
        }
    }

    public static (byte[] C2S, byte[] S2C) Keys(byte[] pairSecret, string clientId, string serverId, byte[] clientNonce, byte[] serverNonce)
    {
        var salt = CcpCrypto.Sha256($"ccp-lan-v1|{clientId}|{serverId}|{CcpCrypto.B64(clientNonce)}|{CcpCrypto.B64(serverNonce)}");
        return (CcpCrypto.Hkdf(pairSecret, salt, "ccp-lan-c2s-v1", 32), CcpCrypto.Hkdf(pairSecret, salt, "ccp-lan-s2c-v1", 32));
    }

    public static SecureChannel ForClient(byte[] pairSecret, string clientId, string serverId, byte[] clientNonce, byte[] serverNonce)
    {
        var (c2s, s2c) = Keys(pairSecret, clientId, serverId, clientNonce, serverNonce);
        return new SecureChannel(c2s, s2c, "c2s", "s2c");
    }

    public static SecureChannel ForServer(byte[] pairSecret, string clientId, string serverId, byte[] clientNonce, byte[] serverNonce)
    {
        var (c2s, s2c) = Keys(pairSecret, clientId, serverId, clientNonce, serverNonce);
        return new SecureChannel(s2c, c2s, "s2c", "c2s");
    }

    public static byte[] Nonce(long counter)
    {
        var nonce = new byte[12];
        BinaryPrimitives.WriteInt64BigEndian(nonce.AsSpan(4), counter);
        return nonce;
    }

    public static byte[] Aad(string direction, long counter) =>
        Encoding.UTF8.GetBytes($"ccp-lan-frame-v1|{direction}|{counter}");
}

/// <summary>Cloud relay key schedule shared with Android.</summary>
public static class CcpCloudKeys
{
    private static (string A, string B) Ordered(string a, string b) =>
        string.CompareOrdinal(a, b) < 0 ? (a, b) : (b, a);

    public static byte[] CloudKey(byte[] pairSecret, string deviceA, string deviceB)
    {
        var (a, b) = Ordered(deviceA, deviceB);
        return CcpCrypto.Hkdf(pairSecret, [], $"ccp-cloud-key-v1|{a}|{b}", 32);
    }

    public static byte[] WrapKey(byte[] pairSecret, string deviceA, string deviceB)
    {
        var (a, b) = Ordered(deviceA, deviceB);
        return CcpCrypto.Hkdf(pairSecret, [], $"ccp-cloud-wrap-v1|{a}|{b}", 32);
    }

    public static string Fingerprint(byte[] cloudKey) => CcpCrypto.Hex(CcpCrypto.Sha256(cloudKey));

    public static byte[] MessageAad(string senderId, string recipientId, string msgType, string msgId) =>
        Encoding.UTF8.GetBytes($"ccp-cloud-msg-v1|{senderId}|{recipientId}|{msgType}|{msgId}");
}

/// <summary>Device identity derivation shared with Android and Convex.</summary>
public static class CcpIdentity
{
    public const string DeviceIdPrefix = "ccp-device-id-v1:";

    public static string DeriveDeviceId(string cloudAuthToken)
    {
        var tokenHash = CcpCrypto.Hex(CcpCrypto.Sha256(cloudAuthToken));
        return CcpCrypto.Hex(CcpCrypto.Sha256(DeviceIdPrefix + tokenHash));
    }

    public static bool IsValidDeviceId(string? value) =>
        value is { Length: 64 } && value.All(c => c is (>= '0' and <= '9') or (>= 'a' and <= 'f'));
}
