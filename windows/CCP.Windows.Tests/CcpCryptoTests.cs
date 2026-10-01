using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using CCP.Windows.Services;
using Xunit;

namespace CCP.Windows.Tests;

/// <summary>Verifies the C# crypto against vectors generated independently with Node.</summary>
public class CcpCryptoTests
{
    private static readonly JsonObject Vectors = LoadVectors();

    private static JsonObject LoadVectors()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            var candidate = Path.Combine(dir.FullName, "shared", "test-vectors", "ccp-crypto-v1.json");
            if (File.Exists(candidate)) return JsonNode.Parse(File.ReadAllText(candidate))!.AsObject();
            dir = dir.Parent;
        }
        throw new FileNotFoundException("shared/test-vectors/ccp-crypto-v1.json not found");
    }

    private static string S(JsonNode? node, string key) => node![key]!.GetValue<string>();

    [Fact]
    public void HkdfMatchesVectors()
    {
        foreach (var c in Vectors["hkdf"]!.AsArray())
        {
            var okm = CcpCrypto.Hkdf(CcpCrypto.UnHex(S(c, "ikm_hex")), CcpCrypto.UnHex(S(c, "salt_hex")),
                S(c, "info"), c!["length"]!.GetValue<int>());
            Assert.Equal(S(c, "okm_hex"), CcpCrypto.Hex(okm));
        }
    }

    [Fact]
    public void EcdhMatchesVectorsBothWays()
    {
        var e = Vectors["ecdh"];
        using var a = CcpCrypto.ImportPrivateKey(CcpCrypto.UnB64(S(e, "a_pkcs8_b64")));
        using var b = CcpCrypto.ImportPrivateKey(CcpCrypto.UnB64(S(e, "b_pkcs8_b64")));
        Assert.Equal(S(e, "shared_hex"), CcpCrypto.Hex(CcpCrypto.Ecdh(a, CcpCrypto.UnB64(S(e, "b_spki_b64")))));
        Assert.Equal(S(e, "shared_hex"), CcpCrypto.Hex(CcpCrypto.Ecdh(b, CcpCrypto.UnB64(S(e, "a_spki_b64")))));
    }

    [Fact]
    public void FreshKeysAgreeAndEncodeAsSpki()
    {
        using var a = CcpCrypto.GenerateEcKey();
        using var b = CcpCrypto.GenerateEcKey();
        var ab = CcpCrypto.Ecdh(a, CcpCrypto.EncodePublicKey(b));
        var ba = CcpCrypto.Ecdh(b, CcpCrypto.EncodePublicKey(a));
        Assert.Equal(ab, ba);
        Assert.Equal(32, ab.Length);
        Assert.Equal(91, CcpCrypto.EncodePublicKey(a).Length); // P-256 SPKI DER
    }

    [Fact]
    public void PairingMatchesVectors()
    {
        var p = Vectors["pairing"];
        var pubI = CcpCrypto.UnB64(S(p, "initiator_pub_b64"));
        var pubR = CcpCrypto.UnB64(S(p, "responder_pub_b64"));
        var nI = CcpCrypto.UnB64(S(p, "initiator_nonce_b64"));
        var nR = CcpCrypto.UnB64(S(p, "responder_nonce_b64"));

        Assert.Equal(S(p, "commitment_hex"), CcpPairing.Commitment(pubI, nI));
        Assert.True(CcpPairing.VerifyCommitment(S(p, "commitment_hex"), pubI, nI));
        Assert.False(CcpPairing.VerifyCommitment(S(p, "commitment_hex"), pubI, nR));

        var result = CcpPairing.Derive(CcpCrypto.UnHex(S(p, "shared_hex")),
            S(p, "initiator_id"), S(p, "responder_id"), pubI, pubR, nI, nR);
        Assert.Equal(S(p, "transcript_hash_hex"), CcpCrypto.Hex(result.TranscriptHash));
        Assert.Equal(S(p, "pair_secret_b64"), CcpCrypto.B64(result.PairSecret));
        Assert.Equal(S(p, "sas"), result.Sas);
        Assert.Equal(S(p, "responder_confirm_b64"), CcpCrypto.B64(result.ResponderConfirm()));
        Assert.True(result.VerifyResponderConfirm(S(p, "responder_confirm_b64")));
        Assert.False(result.VerifyResponderConfirm(CcpCrypto.B64(new byte[32])));
        Assert.False(result.VerifyResponderConfirm("not base64!"));
    }

    [Fact]
    public void LanChannelMatchesVectors()
    {
        var l = Vectors["lan_channel"];
        var secret = CcpCrypto.UnB64(S(l, "pair_secret_b64"));
        var cn = CcpCrypto.UnB64(S(l, "client_nonce_b64"));
        var sn = CcpCrypto.UnB64(S(l, "server_nonce_b64"));
        var (c2s, s2c) = SecureChannel.Keys(secret, S(l, "client_id"), S(l, "server_id"), cn, sn);
        Assert.Equal(S(l, "c2s_key_hex"), CcpCrypto.Hex(c2s));
        Assert.Equal(S(l, "s2c_key_hex"), CcpCrypto.Hex(s2c));

        var client = SecureChannel.ForClient(secret, S(l, "client_id"), S(l, "server_id"), cn, sn);
        var server = SecureChannel.ForServer(secret, S(l, "client_id"), S(l, "server_id"), cn, sn);
        foreach (var f in l!["frames"]!.AsArray())
        {
            if (S(f, "direction") == "c2s")
            {
                Assert.Equal(S(f, "sealed_b64"), client.Seal(S(f, "plaintext")));
                Assert.Equal(S(f, "plaintext"), server.Open(S(f, "sealed_b64")));
            }
            else
            {
                Assert.Equal(S(f, "sealed_b64"), server.Seal(S(f, "plaintext")));
                Assert.Equal(S(f, "plaintext"), client.Open(S(f, "sealed_b64")));
            }
        }
    }

    [Fact]
    public void LanChannelRejectsReplayTamperingAndStrangers()
    {
        var secret = CcpCrypto.RandomBytes(32);
        var cn = CcpCrypto.RandomBytes(16);
        var sn = CcpCrypto.RandomBytes(16);
        var client = SecureChannel.ForClient(secret, "c", "s", cn, sn);
        var server = SecureChannel.ForServer(secret, "c", "s", cn, sn);

        var first = client.Seal("one");
        Assert.Equal("one", server.Open(first));
        Assert.ThrowsAny<CryptographicException>(() => server.Open(first));

        var tampered = CcpCrypto.UnB64(client.Seal("two"));
        tampered[0] ^= 1;
        Assert.ThrowsAny<CryptographicException>(() => server.Open(CcpCrypto.B64(tampered)));

        var stranger = SecureChannel.ForServer(CcpCrypto.RandomBytes(32), "c", "s", cn, sn);
        Assert.ThrowsAny<CryptographicException>(() => stranger.Open(client.Seal("three")));
    }

    [Fact]
    public void CloudKeysMatchVectors()
    {
        var c = Vectors["cloud"];
        var secret = CcpCrypto.UnB64(S(c, "pair_secret_b64"));
        var key = CcpCloudKeys.CloudKey(secret, S(c, "device_b"), S(c, "device_a"));
        Assert.Equal(S(c, "cloud_key_hex"), CcpCrypto.Hex(key));
        Assert.Equal(S(c, "wrap_key_hex"), CcpCrypto.Hex(CcpCloudKeys.WrapKey(secret, S(c, "device_a"), S(c, "device_b"))));
        Assert.Equal(S(c, "fingerprint_hex"), CcpCloudKeys.Fingerprint(key));

        var m = c!["message"];
        var aad = CcpCloudKeys.MessageAad(S(m, "sender_id"), S(m, "recipient_id"), S(m, "msg_type"), S(m, "msg_id"));
        Assert.Equal(S(m, "aad"), Encoding.UTF8.GetString(aad));
        var nonce = CcpCrypto.UnB64(S(m, "nonce_b64"));
        Assert.Equal(S(m, "ciphertext_b64"),
            CcpCrypto.B64(CcpCrypto.Seal(key, nonce, aad, Encoding.UTF8.GetBytes(S(m, "plaintext")))));

        var wrongAad = CcpCloudKeys.MessageAad(S(m, "sender_id"), S(m, "recipient_id"), "file.offer", S(m, "msg_id"));
        Assert.ThrowsAny<CryptographicException>(() =>
            CcpCrypto.Open(key, nonce, wrongAad, CcpCrypto.UnB64(S(m, "ciphertext_b64"))));
    }

    [Fact]
    public void DeviceIdIsBoundToToken()
    {
        var d = Vectors["device_id"];
        Assert.Equal(S(d, "device_id"), CcpIdentity.DeriveDeviceId(S(d, "auth_token")));
        Assert.NotEqual(S(d, "device_id"), CcpIdentity.DeriveDeviceId(S(d, "auth_token") + "x"));
        Assert.True(CcpIdentity.IsValidDeviceId(S(d, "device_id")));
        Assert.False(CcpIdentity.IsValidDeviceId("ABC"));
        Assert.False(CcpIdentity.IsValidDeviceId(S(d, "device_id").ToUpperInvariant()));
    }
}
