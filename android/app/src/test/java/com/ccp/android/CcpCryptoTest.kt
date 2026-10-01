package com.ccp.android

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/** Verifies the Kotlin crypto against vectors generated independently with Node. */
class CcpCryptoTest {
    private val vectors: JSONObject by lazy { JSONObject(locateVectors().readText()) }

    private fun locateVectors(): File {
        var dir: File? = File(System.getProperty("user.dir")).absoluteFile
        while (dir != null) {
            val candidate = File(dir, "shared/test-vectors/ccp-crypto-v1.json")
            if (candidate.isFile) return candidate
            dir = dir.parentFile
        }
        error("shared/test-vectors/ccp-crypto-v1.json not found")
    }

    @Test
    fun hkdfMatchesVectors() {
        val cases = vectors.getJSONArray("hkdf")
        for (i in 0 until cases.length()) {
            val c = cases.getJSONObject(i)
            val okm = CcpCrypto.hkdf(
                CcpCrypto.unhex(c.getString("ikm_hex")),
                CcpCrypto.unhex(c.getString("salt_hex")),
                c.getString("info"),
                c.getInt("length"),
            )
            assertEquals(c.getString("okm_hex"), CcpCrypto.hex(okm))
        }
    }

    @Test
    fun ecdhMatchesVectorsBothWays() {
        val e = vectors.getJSONObject("ecdh")
        val a = CcpCrypto.decodePrivateKey(CcpCrypto.unb64(e.getString("a_pkcs8_b64")))
        val b = CcpCrypto.decodePrivateKey(CcpCrypto.unb64(e.getString("b_pkcs8_b64")))
        assertEquals(e.getString("shared_hex"), CcpCrypto.hex(CcpCrypto.ecdh(a, CcpCrypto.unb64(e.getString("b_spki_b64")))))
        assertEquals(e.getString("shared_hex"), CcpCrypto.hex(CcpCrypto.ecdh(b, CcpCrypto.unb64(e.getString("a_spki_b64")))))
    }

    @Test
    fun freshKeyPairsAgree() {
        val a = CcpCrypto.generateEcKeyPair()
        val b = CcpCrypto.generateEcKeyPair()
        val ab = CcpCrypto.ecdh(a.private, CcpCrypto.encodePublicKey(b.public))
        val ba = CcpCrypto.ecdh(b.private, CcpCrypto.encodePublicKey(a.public))
        assertArrayEquals(ab, ba)
        assertEquals(32, ab.size)
    }

    @Test
    fun pairingMatchesVectors() {
        val p = vectors.getJSONObject("pairing")
        val pubI = CcpCrypto.unb64(p.getString("initiator_pub_b64"))
        val pubR = CcpCrypto.unb64(p.getString("responder_pub_b64"))
        val nI = CcpCrypto.unb64(p.getString("initiator_nonce_b64"))
        val nR = CcpCrypto.unb64(p.getString("responder_nonce_b64"))

        assertEquals(p.getString("commitment_hex"), CcpPairing.commitment(pubI, nI))
        assertTrue(CcpPairing.verifyCommitment(p.getString("commitment_hex"), pubI, nI))
        assertFalse(CcpPairing.verifyCommitment(p.getString("commitment_hex"), pubI, nR))

        val result = CcpPairing.derive(
            CcpCrypto.unhex(p.getString("shared_hex")),
            p.getString("initiator_id"), p.getString("responder_id"),
            pubI, pubR, nI, nR,
        )
        assertEquals(p.getString("transcript_hash_hex"), CcpCrypto.hex(result.transcriptHash))
        assertEquals(p.getString("pair_secret_b64"), CcpCrypto.b64(result.pairSecret))
        assertEquals(p.getString("sas"), result.sas)
        assertEquals(p.getString("responder_confirm_b64"), CcpCrypto.b64(result.responderConfirm()))
        assertTrue(result.verifyResponderConfirm(p.getString("responder_confirm_b64")))
        assertFalse(result.verifyResponderConfirm(CcpCrypto.b64(ByteArray(32))))
        assertFalse(result.verifyResponderConfirm("not base64!"))
    }

    @Test
    fun pairingCodeChangesWithAnyTranscriptField() {
        val p = vectors.getJSONObject("pairing")
        val base = CcpPairing.derive(
            CcpCrypto.unhex(p.getString("shared_hex")),
            p.getString("initiator_id"), p.getString("responder_id"),
            CcpCrypto.unb64(p.getString("initiator_pub_b64")), CcpCrypto.unb64(p.getString("responder_pub_b64")),
            CcpCrypto.unb64(p.getString("initiator_nonce_b64")), CcpCrypto.unb64(p.getString("responder_nonce_b64")),
        )
        val swapped = CcpPairing.derive(
            CcpCrypto.unhex(p.getString("shared_hex")),
            p.getString("responder_id"), p.getString("initiator_id"),
            CcpCrypto.unb64(p.getString("initiator_pub_b64")), CcpCrypto.unb64(p.getString("responder_pub_b64")),
            CcpCrypto.unb64(p.getString("initiator_nonce_b64")), CcpCrypto.unb64(p.getString("responder_nonce_b64")),
        )
        assertFalse(base.pairSecret.contentEquals(swapped.pairSecret))
    }

    @Test
    fun lanChannelMatchesVectors() {
        val l = vectors.getJSONObject("lan_channel")
        val secret = CcpCrypto.unb64(l.getString("pair_secret_b64"))
        val cn = CcpCrypto.unb64(l.getString("client_nonce_b64"))
        val sn = CcpCrypto.unb64(l.getString("server_nonce_b64"))
        val (c2s, s2c) = SecureChannel.keys(secret, l.getString("client_id"), l.getString("server_id"), cn, sn)
        assertEquals(l.getString("c2s_key_hex"), CcpCrypto.hex(c2s))
        assertEquals(l.getString("s2c_key_hex"), CcpCrypto.hex(s2c))

        val client = SecureChannel.forClient(secret, l.getString("client_id"), l.getString("server_id"), cn, sn)
        val server = SecureChannel.forServer(secret, l.getString("client_id"), l.getString("server_id"), cn, sn)
        val frames = l.getJSONArray("frames")
        for (i in 0 until frames.length()) {
            val f = frames.getJSONObject(i)
            if (f.getString("direction") == "c2s") {
                assertEquals(f.getString("sealed_b64"), client.seal(f.getString("plaintext")))
                assertEquals(f.getString("plaintext"), server.open(f.getString("sealed_b64")))
            } else {
                assertEquals(f.getString("sealed_b64"), server.seal(f.getString("plaintext")))
                assertEquals(f.getString("plaintext"), client.open(f.getString("sealed_b64")))
            }
        }
    }

    @Test
    fun lanChannelRejectsReplayAndTampering() {
        val secret = CcpCrypto.randomBytes(32)
        val cn = CcpCrypto.randomBytes(16)
        val sn = CcpCrypto.randomBytes(16)
        val client = SecureChannel.forClient(secret, "c", "s", cn, sn)
        val server = SecureChannel.forServer(secret, "c", "s", cn, sn)

        val first = client.seal("one")
        assertEquals("one", server.open(first))
        expectFailure { server.open(first) } // replay

        val second = client.seal("two")
        val tampered = CcpCrypto.unb64(second).also { it[0] = (it[0].toInt() xor 1).toByte() }
        expectFailure { server.open(CcpCrypto.b64(tampered)) }

        // A different pair secret can't open frames.
        val stranger = SecureChannel.forServer(CcpCrypto.randomBytes(32), "c", "s", cn, sn)
        expectFailure { stranger.open(client.seal("three")) }
    }

    @Test
    fun cloudKeysMatchVectors() {
        val c = vectors.getJSONObject("cloud")
        val secret = CcpCrypto.unb64(c.getString("pair_secret_b64"))
        val a = c.getString("device_a")
        val b = c.getString("device_b")
        val key = CcpCloudKeys.cloudKey(secret, b, a) // order must not matter
        assertEquals(c.getString("cloud_key_hex"), CcpCrypto.hex(key))
        assertEquals(c.getString("wrap_key_hex"), CcpCrypto.hex(CcpCloudKeys.wrapKey(secret, a, b)))
        assertEquals(c.getString("fingerprint_hex"), CcpCloudKeys.fingerprint(key))

        val m = c.getJSONObject("message")
        val aad = CcpCloudKeys.messageAad(m.getString("sender_id"), m.getString("recipient_id"), m.getString("msg_type"), m.getString("msg_id"))
        assertEquals(m.getString("aad"), String(aad, Charsets.UTF_8))
        val nonce = CcpCrypto.unb64(m.getString("nonce_b64"))
        assertEquals(m.getString("ciphertext_b64"), CcpCrypto.b64(CcpCrypto.seal(key, nonce, aad, m.getString("plaintext").toByteArray())))

        // Re-labelling the message type breaks authentication.
        val wrongAad = CcpCloudKeys.messageAad(m.getString("sender_id"), m.getString("recipient_id"), "file.offer", m.getString("msg_id"))
        expectFailure { CcpCrypto.open(key, nonce, wrongAad, CcpCrypto.unb64(m.getString("ciphertext_b64"))) }
    }

    @Test
    fun deviceIdIsBoundToToken() {
        val d = vectors.getJSONObject("device_id")
        assertEquals(d.getString("device_id"), PeerStore.deriveDeviceId(d.getString("auth_token")))
        assertNotEquals(d.getString("device_id"), PeerStore.deriveDeviceId(d.getString("auth_token") + "x"))
        assertTrue(isValidDeviceId(d.getString("device_id")))
    }

    private fun expectFailure(block: () -> Unit) {
        try {
            block()
            fail("expected failure")
        } catch (_: Exception) {
        }
    }
}
