package com.ccp.android

import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * CCP v1 cryptography. Pure JVM (no android.* imports) so it runs in local
 * unit tests against shared/test-vectors/ccp-crypto-v1.json, which is also
 * verified by the Windows client and generated independently with Node.
 *
 * See shared/protocol/ccp-v1.md for the construction.
 */
object CcpCrypto {
    private val random = SecureRandom()

    fun randomBytes(length: Int): ByteArray = ByteArray(length).also { random.nextBytes(it) }

    fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)

    fun unb64(text: String): ByteArray = Base64.getDecoder().decode(text)

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    fun unhex(text: String): ByteArray =
        ByteArray(text.length / 2) { i -> text.substring(i * 2, i * 2 + 2).toInt(16).toByte() }

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    fun sha256(text: String): ByteArray = sha256(text.toByteArray(Charsets.UTF_8))

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        // HMAC zero-pads keys to the block size, so an empty key equals a
        // 32-byte zero key; javax rejects empty keys outright.
        mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /** RFC 5869 HKDF-SHA256. */
    fun hkdf(ikm: ByteArray, salt: ByteArray, info: String, length: Int): ByteArray {
        require(length in 1..(255 * 32)) { "invalid HKDF length" }
        val prk = hmacSha256(salt, ikm)
        val infoBytes = info.toByteArray(Charsets.UTF_8)
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            previous = hmacSha256(prk, previous + infoBytes + byteArrayOf(counter.toByte()))
            val take = minOf(previous.size, length - offset)
            System.arraycopy(previous, 0, out, offset, take)
            offset += take
            counter++
        }
        return out
    }

    /** Constant-time equality. */
    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    // ── AES-256-GCM (ciphertext || 16-byte tag) ────────────────────────────

    fun seal(key: ByteArray, nonce: ByteArray, aad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plaintext)
    }

    fun open(key: ByteArray, nonce: ByteArray, aad: ByteArray, sealed: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(sealed)
    }

    // ── ECDH P-256 ─────────────────────────────────────────────────────────

    fun generateEcKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1"), random) }
            .generateKeyPair()

    /** X.509 SubjectPublicKeyInfo DER. */
    fun encodePublicKey(key: PublicKey): ByteArray = key.encoded

    fun decodePublicKey(spki: ByteArray): PublicKey =
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))

    fun decodePrivateKey(pkcs8: ByteArray): PrivateKey =
        KeyFactory.getInstance("EC").generatePrivate(PKCS8EncodedKeySpec(pkcs8))

    /** Raw shared secret (affine x-coordinate, 32 bytes). */
    fun ecdh(privateKey: PrivateKey, peerSpki: ByteArray): ByteArray {
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(privateKey)
        agreement.doPhase(decodePublicKey(peerSpki), true)
        return agreement.generateSecret()
    }
}

/**
 * Pairing math (numeric comparison with commitment, like Bluetooth SSP):
 *
 *   I → R  pair.request   { commitment = H(pubI, nI) }
 *   R → I  pair.challenge { pubR, nR }
 *   I → R  pair.reveal    { pubI, nI }        R checks the commitment
 *   both   Z = ECDH, show the same 6-digit code; R's user approves
 *   R → I  pair.response  { accepted, confirm = HMAC(kc, "responder") }
 *
 * The commitment stops a man-in-the-middle from choosing a key after seeing
 * the peer's, so a MITM matches the codes with probability 1e-6.
 */
object CcpPairing {
    const val VERSION = 1

    data class Result(
        val pairSecret: ByteArray,
        val sas: String,
        val confirmKey: ByteArray,
        val transcriptHash: ByteArray,
    ) {
        fun responderConfirm(): ByteArray =
            CcpCrypto.hmacSha256(confirmKey, "responder".toByteArray(Charsets.UTF_8))

        fun verifyResponderConfirm(confirmB64: String?): Boolean {
            if (confirmB64.isNullOrBlank()) return false
            val received = runCatching { CcpCrypto.unb64(confirmB64) }.getOrNull() ?: return false
            return CcpCrypto.constantTimeEquals(received, responderConfirm())
        }

        override fun equals(other: Any?) = other is Result && other.sas == sas &&
            pairSecret.contentEquals(other.pairSecret)

        override fun hashCode() = sas.hashCode()
    }

    fun commitment(initiatorPub: ByteArray, initiatorNonce: ByteArray): String =
        CcpCrypto.hex(CcpCrypto.sha256(
            "ccp-pair-commit-v1|${CcpCrypto.b64(initiatorPub)}|${CcpCrypto.b64(initiatorNonce)}"
        ))

    fun verifyCommitment(commitmentHex: String, initiatorPub: ByteArray, initiatorNonce: ByteArray): Boolean =
        CcpCrypto.constantTimeEquals(
            commitmentHex.lowercase().toByteArray(Charsets.US_ASCII),
            commitment(initiatorPub, initiatorNonce).toByteArray(Charsets.US_ASCII),
        )

    fun derive(
        sharedSecret: ByteArray,
        initiatorId: String,
        responderId: String,
        initiatorPub: ByteArray,
        responderPub: ByteArray,
        initiatorNonce: ByteArray,
        responderNonce: ByteArray,
    ): Result {
        val transcript = CcpCrypto.sha256(
            "ccp-pair-v1|$initiatorId|$responderId|" +
                "${CcpCrypto.b64(initiatorPub)}|${CcpCrypto.b64(responderPub)}|" +
                "${CcpCrypto.b64(initiatorNonce)}|${CcpCrypto.b64(responderNonce)}"
        )
        val pairSecret = CcpCrypto.hkdf(sharedSecret, transcript, "ccp-pair-secret-v1", 32)
        val sasBytes = CcpCrypto.hkdf(sharedSecret, transcript, "ccp-pair-sas-v1", 4)
        val sasValue = (ByteBuffer.wrap(sasBytes).int.toLong() and 0xFFFFFFFFL) % 1_000_000L
        val confirmKey = CcpCrypto.hkdf(sharedSecret, transcript, "ccp-pair-confirm-v1", 32)
        return Result(pairSecret, sasValue.toString().padStart(6, '0'), confirmKey, transcript)
    }
}

/**
 * Authenticated, encrypted framing for LAN sessions between paired devices.
 *
 * Each TCP connection starts with session.hello (client nonce) and
 * session.hello.response (server nonce) in clear. Both sides then derive
 * per-direction keys from the pair secret; every later frame is
 * {"sealed": base64(AES-GCM(ciphertext || tag))} with an implicit 64-bit
 * counter as nonce, so frames cannot be replayed, reordered or forged.
 */
class SecureChannel private constructor(
    private val sendKey: ByteArray,
    private val receiveKey: ByteArray,
    private val sendLabel: String,
    private val receiveLabel: String,
) {
    private var sendCounter = 0L
    private var receiveCounter = 0L

    @Synchronized
    fun seal(plaintext: String): String {
        val counter = sendCounter++
        val sealed = CcpCrypto.seal(sendKey, nonce(counter), aad(sendLabel, counter), plaintext.toByteArray(Charsets.UTF_8))
        return CcpCrypto.b64(sealed)
    }

    /** Throws if the frame was forged, replayed or reordered. */
    @Synchronized
    fun open(sealedB64: String): String {
        val counter = receiveCounter
        val plain = CcpCrypto.open(receiveKey, nonce(counter), aad(receiveLabel, counter), CcpCrypto.unb64(sealedB64))
        receiveCounter++
        return String(plain, Charsets.UTF_8)
    }

    companion object {
        fun keys(
            pairSecret: ByteArray,
            clientId: String,
            serverId: String,
            clientNonce: ByteArray,
            serverNonce: ByteArray,
        ): Pair<ByteArray, ByteArray> {
            val salt = CcpCrypto.sha256(
                "ccp-lan-v1|$clientId|$serverId|${CcpCrypto.b64(clientNonce)}|${CcpCrypto.b64(serverNonce)}"
            )
            return CcpCrypto.hkdf(pairSecret, salt, "ccp-lan-c2s-v1", 32) to
                CcpCrypto.hkdf(pairSecret, salt, "ccp-lan-s2c-v1", 32)
        }

        fun forClient(pairSecret: ByteArray, clientId: String, serverId: String, clientNonce: ByteArray, serverNonce: ByteArray): SecureChannel {
            val (c2s, s2c) = keys(pairSecret, clientId, serverId, clientNonce, serverNonce)
            return SecureChannel(c2s, s2c, "c2s", "s2c")
        }

        fun forServer(pairSecret: ByteArray, clientId: String, serverId: String, clientNonce: ByteArray, serverNonce: ByteArray): SecureChannel {
            val (c2s, s2c) = keys(pairSecret, clientId, serverId, clientNonce, serverNonce)
            return SecureChannel(s2c, c2s, "s2c", "c2s")
        }

        fun nonce(counter: Long): ByteArray =
            ByteBuffer.allocate(12).putInt(0).putLong(counter).array()

        fun aad(direction: String, counter: Long): ByteArray =
            "ccp-lan-frame-v1|$direction|$counter".toByteArray(Charsets.UTF_8)
    }
}

/** Cloud relay key schedule. Both peers derive the same key from the pair secret. */
object CcpCloudKeys {
    private fun ordered(a: String, b: String): Pair<String, String> = if (a < b) a to b else b to a

    fun cloudKey(pairSecret: ByteArray, deviceA: String, deviceB: String): ByteArray {
        val (idA, idB) = ordered(deviceA, deviceB)
        return CcpCrypto.hkdf(pairSecret, ByteArray(0), "ccp-cloud-key-v1|$idA|$idB", 32)
    }

    fun wrapKey(pairSecret: ByteArray, deviceA: String, deviceB: String): ByteArray {
        val (idA, idB) = ordered(deviceA, deviceB)
        return CcpCrypto.hkdf(pairSecret, ByteArray(0), "ccp-cloud-wrap-v1|$idA|$idB", 32)
    }

    fun fingerprint(cloudKey: ByteArray): String = CcpCrypto.hex(CcpCrypto.sha256(cloudKey))

    fun messageAad(senderId: String, recipientId: String, msgType: String, msgId: String): ByteArray =
        "ccp-cloud-msg-v1|$senderId|$recipientId|$msgType|$msgId".toByteArray(Charsets.UTF_8)
}
