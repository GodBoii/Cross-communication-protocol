package com.ccp.android

import org.json.JSONObject

private val HEX64 = Regex("^[0-9a-f]{64}$")
private const val MAX_PUBLIC_KEY_B64 = 256

private fun decodeField(payload: JSONObject, name: String, maxB64: Int): ByteArray {
    val text = payload.optString(name)
    require(text.isNotEmpty() && text.length <= maxB64) { "invalid_$name" }
    return runCatching { CcpCrypto.unb64(text) }.getOrElse { throw IllegalArgumentException("invalid_$name") }
}

private fun decodeNonce(payload: JSONObject): ByteArray {
    val nonce = decodeField(payload, "nonce", 64)
    require(nonce.size == SESSION_NONCE_BYTES) { "invalid_nonce" }
    return nonce
}

/**
 * Initiator side of v1 pairing (see CcpPairing). Holds an ephemeral P-256 key
 * that exists only for this attempt.
 */
class PairingInitiator(private val selfId: String) {
    private val keyPair = CcpCrypto.generateEcKeyPair()
    private val publicKey = CcpCrypto.encodePublicKey(keyPair.public)
    private val nonce = CcpCrypto.randomBytes(SESSION_NONCE_BYTES)

    fun requestPayload(): JSONObject = JSONObject()
        .put("version", CcpPairing.VERSION)
        .put("commitment", CcpPairing.commitment(publicKey, nonce))

    fun revealPayload(): JSONObject = JSONObject()
        .put("ephemeral_pub", CcpCrypto.b64(publicKey))
        .put("nonce", CcpCrypto.b64(nonce))

    fun onChallenge(responderId: String, payload: JSONObject): CcpPairing.Result {
        val peerPublicKey = decodeField(payload, "ephemeral_pub", MAX_PUBLIC_KEY_B64)
        val peerNonce = decodeNonce(payload)
        val shared = CcpCrypto.ecdh(keyPair.private, peerPublicKey)
        return CcpPairing.derive(shared, selfId, responderId, publicKey, peerPublicKey, nonce, peerNonce)
    }
}

/**
 * Responder side of v1 pairing. Constructing it validates pair.request;
 * [onReveal] checks the initiator's commitment before deriving anything.
 * Validation failures throw IllegalArgumentException whose message is the
 * reason code sent back to the peer.
 */
class PairingResponder(private val selfId: String, private val initiatorId: String, request: JSONObject) {
    private val commitment: String = request.optString("commitment").lowercase()
    private val keyPair = CcpCrypto.generateEcKeyPair()
    private val publicKey = CcpCrypto.encodePublicKey(keyPair.public)
    private val nonce = CcpCrypto.randomBytes(SESSION_NONCE_BYTES)

    init {
        require(request.optInt("version", 0) == CcpPairing.VERSION) { "unsupported_pairing_version" }
        require(HEX64.matches(commitment)) { "invalid_commitment" }
    }

    fun challengePayload(): JSONObject = JSONObject()
        .put("ephemeral_pub", CcpCrypto.b64(publicKey))
        .put("nonce", CcpCrypto.b64(nonce))

    fun onReveal(payload: JSONObject): CcpPairing.Result {
        val peerPublicKey = decodeField(payload, "ephemeral_pub", MAX_PUBLIC_KEY_B64)
        val peerNonce = decodeNonce(payload)
        require(CcpPairing.verifyCommitment(commitment, peerPublicKey, peerNonce)) { "commitment_mismatch" }
        val shared = try {
            CcpCrypto.ecdh(keyPair.private, peerPublicKey)
        } catch (e: Exception) {
            throw IllegalArgumentException("invalid_ephemeral_pub")
        }
        return CcpPairing.derive(shared, initiatorId, selfId, peerPublicKey, publicKey, peerNonce, nonce)
    }
}
