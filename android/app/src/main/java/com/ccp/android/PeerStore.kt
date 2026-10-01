package com.ccp.android

import android.content.Context
import android.os.Build
import android.util.Base64
import org.json.JSONObject
import java.security.SecureRandom

/**
 * Local identity and trust store.
 *
 * Identity (v1): a random cloud auth token is generated once; the public
 * device id is sha256("ccp-device-id-v1:" + sha256(token)), which lets the
 * Convex backend verify that a caller owns the id it registers.
 *
 * Trust (v1): a peer is trusted only if we hold a 32-byte pair secret derived
 * from an approved ECDH pairing. Pre-v1 secrets were sent over the LAN in
 * plain text, so they are discarded and those peers must pair again.
 */
class PeerStore(context: Context) {
    private val prefs = context.getSharedPreferences("ccp_native", Context.MODE_PRIVATE)

    val cloudAuthToken: String = loadOrCreateCloudToken(context)

    val deviceId: String = deriveDeviceId(cloudAuthToken).also { derived ->
        if (prefs.getString("device_id", null) != derived) {
            prefs.edit().putString("device_id", derived).apply()
        }
    }

    val deviceName: String = prefs.getString("device_name", null)
        ?: (Build.MODEL?.takeIf { it.isNotBlank() } ?: "Android CCP")

    init {
        dropLegacySecrets()
    }

    fun sender(): JSONObject {
        return JSONObject()
            .put("device_id", deviceId)
            .put("device_name", deviceName)
            .put("platform", "android")
    }

    fun isTrusted(deviceId: String): Boolean = pairSecretBytes(deviceId) != null

    /** The 32-byte v1 pair secret, or null if the peer isn't (or is no longer) paired. */
    fun pairSecretBytes(deviceId: String): ByteArray? {
        if (!isValidDeviceId(deviceId)) return null
        val encoded = prefs.getString(SECRET_PREFIX + deviceId, null) ?: return null
        return runCatching { Base64.decode(encoded, Base64.NO_WRAP) }.getOrNull()?.takeIf { it.size == 32 }
    }

    fun peerInfo(deviceId: String): JSONObject? =
        prefs.getString(PEER_PREFIX + deviceId, null)?.let { runCatching { JSONObject(it) }.getOrNull() }

    fun trustedPeerIds(): List<String> =
        prefs.all.keys.filter { it.startsWith(SECRET_PREFIX) }.map { it.removePrefix(SECRET_PREFIX) }.filter(::isValidDeviceId)

    fun trust(peer: JSONObject, pairSecret: ByteArray) {
        require(pairSecret.size == 32) { "pair secret must be 32 bytes" }
        val deviceId = peer.getString("device_id")
        require(isValidDeviceId(deviceId)) { "invalid device id" }
        val info = JSONObject()
            .put("device_id", deviceId)
            .put("device_name", peer.optString("device_name", "Unknown").take(64))
            .put("platform", peer.optString("platform", "unknown").take(16))
            .put("paired_at", System.currentTimeMillis())
        prefs.edit()
            .putString(PEER_PREFIX + deviceId, info.toString())
            .putString(SECRET_PREFIX + deviceId, Base64.encodeToString(pairSecret, Base64.NO_WRAP))
            .apply()
    }

    fun forget(deviceId: String) {
        prefs.edit().remove(PEER_PREFIX + deviceId).remove(SECRET_PREFIX + deviceId).apply()
    }

    private fun dropLegacySecrets() {
        val legacy = prefs.all.keys.filter { it.startsWith(LEGACY_SECRET_PREFIX) }
        if (legacy.isEmpty()) return
        prefs.edit().apply { legacy.forEach { remove(it) } }.apply()
    }

    private fun loadOrCreateCloudToken(context: Context): String {
        prefs.getString("cloud_auth_token", null)?.let { return it }
        // Migrate the token that older builds kept in the Convex bridge prefs.
        val legacy = context.getSharedPreferences("ccp_convex", Context.MODE_PRIVATE)
            .getString("cloud_auth_token", null)
        val token = legacy ?: Base64.encodeToString(
            ByteArray(32).also { SecureRandom().nextBytes(it) },
            Base64.NO_WRAP
        )
        prefs.edit().putString("cloud_auth_token", token).apply()
        return token
    }

    companion object {
        const val DEVICE_ID_PREFIX = "ccp-device-id-v1:"
        private const val PEER_PREFIX = "peer."
        private const val SECRET_PREFIX = "peer_secret_v1."
        private const val LEGACY_SECRET_PREFIX = "peer_secret."

        fun deriveDeviceId(cloudAuthToken: String): String {
            val tokenHash = sha256Hex(cloudAuthToken.toByteArray(Charsets.UTF_8))
            return sha256Hex((DEVICE_ID_PREFIX + tokenHash).toByteArray(Charsets.UTF_8))
        }
    }
}
