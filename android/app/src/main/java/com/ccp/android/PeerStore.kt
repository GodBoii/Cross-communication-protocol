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

    fun sender(): JSONObject {
        return JSONObject()
            .put("device_id", deviceId)
            .put("device_name", deviceName)
            .put("platform", "android")
    }

    fun isTrusted(deviceId: String): Boolean = prefs.contains("peer.$deviceId")

    fun pairSecret(deviceId: String): String? =
        prefs.getString("peer_secret.$deviceId", null)

    fun trust(sender: JSONObject, pairSecretB64: String? = null) {
        val deviceId = sender.getString("device_id")
        prefs.edit()
            .putString("peer.$deviceId", sender.toString())
            .apply {
                if (!pairSecretB64.isNullOrBlank()) {
                    putString("peer_secret.$deviceId", pairSecretB64)
                }
            }
            .apply()
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

        fun deriveDeviceId(cloudAuthToken: String): String {
            val tokenHash = sha256Hex(cloudAuthToken.toByteArray(Charsets.UTF_8))
            return sha256Hex((DEVICE_ID_PREFIX + tokenHash).toByteArray(Charsets.UTF_8))
        }
    }
}
