package com.ccp.android

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.URL
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import javax.net.ssl.HttpsURLConnection
import kotlin.math.min
import kotlinx.coroutines.withTimeoutOrNull

/**
 * ConvexBridge — CCP Android ↔ Convex cloud relay integration.
 *
 * Mirrors the Python Windows implementation so both platforms share the same
 * Convex backend tables and protocol.
 *
 * Key design decisions:
 *   • No external libraries required — uses javax.crypto (AES-256-GCM) and
 *     Android's built-in HTTPS.
 *   • End-to-end encrypted: Convex only ever sees ciphertext.
 *   • The session key is encrypted with a machine-local secret (PBKDF2 over
 *     device_id) before storage in Convex.
 *   • Heartbeat thread keeps presence alive; poll thread delivers messages.
 *
 * Usage:
 *     val bridge = ConvexBridge(context, CONVEX_URL, store.deviceId, store.deviceName)
 *     bridge.start()
 *     bridge.completeKeyExchange(peerDeviceId, peerPublicKeyB64)
 *     bridge.pushMessage(peerDeviceId, "remote.action.request", payload)
 *     val msgs = bridge.pollMessages()
 */

/** Convex deployment URL — must match the Windows client */
const val CONVEX_URL = "https://reminiscent-raven-475.convex.cloud"

class ConvexBridge(
    private val context: Context,
    private val convexUrl: String = CONVEX_URL,
    private val deviceId: String,
    private val deviceName: String,
    private val platform: String = "android",
    private val onMessage: ((ConvexMessage) -> Unit)? = null,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val prefs: SharedPreferences =
        context.getSharedPreferences("ccp_convex", Context.MODE_PRIVATE)

    // ── Key material ────────────────────────────────────────────────────────
    // Public key is retained for device identity display. Cloud session keys are
    // derived from the per-pair secret exchanged during approved local pairing.
    private val privateKeyBytes: ByteArray = getOrCreatePrivateKey()
    val publicKeyB64: String = Base64.encodeToString(
        sha256(privateKeyBytes + "ccp-pub".toByteArray()), Base64.NO_WRAP
    )
    private val cloudAuthToken: String = getOrCreateCloudAuthToken()
    private val cloudAuthTokenHash: String = sha256(cloudAuthToken.toByteArray()).toHex()

    // In-memory session cache: peer_device_id → raw 32-byte AES key
    private val sessionKeys = HashMap<String, ByteArray>()
    private val pendingRequests = ConcurrentHashMap<String, CompletableDeferred<JSONObject>>()

    // Cloud status for UI
    private val _cloudStatus = MutableStateFlow("Connecting to cloud…")
    val cloudStatus: StateFlow<String> = _cloudStatus

    private val _cloudMessages = MutableStateFlow<List<String>>(emptyList())
    val cloudMessages: StateFlow<List<String>> = _cloudMessages

    @Volatile private var running = false

    // ── Lifecycle ───────────────────────────────────────────────────────────

    fun start(appVersion: String = "0.2.0", capabilities: List<String> = listOf(
        "pairing", "file.transfer", "remote.action", "device.snapshot",
        "gallery.list", "notifications.list"
    )) {
        running = true
        scope.launch {
            try {
                mutation("devices:registerDevice", JSONObject().apply {
                    put("device_id", deviceId)
                    put("device_name", deviceName)
                    put("platform", platform)
                    put("public_key_b64", publicKeyB64)
                    put("auth_token_hash", cloudAuthTokenHash)
                    put("capabilities", JSONArray(capabilities))
                    put("app_version", appVersion)
                })
                _cloudStatus.value = "Cloud connected ✓"
                logCloud("Registered on Convex")
            } catch (e: Exception) {
                _cloudStatus.value = "Cloud: offline"
                logCloud("Registration failed: ${e.message}")
            }
        }
        scope.launch { heartbeatLoop() }
        scope.launch { pollLoop() }
    }

    fun stop() {
        running = false
        scope.launch {
            try {
                mutation("presence:goOffline", JSONObject()
                    .put("device_id", deviceId)
                    .put("auth_token", cloudAuthToken))
            }
            catch (_: Exception) {}
        }
    }

    // ── Key Exchange ────────────────────────────────────────────────────────

    /**
     * Call this after a successful local WiFi pairing.
     * The cloud session is derived from the local pair secret rather than any
     * public device identifier, so Convex cannot unwrap stored sessions.
     */
    fun completeKeyExchange(
        peerDeviceId: String,
        peerPublicKeyB64: String,
        pairSecretB64: String?,
        pairedVia: String = "wifi",
    ): String {
        if (pairSecretB64.isNullOrBlank()) {
            logCloud("Session skipped for ${peerDeviceId.take(8)}…: missing pair secret")
            return ""
        }
        val pairSecret = Base64.decode(pairSecretB64, Base64.NO_WRAP)
        val idA = minOf(deviceId, peerDeviceId)
        val idB = maxOf(deviceId, peerDeviceId)
        val sessionKey = hkdf(
            pairSecret + "$idA|$idB".toByteArray(),
            "ccp-session-v1".toByteArray(),
            32
        )
        val wrapKey = hkdf(pairSecret, "ccp-session-wrap-v1".toByteArray(), 32)
        val encryptedBlob = Base64.encodeToString(
            JSONObject(encryptAesGcm(wrapKey, sessionKey)).toString().toByteArray(),
            Base64.NO_WRAP
        )
        val fingerprint = sha256(sessionKey).toHex()

        scope.launch {
            try {
                mutation("sessions:storeSession", JSONObject().apply {
                    put("device_id_a", idA)
                    put("device_id_b", idB)
                    put("caller_device_id", deviceId)
                    put("auth_token", cloudAuthToken)
                    put("encrypted_key_a", encryptedBlob)
                    put("encrypted_key_b", encryptedBlob)
                    put("key_fingerprint", fingerprint)
                    put("paired_via", pairedVia)
                })
                logCloud("Session stored with ${peerDeviceId.take(8)}… (fp: ${fingerprint.take(12)}…)")
                _cloudStatus.value = "Cloud relay ready ✓"
            } catch (e: Exception) {
                logCloud("Session store failed: ${e.message}")
            }
        }

        synchronized(sessionKeys) { sessionKeys[peerDeviceId] = sessionKey }
        return fingerprint
    }

    fun loadSessionFromCloud(peerDeviceId: String, pairSecretB64: String?): Boolean {
        if (pairSecretB64.isNullOrBlank()) {
            logCloud("Session load skipped for ${peerDeviceId.take(8)}…: missing pair secret")
            return false
        }
        return try {
            val data = query("sessions:getSession", JSONObject().apply {
                put("my_device_id", deviceId)
                put("peer_device_id", peerDeviceId)
                put("auth_token", cloudAuthToken)
            }) ?: return false

            val blobJson = JSONObject(
                String(Base64.decode(data.getString("encrypted_key"), Base64.NO_WRAP))
            )
            val wrapKey = hkdf(
                Base64.decode(pairSecretB64, Base64.NO_WRAP),
                "ccp-session-wrap-v1".toByteArray(),
                32
            )
            val sessionKey = decryptAesGcm(
                wrapKey,
                blobJson.getString("nonce"),
                blobJson.getString("ciphertext")
            )
            synchronized(sessionKeys) { sessionKeys[peerDeviceId] = sessionKey }
            logCloud("Session loaded for ${peerDeviceId.take(8)}…")
            true
        } catch (e: Exception) {
            logCloud("Session load failed for ${peerDeviceId.take(8)}…: ${e.message}")
            false
        }
    }

    fun getSessionKey(peerDeviceId: String): ByteArray? =
        synchronized(sessionKeys) { sessionKeys[peerDeviceId] }

    // ── Message Push / Poll ─────────────────────────────────────────────────

    fun pushMessage(
        peerDeviceId: String,
        msgType: String,
        payload: JSONObject,
        ttlMs: Long? = null,
    ): Boolean {
        val key = getSessionKey(peerDeviceId)
        if (key == null) {
            logCloud("No session key for ${peerDeviceId.take(8)}… — pair first")
            return false
        }

        val plaintext = payload.toString().toByteArray(Charsets.UTF_8)
        val enc = encryptAesGcm(key, plaintext)
        val msgId = UUID.randomUUID().toString()

        return try {
            val args = JSONObject().apply {
                put("sender_id", deviceId)
                put("auth_token", cloudAuthToken)
                put("recipient_id", peerDeviceId)
                put("msg_type", msgType)
                put("encrypted_payload", enc["ciphertext"])
                put("nonce", enc["nonce"])
                put("msg_id", msgId)
                if (ttlMs != null) put("ttl_ms", ttlMs)
            }
            mutation("messages:pushMessage", args)
            logCloud("Pushed $msgType → ${peerDeviceId.take(8)}…")
            true
        } catch (e: Exception) {
            logCloud("Push failed: ${e.message}")
            false
        }
    }

    fun ensureSessionKey(peerDeviceId: String, pairSecretB64: String?): Boolean {
        if (getSessionKey(peerDeviceId) != null) return true
        return loadSessionFromCloud(peerDeviceId, pairSecretB64)
    }

    fun pollMessages(): List<ConvexMessage> {
        return try {
            val rawArray = queryArray("messages:pollMessages", JSONObject().apply {
                put("recipient_id", deviceId)
                put("auth_token", cloudAuthToken)
            }) ?: return emptyList()

            val results = mutableListOf<ConvexMessage>()
            val toAck = mutableListOf<String>()

            for (i in 0 until rawArray.length()) {
                val msg = rawArray.getJSONObject(i)
                val senderId = msg.getString("sender_id")
                val key = getSessionKey(senderId)
                if (key == null) {
                    logCloud("No key for sender ${senderId.take(8)}… — skipping")
                    continue
                }
                try {
                    val plaintext = decryptAesGcm(
                        key, msg.getString("nonce"), msg.getString("encrypted_payload")
                    )
                    val payload = JSONObject(String(plaintext, Charsets.UTF_8))
                    results.add(ConvexMessage(
                        messageId = msg.getString("message_id"),
                        senderId = senderId,
                        msgType = msg.getString("msg_type"),
                        payload = payload,
                        createdAt = msg.getLong("created_at"),
                    ))
                    toAck.add(msg.getString("message_id"))
                } catch (e: Exception) {
                    logCloud("Decrypt failed: ${e.message}")
                }
            }

            if (toAck.isNotEmpty()) {
                mutation("messages:ackMessages", JSONObject().apply {
                    put("recipient_id", deviceId)
                    put("auth_token", cloudAuthToken)
                    put("message_ids", JSONArray(toAck))
                })
            }
            results
        } catch (e: Exception) {
            logCloud("Poll failed: ${e.message}")
            emptyList()
        }
    }

    fun getPeerPresence(peerDeviceId: String): JSONObject? = try {
        query("presence:getPresence", JSONObject()
            .put("device_id", peerDeviceId)
            .put("requester_device_id", deviceId)
            .put("auth_token", cloudAuthToken))
    } catch (_: Exception) { null }

    fun listPairedPeers(): JSONArray? = try {
        queryArray("sessions:listSessions", JSONObject()
            .put("device_id", deviceId)
            .put("auth_token", cloudAuthToken))
    } catch (_: Exception) { null }

    fun getPeerDeviceInfo(peerDeviceId: String): JSONObject? = try {
        query("devices:getDevice", JSONObject()
            .put("device_id", peerDeviceId)
            .put("requester_device_id", deviceId)
            .put("auth_token", cloudAuthToken))
    } catch (_: Exception) { null }

    fun getPeerPublicKey(peerDeviceId: String): String? = try {
        query("devices:getPublicKey", JSONObject()
            .put("device_id", peerDeviceId)
            .put("requester_device_id", deviceId)
            .put("auth_token", cloudAuthToken))
            ?.optString("public_key_b64")
    } catch (_: Exception) { null }

    suspend fun sendCloudRequest(
        peerDeviceId: String,
        msgType: String,
        payload: JSONObject = JSONObject(),
        timeoutMs: Long = 15_000,
    ): JSONObject? {
        val requestId = UUID.randomUUID().toString()
        payload.put("request_id", requestId)
        val deferred = CompletableDeferred<JSONObject>()
        pendingRequests[requestId] = deferred
        return try {
            if (!pushMessage(peerDeviceId, msgType, payload)) {
                pendingRequests.remove(requestId)
                return null
            }
            withTimeoutOrNull(timeoutMs) { deferred.await() }
        } finally {
            pendingRequests.remove(requestId)
        }
    }

    // ── Background loops ────────────────────────────────────────────────────

    private suspend fun heartbeatLoop() {
        while (running) {
            try {
                val localIp = try {
                    java.net.NetworkInterface.getNetworkInterfaces()
                        ?.toList()
                        ?.flatMap { it.inetAddresses.toList() }
                        ?.firstOrNull { !it.isLoopbackAddress && it.hostAddress?.contains(':') == false }
                        ?.hostAddress ?: ""
                } catch (_: Exception) { "" }
                val parts = localIp.split(".")
                val ipHint = if (parts.size == 4) "${parts[0]}.${parts[1]}.x.x" else "x.x.x.x"

                mutation("presence:heartbeat", JSONObject().apply {
                    put("device_id", deviceId)
                    put("auth_token", cloudAuthToken)
                    put("ip_hint", ipHint)
                    put("tcp_port", CCP_TCP_PORT)
                })
            } catch (_: Exception) {}
            delay(10_000)
        }
    }

    private suspend fun pollLoop() {
        while (running) {
            try {
                val messages = pollMessages()
                for (msg in messages) {
                    logCloud("Received ${msg.msgType} from ${msg.senderId.take(8)}…")
                    addCloudLog("${msg.msgType} ← ${msg.senderId.take(8)}…")
                    val requestId = msg.payload.optString("request_id", "")
                    val pending = if (requestId.isNotBlank()) pendingRequests.remove(requestId) else null
                    if (pending != null) {
                        pending.complete(msg.payload)
                    } else {
                        onMessage?.invoke(msg)
                    }
                }
            } catch (_: Exception) {}
            delay(3_000)
        }
    }

    // ── HTTP helpers ────────────────────────────────────────────────────────

    private fun mutation(funcName: String, args: JSONObject): JSONObject? =
        convexPost("mutation", funcName, args)

    private fun query(funcName: String, args: JSONObject): JSONObject? =
        convexPost("query", funcName, args)

    private fun queryArray(funcName: String, args: JSONObject): JSONArray? {
        val body = JSONObject().apply {
            put("path", funcName)
            put("args", args)
            put("format", "json")
        }
        val raw = httpPost("$convexUrl/api/query", body.toString()) ?: return null
        val result = JSONObject(raw)
        val value = result.opt("value")
        return when (value) {
            is JSONArray -> value
            else -> null
        }
    }

    private fun convexPost(endpoint: String, funcName: String, args: JSONObject): JSONObject? {
        val body = JSONObject().apply {
            put("path", funcName)
            put("args", args)
            put("format", "json")
        }
        val raw = httpPost("$convexUrl/api/$endpoint", body.toString()) ?: return null
        val result = JSONObject(raw)
        return result.optJSONObject("value")
    }

    private fun httpPost(urlStr: String, body: String): String? {
        val url = URL(urlStr)
        val conn = url.openConnection() as HttpsURLConnection
        conn.requestMethod = "POST"
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setRequestProperty("Accept", "application/json")
        conn.doOutput = true
        conn.connectTimeout = 10_000
        conn.readTimeout = 10_000

        OutputStreamWriter(conn.outputStream).use { it.write(body) }
        return if (conn.responseCode in 200..299) {
            BufferedReader(InputStreamReader(conn.inputStream)).use { it.readText() }
        } else {
            val err = BufferedReader(InputStreamReader(conn.errorStream ?: conn.inputStream)).use { it.readText() }
            logCloud("HTTP ${conn.responseCode}: $err")
            null
        }
    }

    // ── Crypto helpers ──────────────────────────────────────────────────────

    private fun encryptAesGcm(key: ByteArray, plaintext: ByteArray): Map<String, String> {
        val secretKey = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val nonce = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, nonce))
        val ciphertext = cipher.doFinal(plaintext)
        return mapOf(
            "nonce" to Base64.encodeToString(nonce, Base64.NO_WRAP),
            "ciphertext" to Base64.encodeToString(ciphertext, Base64.NO_WRAP),
        )
    }

    private fun decryptAesGcm(key: ByteArray, nonceB64: String, ciphertextB64: String): ByteArray {
        val secretKey = SecretKeySpec(key, "AES")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val nonce = Base64.decode(nonceB64, Base64.NO_WRAP)
        val ciphertext = Base64.decode(ciphertextB64, Base64.NO_WRAP)
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, nonce))
        return cipher.doFinal(ciphertext)
    }

    private fun sha256(input: ByteArray): ByteArray =
        MessageDigest.getInstance("SHA-256").digest(input)

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    /**
     * Minimal HKDF-SHA256 implementation.
     * Extract: PRK = HMAC-SHA256(salt=0x00*32, IKM=input)
     * Expand:  T1  = HMAC-SHA256(PRK, info || 0x01)
     */
    private fun hkdf(input: ByteArray, info: ByteArray, length: Int): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val salt = ByteArray(32)
        mac.init(SecretKeySpec(salt, "HmacSHA256"))
        val prk = mac.doFinal(input)
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        val t = mac.doFinal(info + byteArrayOf(0x01))
        return t.copyOf(min(length, t.size))
    }

    private fun getOrCreatePrivateKey(): ByteArray {
        val stored = prefs.getString("convex_private_key", null)
        if (stored != null) return Base64.decode(stored, Base64.NO_WRAP)
        val key = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        prefs.edit().putString("convex_private_key", Base64.encodeToString(key, Base64.NO_WRAP)).apply()
        return key
    }

    private fun getOrCreateCloudAuthToken(): String {
        val stored = prefs.getString("cloud_auth_token", null)
        if (stored != null) return stored
        val token = ByteArray(32).also { java.security.SecureRandom().nextBytes(it) }
        val encoded = Base64.encodeToString(token, Base64.NO_WRAP)
        prefs.edit().putString("cloud_auth_token", encoded).apply()
        return encoded
    }

    private fun logCloud(msg: String) {
        // Emit to CcpNode events via state flow (non-blocking)
    }

    private fun addCloudLog(msg: String) {
        _cloudMessages.value = (_cloudMessages.value + msg).takeLast(20)
    }
}

// ── Data classes ──────────────────────────────────────────────────────────────

data class ConvexMessage(
    val messageId: String,
    val senderId: String,
    val msgType: String,
    val payload: JSONObject,
    val createdAt: Long,
)
