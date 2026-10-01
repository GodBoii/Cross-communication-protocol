package com.ccp.android

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap
import kotlin.math.abs

/** Thrown when Convex rejects a call (auth failure, validation error, ...). */
class ConvexException(message: String) : IOException(message)

data class ConvexMessage(
    val messageId: String,
    val senderId: String,
    val msgType: String,
    val payload: JSONObject,
    val createdAt: Long,
)

/**
 * ConvexBridge — Android ↔ Convex cloud relay ("Long Distance").
 *
 *  • Every call is authenticated with the device's cloud auth token; the
 *    device id is bound to that token, so ids can't be squatted.
 *  • Payloads are AES-256-GCM encrypted with a key both peers derive locally
 *    from their pair secret (CcpCloudKeys). Sender, recipient, type and
 *    message id are bound as AAD, so Convex only ever stores ciphertext and
 *    cannot re-label or redirect it.
 *  • Messages are acked (deleted) only after they've been handled, and
 *    replays are rejected by message id and send time.
 *  • Polling backs off while idle and wakes immediately for outgoing requests.
 */
class ConvexBridge(
    context: Context,
    private val convexUrl: String,
    private val deviceId: String,
    private val deviceName: String,
    private val cloudAuthToken: String,
    private val platform: String = "android",
    private val pairSecretFor: (String) -> ByteArray?,
    private val onLog: (String) -> Unit = {},
    private val onMessage: ((ConvexMessage) -> Unit)? = null,
) {
    private val scope = CoroutineScope(
        SupervisorJob() + Dispatchers.IO + CoroutineExceptionHandler { _, e -> logCloud("Internal error: ${e.message}") }
    )
    private val prefs: SharedPreferences = context.getSharedPreferences("ccp_convex", Context.MODE_PRIVATE)
    private val replayGuard = ReplayGuard(prefs)
    private val pendingRequests = ConcurrentHashMap<String, PendingRequest>()
    private val wake = Channel<Unit>(Channel.CONFLATED)
    private var loopJob: Job? = null
    @Volatile private var running = false
    @Volatile private var lastActivity = 0L

    private val _cloudStatus = MutableStateFlow("Connecting to cloud…")
    val cloudStatus: StateFlow<String> = _cloudStatus

    private val _cloudMessages = MutableStateFlow<List<String>>(emptyList())
    val cloudMessages: StateFlow<List<String>> = _cloudMessages

    private class PendingRequest(val peerId: String, val deferred: CompletableDeferred<JSONObject>)

    init {
        require(convexUrl.startsWith("https://")) { "Convex URL must use HTTPS" }
        // Pre-v1 builds kept a pseudo key pair and the auth token here.
        prefs.edit().remove("convex_private_key").remove("cloud_auth_token").apply()
    }

    // ── Lifecycle ───────────────────────────────────────────────────────────

    @Synchronized
    fun start(appVersion: String, capabilities: List<String>) {
        if (running) return
        running = true
        loopJob = scope.launch {
            launch { registerLoop(appVersion, capabilities) }
            launch { heartbeatLoop() }
            launch { pollLoop() }
        }
    }

    @Synchronized
    fun stop() {
        if (!running) return
        running = false
        loopJob?.cancel()
        loopJob = null
        pendingRequests.values.forEach { it.deferred.cancel() }
        pendingRequests.clear()
        scope.launch {
            runCatching { call("mutation", "presence:goOffline", auth().put("device_id", deviceId)) }
        }
    }

    // ── Sessions ────────────────────────────────────────────────────────────

    /**
     * Records the pairing in Convex so the relay will carry messages between
     * the two devices. The stored blob is the cloud key wrapped under a key
     * only the two peers can derive; Convex can't unwrap it.
     */
    fun storeSession(peerDeviceId: String, pairSecret: ByteArray, pairedVia: String = "wifi"): Boolean {
        val (idA, idB) = if (deviceId < peerDeviceId) deviceId to peerDeviceId else peerDeviceId to deviceId
        val cloudKey = CcpCloudKeys.cloudKey(pairSecret, deviceId, peerDeviceId)
        val wrapKey = CcpCloudKeys.wrapKey(pairSecret, deviceId, peerDeviceId)
        val nonce = CcpCrypto.randomBytes(12)
        val blob = JSONObject()
            .put("v", 1)
            .put("nonce", CcpCrypto.b64(nonce))
            .put("ciphertext", CcpCrypto.b64(CcpCrypto.seal(wrapKey, nonce, WRAP_AAD, cloudKey)))
            .toString()
        val fingerprint = CcpCloudKeys.fingerprint(cloudKey)
        return try {
            call("mutation", "sessions:storeSession", auth()
                .put("device_id_a", idA)
                .put("device_id_b", idB)
                .put("caller_device_id", deviceId)
                .put("encrypted_key_a", blob)
                .put("encrypted_key_b", blob)
                .put("key_fingerprint", fingerprint)
                .put("paired_via", pairedVia))
            logCloud("Session stored with ${peerDeviceId.take(8)}… (fp ${fingerprint.take(12)}…)")
            setStatus("Cloud relay ready ✓")
            true
        } catch (e: Exception) {
            logCloud("Session store failed: ${e.message}")
            false
        }
    }

    private fun keyFor(peerDeviceId: String): ByteArray? =
        pairSecretFor(peerDeviceId)?.let { CcpCloudKeys.cloudKey(it, deviceId, peerDeviceId) }

    // ── Messages ────────────────────────────────────────────────────────────

    fun pushMessage(peerDeviceId: String, msgType: String, payload: JSONObject, ttlMs: Long? = null): Boolean {
        val key = keyFor(peerDeviceId) ?: run {
            logCloud("Not paired with ${peerDeviceId.take(8)}… — pair first")
            return false
        }
        val msgId = UUID.randomUUID().toString()
        val plaintext = JSONObject()
            .put("v", 1)
            .put("sent_at", System.currentTimeMillis())
            .put("body", payload)
            .toString()
            .toByteArray(Charsets.UTF_8)
        val nonce = CcpCrypto.randomBytes(12)
        val aad = CcpCloudKeys.messageAad(deviceId, peerDeviceId, msgType, msgId)
        val encoded = CcpCrypto.b64(CcpCrypto.seal(key, nonce, aad, plaintext))
        if (encoded.length > MAX_ENCRYPTED_PAYLOAD_CHARS) {
            logCloud("$msgType is too large for the relay")
            return false
        }
        val args = auth()
            .put("sender_id", deviceId)
            .put("recipient_id", peerDeviceId)
            .put("msg_type", msgType)
            .put("encrypted_payload", encoded)
            .put("nonce", CcpCrypto.b64(nonce))
            .put("msg_id", msgId)
        if (ttlMs != null) args.put("ttl_ms", ttlMs)

        // Retrying is safe: Convex de-duplicates by (sender, msg_id).
        repeat(3) { attempt ->
            try {
                call("mutation", "messages:pushMessage", args)
                markActive()
                return true
            } catch (e: ConvexException) {
                logCloud("Relay rejected $msgType: ${e.message}")
                return false
            } catch (e: IOException) {
                if (attempt == 2) {
                    logCloud("Push $msgType failed: ${e.message}")
                } else {
                    Thread.sleep(1_000L * (attempt + 1))
                }
            }
        }
        return false
    }

    suspend fun sendCloudRequest(
        peerDeviceId: String,
        msgType: String,
        payload: JSONObject = JSONObject(),
        timeoutMs: Long = 20_000,
    ): JSONObject? {
        val requestId = UUID.randomUUID().toString()
        payload.put("request_id", requestId)
        val deferred = CompletableDeferred<JSONObject>()
        pendingRequests[requestId] = PendingRequest(peerDeviceId, deferred)
        markActive()
        return try {
            if (!pushMessage(peerDeviceId, msgType, payload)) return null
            withTimeoutOrNull(timeoutMs) { deferred.await() }
        } finally {
            pendingRequests.remove(requestId)
        }
    }

    // ── Peer metadata ──────────────────────────────────────────────────────

    /** Revokes the relay session so neither side can message the other through Convex. */
    fun revokeSession(peerDeviceId: String): Boolean {
        val (idA, idB) = if (deviceId < peerDeviceId) deviceId to peerDeviceId else peerDeviceId to deviceId
        return try {
            call("mutation", "sessions:revokeSession", auth()
                .put("device_id_a", idA)
                .put("device_id_b", idB)
                .put("caller_device_id", deviceId))
            logCloud("Session with ${peerDeviceId.take(8)}… revoked")
            true
        } catch (e: Exception) {
            logCloud("Session revoke failed: ${e.message}")
            false
        }
    }

    fun getPeerPresence(peerDeviceId: String): JSONObject? = safeQuery("presence:getPresence", auth()
        .put("device_id", peerDeviceId)
        .put("requester_device_id", deviceId)) as? JSONObject

    fun listPairedPeers(): JSONArray? = safeQuery("sessions:listSessions", auth()
        .put("device_id", deviceId)) as? JSONArray

    fun getPeerDeviceInfo(peerDeviceId: String): JSONObject? = safeQuery("devices:getDevice", auth()
        .put("device_id", peerDeviceId)
        .put("requester_device_id", deviceId)) as? JSONObject

    private fun safeQuery(path: String, args: JSONObject): Any? = try {
        call("query", path, args)
    } catch (e: Exception) {
        logCloud("$path failed: ${e.message}")
        null
    }

    // ── Background loops ────────────────────────────────────────────────────

    private suspend fun registerLoop(appVersion: String, capabilities: List<String>) {
        var backoff = 5_000L
        while (currentCoroutineContext().isActive) {
            try {
                call("mutation", "devices:registerDevice", JSONObject()
                    .put("device_id", deviceId)
                    .put("device_name", deviceName.take(64))
                    .put("platform", platform)
                    .put("public_key_b64", "")
                    .put("auth_token", cloudAuthToken)
                    .put("capabilities", JSONArray(capabilities))
                    .put("app_version", appVersion))
                setStatus("Cloud connected ✓")
                logCloud("Registered on Convex")
                return
            } catch (e: Exception) {
                setStatus("Cloud: offline")
                logCloud("Registration failed: ${e.message}")
            }
            delay(backoff)
            backoff = (backoff * 2).coerceAtMost(5 * 60_000L)
        }
    }

    private suspend fun heartbeatLoop() {
        while (currentCoroutineContext().isActive) {
            try {
                call("mutation", "presence:heartbeat", auth()
                    .put("device_id", deviceId)
                    .put("ip_hint", localIpHint())
                    .put("tcp_port", CCP_TCP_PORT))
            } catch (_: Exception) {
                // Registration loop reports connectivity; a missed beat just shows us offline.
            }
            delay(HEARTBEAT_INTERVAL_MS)
        }
    }

    private suspend fun pollLoop() {
        var interval = POLL_ACTIVE_MS
        while (currentCoroutineContext().isActive) {
            val count = try {
                pollOnce()
            } catch (e: Exception) {
                logCloud("Poll failed: ${e.message}")
                0
            }
            if (count >= POLL_BATCH) continue // drain a backlog immediately
            val active = count > 0 || pendingRequests.isNotEmpty() ||
                System.currentTimeMillis() - lastActivity < ACTIVE_WINDOW_MS
            interval = if (active) POLL_ACTIVE_MS else (interval * 2).coerceAtMost(POLL_IDLE_MAX_MS)
            withTimeoutOrNull(interval) { wake.receive() }
        }
    }

    /** Polls one batch, handles each message, then acks the batch. Returns the batch size. */
    private fun pollOnce(): Int {
        val raw = call("query", "messages:pollMessages", auth()
            .put("recipient_id", deviceId)
            .put("limit", POLL_BATCH)) as? JSONArray ?: return 0

        val toAck = JSONArray()
        for (i in 0 until raw.length()) {
            val msg = raw.optJSONObject(i) ?: continue
            try {
                dispatch(msg)
            } catch (e: Exception) {
                // Undecryptable, replayed or failing messages are dropped, not redelivered forever.
                logCloud("Dropped ${msg.optString("msg_type")} from ${msg.optString("sender_id").take(8)}…: ${e.message}")
            }
            msg.optString("message_id").takeIf { it.isNotBlank() }?.let { toAck.put(it) }
        }
        if (toAck.length() > 0) {
            call("mutation", "messages:ackMessages", auth()
                .put("recipient_id", deviceId)
                .put("message_ids", toAck))
            replayGuard.persist()
        }
        return raw.length()
    }

    private fun dispatch(msg: JSONObject) {
        val senderId = msg.getString("sender_id")
        val msgType = msg.getString("msg_type")
        val msgId = msg.getString("msg_id")
        val key = keyFor(senderId) ?: throw SecurityException("sender is not paired")
        val aad = CcpCloudKeys.messageAad(senderId, deviceId, msgType, msgId)
        val plain = CcpCrypto.open(key, CcpCrypto.unb64(msg.getString("nonce")), aad, CcpCrypto.unb64(msg.getString("encrypted_payload")))
        val envelope = JSONObject(String(plain, Charsets.UTF_8))
        if (abs(System.currentTimeMillis() - envelope.optLong("sent_at", 0)) > MAX_MESSAGE_AGE_MS) {
            throw SecurityException("message too old")
        }
        if (!replayGuard.firstSeen("$senderId|$msgId")) throw SecurityException("replayed message")

        val payload = envelope.optJSONObject("body") ?: JSONObject()
        markActive()
        addCloudLog("$msgType ← ${senderId.take(8)}…")

        val requestId = payload.optString("request_id")
        val pending = if (requestId.isNotBlank() && msgType.endsWith(".response")) pendingRequests[requestId] else null
        if (pending != null && pending.peerId == senderId) {
            pendingRequests.remove(requestId)
            pending.deferred.complete(payload)
        } else {
            onMessage?.invoke(ConvexMessage(msg.optString("message_id"), senderId, msgType, payload, msg.optLong("created_at")))
        }
    }

    private fun markActive() {
        lastActivity = System.currentTimeMillis()
        wake.trySend(Unit)
    }

    // ── HTTP ────────────────────────────────────────────────────────────────

    private fun auth(): JSONObject = JSONObject().put("auth_token", cloudAuthToken)

    /**
     * Calls a Convex function over the HTTP API. Convex reports function
     * errors as HTTP 200 with status "error", so both are turned into
     * [ConvexException]; transport failures surface as [IOException].
     */
    private fun call(kind: String, path: String, args: JSONObject): Any? {
        val body = JSONObject().put("path", path).put("args", args).put("format", "json").toString()
        val conn = URL("$convexUrl/api/$kind").openConnection() as HttpURLConnection
        try {
            conn.requestMethod = "POST"
            conn.setRequestProperty("Content-Type", "application/json")
            conn.setRequestProperty("Accept", "application/json")
            conn.doOutput = true
            conn.connectTimeout = 10_000
            conn.readTimeout = 15_000
            conn.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else (conn.errorStream ?: conn.inputStream)
            val text = stream.bufferedReader(Charsets.UTF_8).use { it.readText() }
            val json = runCatching { JSONObject(text) }.getOrNull()
            if (code !in 200..299 || json?.optString("status") == "error") {
                throw ConvexException(summarizeError(json?.optString("errorMessage"), code))
            }
            val value = json?.opt("value")
            return if (value == null || value == JSONObject.NULL) null else value
        } finally {
            conn.disconnect()
        }
    }

    private fun localIpHint(): String = try {
        java.net.NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
            .flatMap { it.inetAddresses.toList() }
            .firstOrNull { !it.isLoopbackAddress && it.hostAddress?.contains(':') == false }
            ?.hostAddress
            ?.split(".")
            ?.takeIf { it.size == 4 }
            ?.let { "${it[0]}.${it[1]}.x.x" }
            ?: "x.x.x.x"
    } catch (_: Exception) {
        "x.x.x.x"
    }

    private fun setStatus(status: String) {
        _cloudStatus.value = status
    }

    private fun logCloud(msg: String) = onLog(msg)

    private fun addCloudLog(msg: String) {
        _cloudMessages.update { (it + msg).takeLast(20) }
    }

    companion object {
        private val WRAP_AAD = "ccp-cloud-wrap-v1".toByteArray(Charsets.UTF_8)
        private const val HEARTBEAT_INTERVAL_MS = 15_000L
        private const val POLL_ACTIVE_MS = 3_000L
        private const val POLL_IDLE_MAX_MS = 10_000L
        private const val ACTIVE_WINDOW_MS = 60_000L
        private const val POLL_BATCH = 20
        private const val MAX_MESSAGE_AGE_MS = 8L * 24 * 60 * 60 * 1000
        private const val MAX_ENCRYPTED_PAYLOAD_CHARS = 512 * 1024

        /** Extracts "auth_failed" from Convex's "...Uncaught Error: auth_failed\n at ..." messages. */
        fun summarizeError(message: String?, httpCode: Int): String {
            if (message.isNullOrBlank()) return "HTTP $httpCode"
            Regex("Uncaught Error: ([^\\n]+)").find(message)?.let { return it.groupValues[1].trim().take(200) }
            return message.lineSequence().first().take(200)
        }
    }
}

/**
 * Remembers recently seen relay message ids (persisted) so a message replayed
 * by the relay is processed at most once.
 */
private class ReplayGuard(private val prefs: SharedPreferences) {
    private val seen = object : LinkedHashMap<String, Boolean>(256, 0.75f, false) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Boolean>?) = size > MAX_ENTRIES
    }
    private var dirty = false

    init {
        prefs.getString(KEY, null)?.let { raw ->
            runCatching { JSONArray(raw) }.getOrNull()?.let { array ->
                for (i in 0 until array.length()) seen[array.optString(i)] = true
            }
        }
    }

    @Synchronized
    fun firstSeen(id: String): Boolean {
        if (seen.containsKey(id)) return false
        seen[id] = true
        dirty = true
        return true
    }

    @Synchronized
    fun persist() {
        if (!dirty) return
        prefs.edit().putString(KEY, JSONArray(seen.keys.toList()).toString()).apply()
        dirty = false
    }

    companion object {
        private const val KEY = "seen_msg_ids"
        private const val MAX_ENTRIES = 2_000
    }
}
