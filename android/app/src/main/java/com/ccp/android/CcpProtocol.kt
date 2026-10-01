package com.ccp.android

import org.json.JSONArray
import org.json.JSONObject
import java.io.InputStream
import java.security.MessageDigest
import java.util.UUID

/** v1: ECDH pairing and encrypted LAN sessions; not wire-compatible with v0. */
const val CCP_PROTOCOL = "ccp.v1"
const val CCP_UDP_PORT = 47827
const val CCP_TCP_PORT = 47828
const val CCP_CHUNK_SIZE = 64 * 1024

/** Upper bound on simultaneous inbound TCP sessions. */
const val MAX_CONCURRENT_CONNECTIONS = 16

/** Read timeout for TCP sessions; longer than the 60 s pairing prompt. */
const val CCP_SOCKET_IDLE_TIMEOUT_MS = 90_000

private val DEVICE_ID_PATTERN = Regex("^[0-9a-f]{64}$")

fun isValidDeviceId(value: String?): Boolean = value != null && DEVICE_ID_PATTERN.matches(value)

data class ConnectionRoute(
    val transport: String,
    val host: String,
    val tcpPort: Int
) {
    val label: String get() = "$transport $host:$tcpPort"
}

data class DeviceInfo(
    val deviceId: String,
    val deviceName: String,
    val platform: String,
    val host: String,
    val tcpPort: Int,
    val trusted: Boolean = false,
    val lastSeen: Long = System.currentTimeMillis(),
    val transports: List<String> = emptyList(),
    val routes: List<ConnectionRoute> = emptyList(),
    val isCloudPeer: Boolean = false,
    val cloudOnline: Boolean = false,
) {
    val primaryRouteLabel: String get() = if (isCloudPeer) "cloud relay" else routes.firstOrNull()?.label ?: "$host:$tcpPort"
    val transportSummary: String get() = if (isCloudPeer) "long distance ${if (cloudOnline) "online" else "offline"}" else if (transports.isEmpty()) "direct tcp" else transports.joinToString(" | ")
}

data class RemoteFactItem(
    val label: String,
    val value: String
)

data class RemoteEntryItem(
    val name: String,
    val subtitle: String
)

data class RemotePeerPanel(
    val title: String,
    val subtitle: String,
    val battery: String,
    val storage: String,
    val notificationAccess: String,
    val galleryAccess: String,
    val settings: List<RemoteFactItem>,
    val gallery: List<RemoteEntryItem>,
    val files: List<RemoteEntryItem>,
    val notifications: List<RemoteEntryItem>
)

fun sha256Hex(bytes: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
    return digest.joinToString("") { "%02x".format(it) }
}

fun sha256Hex(input: InputStream): Pair<Long, String> {
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(64 * 1024)
    var total = 0L
    while (true) {
        val read = input.read(buffer)
        if (read <= 0) break
        digest.update(buffer, 0, read)
        total += read
    }
    val hash = digest.digest().joinToString("") { "%02x".format(it) }
    return total to hash
}

fun ccpEnvelope(type: String, sender: JSONObject, payload: JSONObject): JSONObject {
    return JSONObject()
        .put("protocol", CCP_PROTOCOL)
        .put("id", UUID.randomUUID().toString())
        .put("type", type)
        .put("sender", sender)
        .put("payload", payload)
        .put("timestamp", System.currentTimeMillis() / 1000)
}

fun ccpDiscovery(
    sender: JSONObject,
    transports: JSONObject,
    endpoints: JSONArray,
    capabilities: JSONArray = JSONArray(
        listOf(
            "pairing",
            "file.transfer",
            "device.snapshot",
            "gallery.list",
            "files.list",
            "notifications.list",
            "foreground.service"
        )
    )
): JSONObject {
    return JSONObject()
        .put("protocol", CCP_PROTOCOL)
        .put("type", "discovery")
        .put("device_id", sender.getString("device_id"))
        .put("device_name", sender.getString("device_name"))
        .put("platform", "android")
        .put("tcp_port", CCP_TCP_PORT)
        .put("capabilities", capabilities)
        .put("transports", transports)
        .put("endpoints", endpoints)
        .put("timestamp", System.currentTimeMillis() / 1000)
}
