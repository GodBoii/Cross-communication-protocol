package com.ccp.android

import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest
import java.util.UUID

const val CCP_PROTOCOL = "ccp.v0"
const val CCP_UDP_PORT = 47827
const val CCP_TCP_PORT = 47828
const val CCP_CHUNK_SIZE = 64 * 1024

data class DeviceInfo(
    val deviceId: String,
    val deviceName: String,
    val platform: String,
    val host: String,
    val tcpPort: Int,
    val trusted: Boolean = false,
    val lastSeen: Long = System.currentTimeMillis()
)

fun sha256Hex(bytes: ByteArray): String {
    val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
    return digest.joinToString("") { "%02x".format(it) }
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

fun ccpDiscovery(sender: JSONObject): JSONObject {
    return JSONObject()
        .put("protocol", CCP_PROTOCOL)
        .put("type", "discovery")
        .put("device_id", sender.getString("device_id"))
        .put("device_name", sender.getString("device_name"))
        .put("platform", "android")
        .put("tcp_port", CCP_TCP_PORT)
        .put("capabilities", JSONArray(listOf("pairing", "file.transfer", "foreground.service")))
        .put("timestamp", System.currentTimeMillis() / 1000)
}

