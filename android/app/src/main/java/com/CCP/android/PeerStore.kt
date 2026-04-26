package com.ccp.android

import android.content.Context
import android.provider.Settings
import org.json.JSONObject

class PeerStore(context: Context) {
    private val prefs = context.getSharedPreferences("ccp_native", Context.MODE_PRIVATE)
    private val androidId = Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID) ?: "android"

    val deviceId: String = prefs.getString("device_id", null) ?: sha256Hex(
        "$androidId-${System.currentTimeMillis()}".toByteArray()
    ).also { prefs.edit().putString("device_id", it).apply() }

    val deviceName: String = prefs.getString("device_name", null) ?: "Android CCP"

    fun sender(): JSONObject {
        return JSONObject()
            .put("device_id", deviceId)
            .put("device_name", deviceName)
            .put("platform", "android")
    }

    fun isTrusted(deviceId: String): Boolean = prefs.contains("peer.$deviceId")

    fun trust(sender: JSONObject) {
        prefs.edit()
            .putString("peer.${sender.getString("device_id")}", sender.toString())
            .apply()
    }
}

