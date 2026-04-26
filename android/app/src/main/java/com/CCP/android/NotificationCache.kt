package com.ccp.android

import android.content.ComponentName
import android.content.Context
import android.provider.Settings
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.CopyOnWriteArrayList

object NotificationCache {
    private val entries = CopyOnWriteArrayList<JSONObject>()

    fun add(packageName: String, title: String?, text: String?) {
        val item = JSONObject()
            .put("package", packageName)
            .put("title", title ?: packageName)
            .put("text", text ?: "")
            .put("timestamp", System.currentTimeMillis())
        entries.add(0, item)
        while (entries.size > 25) {
            entries.removeLastOrNull()
        }
    }

    fun toJson(): JSONArray = JSONArray(entries.take(12))

    fun hasAccess(context: Context): Boolean {
        val flat = Settings.Secure.getString(context.contentResolver, "enabled_notification_listeners") ?: return false
        val component = ComponentName(context, CcpNotificationListener::class.java).flattenToString()
        return flat.contains(component)
    }
}

