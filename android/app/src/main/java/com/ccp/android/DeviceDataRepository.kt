package com.ccp.android

import android.app.Notification
import android.app.NotificationManager
import android.content.pm.PackageManager
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.media.MediaScannerConnection
import android.net.Uri
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import android.os.Build
import android.os.Environment
import android.os.storage.StorageManager
import android.provider.MediaStore
import android.provider.Settings
import android.text.format.Formatter
import android.webkit.MimeTypeMap
import androidx.core.content.ContextCompat
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Locale

data class LocalDeviceSnapshot(
    val title: String,
    val subtitle: String,
    val battery: String,
    val storage: String,
    val notificationAccess: String,
    val galleryAccess: String,
    val settings: List<Pair<String, String>>
)

class DeviceDataRepository(private val context: Context) {
    private val prefs = context.getSharedPreferences("ccp_device_data", Context.MODE_PRIVATE)

    fun saveIncomingFile(fileName: String, bytes: ByteArray): JSONObject {
        val mimeType = guessMimeType(fileName)
        val now = System.currentTimeMillis()
        val record = when {
            mimeType.startsWith("image/") -> saveToMediaStore(
                collection = MediaStore.Images.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY),
                directory = "Pictures/CCP",
                fileName = fileName,
                mimeType = mimeType,
                bytes = bytes,
                type = "gallery"
            )
            mimeType.startsWith("video/") -> saveToMediaStore(
                collection = MediaStore.Video.Media.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY),
                directory = "Movies/CCP",
                fileName = fileName,
                mimeType = mimeType,
                bytes = bytes,
                type = "gallery"
            )
            else -> saveToMediaStore(
                collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY),
                directory = "Download/CCP",
                fileName = fileName,
                mimeType = mimeType,
                bytes = bytes,
                type = "file"
            )
        }.put("received_at", now)

        val existing = loadJsonArray("recent_received")
        val updated = JSONArray().put(record)
        for (index in 0 until existing.length()) {
            updated.put(existing.getJSONObject(index))
            if (updated.length() >= 24) break
        }
        prefs.edit().putString("recent_received", updated.toString()).apply()
        return record
    }

    fun localSnapshot(notificationAccessEnabled: Boolean, galleryAccessEnabled: Boolean): LocalDeviceSnapshot {
        val batteryManager = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
        val battery = batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
        val storageManager = context.getSystemService(Context.STORAGE_SERVICE) as StorageManager
        val primaryStorage = storageManager.storageVolumes.firstOrNull()?.directory
        val storage = primaryStorage?.let { dir ->
            val total = dir.totalSpace
            val free = dir.freeSpace
            "${Formatter.formatFileSize(context, total - free)} used / ${Formatter.formatFileSize(context, total)}"
        } ?: "Unavailable"

        return LocalDeviceSnapshot(
            title = Build.MODEL ?: "Android device",
            subtitle = "${Build.MANUFACTURER.orEmpty().replaceFirstChar { it.titlecase(Locale.getDefault()) }} Android ${Build.VERSION.RELEASE}",
            battery = if (battery > 0) "$battery%" else "Unknown",
            storage = storage,
            notificationAccess = if (notificationAccessEnabled) "Granted" else "Needs permission",
            galleryAccess = if (galleryAccessEnabled) "Granted" else "Needs permission",
            settings = listOf(
                "Wi-Fi" to if (isWifiEnabled()) "On" else "Off",
                "LAN" to if (isEthernetConnected()) "Connected" else "Unavailable",
                "USB" to if (isUsbConnected()) "Connected" else "Unavailable",
                "Bluetooth" to if (isBluetoothEnabled()) "On" else "Off",
                "Cloud" to if (hasInternetRoute()) "Available" else "Unavailable",
                "Battery saver" to if (isPowerSaveEnabled()) "On" else "Off",
                "Device name" to (Build.MODEL ?: "Android")
            )
        )
    }

    fun hasGalleryAccess(): Boolean {
        return if (Build.VERSION.SDK_INT >= 33) {
            ContextCompat.checkSelfPermission(context, android.Manifest.permission.READ_MEDIA_IMAGES) == PackageManager.PERMISSION_GRANTED
        } else {
            ContextCompat.checkSelfPermission(context, android.Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED
        }
    }

    fun buildRemoteSnapshotPayload(notificationAccessEnabled: Boolean, galleryAccessEnabled: Boolean): JSONObject {
        val snapshot = localSnapshot(notificationAccessEnabled, galleryAccessEnabled)
        return JSONObject()
            .put("device_title", snapshot.title)
            .put("device_subtitle", snapshot.subtitle)
            .put("battery", snapshot.battery)
            .put("storage", snapshot.storage)
            .put("notification_access", snapshot.notificationAccess)
            .put("gallery_access", snapshot.galleryAccess)
            .put("settings", JSONArray(snapshot.settings.map { JSONObject().put("label", it.first).put("value", it.second) }))
    }

    fun buildGalleryPayload(limit: Int = 18): JSONObject {
        return JSONObject()
            .put("items", queryRecentMedia(limit))
    }

    fun buildFilesPayload(limit: Int = 18): JSONObject {
        val recent = loadJsonArray("recent_received")
        val items = JSONArray()
        for (index in 0 until minOf(limit, recent.length())) {
            val item = recent.getJSONObject(index)
            if (item.optString("type") != "file") continue
            items.put(item)
        }
        return JSONObject().put("items", items)
    }

    fun buildNotificationsPayload(): JSONObject {
        return JSONObject()
            .put("permission_granted", NotificationCache.hasAccess(context))
            .put("items", NotificationCache.toJson())
    }

    fun recentReceived(): JSONArray = loadJsonArray("recent_received")

    private fun queryRecentMedia(limit: Int): JSONArray {
        val result = JSONArray()
        val recentReceived = recentReceived()
        for (index in 0 until recentReceived.length()) {
            val item = recentReceived.getJSONObject(index)
            if (item.optString("type") == "gallery") {
                result.put(item)
                if (result.length() >= limit) return result
            }
        }

        val projection = arrayOf(
            MediaStore.Images.Media.DISPLAY_NAME,
            MediaStore.Images.Media.DATE_ADDED,
            MediaStore.Images.Media.SIZE
        )
        context.contentResolver.query(
            MediaStore.Images.Media.EXTERNAL_CONTENT_URI,
            projection,
            null,
            null,
            "${MediaStore.Images.Media.DATE_ADDED} DESC"
        )?.use { cursor ->
            while (cursor.moveToNext() && result.length() < limit) {
                result.put(
                    JSONObject()
                        .put("name", cursor.string(MediaStore.Images.Media.DISPLAY_NAME))
                        .put("size", cursor.long(MediaStore.Images.Media.SIZE))
                        .put("received_at", cursor.long(MediaStore.Images.Media.DATE_ADDED) * 1000)
                        .put("type", "gallery")
                        .put("location", "Gallery")
                )
            }
        }
        return result
    }

    private fun saveToMediaStore(
        collection: Uri,
        directory: String,
        fileName: String,
        mimeType: String,
        bytes: ByteArray,
        type: String
    ): JSONObject {
        val contentValues = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, fileName)
            put(MediaStore.MediaColumns.MIME_TYPE, mimeType)
            put(MediaStore.MediaColumns.RELATIVE_PATH, directory)
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }

        val uri = requireNotNull(context.contentResolver.insert(collection, contentValues))
        context.contentResolver.openOutputStream(uri)?.use { it.write(bytes) }
        contentValues.clear()
        contentValues.put(MediaStore.MediaColumns.IS_PENDING, 0)
        context.contentResolver.update(uri, contentValues, null, null)

        MediaScannerConnection.scanFile(context, arrayOf(uri.toString()), arrayOf(mimeType), null)

        return JSONObject()
            .put("name", fileName)
            .put("size", bytes.size)
            .put("mime_type", mimeType)
            .put("location", directory)
            .put("uri", uri.toString())
            .put("type", type)
    }

    private fun loadJsonArray(key: String): JSONArray {
        val raw = prefs.getString(key, null) ?: return JSONArray()
        return runCatching { JSONArray(raw) }.getOrDefault(JSONArray())
    }

    private fun isWifiEnabled(): Boolean {
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as? android.net.wifi.WifiManager
        return wifi?.isWifiEnabled == true
    }

    private fun isBluetoothEnabled(): Boolean {
        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager
        val adapter = manager?.adapter
        return adapter?.isEnabled == true
    }

    private fun isEthernetConnected(): Boolean {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val capabilities = manager.getNetworkCapabilities(manager.activeNetwork) ?: return false
        return capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
    }

    private fun isUsbConnected(): Boolean {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val capabilities = manager.getNetworkCapabilities(manager.activeNetwork) ?: return false
        return capabilities.hasTransport(NetworkCapabilities.TRANSPORT_USB)
    }

    private fun hasInternetRoute(): Boolean {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
        val capabilities = manager.getNetworkCapabilities(manager.activeNetwork) ?: return false
        return capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    }

    private fun isPowerSaveEnabled(): Boolean {
        val manager = context.getSystemService(Context.POWER_SERVICE) as? android.os.PowerManager
        return manager?.isPowerSaveMode == true
    }

    private fun guessMimeType(fileName: String): String {
        val extension = fileName.substringAfterLast('.', "").lowercase(Locale.getDefault())
        return MimeTypeMap.getSingleton().getMimeTypeFromExtension(extension) ?: "application/octet-stream"
    }
}

private fun Cursor.string(column: String): String = getString(getColumnIndexOrThrow(column))
private fun Cursor.long(column: String): Long = getLong(getColumnIndexOrThrow(column))
