package com.ccp.android

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat

/**
 * Keeps discovery, the LAN listener and the cloud relay alive while the app
 * is in the background.
 *
 * Uses the connectedDevice foreground-service type: CCP maintains links to
 * the user's other devices. (dataSync, used before, is capped at 6 hours a
 * day for apps targeting Android 15.)
 */
class CcpForegroundService : Service() {
    override fun onCreate() {
        super.onCreate()
        createChannel()
        try {
            ServiceCompat.startForeground(this, NOTIFICATION_ID, buildNotification(), foregroundType())
        } catch (e: Exception) {
            // e.g. ForegroundServiceStartNotAllowedException if started from the background.
            Log.w(TAG, "Could not enter the foreground; stopping", e)
            stopSelf()
            return
        }
        AppGraph.node(this).start()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int = START_STICKY

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        AppGraph.node(this).stop()
        super.onDestroy()
    }

    private fun foregroundType(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE else 0

    private fun buildNotification() = NotificationCompat.Builder(this, CHANNEL_ID)
        .setContentTitle("CCP is connected")
        .setContentText("Discovery and transfers are active on your local network.")
        .setSmallIcon(android.R.drawable.stat_sys_upload_done)
        .setOngoing(true)
        .setCategory(NotificationCompat.CATEGORY_SERVICE)
        .setContentIntent(
            PendingIntent.getActivity(
                this,
                0,
                Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
                PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
            )
        )
        .build()

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "CCP connectivity",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    companion object {
        const val CHANNEL_ID = "ccp_connectivity"
        private const val NOTIFICATION_ID = 1001
        private const val TAG = "CcpForegroundService"
    }
}
