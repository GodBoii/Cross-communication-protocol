package com.ccp.android

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat

class CcpForegroundService : Service() {
    override fun onCreate() {
        super.onCreate()
        createChannel()
        AppGraph.node(this).start()
        startForeground(
            1001,
            NotificationCompat.Builder(this, CHANNEL_ID)
                .setContentTitle("CCP is connected")
                .setContentText("Discovery and transfers are active on your local network.")
                .setSmallIcon(android.R.drawable.stat_sys_upload_done)
                .setOngoing(true)
                .build()
        )
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        AppGraph.node(this).stop()
        super.onDestroy()
    }

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
    }
}
