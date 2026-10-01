package com.ccp.android

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification

class CcpNotificationListener : NotificationListenerService() {
    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val extras = sbn.notification.extras
        NotificationCache.add(
            packageName = sbn.packageName,
            title = extras?.getCharSequence("android.title")?.toString(),
            text = extras?.getCharSequence("android.text")?.toString()
        )
    }
}

