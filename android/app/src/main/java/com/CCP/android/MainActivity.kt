package com.ccp.android

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.paddingFromBaseline
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.Battery6Bar
import androidx.compose.material.icons.rounded.Collections
import androidx.compose.material.icons.rounded.DesktopWindows
import androidx.compose.material.icons.rounded.Notifications
import androidx.compose.material.icons.rounded.PermDeviceInformation
import androidx.compose.material.icons.rounded.Settings
import androidx.compose.material.icons.rounded.Storage
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.io.ByteArrayOutputStream
import org.json.JSONArray
import org.json.JSONObject

class MainActivity : ComponentActivity() {
    private lateinit var node: CcpNode

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        node = AppGraph.node(applicationContext)
        node.start()
        ContextCompat.startForegroundService(this, Intent(this, CcpForegroundService::class.java))
        if (Build.VERSION.SDK_INT >= 33) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 20)
        }
        setContent {
            MaterialTheme {
                Surface(Modifier.fillMaxSize(), color = Color(0xFFF3F5F8)) {
                    CcpScreen(
                        node = node,
                        readPickedFile = ::readPickedFile,
                        openNotificationAccess = ::openNotificationAccess,
                        openAppNotificationSettings = ::openAppNotificationSettings
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        node.refreshLocalData()
    }

    private fun readPickedFile(uri: Uri): Pair<String, ByteArray> {
        val name = contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
        } ?: "android-file-${System.currentTimeMillis()}"

        val bytes = contentResolver.openInputStream(uri).use { input ->
            val output = ByteArrayOutputStream()
            requireNotNull(input).copyTo(output)
            output.toByteArray()
        }
        return name to bytes
    }

    private fun openNotificationAccess() {
        val intent = Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS)
        try {
            startActivity(intent)
        } catch (_: ActivityNotFoundException) {
        }
    }

    private fun openAppNotificationSettings() {
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
            putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
        }
        startActivity(intent)
    }
}

@Composable
@OptIn(ExperimentalLayoutApi::class)
fun CcpScreen(
    node: CcpNode,
    readPickedFile: (Uri) -> Pair<String, ByteArray>,
    openNotificationAccess: () -> Unit,
    openAppNotificationSettings: () -> Unit
) {
    val peers by node.peers.collectAsState()
    val events by node.events.collectAsState()
    val snapshot by node.snapshot.collectAsState()
    val recentReceived by node.recentReceived.collectAsState()
    val remotePanel by node.remotePanel.collectAsState()
    var selectedPeer by remember { mutableStateOf<DeviceInfo?>(null) }
    val permissionLauncher = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        node.refreshLocalData()
    }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val peer = selectedPeer
        if (uri != null && peer != null) {
            val file = readPickedFile(uri)
            node.sendFile(peer, file.first, file.second)
        }
    }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(18.dp),
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        HeroCard(snapshot)

        FlowRow(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            StatusPill(Icons.Rounded.Battery6Bar, "Battery", snapshot.battery)
            StatusPill(Icons.Rounded.Storage, "Storage", snapshot.storage)
            StatusPill(Icons.Rounded.Notifications, "Alerts", snapshot.notificationAccess)
            StatusPill(Icons.Rounded.Collections, "Gallery", snapshot.galleryAccess)
        }

        PermissionsCard(
            snapshot = snapshot,
            requestMediaAccess = {
                val permissions = if (Build.VERSION.SDK_INT >= 33) {
                    arrayOf(Manifest.permission.READ_MEDIA_IMAGES, Manifest.permission.READ_MEDIA_VIDEO)
                } else {
                    arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE)
                }
                permissionLauncher.launch(permissions)
            },
            openNotificationAccess = openNotificationAccess,
            openAppNotificationSettings = openAppNotificationSettings
        )

        NearbyDevicesCard(peers = peers, onPair = { node.pair(it) }, onInspect = { node.inspectPeer(it) }, onSend = {
            selectedPeer = it
            picker.launch(arrayOf("*/*"))
        })

        RemotePanelCard(remotePanel)

        RecentTransfersCard(recentReceived)

        ActivityCard(events)
    }
}

@Composable
fun HeroCard(snapshot: LocalDeviceSnapshot) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color(0xFF101A2B)),
        shape = RoundedCornerShape(26.dp)
    ) {
        Column(Modifier.fillMaxWidth().padding(22.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("CCP", color = Color.White, style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
            Text("Cross-device control surface", color = Color(0xFFC7D2E2), style = MaterialTheme.typography.bodyLarge)
            Text(snapshot.title, color = Color.White, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.SemiBold)
            Text(snapshot.subtitle, color = Color(0xFF9FB0C9), style = MaterialTheme.typography.bodyMedium)
        }
    }
}

@Composable
fun StatusPill(icon: androidx.compose.ui.graphics.vector.ImageVector, label: String, value: String) {
    Card(
        colors = CardDefaults.cardColors(containerColor = Color.White),
        shape = RoundedCornerShape(18.dp),
        modifier = Modifier.width(160.dp)
    ) {
        Row(Modifier.padding(14.dp), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
            Box(Modifier.size(34.dp).background(Color(0xFFE9EEF8), CircleShape), contentAlignment = Alignment.Center) {
                Icon(icon, contentDescription = null, tint = Color(0xFF23416A), modifier = Modifier.size(18.dp))
            }
            Column {
                Text(label, color = Color(0xFF69788E), style = MaterialTheme.typography.bodySmall)
                Text(value, color = Color(0xFF17202E), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.SemiBold)
            }
        }
    }
}

@Composable
fun PermissionsCard(
    snapshot: LocalDeviceSnapshot,
    requestMediaAccess: () -> Unit,
    openNotificationAccess: () -> Unit,
    openAppNotificationSettings: () -> Unit
) {
    Card(colors = CardDefaults.cardColors(containerColor = Color.White), shape = RoundedCornerShape(22.dp)) {
        Column(Modifier.fillMaxWidth().padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Permissions and controls", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text("Turn on gallery and notification access so Windows can browse recent media and mirrored alerts.", color = Color(0xFF66758A))
            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                OutlinedButton(onClick = requestMediaAccess, border = BorderStroke(1.dp, Color(0xFFD8E1ED))) {
                    Icon(Icons.Rounded.Collections, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text("Gallery access")
                }
                OutlinedButton(onClick = openNotificationAccess, border = BorderStroke(1.dp, Color(0xFFD8E1ED))) {
                    Icon(Icons.Rounded.Notifications, contentDescription = null, modifier = Modifier.size(18.dp))
                    Text("Notification access")
                }
            }
            AssistChip(onClick = openAppNotificationSettings, label = { Text("App notifications") }, leadingIcon = {
                Icon(Icons.Rounded.Settings, contentDescription = null, modifier = Modifier.size(16.dp))
            })
            Text("Current: gallery ${snapshot.galleryAccess.lowercase()} and notifications ${snapshot.notificationAccess.lowercase()}.", color = Color(0xFF66758A))
        }
    }
}

@Composable
fun NearbyDevicesCard(peers: List<DeviceInfo>, onPair: (DeviceInfo) -> Unit, onInspect: (DeviceInfo) -> Unit, onSend: (DeviceInfo) -> Unit) {
    Card(colors = CardDefaults.cardColors(containerColor = Color.White), shape = RoundedCornerShape(22.dp)) {
        Column(Modifier.fillMaxWidth().padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Nearby devices", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            if (peers.isEmpty()) {
                Text("Scanning on local Wi-Fi for desktops and phones...", color = Color(0xFF687386), style = MaterialTheme.typography.bodyLarge)
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                    peers.forEach { peer ->
                        DeviceRow(peer = peer, onPair = { onPair(peer) }, onInspect = { onInspect(peer) }, onSend = { onSend(peer) })
                    }
                }
            }
        }
    }
}

@Composable
@OptIn(ExperimentalLayoutApi::class)
fun RemotePanelCard(panel: RemotePeerPanel?) {
    if (panel == null) return
    Card(colors = CardDefaults.cardColors(containerColor = Color.White), shape = RoundedCornerShape(22.dp)) {
        Column(Modifier.fillMaxWidth().padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Connected device panel", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Text(panel.title, style = MaterialTheme.typography.titleLarge, fontWeight = FontWeight.Bold, color = Color(0xFF17202E))
            Text(panel.subtitle, color = Color(0xFF66758A))
            FlowRow(horizontalArrangement = Arrangement.spacedBy(10.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
                StatusPill(Icons.Rounded.Battery6Bar, "Battery", panel.battery)
                StatusPill(Icons.Rounded.Storage, "Storage", panel.storage)
                StatusPill(Icons.Rounded.Notifications, "Alerts", panel.notificationAccess)
                StatusPill(Icons.Rounded.DesktopWindows, "Gallery", panel.galleryAccess)
            }
            SectionList("Settings", panel.settings.map { "${it.label}: ${it.value}" })
            SectionList("Gallery", panel.gallery.map { "${it.name}  ${it.subtitle}" })
            SectionList("Files", panel.files.map { "${it.name}  ${it.subtitle}" })
            SectionList("Notifications", panel.notifications.map { "${it.name}  ${it.subtitle}" })
        }
    }
}

@Composable
fun SectionList(title: String, items: List<String>) {
    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(title, fontWeight = FontWeight.SemiBold, color = Color(0xFF17202E))
        if (items.isEmpty()) {
            Text("Nothing available yet.", color = Color(0xFF66758A))
        } else {
            items.take(5).forEach { item ->
                Text(item, color = Color(0xFF3D4654))
            }
        }
    }
}

@Composable
fun RecentTransfersCard(recentReceived: JSONArray) {
    Card(colors = CardDefaults.cardColors(containerColor = Color.White), shape = RoundedCornerShape(22.dp)) {
        Column(Modifier.fillMaxWidth().padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Received on this phone", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            val items = jsonArrayToList(recentReceived)
            if (items.isEmpty()) {
                Text("Incoming files and photos will appear here after sync.", color = Color(0xFF687386))
            } else {
                items.take(6).forEach { item ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .border(1.dp, Color(0xFFE8ECF2), RoundedCornerShape(16.dp))
                            .padding(12.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        Box(Modifier.size(36.dp).background(Color(0xFFE7EEF8), CircleShape), contentAlignment = Alignment.Center) {
                            Icon(
                                if (item.optString("type") == "gallery") Icons.Rounded.Collections else Icons.Rounded.Storage,
                                contentDescription = null,
                                tint = Color(0xFF20406A),
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        Column(Modifier.weight(1f)) {
                            Text(item.optString("name"), fontWeight = FontWeight.SemiBold, color = Color(0xFF17202E))
                            Text(item.optString("location"), color = Color(0xFF66758A), style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ActivityCard(events: List<String>) {
    Card(colors = CardDefaults.cardColors(containerColor = Color.White), shape = RoundedCornerShape(22.dp)) {
        Column(Modifier.fillMaxWidth().padding(18.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
            Text("Activity", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                events.reversed().takeLast(8).reversed().forEach { event ->
                    Text(event, style = MaterialTheme.typography.bodyMedium, color = Color(0xFF3D4654))
                }
            }
        }
    }
}

@Composable
fun DeviceRow(peer: DeviceInfo, onPair: () -> Unit, onInspect: () -> Unit, onSend: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .border(1.dp, Color(0xFFE8ECF2), RoundedCornerShape(18.dp))
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Box(
            modifier = Modifier.size(42.dp).background(if (peer.trusted) Color(0xFF2F8F6B) else Color(0xFF6E7E96), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Text(peer.platform.take(1).uppercase(), color = Color.White, fontWeight = FontWeight.Bold)
        }
        Column(Modifier.weight(1f)) {
            Text(peer.deviceName, fontWeight = FontWeight.SemiBold, color = Color(0xFF17202E))
            Text("${peer.platform}  ${peer.host}:${peer.tcpPort}", style = MaterialTheme.typography.bodySmall, color = Color(0xFF687386))
        }
        OutlinedButton(onClick = onPair, border = BorderStroke(1.dp, Color(0xFFD8E1ED))) {
            Icon(Icons.Rounded.Link, contentDescription = null, modifier = Modifier.size(18.dp))
            Text("Pair")
        }
        OutlinedButton(onClick = onInspect, border = BorderStroke(1.dp, Color(0xFFD8E1ED)), enabled = peer.trusted) {
            Icon(Icons.Rounded.PermDeviceInformation, contentDescription = null, modifier = Modifier.size(18.dp))
            Text("Inspect")
        }
        Button(onClick = onSend, enabled = peer.trusted) {
            Icon(Icons.AutoMirrored.Rounded.Send, contentDescription = null, modifier = Modifier.size(18.dp))
            Text("Send")
        }
    }
}

private fun jsonArrayToList(array: JSONArray): List<JSONObject> {
    val list = ArrayList<JSONObject>(array.length())
    for (index in 0 until array.length()) {
        list.add(array.getJSONObject(index))
    }
    return list
}
