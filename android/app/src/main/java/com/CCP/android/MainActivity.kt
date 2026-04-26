package com.ccp.android

import android.Manifest
import android.content.ActivityNotFoundException
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.slideInVertically
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
import androidx.compose.material.icons.rounded.Visibility
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.delay
import org.json.JSONArray
import org.json.JSONObject

// ── Obsidian Color Tokens ──
private val Void = Color(0xFF000000)
private val Base = Color(0xFF0A0A0A)
private val Surface1 = Color(0xFF111111)
private val Surface2 = Color(0xFF171717)
private val Surface3 = Color(0xFF1E1E1E)
private val BorderClr = Color(0xFF262626)
private val TextPrim = Color(0xFFF5F5F5)
private val TextSec = Color(0xFFA3A3A3)
private val TextMut = Color(0xFF636363)
private val StatusGreen = Color(0xFF34D399)

private val ObsidianScheme = darkColorScheme(
    background = Void,
    surface = Surface1,
    surfaceVariant = Surface2,
    onBackground = TextPrim,
    onSurface = TextPrim,
    onSurfaceVariant = TextSec,
    primary = Color.White,
    onPrimary = Color.Black,
    outline = BorderClr
)

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
            MaterialTheme(colorScheme = ObsidianScheme) {
                Surface(Modifier.fillMaxSize(), color = Void) {
                    CcpScreen(
                        node = node,
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

// ── Reusable glass card ──
@Composable
fun ObsidianCard(modifier: Modifier = Modifier, content: @Composable () -> Unit) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(containerColor = Surface1),
        shape = RoundedCornerShape(14.dp),
        border = BorderStroke(1.dp, BorderClr)
    ) {
        content()
    }
}

@Composable
@OptIn(ExperimentalLayoutApi::class)
fun CcpScreen(
    node: CcpNode,
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
            node.sendFile(peer, uri)
        }
    }

    // Staggered entrance
    var visible by remember { mutableStateOf(false) }
    LaunchedEffect(Unit) { delay(100); visible = true }

    Column(
        Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        AnimatedVisibility(visible, enter = fadeIn(tween(350)) + slideInVertically(spring(Spring.DampingRatioLowBouncy)) { -20 }) {
            HeroCard(snapshot)
        }

        AnimatedVisibility(visible, enter = fadeIn(tween(350, 80)) + slideInVertically(spring(Spring.DampingRatioLowBouncy)) { -16 }) {
            StatsRow(snapshot)
        }

        AnimatedVisibility(visible, enter = fadeIn(tween(350, 160))) {
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
        }

        AnimatedVisibility(visible, enter = fadeIn(tween(350, 240))) {
            NearbyDevicesCard(peers = peers, onPair = { node.pair(it) }, onInspect = { node.inspectPeer(it) }, onSend = {
                selectedPeer = it
                picker.launch(arrayOf("*/*"))
            })
        }

        AnimatedVisibility(visible, enter = fadeIn(tween(350, 320))) {
            RemotePanelCard(remotePanel)
        }

        AnimatedVisibility(visible, enter = fadeIn(tween(350, 400))) {
            RecentTransfersCard(recentReceived)
        }

        AnimatedVisibility(visible, enter = fadeIn(tween(350, 480))) {
            ActivityCard(events)
        }
    }
}

@Composable
fun HeroCard(snapshot: LocalDeviceSnapshot) {
    ObsidianCard {
        Column(Modifier.fillMaxWidth().padding(18.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Text("CCP", color = TextPrim, fontSize = 22.sp, fontWeight = FontWeight.Bold)
                Box(Modifier.background(Surface3, RoundedCornerShape(50)).padding(horizontal = 8.dp, vertical = 2.dp)) {
                    Text("v0.2", color = TextMut, fontSize = 10.sp, fontWeight = FontWeight.Medium)
                }
            }
            Text("Cross-device control surface", color = TextSec, fontSize = 13.sp)
            Spacer(Modifier.height(4.dp))
            Text(snapshot.title, color = TextPrim, fontSize = 17.sp, fontWeight = FontWeight.SemiBold)
            Text(snapshot.subtitle, color = TextMut, fontSize = 12.sp)
        }
    }
}

@Composable
@OptIn(ExperimentalLayoutApi::class)
fun StatsRow(snapshot: LocalDeviceSnapshot) {
    ObsidianCard {
        Row(Modifier.fillMaxWidth()) {
            StatCell("Battery", snapshot.battery, Modifier.weight(1f))
            VertDiv()
            StatCell("Storage", snapshot.storage, Modifier.weight(1f))
            VertDiv()
            StatCell("Alerts", snapshot.notificationAccess, Modifier.weight(1f))
            VertDiv()
            StatCell("Gallery", snapshot.galleryAccess, Modifier.weight(1f))
        }
    }
}

@Composable
fun StatCell(label: String, value: String, modifier: Modifier = Modifier) {
    Column(modifier.padding(12.dp, 10.dp)) {
        Text(label, color = TextMut, fontSize = 10.sp)
        Text(value, color = TextPrim, fontSize = 14.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(top = 3.dp))
    }
}

@Composable
fun VertDiv() {
    Box(Modifier.width(1.dp).height(44.dp).background(BorderClr).padding(vertical = 8.dp))
}

@Composable
fun PermissionsCard(
    snapshot: LocalDeviceSnapshot,
    requestMediaAccess: () -> Unit,
    openNotificationAccess: () -> Unit,
    openAppNotificationSettings: () -> Unit
) {
    ObsidianCard {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Permissions", fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = TextPrim)
            Text("Enable gallery and notification access for full functionality.", color = TextMut, fontSize = 12.sp)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(onClick = requestMediaAccess, border = BorderStroke(1.dp, BorderClr), colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSec)) {
                    Icon(Icons.Rounded.Collections, null, Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Gallery", fontSize = 12.sp)
                }
                OutlinedButton(onClick = openNotificationAccess, border = BorderStroke(1.dp, BorderClr), colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSec)) {
                    Icon(Icons.Rounded.Notifications, null, Modifier.size(16.dp))
                    Spacer(Modifier.width(6.dp))
                    Text("Notifications", fontSize = 12.sp)
                }
                OutlinedButton(onClick = openAppNotificationSettings, border = BorderStroke(1.dp, BorderClr), colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSec)) {
                    Icon(Icons.Rounded.Settings, null, Modifier.size(16.dp))
                }
            }
            Text("Gallery ${snapshot.galleryAccess.lowercase()} · Notifications ${snapshot.notificationAccess.lowercase()}", color = TextMut, fontSize = 11.sp)
        }
    }
}

@Composable
fun NearbyDevicesCard(peers: List<DeviceInfo>, onPair: (DeviceInfo) -> Unit, onInspect: (DeviceInfo) -> Unit, onSend: (DeviceInfo) -> Unit) {
    ObsidianCard {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Nearby devices", fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = TextPrim)
            if (peers.isEmpty()) {
                Text("Scanning on local Wi-Fi…", color = TextMut, fontSize = 13.sp)
            } else {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
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
    ObsidianCard {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Connected device", fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = TextPrim)
            Text(panel.title, fontSize = 17.sp, fontWeight = FontWeight.Bold, color = TextPrim)
            Text(panel.subtitle, color = TextMut, fontSize = 12.sp)

            // Stats row
            Card(colors = CardDefaults.cardColors(containerColor = Surface2), shape = RoundedCornerShape(10.dp), border = BorderStroke(1.dp, BorderClr)) {
                Row(Modifier.fillMaxWidth()) {
                    StatCell("Battery", panel.battery, Modifier.weight(1f))
                    VertDiv()
                    StatCell("Storage", panel.storage, Modifier.weight(1f))
                    VertDiv()
                    StatCell("Alerts", panel.notificationAccess, Modifier.weight(1f))
                    VertDiv()
                    StatCell("Gallery", panel.galleryAccess, Modifier.weight(1f))
                }
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
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(title, fontWeight = FontWeight.SemiBold, color = TextSec, fontSize = 12.sp)
        if (items.isEmpty()) {
            Text("Nothing available yet.", color = TextMut, fontSize = 12.sp)
        } else {
            items.take(5).forEach { item ->
                Text(item, color = TextPrim, fontSize = 12.sp)
            }
        }
    }
}

@Composable
fun RecentTransfersCard(recentReceived: JSONArray) {
    ObsidianCard {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(10.dp)) {
            Text("Received files", fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = TextPrim)
            val items = jsonArrayToList(recentReceived)
            if (items.isEmpty()) {
                Text("Incoming files appear here after sync.", color = TextMut, fontSize = 12.sp)
            } else {
                items.take(6).forEach { item ->
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .border(1.dp, BorderClr, RoundedCornerShape(10.dp))
                            .padding(10.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(10.dp)
                    ) {
                        Box(Modifier.size(32.dp).background(Surface3, CircleShape), contentAlignment = Alignment.Center) {
                            Icon(
                                if (item.optString("type") == "gallery") Icons.Rounded.Collections else Icons.Rounded.Storage,
                                contentDescription = null, tint = TextSec, modifier = Modifier.size(16.dp)
                            )
                        }
                        Column(Modifier.weight(1f)) {
                            Text(item.optString("name"), fontWeight = FontWeight.Medium, color = TextPrim, fontSize = 13.sp)
                            Text(item.optString("location"), color = TextMut, fontSize = 11.sp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
fun ActivityCard(events: List<String>) {
    ObsidianCard {
        Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Activity", fontSize = 15.sp, fontWeight = FontWeight.SemiBold, color = TextPrim)
            events.reversed().takeLast(8).reversed().forEach { event ->
                Text(event, fontSize = 12.sp, color = TextMut)
            }
        }
    }
}

@Composable
fun DeviceRow(peer: DeviceInfo, onPair: () -> Unit, onInspect: () -> Unit, onSend: () -> Unit) {
    Row(
        Modifier
            .fillMaxWidth()
            .border(1.dp, BorderClr, RoundedCornerShape(10.dp))
            .padding(10.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Box(
            modifier = Modifier.size(34.dp).background(if (peer.trusted) Surface3 else Surface2, RoundedCornerShape(10.dp)),
            contentAlignment = Alignment.Center
        ) {
            Text(peer.platform.take(1).uppercase(), color = if (peer.trusted) TextPrim else TextMut, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        }
        Column(Modifier.weight(1f)) {
            Text(peer.deviceName, fontWeight = FontWeight.SemiBold, color = TextPrim, fontSize = 13.sp)
            Text("${peer.platform}  ${peer.primaryRouteLabel}", fontSize = 10.sp, color = TextMut)
            Text(peer.transportSummary, fontSize = 10.sp, color = TextSec, modifier = Modifier.padding(top = 2.dp))
        }
        OutlinedButton(onClick = onPair, border = BorderStroke(1.dp, BorderClr), colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSec), modifier = Modifier.height(32.dp)) {
            Text("Pair", fontSize = 11.sp)
        }
        OutlinedButton(onClick = onInspect, enabled = peer.trusted, border = BorderStroke(1.dp, BorderClr), colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSec), modifier = Modifier.height(32.dp)) {
            Icon(Icons.Rounded.Visibility, null, Modifier.size(15.dp))
        }
        Button(onClick = onSend, enabled = peer.trusted, colors = ButtonDefaults.buttonColors(containerColor = Color.White, contentColor = Color.Black, disabledContainerColor = Surface2, disabledContentColor = TextMut), modifier = Modifier.height(32.dp)) {
            Text("Send", fontSize = 11.sp, fontWeight = FontWeight.SemiBold)
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
