package com.ccp.android

import android.Manifest
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.OpenableColumns
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.core.content.ContextCompat
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.Send
import androidx.compose.material.icons.rounded.Link
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
                Surface(Modifier.fillMaxSize(), color = Color(0xFFF7F8FA)) {
                    CcpScreen(node, ::readPickedFile)
                }
            }
        }
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
}

@Composable
fun CcpScreen(node: CcpNode, readPickedFile: (Uri) -> Pair<String, ByteArray>) {
    val peers by node.peers.collectAsState()
    val events by node.events.collectAsState()
    var selectedPeer by remember { mutableStateOf<DeviceInfo?>(null) }
    val picker = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        val peer = selectedPeer
        if (uri != null && peer != null) {
            val file = readPickedFile(uri)
            node.sendFile(peer, file.first, file.second)
        }
    }

    Column(Modifier.fillMaxSize().padding(18.dp), verticalArrangement = Arrangement.spacedBy(14.dp)) {
        Text("CCP", style = MaterialTheme.typography.headlineMedium, fontWeight = FontWeight.Bold)
        Text("Local device bridge", style = MaterialTheme.typography.bodyMedium, color = Color(0xFF5A6472))

        Card(colors = CardDefaults.cardColors(containerColor = Color.White), elevation = CardDefaults.cardElevation(1.dp)) {
            Column(Modifier.fillMaxWidth().padding(16.dp)) {
                Text("Nearby devices", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(10.dp))
                if (peers.isEmpty()) {
                    Text("Scanning on local Wi-Fi...", color = Color(0xFF687386))
                } else {
                    LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        items(peers) { peer ->
                            DeviceRow(
                                peer = peer,
                                onPair = { node.pair(peer) },
                                onSend = {
                                    selectedPeer = peer
                                    picker.launch(arrayOf("*/*"))
                                }
                            )
                        }
                    }
                }
            }
        }

        Card(
            modifier = Modifier.weight(1f),
            colors = CardDefaults.cardColors(containerColor = Color.White),
            elevation = CardDefaults.cardElevation(1.dp)
        ) {
            Column(Modifier.fillMaxSize().padding(16.dp)) {
                Text("Activity", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(8.dp))
                LazyColumn(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    items(events.reversed()) { event ->
                        Text(event, style = MaterialTheme.typography.bodySmall, color = Color(0xFF3D4654))
                    }
                }
            }
        }
    }
}

@Composable
fun DeviceRow(peer: DeviceInfo, onPair: () -> Unit, onSend: () -> Unit) {
    Row(
        Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Box(
            modifier = Modifier.size(38.dp).background(if (peer.trusted) Color(0xFF2F8F6B) else Color(0xFF6E7E96), CircleShape),
            contentAlignment = Alignment.Center
        ) {
            Text(peer.platform.take(1).uppercase(), color = Color.White, fontWeight = FontWeight.Bold)
        }
        Column(Modifier.weight(1f)) {
            Text(peer.deviceName, fontWeight = FontWeight.SemiBold)
            Text("${peer.platform}  ${peer.host}:${peer.tcpPort}", style = MaterialTheme.typography.bodySmall, color = Color(0xFF687386))
        }
        OutlinedButton(onClick = onPair) {
            Icon(Icons.Rounded.Link, contentDescription = null, modifier = Modifier.size(18.dp))
            Text("Pair")
        }
        Button(onClick = onSend, enabled = peer.trusted) {
            Icon(Icons.AutoMirrored.Rounded.Send, contentDescription = null, modifier = Modifier.size(18.dp))
            Text("Send")
        }
    }
}
