package com.ccp.android

import android.content.Context
import android.content.Intent
import android.database.Cursor
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import android.provider.OpenableColumns
import android.telecom.TelecomManager
import android.util.Base64
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import org.json.JSONArray
import org.json.JSONObject
import java.io.BufferedReader
import java.io.BufferedWriter
import java.io.File
import java.io.FileOutputStream
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import kotlin.random.Random

class CcpNode(private val context: Context) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val store = PeerStore(context)
    private val deviceData = DeviceDataRepository(context)
    private val peersById = linkedMapOf<String, DeviceInfo>()
    private val cloudIncomingTransfers = ConcurrentHashMap<String, CloudIncomingTransfer>()
    @Volatile private var running = false
    private var multicastLock: WifiManager.MulticastLock? = null

    // ── Convex cloud bridge ──────────────────────────────────────────────────
    val convexBridge = ConvexBridge(
        context = context,
        deviceId = store.deviceId,
        deviceName = store.deviceName,
        platform = "android",
        onMessage = { msg -> handleConvexMessage(msg) },
    )

    private val _peers = MutableStateFlow<List<DeviceInfo>>(emptyList())
    val peers: StateFlow<List<DeviceInfo>> = _peers

    private val _events = MutableStateFlow<List<String>>(listOf("Ready as ${store.deviceName}"))
    val events: StateFlow<List<String>> = _events

    private val _snapshot = MutableStateFlow(
        deviceData.localSnapshot(
            notificationAccessEnabled = NotificationCache.hasAccess(context),
            galleryAccessEnabled = deviceData.hasGalleryAccess()
        )
    )
    val snapshot: StateFlow<LocalDeviceSnapshot> = _snapshot

    private val _recentReceived = MutableStateFlow(deviceData.recentReceived())
    val recentReceived: StateFlow<JSONArray> = _recentReceived

    private val _remotePanel = MutableStateFlow<RemotePeerPanel?>(null)
    val remotePanel: StateFlow<RemotePeerPanel?> = _remotePanel

    private val _preferredTransports = MutableStateFlow<Map<String, String>>(emptyMap())
    val preferredTransports: StateFlow<Map<String, String>> = _preferredTransports

    fun start() {
        if (running) return
        running = true
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        multicastLock = wifi.createMulticastLock("ccp-discovery").apply {
            setReferenceCounted(false)
            acquire()
        }
        scope.launch { broadcastDiscovery() }
        scope.launch { listenDiscovery() }
        scope.launch { listenTcp() }
        refreshLocalData()
        // Start Convex cloud bridge
        scope.launch {
            convexBridge.start(
                appVersion = "0.2.0",
                capabilities = listOf(
                    "pairing", "file.transfer", "remote.action",
                    "device.snapshot", "gallery.list", "notifications.list",
                    "foreground.service"
                )
            )
        }
        scope.launch { cloudPeerLoop() }
        log("Native Android node started on UDP $CCP_UDP_PORT and TCP $CCP_TCP_PORT")
    }

    fun stop() {
        running = false
        convexBridge.stop()
        multicastLock?.release()
        multicastLock = null
        log("Native Android node stopped")
    }

    fun pair(peer: DeviceInfo) {
        scope.launch {
            val code = Random.nextInt(0, 999999).toString().padStart(6, '0')
            log("Pair request sent to ${peer.deviceName}. Code $code")
            val response = sendSingle(
                peer,
                ccpEnvelope("pair.request", store.sender(), JSONObject()
                    .put("pair_code", code)
                    // Include our X25519 public key so peer can do key exchange immediately
                    .put("public_key", convexBridge.publicKeyB64))
            )
            if (response?.optJSONObject("payload")?.optBoolean("accepted") == true) {
                store.trust(JSONObject()
                    .put("device_id", peer.deviceId)
                    .put("device_name", peer.deviceName)
                    .put("platform", peer.platform))
                updatePeer(peer.copy(trusted = true))
                log("Paired with ${peer.deviceName}")
                // Trigger cloud key exchange after successful WiFi pairing
                scope.launch { deferredKeyExchange(peer.deviceId) }
            } else {
                log("Pairing rejected by ${peer.deviceName}")
            }
        }
    }

    /** Fetch peer's public key from Convex and complete key exchange. */
    private suspend fun deferredKeyExchange(peerDeviceId: String) {
        repeat(5) { attempt ->
            kotlinx.coroutines.delay(1000L * (1 shl attempt))
            val pubKey = convexBridge.getPeerPublicKey(peerDeviceId)
            if (pubKey != null) {
                val fp = convexBridge.completeKeyExchange(peerDeviceId, pubKey, "wifi")
                log("Cloud key exchange OK for ${peerDeviceId.take(8)}… (fp: ${fp.take(12)}…)")
                return
            }
        }
        log("Key exchange failed for ${peerDeviceId.take(8)}… after 5 attempts")
    }

    fun sendFile(peer: DeviceInfo, uri: Uri) {
        scope.launch {
            if (!peer.trusted) {
                log("Pair with ${peer.deviceName} before sending files.")
                return@launch
            }

            if (peer.isCloudPeer) {
                sendFileViaCloud(peer, uri)
                return@launch
            }

            val fileName = resolveDisplayName(uri)
            val (size, fullHash) = context.contentResolver.openInputStream(uri).use { input ->
                requireNotNull(input) { "Could not open selected file" }
                sha256Hex(input)
            }
            val totalChunks = ((size + CCP_CHUNK_SIZE - 1) / CCP_CHUNK_SIZE).toInt()
            val transferId = java.util.UUID.randomUUID().toString()

            connectPeer(peer).use { socket ->
                val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
                val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream()))
                write(writer, ccpEnvelope("file.offer", store.sender(), JSONObject()
                    .put("transfer_id", transferId)
                    .put("filename", fileName)
                    .put("size", size)
                    .put("sha256", fullHash)
                    .put("chunk_size", CCP_CHUNK_SIZE)
                    .put("total_chunks", totalChunks)))

                val offerResponse = JSONObject(reader.readLine())
                if (!offerResponse.getJSONObject("payload").optBoolean("accepted")) {
                    log("${peer.deviceName} rejected $fileName")
                    return@use
                }

                val buffer = ByteArray(CCP_CHUNK_SIZE)
                var sent = 0L
                var index = 0
                context.contentResolver.openInputStream(uri).use { input ->
                    requireNotNull(input) { "Could not reopen selected file" }
                    while (true) {
                        val read = input.read(buffer)
                        if (read <= 0) break
                        val chunk = if (read == buffer.size) buffer.copyOf() else buffer.copyOfRange(0, read)
                        write(writer, ccpEnvelope("file.chunk", store.sender(), JSONObject()
                            .put("transfer_id", transferId)
                            .put("index", index)
                            .put("sha256", sha256Hex(chunk))
                            .put("data_b64", Base64.encodeToString(chunk, Base64.NO_WRAP))))
                        sent += read
                        index += 1
                        log("Sending $fileName: $sent / $size bytes")
                    }
                }

                write(writer, ccpEnvelope("file.complete", store.sender(), JSONObject()
                    .put("transfer_id", transferId)
                    .put("sha256", fullHash)))
                val complete = JSONObject(reader.readLine())
                log(if (complete.getJSONObject("payload").optBoolean("ok")) "Sent and verified $fileName" else "Receiver verification failed for $fileName")
            }
        }
    }

    fun inspectPeer(peer: DeviceInfo) {
        scope.launch {
            if (!peer.trusted) {
                log("Pair with ${peer.deviceName} before loading its panel.")
                return@launch
            }
            if (peer.isCloudPeer) {
                inspectPeerViaCloud(peer)
                return@launch
            }
            val snapshot = sendSingle(peer, ccpEnvelope("device.snapshot.request", store.sender(), JSONObject()))
            val gallery = sendSingle(peer, ccpEnvelope("gallery.list.request", store.sender(), JSONObject()))
            val files = sendSingle(peer, ccpEnvelope("files.list.request", store.sender(), JSONObject()))
            val notifications = sendSingle(peer, ccpEnvelope("notifications.list.request", store.sender(), JSONObject()))
            _remotePanel.value = RemotePeerPanel(
                title = snapshot?.optJSONObject("payload")?.optString("device_title") ?: peer.deviceName,
                subtitle = snapshot?.optJSONObject("payload")?.optString("device_subtitle") ?: peer.platform,
                battery = snapshot?.optJSONObject("payload")?.optString("battery") ?: "Unknown",
                storage = snapshot?.optJSONObject("payload")?.optString("storage") ?: "Unknown",
                notificationAccess = snapshot?.optJSONObject("payload")?.optString("notification_access") ?: "Unknown",
                galleryAccess = snapshot?.optJSONObject("payload")?.optString("gallery_access") ?: "Unknown",
                settings = parseFacts(snapshot?.optJSONObject("payload")?.optJSONArray("settings")),
                gallery = parseEntries(gallery?.optJSONObject("payload")?.optJSONArray("items"), "Gallery"),
                files = parseEntries(files?.optJSONObject("payload")?.optJSONArray("items"), "Files"),
                notifications = parseNotifications(notifications?.optJSONObject("payload"))
            )
            log("Loaded panel for ${peer.deviceName}")
        }
    }

    private suspend fun sendFileViaCloud(peer: DeviceInfo, uri: Uri) {
        val fileName = resolveDisplayName(uri)
        val (size, fullHash) = context.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Could not open selected file" }
            sha256Hex(input)
        }
        val totalChunks = ((size + CCP_CHUNK_SIZE - 1) / CCP_CHUNK_SIZE).toInt()
        val transferId = java.util.UUID.randomUUID().toString()

        log("Cloud offering $fileName to ${peer.deviceName}")
        val offer = convexBridge.sendCloudRequest(peer.deviceId, "file.offer", JSONObject()
            .put("transfer_id", transferId)
            .put("filename", fileName)
            .put("size", size)
            .put("sha256", fullHash)
            .put("chunk_size", CCP_CHUNK_SIZE)
            .put("total_chunks", totalChunks), timeoutMs = 30_000)

        if (offer?.optBoolean("accepted") != true) {
            val reason = offer?.optString("reason")?.takeIf { it.isNotBlank() }
            log("${peer.deviceName} rejected $fileName${if (reason == null) "" else ": $reason"}")
            return
        }

        val buffer = ByteArray(CCP_CHUNK_SIZE)
        var sent = 0L
        var index = 0
        context.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Could not reopen selected file" }
            while (true) {
                val read = input.read(buffer)
                if (read <= 0) break
                val chunk = if (read == buffer.size) buffer.copyOf() else buffer.copyOfRange(0, read)
                val ok = convexBridge.pushMessage(peer.deviceId, "file.chunk", JSONObject()
                    .put("transfer_id", transferId)
                    .put("index", index)
                    .put("sha256", sha256Hex(chunk))
                    .put("data_b64", Base64.encodeToString(chunk, Base64.NO_WRAP)), ttlMs = 10 * 60 * 1000)
                if (!ok) {
                    log("Cloud send failed while sending chunk $index of $fileName")
                    return
                }
                sent += read
                index += 1
                log("Cloud sending $fileName: $sent / $size bytes")
            }
        }

        val complete = convexBridge.sendCloudRequest(peer.deviceId, "file.complete", JSONObject()
            .put("transfer_id", transferId)
            .put("sha256", fullHash), timeoutMs = 30_000)
        log(if (complete?.optBoolean("ok") == true) "Cloud sent and verified $fileName" else "Cloud receiver verification failed for $fileName")
    }

    private suspend fun inspectPeerViaCloud(peer: DeviceInfo) {
        log("Loading panel for ${peer.deviceName} via cloud relay")
        val snapshot = convexBridge.sendCloudRequest(peer.deviceId, "device.snapshot.request", timeoutMs = 20_000)
        val gallery = convexBridge.sendCloudRequest(peer.deviceId, "gallery.list.request", timeoutMs = 20_000)
        val files = convexBridge.sendCloudRequest(peer.deviceId, "files.list.request", timeoutMs = 20_000)
        val notifications = convexBridge.sendCloudRequest(peer.deviceId, "notifications.list.request", timeoutMs = 20_000)
        _remotePanel.value = RemotePeerPanel(
            title = snapshot?.optString("device_title") ?: peer.deviceName,
            subtitle = snapshot?.optString("device_subtitle") ?: peer.platform,
            battery = snapshot?.optString("battery") ?: "Unknown",
            storage = snapshot?.optString("storage") ?: "Unknown",
            notificationAccess = snapshot?.optString("notification_access") ?: "Unknown",
            galleryAccess = snapshot?.optString("gallery_access") ?: "Unknown",
            settings = parseFacts(snapshot?.optJSONArray("settings")),
            gallery = parseEntries(gallery?.optJSONArray("items"), "Gallery"),
            files = parseEntries(files?.optJSONArray("items"), "Files"),
            notifications = parseNotifications(notifications)
        )
        log("Loaded cloud panel for ${peer.deviceName}")
    }

    fun setPreferredTransport(deviceId: String, transport: String?) {
        _preferredTransports.value = _preferredTransports.value.toMutableMap().apply {
            if (transport.isNullOrBlank() || transport == "auto") remove(deviceId) else put(deviceId, transport)
        }
    }

    private suspend fun broadcastDiscovery() {
        DatagramSocket().use { socket ->
            socket.broadcast = true
            while (running) {
                try {
                    val data = ccpDiscovery(
                        store.sender(),
                        buildTransportPayload(),
                        buildEndpointPayload()
                    ).toString().toByteArray()
                    broadcastTargets().forEach { target ->
                        runCatching {
                            socket.send(DatagramPacket(data, data.size, target, CCP_UDP_PORT))
                        }.onFailure {
                            log("Discovery send failed on ${target.hostAddress}: ${it.message}")
                        }
                    }
                } catch (e: Exception) {
                    log("Discovery broadcast failed: ${e.message}")
                }
                pruneStalePeers()
                delay(3000)
            }
        }
    }

    private fun listenDiscovery() {
        DatagramSocket(CCP_UDP_PORT).use { socket ->
            socket.soTimeout = 2000
            val buffer = ByteArray(8192)
            while (running) {
                try {
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    val json = JSONObject(String(packet.data, 0, packet.length))
                    if (json.optString("protocol") != CCP_PROTOCOL || json.optString("device_id") == store.deviceId) continue
                    updatePeer(
                        DeviceInfo(
                            deviceId = json.getString("device_id"),
                            deviceName = json.optString("device_name", "Unknown"),
                            platform = json.optString("platform", "unknown"),
                            host = packet.address.hostAddress ?: "",
                            tcpPort = json.optInt("tcp_port", CCP_TCP_PORT),
                            trusted = store.isTrusted(json.getString("device_id")),
                            transports = parseTransports(json.optJSONObject("transports")),
                            routes = parseRoutes(json.optJSONArray("endpoints"), packet.address.hostAddress ?: "", json.optInt("tcp_port", CCP_TCP_PORT))
                        )
                    )
                } catch (_: SocketTimeoutException) {
                } catch (e: Exception) {
                    log("Discovery receive failed: ${e.message}")
                }
            }
        }
    }

    private fun listenTcp() {
        ServerSocket(CCP_TCP_PORT).use { server ->
            server.soTimeout = 2000
            log("TCP listener active on $CCP_TCP_PORT")
            while (running) {
                try {
                    val socket = server.accept()
                    scope.launch { handleClient(socket) }
                } catch (_: SocketTimeoutException) {
                }
            }
        }
    }

    private fun handleClient(socket: Socket) {
        socket.use {
            it.tcpNoDelay = true
            val reader = BufferedReader(InputStreamReader(it.getInputStream()))
            val writer = BufferedWriter(OutputStreamWriter(it.getOutputStream()))
            var activeFile: File? = null
            var activeOutput: FileOutputStream? = null
            var expectedHash: String? = null
            try {
                while (true) {
                    val line = reader.readLine() ?: break
                    val message = JSONObject(line)
                    val sender = message.getJSONObject("sender")
                    when (message.optString("type")) {
                        "pair.request" -> {
                            store.trust(sender)
                            write(writer, ccpEnvelope("pair.response", store.sender(), JSONObject()
                                .put("accepted", true)
                                .put("reason", JSONObject.NULL)))
                            log("Accepted pair request from ${sender.optString("device_name")}")
                            // Perform cloud key exchange using the public key from the pair packet
                            val peerPubKey = message.optJSONObject("payload")?.optString("public_key") ?: ""
                            val peerDeviceId = sender.getString("device_id")
                            if (peerPubKey.isNotBlank() && peerPubKey != "reserved-for-v1") {
                                scope.launch {
                                    convexBridge.completeKeyExchange(peerDeviceId, peerPubKey, "wifi")
                                    log("Cloud key exchange with ${sender.optString("device_name")} complete")
                                }
                            } else {
                                scope.launch { deferredKeyExchange(peerDeviceId) }
                            }
                        }
                        "file.offer" -> {
                            val payload = message.getJSONObject("payload")
                            if (!store.isTrusted(sender.getString("device_id"))) {
                                write(writer, ccpEnvelope("file.offer.response", store.sender(), JSONObject()
                                    .put("transfer_id", payload.optString("transfer_id"))
                                    .put("accepted", false)
                                    .put("resume_from", 0)
                                    .put("reason", "peer is not paired")))
                            } else {
                                activeOutput?.close()
                                val inbox = File(context.getExternalFilesDir(null), "CCP-Inbox").apply { mkdirs() }
                                activeFile = uniqueFile(inbox, safeFilename(payload.optString("filename", "received-file")))
                                expectedHash = payload.optString("sha256")
                                activeOutput = FileOutputStream(activeFile, false)
                                write(writer, ccpEnvelope("file.offer.response", store.sender(), JSONObject()
                                    .put("transfer_id", payload.optString("transfer_id"))
                                    .put("accepted", true)
                                    .put("resume_from", 0)
                                    .put("reason", JSONObject.NULL)))
                                log("Receiving ${activeFile.name}")
                            }
                        }
                        "file.chunk" -> {
                            val payload = message.getJSONObject("payload")
                            val chunk = Base64.decode(payload.getString("data_b64"), Base64.NO_WRAP)
                            if (sha256Hex(chunk) != payload.getString("sha256")) error("Chunk checksum mismatch")
                            activeOutput?.write(chunk)
                            log("Received chunk ${payload.optInt("index")}")
                        }
                        "file.complete" -> {
                            activeOutput?.close()
                            activeOutput = null
                            val bytes = activeFile?.readBytes()
                            val ok = bytes?.let { data -> sha256Hex(data) == expectedHash } == true
                            if (ok && activeFile != null && bytes != null) {
                                val saved = deviceData.saveIncomingFile(activeFile.name, bytes)
                                _recentReceived.value = deviceData.recentReceived()
                                refreshLocalData()
                                log("Saved shared copy to ${saved.optString("location")}")
                            }
                            write(writer, ccpEnvelope("file.complete.response", store.sender(), JSONObject()
                                .put("transfer_id", message.getJSONObject("payload").optString("transfer_id"))
                                .put("ok", ok)))
                            log(if (ok) "Received and verified ${activeFile?.name}" else "Received file checksum failed")
                        }
                        "device.snapshot.request" -> {
                            write(writer, ccpEnvelope("device.snapshot.response", store.sender(), deviceData.buildRemoteSnapshotPayload(
                                notificationAccessEnabled = NotificationCache.hasAccess(context),
                                galleryAccessEnabled = deviceData.hasGalleryAccess()
                            )))
                        }
                        "gallery.list.request" -> {
                            write(writer, ccpEnvelope("gallery.list.response", store.sender(), deviceData.buildGalleryPayload()))
                        }
                        "files.list.request" -> {
                            write(writer, ccpEnvelope("files.list.response", store.sender(), deviceData.buildFilesPayload()))
                        }
                        "notifications.list.request" -> {
                            write(writer, ccpEnvelope("notifications.list.response", store.sender(), deviceData.buildNotificationsPayload()))
                        }
                        "remote.action.request" -> {
                            val payload = message.getJSONObject("payload")
                            val action = payload.optString("action")
                            val args = payload.optJSONObject("args") ?: JSONObject()
                            val result = performRemoteAction(action, args)
                            write(writer, ccpEnvelope("remote.action.response", store.sender(), JSONObject()
                                .put("ok", result.first)
                                .put("message", result.second)))
                        }
                    }
                }
            } finally {
                activeOutput?.close()
            }
        }
    }

    private fun sendSingle(peer: DeviceInfo, message: JSONObject): JSONObject? {
        return connectPeer(peer).use { socket ->
            val reader = BufferedReader(InputStreamReader(socket.getInputStream()))
            val writer = BufferedWriter(OutputStreamWriter(socket.getOutputStream()))
            write(writer, message)
            JSONObject(reader.readLine())
        }
    }

    private fun connectPeer(peer: DeviceInfo): Socket {
        val rankedRoutes = rankRoutes(peer)
        var lastError: Exception? = null
        for (route in rankedRoutes) {
            try {
                val socket = Socket()
                socket.tcpNoDelay = true
                socket.connect(java.net.InetSocketAddress(route.host, route.tcpPort), 2500)
                log("Connected to ${peer.deviceName} via ${route.transport}")
                return socket
            } catch (ex: Exception) {
                lastError = ex
            }
        }
        throw IllegalStateException("Could not connect to ${peer.deviceName}: ${lastError?.message}", lastError)
    }

    private fun rankRoutes(peer: DeviceInfo): List<ConnectionRoute> {
        val routes = if (peer.routes.isEmpty()) {
            listOf(ConnectionRoute("direct", peer.host, peer.tcpPort))
        } else {
            peer.routes
        }
        val priority = mapOf("usb" to 0, "wifi" to 1, "lan" to 2, "bluetooth" to 3, "cloud" to 4, "direct" to 5)
        val preferred = _preferredTransports.value[peer.deviceId]
        return routes
            .distinctBy { "${it.transport}|${it.host}|${it.tcpPort}" }
            .sortedWith(compareBy<ConnectionRoute> { if (!preferred.isNullOrBlank() && it.transport == preferred) 0 else 1 }
                .thenBy { priority[it.transport] ?: 99 })
    }

    private fun write(writer: BufferedWriter, message: JSONObject) {
        writer.write(message.toString())
        writer.newLine()
        writer.flush()
    }

    private fun updatePeer(peer: DeviceInfo) {
        peersById[peer.deviceId] = peer.copy(lastSeen = System.currentTimeMillis())
        _peers.value = peersById.values.sortedByDescending { it.lastSeen }
    }

    private suspend fun cloudPeerLoop() {
        delay(2_000)
        while (running) {
            loadCloudPeers()
            delay(15_000)
        }
    }

    private fun loadCloudPeers() {
        val sessions = convexBridge.listPairedPeers() ?: return
        var loaded = 0
        for (index in 0 until sessions.length()) {
            val session = sessions.optJSONObject(index) ?: continue
            val peerId = session.optString("peer_id")
            if (peerId.isBlank()) continue

            val existing = peersById[peerId]
            if (existing != null && !existing.isCloudPeer) continue

            convexBridge.loadSessionFromCloud(peerId)
            val info = convexBridge.getPeerDeviceInfo(peerId)
            val presence = convexBridge.getPeerPresence(peerId)
            updatePeer(
                DeviceInfo(
                    deviceId = peerId,
                    deviceName = info?.optString("device_name")?.takeIf { it.isNotBlank() } ?: "Cloud device ${peerId.take(8)}",
                    platform = info?.optString("platform")?.takeIf { it.isNotBlank() } ?: "unknown",
                    host = "127.0.0.1",
                    tcpPort = 0,
                    trusted = true,
                    transports = listOf("cloud"),
                    routes = emptyList(),
                    isCloudPeer = true,
                    cloudOnline = presence?.optBoolean("online") == true,
                )
            )
            loaded += 1
        }
        if (loaded > 0) log("Loaded $loaded cloud peer(s)")
    }

    private fun pruneStalePeers() {
        val cutoff = System.currentTimeMillis() - 20_000
        val iterator = peersById.iterator()
        var changed = false
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (!entry.value.isCloudPeer && entry.value.lastSeen < cutoff) {
                iterator.remove()
                changed = true
            }
        }
        if (changed) {
            _peers.value = peersById.values.sortedByDescending { it.lastSeen }
        }
    }

    private fun broadcastTargets(): List<InetAddress> {
        val targets = linkedSetOf(InetAddress.getByName("255.255.255.255"))
        NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
            .filter { it.isUp && !it.isLoopback }
            .forEach { network ->
                network.interfaceAddresses
                    .mapNotNull { it.broadcast }
                    .forEach { targets.add(it) }
            }
        return targets.toList()
    }

    private fun safeFilename(name: String): String {
        val invalid = charArrayOf('<', '>', ':', '"', '/', '\\', '|', '?', '*')
        val clean = buildString(name.length) {
            name.forEach { append(if (it in invalid) '_' else it) }
        }.trim()
        return clean.ifEmpty { "received-file" }
    }

    private fun uniqueFile(dir: File, fileName: String): File {
        var candidate = File(dir, fileName)
        if (!candidate.exists()) return candidate
        val dot = fileName.lastIndexOf('.')
        val stem = if (dot > 0) fileName.substring(0, dot) else fileName
        val ext = if (dot > 0) fileName.substring(dot) else ""
        var index = 1
        while (candidate.exists()) {
            candidate = File(dir, "$stem-$index$ext")
            index += 1
        }
        return candidate
    }

    private fun log(message: String) {
        _events.value = (_events.value + message).takeLast(80)
    }

    /** Handle a message received from the Convex cloud relay. */
    private fun handleConvexMessage(msg: ConvexMessage) {
        val senderShort = msg.senderId.take(8)
        val requestId = msg.payload.optString("request_id", "")

        when (msg.msgType) {
            "device.snapshot.request" -> {
                log("[Cloud] Snapshot request from $senderShort…")
                scope.launch {
                    val response = deviceData.buildRemoteSnapshotPayload(
                        notificationAccessEnabled = NotificationCache.hasAccess(context),
                        galleryAccessEnabled = deviceData.hasGalleryAccess()
                    )
                    if (requestId.isNotBlank()) response.put("request_id", requestId)
                    convexBridge.pushMessage(msg.senderId, "device.snapshot.response", response)
                }
            }

            "gallery.list.request" -> {
                log("[Cloud] Gallery request from $senderShort…")
                scope.launch {
                    val response = deviceData.buildGalleryPayload()
                    if (requestId.isNotBlank()) response.put("request_id", requestId)
                    convexBridge.pushMessage(msg.senderId, "gallery.list.response", response)
                }
            }

            "files.list.request" -> {
                log("[Cloud] Files request from $senderShort…")
                scope.launch {
                    val response = deviceData.buildFilesPayload()
                    if (requestId.isNotBlank()) response.put("request_id", requestId)
                    convexBridge.pushMessage(msg.senderId, "files.list.response", response)
                }
            }

            "notifications.list.request" -> {
                log("[Cloud] Notifications request from $senderShort…")
                scope.launch {
                    val response = deviceData.buildNotificationsPayload()
                    if (requestId.isNotBlank()) response.put("request_id", requestId)
                    convexBridge.pushMessage(msg.senderId, "notifications.list.response", response)
                }
            }

            "remote.action.request" -> {
                val action = msg.payload.optString("action")
                val args = msg.payload.optJSONObject("args") ?: JSONObject()
                log("[Cloud] Remote action from $senderShort…: $action")
                scope.launch {
                    val result = performRemoteAction(action, args)
                    val response = JSONObject()
                        .put("ok", result.first)
                        .put("message", result.second)
                        .put("action", action)
                    if (requestId.isNotBlank()) response.put("request_id", requestId)
                    convexBridge.pushMessage(msg.senderId, "remote.action.response", response)
                }
            }

            "file.offer" -> {
                val filename = msg.payload.optString("filename", "?")
                log("[Cloud] File offer from $senderShort…: $filename")
                scope.launch {
                    val transferId = msg.payload.optString("transfer_id", java.util.UUID.randomUUID().toString())
                    val response = JSONObject()
                        .put("transfer_id", transferId)
                        .put("accepted", false)
                        .put("resume_from", 0)
                    if (requestId.isNotBlank()) response.put("request_id", requestId)

                    if (!store.isTrusted(msg.senderId)) {
                        response.put("reason", "peer is not paired")
                        convexBridge.pushMessage(msg.senderId, "file.offer.response", response)
                        return@launch
                    }

                    val inbox = File(context.getExternalFilesDir(null), "CCP-Inbox").apply { mkdirs() }
                    val target = uniqueFile(inbox, safeFilename(filename))
                    val output = FileOutputStream(target, false)
                    cloudIncomingTransfers["${msg.senderId}|$transferId"] = CloudIncomingTransfer(
                        file = target,
                        expectedHash = msg.payload.optString("sha256"),
                        output = output,
                    )
                    response.put("accepted", true).put("reason", JSONObject.NULL)
                    convexBridge.pushMessage(msg.senderId, "file.offer.response", response)
                    log("[Cloud] Receiving ${target.name}")
                }
            }

            "file.chunk" -> {
                val transferId = msg.payload.optString("transfer_id")
                val transfer = cloudIncomingTransfers["${msg.senderId}|$transferId"] ?: return
                val chunk = Base64.decode(msg.payload.getString("data_b64"), Base64.NO_WRAP)
                if (sha256Hex(chunk) != msg.payload.getString("sha256")) {
                    log("[Cloud] Chunk checksum failed for ${transfer.file.name}")
                    return
                }
                synchronized(transfer) {
                    transfer.output.write(chunk)
                }
                log("[Cloud] Received chunk ${msg.payload.optInt("index")}")
            }

            "file.complete" -> {
                val transferId = msg.payload.optString("transfer_id")
                val response = JSONObject()
                    .put("transfer_id", transferId)
                    .put("ok", false)
                if (requestId.isNotBlank()) response.put("request_id", requestId)

                val transfer = cloudIncomingTransfers.remove("${msg.senderId}|$transferId")
                if (transfer != null) {
                    val bytes: ByteArray
                    synchronized(transfer) {
                        transfer.output.close()
                        bytes = transfer.file.readBytes()
                    }
                    val expected = msg.payload.optString("sha256", transfer.expectedHash)
                    val actual = sha256Hex(bytes)
                    val ok = actual == expected && expected == transfer.expectedHash
                    response.put("ok", ok).put("sha256", actual)
                    if (ok) {
                        val saved = deviceData.saveIncomingFile(transfer.file.name, bytes)
                        _recentReceived.value = deviceData.recentReceived()
                        refreshLocalData()
                        log("[Cloud] Saved shared copy to ${saved.optString("location")}")
                    }
                    log(if (ok) "[Cloud] Received and verified ${transfer.file.name}" else "[Cloud] File checksum failed for ${transfer.file.name}")
                }
                scope.launch { convexBridge.pushMessage(msg.senderId, "file.complete.response", response) }
            }

            "clipboard.sync" -> {
                log("[Cloud] Clipboard sync from $senderShort…")
            }

            "notification.push" -> {
                val title = msg.payload.optString("title", "Notification")
                log("[Cloud] Notification from $senderShort…: $title")
            }

            "heartbeat" -> {
                log("[Cloud] Heartbeat from $senderShort…")
            }

            else -> {
                log("[Cloud] ${msg.msgType} from $senderShort…")
            }
        }
    }

    fun refreshLocalData() {
        _snapshot.value = deviceData.localSnapshot(
            notificationAccessEnabled = NotificationCache.hasAccess(context),
            galleryAccessEnabled = deviceData.hasGalleryAccess()
        )
        _recentReceived.value = deviceData.recentReceived()
    }

    private fun parseFacts(array: JSONArray?): List<RemoteFactItem> {
        if (array == null) return emptyList()
        val list = ArrayList<RemoteFactItem>(array.length())
        for (index in 0 until array.length()) {
            val item = array.getJSONObject(index)
            list.add(RemoteFactItem(item.optString("label"), item.optString("value")))
        }
        return list
    }

    private fun parseEntries(array: JSONArray?, fallback: String): List<RemoteEntryItem> {
        if (array == null) return emptyList()
        val list = ArrayList<RemoteEntryItem>(array.length())
        for (index in 0 until array.length()) {
            val item = array.getJSONObject(index)
            list.add(RemoteEntryItem(item.optString("name", fallback), item.optString("location", item.optString("text", fallback))))
        }
        return list
    }

    private fun parseNotifications(payload: JSONObject?): List<RemoteEntryItem> {
        val array = payload?.optJSONArray("items") ?: return emptyList()
        val list = ArrayList<RemoteEntryItem>(array.length())
        for (index in 0 until array.length()) {
            val item = array.getJSONObject(index)
            list.add(RemoteEntryItem(item.optString("title", "Notification"), item.optString("text", "")))
        }
        return list
    }

    private fun buildTransportPayload(): JSONObject {
        val statuses = detectTransportStatus()
        return JSONObject().apply {
            statuses.forEach { (name, status) ->
                put(name, JSONObject()
                    .put("available", status.available)
                    .put("connected", status.connected)
                    .put("detail", status.detail))
            }
        }
    }

    private fun buildEndpointPayload(): JSONArray {
        return JSONArray().apply {
            detectAdvertisedRoutes().forEach { route ->
                put(JSONObject()
                    .put("transport", route.transport)
                    .put("host", route.host)
                    .put("port", route.tcpPort))
            }
        }
    }

    private fun parseTransports(transports: JSONObject?): List<String> {
        if (transports == null) return emptyList()
        val names = ArrayList<String>()
        transports.keys().forEach { key ->
            val item = transports.optJSONObject(key) ?: return@forEach
            if (item.optBoolean("available")) names.add(key)
        }
        return names
    }

    private fun parseRoutes(endpoints: JSONArray?, fallbackHost: String, fallbackPort: Int): List<ConnectionRoute> {
        if (endpoints == null || endpoints.length() == 0) {
            return listOf(ConnectionRoute("direct", fallbackHost, fallbackPort))
        }

        val routes = ArrayList<ConnectionRoute>(endpoints.length())
        for (index in 0 until endpoints.length()) {
            val item = endpoints.optJSONObject(index) ?: continue
            val host = item.optString("host")
            val transport = item.optString("transport", "direct")
            val port = item.optInt("port", fallbackPort)
            if (host.isNotBlank()) {
                routes.add(ConnectionRoute(transport, host, port))
            }
        }
        if (routes.isEmpty()) {
            routes.add(ConnectionRoute("direct", fallbackHost, fallbackPort))
        }
        return routes
    }

    private data class TransportStatus(val available: Boolean, val connected: Boolean, val detail: String)

    private fun detectTransportStatus(): Map<String, TransportStatus> {
        val manager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val active = manager.activeNetwork
        val capabilities = manager.getNetworkCapabilities(active)
        val adapters = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty().filter { it.isUp }

        val wifi = adapters.filter { it.name.contains("wlan", true) || it.name.contains("wifi", true) }
        val lan = adapters.filter { it.name.contains("eth", true) }
        val usb = adapters.filter { it.name.contains("usb", true) || it.name.contains("rndis", true) }
        val bluetooth = adapters.filter { it.name.contains("bt", true) || it.displayName?.contains("bluetooth", true) == true }
        val cloud = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true

        return mapOf(
            "wifi" to TransportStatus(
                available = wifi.isNotEmpty() || capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true,
                connected = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true,
                detail = wifi.firstOrNull()?.displayName ?: "Unavailable"
            ),
            "lan" to TransportStatus(
                available = lan.isNotEmpty() || capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true,
                connected = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true,
                detail = lan.firstOrNull()?.displayName ?: "Unavailable"
            ),
            "usb" to TransportStatus(
                available = usb.isNotEmpty() || capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_USB) == true,
                connected = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_USB) == true,
                detail = usb.firstOrNull()?.displayName ?: "Unavailable"
            ),
            "bluetooth" to TransportStatus(
                available = bluetooth.isNotEmpty() || capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) == true,
                connected = capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) == true,
                detail = bluetooth.firstOrNull()?.displayName ?: "Unavailable"
            ),
            "cloud" to TransportStatus(
                available = cloud,
                connected = cloud,
                detail = if (cloud) "Internet-capable network present" else "Unavailable"
            )
        )
    }

    private fun detectAdvertisedRoutes(): List<ConnectionRoute> {
        val routes = ArrayList<ConnectionRoute>()
        val interfaces = NetworkInterface.getNetworkInterfaces()?.toList().orEmpty()
        interfaces.filter { it.isUp }.forEach { network ->
            val transport = classifyTransport(network)
            network.inetAddresses.toList()
                .filter { address -> !address.isLoopbackAddress && address.hostAddress?.contains(':') == false }
                .forEach { address ->
                    val host = address.hostAddress
                    if (!host.isNullOrBlank()) {
                        routes.add(ConnectionRoute(transport, host, CCP_TCP_PORT))
                    }
                }
        }
        return routes.distinctBy { "${it.transport}|${it.host}|${it.tcpPort}" }
    }

    private fun classifyTransport(network: NetworkInterface): String {
        val name = "${network.name} ${network.displayName.orEmpty()}".lowercase(Locale.getDefault())
        return when {
            "usb" in name || "rndis" in name -> "usb"
            "wlan" in name || "wifi" in name -> "wifi"
            "eth" in name -> "lan"
            "bluetooth" in name || "bt" in name -> "bluetooth"
            else -> "cloud"
        }
    }

    private fun resolveDisplayName(uri: Uri): String {
        return context.contentResolver.query(uri, null, null, null, null)?.use { cursor ->
            val index = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (index >= 0 && cursor.moveToFirst()) cursor.getString(index) else null
        } ?: "android-file-${System.currentTimeMillis()}"
    }

    private fun performRemoteAction(action: String, args: JSONObject): Pair<Boolean, String> {
        return runCatching {
            when (action) {
                "settings.wifi" -> {
                    val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        Intent(Settings.Panel.ACTION_WIFI)
                    } else {
                        Intent(Settings.ACTION_WIFI_SETTINGS)
                    }
                    launchIntent(intent)
                    true to "Opened Wi-Fi panel on Android"
                }
                "settings.bluetooth" -> {
                    launchIntent(Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
                    true to "Opened Bluetooth settings on Android"
                }
                "settings.location" -> {
                    launchIntent(Intent(Settings.ACTION_LOCATION_SOURCE_SETTINGS))
                    true to "Opened Location settings on Android"
                }
                "settings.notifications" -> {
                    launchIntent(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
                        putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                    })
                    true to "Opened notification settings on Android"
                }
                "call.dial" -> {
                    val number = args.optString("number").trim()
                    require(number.isNotBlank()) { "Phone number is required." }
                    launchIntent(Intent(Intent.ACTION_DIAL, Uri.parse("tel:$number")))
                    true to "Opened Android dialer for $number"
                }
                "call.answer" -> {
                    answerIncomingCall()
                    true to "Answered incoming call on Android"
                }
                else -> false to "Unsupported remote action: $action"
            }
        }.getOrElse { false to (it.message ?: "Remote action failed") }
    }

    private fun launchIntent(intent: Intent) {
        intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        context.startActivity(intent)
    }

    private fun answerIncomingCall() {
        val telecom = context.getSystemService(Context.TELECOM_SERVICE) as? TelecomManager
            ?: error("Telecom service unavailable")
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            telecom.acceptRingingCall()
        } else {
            error("Incoming call control requires Android 8.0 or newer")
        }
    }
}

private fun Cursor.string(column: String): String = getString(getColumnIndexOrThrow(column))

private data class CloudIncomingTransfer(
    val file: File,
    val expectedHash: String,
    val output: FileOutputStream,
)
