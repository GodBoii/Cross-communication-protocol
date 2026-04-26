package com.ccp.android

import android.content.Context
import android.database.Cursor
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.net.wifi.WifiManager
import android.provider.OpenableColumns
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
import kotlin.random.Random

class CcpNode(private val context: Context) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val store = PeerStore(context)
    private val deviceData = DeviceDataRepository(context)
    private val peersById = linkedMapOf<String, DeviceInfo>()
    @Volatile private var running = false
    private var multicastLock: WifiManager.MulticastLock? = null

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
        log("Native Android node started on UDP $CCP_UDP_PORT and TCP $CCP_TCP_PORT")
    }

    fun stop() {
        running = false
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
                    .put("public_key", "reserved-for-v1"))
            )
            if (response?.optJSONObject("payload")?.optBoolean("accepted") == true) {
                store.trust(JSONObject()
                    .put("device_id", peer.deviceId)
                    .put("device_name", peer.deviceName)
                    .put("platform", peer.platform))
                updatePeer(peer.copy(trusted = true))
                log("Paired with ${peer.deviceName}")
            } else {
                log("Pairing rejected by ${peer.deviceName}")
            }
        }
    }

    fun sendFile(peer: DeviceInfo, uri: Uri) {
        scope.launch {
            if (!peer.trusted) {
                log("Pair with ${peer.deviceName} before sending files.")
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

    private suspend fun broadcastDiscovery() {
        DatagramSocket().use { socket ->
            socket.broadcast = true
            while (running) {
                val data = ccpDiscovery(
                    store.sender(),
                    buildTransportPayload(),
                    buildEndpointPayload()
                ).toString().toByteArray()
                socket.send(DatagramPacket(data, data.size, InetAddress.getByName("255.255.255.255"), CCP_UDP_PORT))
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
            var expectedHash: String? = null
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
                            val inbox = File(context.getExternalFilesDir(null), "CCP-Inbox").apply { mkdirs() }
                            activeFile = uniqueFile(inbox, safeFilename(payload.optString("filename", "received-file")))
                            expectedHash = payload.optString("sha256")
                            activeFile.writeBytes(ByteArray(0))
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
                        activeFile?.appendBytes(chunk)
                        log("Received chunk ${payload.optInt("index")}")
                    }
                    "file.complete" -> {
                        val ok = activeFile?.readBytes()?.let { bytes -> sha256Hex(bytes) == expectedHash } == true
                        if (ok && activeFile != null) {
                            val saved = deviceData.saveIncomingFile(activeFile.name, activeFile.readBytes())
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
                }
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
        return routes
            .distinctBy { "${it.transport}|${it.host}|${it.tcpPort}" }
            .sortedBy { priority[it.transport] ?: 99 }
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

    private fun pruneStalePeers() {
        val cutoff = System.currentTimeMillis() - 20_000
        val iterator = peersById.iterator()
        var changed = false
        while (iterator.hasNext()) {
            val entry = iterator.next()
            if (entry.value.lastSeen < cutoff) {
                iterator.remove()
                changed = true
            }
        }
        if (changed) {
            _peers.value = peersById.values.sortedByDescending { it.lastSeen }
        }
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
}

private fun Cursor.string(column: String): String = getString(getColumnIndexOrThrow(column))
