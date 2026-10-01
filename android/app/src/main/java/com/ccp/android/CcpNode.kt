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
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/** An inbound pairing waiting for the user to compare codes. */
data class PendingPairRequest(
    val deviceId: String,
    val deviceName: String,
    val platform: String,
    val pairCode: String,
    val alreadyPaired: Boolean = false,
)

/** An outbound pairing: show this code so the other device's user can compare. */
data class OutgoingPairCode(
    val deviceId: String,
    val deviceName: String,
    val code: String,
)

private val PANEL_REQUESTS = listOf(
    "device.snapshot.request",
    "gallery.list.request",
    "files.list.request",
    "notifications.list.request",
)

private const val MAX_CLOUD_TRANSFERS = 4

class CcpNode(private val context: Context) {
    // Any exception escaping a coroutine would otherwise reach the default
    // uncaught-exception handler and kill the process; a malformed packet from
    // the LAN must never be able to do that.
    private val crashGuard = CoroutineExceptionHandler { _, error ->
        log("Internal error: ${error.javaClass.simpleName}: ${error.message}")
    }
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO + crashGuard)
    private var nodeJob: Job? = null
    private val connectionSlots = Semaphore(MAX_CONCURRENT_CONNECTIONS)
    @Volatile private var tcpServer: ServerSocket? = null
    @Volatile private var udpSocket: DatagramSocket? = null
    private val store = PeerStore(context)
    private val deviceData = DeviceDataRepository(context)
    private val peersById = linkedMapOf<String, DeviceInfo>()
    private val peerLock = Any()
    private val cloudIncomingTransfers = ConcurrentHashMap<String, IncomingTransfer>()
    private val pendingPairApprovals = ConcurrentHashMap<String, CompletableDeferred<Boolean>>()
    private val pairingBusy = AtomicBoolean(false)
    private val inspectInFlight = ConcurrentHashMap.newKeySet<String>()
    private val lastSessionSync = ConcurrentHashMap<String, Long>()
    @Volatile private var outgoingPairSocket: Socket? = null
    @Volatile private var running = false
    private var multicastLock: WifiManager.MulticastLock? = null

    // ── Convex cloud bridge ──────────────────────────────────────────────────
    val convexBridge = ConvexBridge(
        context = context,
        convexUrl = BuildConfig.CONVEX_URL,
        deviceId = store.deviceId,
        deviceName = store.deviceName,
        cloudAuthToken = store.cloudAuthToken,
        platform = "android",
        pairSecretFor = { id -> store.pairSecretBytes(id) },
        onLog = { message -> log("[Cloud] $message") },
        onMessage = { msg -> handleConvexMessage(msg) },
    )

    private val _outgoingPair = MutableStateFlow<OutgoingPairCode?>(null)
    val outgoingPair: StateFlow<OutgoingPairCode?> = _outgoingPair

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

    private val _pendingPairRequest = MutableStateFlow<PendingPairRequest?>(null)
    val pendingPairRequest: StateFlow<PendingPairRequest?> = _pendingPairRequest

    fun approvePendingPair(deviceId: String) {
        pendingPairApprovals.remove(deviceId)?.complete(true)
        _pendingPairRequest.value = null
    }

    fun rejectPendingPair(deviceId: String) {
        pendingPairApprovals.remove(deviceId)?.complete(false)
        _pendingPairRequest.value = null
    }

    @Synchronized
    fun start() {
        if (running) return
        running = true
        val wifi = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
        multicastLock = wifi.createMulticastLock("ccp-discovery").apply {
            setReferenceCounted(false)
            acquire()
        }
        val job = SupervisorJob(scope.coroutineContext[Job])
        nodeJob = job
        scope.launch(job) { broadcastDiscovery() }
        scope.launch(job) { resilient("UDP discovery listener") { listenDiscovery() } }
        scope.launch(job) { resilient("TCP listener") { listenTcp() } }
        scope.launch(job) { cleanupInbox() }
        refreshLocalData()
        // Start Convex cloud bridge
        scope.launch(job) {
            convexBridge.start(
                appVersion = BuildConfig.VERSION_NAME,
                capabilities = listOf(
                    "pairing", "file.transfer", "remote.action",
                    "device.snapshot", "gallery.list", "notifications.list",
                    "foreground.service"
                )
            )
        }
        scope.launch(job) { cloudPeerLoop() }
        log("Native Android node started on UDP $CCP_UDP_PORT and TCP $CCP_TCP_PORT")
    }

    @Synchronized
    fun stop() {
        if (!running) return
        running = false
        convexBridge.stop()
        // Closing the sockets unblocks accept()/receive() immediately so a
        // quick restart doesn't race the old listeners for the ports.
        runCatching { tcpServer?.close() }
        runCatching { udpSocket?.close() }
        tcpServer = null
        udpSocket = null
        nodeJob?.cancel()
        nodeJob = null
        runCatching { multicastLock?.release() }
        multicastLock = null
        log("Native Android node stopped")
    }

    /**
     * Runs a long-lived listener, restarting it with backoff if it fails
     * (e.g. the port is briefly still bound after a restart).
     */
    private suspend fun resilient(name: String, block: suspend () -> Unit) {
        var backoffMs = 1_000L
        while (running && kotlin.coroutines.coroutineContext.isActive) {
            try {
                block()
                backoffMs = 1_000L
            } catch (e: Exception) {
                if (!running) return
                log("$name failed: ${e.message}; retrying in ${backoffMs / 1000}s")
                delay(backoffMs)
                backoffMs = (backoffMs * 2).coerceAtMost(30_000L)
            }
        }
    }

    /** Launches user-initiated work, reporting failures in the event log. */
    private fun launchTask(label: String, block: suspend CoroutineScope.() -> Unit): Job =
        scope.launch {
            try {
                block()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                log("$label failed: ${e.message}")
            }
        }

    /**
     * Initiates v1 pairing: ECDH with a commitment, then both screens show the
     * same 6-digit code and the peer's user approves only if they match.
     */
    fun pair(peer: DeviceInfo) {
        launchTask("Pairing with ${peer.deviceName}") {
            if (peer.isCloudPeer) {
                log("Pair with ${peer.deviceName} on the same network first.")
                return@launchTask
            }
            val socket = connectPeer(peer)
            outgoingPairSocket = socket
            try {
                socket.use { runInitiatorPairing(it, peer) }
            } finally {
                outgoingPairSocket = null
                _outgoingPair.update { if (it?.deviceId == peer.deviceId) null else it }
            }
        }
    }

    /**
     * Forgets a peer: deletes its pair secret (so its sessions and relay
     * messages are refused from now on) and revokes the relay session.
     */
    fun unpair(peer: DeviceInfo) {
        store.forget(peer.deviceId)
        lastSessionSync.remove(peer.deviceId)
        synchronized(peerLock) {
            if (peer.isCloudPeer) {
                peersById.remove(peer.deviceId)
            } else {
                peersById[peer.deviceId]?.let { peersById[peer.deviceId] = it.copy(trusted = false) }
            }
            _peers.value = peersById.values.sortedByDescending { it.lastSeen }
        }
        _remotePanel.value = null
        log("Unpaired ${peer.deviceName}")
        launchTask("Revoking Long Distance for ${peer.deviceName}") {
            if (!convexBridge.revokeSession(peer.deviceId)) {
                log("Long Distance session for ${peer.deviceName} will stay until the relay is reachable; it can no longer be decrypted here.")
            }
        }
    }

    fun cancelOutgoingPair() {
        runCatching { outgoingPairSocket?.close() }
        _outgoingPair.value = null
    }

    private fun runInitiatorPairing(socket: Socket, peer: DeviceInfo) {
        val reader = BoundedLineReader(socket.getInputStream())
        val writer = LineWriter(socket.getOutputStream())
        val initiator = PairingInitiator(store.deviceId)
        write(writer, ccpEnvelope("pair.request", store.sender(), initiator.requestPayload()))

        val challenge = JSONObject(reader.readLine() ?: error("Connection closed during pairing"))
        if (challenge.optString("type") == "pair.response") {
            log("${peer.deviceName} refused pairing: ${challenge.optJSONObject("payload")?.optString("reason")}")
            return
        }
        check(challenge.optString("type") == "pair.challenge") { "Unexpected pairing message" }
        val responderId = challenge.optJSONObject("sender")?.optString("device_id")
        check(responderId == peer.deviceId) { "Peer identity changed during pairing" }
        val result = initiator.onChallenge(peer.deviceId, challenge.optJSONObject("payload") ?: JSONObject())
        write(writer, ccpEnvelope("pair.reveal", store.sender(), initiator.revealPayload()))

        _outgoingPair.value = OutgoingPairCode(peer.deviceId, peer.deviceName, result.sas)
        log("Check that ${peer.deviceName} shows code ${result.sas}")

        val response = JSONObject(reader.readLine() ?: error("Connection closed before approval"))
        val payload = response.optJSONObject("payload") ?: JSONObject()
        if (response.optString("type") != "pair.response" || !payload.optBoolean("accepted")) {
            log("Pairing rejected by ${peer.deviceName}: ${payload.optString("reason", "rejected")}")
            return
        }
        check(result.verifyResponderConfirm(payload.optString("confirm"))) { "Key confirmation failed; pairing aborted" }

        store.trust(JSONObject()
            .put("device_id", peer.deviceId)
            .put("device_name", peer.deviceName)
            .put("platform", peer.platform), result.pairSecret)
        updatePeer(peer.copy(trusted = true))
        log("Paired with ${peer.deviceName}")
        scope.launch { establishCloudSession(peer.deviceId, result.pairSecret) }
    }

    /** Registers the pairing with the cloud relay so Long Distance works later. */
    private suspend fun establishCloudSession(peerDeviceId: String, pairSecret: ByteArray) {
        repeat(4) { attempt ->
            if (convexBridge.storeSession(peerDeviceId, pairSecret)) {
                log("Long Distance ready for ${peerDeviceId.take(8)}…")
                return
            }
            delay(5_000L * (1 shl attempt))
        }
        log("Long Distance setup for ${peerDeviceId.take(8)}… deferred; will retry in the background")
    }

    /** Opens an authenticated, encrypted session with a paired LAN peer. */
    private fun openSecureSession(peer: DeviceInfo): SecureConnection {
        val secret = store.pairSecretBytes(peer.deviceId)
            ?: error("Not paired with ${peer.deviceName}; pair again")
        val socket = connectPeer(peer)
        return try {
            LanHandshake.client(socket, store.sender(), peer.deviceId, secret)
        } catch (e: SessionRefusedException) {
            socket.close()
            if (e.reason == "not_paired") {
                error("${peer.deviceName} no longer trusts this device; pair again")
            }
            throw e
        } catch (e: Exception) {
            socket.close()
            throw e
        }
    }

    fun sendFile(peer: DeviceInfo, uri: Uri) {
        launchTask("Sending file to ${peer.deviceName}") {
            if (!peer.trusted) {
                log("Pair with ${peer.deviceName} before sending files.")
                return@launchTask
            }
            if (peer.isCloudPeer) {
                sendFileViaCloud(peer, uri)
                return@launchTask
            }

            val fileName = resolveDisplayName(uri)
            val (size, fullHash) = hashUri(uri)
            check(size <= CCP_MAX_FILE_BYTES) { "$fileName is larger than ${CCP_MAX_FILE_BYTES / (1024 * 1024)} MB" }
            val totalChunks = chunkCount(size, CCP_CHUNK_SIZE)
            val transferId = java.util.UUID.randomUUID().toString()

            openSecureSession(peer).use { conn ->
                val offer = conn.request(ccpEnvelope("file.offer", store.sender(), JSONObject()
                    .put("transfer_id", transferId)
                    .put("filename", fileName)
                    .put("size", size)
                    .put("sha256", fullHash)
                    .put("chunk_size", CCP_CHUNK_SIZE)
                    .put("total_chunks", totalChunks)))
                val offerPayload = offer.optJSONObject("payload") ?: JSONObject()
                if (!offerPayload.optBoolean("accepted")) {
                    log("${peer.deviceName} rejected $fileName: ${offerPayload.optString("reason", "rejected")}")
                    return@use
                }

                val progress = ProgressReporter(size) { log("Sending $fileName: $it%") }
                var sent = 0L
                var index = 0
                streamChunks(uri) { chunk ->
                    conn.send(ccpEnvelope("file.chunk", store.sender(), JSONObject()
                        .put("transfer_id", transferId)
                        .put("index", index)
                        .put("sha256", sha256Hex(chunk))
                        .put("data_b64", Base64.encodeToString(chunk, Base64.NO_WRAP))))
                    sent += chunk.size
                    index += 1
                    progress.update(sent)
                    true
                }

                val complete = conn.request(ccpEnvelope("file.complete", store.sender(), JSONObject()
                    .put("transfer_id", transferId)
                    .put("sha256", fullHash)))
                val ok = complete.optJSONObject("payload")?.optBoolean("ok") == true
                log(if (ok) "Sent and verified $fileName" else "${peer.deviceName} could not verify $fileName")
            }
        }
    }

    private fun hashUri(uri: Uri): Pair<Long, String> =
        context.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Could not open selected file" }
            sha256Hex(input)
        }

    /** Reads the URI in CCP_CHUNK_SIZE pieces; [onChunk] returns false to stop early. */
    private inline fun streamChunks(uri: Uri, onChunk: (ByteArray) -> Boolean) {
        val buffer = ByteArray(CCP_CHUNK_SIZE)
        context.contentResolver.openInputStream(uri).use { input ->
            requireNotNull(input) { "Could not reopen selected file" }
            while (true) {
                var filled = 0
                // Fill whole chunks so chunk count matches the offer even for slow providers.
                while (filled < buffer.size) {
                    val read = input.read(buffer, filled, buffer.size - filled)
                    if (read <= 0) break
                    filled += read
                }
                if (filled == 0) break
                if (!onChunk(buffer.copyOf(filled))) break
                if (filled < buffer.size) break
            }
        }
    }

    fun inspectPeer(peer: DeviceInfo) {
        if (!inspectInFlight.add(peer.deviceId)) return // a refresh is already running
        launchTask("Loading panel for ${peer.deviceName}") {
            try {
                if (!peer.trusted) {
                    log("Pair with ${peer.deviceName} before loading its panel.")
                    return@launchTask
                }
                if (peer.isCloudPeer) {
                    inspectPeerViaCloud(peer)
                    return@launchTask
                }
                val responses = openSecureSession(peer).use { conn ->
                    PANEL_REQUESTS.map { type ->
                        conn.request(ccpEnvelope(type, store.sender(), JSONObject())).optJSONObject("payload")
                    }
                }
                _remotePanel.value = buildPanel(peer, responses[0], responses[1], responses[2], responses[3])
            } finally {
                inspectInFlight.remove(peer.deviceId)
            }
        }
    }

    private suspend fun sendFileViaCloud(peer: DeviceInfo, uri: Uri) {
        val fileName = resolveDisplayName(uri)
        val (size, fullHash) = hashUri(uri)
        if (size > CCP_MAX_CLOUD_FILE_BYTES) {
            log("$fileName is too large for Long Distance (limit ${CCP_MAX_CLOUD_FILE_BYTES / (1024 * 1024)} MB)")
            return
        }
        val totalChunks = chunkCount(size, CCP_CHUNK_SIZE)
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
            val reason = offer?.optString("reason")?.takeIf { it.isNotBlank() } ?: "no response"
            log("${peer.deviceName} rejected $fileName: $reason")
            return
        }

        val progress = ProgressReporter(size) { log("Cloud sending $fileName: $it%") }
        var sent = 0L
        var index = 0
        var failed = false
        streamChunks(uri) { chunk ->
            val ok = convexBridge.pushMessage(peer.deviceId, "file.chunk", JSONObject()
                .put("transfer_id", transferId)
                .put("index", index)
                .put("sha256", sha256Hex(chunk))
                .put("data_b64", Base64.encodeToString(chunk, Base64.NO_WRAP)), ttlMs = 10 * 60 * 1000)
            if (!ok) {
                log("Cloud send failed at chunk $index of $fileName")
                failed = true
                return@streamChunks false
            }
            sent += chunk.size
            index += 1
            progress.update(sent)
            true
        }
        if (failed) return

        val complete = convexBridge.sendCloudRequest(peer.deviceId, "file.complete", JSONObject()
            .put("transfer_id", transferId)
            .put("sha256", fullHash), timeoutMs = 60_000)
        log(if (complete?.optBoolean("ok") == true) "Cloud sent and verified $fileName" else "Cloud receiver could not verify $fileName")
    }

    private suspend fun inspectPeerViaCloud(peer: DeviceInfo) {
        log("Loading panel for ${peer.deviceName} via cloud relay")
        // Requests go out together so the panel costs one relay round trip, not four.
        val responses = coroutineScope {
            PANEL_REQUESTS.map { type ->
                async { convexBridge.sendCloudRequest(peer.deviceId, type, timeoutMs = 25_000) }
            }.awaitAll()
        }
        if (responses.all { it == null }) {
            log("${peer.deviceName} did not answer over the cloud relay")
            return
        }
        _remotePanel.value = buildPanel(peer, responses[0], responses[1], responses[2], responses[3])
    }

    private fun buildPanel(
        peer: DeviceInfo,
        snapshot: JSONObject?,
        gallery: JSONObject?,
        files: JSONObject?,
        notifications: JSONObject?,
    ) = RemotePeerPanel(
        title = snapshot?.optString("device_title")?.takeIf { it.isNotBlank() } ?: peer.deviceName,
        subtitle = snapshot?.optString("device_subtitle")?.takeIf { it.isNotBlank() } ?: peer.platform,
        battery = snapshot?.optString("battery", "Unknown") ?: "Unknown",
        storage = snapshot?.optString("storage", "Unknown") ?: "Unknown",
        notificationAccess = snapshot?.optString("notification_access", "Unknown") ?: "Unknown",
        galleryAccess = snapshot?.optString("gallery_access", "Unknown") ?: "Unknown",
        settings = parseFacts(snapshot?.optJSONArray("settings")),
        gallery = parseEntries(gallery?.optJSONArray("items"), "Gallery"),
        files = parseEntries(files?.optJSONArray("items"), "Files"),
        notifications = parseNotifications(notifications),
    )

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
        DatagramSocket(null).apply {
            reuseAddress = true
            bind(java.net.InetSocketAddress(CCP_UDP_PORT))
        }.use { socket ->
            udpSocket = socket
            socket.soTimeout = 2000
            val buffer = ByteArray(8192)
            while (running) {
                try {
                    val packet = DatagramPacket(buffer, buffer.size)
                    socket.receive(packet)
                    val json = JSONObject(String(packet.data, 0, packet.length, Charsets.UTF_8))
                    if (json.optString("protocol") != CCP_PROTOCOL || json.optString("device_id") == store.deviceId) continue
                    if (!isValidDeviceId(json.optString("device_id"))) continue
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
                } catch (e: java.net.SocketException) {
                    if (!running) return
                    throw e
                } catch (e: Exception) {
                    // Malformed packets are expected on a shared LAN; drop them quietly.
                }
            }
        }
    }

    private fun listenTcp() {
        ServerSocket().apply {
            reuseAddress = true
            bind(java.net.InetSocketAddress(CCP_TCP_PORT))
        }.use { server ->
            tcpServer = server
            server.soTimeout = 2000
            log("TCP listener active on $CCP_TCP_PORT")
            while (running) {
                val socket = try {
                    server.accept()
                } catch (_: SocketTimeoutException) {
                    continue
                } catch (e: java.net.SocketException) {
                    if (!running) return
                    throw e
                }
                if (!connectionSlots.tryAcquire()) {
                    // Too many concurrent peers: refuse rather than queue unbounded work.
                    runCatching { socket.close() }
                    continue
                }
                scope.launch(nodeJob ?: scope.coroutineContext) {
                    try {
                        handleClient(socket)
                    } catch (e: Exception) {
                        log("Connection from ${socket.inetAddress?.hostAddress} closed: ${e.message}")
                    } finally {
                        connectionSlots.release()
                    }
                }
            }
        }
    }

    /**
     * Every inbound connection starts with a plain-text frame: either a
     * pairing attempt or a session.hello that upgrades to an encrypted,
     * authenticated session. Nothing else is served in clear.
     */
    private suspend fun handleClient(socket: Socket) {
        socket.use {
            it.tcpNoDelay = true
            it.soTimeout = CCP_SOCKET_IDLE_TIMEOUT_MS
            val reader = BoundedLineReader(it.getInputStream())
            val writer = LineWriter(it.getOutputStream())
            val first = JSONObject(reader.readLine() ?: return)
            when (first.optString("type")) {
                "pair.request" -> handlePairRequest(socket, reader, writer, first)
                "session.hello" -> {
                    val connection = LanHandshake.server(socket, reader, writer, store.sender(), first) { id ->
                        store.pairSecretBytes(id)
                    } ?: return
                    serveSecureSession(connection)
                }
                else -> write(writer, ccpEnvelope("session.error", store.sender(), JSONObject()
                    .put("reason", "secure_session_required")))
            }
        }
    }

    private suspend fun handlePairRequest(socket: Socket, reader: BoundedLineReader, writer: LineWriter, request: JSONObject) {
        val sender = request.optJSONObject("sender") ?: return
        val peerId = sender.optString("device_id")
        fun refuse(reason: String) = write(writer, ccpEnvelope("pair.response", store.sender(), JSONObject()
            .put("accepted", false)
            .put("reason", reason)))

        if (!isValidDeviceId(peerId) || peerId == store.deviceId) return refuse("invalid_device_id")
        // One prompt at a time; this also rate-limits prompt spam from the LAN.
        if (!pairingBusy.compareAndSet(false, true)) return refuse("busy")
        try {
            val responder = try {
                PairingResponder(store.deviceId, peerId, request.optJSONObject("payload") ?: JSONObject())
            } catch (e: IllegalArgumentException) {
                return refuse(e.message ?: "invalid_request")
            }
            write(writer, ccpEnvelope("pair.challenge", store.sender(), responder.challengePayload()))

            val reveal = JSONObject(reader.readLine() ?: return)
            if (reveal.optString("type") != "pair.reveal") return refuse("protocol_error")
            val result = try {
                responder.onReveal(reveal.optJSONObject("payload") ?: JSONObject())
            } catch (e: IllegalArgumentException) {
                log("Pairing from ${sender.optString("device_name")} failed: ${e.message}")
                return refuse(e.message ?: "invalid_reveal")
            }

            val accepted = requestPairApproval(sender, result.sas, alreadyPaired = store.isTrusted(peerId))
            if (!accepted) {
                log("Rejected pairing from ${sender.optString("device_name")}")
                return refuse("rejected")
            }

            store.trust(sender, result.pairSecret)
            write(writer, ccpEnvelope("pair.response", store.sender(), JSONObject()
                .put("accepted", true)
                .put("confirm", CcpCrypto.b64(result.responderConfirm()))))
            updatePeer(DeviceInfo(
                deviceId = peerId,
                deviceName = sender.optString("device_name", "Unknown").take(64),
                platform = sender.optString("platform", "unknown").take(16),
                host = socket.inetAddress.hostAddress ?: "",
                tcpPort = CCP_TCP_PORT,
                trusted = true,
            ))
            log("Paired with ${sender.optString("device_name")}")
            scope.launch { establishCloudSession(peerId, result.pairSecret) }
        } finally {
            pairingBusy.set(false)
        }
    }

    /** Serves requests on an authenticated session. The peer id comes from the handshake, never from message bodies. */
    private fun serveSecureSession(conn: SecureConnection) {
        var transfer: IncomingTransfer? = null
        try {
            while (true) {
                val message = try {
                    conn.receive() ?: break
                } catch (e: java.security.GeneralSecurityException) {
                    log("Rejected an unauthenticated frame claiming to be ${conn.peerId.take(8)}…")
                    conn.sendPlainError(store.sender(), "bad_frame")
                    return
                }
                if (!store.isTrusted(conn.peerId)) break
                val payload = message.optJSONObject("payload") ?: JSONObject()
                when (val type = message.optString("type")) {
                    "file.offer" -> {
                        transfer?.discard()
                        transfer = null
                        val reason = IncomingTransfer.validateOffer(payload)
                            ?: if (!hasSpaceFor(payload.optLong("size"))) "insufficient_storage" else null
                        val response = JSONObject()
                            .put("transfer_id", payload.optString("transfer_id"))
                            .put("accepted", reason == null)
                            .put("resume_from", 0)
                            .put("reason", reason ?: JSONObject.NULL)
                        if (reason == null) {
                            transfer = IncomingTransfer.create(inboxDir(), payload).also {
                                log("Receiving ${it.displayName} from ${peerName(conn.peerId)}")
                            }
                        }
                        conn.send(ccpEnvelope("file.offer.response", store.sender(), response))
                    }
                    "file.chunk" -> {
                        val active = transfer ?: error("Chunk without an accepted offer")
                        check(payload.optString("transfer_id") == active.transferId) { "Chunk for an unknown transfer" }
                        active.append(
                            payload.optInt("index", -1),
                            Base64.decode(payload.getString("data_b64"), Base64.NO_WRAP),
                            payload.optString("sha256"),
                        )
                    }
                    "file.complete" -> {
                        val active = transfer
                        transfer = null
                        val ok = active != null &&
                            payload.optString("transfer_id") == active.transferId &&
                            finishIncoming(active)
                        if (!ok) active?.discard()
                        conn.send(ccpEnvelope("file.complete.response", store.sender(), JSONObject()
                            .put("transfer_id", payload.optString("transfer_id"))
                            .put("ok", ok)))
                    }
                    else -> conn.send(ccpEnvelope(responseTypeFor(type), store.sender(), handleCapabilityRequest(type, payload)))
                }
            }
        } finally {
            transfer?.discard()
        }
    }

    /** Requests answered identically over the LAN and the cloud relay. */
    private fun handleCapabilityRequest(type: String, payload: JSONObject): JSONObject = when (type) {
        "device.snapshot.request" -> deviceData.buildRemoteSnapshotPayload(
            notificationAccessEnabled = NotificationCache.hasAccess(context),
            galleryAccessEnabled = deviceData.hasGalleryAccess()
        )
        "gallery.list.request" -> deviceData.buildGalleryPayload()
        "files.list.request" -> deviceData.buildFilesPayload()
        "notifications.list.request" -> deviceData.buildNotificationsPayload()
        "remote.action.request" -> {
            val action = payload.optString("action")
            val result = performRemoteAction(action, payload.optJSONObject("args") ?: JSONObject())
            JSONObject().put("ok", result.first).put("message", result.second).put("action", action)
        }
        else -> JSONObject().put("ok", false).put("error", "unsupported_request")
    }

    /** Verifies a completed transfer and moves it into shared storage. */
    private fun finishIncoming(transfer: IncomingTransfer): Boolean {
        if (!transfer.finish()) {
            log("Checksum failed for ${transfer.displayName}; discarded")
            transfer.discard()
            return false
        }
        return try {
            val saved = deviceData.saveIncomingFile(transfer.displayName, transfer.file)
            refreshLocalData()
            log("Received ${transfer.displayName} → ${saved.optString("location")}")
            true
        } catch (e: Exception) {
            log("Saving ${transfer.displayName} failed: ${e.message}")
            false
        } finally {
            transfer.file.delete()
        }
    }

    private fun inboxDir(): File = File(context.getExternalFilesDir(null) ?: context.filesDir, "CCP-Inbox")

    /** Needs room for the temp copy plus the shared-storage copy, with headroom. */
    private fun hasSpaceFor(size: Long): Boolean {
        val dir = inboxDir().apply { mkdirs() }
        return dir.usableSpace > size * 2 + 64L * 1024 * 1024
    }

    /** Removes partial files left behind by a crash or killed process. */
    private fun cleanupInbox() {
        val cutoff = System.currentTimeMillis() - 60 * 60 * 1000L
        inboxDir().listFiles { file -> file.name.endsWith(".part") && file.lastModified() < cutoff }
            ?.forEach { it.delete() }
    }

    private fun peerName(deviceId: String): String =
        store.peerInfo(deviceId)?.optString("device_name")?.takeIf { it.isNotBlank() } ?: deviceId.take(8)

    private fun connectPeer(peer: DeviceInfo): Socket {
        val rankedRoutes = rankRoutes(peer)
        var lastError: Exception? = null
        for (route in rankedRoutes) {
            try {
                val socket = Socket()
                socket.tcpNoDelay = true
                socket.soTimeout = CCP_SOCKET_IDLE_TIMEOUT_MS
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

    private fun write(writer: LineWriter, message: JSONObject) {
        writer.writeLine(message.toString())
    }

    private fun updatePeer(peer: DeviceInfo) {
        synchronized(peerLock) {
            peersById[peer.deviceId] = peer.copy(lastSeen = System.currentTimeMillis())
            _peers.value = peersById.values.sortedByDescending { it.lastSeen }
        }
    }

    private suspend fun cloudPeerLoop() {
        delay(2_000)
        while (running) {
            runCatching { syncCloudPeers() }.onFailure { log("Cloud peer sync failed: ${it.message}") }
            pruneStaleCloudTransfers()
            delay(15_000)
        }
    }

    /**
     * Mirrors cloud sessions into the peer list and re-publishes local
     * pairings the relay doesn't know about yet (e.g. pairing happened offline).
     */
    private fun syncCloudPeers() {
        val sessions = convexBridge.listPairedPeers() ?: return
        val cloudIds = HashSet<String>()
        for (index in 0 until sessions.length()) {
            sessions.optJSONObject(index)?.optString("peer_id")?.takeIf(::isValidDeviceId)?.let(cloudIds::add)
        }

        val now = System.currentTimeMillis()
        for (peerId in store.trustedPeerIds()) {
            if (peerId in cloudIds) continue
            if (now - (lastSessionSync[peerId] ?: 0L) < 5 * 60_000L) continue
            lastSessionSync[peerId] = now
            val secret = store.pairSecretBytes(peerId) ?: continue
            if (convexBridge.storeSession(peerId, secret)) cloudIds += peerId
        }

        // Drop cloud entries for sessions that were revoked or need re-pairing.
        synchronized(peerLock) {
            val removed = peersById.entries.removeIf { (id, peer) ->
                peer.isCloudPeer && (id !in cloudIds || !store.isTrusted(id))
            }
            if (removed) _peers.value = peersById.values.sortedByDescending { it.lastSeen }
        }

        for (peerId in cloudIds) {
            if (!store.isTrusted(peerId)) continue
            val existing = synchronized(peerLock) { peersById[peerId] }
            if (existing != null && !existing.isCloudPeer) continue
            val info = convexBridge.getPeerDeviceInfo(peerId)
            val presence = convexBridge.getPeerPresence(peerId)
            val local = store.peerInfo(peerId)
            updatePeer(
                DeviceInfo(
                    deviceId = peerId,
                    deviceName = info?.optString("device_name")?.takeIf { it.isNotBlank() }
                        ?: local?.optString("device_name")?.takeIf { it.isNotBlank() }
                        ?: "Cloud device ${peerId.take(8)}",
                    platform = info?.optString("platform")?.takeIf { it.isNotBlank() }
                        ?: local?.optString("platform") ?: "unknown",
                    host = "127.0.0.1",
                    tcpPort = 0,
                    trusted = true,
                    transports = listOf("cloud"),
                    routes = emptyList(),
                    isCloudPeer = true,
                    cloudOnline = presence?.optBoolean("online") == true,
                )
            )
        }
    }

    private fun pruneStaleCloudTransfers() {
        val cutoff = System.currentTimeMillis() - CCP_TRANSFER_IDLE_TIMEOUT_MS
        cloudIncomingTransfers.entries.removeIf { (_, transfer) ->
            (transfer.lastActivity < cutoff).also { stale ->
                if (stale) {
                    transfer.discard()
                    log("[Cloud] Abandoned stalled transfer of ${transfer.displayName}")
                }
            }
        }
    }

    private fun pruneStalePeers() {
        val cutoff = System.currentTimeMillis() - 20_000
        synchronized(peerLock) {
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


    private fun log(message: String) {
        // update{} is atomic; read-modify-write on .value loses events under concurrency.
        _events.update { (it + message).takeLast(80) }
    }

    /** Handles a message from the cloud relay (already decrypted and authenticated by ConvexBridge). */
    private fun handleConvexMessage(msg: ConvexMessage) {
        val senderShort = msg.senderId.take(8)
        val requestId = msg.payload.optString("request_id", "")
        if (requiresTrustedPeer(msg.msgType) && !store.isTrusted(msg.senderId)) {
            log("[Cloud] Rejected ${msg.msgType} from unpaired $senderShort…")
            scope.launch { sendCloudRejection(msg.senderId, msg.msgType, requestId) }
            return
        }

        when (msg.msgType) {
            in PANEL_REQUESTS, "remote.action.request" -> {
                log("[Cloud] ${msg.msgType} from $senderShort…")
                scope.launch {
                    val response = handleCapabilityRequest(msg.msgType, msg.payload)
                    if (requestId.isNotBlank()) response.put("request_id", requestId)
                    convexBridge.pushMessage(msg.senderId, responseTypeFor(msg.msgType), response)
                }
            }

            "file.offer" -> {
                val transferId = msg.payload.optString("transfer_id")
                val key = "${msg.senderId}|$transferId"
                val reason = IncomingTransfer.validateOffer(msg.payload, CCP_MAX_CLOUD_FILE_BYTES)
                    ?: when {
                        cloudIncomingTransfers.size >= MAX_CLOUD_TRANSFERS -> "too_many_transfers"
                        !hasSpaceFor(msg.payload.optLong("size")) -> "insufficient_storage"
                        else -> null
                    }
                val response = JSONObject()
                    .put("transfer_id", transferId)
                    .put("accepted", reason == null)
                    .put("resume_from", 0)
                    .put("reason", reason ?: JSONObject.NULL)
                if (requestId.isNotBlank()) response.put("request_id", requestId)
                if (reason == null) {
                    cloudIncomingTransfers.remove(key)?.discard()
                    val transfer = IncomingTransfer.create(inboxDir(), msg.payload)
                    cloudIncomingTransfers[key] = transfer
                    log("[Cloud] Receiving ${transfer.displayName} from ${peerName(msg.senderId)}")
                }
                scope.launch { convexBridge.pushMessage(msg.senderId, "file.offer.response", response) }
            }

            "file.chunk" -> {
                // Chunks arrive in relay order on the poll thread, so they're applied sequentially.
                val key = "${msg.senderId}|${msg.payload.optString("transfer_id")}"
                val transfer = cloudIncomingTransfers[key] ?: return
                try {
                    transfer.append(
                        msg.payload.optInt("index", -1),
                        Base64.decode(msg.payload.getString("data_b64"), Base64.NO_WRAP),
                        msg.payload.optString("sha256"),
                    )
                } catch (e: Exception) {
                    cloudIncomingTransfers.remove(key)
                    transfer.discard()
                    log("[Cloud] Transfer of ${transfer.displayName} aborted: ${e.message}")
                }
            }

            "file.complete" -> {
                val transferId = msg.payload.optString("transfer_id")
                val transfer = cloudIncomingTransfers.remove("${msg.senderId}|$transferId")
                val ok = transfer != null && finishIncoming(transfer)
                val response = JSONObject().put("transfer_id", transferId).put("ok", ok)
                if (requestId.isNotBlank()) response.put("request_id", requestId)
                scope.launch { convexBridge.pushMessage(msg.senderId, "file.complete.response", response) }
            }

            "clipboard.sync" -> log("[Cloud] Clipboard sync from $senderShort…")
            "notification.push" -> log("[Cloud] Notification from $senderShort…: ${msg.payload.optString("title", "Notification")}")
            "heartbeat" -> Unit
            else -> log("[Cloud] Ignored ${msg.msgType} from $senderShort…")
        }
    }

    private fun requiresTrustedPeer(msgType: String): Boolean {
        return msgType in setOf(
            "device.snapshot.request",
            "gallery.list.request",
            "files.list.request",
            "notifications.list.request",
            "remote.action.request",
            "file.offer",
            "file.chunk",
            "file.complete",
            "clipboard.sync",
            "notification.push",
        )
    }

    private fun responseTypeFor(msgType: String): String = when (msgType) {
        "device.snapshot.request" -> "device.snapshot.response"
        "gallery.list.request" -> "gallery.list.response"
        "files.list.request" -> "files.list.response"
        "notifications.list.request" -> "notifications.list.response"
        "remote.action.request" -> "remote.action.response"
        "file.offer" -> "file.offer.response"
        "file.complete" -> "file.complete.response"
        else -> "$msgType.response"
    }

    private fun sendCloudRejection(peerDeviceId: String, msgType: String, requestId: String) {
        val response = JSONObject()
            .put("ok", false)
            .put("accepted", false)
            .put("reason", "peer is not paired")
            .put("message", "peer is not paired")
        if (requestId.isNotBlank()) response.put("request_id", requestId)
        convexBridge.pushMessage(peerDeviceId, responseTypeFor(msgType), response)
    }

    /** Shows the comparison code to the user and waits up to 60 s for a decision. */
    private suspend fun requestPairApproval(sender: JSONObject, code: String, alreadyPaired: Boolean): Boolean {
        val deviceId = sender.getString("device_id")
        val deferred = CompletableDeferred<Boolean>()
        pendingPairApprovals.put(deviceId, deferred)?.complete(false)
        _pendingPairRequest.value = PendingPairRequest(
            deviceId = deviceId,
            deviceName = sender.optString("device_name", "Unknown").take(64),
            platform = sender.optString("platform", "unknown").take(16),
            pairCode = code,
            alreadyPaired = alreadyPaired,
        )
        val accepted = withTimeoutOrNull(60_000) { deferred.await() } == true
        pendingPairApprovals.remove(deviceId, deferred)
        _pendingPairRequest.update { if (it?.deviceId == deviceId) null else it }
        return accepted
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


