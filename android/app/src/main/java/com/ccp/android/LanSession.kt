package com.ccp.android

import org.json.JSONObject
import java.io.Closeable
import java.io.EOFException
import java.io.IOException
import java.net.Socket

const val SESSION_NONCE_BYTES = 16

/** The peer refused or could not authenticate the session (e.g. it no longer trusts us). */
class SessionRefusedException(val reason: String) : IOException("Peer refused session: $reason")

/**
 * An authenticated, encrypted LAN session with a paired peer. Every frame is
 * {"sealed": base64(AES-GCM)} keyed from the pair secret, so a device that
 * merely copies a paired peer's broadcast device id cannot read or forge traffic.
 */
class SecureConnection(
    private val socket: Socket,
    private val reader: BoundedLineReader,
    private val writer: LineWriter,
    private val channel: SecureChannel,
    val peerId: String,
) : Closeable {
    fun send(message: JSONObject) {
        writer.writeLine(JSONObject().put("sealed", channel.seal(message.toString())).toString())
    }

    /**
     * Next authenticated message, or null when the peer closes the connection.
     * Throws [java.security.GeneralSecurityException] for forged/replayed frames
     * and [SessionRefusedException] when the peer sends a plain-text refusal.
     */
    fun receive(): JSONObject? {
        val line = reader.readLine() ?: return null
        val frame = JSONObject(line)
        val sealed = frame.optString("sealed")
        if (sealed.isEmpty()) {
            val reason = frame.optJSONObject("payload")?.optString("reason")
            throw SessionRefusedException(reason?.takeIf { it.isNotBlank() } ?: "unsealed_frame")
        }
        return JSONObject(channel.open(sealed))
    }

    fun request(message: JSONObject): JSONObject {
        send(message)
        return receive() ?: throw EOFException("Connection closed by peer")
    }

    /** Plain-text refusal for a peer whose frames failed to authenticate; reveals nothing secret. */
    fun sendPlainError(self: JSONObject, reason: String) {
        runCatching {
            writer.writeLine(ccpEnvelope("session.error", self, JSONObject().put("reason", reason)).toString())
        }
    }

    override fun close() {
        runCatching { socket.close() }
    }
}

/** session.hello / session.hello.response exchange that precedes every secure LAN session. */
object LanHandshake {
    fun client(socket: Socket, self: JSONObject, peerId: String, pairSecret: ByteArray): SecureConnection {
        val reader = BoundedLineReader(socket.getInputStream())
        val writer = LineWriter(socket.getOutputStream())
        val clientNonce = CcpCrypto.randomBytes(SESSION_NONCE_BYTES)
        writer.writeLine(
            ccpEnvelope("session.hello", self, JSONObject()
                .put("version", 1)
                .put("nonce", CcpCrypto.b64(clientNonce))).toString()
        )
        val response = JSONObject(reader.readLine() ?: throw EOFException("Connection closed during handshake"))
        val payload = response.optJSONObject("payload") ?: JSONObject()
        if (response.optString("type") != "session.hello.response" || !payload.optBoolean("ok")) {
            throw SessionRefusedException(payload.optString("reason").ifBlank { "handshake_failed" })
        }
        if (response.optJSONObject("sender")?.optString("device_id") != peerId) {
            throw SessionRefusedException("unexpected_peer")
        }
        val serverNonce = runCatching { CcpCrypto.unb64(payload.getString("nonce")) }.getOrNull()
        if (serverNonce?.size != SESSION_NONCE_BYTES) throw SessionRefusedException("bad_nonce")
        val channel = SecureChannel.forClient(pairSecret, self.getString("device_id"), peerId, clientNonce, serverNonce)
        return SecureConnection(socket, reader, writer, channel, peerId)
    }

    /**
     * Answers a session.hello. Returns null (after replying with a refusal) when
     * the caller isn't paired or the hello is malformed.
     */
    fun server(
        socket: Socket,
        reader: BoundedLineReader,
        writer: LineWriter,
        self: JSONObject,
        hello: JSONObject,
        secretFor: (String) -> ByteArray?,
    ): SecureConnection? {
        val peerId = hello.optJSONObject("sender")?.optString("device_id").orEmpty()
        val secret = if (isValidDeviceId(peerId)) secretFor(peerId) else null
        val clientNonce = runCatching {
            CcpCrypto.unb64(hello.getJSONObject("payload").getString("nonce"))
        }.getOrNull()

        val refusal = when {
            secret == null -> "not_paired"
            clientNonce?.size != SESSION_NONCE_BYTES -> "bad_hello"
            else -> null
        }
        if (refusal != null || secret == null || clientNonce == null) {
            writer.writeLine(ccpEnvelope("session.hello.response", self, JSONObject()
                .put("ok", false)
                .put("reason", refusal ?: "bad_hello")).toString())
            return null
        }

        val serverNonce = CcpCrypto.randomBytes(SESSION_NONCE_BYTES)
        writer.writeLine(ccpEnvelope("session.hello.response", self, JSONObject()
            .put("ok", true)
            .put("version", 1)
            .put("nonce", CcpCrypto.b64(serverNonce))).toString())
        val channel = SecureChannel.forServer(secret, peerId, self.getString("device_id"), clientNonce, serverNonce)
        return SecureConnection(socket, reader, writer, channel, peerId)
    }
}
