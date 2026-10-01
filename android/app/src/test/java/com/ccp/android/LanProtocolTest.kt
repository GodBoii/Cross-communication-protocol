package com.ccp.android

import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.file.Files
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class LanProtocolTest {
    private val initiatorId = "a".repeat(64)
    private val responderId = "b".repeat(64)

    private fun sender(id: String) = JSONObject().put("device_id", id).put("device_name", "test").put("platform", "test")

    @Test
    fun pairingDerivesTheSameSecretAndCodeOnBothSides() {
        val initiator = PairingInitiator(initiatorId)
        val responder = PairingResponder(responderId, initiatorId, initiator.requestPayload())
        val initiatorResult = initiator.onChallenge(responderId, responder.challengePayload())
        val responderResult = responder.onReveal(initiator.revealPayload())

        assertEquals(initiatorResult.sas, responderResult.sas)
        assertArrayEquals(initiatorResult.pairSecret, responderResult.pairSecret)
        assertTrue(initiatorResult.verifyResponderConfirm(CcpCrypto.b64(responderResult.responderConfirm())))
        assertTrue(Regex("^\\d{6}$").matches(initiatorResult.sas))
    }

    @Test
    fun responderRejectsARevealThatDoesNotMatchTheCommitment() {
        val honest = PairingInitiator(initiatorId)
        val attacker = PairingInitiator(initiatorId)
        val responder = PairingResponder(responderId, initiatorId, honest.requestPayload())
        responder.challengePayload()
        try {
            responder.onReveal(attacker.revealPayload())
            fail("expected commitment_mismatch")
        } catch (e: IllegalArgumentException) {
            assertEquals("commitment_mismatch", e.message)
        }
    }

    @Test
    fun responderRejectsBadRequests() {
        for ((payload, reason) in listOf(
            JSONObject().put("version", 0).put("commitment", "0".repeat(64)) to "unsupported_pairing_version",
            JSONObject().put("version", 1).put("commitment", "xyz") to "invalid_commitment",
        )) {
            try {
                PairingResponder(responderId, initiatorId, payload)
                fail("expected $reason")
            } catch (e: IllegalArgumentException) {
                assertEquals(reason, e.message)
            }
        }
    }

    @Test
    fun secureSessionRoundTripsOverRealSockets() {
        val secret = CcpCrypto.randomBytes(32)
        withServer({ socket ->
            val reader = BoundedLineReader(socket.getInputStream())
            val writer = LineWriter(socket.getOutputStream())
            val hello = JSONObject(reader.readLine()!!)
            val conn = LanHandshake.server(socket, reader, writer, sender(responderId), hello) { id ->
                if (id == initiatorId) secret else null
            }!!
            val request = conn.receive()!!
            conn.send(JSONObject().put("type", "echo.response").put("payload", request.getJSONObject("payload")))
        }) { port ->
            LanHandshake.client(Socket(InetAddress.getLoopbackAddress(), port), sender(initiatorId), responderId, secret).use { conn ->
                val reply = conn.request(JSONObject().put("type", "echo").put("payload", JSONObject().put("x", "✓")))
                assertEquals("✓", reply.getJSONObject("payload").getString("x"))
            }
        }
    }

    @Test
    fun serverRefusesUnpairedClients() {
        withServer({ socket ->
            val reader = BoundedLineReader(socket.getInputStream())
            val writer = LineWriter(socket.getOutputStream())
            val conn = LanHandshake.server(socket, reader, writer, sender(responderId), JSONObject(reader.readLine()!!)) { null }
            assertNull(conn)
        }) { port ->
            try {
                LanHandshake.client(Socket(InetAddress.getLoopbackAddress(), port), sender(initiatorId), responderId, CcpCrypto.randomBytes(32))
                fail("expected refusal")
            } catch (e: SessionRefusedException) {
                assertEquals("not_paired", e.reason)
            }
        }
    }

    @Test
    fun clientWithWrongSecretCannotProduceValidFrames() {
        withServer({ socket ->
            val reader = BoundedLineReader(socket.getInputStream())
            val writer = LineWriter(socket.getOutputStream())
            val conn = LanHandshake.server(socket, reader, writer, sender(responderId), JSONObject(reader.readLine()!!)) {
                CcpCrypto.randomBytes(32) // the real pair secret, which the impostor doesn't know
            }!!
            try {
                conn.receive()
                fail("forged frame accepted")
            } catch (_: java.security.GeneralSecurityException) {
                conn.sendPlainError(sender(responderId), "bad_frame")
            }
        }) { port ->
            LanHandshake.client(Socket(InetAddress.getLoopbackAddress(), port), sender(initiatorId), responderId, CcpCrypto.randomBytes(32)).use { conn ->
                try {
                    conn.request(JSONObject().put("type", "device.snapshot.request"))
                    fail("impostor got a response")
                } catch (e: SessionRefusedException) {
                    assertEquals("bad_frame", e.reason)
                }
            }
        }
    }

    @Test
    fun incomingTransferValidatesOffersAndChunks() {
        val data = ByteArray(150_000) { (it % 251).toByte() }
        val chunkSize = 64 * 1024
        val offer = JSONObject()
            .put("transfer_id", "t1")
            .put("filename", "../../evil\u0000name.txt")
            .put("size", data.size)
            .put("sha256", sha256Hex(data))
            .put("chunk_size", chunkSize)
            .put("total_chunks", chunkCount(data.size.toLong(), chunkSize))
        assertNull(IncomingTransfer.validateOffer(offer))
        assertEquals("file_too_large", IncomingTransfer.validateOffer(offer, maxBytes = 10))
        assertEquals("invalid_total_chunks", IncomingTransfer.validateOffer(JSONObject(offer.toString()).put("total_chunks", 1)))
        assertEquals("invalid_sha256", IncomingTransfer.validateOffer(JSONObject(offer.toString()).put("sha256", "nope")))

        val inbox = Files.createTempDirectory("ccp-inbox").toFile()
        try {
            val transfer = IncomingTransfer.create(inbox, offer)
            assertEquals("_.._evil_name.txt", transfer.displayName)
            val chunks = data.toList().chunked(chunkSize).map { it.toByteArray() }
            try {
                transfer.append(1, chunks[1], sha256Hex(chunks[1]))
                fail("out-of-order chunk accepted")
            } catch (_: IllegalStateException) {
            }
            chunks.forEachIndexed { i, chunk -> transfer.append(i, chunk, sha256Hex(chunk)) }
            assertTrue(transfer.finish())
            assertArrayEquals(data, transfer.file.readBytes())

            val truncated = IncomingTransfer.create(inbox, JSONObject(offer.toString()).put("transfer_id", "t2"))
            truncated.append(0, chunks[0], sha256Hex(chunks[0]))
            assertTrue(!truncated.finish())
            truncated.discard()
        } finally {
            inbox.deleteRecursively()
        }
    }

    @Test
    fun safeFilenameNeutralisesHostileNames() {
        assertEquals("received-file", safeFilename("..."))
        assertEquals("a_b_c", safeFilename("a/b\\c"))
        assertEquals(120, safeFilename("x".repeat(500)).length)
        assertEquals("photo.jpg", safeFilename("photo.jpg"))
    }

    private fun withServer(serve: (Socket) -> Unit, client: (Int) -> Unit) {
        val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val pool = Executors.newSingleThreadExecutor()
        val future = pool.submit { server.accept().use { serve(it) } }
        try {
            client(server.localPort)
            future.get(10, TimeUnit.SECONDS)
        } finally {
            server.close()
            pool.shutdownNow()
        }
    }

    @Suppress("unused")
    private fun File.deleteQuietly() = runCatching { delete() }
}
