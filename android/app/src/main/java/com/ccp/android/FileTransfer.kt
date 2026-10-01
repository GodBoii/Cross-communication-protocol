package com.ccp.android

import org.json.JSONObject
import java.io.File
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.UUID

/** Largest file accepted over the LAN. */
const val CCP_MAX_FILE_BYTES = 4L * 1024 * 1024 * 1024

/** Largest file accepted over the cloud relay (each chunk is a relay message). */
const val CCP_MAX_CLOUD_FILE_BYTES = 100L * 1024 * 1024

const val CCP_MAX_CHUNK_SIZE = 256 * 1024

/** Cloud transfers with no chunk for this long are abandoned. */
const val CCP_TRANSFER_IDLE_TIMEOUT_MS = 10 * 60 * 1000L

private val SHA256_HEX = Regex("^[0-9a-f]{64}$")

fun chunkCount(size: Long, chunkSize: Int): Int = ((size + chunkSize - 1) / chunkSize).toInt()

/**
 * Makes a peer-supplied file name safe to show and store: strips path
 * separators, reserved and control characters, leading dots, and caps length.
 */
fun safeFilename(name: String): String {
    val reserved = "<>:\"/\\|?*"
    var cleaned = buildString(name.length) {
        name.forEach { c -> append(if (c in reserved || c.code < 32 || c.code == 127) '_' else c) }
    }.trim().trimStart('.').trim()
    if (cleaned.length > 120) {
        cleaned = cleaned.take(120)
        if (cleaned.last().isHighSurrogate()) cleaned = cleaned.dropLast(1)
    }
    return cleaned.ifEmpty { "received-file" }
}

/** Throttles progress logging to roughly every 10%. */
class ProgressReporter(private val total: Long, private val report: (Int) -> Unit) {
    private var lastBucket = -1

    fun update(done: Long) {
        val percent = if (total <= 0) 100 else ((done * 100) / total).toInt()
        val bucket = percent / 10
        if (bucket != lastBucket) {
            lastBucket = bucket
            report(percent)
        }
    }
}

/**
 * An inbound transfer streamed to a temp file. Chunks must arrive in order,
 * match their hash, and never exceed what the offer declared; the whole-file
 * hash is computed incrementally so nothing is ever loaded fully into memory.
 */
class IncomingTransfer private constructor(
    val transferId: String,
    val displayName: String,
    val file: File,
    val declaredSize: Long,
    private val chunkSize: Int,
    val totalChunks: Int,
    private val expectedHash: String,
) {
    private val output = FileOutputStream(file)
    private val digest = MessageDigest.getInstance("SHA-256")

    var nextIndex = 0
        private set
    var received = 0L
        private set
    @Volatile
    var lastActivity = System.currentTimeMillis()
        private set

    @Synchronized
    fun append(index: Int, chunk: ByteArray, chunkSha256: String) {
        check(index == nextIndex) { "Unexpected chunk $index; expected $nextIndex" }
        check(index < totalChunks) { "More chunks than offered" }
        check(chunk.size <= chunkSize) { "Chunk larger than offered chunk size" }
        check(received + chunk.size <= declaredSize) { "More data than offered" }
        check(sha256Hex(chunk).equals(chunkSha256, ignoreCase = true)) { "Chunk checksum mismatch" }
        output.write(chunk)
        digest.update(chunk)
        received += chunk.size
        nextIndex++
        lastActivity = System.currentTimeMillis()
    }

    /** Closes the file; true only if every chunk arrived and the full hash matches. */
    @Synchronized
    fun finish(): Boolean {
        close()
        return nextIndex == totalChunks &&
            received == declaredSize &&
            CcpCrypto.hex(digest.digest()).equals(expectedHash, ignoreCase = true)
    }

    fun close() {
        runCatching { output.close() }
    }

    fun discard() {
        close()
        file.delete()
    }

    companion object {
        /** Returns a refusal reason, or null if the offer is acceptable. */
        fun validateOffer(payload: JSONObject, maxBytes: Long = CCP_MAX_FILE_BYTES): String? {
            val transferId = payload.optString("transfer_id")
            if (transferId.isBlank() || transferId.length > 64) return "invalid_transfer_id"
            val size = payload.optLong("size", -1)
            if (size < 0) return "invalid_size"
            if (size > maxBytes) return "file_too_large"
            val chunkSize = payload.optInt("chunk_size", 0)
            if (chunkSize !in 1..CCP_MAX_CHUNK_SIZE) return "invalid_chunk_size"
            if (payload.optInt("total_chunks", -1) != chunkCount(size, chunkSize)) return "invalid_total_chunks"
            if (!SHA256_HEX.matches(payload.optString("sha256").lowercase())) return "invalid_sha256"
            return null
        }

        /** Call only after [validateOffer] returned null. */
        fun create(inbox: File, payload: JSONObject): IncomingTransfer {
            inbox.mkdirs()
            return IncomingTransfer(
                transferId = payload.getString("transfer_id"),
                displayName = safeFilename(payload.optString("filename", "received-file")),
                file = File(inbox, "${UUID.randomUUID()}.part"),
                declaredSize = payload.getLong("size"),
                chunkSize = payload.getInt("chunk_size"),
                totalChunks = payload.getInt("total_chunks"),
                expectedHash = payload.getString("sha256").lowercase(),
            )
        }
    }
}
