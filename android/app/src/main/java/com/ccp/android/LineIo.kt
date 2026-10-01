package com.ccp.android

import java.io.BufferedInputStream
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream

/** Largest single newline-delimited frame accepted from a peer. */
const val CCP_MAX_FRAME_BYTES = 512 * 1024

class FrameTooLargeException(limit: Int) : IOException("Frame exceeds $limit bytes")

/**
 * Reads UTF-8, newline-delimited frames with a hard size cap so a peer cannot
 * exhaust memory by streaming a line that never ends.
 */
class BoundedLineReader(
    input: InputStream,
    private val maxBytes: Int = CCP_MAX_FRAME_BYTES,
) {
    private val stream = if (input is BufferedInputStream) input else BufferedInputStream(input, 16 * 1024)
    private val buffer = ByteArrayOutputStream(4 * 1024)

    /** Returns the next line without the terminator, or null at end of stream. */
    fun readLine(): String? {
        buffer.reset()
        while (true) {
            val next = stream.read()
            if (next == -1) {
                return if (buffer.size() == 0) null else buffer.toString(Charsets.UTF_8.name())
            }
            if (next == '\n'.code) {
                val text = buffer.toString(Charsets.UTF_8.name())
                return if (text.endsWith('\r')) text.dropLast(1) else text
            }
            if (buffer.size() >= maxBytes) throw FrameTooLargeException(maxBytes)
            buffer.write(next)
        }
    }
}

/** Writes one UTF-8 frame terminated by '\n' and flushes. */
class LineWriter(private val output: OutputStream) {
    @Synchronized
    fun writeLine(text: String) {
        output.write(text.toByteArray(Charsets.UTF_8))
        output.write('\n'.code)
        output.flush()
    }
}
