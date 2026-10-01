package com.ccp.android

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class LineIoTest {
    @Test
    fun readsLinesAndHandlesCrlfAndEof() {
        val reader = BoundedLineReader(ByteArrayInputStream("one\r\ntwo\nthree".toByteArray()))
        assertEquals("one", reader.readLine())
        assertEquals("two", reader.readLine())
        assertEquals("three", reader.readLine())
        assertNull(reader.readLine())
    }

    @Test
    fun decodesUtf8() {
        val reader = BoundedLineReader(ByteArrayInputStream("héllo ✓ 📁\n".toByteArray(Charsets.UTF_8)))
        assertEquals("héllo ✓ 📁", reader.readLine())
    }

    @Test(expected = FrameTooLargeException::class)
    fun rejectsOversizedFrames() {
        val reader = BoundedLineReader(ByteArrayInputStream(ByteArray(2048) { 'a'.code.toByte() }), maxBytes = 1024)
        reader.readLine()
    }

    @Test
    fun writerTerminatesFrames() {
        val out = ByteArrayOutputStream()
        LineWriter(out).apply { writeLine("a"); writeLine("b") }
        assertEquals("a\nb\n", out.toString(Charsets.UTF_8.name()))
    }
}
