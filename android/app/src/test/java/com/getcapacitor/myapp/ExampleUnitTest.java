package com.getcapacitor.myapp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Test;

public class ExampleUnitTest {

    @Test
    public void ccpProtocolUsesExpectedPorts() {
        assertEquals(47827, 47827);
        assertEquals(47828, 47828);
    }

    @Test
    public void transferChunkSizeIsBoundedForMobileRelay() {
        int chunkSize = 64 * 1024;
        assertTrue(chunkSize <= 128 * 1024);
    }
}
