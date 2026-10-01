package com.ccp.android

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Encrypts small secrets (cloud auth token, pair secrets) with an AES-256-GCM
 * key that lives in the Android Keystore and never leaves it, so the values in
 * SharedPreferences are useless if the prefs file is copied off the device.
 *
 * Values are stored as "ks1:" + base64(iv || ciphertext || tag). Plain values
 * written by older builds are still readable and get re-encrypted on the next
 * write. If the Keystore is unavailable (rare, broken OEM implementations) the
 * box falls back to app-private plain storage rather than losing pairings.
 */
class SecretBox(private val alias: String = "ccp-secrets-v1") {
    private val key: SecretKey? = runCatching { loadOrCreateKey() }
        .onFailure { Log.w(TAG, "Android Keystore unavailable; secrets stay in app-private storage", it) }
        .getOrNull()

    val isHardwareBacked: Boolean get() = key != null

    fun seal(plaintext: String): String {
        val key = key ?: return plaintext
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val ciphertext = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return PREFIX + Base64.encodeToString(cipher.iv + ciphertext, Base64.NO_WRAP)
    }

    /** Returns null if a sealed value can't be opened (e.g. the key was wiped by a device reset). */
    fun open(stored: String): String? {
        if (!stored.startsWith(PREFIX)) return stored
        val key = key ?: return null
        return runCatching {
            val data = Base64.decode(stored.substring(PREFIX.length), Base64.NO_WRAP)
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, data, 0, IV_BYTES))
            String(cipher.doFinal(data, IV_BYTES, data.size - IV_BYTES), Charsets.UTF_8)
        }.getOrNull()
    }

    fun isSealed(stored: String): Boolean = stored.startsWith(PREFIX)

    private fun loadOrCreateKey(): SecretKey {
        val keyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (keyStore.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    private companion object {
        const val TAG = "CcpSecretBox"
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val PREFIX = "ks1:"
        const val IV_BYTES = 12
    }
}
