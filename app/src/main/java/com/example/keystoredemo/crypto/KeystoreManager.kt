package com.example.keystoredemo.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

enum class AuthMode(val label: String, val description: String) {
    NONE(
        "No Authentication",
        "Key usable anytime — no user verification required."
    ),
    BIOMETRIC_ONLY(
        "Biometric Only",
        "Requires fingerprint or face. Fails if no biometric enrolled. Analogous to iOS kSecAccessControlBiometryAny."
    ),
    DEVICE_CREDENTIAL(
        "Device Credential (PIN/Pattern/Password)",
        "Requires screen lock credential. Works even without biometrics enrolled."
    ),
    BIOMETRIC_OR_CREDENTIAL(
        "Biometric OR Credential",
        "User can authenticate with either biometric or PIN/pattern/password. Most flexible."
    ),
    BIOMETRIC_PER_USE(
        "Biometric Per-Use (Crypto-Bound)",
        "Each crypto operation requires a fresh biometric. The Cipher must be initialized inside BiometricPrompt.CryptoObject. Strongest protection."
    ),
    UNLOCKED_DEVICE(
        "Unlocked Device Required",
        "Key only usable while device is unlocked. Becomes unavailable when screen locks. No prompt shown."
    )
}

object KeystoreManager {
    private const val KEYSTORE_PROVIDER = "AndroidKeyStore"

    fun generateProtectedAesKey(alias: String, mode: AuthMode): String {
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE_PROVIDER)
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)

        when (mode) {
            AuthMode.NONE -> { }
            AuthMode.BIOMETRIC_ONLY -> {
                builder.setUserAuthenticationRequired(true)
                builder.setUserAuthenticationParameters(30, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            AuthMode.DEVICE_CREDENTIAL -> {
                builder.setUserAuthenticationRequired(true)
                builder.setUserAuthenticationParameters(30, KeyProperties.AUTH_DEVICE_CREDENTIAL)
            }
            AuthMode.BIOMETRIC_OR_CREDENTIAL -> {
                builder.setUserAuthenticationRequired(true)
                builder.setUserAuthenticationParameters(
                    30,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                )
            }
            AuthMode.BIOMETRIC_PER_USE -> {
                builder.setUserAuthenticationRequired(true)
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            }
            AuthMode.UNLOCKED_DEVICE -> {
                builder.setUnlockedDeviceRequired(true)
            }
        }

        keyGen.init(builder.build())
        keyGen.generateKey()
        return "AES-256-GCM key '$alias' created [${mode.label}]"
    }

    fun generateAesKey(alias: String, requireAuth: Boolean = false): String {
        return generateProtectedAesKey(alias, if (requireAuth) AuthMode.BIOMETRIC_ONLY else AuthMode.NONE)
    }

    fun generateRsaKeyPair(alias: String): String {
        val keyGen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, KEYSTORE_PROVIDER)
        keyGen.initialize(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY or
                        KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PKCS1)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_PKCS1)
                .setKeySize(2048)
                .build()
        )
        keyGen.generateKeyPair()
        return "RSA-2048 key pair '$alias' created"
    }

    fun generateEcKeyPair(alias: String): String {
        val keyGen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
        keyGen.initialize(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            )
                .setDigests(KeyProperties.DIGEST_SHA256)
                .setKeySize(256)
                .build()
        )
        keyGen.generateKeyPair()
        return "EC P-256 key pair '$alias' created"
    }

    fun generateHmacKey(alias: String): String {
        val keyGen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_HMAC_SHA256, KEYSTORE_PROVIDER)
        keyGen.init(
            KeyGenParameterSpec.Builder(
                alias,
                KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
            ).build()
        )
        keyGen.generateKey()
        return "HMAC-SHA256 key '$alias' created"
    }

    fun initEncryptCipher(alias: String): Cipher {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val key = keyStore.getKey(alias, null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        return cipher
    }

    fun encryptWithCipher(cipher: Cipher, plaintext: String): Pair<String, String> {
        val iv = cipher.iv
        val ciphertext = cipher.doFinal(plaintext.toByteArray())
        return Base64.getEncoder().encodeToString(iv) to Base64.getEncoder().encodeToString(ciphertext)
    }

    fun encryptAes(alias: String, plaintext: String): Pair<String, String> {
        val cipher = initEncryptCipher(alias)
        return encryptWithCipher(cipher, plaintext)
    }

    fun decryptAes(alias: String, ivBase64: String, ciphertextBase64: String): String {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val key = keyStore.getKey(alias, null) as SecretKey
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val iv = Base64.getDecoder().decode(ivBase64)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
        val plaintext = cipher.doFinal(Base64.getDecoder().decode(ciphertextBase64))
        return String(plaintext)
    }

    fun encryptRsa(alias: String, plaintext: String): String {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val publicKey = keyStore.getCertificate(alias).publicKey
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, publicKey)
        val ciphertext = cipher.doFinal(plaintext.toByteArray())
        return Base64.getEncoder().encodeToString(ciphertext)
    }

    fun decryptRsa(alias: String, ciphertextBase64: String): String {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val privateKey = keyStore.getKey(alias, null)
        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, privateKey)
        val plaintext = cipher.doFinal(Base64.getDecoder().decode(ciphertextBase64))
        return String(plaintext)
    }

    fun signWithRsa(alias: String, data: String): String {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val privateKey = keyStore.getKey(alias, null) as java.security.PrivateKey
        val signature = Signature.getInstance("SHA256withRSA")
        signature.initSign(privateKey)
        signature.update(data.toByteArray())
        return Base64.getEncoder().encodeToString(signature.sign())
    }

    fun verifyWithRsa(alias: String, data: String, signatureBase64: String): Boolean {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val publicKey = keyStore.getCertificate(alias).publicKey
        val sig = Signature.getInstance("SHA256withRSA")
        sig.initVerify(publicKey)
        sig.update(data.toByteArray())
        return sig.verify(Base64.getDecoder().decode(signatureBase64))
    }

    fun signWithEc(alias: String, data: String): String {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val privateKey = keyStore.getKey(alias, null) as java.security.PrivateKey
        val signature = Signature.getInstance("SHA256withECDSA")
        signature.initSign(privateKey)
        signature.update(data.toByteArray())
        return Base64.getEncoder().encodeToString(signature.sign())
    }

    fun verifyWithEc(alias: String, data: String, signatureBase64: String): Boolean {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val publicKey = keyStore.getCertificate(alias).publicKey
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initVerify(publicKey)
        sig.update(data.toByteArray())
        return sig.verify(Base64.getDecoder().decode(signatureBase64))
    }

    fun getKeyAuthInfo(alias: String): KeyAuthInfo? {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        val entry = keyStore.getEntry(alias, null) ?: return null
        return when (entry) {
            is KeyStore.SecretKeyEntry -> {
                val factory = SecretKeyFactory.getInstance(entry.secretKey.algorithm, KEYSTORE_PROVIDER)
                val info = factory.getKeySpec(entry.secretKey, KeyInfo::class.java) as KeyInfo
                buildKeyAuthInfo(info)
            }
            is KeyStore.PrivateKeyEntry -> {
                val factory = java.security.KeyFactory.getInstance(entry.privateKey.algorithm, KEYSTORE_PROVIDER)
                val info = factory.getKeySpec(entry.privateKey, KeyInfo::class.java) as KeyInfo
                buildKeyAuthInfo(info)
            }
            else -> null
        }
    }

    private fun buildKeyAuthInfo(info: KeyInfo): KeyAuthInfo {
        val authRequired = info.isUserAuthenticationRequired
        val authTimeout = info.userAuthenticationValidityDurationSeconds
        val perUse = authRequired && authTimeout == 0
        val authTypes = if (authRequired) info.userAuthenticationType else 0

        val biometric = (authTypes and KeyProperties.AUTH_BIOMETRIC_STRONG) != 0
        val credential = (authTypes and KeyProperties.AUTH_DEVICE_CREDENTIAL) != 0

        val modeLabel = when {
            !authRequired -> "None"
            perUse && biometric -> "Biometric per-use (crypto-bound)"
            biometric && credential -> "Biometric OR Credential (${authTimeout}s)"
            biometric -> "Biometric only (${authTimeout}s)"
            credential -> "Device Credential only (${authTimeout}s)"
            else -> "Auth required (${authTimeout}s)"
        }

        return KeyAuthInfo(
            requiresAuth = authRequired,
            biometricAllowed = biometric,
            credentialAllowed = credential,
            perUse = perUse,
            validitySeconds = authTimeout,
            modeLabel = modeLabel,
            securityLevel = info.securityLevel
        )
    }

    fun listKeys(): List<KeyInfo_> {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        return keyStore.aliases().toList().map { alias ->
            val entry = keyStore.getEntry(alias, null)
            val algorithm: String
            val isHardwareBacked: Boolean
            val keySize: Int
            var authInfo: KeyAuthInfo? = null

            when (entry) {
                is KeyStore.SecretKeyEntry -> {
                    algorithm = entry.secretKey.algorithm
                    val factory = SecretKeyFactory.getInstance(entry.secretKey.algorithm, KEYSTORE_PROVIDER)
                    val info = factory.getKeySpec(entry.secretKey, KeyInfo::class.java) as KeyInfo
                    isHardwareBacked = info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
                    keySize = info.keySize
                    authInfo = buildKeyAuthInfo(info)
                }
                is KeyStore.PrivateKeyEntry -> {
                    algorithm = entry.privateKey.algorithm
                    val factory = java.security.KeyFactory.getInstance(entry.privateKey.algorithm, KEYSTORE_PROVIDER)
                    val info = factory.getKeySpec(entry.privateKey, KeyInfo::class.java) as KeyInfo
                    isHardwareBacked = info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                            info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
                    keySize = info.keySize
                    authInfo = buildKeyAuthInfo(info)
                }
                else -> {
                    algorithm = "Unknown"
                    isHardwareBacked = false
                    keySize = 0
                }
            }

            KeyInfo_(alias, algorithm, keySize, isHardwareBacked, authInfo)
        }
    }

    fun deleteKey(alias: String) {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        keyStore.deleteEntry(alias)
    }

    fun deleteAllDemoKeys() {
        val keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }
        keyStore.aliases().toList()
            .filter { it.startsWith("demo_") }
            .forEach { keyStore.deleteEntry(it) }
    }
}

data class KeyAuthInfo(
    val requiresAuth: Boolean,
    val biometricAllowed: Boolean,
    val credentialAllowed: Boolean,
    val perUse: Boolean,
    val validitySeconds: Int,
    val modeLabel: String,
    val securityLevel: Int
)

data class KeyInfo_(
    val alias: String,
    val algorithm: String,
    val keySize: Int,
    val isHardwareBacked: Boolean,
    val authInfo: KeyAuthInfo? = null
)
