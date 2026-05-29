package com.example.keystoredemo.ui.screens

import android.content.ContextWrapper
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.example.keystoredemo.crypto.AuthMode
import com.example.keystoredemo.crypto.KeystoreManager

private const val TAG = "KeyProtection"

private fun android.content.Context.findFragmentActivity(): FragmentActivity {
    var ctx = this
    while (ctx is ContextWrapper) {
        if (ctx is FragmentActivity) return ctx
        ctx = ctx.baseContext
    }
    throw IllegalStateException("No FragmentActivity in context chain")
}

private fun biometricStatusString(code: Int): String = when (code) {
    BiometricManager.BIOMETRIC_SUCCESS -> "SUCCESS"
    BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> "NO_HARDWARE"
    BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "HW_UNAVAILABLE"
    BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "NONE_ENROLLED"
    BiometricManager.BIOMETRIC_ERROR_SECURITY_UPDATE_REQUIRED -> "SECURITY_UPDATE_REQUIRED"
    BiometricManager.BIOMETRIC_STATUS_UNKNOWN -> "STATUS_UNKNOWN"
    else -> "UNKNOWN($code)"
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyProtectionScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val activity = remember { context.findFragmentActivity() }

    var log by remember { mutableStateOf("") }
    var strongBioStatus by remember { mutableIntStateOf(-1) }
    var weakBioStatus by remember { mutableIntStateOf(-1) }
    var credentialStatus by remember { mutableIntStateOf(-1) }

    fun appendLog(msg: String) {
        log = if (log.isEmpty()) "> $msg" else "$log\n\n> $msg"
    }

    LaunchedEffect(Unit) {
        val bioManager = BiometricManager.from(context)

        strongBioStatus = bioManager.canAuthenticate(Authenticators.BIOMETRIC_STRONG)
        weakBioStatus = bioManager.canAuthenticate(Authenticators.BIOMETRIC_WEAK)
        credentialStatus = bioManager.canAuthenticate(Authenticators.DEVICE_CREDENTIAL)

        val strongCombo = bioManager.canAuthenticate(
            Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL
        )

        Log.d(TAG, "BIOMETRIC_STRONG: ${biometricStatusString(strongBioStatus)}")
        Log.d(TAG, "BIOMETRIC_WEAK: ${biometricStatusString(weakBioStatus)}")
        Log.d(TAG, "DEVICE_CREDENTIAL: ${biometricStatusString(credentialStatus)}")
        Log.d(TAG, "STRONG|CREDENTIAL: ${biometricStatusString(strongCombo)}")

        appendLog(
            "Device biometric capabilities:\n" +
            "  BIOMETRIC_STRONG: ${biometricStatusString(strongBioStatus)}\n" +
            "  BIOMETRIC_WEAK:   ${biometricStatusString(weakBioStatus)}\n" +
            "  DEVICE_CREDENTIAL: ${biometricStatusString(credentialStatus)}\n" +
            "  STRONG|CREDENTIAL: ${biometricStatusString(strongCombo)}"
        )
    }

    val biometricAvailable = strongBioStatus == BiometricManager.BIOMETRIC_SUCCESS ||
            weakBioStatus == BiometricManager.BIOMETRIC_SUCCESS
    val credentialAvailable = credentialStatus == BiometricManager.BIOMETRIC_SUCCESS

    fun tryUseKeyWithoutAuth(alias: String) {
        try {
            val (iv, ct) = KeystoreManager.encryptAes(alias, "test data")
            val decrypted = KeystoreManager.decryptAes(alias, iv, ct)
            appendLog("Key '$alias' used WITHOUT prompt — encrypted and decrypted: '$decrypted'")
        } catch (e: UserNotAuthenticatedException) {
            appendLog("BLOCKED: '$alias' threw UserNotAuthenticatedException — authentication required before use!")
        } catch (e: KeyPermanentlyInvalidatedException) {
            appendLog("INVALIDATED: '$alias' — key permanently invalidated (biometric enrollment changed)")
        } catch (e: Exception) {
            appendLog("Error using '$alias': ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    fun authenticateAndUseKey(alias: String, mode: AuthMode) {
        Log.d(TAG, "authenticateAndUseKey: alias=$alias mode=$mode")
        val executor = ContextCompat.getMainExecutor(context)

        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                Log.d(TAG, "onAuthenticationSucceeded for $alias, mode=$mode")
                if (mode == AuthMode.BIOMETRIC_PER_USE) {
                    val cipher = result.cryptoObject?.cipher
                    if (cipher != null) {
                        try {
                            val (iv, ct) = KeystoreManager.encryptWithCipher(cipher, "secret per-use data")
                            appendLog(
                                "PER-USE auth succeeded for '$alias'!\n" +
                                "Encrypted via CryptoObject cipher.\n" +
                                "IV: ${iv.take(20)}...\n" +
                                "Ciphertext: ${ct.take(30)}..."
                            )
                        } catch (e: Exception) {
                            appendLog("Encryption after per-use auth failed: ${e.message}")
                        }
                    } else {
                        appendLog("Per-use auth succeeded but no CryptoObject cipher returned")
                    }
                } else {
                    try {
                        val (iv, ct) = KeystoreManager.encryptAes(alias, "authenticated data")
                        val decrypted = KeystoreManager.decryptAes(alias, iv, ct)
                        appendLog("Auth succeeded for '$alias'! Encrypted and decrypted: '$decrypted'")
                    } catch (e: Exception) {
                        appendLog("Post-auth operation failed: ${e.javaClass.simpleName}: ${e.message}")
                    }
                }
            }

            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                Log.e(TAG, "onAuthenticationError: [$errorCode] $errString")
                appendLog("Auth error for '$alias': [$errorCode] $errString")
            }

            override fun onAuthenticationFailed() {
                Log.d(TAG, "onAuthenticationFailed for $alias")
                appendLog("Auth failed for '$alias' — biometric not recognized, try again")
            }
        }

        val biometricPrompt = BiometricPrompt(activity, executor, callback)

        try {
            when (mode) {
                AuthMode.BIOMETRIC_ONLY -> {
                    val authenticators = if (strongBioStatus == BiometricManager.BIOMETRIC_SUCCESS)
                        Authenticators.BIOMETRIC_STRONG
                    else
                        Authenticators.BIOMETRIC_WEAK

                    val promptInfo = BiometricPrompt.PromptInfo.Builder()
                        .setTitle("Biometric Authentication")
                        .setSubtitle("Authenticate to use key '$alias'")
                        .setDescription("This key requires biometric authentication.")
                        .setNegativeButtonText("Cancel")
                        .setConfirmationRequired(true)
                        .setAllowedAuthenticators(authenticators)
                        .build()

                    Log.d(TAG, "Showing biometric prompt for BIOMETRIC_ONLY")
                    biometricPrompt.authenticate(promptInfo)
                }
                AuthMode.DEVICE_CREDENTIAL -> {
                    val promptInfo = BiometricPrompt.PromptInfo.Builder()
                        .setTitle("Device Credential")
                        .setSubtitle("Enter PIN/Pattern/Password for key '$alias'")
                        .setDescription("This key requires device credential authentication.")
                        .setAllowedAuthenticators(Authenticators.DEVICE_CREDENTIAL)
                        .build()

                    Log.d(TAG, "Showing credential prompt")
                    biometricPrompt.authenticate(promptInfo)
                }
                AuthMode.BIOMETRIC_OR_CREDENTIAL -> {
                    val authenticators = if (strongBioStatus == BiometricManager.BIOMETRIC_SUCCESS)
                        Authenticators.BIOMETRIC_STRONG or Authenticators.DEVICE_CREDENTIAL
                    else
                        Authenticators.BIOMETRIC_WEAK or Authenticators.DEVICE_CREDENTIAL

                    val promptInfo = BiometricPrompt.PromptInfo.Builder()
                        .setTitle("Authentication Required")
                        .setSubtitle("Use biometric or enter PIN for key '$alias'")
                        .setDescription("This key accepts biometric OR device credential.")
                        .setConfirmationRequired(true)
                        .setAllowedAuthenticators(authenticators)
                        .build()

                    Log.d(TAG, "Showing biometric-or-credential prompt")
                    biometricPrompt.authenticate(promptInfo)
                }
                AuthMode.BIOMETRIC_PER_USE -> {
                    try {
                        val cipher = KeystoreManager.initEncryptCipher(alias)
                        val promptInfo = BiometricPrompt.PromptInfo.Builder()
                            .setTitle("Per-Use Biometric")
                            .setSubtitle("Authenticate for EACH crypto operation")
                            .setDescription("Cipher is bound to CryptoObject — one auth per use.")
                            .setNegativeButtonText("Cancel")
                            .setConfirmationRequired(true)
                            .setAllowedAuthenticators(Authenticators.BIOMETRIC_STRONG)
                            .build()

                        Log.d(TAG, "Showing per-use biometric prompt with CryptoObject")
                        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
                    } catch (e: Exception) {
                        appendLog("Per-use cipher init: ${e.javaClass.simpleName}: ${e.message}")
                    }
                }
                else -> {
                    appendLog("Mode ${mode.label} doesn't use BiometricPrompt")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "BiometricPrompt error", e)
            appendLog("BiometricPrompt error: ${e.javaClass.simpleName}: ${e.message}")
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Key Protection") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            Text("How Can We Protect Keys?", style = MaterialTheme.typography.titleLarge)
            Text(
                "Android Keystore keys can be protected with authentication requirements. " +
                "The key exists in hardware but is UNUSABLE until the user proves their identity. " +
                "This is analogous to iOS Keychain access controls (kSecAccessControl*).",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            AuthMode.entries.forEach { mode ->
                val alias = "demo_prot_${mode.name.lowercase()}"
                ProtectionModeCard(
                    mode = mode,
                    alias = alias,
                    biometricAvailable = biometricAvailable,
                    credentialAvailable = credentialAvailable,
                    onGenerate = {
                        try {
                            KeystoreManager.deleteKey(alias)
                        } catch (_: Exception) { }
                        try {
                            appendLog(KeystoreManager.generateProtectedAesKey(alias, mode))
                        } catch (e: Exception) {
                            appendLog("Generate failed: ${e.javaClass.simpleName}: ${e.message}")
                        }
                    },
                    onTryWithoutAuth = { tryUseKeyWithoutAuth(alias) },
                    onAuthenticate = { authenticateAndUseKey(alias, mode) }
                )
            }

            HorizontalDivider()

            OutlinedButton(
                onClick = {
                    KeystoreManager.deleteAllDemoKeys()
                    appendLog("All demo keys deleted")
                },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error),
                modifier = Modifier.fillMaxWidth()
            ) { Text("Delete All Demo Keys") }

            HorizontalDivider()

            OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("iOS Comparison", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelLarge)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "iOS Keychain access controls map to Android as follows:\n\n" +
                        "kSecAccessControlUserPresence → BIOMETRIC_OR_CREDENTIAL\n" +
                        "kSecAccessControlBiometryAny → BIOMETRIC_ONLY (30s)\n" +
                        "kSecAccessControlBiometryCurrentSet → BIOMETRIC_PER_USE\n" +
                        "kSecAccessControlDevicePasscode → DEVICE_CREDENTIAL\n" +
                        "kSecAttrAccessibleWhenUnlocked → UNLOCKED_DEVICE",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            Text("Log", style = MaterialTheme.typography.labelLarge)
            Surface(
                tonalElevation = 2.dp,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = if (log.isEmpty()) "Waiting for actions..." else log,
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
            }

            Spacer(Modifier.height(32.dp))
        }
    }
}

@Composable
private fun ProtectionModeCard(
    mode: AuthMode,
    alias: String,
    biometricAvailable: Boolean,
    credentialAvailable: Boolean,
    onGenerate: () -> Unit,
    onTryWithoutAuth: () -> Unit,
    onAuthenticate: () -> Unit
) {
    val icon = when (mode) {
        AuthMode.NONE -> Icons.Default.LockOpen
        AuthMode.BIOMETRIC_ONLY -> Icons.Default.Fingerprint
        AuthMode.DEVICE_CREDENTIAL -> Icons.Default.Pin
        AuthMode.BIOMETRIC_OR_CREDENTIAL -> Icons.Default.Shield
        AuthMode.BIOMETRIC_PER_USE -> Icons.Default.VerifiedUser
        AuthMode.UNLOCKED_DEVICE -> Icons.Default.PhoneLocked
    }

    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(28.dp)
                )
                Spacer(Modifier.width(12.dp))
                Text(mode.label, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.titleSmall)
            }

            Spacer(Modifier.height(8.dp))
            Text(mode.description, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)

            Spacer(Modifier.height(12.dp))
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                modifier = Modifier.fillMaxWidth()
            ) {
                FilledTonalButton(onClick = onGenerate) { Text("Generate") }

                OutlinedButton(onClick = onTryWithoutAuth) { Text("Use (no auth)") }

                if (mode != AuthMode.NONE && mode != AuthMode.UNLOCKED_DEVICE) {
                    Button(onClick = onAuthenticate) { Text("Auth & Use") }
                }
            }
        }
    }
}
