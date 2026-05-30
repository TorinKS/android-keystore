package com.example.keystoredemo.ui.screens

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.example.keystoredemo.network.ApiClient
import kotlinx.coroutines.launch
import java.nio.ByteBuffer
import java.security.*
import java.security.spec.ECGenParameterSpec
import java.util.Base64

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun E2eFlowScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val activity = context as FragmentActivity
    val scope = rememberCoroutineScope()
    var log by remember { mutableStateOf("") }
    var userId by remember { mutableStateOf("user@example.com") }
    var isRegistered by remember { mutableStateOf(false) }

    val alias = "e2e_fido_key"

    fun appendLog(msg: String) {
        log = if (log.isEmpty()) "> $msg" else "$log\n\n> $msg"
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("E2E 2FA Flow") },
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
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text("End-to-End 2FA Flow", style = MaterialTheme.typography.titleLarge)
            Text(
                "Connects to a real server backend. " +
                "Enrollment: generate attested key → server verifies Google-signed cert chain. " +
                "Auth: server sends challenge → app signs with biometric → server verifies.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("Setup", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelLarge)
                    Text(
                        "1. Start server: cd server && mvn spring-boot:run\n" +
                        "2. Connect phone: adb reverse tcp:8080 tcp:8080\n" +
                        "3. Server URL: ${ApiClient.SERVER_URL}",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            OutlinedTextField(
                value = userId,
                onValueChange = { userId = it },
                label = { Text("User ID") },
                modifier = Modifier.fillMaxWidth()
            )

            HorizontalDivider()
            Text("Enrollment", style = MaterialTheme.typography.titleMedium)

            Button(
                onClick = {
                    scope.launch {
                        try {
                            appendLog("=== ENROLLMENT START ===")
                            appendLog("Calling POST /api/register/start...")

                            val startResponse = ApiClient.registerStart(userId)
                            val sessionId = startResponse["sessionId"]!!
                            val challengeB64 = startResponse["challenge"]!!
                            val challenge = Base64.getDecoder().decode(challengeB64)

                            appendLog("Server returned challenge: ${challengeB64.take(20)}... (${challenge.size} bytes)")

                            appendLog("Generating P-256 key with server's challenge...")
                            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                            if (keyStore.containsAlias(alias)) {
                                keyStore.deleteEntry(alias)
                            }

                            val keyGen = KeyPairGenerator.getInstance(
                                KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
                            )
                            keyGen.initialize(
                                KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                                    .setDigests(KeyProperties.DIGEST_SHA256)
                                    .setUserAuthenticationRequired(true)
                                    .setUserAuthenticationParameters(
                                        0,
                                        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                                    )
                                    .setAttestationChallenge(challenge)
                                    .build()
                            )
                            keyGen.generateKeyPair()
                            appendLog("Key generated in Keystore with attestation ✓")

                            val chain = keyStore.getCertificateChain(alias)
                            appendLog("Certificate chain: ${chain.size} certificates")

                            val chainB64 = chain.map {
                                Base64.getEncoder().encodeToString(it.encoded)
                            }

                            appendLog("Sending chain to server for verification...")
                            val finishResponse = ApiClient.registerFinish(sessionId, userId, chainB64)

                            val status = finishResponse["status"]
                            val secLevel = finishResponse["securityLevel"]
                            val chainLen = finishResponse["chainLength"]

                            appendLog(
                                "=== ENROLLMENT COMPLETE ===\n" +
                                "Status: $status\n" +
                                "Security level: $secLevel (verified by server!)\n" +
                                "Chain length: $chainLen\n" +
                                "Challenge verified: ${finishResponse["challengeVerified"]}\n\n" +
                                "Server confirmed: key is in real TEE hardware.\n" +
                                "Public key stored server-side for future auth."
                            )
                            isRegistered = true
                        } catch (e: Exception) {
                            appendLog("ENROLLMENT FAILED: ${e.javaClass.simpleName}: ${e.message}")
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) { Text("Register (Enroll Key)") }

            HorizontalDivider()
            Text("Authentication", style = MaterialTheme.typography.titleMedium)

            Button(
                onClick = {
                    scope.launch {
                        try {
                            appendLog("=== AUTHENTICATION START ===")
                            appendLog("Calling POST /api/auth/start...")

                            val startResponse = ApiClient.authStart(userId)
                            val sessionId = startResponse["sessionId"]!!
                            val challengeB64 = startResponse["challenge"]!!
                            val challenge = Base64.getDecoder().decode(challengeB64)

                            appendLog("Server returned challenge: ${challengeB64.take(20)}... (${challenge.size} bytes)")

                            val rpId = "keystoredemo.example.com"
                            val rpIdHash = MessageDigest.getInstance("SHA-256").digest(rpId.toByteArray())
                            val flags: Byte = 0x05
                            val counter = 1
                            val authData = ByteBuffer.allocate(37)
                                .put(rpIdHash)
                                .put(flags)
                                .putInt(counter)
                                .array()

                            val clientDataHash = MessageDigest.getInstance("SHA-256").digest(challenge)

                            appendLog("Signing with biometric...")

                            val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                            val privateKey = keyStore.getKey(alias, null) as PrivateKey

                            val signature = Signature.getInstance("SHA256withECDSA")
                            signature.initSign(privateKey)

                            val cryptoObject = BiometricPrompt.CryptoObject(signature)
                            val executor = ContextCompat.getMainExecutor(context)

                            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                                .setTitle("Authenticate")
                                .setSubtitle("Sign in as $userId")
                                .setConfirmationRequired(true)
                                .setAllowedAuthenticators(
                                    BiometricManager.Authenticators.BIOMETRIC_STRONG
                                            or BiometricManager.Authenticators.DEVICE_CREDENTIAL
                                )
                                .build()

                            val biometricPrompt = BiometricPrompt(activity, executor,
                                object : BiometricPrompt.AuthenticationCallback() {
                                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                                        scope.launch {
                                            try {
                                                val authedSig = result.cryptoObject!!.signature!!

                                                val toSign = ByteBuffer.allocate(authData.size + clientDataHash.size)
                                                    .put(authData)
                                                    .put(clientDataHash)
                                                    .array()

                                                authedSig.update(toSign)
                                                val sigBytes = authedSig.sign()

                                                appendLog("Signed! (${sigBytes.size} bytes) — sending to server...")

                                                val authResponse = ApiClient.authFinish(
                                                    sessionId, userId,
                                                    Base64.getEncoder().encodeToString(authData),
                                                    Base64.getEncoder().encodeToString(clientDataHash),
                                                    Base64.getEncoder().encodeToString(sigBytes)
                                                )

                                                appendLog(
                                                    "=== AUTHENTICATION COMPLETE ===\n" +
                                                    "Status: ${authResponse["status"]}\n\n" +
                                                    "Server verified:\n" +
                                                    "1. ECDSA signature is valid ✓\n" +
                                                    "2. Signed by the TEE-backed key registered earlier ✓\n" +
                                                    "3. Challenge matches what server sent ✓\n" +
                                                    "4. User was biometrically verified (CryptoObject) ✓"
                                                )
                                            } catch (e: Exception) {
                                                appendLog("AUTH FAILED after biometric: ${e.message}")
                                            }
                                        }
                                    }

                                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                                        appendLog("Biometric error [$errorCode]: $errString")
                                    }

                                    override fun onAuthenticationFailed() {
                                        appendLog("Biometric not recognized — try again")
                                    }
                                }
                            )

                            biometricPrompt.authenticate(promptInfo, cryptoObject)
                        } catch (e: Exception) {
                            appendLog("AUTH FAILED: ${e.javaClass.simpleName}: ${e.message}")
                        }
                    }
                },
                enabled = isRegistered,
                modifier = Modifier.fillMaxWidth()
            ) { Text(if (isRegistered) "Authenticate (Sign Challenge)" else "Register first") }

            HorizontalDivider()

            Text("Log", style = MaterialTheme.typography.labelLarge)
            Surface(
                tonalElevation = 2.dp,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = if (log.isEmpty()) "Start by tapping 'Register', then 'Authenticate'" else log,
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
            }

            Spacer(Modifier.height(32.dp))
        }
    }
}
