package com.example.keystoredemo.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.example.keystoredemo.crypto.KeystoreManager

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyGenScreen(onBack: () -> Unit) {
    var log by remember { mutableStateOf("Ready to generate keys.\n\nKeys are stored in the Android Keystore — a hardware-backed (TEE/StrongBox) secure container. Keys never leave the secure hardware in plaintext.\n\nThis is the Android equivalent of storing keys in the iOS Secure Enclave via Keychain.") }
    var aliasCounter by remember { mutableIntStateOf(1) }

    fun appendLog(msg: String) {
        log = "$log\n\n> $msg"
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Key Generation") },
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
            Text("Generate Cryptographic Keys", style = MaterialTheme.typography.titleMedium)
            Text(
                "Each button generates a key in the Android Keystore. " +
                "Keys are bound to hardware and cannot be exported.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    val alias = "demo_aes_${aliasCounter++}"
                    try {
                        appendLog(KeystoreManager.generateAesKey(alias))
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("AES-256") }

                Button(onClick = {
                    val alias = "demo_rsa_${aliasCounter++}"
                    try {
                        appendLog(KeystoreManager.generateRsaKeyPair(alias))
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("RSA-2048") }
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    val alias = "demo_ec_${aliasCounter++}"
                    try {
                        appendLog(KeystoreManager.generateEcKeyPair(alias))
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("EC P-256") }

                Button(onClick = {
                    val alias = "demo_hmac_${aliasCounter++}"
                    try {
                        appendLog(KeystoreManager.generateHmacKey(alias))
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("HMAC-SHA256") }
            }

            FilledTonalButton(onClick = {
                val alias = "demo_aes_bio_${aliasCounter++}"
                try {
                    appendLog(KeystoreManager.generateAesKey(alias, requireAuth = true))
                    appendLog("(This key requires biometric authentication before each use — similar to kSecAccessControlBiometryAny on iOS)")
                } catch (e: Exception) {
                    appendLog("ERROR: ${e.message}")
                }
            }) { Text("AES-256 + Biometric") }

            HorizontalDivider()

            OutlinedButton(
                onClick = {
                    try {
                        KeystoreManager.deleteAllDemoKeys()
                        appendLog("All demo keys deleted from Keystore")
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                },
                colors = ButtonDefaults.outlinedButtonColors(
                    contentColor = MaterialTheme.colorScheme.error
                )
            ) { Text("Delete All Demo Keys") }

            HorizontalDivider()

            Text("Log", style = MaterialTheme.typography.labelLarge)
            Surface(
                tonalElevation = 2.dp,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = log,
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
            }
        }
    }
}
