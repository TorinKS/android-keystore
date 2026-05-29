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
fun SignVerifyScreen(onBack: () -> Unit) {
    var dataToSign by remember { mutableStateOf("This message is authentic.") }
    var log by remember { mutableStateOf("Digital signatures prove data integrity and authenticity.\n\nPrivate key (in Keystore) signs → Public key verifies.\nThe private key never leaves hardware.") }

    val rsaAlias = "demo_sign_rsa"
    val ecAlias = "demo_sign_ec"
    var rsaSignature by remember { mutableStateOf("") }
    var ecSignature by remember { mutableStateOf("") }

    fun appendLog(msg: String) {
        log = "$log\n\n> $msg"
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Sign / Verify") },
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
            OutlinedTextField(
                value = dataToSign,
                onValueChange = { dataToSign = it },
                label = { Text("Data to Sign") },
                modifier = Modifier.fillMaxWidth()
            )

            Text("RSA-2048 SHA256 Signature", style = MaterialTheme.typography.titleSmall)

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    try {
                        appendLog(KeystoreManager.generateRsaKeyPair(rsaAlias))
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("1. Gen Key") }

                Button(onClick = {
                    try {
                        rsaSignature = KeystoreManager.signWithRsa(rsaAlias, dataToSign)
                        appendLog("RSA Signature:\n${rsaSignature.take(40)}...")
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("2. Sign") }

                Button(onClick = {
                    try {
                        val valid = KeystoreManager.verifyWithRsa(rsaAlias, dataToSign, rsaSignature)
                        appendLog("RSA Verify: ${if (valid) "VALID" else "INVALID"}")
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("3. Verify") }
            }

            FilledTonalButton(onClick = {
                try {
                    val valid = KeystoreManager.verifyWithRsa(rsaAlias, dataToSign + " TAMPERED", rsaSignature)
                    appendLog("RSA Verify (tampered data): ${if (valid) "VALID" else "INVALID — tampering detected!"}")
                } catch (e: Exception) {
                    appendLog("ERROR: ${e.message}")
                }
            }) { Text("Verify with Tampered Data") }

            HorizontalDivider()

            Text("ECDSA P-256 SHA256 Signature", style = MaterialTheme.typography.titleSmall)
            Text(
                "EC signatures are smaller and faster than RSA. Common for mobile apps.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    try {
                        appendLog(KeystoreManager.generateEcKeyPair(ecAlias))
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("1. Gen Key") }

                Button(onClick = {
                    try {
                        ecSignature = KeystoreManager.signWithEc(ecAlias, dataToSign)
                        appendLog("EC Signature:\n$ecSignature")
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("2. Sign") }

                Button(onClick = {
                    try {
                        val valid = KeystoreManager.verifyWithEc(ecAlias, dataToSign, ecSignature)
                        appendLog("EC Verify: ${if (valid) "VALID" else "INVALID"}")
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("3. Verify") }
            }

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
