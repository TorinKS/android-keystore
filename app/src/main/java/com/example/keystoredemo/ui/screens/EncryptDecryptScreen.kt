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
fun EncryptDecryptScreen(onBack: () -> Unit) {
    var plaintext by remember { mutableStateOf("Hello from Android Keystore!") }
    var log by remember { mutableStateOf("Keys never leave the secure hardware. Encryption/decryption happens inside the TEE.\n\nGenerate a key first, then encrypt and decrypt.") }

    val aesAlias = "demo_enc_aes"
    val rsaAlias = "demo_enc_rsa"
    var aesIv by remember { mutableStateOf("") }
    var aesCiphertext by remember { mutableStateOf("") }
    var rsaCiphertext by remember { mutableStateOf("") }

    fun appendLog(msg: String) {
        log = "$log\n\n> $msg"
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Encrypt / Decrypt") },
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
                value = plaintext,
                onValueChange = { plaintext = it },
                label = { Text("Plaintext") },
                modifier = Modifier.fillMaxWidth()
            )

            Text("AES-256-GCM (Symmetric)", style = MaterialTheme.typography.titleSmall)
            Text(
                "Same key encrypts and decrypts. Key stays in Keystore.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    try {
                        appendLog(KeystoreManager.generateAesKey(aesAlias))
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("1. Gen Key") }

                Button(onClick = {
                    try {
                        val (iv, ct) = KeystoreManager.encryptAes(aesAlias, plaintext)
                        aesIv = iv
                        aesCiphertext = ct
                        appendLog("AES Encrypted:\nIV: $iv\nCiphertext: ${ct.take(40)}...")
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("2. Encrypt") }

                Button(onClick = {
                    try {
                        val result = KeystoreManager.decryptAes(aesAlias, aesIv, aesCiphertext)
                        appendLog("AES Decrypted: $result")
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("3. Decrypt") }
            }

            HorizontalDivider()

            Text("RSA-2048 (Asymmetric)", style = MaterialTheme.typography.titleSmall)
            Text(
                "Public key encrypts, private key (in Keystore) decrypts.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

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
                        rsaCiphertext = KeystoreManager.encryptRsa(rsaAlias, plaintext)
                        appendLog("RSA Encrypted:\n${rsaCiphertext.take(40)}...")
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("2. Encrypt") }

                Button(onClick = {
                    try {
                        val result = KeystoreManager.decryptRsa(rsaAlias, rsaCiphertext)
                        appendLog("RSA Decrypted: $result")
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("3. Decrypt") }
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
