package com.example.keystoredemo.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.keystoredemo.crypto.SecretStorageManager

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecretStorageScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var secretKey by remember { mutableStateOf("auth_token") }
    var secretValue by remember { mutableStateOf("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...") }
    var storedSecrets by remember { mutableStateOf(mapOf<String, String>()) }
    var log by remember { mutableStateOf("EncryptedSharedPreferences — the Android equivalent of storing arbitrary secrets in iOS Keychain.\n\nThe encryption key (AES-256-GCM) lives in the Android Keystore.\nThe encrypted data lives in SharedPreferences files.\n\nThis is the idiomatic way to store tokens, passwords, and API keys on Android.") }

    fun appendLog(msg: String) {
        log = "$log\n\n> $msg"
    }

    fun refreshSecrets() {
        try {
            storedSecrets = SecretStorageManager.listSecrets(context)
        } catch (e: Exception) {
            appendLog("ERROR listing: ${e.message}")
        }
    }

    LaunchedEffect(Unit) { refreshSecrets() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Secret Storage") },
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
            Text("EncryptedSharedPreferences", style = MaterialTheme.typography.titleMedium)

            OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text("How it works:", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelLarge)
                    Text(
                        "1. MasterKey is created in Android Keystore (AES-256-GCM)\n" +
                        "2. Keys are encrypted with AES-256-SIV (deterministic)\n" +
                        "3. Values are encrypted with AES-256-GCM\n" +
                        "4. Encrypted data stored in regular SharedPreferences XML file",
                        style = MaterialTheme.typography.bodySmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            OutlinedTextField(
                value = secretKey,
                onValueChange = { secretKey = it },
                label = { Text("Secret Name (key)") },
                modifier = Modifier.fillMaxWidth()
            )

            OutlinedTextField(
                value = secretValue,
                onValueChange = { secretValue = it },
                label = { Text("Secret Value") },
                modifier = Modifier.fillMaxWidth()
            )

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = {
                    try {
                        SecretStorageManager.saveSecret(context, secretKey, secretValue)
                        appendLog("Saved: '$secretKey' = '${secretValue.take(20)}...'")
                        refreshSecrets()
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("Save Secret") }

                Button(onClick = {
                    try {
                        val value = SecretStorageManager.readSecret(context, secretKey)
                        appendLog("Read '$secretKey': ${value ?: "(not found)"}")
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.message}")
                    }
                }) { Text("Read Secret") }
            }

            if (storedSecrets.isNotEmpty()) {
                Text("Stored Secrets", style = MaterialTheme.typography.titleSmall)
                storedSecrets.forEach { (key, value) ->
                    ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(key, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    value.take(50) + if (value.length > 50) "..." else "",
                                    style = MaterialTheme.typography.bodySmall,
                                    fontFamily = FontFamily.Monospace,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            IconButton(onClick = {
                                SecretStorageManager.deleteSecret(context, key)
                                appendLog("Deleted '$key'")
                                refreshSecrets()
                            }) {
                                Icon(Icons.Default.Delete, contentDescription = "Delete", tint = MaterialTheme.colorScheme.error)
                            }
                        }
                    }
                }
            }

            OutlinedButton(
                onClick = {
                    SecretStorageManager.clearAll(context)
                    appendLog("All secrets cleared")
                    refreshSecrets()
                },
                colors = ButtonDefaults.outlinedButtonColors(contentColor = MaterialTheme.colorScheme.error)
            ) { Text("Clear All Secrets") }

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
