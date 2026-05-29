package com.example.keystoredemo.ui.screens

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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.example.keystoredemo.crypto.KeyInfo_
import com.example.keystoredemo.crypto.KeystoreManager

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyListScreen(onBack: () -> Unit) {
    var keys by remember { mutableStateOf(listOf<KeyInfo_>()) }
    var error by remember { mutableStateOf<String?>(null) }

    fun refresh() {
        try {
            keys = KeystoreManager.listKeys()
            error = null
        } catch (e: Exception) {
            error = e.message
        }
    }

    LaunchedEffect(Unit) { refresh() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Key Inspector") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
                actions = {
                    IconButton(onClick = { refresh() }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Refresh")
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
            Text("All keys in Android Keystore", style = MaterialTheme.typography.titleMedium)
            Text(
                "Shows every key stored in the Keystore, its algorithm, size, hardware-backing, " +
                "and authentication requirements.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            error?.let {
                ElevatedCard(
                    colors = CardDefaults.elevatedCardColors(
                        containerColor = MaterialTheme.colorScheme.errorContainer
                    )
                ) {
                    Text(
                        "Error: $it",
                        modifier = Modifier.padding(16.dp),
                        color = MaterialTheme.colorScheme.onErrorContainer
                    )
                }
            }

            if (keys.isEmpty() && error == null) {
                ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Text("No keys found", style = MaterialTheme.typography.titleSmall)
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "Generate keys from the Key Generation screen",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }

            keys.forEach { keyInfo ->
                ElevatedCard(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp)) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                if (keyInfo.isHardwareBacked) Icons.Default.Shield else Icons.Default.Warning,
                                contentDescription = null,
                                tint = if (keyInfo.isHardwareBacked)
                                    MaterialTheme.colorScheme.primary
                                else
                                    MaterialTheme.colorScheme.tertiary,
                                modifier = Modifier.size(28.dp)
                            )

                            Spacer(Modifier.width(12.dp))

                            Column(modifier = Modifier.weight(1f)) {
                                Text(keyInfo.alias, fontWeight = FontWeight.Bold, style = MaterialTheme.typography.bodyMedium)
                                Text(
                                    "${keyInfo.algorithm} · ${keyInfo.keySize}-bit · ${if (keyInfo.isHardwareBacked) "Hardware (TEE)" else "Software"}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }

                            if (keyInfo.alias.startsWith("demo_")) {
                                IconButton(onClick = {
                                    KeystoreManager.deleteKey(keyInfo.alias)
                                    refresh()
                                }) {
                                    Icon(
                                        Icons.Default.Delete,
                                        contentDescription = "Delete",
                                        tint = MaterialTheme.colorScheme.error
                                    )
                                }
                            }
                        }

                        keyInfo.authInfo?.let { auth ->
                            Spacer(Modifier.height(8.dp))
                            Row(
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.spacedBy(6.dp)
                            ) {
                                val (authIcon, authColor) = when {
                                    !auth.requiresAuth -> Icons.Default.LockOpen to MaterialTheme.colorScheme.outline
                                    auth.perUse -> Icons.Default.Fingerprint to MaterialTheme.colorScheme.error
                                    auth.biometricAllowed && auth.credentialAllowed ->
                                        Icons.Default.Shield to MaterialTheme.colorScheme.primary
                                    auth.biometricAllowed -> Icons.Default.Fingerprint to MaterialTheme.colorScheme.primary
                                    auth.credentialAllowed -> Icons.Default.Pin to MaterialTheme.colorScheme.tertiary
                                    else -> Icons.Default.Lock to MaterialTheme.colorScheme.outline
                                }
                                Icon(authIcon, contentDescription = null, modifier = Modifier.size(16.dp), tint = authColor)
                                Text(
                                    "Auth: ${auth.modeLabel}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = authColor
                                )
                            }
                        }
                    }
                }
            }

            if (keys.any { it.alias.startsWith("demo_") }) {
                Spacer(Modifier.height(8.dp))
                OutlinedButton(
                    onClick = {
                        KeystoreManager.deleteAllDemoKeys()
                        refresh()
                    },
                    colors = ButtonDefaults.outlinedButtonColors(
                        contentColor = MaterialTheme.colorScheme.error
                    ),
                    modifier = Modifier.fillMaxWidth()
                ) { Text("Delete All Demo Keys") }
            }

            Spacer(Modifier.height(16.dp))

            OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Comparison with iOS", fontWeight = FontWeight.Bold, style = MaterialTheme.typography.labelLarge)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "iOS Keychain stores both keys and arbitrary data in one API. " +
                        "Android Keystore only stores cryptographic keys — for arbitrary " +
                        "secrets, use EncryptedSharedPreferences (see Secret Storage screen).\n\n" +
                        "Both platforms support hardware-backed storage:\n" +
                        "• iOS: Secure Enclave\n" +
                        "• Android: TEE (Trusted Execution Environment) or StrongBox",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
    }
}
