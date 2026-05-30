package com.example.keystoredemo.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

data class DemoItem(
    val title: String,
    val subtitle: String,
    val icon: ImageVector,
    val route: String
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen(onNavigate: (String) -> Unit) {
    val items = listOf(
        DemoItem("Key Generation", "AES, RSA, EC, HMAC keys in Android Keystore", Icons.Default.Key, "keygen"),
        DemoItem("Key Protection", "Biometric, PIN, credential-gated key access", Icons.Default.Fingerprint, "protection"),
        DemoItem("Encrypt / Decrypt", "AES-GCM and RSA encryption using Keystore keys", Icons.Default.Lock, "encrypt"),
        DemoItem("Sign / Verify", "RSA and ECDSA digital signatures", Icons.Default.VerifiedUser, "sign"),
        DemoItem("Secret Storage", "EncryptedSharedPreferences for tokens & passwords", Icons.Default.Security, "secrets"),
        DemoItem("E2E 2FA Flow", "Full enrollment + auth with real server backend", Icons.Default.Cloud, "e2eflow"),
        DemoItem("Key Attestation", "Prove key is hardware-backed via Google CA", Icons.Default.Verified, "attestation"),
        DemoItem("Key Inspector", "List all Keystore keys and their properties", Icons.Default.List, "keys"),
    )

    Scaffold(
        topBar = {
            LargeTopAppBar(
                title = {
                    Column {
                        Text("Android Keystore", fontWeight = FontWeight.Bold)
                        Text(
                            "iOS Keychain Analogues Demo",
                            style = MaterialTheme.typography.titleSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
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
            items.forEach { item ->
                ElevatedCard(
                    onClick = { onNavigate(item.route) },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(20.dp),
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(16.dp)
                    ) {
                        Icon(
                            item.icon,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(32.dp)
                        )
                        Column(modifier = Modifier.weight(1f)) {
                            Text(item.title, style = MaterialTheme.typography.titleMedium)
                            Text(
                                item.subtitle,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                        Icon(Icons.Default.ChevronRight, contentDescription = null)
                    }
                }
            }

            Spacer(Modifier.height(8.dp))

            OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("About This Demo", style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "This app demonstrates Android's equivalents to the iOS Keychain:\n\n" +
                        "• Android Keystore System — hardware-backed cryptographic key storage (TEE/StrongBox)\n" +
                        "• EncryptedSharedPreferences — secure storage for arbitrary secrets (tokens, passwords)\n\n" +
                        "iOS Keychain is a unified API for both keys and secrets. Android splits this across " +
                        "Keystore (keys) + EncryptedSharedPreferences (data), but the security model is comparable.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }
    }
}
