package com.example.keystoreattacker

import android.os.Bundle
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MaterialTheme(colorScheme = darkColorScheme()) {
                Surface(modifier = Modifier.fillMaxSize()) {
                    AttackerScreen()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AttackerScreen() {
    var log by remember { mutableStateOf("") }

    fun appendLog(msg: String) {
        log = if (log.isEmpty()) msg else "$log\n\n$msg"
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = {
                    Column {
                        Text("Keystore Attacker", fontWeight = FontWeight.Bold)
                        Text(
                            "Can we steal keys from another app?",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.errorContainer,
                    titleContentColor = MaterialTheme.colorScheme.onErrorContainer
                )
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
            Text(
                "This app (com.example.keystoreattacker) attempts to access " +
                "keys created by the Keystore Demo app (com.example.keystoredemo). " +
                "Every attempt should FAIL — proving that Android Keystore is sandboxed per app.",
                style = MaterialTheme.typography.bodySmall
            )

            Button(
                onClick = {
                    appendLog("═══ ATTACK 1: List all Keystore aliases ═══")
                    appendLog("Trying to enumerate all keys in AndroidKeyStore...")
                    try {
                        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                        val aliases = ks.aliases().toList()
                        if (aliases.isEmpty()) {
                            appendLog("RESULT: No keys found!\n" +
                                "The Keystore namespace is EMPTY from this app's perspective.\n" +
                                "Keys from com.example.keystoredemo are INVISIBLE.\n" +
                                "Each app gets its own isolated Keystore namespace (bound to UID).")
                        } else {
                            appendLog("Found ${aliases.size} key(s): ${aliases.joinToString()}\n" +
                                "(These are THIS app's own keys, not the victim app's)")
                        }
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message}")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) { Text("Attack 1: Enumerate Keys") }

            Button(
                onClick = {
                    appendLog("═══ ATTACK 2: Access key by known alias ═══")
                    val targetAliases = listOf(
                        "demo_aes_1", "demo_rsa_1", "demo_ec_1",
                        "demo_prot_none", "demo_prot_biometric_only",
                        "demo_enc_aes", "demo_enc_rsa",
                        "demo_sign_rsa", "demo_sign_ec"
                    )
                    appendLog("Trying known aliases from the Demo app:\n${targetAliases.joinToString("\n")}")

                    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    var found = 0
                    for (alias in targetAliases) {
                        try {
                            val entry = ks.getEntry(alias, null)
                            if (entry != null) {
                                found++
                                appendLog("FOUND '$alias': ${entry.javaClass.simpleName}")
                            } else {
                                appendLog("'$alias': null — does not exist in our namespace")
                            }
                        } catch (e: Exception) {
                            appendLog("'$alias': ${e.javaClass.simpleName}")
                        }
                    }
                    appendLog(
                        if (found == 0)
                            "RESULT: 0 of ${targetAliases.size} keys accessible!\n" +
                            "Even knowing the exact alias names, we CANNOT access another app's keys.\n" +
                            "The Keystore daemon (keystore2) enforces UID-based isolation at the system level."
                        else
                            "WARNING: Found $found key(s) — this should not happen!"
                    )
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) { Text("Attack 2: Access by Known Alias") }

            Button(
                onClick = {
                    appendLog("═══ ATTACK 3: Try to use victim's AES key ═══")
                    appendLog("Attempting: Cipher.init() with alias 'demo_enc_aes'...")
                    try {
                        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                        val key = ks.getKey("demo_enc_aes", null)
                        if (key == null) {
                            appendLog("RESULT: getKey() returned null — key does not exist in our namespace.\n" +
                                "Cannot encrypt, decrypt, or use the key in any way.\n" +
                                "The key exists in com.example.keystoredemo's namespace but is completely invisible to us.")
                        } else {
                            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                            cipher.init(Cipher.ENCRYPT_MODE, key as SecretKey)
                            appendLog("WARNING: Cipher initialized — this should NOT happen!")
                        }
                    } catch (e: Exception) {
                        appendLog("BLOCKED: ${e.javaClass.simpleName}: ${e.message}")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) { Text("Attack 3: Use Victim's AES Key") }

            Button(
                onClick = {
                    appendLog("═══ ATTACK 4: Try to sign with victim's RSA key ═══")
                    appendLog("Attempting: Signature.initSign() with alias 'demo_sign_rsa'...")
                    try {
                        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                        val key = ks.getKey("demo_sign_rsa", null)
                        if (key == null) {
                            appendLog("RESULT: getKey() returned null — private key invisible.\n" +
                                "Cannot sign anything with the victim app's RSA key.\n" +
                                "Even the public key certificate is inaccessible.")
                        } else {
                            val sig = Signature.getInstance("SHA256withRSA")
                            sig.initSign(key as java.security.PrivateKey)
                            appendLog("WARNING: Signature initialized — this should NOT happen!")
                        }
                    } catch (e: Exception) {
                        appendLog("BLOCKED: ${e.javaClass.simpleName}: ${e.message}")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) { Text("Attack 4: Sign with Victim's RSA Key") }

            Button(
                onClick = {
                    appendLog("═══ ATTACK 5: Create key with SAME alias ═══")
                    appendLog("Creating our own 'demo_enc_aes' key — does it collide?")
                    try {
                        val keyGen = KeyGenerator.getInstance(
                            KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore"
                        )
                        keyGen.init(
                            KeyGenParameterSpec.Builder(
                                "demo_enc_aes",
                                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                            )
                            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                            .setKeySize(256)
                            .build()
                        )
                        keyGen.generateKey()

                        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                        val key = ks.getKey("demo_enc_aes", null) as SecretKey
                        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                        cipher.init(Cipher.ENCRYPT_MODE, key)
                        val ct = cipher.doFinal("attacker data".toByteArray())

                        appendLog("RESULT: We created OUR OWN 'demo_enc_aes' — it works!\n" +
                            "But this is OUR key, not the victim's. Same alias, different namespace.\n" +
                            "Ciphertext: ${Base64.getEncoder().encodeToString(ct).take(30)}...\n\n" +
                            "The victim app's 'demo_enc_aes' is completely separate.\n" +
                            "Our key cannot decrypt their data. Their key cannot decrypt ours.\n" +
                            "Alias names are scoped to UID — no collision possible.")
                    } catch (e: Exception) {
                        appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message}")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) { Text("Attack 5: Same Alias Collision") }

            Button(
                onClick = {
                    appendLog("═══ ATTACK 6: Read EncryptedSharedPreferences ═══")
                    appendLog("Trying to read victim's SharedPreferences file directly...")
                    try {
                        val victimPrefsPath = "/data/data/com.example.keystoredemo/shared_prefs/demo_secret_prefs.xml"
                        val file = java.io.File(victimPrefsPath)
                        if (file.exists()) {
                            val content = file.readText()
                            appendLog("File accessible! Content:\n$content")
                        } else {
                            appendLog("RESULT: File not accessible — permission denied.\n" +
                                "Path: $victimPrefsPath\n" +
                                "Android's filesystem sandboxing prevents reading another app's private files.\n" +
                                "Even if we could read the XML, the values are AES-256-GCM encrypted\n" +
                                "with a key in the victim's Keystore namespace — double protection.")
                        }
                    } catch (e: SecurityException) {
                        appendLog("BLOCKED by SecurityException: ${e.message}\n" +
                            "Android prevents filesystem access to other apps' private storage.")
                    } catch (e: Exception) {
                        appendLog("BLOCKED: ${e.javaClass.simpleName}: ${e.message}")
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) { Text("Attack 6: Read Victim's SharedPrefs") }

            Button(
                onClick = {
                    appendLog("═══ ATTACK 7: Brute-force enumerate aliases ═══")
                    appendLog("Trying 20 common alias patterns...")
                    val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    val patterns = listOf(
                        "master_key", "_androidx_security_master_key_",
                        "key", "secret", "token", "auth",
                        "encryption_key", "signing_key",
                        "aes_key", "rsa_key", "ec_key",
                        "demo_aes_1", "demo_rsa_2", "demo_ec_3",
                        "demo_hmac_1", "demo_prot_none",
                        "demo_prot_biometric_only", "demo_prot_device_credential",
                        "demo_prot_biometric_or_credential", "demo_prot_biometric_per_use"
                    )
                    var found = 0
                    for (alias in patterns) {
                        if (ks.containsAlias(alias)) {
                            found++
                            appendLog("HIT: '$alias' exists (but it's OUR key if we created it earlier)")
                        }
                    }
                    appendLog(
                        "RESULT: ${found} alias(es) found in OUR namespace.\n" +
                        "None of these are the victim's keys — even if aliases match,\n" +
                        "they're in a completely separate namespace.\n\n" +
                        "CONCLUSION: Brute-forcing aliases is useless. The isolation\n" +
                        "is at the UID level in the keystore2 system daemon,\n" +
                        "not at the alias level."
                    )
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) { Text("Attack 7: Brute-Force Aliases") }

            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))

            OutlinedCard(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("Why All Attacks Fail", fontWeight = FontWeight.Bold)
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "Android Keystore isolation is enforced at multiple layers:\n\n" +
                        "1. KERNEL LEVEL: Each app runs under a unique Linux UID. " +
                        "The keystore2 daemon checks the caller's UID and only " +
                        "returns keys belonging to that UID.\n\n" +
                        "2. FILESYSTEM LEVEL: Each app's /data/data/ directory " +
                        "has permissions 700 (owner only). Other apps cannot " +
                        "read SharedPreferences or any private files.\n\n" +
                        "3. HARDWARE LEVEL: Even if an attacker gains root, " +
                        "hardware-backed keys (TEE/StrongBox) cannot be extracted. " +
                        "The key material exists only inside the secure processor.\n\n" +
                        "4. SELinux: Mandatory Access Control policies prevent " +
                        "cross-app access even if DAC permissions are bypassed.\n\n" +
                        "This is fundamentally different from iOS Keychain access groups, " +
                        "which allow controlled sharing between apps from the same developer.",
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }

            Text("Attack Log", style = MaterialTheme.typography.labelLarge)
            Surface(
                tonalElevation = 2.dp,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = if (log.isEmpty()) "No attacks run yet. Tap a button above." else log,
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
            }

            Spacer(Modifier.height(32.dp))
        }
    }
}
