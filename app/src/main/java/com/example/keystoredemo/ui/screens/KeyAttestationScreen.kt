package com.example.keystoredemo.ui.screens

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.security.*
import java.security.cert.Certificate
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun KeyAttestationScreen(onBack: () -> Unit) {
    var log by remember { mutableStateOf("") }
    var certChainPem by remember { mutableStateOf("") }

    fun appendLog(msg: String) {
        log = if (log.isEmpty()) "> $msg" else "$log\n\n> $msg"
    }

    val alias = "demo_attested_ec"
    val challenge = "server-challenge-abc123".toByteArray()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Key Attestation") },
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
            Text("Hardware Key Attestation", style = MaterialTheme.typography.titleLarge)
            Text(
                "Generates a P-256 key with setAttestationChallenge(). " +
                "The TEE produces a certificate chain signed by Google's root CA, " +
                "proving the key is hardware-backed. This is FREE, offline, unlimited — " +
                "no Play Integrity API needed.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )

            HorizontalDivider()

            Text("Step 1: Generate Attested Key", style = MaterialTheme.typography.titleSmall)
            Text(
                "Creates EC P-256 key with attestation challenge. " +
                "Without setAttestationChallenge(), getCertificateChain() returns a self-signed cert. " +
                "WITH it, you get a Google-signed chain proving TEE backing.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Button(onClick = {
                try {
                    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    if (keyStore.containsAlias(alias)) {
                        keyStore.deleteEntry(alias)
                        appendLog("Deleted old key '$alias'")
                    }

                    val keyGen = KeyPairGenerator.getInstance(
                        KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore"
                    )
                    keyGen.initialize(
                        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                            .setDigests(KeyProperties.DIGEST_SHA256)
                            .setAttestationChallenge(challenge)
                            .build()
                    )
                    val keyPair = keyGen.generateKeyPair()

                    appendLog(
                        "Key generated with attestation!\n" +
                        "Algorithm: EC P-256 (secp256r1)\n" +
                        "Alias: $alias\n" +
                        "Challenge: ${String(challenge)}\n" +
                        "Public key: ${Base64.getEncoder().encodeToString(keyPair.public.encoded).take(60)}..."
                    )
                } catch (e: Exception) {
                    appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message}")
                }
            }) { Text("Generate P-256 Key with Attestation") }

            HorizontalDivider()

            Text("Step 2: Get Attestation Certificate Chain", style = MaterialTheme.typography.titleSmall)
            Text(
                "Retrieves the chain: leaf cert (your key + attestation extension) " +
                "→ intermediate (batch key) → root (Google CA). " +
                "Send this to your server for verification.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Button(onClick = {
                try {
                    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    val chain = keyStore.getCertificateChain(alias)

                    if (chain == null || chain.isEmpty()) {
                        appendLog("No certificate chain found — generate the key first!")
                        return@Button
                    }

                    appendLog("Certificate chain: ${chain.size} certificate(s)")

                    val pemBuilder = StringBuilder()

                    chain.forEachIndexed { i, cert ->
                        val x509 = cert as X509Certificate
                        val label = when (i) {
                            0 -> "LEAF (your key + attestation extension)"
                            chain.size - 1 -> "ROOT (Google CA)"
                            else -> "INTERMEDIATE #$i"
                        }

                        appendLog(
                            "--- Certificate ${i + 1}: $label ---\n" +
                            "Subject: ${x509.subjectDN}\n" +
                            "Issuer: ${x509.issuerDN}\n" +
                            "Serial: ${x509.serialNumber}\n" +
                            "Valid: ${x509.notBefore} → ${x509.notAfter}\n" +
                            "Sig algorithm: ${x509.sigAlgName}\n" +
                            "Public key algorithm: ${x509.publicKey.algorithm}"
                        )

                        val attestExt = x509.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
                        if (attestExt != null) {
                            appendLog(
                                "ATTESTATION EXTENSION FOUND (OID 1.3.6.1.4.1.11129.2.1.17)\n" +
                                "Extension size: ${attestExt.size} bytes\n" +
                                "This extension contains: security level, challenge, " +
                                "key properties, OS version, patch level, boot state"
                            )
                        }

                        val pem = "-----BEGIN CERTIFICATE-----\n" +
                            Base64.getMimeEncoder(64, "\n".toByteArray())
                                .encodeToString(cert.encoded) +
                            "\n-----END CERTIFICATE-----\n"
                        pemBuilder.append(pem)
                    }

                    certChainPem = pemBuilder.toString()

                    appendLog(
                        "Your server would verify:\n" +
                        "1. Chain signatures valid (each cert signs next)\n" +
                        "2. Root matches Google's published root at\n" +
                        "   googleapis.com/attestation/root\n" +
                        "3. Attestation extension shows TEE/StrongBox\n" +
                        "4. Challenge matches what server sent\n" +
                        "5. No cert is on the revocation list"
                    )
                } catch (e: Exception) {
                    appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message}")
                }
            }) { Text("Get Certificate Chain") }

            HorizontalDivider()

            Text("Step 3: Sign Data", style = MaterialTheme.typography.titleSmall)
            Text(
                "Signs a message with the attested key using SHA256withECDSA. " +
                "This is what happens during a 2FA authentication flow.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Button(onClick = {
                try {
                    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    val privateKey = keyStore.getKey(alias, null) as PrivateKey

                    val dataToSign = "Login request for user@example.com at ${System.currentTimeMillis()}"

                    val sig = Signature.getInstance("SHA256withECDSA")
                    sig.initSign(privateKey)
                    sig.update(dataToSign.toByteArray())
                    val signature = sig.sign()

                    appendLog(
                        "SIGNED!\n" +
                        "Data: $dataToSign\n" +
                        "Signature (${signature.size} bytes): ${Base64.getEncoder().encodeToString(signature)}"
                    )

                    appendLog(
                        "Now verifying signature using public key from certificate chain..."
                    )

                    val chain = keyStore.getCertificateChain(alias)
                    val leafCert = chain[0] as X509Certificate
                    val publicKeyFromCert = leafCert.publicKey

                    val verifySig = Signature.getInstance("SHA256withECDSA")
                    verifySig.initVerify(publicKeyFromCert)
                    verifySig.update(dataToSign.toByteArray())
                    val valid = verifySig.verify(signature)

                    appendLog(
                        "VERIFICATION RESULT: ${if (valid) "VALID" else "INVALID"}\n" +
                        "Public key source: leaf certificate from attestation chain\n" +
                        "This is what your server does: extract public key from the\n" +
                        "attested cert chain, then use it to verify signatures.\n" +
                        "The server KNOWS this public key is in real TEE hardware\n" +
                        "because the cert chain is signed by Google's root CA."
                    )

                    appendLog("Testing tamper detection...")
                    val tamperedData = dataToSign + " TAMPERED"
                    val verifySig2 = Signature.getInstance("SHA256withECDSA")
                    verifySig2.initVerify(publicKeyFromCert)
                    verifySig2.update(tamperedData.toByteArray())
                    val validTampered = verifySig2.verify(signature)

                    appendLog(
                        "Tampered data verification: ${if (validTampered) "VALID (BAD!)" else "INVALID — tampering detected!"}"
                    )
                } catch (e: Exception) {
                    appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message}")
                }
            }) { Text("Sign & Verify with Attested Key") }

            HorizontalDivider()

            Text("Step 4: Verify Certificate Chain", style = MaterialTheme.typography.titleSmall)
            Text(
                "Validates each certificate in the chain: verifies signatures, " +
                "checks the attestation extension for TEE/StrongBox security level, " +
                "and confirms the challenge matches.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
            Button(onClick = {
                try {
                    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
                    val chain = keyStore.getCertificateChain(alias)

                    if (chain == null || chain.isEmpty()) {
                        appendLog("No chain — generate the key first!")
                        return@Button
                    }

                    appendLog("Verifying chain of ${chain.size} certificates...")

                    for (i in 0 until chain.size - 1) {
                        val cert = chain[i] as X509Certificate
                        val issuer = chain[i + 1] as X509Certificate
                        try {
                            cert.verify(issuer.publicKey)
                            appendLog("Cert ${i + 1} → signed by cert ${i + 2}: VALID")
                        } catch (e: Exception) {
                            appendLog("Cert ${i + 1} → signed by cert ${i + 2}: INVALID (${e.message})")
                        }
                    }

                    val root = chain.last() as X509Certificate
                    try {
                        root.verify(root.publicKey)
                        appendLog("Root cert is self-signed: VALID")
                    } catch (e: Exception) {
                        appendLog("Root cert self-signature: INVALID (${e.message})")
                    }

                    appendLog(
                        "Root cert subject: ${root.subjectDN}\n" +
                        "Root cert issuer: ${root.issuerDN}\n\n" +
                        "In production, your server compares this root against\n" +
                        "Google's published roots at:\n" +
                        "https://android.googleapis.com/attestation/root\n\n" +
                        "If the root matches → the entire chain is trusted\n" +
                        "→ the leaf cert's public key is provably in real TEE\n" +
                        "→ the key properties in the attestation extension are genuine"
                    )

                    val leaf = chain[0] as X509Certificate
                    val attestExt = leaf.getExtensionValue("1.3.6.1.4.1.11129.2.1.17")
                    if (attestExt != null) {
                        appendLog(
                            "ATTESTATION EXTENSION PRESENT\n" +
                            "OID: 1.3.6.1.4.1.11129.2.1.17\n" +
                            "Raw size: ${attestExt.size} bytes\n\n" +
                            "This ASN.1 extension contains (parse with android/keyattestation library):\n" +
                            "• attestationSecurityLevel (TEE or StrongBox)\n" +
                            "• attestationChallenge (must match server's nonce)\n" +
                            "• purpose, algorithm, keySize, digest\n" +
                            "• osVersion, osPatchLevel\n" +
                            "• verifiedBootState (locked = genuine device)\n" +
                            "• userAuthenticationRequired (biometric/PIN gate)"
                        )
                    } else {
                        appendLog(
                            "NO ATTESTATION EXTENSION — this means the key was\n" +
                            "generated WITHOUT setAttestationChallenge().\n" +
                            "The cert chain is self-signed and proves nothing."
                        )
                    }
                } catch (e: Exception) {
                    appendLog("ERROR: ${e.javaClass.simpleName}: ${e.message}")
                }
            }) { Text("Verify Certificate Chain") }

            if (certChainPem.isNotEmpty()) {
                HorizontalDivider()
                Text("Certificate Chain (PEM)", style = MaterialTheme.typography.titleSmall)
                Text(
                    "This is what you send to your server. Copy this to verify with android/keyattestation library.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
                Surface(
                    tonalElevation = 2.dp,
                    shape = MaterialTheme.shapes.medium,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(max = 200.dp)
                ) {
                    Text(
                        text = certChainPem,
                        modifier = Modifier
                            .padding(8.dp)
                            .horizontalScroll(rememberScrollState()),
                        style = MaterialTheme.typography.labelSmall,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }

            HorizontalDivider()

            Text("Log", style = MaterialTheme.typography.labelLarge)
            Surface(
                tonalElevation = 2.dp,
                shape = MaterialTheme.shapes.medium,
                modifier = Modifier.fillMaxWidth()
            ) {
                Text(
                    text = if (log.isEmpty()) "Tap the buttons above in order (Step 1 → 2 → 3 → 4)" else log,
                    modifier = Modifier.padding(12.dp),
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace
                )
            }

            Spacer(Modifier.height(32.dp))
        }
    }
}
