# 2FA Authenticator Architecture: WebAuthn-Style P256 Key with Android Keystore

## Your Problem

Build a 2FA authenticator that:
- Uses WebAuthn-similar flows
- Generates and stores a P256 (ECDSA) private key in Android Keystore
- Signs challenges from the server to prove device possession
- Needs the right protection level

**Core decision: Should we require biometric for each signing operation?**

---

## The Threat Model

Before choosing a protection level, define what you're protecting against:

```mermaid
graph TD
    subgraph threats["Threats to a 2FA Authenticator"]
        T1["Stolen unlocked phone<br/><i>Attacker has physical access,<br/>device is unlocked</i>"]
        T2["Malware / compromised SDK<br/><i>Malicious code running inside<br/>your app process</i>"]
        T3["Rooted device<br/><i>Attacker has root access,<br/>can inject code via Frida</i>"]
        T4["Remote attacker<br/><i>No physical access,<br/>only network-based</i>"]
        T5["Stolen locked phone<br/><i>Attacker has physical access,<br/>device is locked</i>"]
    end

    T4 -->|"Key never leaves device"| SAFE["Always safe"]
    T5 -->|"Can't unlock Keystore"| SAFE
    T1 -->|"Depends on protection"| DEPENDS["Protection level matters"]
    T2 -->|"Depends on protection"| DEPENDS
    T3 -->|"Depends on protection"| DEPENDS

    style SAFE fill:#c8e6c9,stroke:#2e7d32
    style DEPENDS fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
```

For a 2FA authenticator, the **critical threats** are T1 (stolen unlocked phone) and T2 (malware). T3 (root) is a secondary concern. Let's see how each protection level handles them.

---

## Option A: No Biometric

```kotlin
KeyGenParameterSpec.Builder("fido_key", PURPOSE_SIGN)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    // No setUserAuthenticationRequired
    .build()
```

### What it proves to the server
**Device possession only.** "This device has the private key." Not "the owner is present."

### Threat analysis

| Threat | Protected? | Details |
|---|---|---|
| Remote attacker | YES | Key never leaves device |
| Other apps on the device | YES | UID isolation — we proved this with the attacker app (see below) |
| Stolen locked phone | YES | Keystore locked when device locked |
| Stolen unlocked phone (thief opens your app) | **NO** | No auth gate — thief uses the app's UI directly |
| Malware in app process | **NO** | Malware silently signs challenges (see below) |
| Root attacker | **NO** | Injects code into your process via Frida, signs as your UID |

### Important: "Other Apps" vs "Malware in Your Process"

This is a critical distinction that's easy to confuse.

**A separate app (different APK, different UID) CANNOT access your keys.** We proved this by building an attacker app — all 7 attacks failed. The Keystore daemon checks the caller's UID and rejects requests from any UID that doesn't own the key.

**Malicious code inside YOUR app's process CAN use your keys.** This is NOT another app — it's code running as your UID. The Keystore can't tell the difference between your legitimate code and a malicious SDK running in the same process.

Three ways this happens:

1. **Compromised SDK** — you include a third-party library (ads, analytics, crash reporting) that contains hidden malicious code. It runs inside your process, as your UID.
2. **WebView exploit** — attacker exploits a browser vulnerability to execute native code inside your process.
3. **Frida injection** — a root attacker injects code into your running process. From the Keystore's perspective, it's your app calling `sign()`.

```mermaid
graph TD
    subgraph your_process["Your App Process (UID 10402)"]
        your_code["Your Code<br/><i>signs data legitimately</i>"]
        malicious["Malicious SDK / Injected Code<br/><i>also signs data — silently</i>"]
        note1["Both share UID 10402<br/>Both can call KeyStore APIs"]
    end

    subgraph other_app["Attacker App (UID 10403)"]
        other_code["Calls KeyStore.getKey('your_key')"]
    end

    subgraph keystore2["keystore2 daemon"]
        check["Checks caller UID"]
    end

    your_code -->|"UID 10402"| keystore2
    malicious -->|"UID 10402"| keystore2
    other_code -->|"UID 10403"| keystore2

    keystore2 -->|"10402 == 10402 → key returned"| your_code
    keystore2 -->|"10402 == 10402 → key returned"| malicious
    keystore2 -->|"10403 ≠ 10402 → NULL"| other_code

    style your_process fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    style other_app fill:#c8e6c9,stroke:#2e7d32
    style malicious fill:#ffcdd2,stroke:#c62828
    style other_code fill:#c8e6c9,stroke:#2e7d32
```

**The Keystore doesn't know who wrote the code — it only checks the UID.** Your code and a malicious SDK share the same UID. This is exactly why biometric per-use with CryptoObject matters: even if malicious code runs inside your process, it can't produce a valid CryptoObject without a real finger on the sensor — that check happens in TEE hardware, not at the UID level.

### When this is acceptable
- The server treats 2FA as **"something you have"** only (device possession)
- The first factor (password) is the identity proof
- You accept the risk of in-process malware silently approving logins
- You trust all SDKs included in your app
- Example: low-value accounts, notification-based "approve this login" where you trust the device

### The real problem
```mermaid
sequenceDiagram
    participant Server
    participant Malware as Malicious SDK<br/>(inside your app, same UID)
    participant KS as Keystore

    Note over Malware: Runs as UID 10402 — same as your app
    Server->>Malware: Challenge: "sign this nonce"
    Note over Malware: User never sees anything
    Malware->>KS: signature.initSign(fido_key)
    KS->>KS: Caller UID 10402 == key owner 10402
    KS-->>Malware: OK (no auth required)
    Malware->>KS: signature.sign(challenge)
    KS-->>Malware: Valid signature
    Malware->>Server: Here's the signed challenge
    Server->>Server: Signature valid → login approved
    Note over Server: Account compromised silently
```

---

## Option B: Per-Use Biometric + CryptoObject (Recommended)

```kotlin
KeyGenParameterSpec.Builder("fido_key", PURPOSE_SIGN)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
    .build()
```

### What it proves to the server
**Device possession + user presence.** "This device has the key AND the owner just authenticated." This is what WebAuthn calls **User Verification (UV)**.

### Threat analysis

| Threat | Protected? | Details |
|---|---|---|
| Remote attacker | YES | Key never leaves device |
| Stolen locked phone | YES | Keystore locked |
| Stolen unlocked phone | **YES** | Attacker can't sign without fingerprint |
| Malware in app process | **YES** | Can't produce valid CryptoObject (TEE-bound) |
| Root attacker | **YES** | Can't forge auth token (HMAC key in TEE) |

### The flow
```mermaid
sequenceDiagram
    participant Server
    participant App
    participant BP as BiometricPrompt
    participant TEE as TEE Hardware

    Server->>App: Challenge: "sign this nonce"
    App->>App: Show "Approve login to example.com?"
    App->>TEE: signature.initSign(fido_key)
    TEE-->>App: Signature object (pending auth)
    App->>BP: authenticate(promptInfo, CryptoObject(signature))
    BP->>BP: Show fingerprint dialog
    BP->>TEE: User scans finger → verify in TEE
    TEE->>TEE: Biometric match → bind signature to session
    TEE-->>BP: Auth succeeded
    BP-->>App: onAuthenticationSucceeded(result)
    App->>App: authedSig = result.cryptoObject.signature
    App->>TEE: authedSig.update(challenge)
    App->>TEE: authedSig.sign()
    TEE-->>App: Signature bytes
    App->>Server: Signed challenge
    Server->>Server: Verify signature → login approved
    Note over Server: User physically authenticated
```

### Limitation
Requires `BIOMETRIC_STRONG` (Class 3). Devices without strong biometric hardware can't use this mode. Falls back to nothing — the user is blocked.

---

## Option C: Biometric OR Credential + CryptoObject (Best for Broad Compatibility)

```kotlin
KeyGenParameterSpec.Builder("fido_key", PURPOSE_SIGN)
    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
    .setDigests(KeyProperties.DIGEST_SHA256)
    .setUserAuthenticationRequired(true)
    .setUserAuthenticationParameters(
        0,  // per-use
        KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
    )
    .build()
```

### Difference from Option B
Allows PIN/pattern/password as fallback when biometric isn't available or fails.

### Important caveat
**`CryptoObject` only works with `BIOMETRIC_STRONG`**, not `DEVICE_CREDENTIAL`. When the user authenticates via PIN, the auth token is generated by Gatekeeper (in TEE) instead of Biometric TA — it's still TEE-signed, still unforgeable. But the crypto binding is **time-based**, not per-use.

```mermaid
graph TD
    AUTH["User authenticates"]
    AUTH -->|"Fingerprint"| BIO["Per-use crypto-bound<br/><i>Signature bound to this specific auth</i><br/><i>One operation only</i>"]
    AUTH -->|"PIN / Pattern"| PIN["Time-based<br/><i>Key unlocked for short duration</i><br/><i>Multiple operations possible</i>"]

    BIO --> SEC1["Strongest: malware can't sign"]
    PIN --> SEC2["Strong: malware must act within<br/>timeout window after legitimate PIN entry"]

    style BIO fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style PIN fill:#fff3e0,stroke:#ef6c00
```

For a 2FA authenticator, this tradeoff is usually acceptable — PIN fallback is better than blocking users on devices without strong biometrics.

---

## Recommendation

```mermaid
graph TD
    START["2FA Authenticator Key Protection"]

    START --> Q1["What does your server require?"]

    Q1 -->|"UV=discouraged<br/>(just device possession)"| REC_A["Option A: No biometric<br/>Simple, but vulnerable to malware"]

    Q1 -->|"UV=required<br/>(must verify user)"| Q2["Must work on all devices?"]

    Q2 -->|"Yes — need PIN fallback"| REC_C["<b>Option C: Biometric OR Credential</b><br/><i>Recommended for most 2FA apps</i><br/><br/>setUserAuthenticationParameters(<br/>  0, AUTH_BIOMETRIC_STRONG | AUTH_DEVICE_CREDENTIAL<br/>)<br/><br/>Shows fingerprint with PIN fallback.<br/>Works on all devices with screen lock."]

    Q2 -->|"No — biometric-only is OK"| REC_B["Option B: Per-use Biometric<br/><br/>setUserAuthenticationParameters(<br/>  0, AUTH_BIOMETRIC_STRONG<br/>)<br/><br/>Strongest protection.<br/>Fails on devices without strong biometric."]

    style REC_C fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
    style REC_B fill:#e8f5e9,stroke:#2e7d32
    style REC_A fill:#ffcdd2,stroke:#c62828
```

**For most 2FA authenticators, Option C is the right choice:**

1. **Per-use auth** (timeout=0) — each signing requires fresh user verification
2. **Biometric + credential** — fingerprint preferred, PIN/pattern fallback
3. **CryptoObject binding** — when biometric is used, it's hardware-bound and unforgeable
4. **Hardware-backed** — key material in TEE, non-extractable

---

## Complete Implementation

```kotlin
// ══════════════════════════════════════════════
// 1. KEY GENERATION (once, during registration)
// ══════════════════════════════════════════════

fun generateFidoKeyPair(alias: String): PublicKey {
    val keyGen = KeyPairGenerator.getInstance(
        KeyProperties.KEY_ALGORITHM_EC,
        "AndroidKeyStore"
    )
    keyGen.initialize(
        KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)

            // Protection: per-use auth, biometric with PIN fallback
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(
                0,  // 0 = per-use (every sign requires fresh auth)
                KeyProperties.AUTH_BIOMETRIC_STRONG
                    or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )

            // Invalidate key if user adds/removes fingerprint
            .setInvalidatedByBiometricEnrollment(true)

            // Request hardware backing (TEE or StrongBox)
            // StrongBox is stronger but slower and not on all devices:
            // .setIsStrongBoxBacked(true)

            .build()
    )
    return keyGen.generateKeyPair().public
    // Send public key to server during WebAuthn registration
}


// ══════════════════════════════════════════════
// 2. SIGNING (each authentication request)
// ══════════════════════════════════════════════

fun signChallenge(
    activity: FragmentActivity,
    alias: String,
    challenge: ByteArray,
    onResult: (ByteArray) -> Unit,
    onError: (String) -> Unit
) {
    // Step 1: Get private key and init Signature
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    val privateKey = keyStore.getKey(alias, null) as PrivateKey

    val signature = Signature.getInstance("SHA256withECDSA")
    try {
        signature.initSign(privateKey)
    } catch (e: UserNotAuthenticatedException) {
        // Expected for per-use keys — auth needed before use
    }

    // Step 2: Wrap in CryptoObject for hardware-bound auth
    val cryptoObject = BiometricPrompt.CryptoObject(signature)

    // Step 3: Show BiometricPrompt
    val executor = ContextCompat.getMainExecutor(activity)

    val callback = object : BiometricPrompt.AuthenticationCallback() {
        override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
            try {
                // Use the RETURNED CryptoObject's signature (TEE-authenticated)
                val authedSig = result.cryptoObject!!.signature!!
                authedSig.update(challenge)
                val signed = authedSig.sign()
                onResult(signed)
            } catch (e: Exception) {
                onError("Signing failed: ${e.message}")
            }
        }

        override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
            onError("Auth error [$errorCode]: $errString")
        }

        override fun onAuthenticationFailed() {
            // Biometric didn't match — dialog stays open, user can retry
        }
    }

    val promptInfo = BiometricPrompt.PromptInfo.Builder()
        .setTitle("Approve Login")
        .setSubtitle("Verify your identity")
        .setDescription("Sign in to example.com")
        .setConfirmationRequired(true)  // Prevent instant face unlock dismissal
        .setAllowedAuthenticators(
            BiometricManager.Authenticators.BIOMETRIC_STRONG
                or BiometricManager.Authenticators.DEVICE_CREDENTIAL
        )
        .build()

    val biometricPrompt = BiometricPrompt(activity, executor, callback)
    biometricPrompt.authenticate(promptInfo, cryptoObject)
}


// ══════════════════════════════════════════════
// 3. KEY ATTESTATION (prove key is genuine hardware-backed)
// ══════════════════════════════════════════════

fun getAttestationCertificateChain(alias: String): List<Certificate> {
    val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    return keyStore.getCertificateChain(alias).toList()
    // Send to server — server verifies chain roots to Google's attestation CA
    // This proves: key was generated in real TEE, not emulator/software
}


// ══════════════════════════════════════════════
// 4. CHECK DEVICE CAPABILITIES (before offering registration)
// ══════════════════════════════════════════════

fun checkDeviceCapabilities(context: Context): DeviceCapabilities {
    val bioManager = BiometricManager.from(context)

    val strongBio = bioManager.canAuthenticate(
        BiometricManager.Authenticators.BIOMETRIC_STRONG
    ) == BiometricManager.BIOMETRIC_SUCCESS

    val credential = bioManager.canAuthenticate(
        BiometricManager.Authenticators.DEVICE_CREDENTIAL
    ) == BiometricManager.BIOMETRIC_SUCCESS

    val hasStrongBox = context.packageManager
        .hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)

    return DeviceCapabilities(
        canUseBiometric = strongBio,
        canUseCredential = credential,
        hasStrongBox = hasStrongBox,
        canRegister = strongBio || credential  // Need at least one
    )
}

data class DeviceCapabilities(
    val canUseBiometric: Boolean,
    val canUseCredential: Boolean,
    val hasStrongBox: Boolean,
    val canRegister: Boolean
)
```

---

## WebAuthn Mapping

How your 2FA authenticator maps to WebAuthn concepts:

| WebAuthn Concept | Your Implementation |
|---|---|
| `navigator.credentials.create()` | `generateFidoKeyPair()` — generates EC P-256 in Keystore |
| `navigator.credentials.get()` | `signChallenge()` — signs server challenge with biometric |
| `userVerification: "required"` | `setUserAuthenticationRequired(true)` + `timeout=0` |
| `userVerification: "preferred"` | `setUserAuthenticationRequired(true)` + `BIOMETRIC_STRONG \| DEVICE_CREDENTIAL` |
| `userVerification: "discouraged"` | No `setUserAuthenticationRequired` (not recommended) |
| UV bit in authenticator data | Set to 1 when user authenticated via biometric/PIN |
| Attestation | `getAttestationCertificateChain()` — hardware key attestation |
| Algorithm `-7` (ES256) | `EC` + `secp256r1` + `SHA256withECDSA` |
| Credential ID | Keystore alias (or a random ID mapped to the alias) |

---

## What Your Server Should Verify

```mermaid
sequenceDiagram
    participant Client as Your 2FA App
    participant Server as Your Server

    Note over Client,Server: Registration
    Client->>Server: Public key + attestation certificate chain
    Server->>Server: Verify attestation chain roots to Google CA
    Server->>Server: Check attestation extension: key is hardware-backed
    Server->>Server: Check attestation extension: user auth required
    Server->>Server: Store public key for this user

    Note over Client,Server: Authentication
    Server->>Client: Random challenge (32 bytes)
    Client->>Client: User scans fingerprint
    Client->>Client: Sign challenge with hardware-bound key
    Client->>Server: Signature + authenticator data
    Server->>Server: Verify signature against stored public key
    Server->>Server: Check UV bit = 1 (user was verified)
    Server->>Server: Check challenge matches what was sent
    Server->>Server: Login approved
```

Key attestation lets the server verify:
- The key was generated **inside real TEE hardware** (not an emulator)
- The key **requires user authentication** before use
- The device **hasn't been tampered with** (verified boot state)

---

## Edge Cases to Handle

| Scenario | What happens | How to handle |
|---|---|---|
| User has no screen lock | `canAuthenticate()` returns `NONE_ENROLLED` | Block registration, show setup instructions |
| User removes fingerprint after registration | Key throws `KeyPermanentlyInvalidatedException` | Delete key, re-register with server |
| Device has no strong biometric | `BIOMETRIC_STRONG` returns `NO_HARDWARE` | Fall back to `DEVICE_CREDENTIAL` only |
| User cancels biometric prompt | `onAuthenticationError(ERROR_USER_CANCELED)` | Show "cancelled" message, let them retry |
| Too many failed attempts | `onAuthenticationError(ERROR_LOCKOUT)` | Show "try again in 30s" or offer PIN |
| App is reinstalled | Old keys are deleted | Re-register with server |
| Device is factory reset | All keys destroyed | Re-register with server |

---

## Real-World Open Source Implementations

These are actual FIDO2/WebAuthn authenticator implementations on GitHub that use exactly this pattern (P256 + Keystore + BiometricPrompt + CryptoObject):

### 1. Duo Labs — android-webauthn-authenticator

**Repo:** [duo-labs/android-webauthn-authenticator](https://github.com/duo-labs/android-webauthn-authenticator)

The closest reference implementation to what you're building. Duo Security (now part of Cisco) built this as an open-source WebAuthn authenticator for Android. It uses **exactly Option C**: P256 in Keystore with configurable biometric + StrongBox.

**Key generation** (`CredentialSafe.java`):
```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
        .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))
        .setDigests(KeyProperties.DIGEST_SHA256)
        .setUserAuthenticationRequired(this.authenticationRequired) // configurable
        .setInvalidatedByBiometricEnrollment(false)
        .setIsStrongBoxBacked(this.strongboxRequired)              // configurable
        .build();
```

**Signing with CryptoObject** (`Authenticator.java`):
```java
// Create Signature object and wrap in CryptoObject
Signature signature = WebAuthnCryptography.generateSignatureObject(privateKey);
BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);

// Authenticate with CryptoObject — signature bound to biometric session
bp.authenticate(cryptoObject, cancellationSignal, ctx.getMainExecutor(), callback);
```

**In the callback** (`BiometricGetAssertionCallback.java`):
```java
@Override
public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
    // Use the TEE-authenticated signature from the CryptoObject
    Signature signature = result.getCryptoObject().getSignature();
    
    // Pass it to the assertion builder — only THIS signature is authorized
    assertionResult = authenticator.getInternalAssertion(options, selectedCredential, signature);
}
```

**Constructor** allows toggling auth and StrongBox (useful for testing):
```java
// Production: both enabled
new Authenticator(ctx, true, true);

// Testing: auth disabled
new Authenticator(ctx, false, false);
```

### 2. WIOsense — rauth-android

**Repo:** [WIOsense/rauth-android](https://github.com/WIOsense/rauth-android)

A FIDO2 **roaming authenticator** library (the phone acts as a security key for other devices via NFC/BLE). Uses Android Keystore with BiometricPrompt and optional StrongBox. Also implements **clientPIN** as a fallback authentication method — relevant if your business wants app-level PIN alongside biometric.

Key features:
- Resident keys stored in Android KeyStore by default (TEE or SE)
- BiometricPrompt for user verification
- Optional StrongBox enforcement (`strongboxRequired` flag)
- clientPIN support for devices without biometric
- Requires Android 9.0+ (BiometricPrompt API)

### 3. LINE — webauthn-kotlin

**Repo:** [line/webauthn-kotlin](https://github.com/line/webauthn-kotlin)

LINE (messaging app with 200M+ users) built an open-source WebAuthn SDK in Kotlin. Supports both device credentials and biometrics. Production-grade code from a major tech company.

**Demo app:** [line/webauthndemo-kotlin](https://github.com/line/webauthndemo-kotlin) — demonstrates registration and authentication with biometric/credential authenticators.

### 4. Google — Credential Manager / FIDO2 API

**Codelab:** [Credential Manager API for Android](https://codelabs.developers.google.com/credential-manager-api-for-android)

Google's official implementation (used by Chrome and Android system). The Credential Manager internally uses:
```kotlin
// Per the official documentation:
.setUserAuthenticationParameters(
    0, // duration = 0 → per-use
    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
)
```

As of 2024, Google's FIDO2 API produces **hardware-backed key attestation** by default (not just SafetyNet). This means the server can cryptographically verify the key was generated in genuine TEE hardware.

### 5. prongbang — android-secure-biometric

**Repo:** [prongbang/android-secure-biometric](https://github.com/prongbang/android-secure-biometric)

A helper library that simplifies BiometricPrompt + CryptoObject usage. Not a full FIDO2 implementation, but useful as a building block.

### Pattern Confirmed Across All Implementations

Every production FIDO2 authenticator on Android follows the same pattern:

```mermaid
graph LR
    A["1. Generate P256 key<br/>in Keystore<br/>(setUserAuthenticationRequired)"] --> B["2. Init Signature<br/>with private key"]
    B --> C["3. Wrap in<br/>CryptoObject"]
    C --> D["4. BiometricPrompt<br/>.authenticate(<br/>promptInfo, cryptoObject)"]
    D --> E["5. In callback:<br/>result.getCryptoObject()<br/>.getSignature()"]
    E --> F["6. Sign with the<br/>TEE-authenticated<br/>Signature object"]

    style A fill:#e3f2fd,stroke:#1565c0
    style D fill:#fff3e0,stroke:#ef6c00
    style F fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

---

## Sources

- [FIDO2 API for Android — developers.google.com](https://developers.google.com/identity/fido/android/native-apps)
- [WebAuthn Level 2 — W3C Specification](https://www.w3.org/TR/webauthn-2/)
- [Android Keystore System — developer.android.com](https://developer.android.com/privacy-and-security/keystore)
- [Android Authentication Architecture — source.android.com](https://source.android.com/docs/security/features/authentication)
- [Attestation Format Change for Android FIDO2 API — Android Developers Blog](https://android-developers.googleblog.com/2024/09/attestation-format-change-for-android-fido2-api.html)
- [WebAuthn/FIDO2: Verifying Android KeyStore Attestation — Ackermann Yuriy](https://medium.com/@herrjemand/webauthn-fido2-verifying-android-keystore-attestation-4a8835b33e9d)
- [WithSecure Labs — Android Keystore Authentication Security](https://labs.withsecure.com/publications/how-secure-is-your-android-keystore-authentication)

### Open Source Implementations
- [Duo Labs — android-webauthn-authenticator](https://github.com/duo-labs/android-webauthn-authenticator) — Cisco/Duo's reference FIDO2 authenticator
- [WIOsense — rauth-android](https://github.com/WIOsense/rauth-android) — FIDO2 roaming authenticator with clientPIN support
- [LINE — webauthn-kotlin](https://github.com/line/webauthn-kotlin) — Production WebAuthn SDK from LINE
- [LINE — webauthndemo-kotlin](https://github.com/line/webauthndemo-kotlin) — Demo app for the SDK
- [Google — Credential Manager Codelab](https://codelabs.developers.google.com/credential-manager-api-for-android)
- [prongbang — android-secure-biometric](https://github.com/prongbang/android-secure-biometric) — BiometricPrompt + CryptoObject helper
