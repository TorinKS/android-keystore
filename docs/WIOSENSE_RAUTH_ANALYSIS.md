# WIOsense rauth-android: ClientPIN Implementation Analysis

**Repo:** [WIOsense/rauth-android](https://github.com/WIOsense/rauth-android)

This is a FIDO2 roaming authenticator that turns an Android phone into a security key (via NFC/BLE). It implements the CTAP2 clientPIN protocol as an alternative to biometric authentication. This analysis traces how clientPIN works end-to-end and evaluates its security.

---

## Architecture Overview

```mermaid
graph TD
    subgraph client["Client (Browser / OS)"]
        RP["Relying Party (website)"]
        CTAP["CTAP2 Client"]
    end

    subgraph rauth["rauth-android (Authenticator)"]
        AUTH["Authenticator.java<br/><i>Main CTAP2 command handler</i>"]
        CRED["CredentialSafe.java<br/><i>P256 key generation in Keystore</i>"]
        PIN_LOCK["ClientPinLocker.java<br/><i>PIN storage in EncryptedSharedPrefs</i>"]
        BIO["WioBiometricPrompt.java<br/><i>BiometricPrompt wrapper</i>"]
        CRYPTO["WebAuthnCryptography.java<br/><i>ECDH, AES, HMAC, signing</i>"]
    end

    subgraph hardware["Hardware"]
        KS["Android Keystore<br/>(TEE / StrongBox)"]
        ESP["EncryptedSharedPreferences<br/>(PIN data on disk)"]
    end

    RP -->|"WebAuthn API"| CTAP
    CTAP -->|"CTAP2 over NFC/BLE"| AUTH
    AUTH --> CRED
    AUTH --> PIN_LOCK
    AUTH --> BIO
    AUTH --> CRYPTO
    CRED --> KS
    PIN_LOCK --> ESP
    ESP -.->|"MasterKey in"| KS

    style KS fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style ESP fill:#fff3e0,stroke:#ef6c00
    style PIN_LOCK fill:#fff3e0,stroke:#ef6c00
```

---

## 1. How ClientPIN Is Stored

**File:** `util/ClientPinLocker.java`

### Storage Architecture

```mermaid
graph TD
    subgraph storage["PIN Storage Stack"]
        PIN["User's PIN (e.g., '1234')"]
        SHA["SHA-256 hash<br/><i>first 16 bytes used for CTAP2</i>"]
        HEX["Hex string representation"]
        ESP2["EncryptedSharedPreferences<br/><i>AES-256-SIV keys / AES-256-GCM values</i>"]
        MK["MasterKey in Android Keystore<br/><i>AES-256-GCM, StrongBox optional</i>"]
        DISK["XML file on disk<br/><i>/data/data/{app}/shared_prefs/<br/>Android_ePIN_{clientId}.xml</i>"]
    end

    PIN --> SHA --> HEX --> ESP2
    MK -->|"encrypts"| ESP2
    ESP2 -->|"writes to"| DISK

    style MK fill:#c8e6c9,stroke:#2e7d32
    style ESP2 fill:#e3f2fd,stroke:#1565c0
    style DISK fill:#fff3e0,stroke:#ef6c00
```

### What's Stored in EncryptedSharedPreferences

| Field | Key | Value | Purpose |
|---|---|---|---|
| PIN hash | `PIN-SHA256` | Hex-encoded first 16 bytes of SHA-256(PIN) | PIN verification |
| Retry counter | `RETRIES` | Long (0-8) | Brute-force protection |
| PIN token | `TOKEN` | Hex-encoded 16 random bytes | HMAC key for pinAuth |

### MasterKey Configuration

```java
// ClientPinLocker.java lines 71-82
KeyGenParameterSpec keySpec = new KeyGenParameterSpec.Builder(
        cpkAlias,
        KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
    .setKeySize(256)
    .setUserAuthenticationRequired(false)   // ← No biometric/PIN gate on the MasterKey itself
    .setRandomizedEncryptionRequired(true)
    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
    .setIsStrongBoxBacked(strongboxRequired)
    .setUnlockedDeviceRequired(true)        // ← Only works when device is unlocked
    .build();
```

**Key observation:** The MasterKey that protects the PIN storage is **not** protected by user authentication. Any code running in the app's process on an unlocked device can read the EncryptedSharedPreferences.

---

## 2. The CTAP2 ClientPIN Protocol: All 5 Subcommands

The clientPIN protocol establishes a secure channel between the CTAP2 client and the authenticator using ECDH key agreement, then uses that channel to exchange PINs and obtain a `pinToken` for subsequent operations.

**File:** `Authenticator.java`, method `getPinResult()` (lines 576-690)

### Subcommand 1: getRetries

```mermaid
sequenceDiagram
    participant Client as CTAP2 Client
    participant Auth as Authenticator
    participant Locker as ClientPinLocker

    Client->>Auth: clientPIN(subCommand=1)
    Auth->>Locker: getRetries()
    Locker-->>Auth: retries (0-8)
    Auth-->>Client: {retries: N}
    Note over Client: If 0 → PIN is blocked
```

Returns current retry count. No authentication needed. Client checks if PIN is blocked before prompting user.

### Subcommand 2: getKeyAgreement

```mermaid
sequenceDiagram
    participant Client as CTAP2 Client
    participant Auth as Authenticator

    Client->>Auth: clientPIN(subCommand=2)
    Auth->>Auth: Generate ephemeral EC P-256 key pair<br/>(authenticatorKeyAgreement)
    Auth-->>Client: {keyAgreement: {x: ..., y: ...}}
    Note over Client: Client now has authenticator's<br/>ephemeral public key for ECDH
```

Returns the authenticator's ephemeral P-256 public key. Client will use this with its own ephemeral key to compute a shared secret via ECDH.

### Subcommand 3: setPIN (First-Time Setup)

```mermaid
sequenceDiagram
    participant Client as CTAP2 Client
    participant Auth as Authenticator
    participant Crypto as WebAuthnCryptography
    participant Locker as ClientPinLocker

    Note over Client: User enters new PIN (e.g., "1234")
    Client->>Client: Generate ephemeral EC key pair
    Client->>Auth: getKeyAgreement → get authenticator's public key
    Client->>Client: sharedSecret = SHA-256(ECDH(clientPriv, authPub).x)
    Client->>Client: newPinEnc = AES-256-CBC(sharedSecret, pad(utf8(PIN)))
    Client->>Client: pinAuth = HMAC-SHA256(sharedSecret, newPinEnc)[0:16]
    Client->>Auth: clientPIN(subCommand=3,<br/>keyAgreement=clientPub,<br/>newPinEnc, pinAuth)

    Auth->>Crypto: sharedSecret = SHA-256(ECDH(authPriv, clientPub).x)
    Auth->>Crypto: Verify pinAuth == HMAC-SHA256(sharedSecret, newPinEnc)[0:16]
    Note over Auth: If mismatch → PIN_AUTH_INVALID

    Auth->>Crypto: decryptedPIN = AES-256-CBC-decrypt(sharedSecret, newPinEnc)
    Auth->>Auth: Validate PIN length ≥ 4 chars
    Auth->>Locker: lockPin(SHA-256(PIN)[0:16])
    Auth->>Locker: setRetries(8)
    Auth->>Locker: refreshToken() → new random 16-byte pinToken

    Auth-->>Client: Success
```

### Subcommand 4: changePIN

```mermaid
sequenceDiagram
    participant Client as CTAP2 Client
    participant Auth as Authenticator
    participant Locker as ClientPinLocker

    Note over Client: User enters old PIN + new PIN
    Client->>Client: sharedSecret = SHA-256(ECDH(clientPriv, authPub).x)
    Client->>Client: pinHashEnc = AES-CBC(sharedSecret, SHA-256(oldPIN)[0:16])
    Client->>Client: newPinEnc = AES-CBC(sharedSecret, pad(utf8(newPIN)))
    Client->>Client: pinAuth = HMAC(sharedSecret, newPinEnc || pinHashEnc)[0:16]

    Client->>Auth: clientPIN(subCommand=4,<br/>keyAgreement, pinHashEnc,<br/>newPinEnc, pinAuth)

    Auth->>Auth: Verify pinAuth
    Auth->>Auth: Decrypt pinHashEnc → verify old PIN matches stored hash
    Note over Auth: On mismatch → decrement retries,<br/>3 consecutive → PIN_AUTH_BLOCKED,<br/>0 retries → PIN_BLOCKED
    Auth->>Auth: Decrypt newPinEnc → validate & store new PIN
    Auth->>Locker: lockPin(SHA-256(newPIN)[0:16])
    Auth->>Locker: setRetries(8)
    Auth->>Locker: refreshToken()

    Auth-->>Client: Success
```

### Subcommand 5: getPinToken (The Critical One)

This is where the client proves PIN knowledge and gets a `pinToken` to use for subsequent operations:

```mermaid
sequenceDiagram
    participant Client as CTAP2 Client
    participant Auth as Authenticator
    participant Crypto as WebAuthnCryptography
    participant Locker as ClientPinLocker

    Note over Client: User enters PIN
    Client->>Client: sharedSecret = SHA-256(ECDH(clientPriv, authPub).x)
    Client->>Client: pinHashEnc = AES-CBC(sharedSecret, SHA-256(PIN)[0:16])

    Client->>Auth: clientPIN(subCommand=5,<br/>keyAgreement=clientPub,<br/>pinHashEnc)

    Auth->>Crypto: sharedSecret = SHA-256(ECDH(authPriv, clientPub).x)
    Auth->>Crypto: decryptedHash = AES-CBC-decrypt(sharedSecret, pinHashEnc)
    Auth->>Locker: isPinMatch(decryptedHash)?

    alt PIN matches
        Auth->>Locker: setRetries(8)
        Auth->>Locker: getToken() → pinToken (16 random bytes)
        Auth->>Crypto: pinTokenEnc = AES-CBC(sharedSecret, pinToken)
        Auth-->>Client: {pinToken: pinTokenEnc}
        Client->>Client: pinToken = AES-CBC-decrypt(sharedSecret, pinTokenEnc)
        Note over Client: Client now has pinToken<br/>for computing pinAuth in<br/>makeCredential / getAssertion
    else PIN doesn't match
        Auth->>Locker: decrementPinRetries()
        Auth-->>Client: PIN_INVALID or PIN_BLOCKED
    end
```

---

## 3. How pinToken Gates Signing Operations

After the client obtains `pinToken` via subcommand 5, it uses it to authenticate every subsequent makeCredential or getAssertion request:

```mermaid
sequenceDiagram
    participant Client as CTAP2 Client
    participant Auth as Authenticator
    participant Locker as ClientPinLocker
    participant KS as Keystore (TEE)

    Note over Client: Client already has pinToken from getPinToken subcommand

    Client->>Client: pinAuth = HMAC-SHA256(pinToken, clientDataHash)[0:16]
    Client->>Auth: getAssertion(rpId, clientDataHash,<br/>pinAuth, pinProtocol=1)

    Note over Auth: Step 1: Verify pinAuth
    Auth->>Locker: getToken() → stored pinToken
    Auth->>Auth: expectedPinAuth = HMAC-SHA256(pinToken, clientDataHash)[0:16]
    Auth->>Auth: Compare pinAuth == expectedPinAuth

    alt pinAuth matches
        Auth->>Auth: Reset retries to 8, set UV=true
        Note over Auth: Step 2: Sign with Keystore key
        Auth->>KS: Signature.initSign(privateKey)
        Note over KS: Key has 120s auth timeout<br/>May require biometric/device credential
        KS-->>Auth: Signature object
        Auth->>KS: signature.update(authenticatorData || clientDataHash)
        Auth->>KS: signature.sign()
        KS-->>Auth: ECDSA signature bytes
        Auth-->>Client: {authenticatorData, signature}
    else pinAuth doesn't match
        Auth->>Locker: decrementPinRetries()
        Auth-->>Client: PIN_AUTH_INVALID
    end
```

**Critical insight:** The pinAuth verification and the Keystore signing are **two independent checks**:

1. **pinAuth** — verified in app code (HMAC comparison in `PINverifyClientDataHash()`)
2. **Keystore signing** — verified in TEE hardware (key requires `setUserAuthenticationRequired(true)` with 120s timeout)

---

## 4. Signing Key Configuration

**File:** `util/CredentialSafe.java` (lines 106-115)

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))   // P-256
    .setDigests(KeyProperties.DIGEST_SHA256)                          // SHA-256
    .setUserAuthenticationRequired(true)                              // Auth required
    .setUserAuthenticationValidityDurationSeconds(120)                // 120s timeout
    .setUserConfirmationRequired(false)
    .setInvalidatedByBiometricEnrollment(false)
    .setIsStrongBoxBacked(this.strongboxRequired)                     // StrongBox optional
    .build();
```

| Parameter | Value | Implication |
|---|---|---|
| Algorithm | ECDSA P-256 (secp256r1) | Standard WebAuthn ES256 |
| Auth required | `true` | TEE won't sign without auth |
| Timeout | **120 seconds** | After one auth, key usable for 2 minutes |
| Per-use CryptoObject | **No** (timeout > 0) | Not bound to specific biometric event |
| StrongBox | Optional | Dedicated secure element if available |
| Biometric invalidation | `false` | Key survives fingerprint enrollment changes |

**Note:** `biometricSigningSupported` is hardcoded to `false` (line 74 of CredentialSafe), meaning CryptoObject signing is **disabled by design**. The library uses time-based authentication, not per-use.

---

## 5. BiometricPrompt Integration

**File:** `util/WioBiometricPrompt.java`

```mermaid
sequenceDiagram
    participant Auth as Authenticator
    participant WBP as WioBiometricPrompt
    participant BP as BiometricPrompt (AndroidX)
    participant User as User

    Auth->>WBP: showPrompt(activity, title, subtitle,<br/>cryptoObject, callback)
    WBP->>BP: Create BiometricPrompt with callback
    WBP->>BP: Build PromptInfo:<br/>title, subtitle,<br/>deviceCredentialAllowed=true

    alt CryptoObject provided
        WBP->>BP: authenticate(promptInfo, cryptoObject)
    else No CryptoObject
        WBP->>BP: authenticate(promptInfo)
    end

    BP->>User: Show fingerprint/PIN dialog

    alt User authenticates via fingerprint
        User->>BP: Scan fingerprint
        BP-->>WBP: onAuthenticationSucceeded(result)
        WBP-->>Auth: result.getCryptoObject().getSignature()
        Note over Auth: TEE-bound Signature (if CryptoObject was used)
    else User authenticates via device PIN
        User->>BP: Enter device PIN
        BP-->>WBP: onAuthenticationSucceeded(result)
        WBP-->>Auth: result (CryptoObject may be null with PIN)
        Note over Auth: Time-based auth — key usable for 120s
    end
```

**Important:** When user chooses device PIN instead of biometric, the CryptoObject is not crypto-bound. The 120s timeout makes the key usable for any code in the process during that window.

---

## 6. Security Analysis

### The Two-Layer Architecture

```mermaid
graph TD
    subgraph layer1["Layer 1: CTAP2 ClientPIN (App-Level)"]
        direction TB
        L1A["PIN hash stored in<br/>EncryptedSharedPreferences"]
        L1B["pinToken used as HMAC key<br/>for pinAuth verification"]
        L1C["Retry counter (8 attempts)<br/>3 consecutive → blocked"]
        L1D["ECDH key agreement<br/>encrypts PIN in transit"]

        L1A --- L1B --- L1C --- L1D
    end

    subgraph layer2["Layer 2: Android Keystore (Hardware-Level)"]
        direction TB
        L2A["P256 private key in TEE"]
        L2B["setUserAuthenticationRequired(true)"]
        L2C["120-second timeout after auth"]
        L2D["Key material non-extractable"]

        L2A --- L2B --- L2C --- L2D
    end

    layer1 -->|"If PIN verification passes"| layer2

    style layer1 fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    style layer2 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

### What Can Be Attacked

```mermaid
graph TD
    subgraph attacks["Attack Vectors"]
        A1["Frida: Hook isPinMatch()<br/>to return true"]
        A2["Frida: Hook PINverifyClientDataHash()<br/>to skip check"]
        A3["Frida: Extract pinToken<br/>from ClientPinLocker"]
        A4["Frida: Modify retry counter<br/>to avoid lockout"]
        A5["Root: Read EncryptedSharedPreferences<br/>file (app process access)"]
        A6["Root: Brute-force PIN hash<br/>(SHA-256, no salt, no KDF)"]
    end

    subgraph results["Result"]
        R1["pinAuth verification bypassed"]
        R2["But still need Keystore auth<br/>(120s timeout)"]
    end

    subgraph blocked["Still Protected"]
        B1["Key material in TEE<br/>→ cannot extract"]
        B2["Need biometric/device credential<br/>to unlock key for 120s"]
        B3["Signature happens inside TEE<br/>→ correct, non-forgeable"]
    end

    A1 --> R1
    A2 --> R1
    A3 --> R1
    A4 --> R1
    A5 --> R1
    A6 --> R1
    R1 --> R2
    R2 --> blocked

    style attacks fill:#ffcdd2,stroke:#c62828
    style results fill:#fff3e0,stroke:#ef6c00
    style blocked fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

### Complete Attack Scenario: Frida Bypasses PIN, But Then What?

```mermaid
sequenceDiagram
    participant Attacker as Attacker (Frida)
    participant App as rauth-android
    participant Locker as ClientPinLocker
    participant KS as Keystore (TEE)

    Note over Attacker: Step 1: Bypass PIN verification
    Attacker->>App: Hook PINverifyClientDataHash() → return true
    Note over App: PIN check bypassed ✓

    Note over Attacker: Step 2: Try to sign
    App->>KS: Signature.initSign(privateKey)

    alt No recent biometric/device credential auth
        KS--xApp: UserNotAuthenticatedException
        Note over Attacker: BLOCKED — TEE requires<br/>real biometric or device PIN
        Note over Attacker: Attacker must either:<br/>1. Wait for user to authenticate legitimately<br/>2. Somehow trigger biometric prompt<br/>3. Know the device PIN
    else User authenticated within last 120s
        KS-->>App: Signature object ready
        App->>KS: signature.sign(attackerData)
        KS-->>App: Valid ECDSA signature
        Note over Attacker: SUCCESS — signed within<br/>120s window after legit auth
    end
```

### Vulnerability Summary

| Component | Weakness | Severity | Why |
|---|---|---|---|
| PIN hash | SHA-256, no salt, no KDF (no PBKDF2/Argon2) | **Medium** | Fast brute-force: 10,000 4-digit PINs × SHA-256 = milliseconds |
| PIN storage | EncryptedSharedPrefs with no-auth MasterKey | **Medium** | Any code in process can access when device unlocked |
| Retry counter | Stored in same EncryptedSharedPrefs | **Medium** | Frida can reset to 8 retries indefinitely |
| pinToken | 16 random bytes, stored alongside PIN hash | **Medium** | Extractable by Frida → can compute valid pinAuth |
| Signing key | 120s timeout, not per-use | **Low-Medium** | Root can piggyback within 120s of legitimate auth |
| Key material | TEE-backed, non-extractable | **Strong** | Cannot be extracted even with root |

### What WIOsense Gets Right

1. **ECDH channel**: PIN is never sent in plaintext — encrypted via AES-256-CBC over ECDH shared secret
2. **Retry limiting**: 8 total attempts, 3 consecutive mismatches → blocked
3. **Key agreement regeneration**: New ECDH key pair generated on each PIN mismatch (prevents replay)
4. **TEE key storage**: Signing key is hardware-backed, non-extractable
5. **StrongBox support**: Optional strongest hardware backing
6. **Follows CTAP2 spec**: Compliant with [FIDO Client to Authenticator Protocol](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html)

### What Could Be Stronger

1. **Per-use CryptoObject** (timeout=0) instead of 120s timeout — blocks root piggybacking
2. **Argon2id instead of SHA-256** for PIN hashing — makes brute-force infeasible
3. **MasterKey with biometric auth** — prevents app-level PIN extraction
4. **Hardware-bound PIN verification** — not possible with Keystore API, but Split Signing would achieve this

---

## 7. How This Applies to Your 2FA Authenticator

### If you adopt the WIOsense pattern:

```mermaid
graph TD
    GOOD["What you get from WIOsense's approach"]
    GOOD --> G1["CTAP2-compliant clientPIN protocol"]
    GOOD --> G2["ECDH-encrypted PIN channel"]
    GOOD --> G3["TEE-backed signing keys"]
    GOOD --> G4["Retry limiting (8 attempts)"]

    RISK["What you should improve"]
    RISK --> R1["Use Argon2id instead of SHA-256 for PIN hashing"]
    RISK --> R2["Use per-use CryptoObject (timeout=0)<br/>instead of 120s timeout"]
    RISK --> R3["Add server-side PIN-derived authorization<br/>(Option 2 from APP_PIN_VS_BIOMETRIC_ANALYSIS.md)"]
    RISK --> R4["Add RASP / Frida detection<br/>to raise the bar for hooking"]

    style GOOD fill:#c8e6c9,stroke:#2e7d32
    style RISK fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
```

### Recommended Hybrid: WIOsense Pattern + Server-Side Binding

Combine WIOsense's CTAP2 clientPIN with server-side authorization token verification:

```mermaid
sequenceDiagram
    participant User
    participant App as Your 2FA App
    participant PIN as ClientPinLocker<br/>(WIOsense pattern)
    participant KS as Keystore (TEE)
    participant Server

    Note over User,Server: Enrollment (once)
    App->>KS: Generate P256 key pair (per-use auth, timeout=0)
    Server->>App: authorization_secret (32 random bytes)
    User->>App: Choose app PIN
    App->>PIN: Store PIN hash (Argon2id, not SHA-256)
    App->>App: Encrypt authorization_secret with PIN-derived AES key
    App->>Server: Public key + attestation

    Note over User,Server: Authentication
    Server->>App: challenge (32 bytes)
    User->>App: Enter app PIN
    App->>PIN: Verify PIN (CTAP2 protocol, retry limiting)
    App->>App: Decrypt authorization_secret with PIN-derived key
    App->>KS: Signature.initSign(privateKey) via CryptoObject
    User->>App: Scan fingerprint (per-use biometric)
    App->>KS: Sign(challenge || authorization_secret)
    KS-->>App: ECDSA signature
    App->>Server: signature + HMAC(authorization_secret, challenge)
    Server->>Server: Verify ECDSA signature ✓
    Server->>Server: Verify authorization proof ✓
    Note over Server: Both pass → approved
```

This gives you **three independent layers**:
1. **App PIN** — stops casual physical access (CTAP2 protocol with retry limiting)
2. **Biometric (per-use CryptoObject)** — stops Frida/root (TEE-enforced)
3. **Server-side authorization** — stops any device-only attack (even if PIN + biometric bypassed, server rejects without authorization proof)

---

## Sources

- [WIOsense/rauth-android — GitHub](https://github.com/WIOsense/rauth-android)
- [FIDO CTAP2 Specification — fidoalliance.org](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html)
- [Android Keystore System — developer.android.com](https://developer.android.com/privacy-and-security/keystore)
- [WithSecure — Android Keystore Authentication Security](https://labs.withsecure.com/publications/how-secure-is-your-android-keystore-authentication)
