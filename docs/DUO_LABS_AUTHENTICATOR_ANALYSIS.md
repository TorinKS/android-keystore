# Duo Labs (Cisco) Android WebAuthn Authenticator — Implementation Analysis

**Repo:** [duo-labs/android-webauthn-authenticator](https://github.com/duo-labs/android-webauthn-authenticator)

Duo Security (acquired by Cisco) built this open-source FIDO2/WebAuthn authenticator library for Android. It turns a phone into a WebAuthn authenticator — the same role as a YubiKey, but using the phone's hardware (TEE/StrongBox) instead of a USB dongle.

---

## Architecture Overview

```mermaid
graph TD
    subgraph client["Client (Browser/OS)"]
        RP["Relying Party<br/>(website)"]
    end

    subgraph authenticator["Duo Labs Authenticator Library"]
        AUTH["Authenticator.java<br/><i>Main CTAP2 handler</i><br/>makeCredential / getAssertion"]
        CRED["CredentialSafe.java<br/><i>Key generation & Keystore access</i><br/>ES256, P-256, StrongBox"]
        CRYPTO["WebAuthnCryptography.java<br/><i>SHA256withECDSA signing</i><br/>Handles pre-authed CryptoObject"]
        BIO_MC["BiometricMakeCredential<br/>Callback.java<br/><i>Registration with biometric</i>"]
        BIO_GA["BiometricGetAssertion<br/>Callback.java<br/><i>Authentication with biometric</i>"]
    end

    subgraph storage["Storage"]
        KS["Android Keystore<br/>(TEE / StrongBox)<br/><i>P-256 private keys</i>"]
        DB["Room Database<br/><i>Credential metadata:</i><br/>rpId, userId, counter, alias"]
    end

    RP -->|"WebAuthn API"| AUTH
    AUTH --> CRED
    AUTH --> CRYPTO
    AUTH --> BIO_MC
    AUTH --> BIO_GA
    CRED --> KS
    CRED --> DB

    style KS fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style AUTH fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
```

### Source Files

| File | Purpose |
|---|---|
| `Authenticator.java` | Main entry point — implements `makeCredential()` and `getAssertion()` per WebAuthn spec |
| `CredentialSafe.java` | Android Keystore wrapper — key generation, COSE encoding, credential persistence |
| `WebAuthnCryptography.java` | Signing operations — handles both pre-authenticated (biometric) and direct signatures |
| `BiometricMakeCredentialCallback.java` | Extracts CryptoObject signature after biometric auth during registration |
| `BiometricGetAssertionCallback.java` | Extracts CryptoObject signature after biometric auth during authentication |
| `PublicKeyCredentialSource.java` | Room entity — credential metadata (rpId, userId, counter, Keystore alias) |
| `CredentialDatabase.java` | Room database singleton |
| `CredentialDao.java` | Data access — queries, insert, delete, counter increment |
| `NoneAttestationObject.java` | "none" attestation format (currently used) |
| `PackedSelfAttestationObject.java` | Self-signed packed attestation (implemented but disabled) |
| `SelectCredentialDialogFragment.java` | UI dialog for choosing between multiple credentials |

---

## Key Generation

**File:** `CredentialSafe.java`, lines 105-118

```java
KeyGenParameterSpec spec = new KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
    .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))   // NIST P-256
    .setDigests(KeyProperties.DIGEST_SHA256)                          // SHA-256
    .setUserAuthenticationRequired(this.authenticationRequired)       // Per-use biometric
    .setUserConfirmationRequired(false)
    .setInvalidatedByBiometricEnrollment(false)                      // Survives new fingerprint
    .setIsStrongBoxBacked(this.strongboxRequired)                    // Optional HSM
    .build();
```

| Parameter | Value | Why |
|---|---|---|
| Algorithm | EC P-256 (secp256r1) | WebAuthn ES256 = COSE algorithm `-7` |
| Digest | SHA-256 | Required for SHA256withECDSA |
| Auth required | Configurable (`true`/`false`) | Per-use biometric gate when enabled |
| Biometric invalidation | `false` | Key survives fingerprint enrollment changes |
| StrongBox | Configurable | Dedicated HSM if available |
| Timeout | **Not set** (defaults to per-use) | No `setUserAuthenticationValidityDurationSeconds` = per-use |

**Key alias format:** `"virgil-keypair-" + Base64(credentialId)`

**Constructor variants:**
```java
new Authenticator(ctx);                           // auth=true, strongbox=true (most secure)
new Authenticator(ctx, true, true);               // same as above
new Authenticator(ctx, true, false);              // biometric, TEE only
new Authenticator(ctx, false, false);             // no biometric, TEE only (testing)
```

---

## Registration Flow (makeCredential)

```mermaid
sequenceDiagram
    participant Client as Relying Party
    participant Auth as Authenticator
    participant Safe as CredentialSafe
    participant KS as Keystore (TEE)
    participant BP as BiometricPrompt
    participant User as User
    participant CB as MakeCredentialCallback

    Client->>Auth: makeCredential(options, ctx)

    Note over Auth: Step 1-2: Validate options<br/>(clientDataHash=32b, rpId, userEntity,<br/>algorithm support check: only ES256)

    Note over Auth: Step 3: Check excludeList<br/>(reject if credential already exists for this RP)

    Auth->>Safe: generateCredential(rpId, userId, userName)
    Safe->>KS: KeyPairGenerator.generateKeyPair()<br/>EC P-256, auth required, StrongBox
    KS-->>Safe: KeyPair created in hardware
    Safe->>Safe: Insert PublicKeyCredentialSource<br/>into Room database
    Safe-->>Auth: credentialSource (with keyPairAlias)

    Note over Auth: Step 8: User consent via biometric

    Auth->>Auth: Signature.getInstance("SHA256withECDSA")
    Auth->>KS: signature.initSign(privateKey)
    KS-->>Auth: Signature object (pending biometric)
    Auth->>Auth: Wrap in CryptoObject(signature)

    Auth->>BP: authenticate(cryptoObject, callback)
    BP->>User: Show fingerprint dialog
    User->>BP: Scan fingerprint
    BP->>KS: Verify biometric in TEE
    KS-->>BP: Auth succeeded
    BP->>CB: onAuthenticationSucceeded(result)

    CB->>CB: signature = result.getCryptoObject().getSignature()
    Note over CB: This signature is now TEE-authenticated

    CB->>Auth: makeInternalCredential(options, cred, signature)

    Note over Auth: Build authenticatorData:<br/>rpIdHash(32) + flags(1) + counter(4)<br/>+ attestedCredData(AAGUID + credId + COSEkey)

    Auth->>Auth: toSign = authenticatorData || clientDataHash
    Auth->>Auth: cryptoProvider.performSignature(key, toSign, signature)
    Note over Auth: Uses the biometric-authenticated signature object

    Auth->>Auth: Build NoneAttestationObject<br/>{fmt:"none", attStmt:{}, authData}

    Auth-->>Client: AttestationObject (CBOR)
```

---

## Authentication Flow (getAssertion)

```mermaid
sequenceDiagram
    participant Client as Relying Party
    participant Auth as Authenticator
    participant Safe as CredentialSafe
    participant KS as Keystore (TEE)
    participant BP as BiometricPrompt
    participant User as User
    participant CB as GetAssertionCallback

    Client->>Auth: getAssertion(options, credentialSelector, ctx)

    Note over Auth: Step 1: Validate options

    Auth->>Safe: getKeysForEntity(rpId)
    Safe-->>Auth: List of matching credentials

    Note over Auth: Step 2-3: Filter by allowList if provided

    alt Multiple credentials
        Auth->>User: Show credential selection dialog
        User-->>Auth: Selected credential
    else Single credential
        Auth->>Auth: Auto-select
    end

    Note over Auth: Check if key requires verification

    Auth->>Auth: Signature.getInstance("SHA256withECDSA")
    Auth->>KS: signature.initSign(privateKey)
    Auth->>Auth: Wrap in CryptoObject(signature)

    Auth->>BP: authenticate(cryptoObject, callback)
    BP->>User: Show fingerprint dialog
    User->>BP: Scan fingerprint
    BP->>KS: Verify biometric in TEE
    KS-->>BP: Auth succeeded
    BP->>CB: onAuthenticationSucceeded(result)

    CB->>CB: signature = result.getCryptoObject().getSignature()

    CB->>Auth: getInternalAssertion(options, cred, signature)

    Auth->>Safe: incrementCredentialUseCounter(cred)
    Safe-->>Auth: previousCounter

    Note over Auth: Build authenticatorData:<br/>rpIdHash(32) + flags(1) + counter(4)<br/>(no attestedCredData in assertions)

    Auth->>Auth: toSign = authenticatorData || clientDataHash
    Auth->>Auth: cryptoProvider.performSignature(key, toSign, signature)
    Note over Auth: Uses biometric-authenticated signature

    Auth-->>Client: {credentialId, authenticatorData,<br/>signature, userHandle}
```

---

## The Signing Mechanism: Two Modes

**File:** `WebAuthnCryptography.java`, lines 32-51

```java
public byte[] performSignature(PrivateKey privateKey, byte[] data, Signature sig)
        throws VirgilException {
    if (sig == null) {
        // Mode B: Create fresh signature (no biometric gate)
        sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(privateKey);
    }
    // Mode A: Use pre-authenticated signature from BiometricPrompt
    sig.update(data);
    return sig.sign();
}
```

```mermaid
graph TD
    INPUT["performSignature(privateKey, data, sig)"]

    INPUT --> CHECK{"sig == null?"}

    CHECK -->|"Yes — no biometric"| MODE_B["Mode B: Direct Signing<br/><br/>Create new Signature object<br/>initSign(privateKey)<br/>No biometric involved<br/>Key must not require auth"]
    CHECK -->|"No — from BiometricPrompt"| MODE_A["Mode A: Biometric-Bound Signing<br/><br/>Use the CryptoObject signature<br/>Already authenticated by TEE<br/>Bound to specific biometric event"]

    MODE_A --> SIGN["sig.update(data)<br/>sig.sign()<br/><br/>Returns DER-encoded<br/>ECDSA signature"]
    MODE_B --> SIGN

    style MODE_A fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style MODE_B fill:#fff3e0,stroke:#ef6c00
```

**What gets signed (the exact bytes):**

```
toSign = authenticatorData || clientDataHash

authenticatorData (37 bytes for assertion, 141+ for registration):
┌──────────────────┬───────┬──────────┬─────────────────────────┐
│ SHA-256(rpId)    │ flags │ counter  │ attestedCredData (reg)  │
│ 32 bytes         │ 1 byte│ 4 bytes  │ variable (reg only)     │
└──────────────────┴───────┴──────────┴─────────────────────────┘

flags byte:
  bit 0 (0x01): User Present (UP) — always set
  bit 2 (0x04): User Verified (UV) — set if biometric auth used
  bit 6 (0x40): Attested Credential Data — set in registration only

clientDataHash: 32 bytes (SHA-256 of client data JSON)

Total toSign: 69 bytes (assertion) or 173+ bytes (registration)
```

---

## Credential Storage: Split Architecture

```mermaid
graph LR
    subgraph keystore["Android Keystore (TEE/StrongBox)"]
        PK["P-256 Private Key<br/><i>alias: virgil-keypair-{base64(id)}</i><br/><br/>Non-extractable<br/>Biometric-gated (if enabled)<br/>Hardware-backed"]
    end

    subgraph room["Room Database (SQLite)"]
        CRED["PublicKeyCredentialSource<br/><br/>id: byte[32] (credential ID)<br/>keyPairAlias: String<br/>rpId: String<br/>userHandle: byte[]<br/>userDisplayName: String<br/>keyUseCounter: int"]
    end

    CRED -->|"keyPairAlias links to"| PK

    style keystore fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style room fill:#fff3e0,stroke:#ef6c00
```

**What's secure:** The private key never leaves TEE hardware. Even if the Room database is compromised, the attacker gets metadata (which rpId, which userId) but cannot sign anything.

**What's not secure:** The Room database is unencrypted SQLite. An attacker with file access can see which sites the user has credentials for, and the userHandle. This is metadata leakage, not key compromise.

---

## COSE Public Key Encoding

**File:** `CredentialSafe.java`, lines 228-265

The public key is CBOR-encoded in COSE_Key format for transmission to the Relying Party:

```
COSE_Key = {
    1:  2,       // kty: EC2 (Elliptic Curve with x,y coordinates)
    3:  -7,      // alg: ES256 (ECDSA with SHA-256)
    -1: 1,       // crv: P-256 (NIST curve)
    -2: x,       // x-coordinate (32 bytes, unsigned big-endian)
    -3: y        // y-coordinate (32 bytes, unsigned big-endian)
}
```

The code handles a subtle issue: Java's `BigInteger.toByteArray()` returns signed two's complement, which may be 33 bytes (extra leading zero) or fewer than 32 bytes. The `toUnsignedFixedLength()` method normalizes to exactly 32 bytes.

---

## Security Analysis

### Biometric Binding: Per-Use, Not Time-Based

Duo Labs uses **the strongest biometric pattern**: per-use CryptoObject binding.

```mermaid
graph TD
    subgraph duo["Duo Labs Implementation"]
        D1["Key created with<br/>setUserAuthenticationRequired(true)<br/><b>No timeout set</b> → per-use"]
        D2["Each sign() requires<br/>BiometricPrompt + CryptoObject"]
        D3["Signature object bound to<br/>specific biometric event in TEE"]
    end

    subgraph compare["Comparison"]
        C1["WIOsense rauth:<br/>120-second timeout<br/><i>Root can piggyback</i>"]
        C2["Duo Labs:<br/>Per-use, no timeout<br/><i>Root CANNOT piggyback</i>"]
    end

    style duo fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style C1 fill:#fff3e0,stroke:#ef6c00
    style C2 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

**Why this matters:** With WIOsense's 120-second timeout, a root attacker can wait for legitimate authentication and piggyback within the window. With Duo's per-use binding, **each signature requires its own biometric event** — there is no window.

### Configurable Security Levels

```mermaid
graph LR
    subgraph levels["Constructor Options"]
        L1["Authenticator(ctx, true, true)<br/><b>Maximum Security</b><br/>Biometric per-use + StrongBox"]
        L2["Authenticator(ctx, true, false)<br/><b>Strong</b><br/>Biometric per-use + TEE"]
        L3["Authenticator(ctx, false, false)<br/><b>Testing Only</b><br/>No biometric, no StrongBox"]
    end

    style L1 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style L2 fill:#e8f5e9,stroke:#2e7d32
    style L3 fill:#ffcdd2,stroke:#c62828
```

### Known Limitations

| Issue | Details | Impact |
|---|---|---|
| **Attestation is "none"** | No certificate chain to verify key origin | RP cannot prove keys are hardware-backed |
| **Key cleanup missing** | Deleting credential doesn't delete Keystore key | Orphaned keys accumulate |
| **Database unencrypted** | Room SQLite stores metadata in plaintext | Metadata leakage (which sites, userIds) |
| **Main-thread DB queries** | `allowMainThreadQueries()` enabled | ANR risk in production |
| **No PIN fallback** | Only biometric or nothing | Devices without biometric can't use auth mode |
| **Single algorithm** | Only ES256 supported | No RSA or EdDSA support |
| **`setInvalidatedByBiometricEnrollment(false)`** | Key survives new fingerprint enrollment | Attacker who enrolls their finger can use existing keys |

### Frida Resistance

```mermaid
graph TD
    Q["Can Frida bypass Duo Labs authenticator?"]

    Q -->|"auth=true (default)"| SAFE["Per-use CryptoObject:<br/><b>Frida CANNOT bypass</b><br/><br/>• Can't fake CryptoObject (TEE-bound)<br/>• Can't forge auth token (HMAC in TEE)<br/>• Can't skip biometric (hardware check)<br/>• Each sign() needs real finger"]

    Q -->|"auth=false (testing)"| UNSAFE["No biometric:<br/><b>Frida CAN sign freely</b><br/><br/>• Call performSignature(key, data, null)<br/>• Key has no auth requirement<br/>• Any code in process can sign"]

    style SAFE fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style UNSAFE fill:#ffcdd2,stroke:#c62828
```

---

## Duo Labs vs WIOsense: Side-by-Side

| Aspect | Duo Labs | WIOsense rauth |
|---|---|---|
| **Biometric model** | **Per-use** (no timeout) | Time-based (120s timeout) |
| **CryptoObject** | Always used when biometric enabled | Disabled by default (`biometricSigningSupported=false`) |
| **clientPIN** | Not supported | Full CTAP2 clientPIN protocol |
| **StrongBox** | Configurable | Configurable |
| **Attestation** | "none" only | "none", packed-self, packed-basic |
| **Key invalidation on biometric change** | No (`false`) | No (`false`) |
| **PIN fallback** | No — biometric or nothing | Yes — CTAP2 clientPIN |
| **Database encryption** | No (plain Room) | No (plain Room) |
| **Root resistance** | **Strong** (per-use CryptoObject) | **Medium** (120s window) |
| **Frida resistance** | **Strong** (can't forge CryptoObject) | **Weak** (PIN check bypassable, then 120s window) |

### Key Takeaway for Your 2FA Authenticator

Duo Labs demonstrates the **correct implementation pattern** for maximum security:

1. **Per-use biometric** — no `setUserAuthenticationValidityDurationSeconds`, so every signing operation requires fresh biometric
2. **CryptoObject binding** — the `Signature` object lives inside `CryptoObject`, so only a TEE-authenticated biometric can unlock it
3. **Dual-mode signing** — `performSignature(key, data, sig)` accepts either a pre-authenticated signature (from biometric) or `null` (for testing/no-auth mode)

If your business requires app PIN instead of biometric, Duo's pattern doesn't help directly — but combining it with WIOsense's clientPIN approach (PIN gates the request, per-use CryptoObject gates the signing) gives you both.

---

## Sources

- [duo-labs/android-webauthn-authenticator — GitHub](https://github.com/duo-labs/android-webauthn-authenticator)
- [WebAuthn Level 2 — W3C Specification](https://www.w3.org/TR/webauthn-2/)
- [Android Keystore System — developer.android.com](https://developer.android.com/privacy-and-security/keystore)
- [COSE Key Format — RFC 8152](https://datatracker.ietf.org/doc/html/rfc8152)
