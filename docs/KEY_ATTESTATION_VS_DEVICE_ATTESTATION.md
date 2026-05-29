# Key Attestation vs Device Attestation: What's the Difference?

These two terms are often confused. They are **different mechanisms** that prove **different things**.

---

## One-Sentence Definitions

**Key Attestation:** "This specific cryptographic key was generated inside real TEE/StrongBox hardware and has these properties." — Proved by a certificate chain signed by Google's root CA.

**Device Attestation (Play Integrity):** "This device is genuine, not rooted, runs verified Android, and your app is the real one." — Proved by a verdict token from Google's servers.

---

## Side-by-Side Comparison

```mermaid
graph LR
    subgraph ka["Key Attestation"]
        KA["Proves: one specific key<br/>is hardware-backed<br/><br/>API: KeyStore.getCertificateChain()<br/>Cost: FREE, unlimited<br/>Network: offline on device<br/>Needs Play Services: NO<br/>Server library: android/keyattestation"]
    end

    subgraph da["Device Attestation (Play Integrity)"]
        DA["Proves: the whole device<br/>is genuine and not tampered<br/><br/>API: PlayIntegrityClient<br/>.requestIntegrityToken()<br/>Cost: 10K/day free, then quota request<br/>Network: REQUIRED (Google servers)<br/>Needs Play Services: YES"]
    end

    style ka fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style da fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
```

| Aspect | **Key Attestation** | **Device Attestation (Play Integrity)** |
|---|---|---|
| **What it proves** | This P-256 key is in real TEE, requires biometric, is non-extractable | This device runs verified Android, isn't rooted, has genuine Play Store |
| **Granularity** | **Per-key** — each key has its own attestation | **Per-device** — one verdict for the whole device |
| **Android API** | `KeyGenParameterSpec.setAttestationChallenge()` + `KeyStore.getCertificateChain()` | `PlayIntegrityClient.requestIntegrityToken()` |
| **Cost** | **Free, unlimited, no quota** | **10,000 requests/day free**, then must request quota increase from Google |
| **Network on device** | **Not needed** — certificate generated locally by TEE | **Required** — device must contact Google's servers |
| **Network on your server** | Fetch root certs once (cacheable), fetch CRL periodically | Verify verdict token (may call Google or verify locally) |
| **Needs Google Play Services** | **No** — pure Keystore API | **Yes** — requires Play Services |
| **Works on Huawei** | **Yes** (EMUI, HarmonyOS 2-3) | **No** (no Play Services) |
| **Works on AOSP/custom ROMs** | **Yes** (if TEE is provisioned) | **No** |
| **What server verifies** | X.509 certificate chain → standard crypto, no Google API | Signed verdict token → may need Google API to decode |
| **Can prove key requires biometric** | **Yes** — `userAuthenticationRequired` in attestation extension | **No** — knows nothing about individual keys |
| **Can prove device isn't rooted** | **Partially** — `verifiedBootState` field in extension | **Yes** — primary purpose |
| **Can prove app is genuine** | **No** | **Yes** — includes app signing certificate hash |
| **Minimum Android** | API 24 (7.0), mandatory since API 26 (8.0) | Varies, requires Play Services |
| **Server verification library** | [android/keyattestation](https://github.com/android/keyattestation) (Kotlin, official) | Google Play Integrity API client library |

---

## What Each One Tells Your Server

### Key Attestation — Per-Key Proof

When your server verifies a key attestation certificate chain, it learns:

```
About THIS specific key:
  ✓ Algorithm: EC P-256
  ✓ Security level: TrustedEnvironment (TEE) or StrongBox
  ✓ Key is non-exportable
  ✓ Key requires user authentication (biometric/PIN)
  ✓ Key was generated on-device (not imported)

About the device (from attestation extension):
  ✓ Android OS version (e.g., 16)
  ✓ Security patch level (e.g., May 2026)
  ✓ Verified boot state (locked bootloader = genuine)
  ✓ Device is not an emulator

NOT proven:
  ✗ Whether the app is genuine (could be repackaged)
  ✗ Whether Play Services is present
  ✗ Whether the user has screen lock enabled (beyond key's own auth requirement)
```

### Device Attestation (Play Integrity) — Device-Level Verdict

When your server decodes a Play Integrity verdict, it learns:

```
About the device:
  ✓ MEETS_BASIC_INTEGRITY — device passes basic checks
  ✓ MEETS_DEVICE_INTEGRITY — genuine device with verified Android
  ✓ MEETS_STRONG_INTEGRITY — hardware-backed security + recent patch

About the app:
  ✓ App package name matches
  ✓ App signing certificate matches (not repackaged)
  ✓ App was installed from Play Store (optional check)

NOT proven:
  ✗ Whether any specific key is hardware-backed
  ✗ Whether the key requires biometric
  ✗ Any per-key property at all
```

---

## How Key Attestation Works (The Free One)

```mermaid
sequenceDiagram
    participant App as Your App
    participant KS as Android Keystore (TEE)
    participant Server as Your Server

    Note over App: During enrollment
    App->>Server: "I want to register, give me a challenge"
    Server->>Server: Generate random nonce (32 bytes)
    Server-->>App: challenge = 0xA3B7F2...

    App->>KS: KeyGenParameterSpec.Builder("my_key")<br/>.setAttestationChallenge(challenge)<br/>.build()
    KS->>KS: Generate P-256 key pair inside TEE
    KS->>KS: Create certificate chain:<br/>leaf cert (with attestation extension)<br/>+ intermediate cert<br/>+ root cert (Google's CA)
    KS-->>App: Certificate chain (3-4 certs)

    App->>Server: Send certificate chain (DER/PEM encoded)

    Note over Server: Verification (no Google API call needed)
    Server->>Server: 1. Parse X.509 certificate chain
    Server->>Server: 2. Verify each cert signs the next
    Server->>Server: 3. Check root matches Google's published root<br/>(cached from googleapis.com/attestation/root)
    Server->>Server: 4. Check no cert is revoked<br/>(cached CRL from googleapis.com/attestation/status)
    Server->>Server: 5. Parse attestation extension from leaf cert
    Server->>Server: 6. Verify challenge matches our nonce
    Server->>Server: 7. Check securityLevel = TEE or StrongBox
    Server->>Server: 8. Check key properties (EC, 256-bit, auth required)

    Server-->>App: Registration accepted ✓
```

**Zero Google API calls.** Your server does standard X.509 certificate verification using the [android/keyattestation](https://github.com/android/keyattestation) Kotlin library. The only network calls are fetching the root certificate list and CRL from Google's public endpoints — both cacheable.

---

## How Device Attestation (Play Integrity) Works (The Quota-Limited One)

```mermaid
sequenceDiagram
    participant App as Your App
    participant Play as Google Play Services<br/>(on device)
    participant Google as Google's Servers
    participant Server as Your Server

    App->>Server: "Give me a nonce"
    Server-->>App: nonce = 0xF4E9...

    App->>Play: requestIntegrityToken(nonce)
    Play->>Google: Send device signals + nonce<br/>(device hardware info, app cert, etc.)
    Note over Google: Google evaluates device:<br/>• Is bootloader locked?<br/>• Is this a real device or emulator?<br/>• Is the app genuine?<br/>• Is Play Protect enabled?
    Google-->>Play: Signed verdict token
    Play-->>App: IntegrityTokenResponse

    App->>Server: Send verdict token

    Note over Server: Decode verdict (needs Google or crypto library)
    Server->>Server: Verify token signature
    Server->>Server: Check verdict levels:<br/>MEETS_BASIC_INTEGRITY?<br/>MEETS_DEVICE_INTEGRITY?<br/>MEETS_STRONG_INTEGRITY?
    Server->>Server: Check app identity:<br/>package name, signing cert

    Server-->>App: Device trusted ✓

    Note over Google: This counts against your<br/>10,000/day quota
```

**Requires Google Play Services on the device** and **counts against your quota** (10K/day free).

---

## Which Open-Source Projects Support Key Attestation?

| Project | Uses `setAttestationChallenge`? | Attestation type |
|---|---|---|
| **Duo Labs** (android-webauthn-authenticator) | **No** | WebAuthn "none" attestation (no hardware proof) |
| **WIOsense** (rauth-android) | **No** | WebAuthn "none" or "packed-self" (self-signed, no hardware proof) |
| **LINE** (webauthn-kotlin) | Not documented | Unknown |
| **Google Credential Manager** | **Yes** (internally) | Hardware-backed key attestation (since 2024) |

**None of the open-source FIDO2 authenticator libraries we analyzed use Android hardware key attestation.** They all use WebAuthn-level attestation ("none" or self-signed "packed"), which doesn't prove the key is hardware-backed.

This is a significant gap. For a production 2FA authenticator, you should add `setAttestationChallenge()` to the key generation and verify the certificate chain on your server.

---

## Server-Side Verification Libraries

| Library | Language | Purpose | Status |
|---|---|---|---|
| **[android/keyattestation](https://github.com/android/keyattestation)** | Kotlin | **Official** Google library for verifying key attestation certificate chains | **Current — recommended** |
| ~~[google/android-key-attestation](https://github.com/google/android-key-attestation)~~ | Java | Old Google sample for key attestation verification | **Deprecated** — use android/keyattestation instead |
| **[webauthn4j/webauthn4j](https://github.com/webauthn4j/webauthn4j)** | Java | WebAuthn server library — supports "android-key" attestation format | Active, passes FIDO Alliance tests |
| **[webauthn-open-source/fido2-lib](https://github.com/webauthn-open-source/fido2-lib)** | Node.js | WebAuthn server — supports android-safetynet and packed attestation | Active |
| **[lbuchs/WebAuthn](https://github.com/lbuchs/WebAuthn)** | PHP | Lightweight WebAuthn server | Active |

**For your 2FA backend, use [android/keyattestation](https://github.com/android/keyattestation)** — it's the current official Google library, written in Kotlin, includes the 2026 root certificates, and handles edge cases that custom verifiers miss.

---

## What Should You Use for Your 2FA Authenticator?

```mermaid
graph TD
    Q["What do you need to prove?"]

    Q -->|"This specific signing key<br/>is in real TEE hardware"| KA["Use Key Attestation<br/><br/>• setAttestationChallenge() on device<br/>• Verify cert chain on server<br/>• android/keyattestation library<br/>• FREE, unlimited, no Play Services"]

    Q -->|"This device is genuine<br/>and not rooted"| PI["Use Play Integrity API<br/><br/>• requestIntegrityToken() on device<br/>• Verify verdict on server<br/>• 10K/day free quota<br/>• Requires Play Services"]

    Q -->|"Both"| BOTH["Use both together<br/><br/>• Key Attestation during enrollment<br/>  (verify key is hardware-backed)<br/>• Play Integrity periodically<br/>  (verify device stays genuine)"]

    style KA fill:#c8e6c9,stroke:#2e7d32,stroke-width:3px
    style PI fill:#fff3e0,stroke:#ef6c00
    style BOTH fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
```

**For a 2FA authenticator:** Key Attestation is essential (prove the signing key is real). Play Integrity is optional (nice to have but not critical, and has quota limits).

---

## Sources

- [Verify hardware-backed key pairs with key attestation — developer.android.com](https://developer.android.com/privacy-and-security/security-key-attestation)
- [Key and ID attestation — source.android.com](https://source.android.com/docs/security/features/keystore/attestation)
- [android/keyattestation — GitHub (official Google library)](https://github.com/android/keyattestation)
- [Play Integrity API overview — developer.android.com](https://developer.android.com/google/play/integrity/overview)
- [Comparing Key Attestation and Play Integrity API — Mayrhofer 2024](https://www.mayrhofer.eu.org/courses/android-security/selected-paper/2024/Comparing_key_attestation_and_Play_Integrity_API.pdf)
- [Android Device Attestation — Scalefusion](https://blog.scalefusion.com/android-device-attestation/)
- [Device vs App Attestation — Approov](https://approov.io/knowledge/what-is-the-difference-between-device-attestation-and-app-attestation)
- [Google Play Integrity API limitations — Approov](https://approov.io/blog/limitations-of-google-play-integrity-api-ex-safetynet)
