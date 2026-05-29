# Duo Labs vs WIOsense: FIDO2 Authenticator Implementation Comparison

Two open-source Android FIDO2 authenticator libraries, both turning the phone into a security key. Same goal, different security tradeoffs.

| | **Duo Labs** | **WIOsense rauth** |
|---|---|---|
| **Repo** | [duo-labs/android-webauthn-authenticator](https://github.com/duo-labs/android-webauthn-authenticator) | [WIOsense/rauth-android](https://github.com/WIOsense/rauth-android) |
| **Company** | Cisco / Duo Security | WIOsense GmbH |
| **Purpose** | WebAuthn authenticator library | FIDO2 roaming authenticator (NFC/BLE) |

---

## 1. Key Generation

Both generate P-256 (secp256r1) keys in Android Keystore. The critical difference is how they configure authentication.

```mermaid
graph LR
    subgraph duo["Duo Labs — CredentialSafe.java"]
        D["setUserAuthenticationRequired(true)<br/><b>No timeout set</b><br/>→ Per-use authentication<br/>Every sign() needs fresh biometric"]
    end

    subgraph wio["WIOsense — CredentialSafe.java"]
        W["setUserAuthenticationRequired(true)<br/><b>setUserAuthenticationValidityDurationSeconds(120)</b><br/>→ Time-based authentication<br/>Key usable for 120s after auth"]
    end

    style duo fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style wio fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
```

| Parameter | Duo Labs | WIOsense |
|---|---|---|
| Algorithm | EC P-256 (secp256r1) | EC P-256 (secp256r1) |
| COSE algorithm | -7 (ES256) | -7 (ES256) |
| Auth required | Configurable (default: `true`) | Always `true` |
| **Auth timeout** | **Not set → per-use** | **120 seconds** |
| StrongBox | Configurable (default: `true`) | Configurable |
| Invalidated by biometric enrollment | `false` | `false` |
| Key alias prefix | `virgil-keypair-` | `virgil-keypair-` |

**Impact of this single difference (timeout):**

```mermaid
sequenceDiagram
    participant User
    participant TEE

    Note over User,TEE: Duo Labs (per-use, no timeout)
    User->>TEE: Sign request #1 → biometric required
    User->>TEE: Sign request #2 → biometric required again
    User->>TEE: Sign request #3 → biometric required again
    Note over TEE: Every operation needs a finger

    Note over User,TEE: WIOsense (120s timeout)
    User->>TEE: Sign request #1 → biometric required
    Note over TEE: Key unlocked for 120 seconds
    User->>TEE: Sign request #2 → no biometric needed
    User->>TEE: Sign request #3 → no biometric needed
    Note over TEE: ⏱ 120 seconds pass...
    User->>TEE: Sign request #4 → biometric required again
```

---

## 2. Biometric Integration

```mermaid
graph TD
    subgraph duo_bio["Duo Labs Biometric Flow"]
        D1["Signature.initSign(privateKey)"]
        D2["Wrap in CryptoObject(signature)"]
        D3["BiometricPrompt.authenticate(<br/>promptInfo, cryptoObject)"]
        D4["onAuthenticationSucceeded:<br/>sig = result.getCryptoObject()<br/>.getSignature()"]
        D5["performSignature(key, data, sig)<br/><i>Uses TEE-authenticated signature</i>"]

        D1 --> D2 --> D3 --> D4 --> D5
    end

    subgraph wio_bio["WIOsense Biometric Flow"]
        W1["biometricSigningSupported = false<br/><i>(hardcoded, line 74)</i>"]
        W2["CryptoObject set to null"]
        W3["BiometricPrompt.authenticate(<br/>promptInfo)<br/><i>No CryptoObject!</i>"]
        W4["onAuthenticationSucceeded:<br/>result.getCryptoObject() = null"]
        W5["performSignature(key, data, null)<br/><i>Creates new Signature, no binding</i>"]

        W1 --> W2 --> W3 --> W4 --> W5
    end

    style D5 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style W5 fill:#ffcdd2,stroke:#c62828,stroke-width:2px
    style W1 fill:#ffcdd2,stroke:#c62828
```

| Aspect | Duo Labs | WIOsense |
|---|---|---|
| **CryptoObject used** | **Yes — always when auth enabled** | **No — disabled by design** |
| Signature source | From `result.getCryptoObject().getSignature()` | Created fresh via `Signature.getInstance()` |
| Biometric binding | Signature bound to specific biometric event in TEE | Biometric unlocks the key for 120s, signing is separate |
| BiometricPrompt type | `authenticate(promptInfo, cryptoObject)` | `authenticate(promptInfo)` (no crypto) |
| Device credential fallback | No — biometric only | Yes — `setDeviceCredentialAllowed(true)` |

**Why this matters:**

```mermaid
graph TD
    subgraph duo_sec["Duo Labs: CryptoObject Binding"]
        DS1["BiometricPrompt verifies fingerprint<br/>inside TEE"]
        DS2["TEE binds the Signature object<br/>to THIS specific auth event"]
        DS3["Only THIS Signature can sign"]
        DS4["Frida hooks onAuthenticationSucceeded?<br/>Gets null CryptoObject → crash"]
        DS1 --> DS2 --> DS3
        DS1 --> DS4
    end

    subgraph wio_sec["WIOsense: No CryptoObject"]
        WS1["BiometricPrompt verifies fingerprint<br/>inside TEE"]
        WS2["TEE unlocks all keys for this UID<br/>for 120 seconds"]
        WS3["ANY code in process can sign<br/>during that window"]
        WS4["Frida hooks onAuthenticationSucceeded?<br/>Still needs to wait for real auth,<br/>but then can sign freely for 120s"]
        WS1 --> WS2 --> WS3
        WS1 --> WS4
    end

    style DS3 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style WS3 fill:#ffcdd2,stroke:#c62828,stroke-width:2px
    style DS4 fill:#c8e6c9,stroke:#2e7d32
    style WS4 fill:#fff3e0,stroke:#ef6c00
```

---

## 3. PIN Support

This is where WIOsense has a feature Duo Labs completely lacks.

| Aspect | Duo Labs | WIOsense |
|---|---|---|
| **App-level PIN** | Not supported | Full CTAP2 clientPIN protocol |
| PIN storage | N/A | EncryptedSharedPreferences (AES-256-GCM) |
| PIN hashing | N/A | SHA-256, first 16 bytes (no salt, no KDF) |
| PIN retry limit | N/A | 8 attempts, 3 consecutive → blocked |
| PIN token | N/A | 16-byte random, used as HMAC key for pinAuth |
| PIN-to-signing binding | N/A | pinAuth = HMAC(pinToken, clientDataHash) verified before sign |
| PIN channel encryption | N/A | ECDH key agreement + AES-256-CBC |
| **Can a device without biometric be used?** | **No** (auth=true requires biometric) | **Yes** (clientPIN as fallback) |

### WIOsense clientPIN Flow (Duo Labs has no equivalent)

```mermaid
sequenceDiagram
    participant Client as CTAP2 Client
    participant Auth as WIOsense Authenticator
    participant Locker as ClientPinLocker

    Note over Client,Locker: Step 1: Get PIN token (proves PIN knowledge)
    Client->>Auth: clientPIN(subCommand=5,<br/>keyAgreement, pinHashEnc)
    Auth->>Auth: ECDH shared secret
    Auth->>Auth: Decrypt pinHashEnc
    Auth->>Locker: isPinMatch(decryptedHash)?
    Locker-->>Auth: Match!
    Auth->>Locker: getToken() → pinToken
    Auth-->>Client: Encrypted pinToken

    Note over Client,Locker: Step 2: Use pinToken to authorize signing
    Client->>Client: pinAuth = HMAC(pinToken, clientDataHash)[0:16]
    Client->>Auth: getAssertion(rpId, clientDataHash, pinAuth)
    Auth->>Auth: Verify pinAuth matches<br/>HMAC(storedPinToken, clientDataHash)
    Note over Auth: PIN verified → proceed to sign
    Auth->>Auth: Sign with Keystore key
    Auth-->>Client: Assertion result
```

---

## 4. Attack Resistance

### Frida Attack

```mermaid
graph TD
    subgraph frida["Attacker with Frida (root required)"]
        F1["Hook onAuthenticationSucceeded()"]
        F2["Call it directly with fake result"]
    end

    subgraph duo_r["Duo Labs Result"]
        DR1["Fake result has null CryptoObject"]
        DR2["result.getCryptoObject().getSignature()"]
        DR3["NullPointerException!"]
        DR4["Even if bypassed: no valid<br/>Signature object exists<br/>without real biometric"]
        DR1 --> DR2 --> DR3
        DR2 --> DR4
    end

    subgraph wio_r["WIOsense Result"]
        WR1["Fake result accepted<br/>(CryptoObject not used)"]
        WR2["But Keystore key still needs<br/>authentication (120s timeout)"]
        WR3["Attacker must wait for<br/>legitimate user to authenticate"]
        WR4["After real auth: sign freely<br/>for 120 seconds"]
        WR1 --> WR2 --> WR3 --> WR4
    end

    frida --> duo_r
    frida --> wio_r

    style DR3 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style WR4 fill:#ffcdd2,stroke:#c62828,stroke-width:2px
```

### Root Attack: Piggybacking Explained

"Piggybacking" means the attacker **doesn't authenticate themselves** — they wait for the **legitimate user** to authenticate for any reason, then ride on that authentication window to perform their own operations. Like following someone through a locked door before it closes.

#### How piggybacking works with a 120-second timeout

```mermaid
sequenceDiagram
    participant User as Legitimate User
    participant App as 2FA App
    participant Malware as Root Attacker<br/>(Frida, injected code)
    participant TEE as TEE / Keystore

    Note over Malware: Attacker is running as the app's UID<br/>(via Frida injection or root code execution)

    Note over Malware: Step 1: Attacker tries to sign — FAILS
    Malware->>TEE: Signature.initSign(privateKey)
    TEE--xMalware: UserNotAuthenticatedException<br/>(no recent authentication)

    Note over Malware: Step 2: Attacker WAITS...<br/>doing nothing, just monitoring

    Note over User: User opens the app for<br/>a legitimate login to example.com
    User->>App: Scans fingerprint on BiometricPrompt
    App->>TEE: BiometricPrompt.authenticate()
    TEE->>TEE: Fingerprint verified ✓
    TEE->>TEE: Generate HardwareAuthToken
    Note over TEE: ALL keys for this UID are now<br/>unlocked for 120 seconds

    App->>TEE: Signature.initSign(key) → sign(challenge)
    TEE-->>App: Legitimate signature for example.com ✓
    Note over User: User sees "Login successful"<br/>and puts the phone down

    Note over Malware: Step 3: Attacker acts NOW<br/>(still within the 120s window)
    Malware->>TEE: Signature.initSign(SAME privateKey)
    TEE-->>Malware: OK! Auth token still valid (87s remaining)
    Malware->>TEE: signature.update(ATTACKER'S data)
    Malware->>TEE: signature.sign()
    TEE-->>Malware: Valid ECDSA signature!
    Note over Malware: Attacker signed their own payload<br/>using the user's key, without<br/>the user knowing or seeing a prompt

    Malware->>Malware: Send forged signature to<br/>attacker's server / relay to victim RP

    Note over TEE: ⏱ 120 seconds pass...
    Malware->>TEE: Signature.initSign(key)
    TEE--xMalware: UserNotAuthenticatedException<br/>(window closed, must wait again)
```

#### Why it's called "piggybacking"

The attacker **does not authenticate**. They don't need to — the TEE doesn't track *which code* triggered the biometric prompt. It only knows: "user with UID 10402 authenticated 87 seconds ago, timeout is 120 seconds, so any code running as UID 10402 can use the key."

The attacker **piggybacks on the user's legitimate authentication** — using the trust the user established with the TEE for their own malicious signing.

#### Why this DOESN'T work with Duo Labs (per-use CryptoObject)

```mermaid
sequenceDiagram
    participant User as Legitimate User
    participant App as 2FA App
    participant Malware as Root Attacker
    participant TEE as TEE / Keystore

    Note over User: User scans fingerprint for legitimate login
    App->>TEE: BiometricPrompt.authenticate(cryptoObject)
    TEE->>TEE: Fingerprint verified ✓
    TEE->>TEE: Bind THIS specific Signature object<br/>to THIS biometric event
    TEE-->>App: CryptoObject with bound Signature

    App->>TEE: boundSignature.sign(legitimateData)
    TEE-->>App: Signature ✓ (one-time use, now spent)

    Note over Malware: Attacker tries to use the same key
    Malware->>TEE: Signature.initSign(samePrivateKey)
    TEE--xMalware: UserNotAuthenticatedException
    Note over Malware: BLOCKED!<br/>Per-use = no timeout window.<br/>Each sign() needs its OWN biometric event.<br/>The user's authentication was bound to<br/>THAT specific Signature object,<br/>not to a time window.

    Note over Malware: Attacker's only option:<br/>show BiometricPrompt themselves<br/>→ but user sees unexpected prompt<br/>→ and must physically touch sensor
```

The difference: with per-use, the TEE doesn't say "keys unlocked for 120 seconds." It says "**this specific Signature object** is unlocked for **one operation**." There is no window. There is nothing to piggyback on.

#### Real-world piggybacking scenario

Think of a banking app with 120-second key timeout:

1. **9:00:00** — User opens app, scans fingerprint, approves a $50 transfer
2. **9:00:15** — Malware (running silently in the same process) signs a $5,000 transfer to the attacker's account
3. **9:00:16** — Malware sends the signed request to the bank's server
4. **9:00:17** — Bank verifies the ECDSA signature — it's valid (key was unlocked at 9:00:00)
5. **9:01:45** — User gets a notification: "$5,000 transferred"
6. **9:02:00** — 120-second window closes. Too late.

With per-use CryptoObject, step 2 fails immediately — the malware can't get a valid Signature object without triggering a new BiometricPrompt that the user would see.

### Root Attack Comparison Diagram

```mermaid
graph TD
    subgraph root["Root attacker running as app's UID"]
        R1["Call Signature.initSign(key)<br/>directly, bypass all UI"]
    end

    subgraph duo_root["Duo Labs (per-use)"]
        DD1["initSign() throws<br/>UserNotAuthenticatedException"]
        DD2["Key requires per-use auth"]
        DD3["Cannot forge auth token<br/>(HMAC key in TEE)"]
        DD4["BLOCKED — needs real finger<br/>for EACH signature"]
        DD1 --> DD2 --> DD3 --> DD4
    end

    subgraph wio_root["WIOsense (120s timeout)"]
        WD1["initSign() throws<br/>UserNotAuthenticatedException"]
        WD2["Key requires auth (120s timeout)"]
        WD3["Wait for user to authenticate<br/>for any purpose..."]
        WD4["Within 120s: initSign() succeeds!"]
        WD5["Sign anything — user doesn't know"]
        WD1 --> WD2 --> WD3 --> WD4 --> WD5
    end

    root --> duo_root
    root --> wio_root

    style DD4 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style WD5 fill:#ffcdd2,stroke:#c62828,stroke-width:2px
```

### Stolen Unlocked Phone (Thief Opens App)

| Scenario | Duo Labs | WIOsense |
|---|---|---|
| Thief opens app | Sees BiometricPrompt | May see PIN prompt or BiometricPrompt |
| Thief tries to sign | Must scan fingerprint — blocked | Must enter PIN or scan fingerprint — blocked |
| Thief knows/guesses PIN | N/A (no PIN support) | Can enter PIN, then sign |
| **Verdict** | **Protected** (biometric can't be guessed) | **Partially protected** (4-digit PIN is guessable, 8 attempts) |

### Full Comparison Matrix

| Attack Vector | Duo Labs (auth=true) | WIOsense (with PIN, 120s timeout) |
|---|---|---|
| **Other app** | Blocked (UID isolation) | Blocked (UID isolation) |
| **Frida: hook callback** | **Blocked** — null CryptoObject | Callback fires but key still locked |
| **Frida: call sign() directly** | **Blocked** — per-use auth needed | **Blocked** — auth needed |
| **Frida: bypass PIN** | N/A (no PIN) | **Possible** — hook `isPinMatch()` |
| **Root: piggyback after legit auth** | **Blocked** — per-use, no window | **120s window to sign freely** |
| **Root: forge auth token** | **Blocked** — HMAC in TEE | **Blocked** — HMAC in TEE |
| **Root: brute-force PIN** | N/A | **Possible** — SHA-256 no salt, 10K combos |
| **Stolen phone, thief has PIN** | N/A | **Compromised** |
| **Stolen phone, no PIN** | **Blocked** — biometric only | **Blocked** — PIN or biometric required |
| **Key extraction from TEE** | **Blocked** — hardware isolation | **Blocked** — hardware isolation |

---

## 5. Attestation

| Aspect | Duo Labs | WIOsense |
|---|---|---|
| Default format | `"none"` | `"none"` |
| Packed self-attestation | Implemented but **disabled** | Implemented, selectable |
| Packed basic attestation | Not implemented | Implemented (with external cert) |
| Key attestation | Not implemented | Not implemented |
| **Can server verify key is hardware-backed?** | **No** | **No** (unless basic attestation cert configured) |

Both libraries default to "none" attestation — the server cannot cryptographically verify the keys came from real hardware. This is a significant gap for high-security deployments.

---

## 6. Credential Storage

| Aspect | Duo Labs | WIOsense |
|---|---|---|
| Private keys | Android Keystore (TEE/StrongBox) | Android Keystore (TEE/StrongBox) |
| Metadata storage | Room database (unencrypted SQLite) | Room database (unencrypted SQLite) |
| PIN data | N/A | EncryptedSharedPreferences (AES-256-GCM) |
| Key alias format | `virgil-keypair-{base64(id)}` | `virgil-keypair-{base64(id)}` |
| Counter persistence | Room database | Room database |
| Key cleanup on credential delete | **No** — Keystore key orphaned | **No** — Keystore key orphaned |
| Database encryption | **No** | **No** |

Both share the same weakness: deleting a credential removes the Room record but **leaves the Keystore key behind**. Over time, orphaned keys accumulate.

---

## 7. Device Compatibility

| Requirement | Duo Labs | WIOsense |
|---|---|---|
| Minimum Android | 9.0 (API 28) — BiometricPrompt | 9.0 (API 28) — BiometricPrompt |
| Biometric hardware | **Required** when auth=true | Optional (clientPIN fallback) |
| StrongBox hardware | Optional (configurable) | Optional (configurable) |
| Screen lock required | Only if biometric enabled | Yes (BiometricPrompt requires it) |
| **Devices without biometric** | **Cannot use with auth=true** | **Can use via clientPIN** |
| NFC/BLE transport | Not implemented | Implemented (roaming authenticator) |

---

## 8. Verdict: Which to Use?

```mermaid
graph TD
    Q1["What does your 2FA app need?"]

    Q1 -->|"Maximum security,<br/>biometric always available"| DUO["Use Duo Labs pattern<br/><br/>Per-use CryptoObject<br/>Strongest Frida/root resistance<br/>No PIN fallback needed"]

    Q1 -->|"Must work without biometric,<br/>need PIN fallback"| WIO["Use WIOsense pattern<br/><br/>CTAP2 clientPIN protocol<br/>Works on all devices<br/>Weaker root resistance (120s window)"]

    Q1 -->|"Maximum security +<br/>PIN fallback"| HYBRID["Combine both<br/><br/>Duo's per-use CryptoObject for signing<br/>+ WIOsense's clientPIN for user verification<br/>+ Server-side authorization token<br/>= Three independent layers"]

    style DUO fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
    style WIO fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    style HYBRID fill:#e3f2fd,stroke:#1565c0,stroke-width:3px
```

### For Your 2FA Authenticator

Your business wants app PIN instead of forcing biometric. Neither library does exactly what you need:

- **Duo Labs** has the strongest signing security (per-use CryptoObject) but no PIN support at all
- **WIOsense** has clientPIN but weaker signing security (120s timeout, no CryptoObject binding)

**The recommended hybrid:**

```mermaid
graph TD
    subgraph hybrid["Recommended: Hybrid Architecture"]
        H1["Key Generation<br/><i>From Duo Labs:</i><br/>setUserAuthenticationRequired(true)<br/>No timeout (per-use)<br/>StrongBox if available"]

        H2["PIN Verification<br/><i>From WIOsense:</i><br/>CTAP2 clientPIN protocol<br/><b>Improved:</b> Argon2id instead of SHA-256<br/>Rate limiting (8 attempts)"]

        H3["Signing<br/><i>From Duo Labs:</i><br/>BiometricPrompt + CryptoObject<br/>Signature bound to biometric event"]

        H4["Server Validation<br/><i>Added layer:</i><br/>PIN-derived authorization token<br/>Server rejects without proof"]

        H1 --> H2
        H2 -->|"PIN correct"| H3
        H3 -->|"Finger scanned"| H4
    end

    style hybrid fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
```

This gives three independent gates:
1. **PIN** — stops casual theft (CTAP2 protocol, retry-limited)
2. **Biometric** — stops Frida/root (TEE-enforced per-use CryptoObject)
3. **Server token** — stops any device-only attack (even if PIN + biometric somehow bypassed)

---

## Sources

- [duo-labs/android-webauthn-authenticator — GitHub](https://github.com/duo-labs/android-webauthn-authenticator)
- [WIOsense/rauth-android — GitHub](https://github.com/WIOsense/rauth-android)
- [FIDO CTAP2 Specification — fidoalliance.org](https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html)
- [Android Keystore System — developer.android.com](https://developer.android.com/privacy-and-security/keystore)
- [Trusty TEE — source.android.com](https://source.android.com/docs/security/features/trusty)
