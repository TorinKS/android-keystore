# CTAP2 ClientPIN Protocol: Complete Technical Description

## What Problem Does ClientPIN Solve?

FIDO2 authenticators (YubiKeys, phones) need a way to verify the user's identity. Biometrics (fingerprint, face) is one option, but not all devices have biometric hardware. ClientPIN provides a **software PIN alternative** — the user sets a 4-63 character PIN on the authenticator, and proves knowledge of it before each operation.

The challenge: the PIN must travel from the client (browser/OS) to the authenticator (phone/security key) — but the transport (USB, NFC, BLE) might be sniffable. **ClientPIN solves this with ECDH key agreement** — the PIN is encrypted in transit and never sent in plaintext.

---

## Protocol Architecture

```mermaid
graph TD
    subgraph client["CTAP2 Client (Browser / OS)"]
        CL_PIN["User enters PIN"]
        CL_ECDH["Generate ephemeral EC key pair"]
        CL_SECRET["Derive shared secret via ECDH"]
        CL_ENC["Encrypt PIN with shared secret"]
        CL_AUTH["Compute pinAuth = HMAC(pinToken, clientDataHash)"]
    end

    subgraph transport["Transport (USB / NFC / BLE)"]
        TR["Encrypted messages only<br/><i>Plaintext PIN never on the wire</i>"]
    end

    subgraph authenticator["Authenticator (Phone / Security Key)"]
        AU_ECDH["Generate ephemeral EC key pair"]
        AU_SECRET["Derive same shared secret via ECDH"]
        AU_DEC["Decrypt PIN"]
        AU_VERIFY["Compare against stored PIN hash"]
        AU_TOKEN["Issue pinToken (16 random bytes)"]
        AU_SIGN["Use pinToken to authorize<br/>makeCredential / getAssertion"]
    end

    client <-->|"ECDH public keys exchanged"| transport
    transport <-->|"Encrypted PIN + commands"| authenticator

    style transport fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px
```

---

## The ECDH Key Agreement

Before any PIN can be sent, the client and authenticator must establish a **shared secret** over the untrusted transport. This uses Elliptic Curve Diffie-Hellman (ECDH):

```mermaid
sequenceDiagram
    participant Client as Client (Browser)
    participant Auth as Authenticator (Phone)

    Note over Client,Auth: Both generate ephemeral P-256 key pairs

    Client->>Client: Generate key pair:<br/>clientPriv (secret), clientPub (shared)
    Auth->>Auth: Generate key pair:<br/>authPriv (secret), authPub (shared)

    Client->>Auth: getKeyAgreement command
    Auth-->>Client: authPub (authenticator's public key)

    Note over Client,Auth: Both compute the SAME shared secret independently

    Client->>Client: sharedSecret = SHA-256(<br/>  ECDH(clientPriv, authPub).x<br/>)<br/><br/>Only the x-coordinate is used
    Auth->>Auth: sharedSecret = SHA-256(<br/>  ECDH(authPriv, clientPub).x<br/>)<br/><br/>Same result due to ECDH math

    Note over Client,Auth: Both now have identical 32-byte sharedSecret<br/>An eavesdropper who captured authPub and clientPub<br/>CANNOT compute the shared secret (ECDH problem)
```

| Parameter | Value |
|---|---|
| Curve | NIST P-256 (secp256r1) |
| Key type | Ephemeral (new key pair each session) |
| Shared secret derivation | `SHA-256(ECDH(a, bG).x)` — hash of x-coordinate only |
| Shared secret size | 32 bytes |
| Encryption algorithm | AES-256-CBC (PIN protocol v1) |
| HMAC algorithm | HMAC-SHA-256 |

**Why ephemeral keys?** A new key pair is generated for each session. Even if an attacker records all traffic, they can't decrypt past sessions (forward secrecy). If a PIN verification fails, the authenticator generates a **new** key pair, invalidating the old shared secret.

---

## All Subcommands

The clientPIN command (`0x06`) has multiple subcommands:

| Sub-command | Code | Purpose | When used |
|---|---|---|---|
| **getPinRetries** | `0x01` | Get remaining PIN attempts | Before prompting user for PIN |
| **getKeyAgreement** | `0x02` | Get authenticator's ECDH public key | Before any PIN operation |
| **setPIN** | `0x03` | Set PIN for first time | First-time setup |
| **changePIN** | `0x04` | Change existing PIN | User wants new PIN |
| **getPinToken** | `0x05` | Get pinToken after proving PIN knowledge | Before every makeCredential/getAssertion |
| **getPinUvAuthTokenUsingPinWithPermissions** | `0x09` | Get scoped pinToken (CTAP 2.1) | Modern replacement for `0x05` |
| **getUvRetries** | `0x07` | Get remaining UV (biometric) attempts | For built-in biometric |
| **getPinUvAuthTokenUsingUvWithPermissions** | `0x06` | Get token via built-in biometric | Biometric alternative to PIN |

---

## Subcommand Flows in Detail

### getPinRetries (0x01) — Check Before Prompting

```mermaid
sequenceDiagram
    participant Client
    participant Auth as Authenticator

    Client->>Auth: clientPIN(subCommand=0x01)
    Auth-->>Client: {retries: 8}

    Note over Client: 8 = full retries<br/>0 = PIN is blocked<br/>Show appropriate UI to user
```

No authentication needed. Returns how many attempts remain. Starts at 8, decrements on each failed attempt.

### getKeyAgreement (0x02) — Establish Encrypted Channel

```mermaid
sequenceDiagram
    participant Client
    participant Auth as Authenticator

    Client->>Auth: clientPIN(subCommand=0x02)
    Auth->>Auth: Generate ephemeral P-256 key pair
    Auth-->>Client: {keyAgreement: {<br/>  kty: 2 (EC),<br/>  crv: 1 (P-256),<br/>  x: <32 bytes>,<br/>  y: <32 bytes><br/>}}

    Client->>Client: Store authPub for ECDH
```

Returns the authenticator's ephemeral public key in COSE format. Client uses this with its own private key to compute the shared secret.

### setPIN (0x03) — First-Time PIN Setup

```mermaid
sequenceDiagram
    participant User
    participant Client as Client (Browser)
    participant Auth as Authenticator

    User->>Client: "My new PIN is 1234"

    Client->>Auth: getKeyAgreement → authPub
    Client->>Client: Generate own key pair (clientPriv, clientPub)
    Client->>Client: sharedSecret = SHA-256(ECDH(clientPriv, authPub).x)

    Note over Client: Encrypt the new PIN

    Client->>Client: paddedPin = utf8("1234") + zeros to 64 bytes
    Client->>Client: newPinEnc = AES-256-CBC(sharedSecret, paddedPin)
    Client->>Client: pinAuth = HMAC-SHA-256(sharedSecret, newPinEnc)[0:16]

    Client->>Auth: clientPIN(subCommand=0x03,<br/>  keyAgreement=clientPub,<br/>  newPinEnc=<encrypted PIN>,<br/>  pinAuth=<16-byte HMAC>)

    Note over Auth: Authenticator verifies and stores

    Auth->>Auth: sharedSecret = SHA-256(ECDH(authPriv, clientPub).x)
    Auth->>Auth: Verify: HMAC(sharedSecret, newPinEnc)[0:16] == pinAuth?
    Auth->>Auth: Decrypt: paddedPin = AES-256-CBC-decrypt(sharedSecret, newPinEnc)
    Auth->>Auth: Remove padding → "1234"
    Auth->>Auth: Validate: length ≥ 4 characters
    Auth->>Auth: Store: SHA-256("1234")[0:16] (first 16 bytes of hash)
    Auth->>Auth: Set retries = 8
    Auth->>Auth: Generate new random pinToken (16 bytes)

    Auth-->>Client: Success
```

**What's stored on the authenticator:** NOT the raw PIN. Only the **first 16 bytes of SHA-256(PIN)**. This is enough for verification but can't be reversed to the original PIN.

### changePIN (0x04) — Update Existing PIN

```mermaid
sequenceDiagram
    participant User
    participant Client as Client (Browser)
    participant Auth as Authenticator

    User->>Client: "Old PIN: 1234, New PIN: 5678"

    Client->>Auth: getKeyAgreement → authPub
    Client->>Client: sharedSecret = SHA-256(ECDH(...).x)

    Note over Client: Encrypt both old hash and new PIN

    Client->>Client: pinHashEnc = AES-CBC(sharedSecret,<br/>  SHA-256("1234")[0:16])
    Client->>Client: newPinEnc = AES-CBC(sharedSecret,<br/>  pad(utf8("5678")))
    Client->>Client: pinAuth = HMAC(sharedSecret,<br/>  newPinEnc || pinHashEnc)[0:16]

    Client->>Auth: clientPIN(subCommand=0x04,<br/>  keyAgreement, pinHashEnc,<br/>  newPinEnc, pinAuth)

    Auth->>Auth: Verify pinAuth HMAC
    Auth->>Auth: Decrypt pinHashEnc → old PIN hash
    Auth->>Auth: Compare against stored hash

    alt Old PIN matches
        Auth->>Auth: Decrypt newPinEnc → new PIN
        Auth->>Auth: Store SHA-256("5678")[0:16]
        Auth->>Auth: Reset retries = 8
        Auth->>Auth: Generate new pinToken
        Auth-->>Client: Success
    else Old PIN doesn't match
        Auth->>Auth: Decrement retries
        Auth-->>Client: PIN_INVALID or PIN_BLOCKED
    end
```

### getPinToken (0x05) — The Critical Subcommand

This is used **before every makeCredential/getAssertion** to prove the user knows the PIN.

```mermaid
sequenceDiagram
    participant User
    participant Client as Client (Browser)
    participant Auth as Authenticator

    User->>Client: "PIN is 1234"

    Client->>Auth: getKeyAgreement → authPub
    Client->>Client: sharedSecret = SHA-256(ECDH(...).x)

    Note over Client: Send encrypted PIN hash

    Client->>Client: pinHashEnc = AES-CBC(sharedSecret,<br/>  SHA-256("1234")[0:16])

    Client->>Auth: clientPIN(subCommand=0x05,<br/>  keyAgreement=clientPub,<br/>  pinHashEnc=<encrypted hash>)

    Auth->>Auth: sharedSecret = SHA-256(ECDH(...).x)
    Auth->>Auth: Decrypt pinHashEnc → PIN hash
    Auth->>Auth: Compare against stored hash

    alt PIN matches
        Auth->>Auth: Reset retries = 8
        Auth->>Auth: Get stored pinToken (16 random bytes)
        Auth->>Auth: pinTokenEnc = AES-CBC(sharedSecret, pinToken)
        Auth-->>Client: {pinToken: <encrypted pinToken>}

        Client->>Client: pinToken = AES-CBC-decrypt(sharedSecret, pinTokenEnc)
        Note over Client: Client now has pinToken<br/>Use it to compute pinAuth for<br/>subsequent operations
    else PIN doesn't match
        Auth->>Auth: Decrement retries
        Auth->>Auth: Regenerate ECDH key pair<br/>(invalidates old sharedSecret)

        alt retries == 0
            Auth-->>Client: PIN_BLOCKED
        else 3 consecutive failures
            Auth-->>Client: PIN_AUTH_BLOCKED<br/>(requires power cycle)
        else
            Auth-->>Client: PIN_INVALID
        end
    end
```

---

## How pinToken Gates Signing Operations

After obtaining `pinToken`, the client uses it to authenticate every subsequent `makeCredential` or `getAssertion` request:

```mermaid
sequenceDiagram
    participant Client as Client (has pinToken)
    participant Auth as Authenticator

    Note over Client: Client already has pinToken from getPinToken

    Note over Client,Auth: makeCredential or getAssertion

    Client->>Client: Compute:<br/>pinAuth = HMAC-SHA-256(pinToken, clientDataHash)[0:16]

    Client->>Auth: makeCredential(<br/>  ...,<br/>  pinAuth=<16 bytes>,<br/>  pinProtocol=1<br/>)

    Auth->>Auth: Compute:<br/>expected = HMAC-SHA-256(storedPinToken, clientDataHash)[0:16]
    Auth->>Auth: Compare: pinAuth == expected?

    alt Match
        Auth->>Auth: Reset retries = 8
        Auth->>Auth: Set UV flag = true in response
        Auth->>Auth: Proceed with operation<br/>(generate key / sign assertion)
        Auth-->>Client: Success (with UV=true)
    else No match
        Auth->>Auth: Decrement retries
        Auth-->>Client: PIN_AUTH_INVALID
    end
```

**Key insight:** The actual PIN is never sent during `makeCredential`/`getAssertion`. Only the `pinAuth` (an HMAC) is sent. The authenticator verifies it using the stored `pinToken` — proving the client previously proved PIN knowledge via `getPinToken`.

---

## Retry and Lockout Mechanism

```mermaid
graph TD
    START["8 retries available"]
    START --> ATTEMPT["User enters PIN"]

    ATTEMPT -->|"Correct"| RESET["Reset retries = 8<br/>Reset consecutive counter = 0<br/>Issue pinToken"]
    ATTEMPT -->|"Wrong"| DEC["Decrement retries<br/>Increment consecutive counter"]

    DEC --> CHECK_CON{"3 consecutive<br/>failures?"}
    CHECK_CON -->|"Yes"| SOFT_LOCK["PIN_AUTH_BLOCKED<br/><br/>Requires power cycle<br/>(unplug and replug,<br/>or reboot phone)<br/>Retries still available"]
    CHECK_CON -->|"No"| CHECK_TOTAL{"retries == 0?"}

    CHECK_TOTAL -->|"Yes"| HARD_LOCK["PIN_BLOCKED<br/><br/>Authenticator permanently locked<br/>Must factory reset<br/>All credentials lost"]
    CHECK_TOTAL -->|"No"| ATTEMPT

    SOFT_LOCK -->|"Power cycle"| ATTEMPT
    RESET --> DONE["Operation proceeds"]

    style HARD_LOCK fill:#ffcdd2,stroke:#c62828,stroke-width:2px
    style SOFT_LOCK fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    style RESET fill:#c8e6c9,stroke:#2e7d32
```

| Event | Effect |
|---|---|
| Correct PIN | Retries reset to 8, consecutive counter reset to 0 |
| Wrong PIN | Retries decremented, consecutive counter incremented |
| 3 consecutive wrong | `PIN_AUTH_BLOCKED` — requires power cycle, retries preserved |
| 0 retries remaining | `PIN_BLOCKED` — authenticator permanently locked, factory reset needed |
| ECDH key pair | Regenerated after every failed attempt (prevents replay of old shared secret) |

---

## PIN Protocol Versions

### Protocol v1 (CTAP 2.0)

| Operation | Algorithm |
|---|---|
| Shared secret | `SHA-256(ECDH(a, bG).x)` |
| PIN encryption | `AES-256-CBC(sharedSecret, paddedPIN)` — IV = 0 (all zeros) |
| pinAuth | `HMAC-SHA-256(pinToken, clientDataHash)[0:16]` — first 16 bytes |
| PIN hash storage | `SHA-256(PIN)[0:16]` — first 16 bytes |

**Weakness of v1:** AES-CBC with zero IV means identical PINs encrypted with the same shared secret produce identical ciphertext. The shared secret changes per session, so this is mostly theoretical.

### Protocol v2 (CTAP 2.1)

| Operation | Algorithm |
|---|---|
| Shared secret | `HKDF-SHA-256(ECDH(a, bG).x)` — proper key derivation |
| PIN encryption | `AES-256-CBC(key, paddedPIN)` — random IV prepended |
| pinAuth | `HMAC-SHA-256(pinToken, message)[0:32]` — full 32 bytes |
| Permissions | Scoped to specific operations (`mc`, `ga`, `cm`, etc.) |
| RP binding | pinToken can be bound to specific RP ID |

**v2 improvements:**
- Proper HKDF instead of raw SHA-256 for key derivation
- Random IV for AES-CBC (not all zeros)
- Full 32-byte HMAC (not truncated to 16)
- Permission scoping: pinToken can be limited to specific operations
- RP ID binding: pinToken only valid for a specific relying party

---

## Complete Flow: Login Using ClientPIN

```mermaid
sequenceDiagram
    participant User
    participant Browser as Browser (Client)
    participant Auth as Phone (Authenticator)
    participant TEE as TEE / Keystore
    participant Server as Website (RP)

    Note over User,Server: User clicks "Sign in" on website

    Server->>Browser: navigator.credentials.get({<br/>  challenge, rpId, allowCredentials,<br/>  userVerification: "required"<br/>})

    Browser->>Auth: CTAP2: getInfo
    Auth-->>Browser: {options: {clientPin: true},<br/>  pinUvAuthProtocols: [1]}

    Note over Browser: Authenticator supports clientPIN

    Browser->>Auth: clientPIN(subCommand=0x02)<br/>getKeyAgreement
    Auth-->>Browser: {keyAgreement: authPub}

    Browser->>Browser: Generate ephemeral key pair
    Browser->>Browser: sharedSecret = SHA-256(ECDH.x)

    Browser->>User: "Enter your PIN"
    User->>Browser: "1234"

    Browser->>Browser: pinHashEnc = AES-CBC(sharedSecret,<br/>  SHA-256("1234")[0:16])

    Browser->>Auth: clientPIN(subCommand=0x05,<br/>  keyAgreement=browserPub,<br/>  pinHashEnc)

    Auth->>Auth: Derive same sharedSecret
    Auth->>Auth: Decrypt → verify PIN hash
    Auth-->>Browser: {pinToken: encrypted(pinToken)}

    Browser->>Browser: Decrypt pinToken
    Browser->>Browser: pinAuth = HMAC(pinToken, clientDataHash)[0:16]

    Note over Browser,Auth: Now use pinAuth to authorize getAssertion

    Browser->>Auth: getAssertion(<br/>  rpId, clientDataHash,<br/>  allowCredentials,<br/>  pinAuth, pinProtocol=1<br/>)

    Auth->>Auth: Verify pinAuth matches<br/>HMAC(storedPinToken, clientDataHash)
    Auth->>Auth: Find credential for rpId

    Auth->>TEE: Signature.initSign(privateKey)
    TEE-->>Auth: Signature ready

    Auth->>Auth: authenticatorData = rpIdHash + flags(UV=1) + counter
    Auth->>Auth: toSign = authenticatorData + clientDataHash

    Auth->>TEE: signature.sign(toSign)
    TEE-->>Auth: ECDSA signature

    Auth-->>Browser: {credentialId, authenticatorData,<br/>  signature, userHandle}

    Browser->>Server: AuthenticatorAssertionResponse
    Server->>Server: Verify signature with stored public key
    Server->>Server: Check UV flag = 1 (PIN verified)
    Server-->>User: Login approved ✓
```

---

## Security Properties

### What ClientPIN Protects Against

| Threat | Protected? | How |
|---|---|---|
| PIN sniffing on transport (USB/NFC/BLE) | **Yes** | ECDH encryption — PIN never in plaintext |
| Replay of old PIN exchange | **Yes** | Ephemeral ECDH keys — new shared secret each session |
| Brute force (remote) | **Yes** | 8 attempts max, then permanently blocked |
| Brute force (offline, extracted hash) | **Partially** | SHA-256 is fast to brute-force, but hash is inside TEE |
| Stolen pinToken | **Mitigated** | pinToken refreshed on each PIN set/change, scoped to RP in v2 |
| Malware on client | **No** | If malware captures PIN keystrokes, it has everything |

### What ClientPIN Does NOT Protect Against

- **Keylogging on the client side:** If malware captures the PIN as the user types it, the malware can replay the entire flow
- **TEE compromise:** If the authenticator's TEE is exploited, the stored PIN hash and pinToken can be extracted
- **Social engineering:** User can be tricked into entering PIN on a phishing client

### ClientPIN vs Biometric vs Device Credential

| Aspect | ClientPIN | Biometric (CryptoObject) | Device Credential |
|---|---|---|---|
| Verified by | Authenticator's app code | TEE hardware | TEE Gatekeeper |
| Frida can bypass | **Yes** (hook `isPinMatch`) | **No** (TEE-bound) | **No** (TEE-bound) |
| Root can bypass | **Yes** (extract pinToken) | **No** (HMAC in TEE) | **No** (HMAC in TEE) |
| Brute force protection | Software counter (8 attempts) | **Hardware** rate limiting | **Hardware** rate limiting |
| Works without biometric hardware | **Yes** | No | **Yes** |
| FIDO2 spec compliance | **Yes** (CTAP2) | Not part of CTAP2 | Not part of CTAP2 |

---

## Sources

- [CTAP 2.1 Specification — FIDO Alliance](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html)
- [CTAP 2.0 Specification — FIDO Alliance](https://fidoalliance.org/specs/fido-v2.0-rd-20180702/fido-client-to-authenticator-protocol-v2.0-rd-20180702.html)
- [CTAP2.1 Migration Guide — PIN Protocol v2](https://github.com/WebauthnWorks/CTAP2.1-Migration-Guide/blob/main/Protocol/PinUvAuthnProtocol2.md)
- [Provable Security Analysis of FIDO2 — Barbosa et al. 2020](https://eprint.iacr.org/2020/756.pdf)
- [FIDO2, CTAP 2.1, and WebAuthn 2 — Bindel et al. 2022](https://eprint.iacr.org/2022/1029.pdf)
- [python-fido2 CTAP2 PIN documentation — Yubico](https://developers.yubico.com/python-fido2/API_Documentation/autoapi/fido2/ctap2/pin/index.html)
- [WIOsense/rauth-android — GitHub (implementation reference)](https://github.com/WIOsense/rauth-android)
