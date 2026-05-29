# How a Phone Becomes a Security Key: FIDO2 Roaming Authenticators Explained

## What Is a Roaming Authenticator?

A **roaming authenticator** is a security device that can connect to **multiple client devices** — it "roams" between your laptop, desktop, tablet, etc. You know it as a YubiKey, but your **phone** can be one too.

```mermaid
graph LR
    subgraph roaming["Roaming Authenticators"]
        YK["YubiKey<br/><i>USB / NFC</i>"]
        PHONE["Your Android Phone<br/><i>NFC / BLE / Hybrid</i>"]
        TITAN["Google Titan Key<br/><i>USB / NFC / BLE</i>"]
    end

    subgraph clients["Client Devices (what you're logging into)"]
        LAPTOP["Laptop Browser<br/><i>Chrome on Windows</i>"]
        DESKTOP["Desktop Browser<br/><i>Firefox on Mac</i>"]
        TABLET["Tablet<br/><i>iPad Safari</i>"]
    end

    YK <-->|"USB / NFC"| LAPTOP
    PHONE <-->|"NFC / BLE / Hybrid"| LAPTOP
    PHONE <-->|"NFC / BLE / Hybrid"| DESKTOP
    TITAN <-->|"USB / NFC"| DESKTOP

    style PHONE fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
```

The contrast is a **platform authenticator** — built into the device you're logging in from (like Face ID on a Mac, or fingerprint on the same Android phone running the browser). A roaming authenticator is **external** — the keys live on a separate device.

---

## The Protocol Stack

```mermaid
graph TD
    subgraph stack["FIDO2 Protocol Stack"]
        WA["WebAuthn API<br/><i>Browser JavaScript API</i><br/>navigator.credentials.create() / .get()"]
        CTAP["CTAP2 Protocol<br/><i>Client to Authenticator Protocol</i><br/>Binary commands (CBOR-encoded)"]
        TRANSPORT["Transport Layer<br/><i>How bytes get to the authenticator</i>"]
    end

    subgraph transports["Available Transports"]
        USB["USB HID<br/><i>YubiKey plugged in</i>"]
        NFC_T["NFC<br/><i>Tap phone to laptop</i>"]
        BLE["BLE / Hybrid (caBLE)<br/><i>Phone nearby, cloud-assisted</i>"]
    end

    WA -->|"Browser passes request"| CTAP
    CTAP -->|"CBOR-encoded commands"| TRANSPORT
    TRANSPORT --> USB
    TRANSPORT --> NFC_T
    TRANSPORT --> BLE

    style WA fill:#e3f2fd,stroke:#1565c0
    style CTAP fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    style TRANSPORT fill:#e8f5e9,stroke:#2e7d32
```

**WebAuthn** is the browser-side JavaScript API (what the website calls).
**CTAP2** is the wire protocol between the browser/OS and the authenticator (what your phone speaks).
**Transport** is how CTAP2 messages physically travel (USB, NFC, or BLE).

---

## Transport 1: NFC (Tap to Authenticate)

The simplest transport. Phone acts as an **NFC smartcard** using Android's Host Card Emulation (HCE).

### How It Works

```mermaid
sequenceDiagram
    participant Website as Website (example.com)
    participant Browser as Laptop Browser
    participant OS as Laptop OS
    participant NFC_R as Laptop NFC Reader
    participant NFC_P as Phone NFC Antenna
    participant HCE as Android HCE Service
    participant Auth as rauth-android Library
    participant KS as Keystore (TEE)

    Website->>Browser: navigator.credentials.get({challenge})
    Browser->>OS: "I need a security key"
    OS->>OS: Show "Tap your security key" dialog

    Note over NFC_R,NFC_P: User holds phone against laptop

    NFC_R->>NFC_P: ISO 7816 SELECT command<br/>(FIDO2 AID: A0000006472F0001)
    NFC_P->>HCE: Incoming APDU
    HCE->>Auth: Route to TransactionManager

    Note over NFC_R,Auth: CTAP2 over NFC uses ISO 7816 APDU framing

    NFC_R->>NFC_P: APDU: CTAP2 getAssertion<br/>{rpId, clientDataHash, allowList}
    NFC_P->>HCE: Forward APDU
    HCE->>Auth: Parse CBOR → GetAssertionOptions

    Auth->>Auth: Find matching credential for rpId
    Auth->>Auth: Show BiometricPrompt on phone
    Note over Auth: User scans fingerprint ON THE PHONE

    Auth->>KS: Sign(authenticatorData || clientDataHash)
    KS-->>Auth: ECDSA signature

    Auth->>HCE: CBOR response: {credentialId, authData, signature}
    HCE->>NFC_P: Response APDU (status: 9000 = success)
    NFC_P->>NFC_R: Response bytes

    NFC_R->>OS: Got assertion
    OS->>Browser: AuthenticatorAssertionResponse
    Browser->>Website: Signed assertion
    Website->>Website: Verify signature → login approved
```

### NFC Message Format

NFC uses **ISO 7816 APDU** (Application Protocol Data Unit) framing — the same smartcard protocol used by credit cards and passports:

```
Command APDU (laptop → phone):
┌─────┬─────┬─────┬─────┬──────┬──────────────────────┬─────┐
│ CLA │ INS │ P1  │ P2  │ Lc   │ Data (CBOR payload)  │ Le  │
│ 1B  │ 1B  │ 1B  │ 1B  │ 1-3B │ variable             │ 0-3B│
└─────┴─────┴─────┴─────┴──────┴──────────────────────┴─────┘

INS = 0x10 → CTAP2 message (CBOR inside)
INS = 0x02 → U2F message (legacy FIDO U2F)

Response APDU (phone → laptop):
┌──────────────────────┬─────┬─────┐
│ Data (CBOR response) │ SW1 │ SW2 │
│ variable             │ 1B  │ 1B  │
└──────────────────────┴─────┴─────┘

SW1=90, SW2=00 → Success
SW1=69, SW2=85 → Conditions not satisfied (user denied)
```

The WIOsense rauth library handles this in `TransactionManager.java` — it receives raw APDUs, extracts the CBOR-encoded CTAP2 command, routes it to `Authenticator.makeCredential()` or `Authenticator.getAssertion()`, and wraps the CBOR response back into an APDU.

### NFC Limitations

- **Range:** ~4 cm — phone must physically touch the laptop
- **Speed:** Slow for large payloads (NFC bandwidth is limited)
- **Framing:** Large CTAP2 messages must be split into chained APDUs
- **Always-on:** No pairing needed, works instantly
- **One-shot:** Tap, authenticate, done. No persistent connection.

---

## Transport 2: BLE / Hybrid (caBLE)

The more complex transport. Used when you authenticate on a laptop by approving on your phone **nearby but not touching**.

### The Problem BLE Solves

NFC requires physical contact. USB requires a cable. What if you want to log in on a laptop and approve on your phone sitting on the desk? That's what BLE is for — but raw Bluetooth pairing is unreliable, so Google created **caBLE (Cloud-Assisted BLE)**, now standardized as the **hybrid transport** in CTAP 2.2.

### How Hybrid/caBLE Works

BLE is used **only for proximity discovery** — to prove your phone is physically nearby. The actual CTAP2 data travels over an **encrypted cloud tunnel** (via Google's servers), not over BLE itself.

```mermaid
sequenceDiagram
    participant Website as Website
    participant Browser as Laptop Browser
    participant Cloud as Google Cloud Tunnel<br/>(encrypted relay)
    participant BLE as BLE Radio
    participant Phone as Your Phone

    Website->>Browser: navigator.credentials.get()
    Browser->>Browser: Generate ephemeral key pair
    Browser->>Browser: Show QR code containing:<br/>• Browser's public key<br/>• Tunnel server URL<br/>• Random challenge

    Note over Browser,Phone: First-time pairing (QR code scan)

    Phone->>Phone: User scans QR code with camera
    Phone->>Phone: Extract browser's public key + tunnel URL
    Phone->>Phone: Generate own ephemeral key pair
    Phone->>Phone: ECDH → shared secret with browser

    Note over Browser,Phone: Subsequent uses (no QR needed)

    Browser->>BLE: BLE advertisement:<br/>encrypted hint (derived from paired state)
    BLE->>Phone: Phone detects advertisement
    Phone->>Phone: Decrypt hint → recognize paired browser

    Note over Browser,Phone: Establish encrypted tunnel

    Phone->>Cloud: Connect to tunnel server<br/>(WebSocket over HTTPS)
    Browser->>Cloud: Connect to tunnel server<br/>(WebSocket over HTTPS)
    Cloud->>Cloud: Relay encrypted messages<br/>(cloud cannot read content —<br/>end-to-end encrypted with shared secret)

    Note over Browser,Phone: CTAP2 over the tunnel

    Browser->>Cloud: Encrypted CTAP2 getAssertion command
    Cloud->>Phone: Relay (encrypted, opaque to cloud)
    Phone->>Phone: Decrypt → parse CTAP2 command
    Phone->>Phone: Show notification: "Sign in to example.com?"
    Phone->>Phone: User scans fingerprint
    Phone->>Phone: Sign with Keystore key
    Phone->>Cloud: Encrypted CTAP2 response (assertion)
    Cloud->>Browser: Relay
    Browser->>Browser: Decrypt → extract assertion
    Browser->>Website: Signed assertion
    Website->>Website: Verify → login approved
```

### What Goes Where

| Data | Travels over | Why |
|---|---|---|
| QR code content (initial pairing) | Displayed on screen, scanned by camera | One-time setup, no network needed |
| BLE advertisement (subsequent uses) | Bluetooth Low Energy radio (~10m range) | Proves phone is physically nearby |
| CTAP2 commands and responses | **Encrypted cloud tunnel** (Google's relay) | Reliable, fast, handles large payloads |
| Biometric verification | Happens locally on phone (TEE) | Never leaves the phone |

**Key insight:** BLE is NOT used to transport the actual authentication data. It's only a **proximity signal** — proof that your phone is physically near the laptop. The actual crypto payload goes through an end-to-end encrypted tunnel that the cloud relay cannot read.

### Why Not Just Use BLE Directly?

1. **Bandwidth:** BLE is slow — CTAP2 responses can be hundreds of bytes, BLE maxes at ~20 bytes per characteristic
2. **Reliability:** BLE connections are flaky, drop frequently, have pairing issues
3. **Security:** Raw BLE pairing has known MITM vulnerabilities
4. **UX:** BLE pairing requires explicit user action on both devices; caBLE is seamless after first QR scan

---

## Transport 3: USB HID (Traditional Security Key)

Not relevant for phone-as-authenticator (phones don't normally act as USB HID devices), but included for completeness:

```
USB HID framing uses 64-byte reports.
Laptop sends CTAPHID_MSG containing CBOR.
Security key responds with CTAPHID_MSG containing CBOR response.
Standard for YubiKey, Titan, SoloKeys, etc.
```

---

## What WIOsense rauth Actually Implements

The rauth library implements the **authenticator side** — it receives CTAP2 commands (via NFC APDUs or HID frames) and produces responses.

```mermaid
graph TD
    subgraph external["External Device (Laptop)"]
        BROWSER["Browser with WebAuthn"]
    end

    subgraph transport["Transport Layer"]
        NFC_APDU["NFC: ISO 7816 APDUs"]
        HID["USB HID: 64-byte reports"]
    end

    subgraph rauth["rauth-android Library"]
        TM["TransactionManager.java<br/><i>Receives raw bytes</i><br/><i>Detects transport type</i><br/><i>Extracts CBOR payload</i>"]

        CTAP2["CTAP2 Message Parser<br/>(Messages.java)<br/><i>Decodes CBOR commands</i>"]

        AUTH["Authenticator.java<br/><i>makeCredential()</i><br/><i>getAssertion()</i><br/><i>getPinResult()</i><br/><i>getInfo()</i>"]

        U2F["U2F Legacy Handler<br/>(RawMessages.java)<br/><i>FIDO U2F backward compat</i>"]
    end

    subgraph local["On-Device Security"]
        BIO["BiometricPrompt<br/><i>User verification</i>"]
        KS_TEE["Keystore (TEE)<br/><i>P-256 signing key</i>"]
        PIN["ClientPinLocker<br/><i>CTAP2 clientPIN</i>"]
    end

    BROWSER <--> NFC_APDU
    BROWSER <--> HID
    NFC_APDU --> TM
    HID --> TM
    TM -->|"CTAP2 CBOR"| CTAP2
    TM -->|"U2F raw"| U2F
    CTAP2 --> AUTH
    U2F --> AUTH
    AUTH --> BIO
    AUTH --> KS_TEE
    AUTH --> PIN

    style TM fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    style AUTH fill:#fff3e0,stroke:#ef6c00,stroke-width:2px
    style KS_TEE fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

### TransactionManager: The Transport Router

`TransactionManager.java` is the entry point. It receives raw bytes from whichever transport layer is active (NFC HCE service, or USB HID bridge) and:

1. **Detects protocol:** Is this a CTAP2 command (CBOR) or a legacy U2F command (raw bytes)?
2. **Handles HID framing:** For USB/BLE HID, reassembles multi-report messages (64-byte chunks) into complete CTAP2 commands
3. **Routes to authenticator:** Passes decoded options to `Authenticator.makeCredential()`, `getAssertion()`, `getPinResult()`, or `getInfo()`
4. **Packages response:** Wraps CBOR response back into APDUs or HID reports for transmission

---

## Complete End-to-End Example: Logging into a Website

### Scenario: User logs into `example.com` on laptop, authenticates on phone via NFC

```mermaid
sequenceDiagram
    participant User
    participant Website as example.com
    participant Browser as Laptop Chrome
    participant Phone as Android Phone<br/>(rauth-android)
    participant TEE as Phone TEE

    Note over User,TEE: STEP 1: Website initiates login

    User->>Website: Click "Sign in"
    Website->>Website: Generate random challenge (32 bytes)
    Website->>Browser: navigator.credentials.get({<br/>  publicKey: {<br/>    challenge: <32 bytes>,<br/>    rpId: "example.com",<br/>    allowCredentials: [{id: <credId>}],<br/>    userVerification: "required"<br/>  }<br/>})

    Note over User,TEE: STEP 2: Browser looks for authenticator

    Browser->>Browser: Show "Use your security key" dialog
    Browser->>Browser: Listen for NFC tap / BLE / USB

    Note over User,TEE: STEP 3: User taps phone to laptop

    User->>Phone: Hold phone against laptop NFC reader

    Note over User,TEE: STEP 4: CTAP2 over NFC

    Browser->>Phone: APDU: authenticatorGetAssertion<br/>{rpId: "example.com",<br/> clientDataHash: SHA256(clientData),<br/> allowList: [{id: <credId>}]}

    Phone->>Phone: TransactionManager receives APDU
    Phone->>Phone: Parse CBOR → GetAssertionOptions
    Phone->>Phone: Look up credential by rpId

    Note over User,TEE: STEP 5: User verification on phone

    Phone->>User: Show BiometricPrompt:<br/>"Sign in to example.com"
    User->>Phone: Scan fingerprint
    Phone->>TEE: Verify fingerprint in TEE
    TEE-->>Phone: Auth token (HardwareAuthToken)

    Note over User,TEE: STEP 6: Sign on phone

    Phone->>TEE: Signature.initSign(privateKey)
    TEE-->>Phone: Signature ready (auth token valid)
    Phone->>Phone: authenticatorData = SHA256("example.com")<br/>  + flags(UP=1, UV=1) + counter(4 bytes)
    Phone->>Phone: toSign = authenticatorData + clientDataHash
    Phone->>TEE: signature.update(toSign); signature.sign()
    TEE-->>Phone: ECDSA signature (DER encoded)

    Note over User,TEE: STEP 7: Response back via NFC

    Phone->>Browser: Response APDU:<br/>{credentialId, authenticatorData,<br/> signature, userHandle}

    Note over User,TEE: STEP 8: Browser forwards to website

    Browser->>Website: AuthenticatorAssertionResponse
    Website->>Website: Look up public key for credentialId
    Website->>Website: Verify ECDSA signature over<br/>(authenticatorData + clientDataHash)
    Website->>Website: Check counter > last seen counter
    Website->>Website: Check UV flag = 1 (user verified)
    Website->>Website: All checks pass → LOGIN APPROVED
    Website->>User: "Welcome back!"
```

---

## How This Differs from a YubiKey

| Aspect | YubiKey | Phone (rauth-android) |
|---|---|---|
| Key storage | Dedicated secure element (on the YubiKey chip) | Android Keystore (TEE or StrongBox) |
| User verification | Touch the metal contact (presence only) or PIN | Fingerprint / face / device PIN / CTAP2 clientPIN |
| Transport | USB HID + NFC | NFC + BLE/Hybrid |
| Battery | None (powered by USB/NFC) | Phone battery |
| Cost | $25-$75 per key | Free (use existing phone) |
| Attestation | Yubico-signed certificate (device-specific) | Android Key Attestation (Google-signed) or "none" |
| Cross-device | Works with any computer with USB/NFC | Works with any device with NFC/BLE |
| Lost device | Buy a new YubiKey, re-register | Factory reset phone, re-register |
| Side-channel resistance | Dedicated secure element (very high) | TEE (high) or StrongBox (very high) |

---

## Why Would You Use This Instead of a Platform Authenticator?

**Platform authenticator** = keys stored on the same device you're logging in from (e.g., fingerprint on your Android phone to log into a site in Chrome on that same phone).

**Roaming authenticator** = keys stored on a **different** device (e.g., keys on your phone, logging in on your laptop).

```mermaid
graph TD
    subgraph platform["Platform Authenticator"]
        P1["User on laptop"]
        P2["Keys also on laptop"]
        P3["Biometric on laptop"]
        P1 --- P2 --- P3
        P4["If laptop is compromised:<br/>keys are compromised too"]
    end

    subgraph roaming2["Roaming Authenticator (phone)"]
        R1["User on laptop"]
        R2["Keys on PHONE (separate device)"]
        R3["Biometric on PHONE"]
        R1 --- R2 --- R3
        R4["If laptop is compromised:<br/>keys are safe on phone<br/>(separate TEE, separate OS)"]
    end

    style P4 fill:#ffcdd2,stroke:#c62828
    style R4 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px
```

The security advantage: even if the laptop has malware, the signing key is on the phone's TEE. The laptop never sees the private key — it only receives the signed assertion. Malware on the laptop can't extract the key or forge signatures.

---

## Sources

- [CTAP2 Specification — FIDO Alliance](https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html)
- [WIOsense/rauth-android — GitHub](https://github.com/WIOsense/rauth-android)
- [WebAuthn vs CTAP vs FIDO2: Key Differences — Corbado](https://www.corbado.com/blog/webauthn-vs-ctap-vs-fido2)
- [Smartphone as FIDO2 Roaming Authenticator via BLE — Chuni Lal Kukreja](https://medium.com/@chunilalkukreja/smartphone-as-a-fido2-roaming-authenticator-via-ble-8002d0209747)
- [What does caBLE have to do with passkeys — Good Sign-In](https://www.goodsignin.com/blog/what-does-cable-have-to-do-with-passkeys)
- [Chrome caBLE v2 preview — Matt Miller](https://blog.millerti.me/2021/06/18/previewing-chromes-cable-v2-support-for-webauthn/)
- [FIDO2 API for Android — Google Developers](https://developers.google.com/identity/fido/android/native-apps)
