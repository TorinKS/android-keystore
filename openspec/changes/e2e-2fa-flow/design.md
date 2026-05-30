## Context

We have a demo Android app with 7 screens demonstrating individual Keystore operations, tested on Moto G86 5G (Android 16). We need to add a working end-to-end 2FA flow: a Java backend server that verifies key attestation and ECDSA signatures, and an app screen that performs enrollment and authentication against it.

The backend must use existing open-source libraries — not reinvent crypto verification. The phone must connect to a localhost server during development.

## Goals / Non-Goals

**Goals:**
- Working Java backend that verifies Android Key attestation certificate chains
- Working enrollment flow: app generates attested P-256 key → server verifies chain → stores public key
- Working authentication flow: server sends challenge → app signs with biometric → server verifies
- Phone-to-localhost connectivity during development
- Code that demonstrates the concepts from our 14 docs

**Non-Goals:**
- Production-grade server (no database, no user management, no session handling)
- Push notifications (out of scope for this change)
- Key migration/recovery (separate concern)
- CTAP2/WebAuthn browser integration (we're building a direct app-to-server flow, not a browser-based passkey flow)
- Compliance certification

## Decisions

### 1. Server Framework: Spring Boot + webauthn4j

**Choice:** Spring Boot 3.x with [webauthn4j](https://github.com/webauthn4j/webauthn4j) for attestation/assertion verification.

**Why webauthn4j:**
- Only production-grade Java WebAuthn library
- Passes ALL mandatory FIDO Alliance conformance tests
- Supports `android-key` attestation format (exactly what `setAttestationChallenge()` produces)
- Minimal dependencies (SLF4J + Jackson only)
- Used by Spring Security 6.4+ internally
- Apache 2.0 license

**Alternatives considered:**
- Yubico java-webauthn-server: Less actively maintained, fewer attestation formats
- Custom X.509 chain verification: Reinventing the wheel, error-prone
- Node.js fido2-lib: Would require switching languages

### 2. Server API Design: REST, Not WebAuthn Browser API

**Choice:** Simple REST endpoints (`/register/start`, `/register/finish`, `/auth/start`, `/auth/finish`) with JSON payloads.

**Why:** We're building app-to-server, not browser-to-server. The WebAuthn JavaScript API (`navigator.credentials.create()`) is for browsers. Our Android app talks directly to the server via HTTP. We use webauthn4j's low-level verification classes, not its browser-oriented wrappers.

### 3. Network: `adb reverse` (Not ngrok)

**Choice:** `adb reverse tcp:8080 tcp:8080` — makes the phone's `localhost:8080` route to the laptop's `localhost:8080`.

**Why:**
- Zero setup (built into adb, already installed)
- No account, no signup, no external service
- Works offline (no internet needed between phone and laptop)
- Secure (traffic stays on USB cable, no cloud relay)
- One command: `adb reverse tcp:8080 tcp:8080`

**Alternatives considered:**
- ngrok: Requires account, exposes to internet, adds latency, overkill for dev
- Same-WiFi IP: Requires finding laptop IP, changes between networks, firewall issues
- Android emulator `10.0.2.2`: Only works on emulator, not real device

### 4. Storage: In-Memory HashMap

**Choice:** Store registered credentials in a `ConcurrentHashMap<String, StoredCredential>`. No database.

**Why:** This is a demo/proof-of-concept. Adding a database (H2, SQLite, PostgreSQL) adds complexity without proving anything about the Keystore/attestation flow. Server restart clears credentials — that's fine for demo purposes.

### 5. Android HTTP Client: OkHttp

**Choice:** OkHttp directly (no Retrofit).

**Why:** We're making 4 API calls total. Retrofit's annotation processing and interface generation is overkill. OkHttp is already a transitive dependency of many AndroidX libraries. Simple `Request.Builder()` calls are clearer for demo code.

### 6. Attestation Verification: Strict Mode

**Choice:** Server rejects registration if attestation doesn't show TEE or StrongBox security level.

**Why:** This is the whole point — proving that key attestation works. Accepting software-backed keys would defeat the purpose of the demo. The server will:
- Verify certificate chain roots to Google's attestation root
- Check `attestationSecurityLevel == TEE or StrongBox`
- Verify challenge matches the nonce it sent
- Check key algorithm is EC P-256

## Risks / Trade-offs

| Risk | Mitigation |
|---|---|
| webauthn4j may not directly support raw `getCertificateChain()` format (it expects WebAuthn `attestationObject` CBOR) | Use webauthn4j's lower-level `CertificateBaseAttestationStatementValidator` or parse the X.509 chain directly with `android/keyattestation` library as fallback |
| `adb reverse` only works over USB, not wireless debugging | Document this limitation; suggest ngrok as alternative for wireless |
| In-memory storage loses data on server restart | Acceptable for demo; document clearly |
| Phone needs to trust self-signed HTTPS cert (or use plain HTTP) | Use plain HTTP for demo (`http://localhost:8080`). Document that production needs HTTPS. |
| OkHttp calls on main thread will ANR | Use Kotlin coroutines (`withContext(Dispatchers.IO)`) for all network calls |
