## Why

The demo app demonstrates individual Keystore operations (generate, sign, verify, attest) but lacks a working end-to-end 2FA flow. Without a server backend, we can't prove the full lifecycle: server sends challenge → app signs with hardware-backed key → server verifies attestation + signature → login approved. This is the gap between "demo of primitives" and "proof that the architecture works."

## What Changes

- **New Java backend server** using Spring Boot + [webauthn4j](https://github.com/webauthn4j/webauthn4j) library for WebAuthn/attestation verification. Webauthn4j passes all mandatory FIDO Alliance tests and supports Android Key attestation format.
- **New 2FA screen in the demo app** that connects to the backend: enrollment (register key + send attestation chain) and authentication (receive challenge, sign, send assertion).
- **Network connectivity solution** for phone-to-localhost: the phone must reach the backend running on the dev laptop. Options: `adb reverse` (simplest, maps phone's localhost to laptop), ngrok, or same-WiFi IP.
- **Docs index** created (already done — `docs/README.md`).

## Capabilities

### New Capabilities
- `server-backend`: Java/Spring Boot backend with registration + authentication endpoints, webauthn4j attestation verification, in-memory credential storage, challenge management
- `e2e-enrollment-flow`: Complete enrollment flow — app generates attested key, sends cert chain to server, server verifies attestation + stores public key
- `e2e-auth-flow`: Complete authentication flow — server sends challenge, app signs with biometric + CryptoObject, server verifies ECDSA signature
- `network-connectivity`: Phone-to-localhost connectivity via `adb reverse tcp:8080 tcp:8080` (phone's localhost:8080 → laptop's localhost:8080)

### Modified Capabilities
- None — existing demo screens are not modified

## Impact

- **New module:** `server/` — Java Spring Boot application (separate from the Android app)
- **New screen:** `app/src/main/java/.../ui/screens/E2eFlowScreen.kt` — 2FA enrollment + auth UI
- **Dependencies:** webauthn4j (server-side), OkHttp or Retrofit (Android HTTP client)
- **Dev setup:** Requires `adb reverse` to connect phone to localhost backend
- **No breaking changes** to existing demo screens
