## ADDED Requirements

### Requirement: App requests authentication challenge from server
The app SHALL send `POST /api/auth/start` with the userId and receive a challenge from the server.

#### Scenario: Challenge received
- **WHEN** user taps "Authenticate"
- **THEN** app sends userId to server and receives a 32-byte challenge

### Requirement: App signs challenge with biometric-gated key
The app SHALL sign `authenticatorData || clientDataHash` using the Keystore P-256 key via `BiometricPrompt` with `CryptoObject` (per-use authentication). The user MUST scan fingerprint or enter device credential before the signature is produced.

#### Scenario: Signing with biometric
- **WHEN** app receives challenge from server
- **THEN** app shows BiometricPrompt, user authenticates, and the key signs the challenge inside the TEE

#### Scenario: User cancels biometric
- **WHEN** user cancels the BiometricPrompt
- **THEN** authentication is aborted and the app displays "Authentication cancelled"

### Requirement: App sends signed assertion to server
The app SHALL send `authenticatorData`, `signature`, and `clientDataHash` to the server's `/api/auth/finish` endpoint.

#### Scenario: Assertion sent and verified
- **WHEN** app sends the signed assertion to the server
- **THEN** server verifies the ECDSA signature against the stored public key and returns success or failure

### Requirement: App shows authentication result
The app SHALL display the server's authentication verdict.

#### Scenario: Successful authentication displayed
- **WHEN** server verifies the signature and returns success
- **THEN** app displays "Authenticated! Server verified your signature."

#### Scenario: Failed authentication displayed
- **WHEN** server rejects the signature
- **THEN** app displays the error message from the server
