## ADDED Requirements

### Requirement: App generates attested P-256 key during enrollment
The app SHALL generate an EC P-256 key pair in Android Keystore with `setAttestationChallenge(serverChallenge)` where `serverChallenge` is the challenge received from the server's `/api/register/start` endpoint.

#### Scenario: Key generated with server challenge
- **WHEN** user taps "Register" and server returns a challenge
- **THEN** app generates P-256 key with `setAttestationChallenge(challenge)` and the key is hardware-backed (TEE or StrongBox)

### Requirement: App sends attestation certificate chain to server
The app SHALL call `KeyStore.getCertificateChain(alias)`, encode each certificate as Base64 DER, and send the array to the server's `/api/register/finish` endpoint.

#### Scenario: Certificate chain sent to server
- **WHEN** key is generated with attestation
- **THEN** app retrieves the certificate chain (3-5 certs) and sends all certificates to the server as Base64-encoded DER

### Requirement: App shows registration result
The app SHALL display the server's response after registration: success (with security level), or failure (with error reason).

#### Scenario: Successful registration displayed
- **WHEN** server accepts the attestation and returns success
- **THEN** app displays "Registered! Key verified as TEE-backed by server"

#### Scenario: Failed registration displayed
- **WHEN** server rejects the attestation (e.g., software-backed key)
- **THEN** app displays the error message from the server
