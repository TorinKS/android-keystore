## ADDED Requirements

### Requirement: Server exposes registration start endpoint
The server SHALL expose `POST /api/register/start` that generates a random 32-byte challenge, stores it in a session map keyed by a session ID, and returns `{sessionId, challenge}` as JSON.

#### Scenario: Registration start returns challenge
- **WHEN** client sends `POST /api/register/start` with `{userId: "user@example.com"}`
- **THEN** server returns HTTP 200 with `{sessionId: "<uuid>", challenge: "<base64-32-bytes>"}`

### Requirement: Server exposes registration finish endpoint
The server SHALL expose `POST /api/register/finish` that receives the attestation certificate chain (DER-encoded, base64), verifies the chain using webauthn4j or android/keyattestation library, checks attestation security level is TEE or StrongBox, verifies the challenge matches, extracts the public key from the leaf certificate, and stores it keyed by userId.

#### Scenario: Valid attestation accepted
- **WHEN** client sends `POST /api/register/finish` with `{sessionId, userId, certificateChain: ["<base64-cert1>", "<base64-cert2>", ...]}`
- **THEN** server verifies chain, extracts public key, stores credential, returns HTTP 200 with `{status: "registered", securityLevel: "TEE"}`

#### Scenario: Software-backed key rejected
- **WHEN** client sends attestation chain where attestation security level is SOFTWARE
- **THEN** server returns HTTP 400 with `{error: "Key is not hardware-backed"}`

#### Scenario: Challenge mismatch rejected
- **WHEN** client sends attestation chain where the attestation challenge does not match the stored session challenge
- **THEN** server returns HTTP 400 with `{error: "Challenge mismatch"}`

### Requirement: Server exposes authentication start endpoint
The server SHALL expose `POST /api/auth/start` that generates a random 32-byte challenge, stores it in a session map, and returns `{sessionId, challenge}` as JSON.

#### Scenario: Auth start returns challenge
- **WHEN** client sends `POST /api/auth/start` with `{userId: "user@example.com"}`
- **THEN** server returns HTTP 200 with `{sessionId: "<uuid>", challenge: "<base64-32-bytes>"}`

#### Scenario: Unknown user rejected
- **WHEN** client sends `POST /api/auth/start` with a userId that has no registered credential
- **THEN** server returns HTTP 404 with `{error: "User not registered"}`

### Requirement: Server exposes authentication finish endpoint
The server SHALL expose `POST /api/auth/finish` that receives authenticatorData + signature + clientDataHash, looks up the stored public key for the userId, verifies the ECDSA signature over `authenticatorData || clientDataHash` using the stored public key, and returns success/failure.

#### Scenario: Valid signature accepted
- **WHEN** client sends `POST /api/auth/finish` with `{sessionId, userId, authenticatorData: "<base64>", signature: "<base64>", clientDataHash: "<base64>"}`
- **THEN** server verifies ECDSA signature against stored public key, returns HTTP 200 with `{status: "authenticated"}`

#### Scenario: Invalid signature rejected
- **WHEN** client sends a signature that does not verify against the stored public key
- **THEN** server returns HTTP 401 with `{error: "Signature verification failed"}`

### Requirement: Server uses in-memory storage
The server SHALL store registered credentials in a `ConcurrentHashMap`. No database is required. Server restart clears all credentials.

#### Scenario: Credentials persist during server lifetime
- **WHEN** user registers and then authenticates within the same server session
- **THEN** authentication succeeds using the stored public key

### Requirement: Server logs verification details
The server SHALL log attestation verification results including: chain length, root certificate subject, security level, challenge match result, and signature verification result.

#### Scenario: Successful registration logs details
- **WHEN** a valid registration completes
- **THEN** server logs: "Registered user@example.com | chain: 5 certs | root: Key Attestation CA1 | level: TEE"
