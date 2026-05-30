# Keystore 2FA Server

Java Spring Boot backend that verifies Android Key Attestation certificate chains and ECDSA signatures.

## Setup

### Prerequisites
- Java 17+ (Android Studio's JBR works: `C:\Program Files\Android\Android Studio\jbr`)
- Maven (or use the included `mvnw.cmd` wrapper)

### Run the server

```bash
cd server
mvnw.cmd spring-boot:run
```

Server starts on `http://localhost:8080`.

### Connect phone to server

```bash
adb reverse tcp:8080 tcp:8080
```

This makes the phone's `localhost:8080` route to the laptop's `localhost:8080` over USB. No ngrok needed.

### Test with the demo app

1. Start the server
2. Run `adb reverse tcp:8080 tcp:8080`
3. Open the demo app on the phone
4. Tap **E2E 2FA Flow**
5. Tap **Register** → generates attested key, server verifies cert chain
6. Tap **Authenticate** → signs challenge with biometric, server verifies signature

## API Endpoints

| Endpoint | Method | Request | Response |
|---|---|---|---|
| `/api/register/start` | POST | `{userId}` | `{sessionId, challenge}` |
| `/api/register/finish` | POST | `{sessionId, userId, certificateChain[]}` | `{status, securityLevel, chainLength}` |
| `/api/auth/start` | POST | `{userId}` | `{sessionId, challenge}` |
| `/api/auth/finish` | POST | `{sessionId, userId, authenticatorData, clientDataHash, signature}` | `{status: "authenticated"}` |

## What the server verifies

### During registration
1. Certificate chain signatures (each cert signs the next)
2. Root certificate matches Google's published attestation roots
3. Attestation extension present (OID 1.3.6.1.4.1.11129.2.1.17)
4. Security level is TEE or StrongBox (rejects software-backed keys)
5. Challenge matches the nonce the server sent

### During authentication
1. ECDSA signature over (authenticatorData || clientDataHash) is valid
2. Signature verifies against the public key stored during registration
