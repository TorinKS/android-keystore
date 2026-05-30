## 1. Server Setup

- [x] 1.1 Create `server/` directory with Spring Boot project (Maven or Gradle, Java 17+)
- [x] 1.2 Add dependencies: spring-boot-starter-web, webauthn4j-core (or android/keyattestation), bouncy-castle for X.509 parsing
- [x] 1.3 Configure server to run on port 8080, enable CORS for all origins (dev mode)

## 2. Server Registration Endpoints

- [x] 2.1 Implement `POST /api/register/start` — generate 32-byte challenge, store in ConcurrentHashMap with session ID, return JSON
- [x] 2.2 Implement `POST /api/register/finish` — receive Base64 DER certificate chain, parse X.509 certs, verify chain signatures, verify root against Google's attestation root, check attestation extension for TEE/StrongBox security level, verify challenge matches, extract and store public key
- [x] 2.3 Download and cache Google's attestation root certificates from `https://android.googleapis.com/attestation/root`

## 3. Server Authentication Endpoints

- [x] 3.1 Implement `POST /api/auth/start` — look up userId in stored credentials, generate 32-byte challenge, return JSON
- [x] 3.2 Implement `POST /api/auth/finish` — receive authenticatorData + signature + clientDataHash, look up stored public key, verify ECDSA SHA256withECDSA signature over (authenticatorData || clientDataHash), return success/failure

## 4. Android App: Network Layer

- [x] 4.1 Add OkHttp dependency to `app/build.gradle.kts`
- [x] 4.2 Add `android:usesCleartextTraffic="true"` to AndroidManifest.xml (or network security config for localhost)
- [x] 4.3 Create `ApiClient.kt` with configurable `SERVER_URL` constant (default `http://localhost:8080`), methods for all 4 endpoints, coroutine-based with `Dispatchers.IO`

## 5. Android App: E2E Flow Screen

- [x] 5.1 Create `E2eFlowScreen.kt` composable with enrollment and authentication sections
- [x] 5.2 Implement enrollment flow: call `/register/start` → generate attested P-256 key with server's challenge → get cert chain → call `/register/finish` → show result
- [x] 5.3 Implement authentication flow: call `/auth/start` → build authenticatorData → sign with BiometricPrompt + CryptoObject → call `/auth/finish` → show result
- [x] 5.4 Add route to navigation in MainActivity.kt and card to HomeScreen.kt

## 6. Integration Testing

- [x] 6.1 Document setup instructions: start server, run `adb reverse tcp:8080 tcp:8080`, launch app
- [x] 6.2 Test enrollment flow on Moto G86 5G — verify server accepts the 5-cert attestation chain
- [x] 6.3 Test authentication flow — verify server accepts the ECDSA signature
- [x] 6.4 Test failure cases: wrong challenge, tampered signature, software-backed key (if testable)
