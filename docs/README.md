# Documentation Index

## Reading Order

### Start Here
1. **[ARTICLE.md](ARTICLE.md)** — Main article: Android Keystore as iOS Keychain analogue. Key types, code examples, EncryptedSharedPreferences, version support, Huawei compatibility.

### Key Protection & Biometrics
2. **[BIOMETRIC_PROTECTION_DEEP_DIVE.md](BIOMETRIC_PROTECTION_DEEP_DIVE.md)** — Three biometric patterns (event-based, time-based, per-use CryptoObject). Which ones Frida can bypass and which it can't.
3. **[HOW_TEE_AUTH_TOKENS_WORK.md](HOW_TEE_AUTH_TOKENS_WORK.md)** — How fingerprint/face/PIN becomes a HardwareAuthToken. HMAC signing inside TEE. Why root can't forge authentication.

### Attack Vectors & Security
4. **[SECURITY_ANALYSIS.md](SECURITY_ANALYSIS.md)** — App isolation (tested with attacker app), reinstall behavior, Frida attacks, root attacks, Samsung CVEs, defense recommendations.
5. **[DUO_VS_WIOSENSE_COMPARISON.md](DUO_VS_WIOSENSE_COMPARISON.md)** — Per-use CryptoObject (Duo) vs 120s timeout (WIOsense). Piggybacking attack explained in detail.

### 2FA Authenticator Architecture
6. **[2FA_AUTHENTICATOR_ARCHITECTURE.md](2FA_AUTHENTICATOR_ARCHITECTURE.md)** — Architecture for your 2FA app. Options A/B/C, code, WebAuthn mapping, edge cases.
7. **[APP_PIN_VS_BIOMETRIC_ANALYSIS.md](APP_PIN_VS_BIOMETRIC_ANALYSIS.md)** — Software PIN vs biometric vs device credential. 5 options with tradeoffs.

### Key Attestation
8. **[KEY_ATTESTATION_EXPLAINED.md](KEY_ATTESTATION_EXPLAINED.md)** — What attestation is, is it free (yes), server-side verification steps, code.
9. **[KEY_ATTESTATION_VS_DEVICE_ATTESTATION.md](KEY_ATTESTATION_VS_DEVICE_ATTESTATION.md)** — Key attestation (free, unlimited) vs Play Integrity (10K/day quota). Which you need.
10. **[KEY_ATTESTATION_CHAIN_AND_BACKENDS.md](KEY_ATTESTATION_CHAIN_AND_BACKENDS.md)** — How the cert chain forms (RKP, batch keys), real 5-cert chain from Moto G86, open-source backends.

### Open-Source Implementations
11. **[DUO_LABS_AUTHENTICATOR_ANALYSIS.md](DUO_LABS_AUTHENTICATOR_ANALYSIS.md)** — Cisco/Duo's FIDO2 authenticator. Per-use CryptoObject, key generation, signing flow.
12. **[WIOSENSE_RAUTH_ANALYSIS.md](WIOSENSE_RAUTH_ANALYSIS.md)** — WIOsense's roaming authenticator. CTAP2 clientPIN protocol implementation.

### Protocol References
13. **[CTAP2_CLIENT_PIN_PROTOCOL.md](CTAP2_CLIENT_PIN_PROTOCOL.md)** — Full CTAP2 clientPIN spec: ECDH, all subcommands, pinToken, pinAuth, retry/lockout, protocol v1 vs v2.
14. **[ROAMING_AUTHENTICATOR_EXPLAINED.md](ROAMING_AUTHENTICATOR_EXPLAINED.md)** — How phone-as-security-key works: NFC, BLE/caBLE hybrid transport, CTAP2 over APDU.

## Tested On

- **Device:** Motorola Moto G86 5G
- **Android:** 16 (API 36)
- **TEE:** ARM TrustZone, RKP-provisioned
- **Attestation root:** `CN=Key Attestation CA1, O=Google LLC` (ECDSA P-384, 2026 rotation)
- **Biometric:** Fingerprint (Class 3/Strong) + Face unlock
