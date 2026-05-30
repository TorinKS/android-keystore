package com.example.keystoreserver.service;

import com.example.keystoreserver.model.StoredCredential;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import jakarta.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URI;
import java.security.*;
import java.security.cert.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class AttestationService {

    private static final Logger log = LoggerFactory.getLogger(AttestationService.class);
    private static final String ATTESTATION_EXTENSION_OID = "1.3.6.1.4.1.11129.2.1.17";
    private static final String GOOGLE_ROOT_URL = "https://android.googleapis.com/attestation/root";

    private final Map<String, byte[]> challengeStore = new ConcurrentHashMap<>();
    private final Map<String, StoredCredential> credentialStore = new ConcurrentHashMap<>();
    private final Set<String> trustedRootSubjects = ConcurrentHashMap.newKeySet();
    private final List<X509Certificate> trustedRoots = new ArrayList<>();

    @PostConstruct
    public void init() {
        Security.addProvider(new BouncyCastleProvider());
        loadGoogleRoots();
    }

    private void loadGoogleRoots() {
        try {
            URI uri = URI.create(GOOGLE_ROOT_URL);
            try (InputStream is = uri.toURL().openStream()) {
                String json = new String(is.readAllBytes());
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                int start = 0;
                while ((start = json.indexOf("-----BEGIN CERTIFICATE-----", start)) != -1) {
                    int end = json.indexOf("-----END CERTIFICATE-----", start) + "-----END CERTIFICATE-----".length();
                    String pem = json.substring(start, end).replace("\\n", "\n");
                    X509Certificate cert = (X509Certificate) cf.generateCertificate(
                            new ByteArrayInputStream(pem.getBytes()));
                    trustedRoots.add(cert);
                    trustedRootSubjects.add(cert.getSubjectX500Principal().getName());
                    log.info("Loaded Google root: {}", cert.getSubjectX500Principal().getName());
                    start = end;
                }
            }
            log.info("Loaded {} Google attestation root certificate(s)", trustedRoots.size());
        } catch (Exception e) {
            log.warn("Could not load Google roots from network: {}. Using permissive root matching.", e.getMessage());
        }
    }

    public String createChallenge(String sessionId) {
        byte[] challenge = new byte[32];
        new SecureRandom().nextBytes(challenge);
        challengeStore.put(sessionId, challenge);
        return Base64.getEncoder().encodeToString(challenge);
    }

    public byte[] getChallenge(String sessionId) {
        return challengeStore.remove(sessionId);
    }

    public Map<String, Object> verifyAttestation(String userId, List<String> certChainBase64, byte[] expectedChallenge)
            throws Exception {

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        List<X509Certificate> chain = new ArrayList<>();
        for (String certB64 : certChainBase64) {
            byte[] certBytes = Base64.getDecoder().decode(certB64);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certBytes));
            chain.add(cert);
        }

        log.info("Verifying attestation for {} | chain: {} certs", userId, chain.size());

        for (int i = 0; i < chain.size() - 1; i++) {
            X509Certificate cert = chain.get(i);
            X509Certificate issuer = chain.get(i + 1);
            cert.verify(issuer.getPublicKey());
            log.info("  Cert {} → signed by cert {}: VALID", i + 1, i + 2);
        }

        X509Certificate root = chain.get(chain.size() - 1);
        root.verify(root.getPublicKey());
        log.info("  Root is self-signed: VALID");

        String rootSubject = root.getSubjectX500Principal().getName();
        boolean rootTrusted;
        if (!trustedRoots.isEmpty()) {
            rootTrusted = trustedRoots.stream().anyMatch(tr ->
                    tr.getSubjectX500Principal().equals(root.getSubjectX500Principal()));
        } else {
            rootTrusted = rootSubject.contains("Google") && rootSubject.contains("Attestation");
            log.warn("  No cached Google roots — using permissive matching: {}", rootTrusted);
        }

        if (!rootTrusted) {
            throw new SecurityException("Root certificate is NOT a Google attestation root: " + rootSubject);
        }
        log.info("  Root trusted: {} ✓", rootSubject);

        X509Certificate leaf = chain.get(0);
        byte[] extValue = leaf.getExtensionValue(ATTESTATION_EXTENSION_OID);
        if (extValue == null) {
            throw new SecurityException("Leaf certificate has no attestation extension (OID " + ATTESTATION_EXTENSION_OID + ")");
        }

        Map<String, Object> attestationInfo = parseAttestationExtension(extValue, expectedChallenge);
        String securityLevel = (String) attestationInfo.get("securityLevel");

        if (!"TEE".equals(securityLevel) && !"StrongBox".equals(securityLevel)) {
            throw new SecurityException("Key is not hardware-backed. Security level: " + securityLevel);
        }

        PublicKey publicKey = leaf.getPublicKey();
        credentialStore.put(userId, new StoredCredential(userId, publicKey, securityLevel));
        log.info("Registered {} | root: {} | level: {}", userId, rootSubject, securityLevel);

        Map<String, Object> result = new HashMap<>();
        result.put("status", "registered");
        result.put("securityLevel", securityLevel);
        result.put("chainLength", chain.size());
        result.put("rootSubject", rootSubject);
        result.putAll(attestationInfo);
        return result;
    }

    private int getIntValue(ASN1Encodable obj) {
        if (obj instanceof ASN1Integer) return ((ASN1Integer) obj).intValueExact();
        if (obj instanceof ASN1Enumerated) return ((ASN1Enumerated) obj).intValueExact();
        throw new IllegalArgumentException("Expected integer or enumerated, got: " + obj.getClass().getSimpleName());
    }

    private Map<String, Object> parseAttestationExtension(byte[] extValue, byte[] expectedChallenge) throws Exception {
        Map<String, Object> info = new HashMap<>();

        ASN1OctetString octetString = ASN1OctetString.getInstance(extValue);
        ASN1Sequence seq = ASN1Sequence.getInstance(octetString.getOctets());

        int attestationVersion = getIntValue(seq.getObjectAt(0));
        int attestationSecurityLevel = getIntValue(seq.getObjectAt(1));
        int keymasterVersion = getIntValue(seq.getObjectAt(2));
        int keymasterSecurityLevel = getIntValue(seq.getObjectAt(3));
        byte[] attestationChallenge = ASN1OctetString.getInstance(seq.getObjectAt(4)).getOctets();

        String secLevel;
        switch (attestationSecurityLevel) {
            case 0: secLevel = "Software"; break;
            case 1: secLevel = "TEE"; break;
            case 2: secLevel = "StrongBox"; break;
            default: secLevel = "Unknown(" + attestationSecurityLevel + ")"; break;
        }

        if (!Arrays.equals(attestationChallenge, expectedChallenge)) {
            throw new SecurityException("Attestation challenge mismatch! Expected: " +
                    Base64.getEncoder().encodeToString(expectedChallenge) + " Got: " +
                    Base64.getEncoder().encodeToString(attestationChallenge));
        }
        log.info("  Challenge verified ✓");

        info.put("attestationVersion", attestationVersion);
        info.put("securityLevel", secLevel);
        info.put("keymasterVersion", keymasterVersion);
        info.put("challengeVerified", true);
        return info;
    }

    public boolean verifySignature(String userId, byte[] authenticatorData, byte[] clientDataHash, byte[] signature)
            throws Exception {
        StoredCredential cred = credentialStore.get(userId);
        if (cred == null) {
            throw new IllegalArgumentException("User not registered: " + userId);
        }

        byte[] signedData = new byte[authenticatorData.length + clientDataHash.length];
        System.arraycopy(authenticatorData, 0, signedData, 0, authenticatorData.length);
        System.arraycopy(clientDataHash, 0, signedData, authenticatorData.length, clientDataHash.length);

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(cred.publicKey);
        sig.update(signedData);
        boolean valid = sig.verify(signature);

        log.info("Auth {} | signature: {}", userId, valid ? "VALID ✓" : "INVALID ✗");
        return valid;
    }

    public boolean isUserRegistered(String userId) {
        return credentialStore.containsKey(userId);
    }

    public StoredCredential getCredential(String userId) {
        return credentialStore.get(userId);
    }
}
