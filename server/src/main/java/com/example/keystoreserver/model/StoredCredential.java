package com.example.keystoreserver.model;

import java.security.PublicKey;

public class StoredCredential {
    public final String userId;
    public final PublicKey publicKey;
    public final String securityLevel;
    public final long registeredAt;

    public StoredCredential(String userId, PublicKey publicKey, String securityLevel) {
        this.userId = userId;
        this.publicKey = publicKey;
        this.securityLevel = securityLevel;
        this.registeredAt = System.currentTimeMillis();
    }
}
