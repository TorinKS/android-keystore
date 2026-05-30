package com.example.keystoreserver.model;

public class AuthFinishRequest {
    public String sessionId;
    public String userId;
    public String authenticatorData;
    public String clientDataHash;
    public String signature;
}
