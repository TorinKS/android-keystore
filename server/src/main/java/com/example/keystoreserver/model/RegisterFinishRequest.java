package com.example.keystoreserver.model;

import java.util.List;

public class RegisterFinishRequest {
    public String sessionId;
    public String userId;
    public List<String> certificateChain;
}
