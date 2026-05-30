package com.example.keystoreserver.controller;

import com.example.keystoreserver.model.*;
import com.example.keystoreserver.service.AttestationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.*;

@RestController
@RequestMapping("/api")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);
    private final AttestationService attestationService;

    public AuthController(AttestationService attestationService) {
        this.attestationService = attestationService;
    }

    @PostMapping("/register/start")
    public ResponseEntity<Map<String, String>> registerStart(@RequestBody RegisterStartRequest request) {
        String sessionId = UUID.randomUUID().toString();
        String challenge = attestationService.createChallenge(sessionId);

        log.info("Register start | user: {} | session: {}", request.userId, sessionId);

        Map<String, String> response = new HashMap<>();
        response.put("sessionId", sessionId);
        response.put("challenge", challenge);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register/finish")
    public ResponseEntity<Map<String, Object>> registerFinish(@RequestBody RegisterFinishRequest request) {
        try {
            byte[] challenge = attestationService.getChallenge(request.sessionId);
            if (challenge == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired session"));
            }

            Map<String, Object> result = attestationService.verifyAttestation(
                    request.userId, request.certificateChain, challenge);

            return ResponseEntity.ok(result);
        } catch (SecurityException e) {
            log.warn("Registration rejected for {}: {}", request.userId, e.getMessage());
            return ResponseEntity.badRequest().body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Registration error for {}", request.userId, e);
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }

    @PostMapping("/auth/start")
    public ResponseEntity<Map<String, String>> authStart(@RequestBody AuthStartRequest request) {
        if (!attestationService.isUserRegistered(request.userId)) {
            return ResponseEntity.status(404).body(Map.of("error", "User not registered"));
        }

        String sessionId = UUID.randomUUID().toString();
        String challenge = attestationService.createChallenge(sessionId);

        log.info("Auth start | user: {} | session: {}", request.userId, sessionId);

        Map<String, String> response = new HashMap<>();
        response.put("sessionId", sessionId);
        response.put("challenge", challenge);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/auth/finish")
    public ResponseEntity<Map<String, Object>> authFinish(@RequestBody AuthFinishRequest request) {
        try {
            byte[] challenge = attestationService.getChallenge(request.sessionId);
            if (challenge == null) {
                return ResponseEntity.badRequest().body(Map.of("error", "Invalid or expired session"));
            }

            byte[] authenticatorData = Base64.getDecoder().decode(request.authenticatorData);
            byte[] clientDataHash = Base64.getDecoder().decode(request.clientDataHash);
            byte[] signature = Base64.getDecoder().decode(request.signature);

            boolean valid = attestationService.verifySignature(
                    request.userId, authenticatorData, clientDataHash, signature);

            if (valid) {
                return ResponseEntity.ok(Map.of("status", "authenticated"));
            } else {
                return ResponseEntity.status(401).body(Map.of("error", "Signature verification failed"));
            }
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(404).body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            log.error("Auth error for {}", request.userId, e);
            return ResponseEntity.internalServerError().body(Map.of("error", e.getMessage()));
        }
    }
}
