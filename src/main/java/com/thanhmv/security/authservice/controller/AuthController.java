package com.thanhmv.security.authservice.controller;

import com.thanhmv.security.authservice.model.dto.req.TokenRequest;
import com.thanhmv.security.authservice.service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping(value = "/oauth/login", consumes = "application/json")
    public ResponseEntity<Map<String, Object>> tokenJson(@Valid @RequestBody TokenRequest req) {
        return handleToken(req);
    }

    @PostMapping(value = "/oauth/genPassword", consumes = "application/json")
    public ResponseEntity<String> genPassword(@Valid @RequestBody TokenRequest req) {
        return genPass(req);
    }

    private ResponseEntity<String> genPass(TokenRequest req) {
        return ResponseEntity.ok(passwordEncoder.encode(req.getPassword()));
    }

    private ResponseEntity<Map<String, Object>> handleToken(TokenRequest req) {
        String gt = req.getGrant_type();
        if ("password".equalsIgnoreCase(gt)) {
            if (req.getEmail() == null || req.getPassword() == null) {
                throw new IllegalArgumentException("username/password required");
            }
            Map<String, Object> resp = authService.passwordGrant(
                    req.getEmail(), req.getPassword(),
                    req.getScope() == null ? "" : req.getScope()
            );
            return ResponseEntity.ok(resp);
        } else if ("refresh_token".equalsIgnoreCase(gt)) {
            if (req.getRefresh_token() == null) {
                throw new IllegalArgumentException("refresh_token required");
            }
            Map<String, Object> resp = authService.refreshGrant(req.getRefresh_token());
            return ResponseEntity.ok(resp);
        } else {
            throw new IllegalArgumentException("Unsupported grant_type");
        }
    }
}
