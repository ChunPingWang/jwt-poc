package com.example.jwtpoc.adapter.in.web;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * 受保護資源控制器
 *
 * 對應圖中 Step 5-8:
 *   5. User → Access Page
 *   6. Client sends Request + Cookie (Bearer Token)
 *   7. Server Verify JWT
 *   8. Server returns Response Data
 *
 * 所有端點都需要有效的 JWT Token
 */
@RestController
@RequestMapping("/api/protected")
public class ProtectedController {

    /**
     * GET /api/protected/profile
     * 需要認證（任何角色）
     */
    @GetMapping("/profile")
    public ResponseEntity<Map<String, Object>> getProfile(Authentication auth) {
        return ResponseEntity.ok(Map.of(
                "username", auth.getName(),
                "authorities", auth.getAuthorities().toString(),
                "message", "This is a protected resource. Your JWT is valid!",
                "timestamp", LocalDateTime.now().toString()
        ));
    }

    /**
     * GET /api/protected/admin
     * 需要 ADMIN 角色
     */
    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getAdminData(Authentication auth) {
        return ResponseEntity.ok(Map.of(
                "username", auth.getName(),
                "message", "Welcome Admin! This is an admin-only resource.",
                "secretData", "Sensitive admin information here...",
                "timestamp", LocalDateTime.now().toString()
        ));
    }

    /**
     * GET /api/protected/jwt-explained
     * 回傳 JWT 結構說明（教學用途）
     */
    @GetMapping("/jwt-explained")
    public ResponseEntity<Map<String, Object>> explainJwt(Authentication auth) {
        return ResponseEntity.ok(Map.of(
                "authenticatedUser", auth.getName(),
                "jwtStructure", Map.of(
                        "header", "Base64Url encoded: {\"alg\":\"HS256\",\"typ\":\"JWT\"}",
                        "payload", "Base64Url encoded: {\"sub\":\"username\",\"role\":\"...\",\"iat\":...,\"exp\":...}",
                        "signature", "HMAC-SHA256(base64(header) + \".\" + base64(payload), secret)"
                ),
                "authFlow", Map.of(
                        "step1", "User sends login credentials",
                        "step2", "Server authenticates user",
                        "step3", "Server creates & signs JWT",
                        "step4", "Server returns JWT to client",
                        "step5", "User accesses protected page",
                        "step6", "Client sends request with JWT in Authorization header",
                        "step7", "Server verifies JWT signature & expiration",
                        "step8", "Server returns protected data"
                )
        ));
    }
}
