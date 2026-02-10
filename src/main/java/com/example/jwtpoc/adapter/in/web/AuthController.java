package com.example.jwtpoc.adapter.in.web;

import com.example.jwtpoc.adapter.in.web.dto.LoginRequest;
import com.example.jwtpoc.adapter.in.web.dto.LoginResponse;
import com.example.jwtpoc.adapter.in.web.dto.UserRegistrationRequest;
import com.example.jwtpoc.application.port.in.AuthUseCase;
import com.example.jwtpoc.domain.model.User;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * 認證控制器 (入站 Web 適配器)
 *
 * 對應圖中的流程：
 *   Step 1: User → Log in → 呼叫 POST /api/auth/login
 *   Step 2: Authenticate → AuthService 驗證帳密
 *   Step 3: Create & sign JWT → JwtTokenProvider 產生 Token
 *   Step 4: Returns Cookie + JWT → 回傳 LoginResponse
 */
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthUseCase authUseCase;
    private final long expirationMs;

    public AuthController(AuthUseCase authUseCase,
                          @Value("${jwt.expiration-ms}") long expirationMs) {
        this.authUseCase = authUseCase;
        this.expirationMs = expirationMs;
    }

    /**
     * POST /api/auth/login
     *
     * 對應圖中 Step 1-4:
     *   1. User sends credentials
     *   2. Server authenticates
     *   3. Server creates & signs JWT
     *   4. Server returns JWT to client
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        String token = authUseCase.login(request.username(), request.password());
        return ResponseEntity.ok(
                new LoginResponse(token, request.username(), expirationMs));
    }

    /**
     * POST /api/auth/register
     */
    @PostMapping("/register")
    public ResponseEntity<Map<String, Object>> register(
            @Valid @RequestBody UserRegistrationRequest request) {
        User user = authUseCase.register(
                request.username(), request.password(), request.role());
        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of(
                        "message", "User registered successfully",
                        "username", user.getUsername(),
                        "role", user.getRole()
                ));
    }
}
