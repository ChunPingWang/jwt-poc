package com.example.jwtpoc.adapter.in.web;

import com.example.jwtpoc.adapter.in.web.dto.*;
import com.example.jwtpoc.application.port.in.AuthUseCase;
import com.example.jwtpoc.application.port.in.LoginResult;
import com.example.jwtpoc.application.port.in.TokenRefreshUseCase;
import com.example.jwtpoc.domain.model.User;

import jakarta.validation.Valid;

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
    private final TokenRefreshUseCase tokenRefreshUseCase;

    public AuthController(AuthUseCase authUseCase,
                          TokenRefreshUseCase tokenRefreshUseCase) {
        this.authUseCase = authUseCase;
        this.tokenRefreshUseCase = tokenRefreshUseCase;
    }

    /**
     * POST /api/auth/login
     *
     * 對應圖中 Step 1-4:
     *   1. User sends credentials
     *   2. Server authenticates
     *   3. Server creates & signs JWT + Refresh Token
     *   4. Server returns both tokens to client
     */
    @PostMapping("/login")
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        LoginResult result = authUseCase.login(request.username(), request.password());
        return ResponseEntity.ok(new LoginResponse(
                result.accessToken(),
                result.refreshToken(),
                result.username(),
                result.accessTokenExpiresInMs()));
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

    /**
     * POST /api/auth/refresh
     *
     * Token Rotation 流程：
     * 1. Client 送出 Refresh Token
     * 2. Server 驗證 Refresh Token（是否存在、未過期、未撤銷）
     * 3. Server 撤銷舊 Refresh Token
     * 4. Server 產生新的 Access Token + Refresh Token
     * 5. Server 回傳新的 Token 對
     */
    @PostMapping("/refresh")
    public ResponseEntity<LoginResponse> refresh(@Valid @RequestBody RefreshTokenRequest request) {
        TokenRefreshUseCase.TokenPair pair = tokenRefreshUseCase.refresh(request.refreshToken());
        return ResponseEntity.ok(new LoginResponse(
                pair.accessToken(),
                pair.refreshToken(),
                null,
                pair.accessTokenExpiresInMs()));
    }

    /**
     * POST /api/auth/logout
     *
     * 撤銷 Refresh Token，使其無法再用來取得新的 Access Token。
     * 注意：已發出的 Access Token (JWT) 仍然有效直到過期，
     * 因為 JWT 是 stateless 的。這是 JWT 架構的已知限制。
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(@Valid @RequestBody LogoutRequest request) {
        tokenRefreshUseCase.logout(request.refreshToken());
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}
