package com.example.jwtpoc.infrastructure.security;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JWT Token Provider 單元測試
 *
 * 驗證 JWT 的核心功能：
 * - Token 產生
 * - Token 驗證 (簽章、過期)
 * - Claims 提取
 */
class JwtTokenProviderTest {

    private JwtTokenProvider tokenProvider;

    @BeforeEach
    void setUp() {
        tokenProvider = new JwtTokenProvider(
                "ThisIsAVeryLongSecretKeyForHS256AlgorithmAtLeast256BitsLong!!",
                3600000,  // 1 hour
                "test-issuer"
        );
    }

    @Test
    @DisplayName("應該成功產生 JWT Token (header.payload.signature 格式)")
    void shouldGenerateValidToken() {
        String token = tokenProvider.generateToken("rex", "ADMIN");

        assertNotNull(token);
        // JWT 應該有三個部分，用 . 分隔
        String[] parts = token.split("\\.");
        assertEquals(3, parts.length, "JWT should have 3 parts: header.payload.signature");
    }

    @Test
    @DisplayName("應該從 Token 正確提取 username (sub claim)")
    void shouldExtractUsername() {
        String token = tokenProvider.generateToken("rex", "ADMIN");

        String username = tokenProvider.getUsernameFromToken(token);
        assertEquals("rex", username);
    }

    @Test
    @DisplayName("應該從 Token 正確提取 role (custom claim)")
    void shouldExtractRole() {
        String token = tokenProvider.generateToken("rex", "ADMIN");

        String role = tokenProvider.getRoleFromToken(token);
        assertEquals("ADMIN", role);
    }

    @Test
    @DisplayName("有效 Token 驗證應回傳 true")
    void shouldValidateValidToken() {
        String token = tokenProvider.generateToken("rex", "USER");

        assertTrue(tokenProvider.validateToken(token));
    }

    @Test
    @DisplayName("無效 Token 驗證應回傳 false")
    void shouldRejectInvalidToken() {
        assertFalse(tokenProvider.validateToken("invalid.token.here"));
    }

    @Test
    @DisplayName("篡改過的 Token 驗證應回傳 false (簽章不符)")
    void shouldRejectTamperedToken() {
        String token = tokenProvider.generateToken("rex", "ADMIN");
        // 篡改 payload 部分
        String[] parts = token.split("\\.");
        String tamperedToken = parts[0] + ".dGFtcGVyZWQ." + parts[2];

        assertFalse(tokenProvider.validateToken(tamperedToken));
    }

    @Test
    @DisplayName("過期 Token 驗證應回傳 false")
    void shouldRejectExpiredToken() {
        // 建立一個 expiration = 0ms 的 provider
        JwtTokenProvider expiredProvider = new JwtTokenProvider(
                "ThisIsAVeryLongSecretKeyForHS256AlgorithmAtLeast256BitsLong!!",
                0,  // immediately expired
                "test-issuer"
        );

        String token = expiredProvider.generateToken("rex", "USER");

        assertFalse(expiredProvider.validateToken(token));
    }
}
