package com.example.jwtpoc.infrastructure.security;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * JWT Token Provider 單元測試
 *
 * 驗證 HS256 和 RS256 雙演算法的核心功能：
 * - Token 產生
 * - Token 驗證 (簽章、過期)
 * - Claims 提取
 * - 跨演算法拒絕
 */
class JwtTokenProviderTest {

    private static final long ONE_HOUR = 3600000;
    private static final String ISSUER = "test-issuer";
    private static final String HS256_SECRET = "ThisIsAVeryLongSecretKeyForHS256AlgorithmAtLeast256BitsLong!!";

    private JwtTokenProvider createHs256Provider(long expirationMs) {
        return new JwtTokenProvider("HS256", HS256_SECRET, "", "", expirationMs, ISSUER);
    }

    private JwtTokenProvider createRs256Provider(long expirationMs) {
        return new JwtTokenProvider("RS256", "", "keys/public.pem", "keys/private.pem", expirationMs, ISSUER);
    }

    // ==========================================
    // HS256 Tests
    // ==========================================

    @Nested
    @DisplayName("HS256（對稱式）")
    class Hs256Tests {

        private final JwtTokenProvider provider = createHs256Provider(ONE_HOUR);

        @Test
        @DisplayName("應該成功產生 JWT Token (header.payload.signature 格式)")
        void shouldGenerateValidToken() {
            String token = provider.generateToken("rex", "ADMIN");

            assertNotNull(token);
            String[] parts = token.split("\\.");
            assertEquals(3, parts.length, "JWT should have 3 parts: header.payload.signature");
        }

        @Test
        @DisplayName("應該從 Token 正確提取 username (sub claim)")
        void shouldExtractUsername() {
            String token = provider.generateToken("rex", "ADMIN");
            assertEquals("rex", provider.getUsernameFromToken(token));
        }

        @Test
        @DisplayName("應該從 Token 正確提取 role (custom claim)")
        void shouldExtractRole() {
            String token = provider.generateToken("rex", "ADMIN");
            assertEquals("ADMIN", provider.getRoleFromToken(token));
        }

        @Test
        @DisplayName("有效 Token 驗證應回傳 true")
        void shouldValidateValidToken() {
            String token = provider.generateToken("rex", "USER");
            assertTrue(provider.validateToken(token));
        }

        @Test
        @DisplayName("無效 Token 驗證應回傳 false")
        void shouldRejectInvalidToken() {
            assertFalse(provider.validateToken("invalid.token.here"));
        }

        @Test
        @DisplayName("篡改過的 Token 驗證應回傳 false (簽章不符)")
        void shouldRejectTamperedToken() {
            String token = provider.generateToken("rex", "ADMIN");
            String[] parts = token.split("\\.");
            String tamperedToken = parts[0] + ".dGFtcGVyZWQ." + parts[2];
            assertFalse(provider.validateToken(tamperedToken));
        }

        @Test
        @DisplayName("過期 Token 驗證應回傳 false")
        void shouldRejectExpiredToken() {
            JwtTokenProvider expiredProvider = createHs256Provider(0);
            String token = expiredProvider.generateToken("rex", "USER");
            assertFalse(expiredProvider.validateToken(token));
        }

        @Test
        @DisplayName("演算法應為 HS256")
        void shouldReportAlgorithm() {
            assertEquals("HS256", provider.getAlgorithm());
        }
    }

    // ==========================================
    // RS256 Tests
    // ==========================================

    @Nested
    @DisplayName("RS256（非對稱式）")
    class Rs256Tests {

        private final JwtTokenProvider provider = createRs256Provider(ONE_HOUR);

        @Test
        @DisplayName("應該成功產生 RS256 JWT Token (header.payload.signature 格式)")
        void shouldGenerateValidToken() {
            String token = provider.generateToken("rex", "ADMIN");

            assertNotNull(token);
            String[] parts = token.split("\\.");
            assertEquals(3, parts.length, "JWT should have 3 parts: header.payload.signature");
        }

        @Test
        @DisplayName("應該從 RS256 Token 正確提取 username")
        void shouldExtractUsername() {
            String token = provider.generateToken("rex", "ADMIN");
            assertEquals("rex", provider.getUsernameFromToken(token));
        }

        @Test
        @DisplayName("應該從 RS256 Token 正確提取 role")
        void shouldExtractRole() {
            String token = provider.generateToken("rex", "ADMIN");
            assertEquals("ADMIN", provider.getRoleFromToken(token));
        }

        @Test
        @DisplayName("有效 RS256 Token 驗證應回傳 true")
        void shouldValidateValidToken() {
            String token = provider.generateToken("rex", "USER");
            assertTrue(provider.validateToken(token));
        }

        @Test
        @DisplayName("無效 Token 驗證應回傳 false")
        void shouldRejectInvalidToken() {
            assertFalse(provider.validateToken("invalid.token.here"));
        }

        @Test
        @DisplayName("篡改過的 RS256 Token 驗證應回傳 false")
        void shouldRejectTamperedToken() {
            String token = provider.generateToken("rex", "ADMIN");
            String[] parts = token.split("\\.");
            String tamperedToken = parts[0] + ".dGFtcGVyZWQ." + parts[2];
            assertFalse(provider.validateToken(tamperedToken));
        }

        @Test
        @DisplayName("過期 RS256 Token 驗證應回傳 false")
        void shouldRejectExpiredToken() {
            JwtTokenProvider expiredProvider = createRs256Provider(0);
            String token = expiredProvider.generateToken("rex", "USER");
            assertFalse(expiredProvider.validateToken(token));
        }

        @Test
        @DisplayName("演算法應為 RS256")
        void shouldReportAlgorithm() {
            assertEquals("RS256", provider.getAlgorithm());
        }
    }

    // ==========================================
    // Cross-Algorithm Tests
    // ==========================================

    @Nested
    @DisplayName("跨演算法驗證")
    class CrossAlgorithmTests {

        private final JwtTokenProvider hs256Provider = createHs256Provider(ONE_HOUR);
        private final JwtTokenProvider rs256Provider = createRs256Provider(ONE_HOUR);

        @Test
        @DisplayName("HS256 Token 不應通過 RS256 驗證")
        void hs256TokenShouldFailRs256Validation() {
            String hs256Token = hs256Provider.generateToken("rex", "ADMIN");
            assertFalse(rs256Provider.validateToken(hs256Token));
        }

        @Test
        @DisplayName("RS256 Token 不應通過 HS256 驗證")
        void rs256TokenShouldFailHs256Validation() {
            String rs256Token = rs256Provider.generateToken("rex", "ADMIN");
            assertFalse(hs256Provider.validateToken(rs256Token));
        }
    }
}
