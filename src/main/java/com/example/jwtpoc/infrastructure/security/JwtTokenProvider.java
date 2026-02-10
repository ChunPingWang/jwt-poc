package com.example.jwtpoc.infrastructure.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

/**
 * JWT Token 提供者
 *
 * 對應圖中 JWT 結構：
 *   Header:    {"alg": "HS256", "typ": "JWT"}
 *   Payload:   {"sub": "username", "role": "ADMIN", "iat": ..., "exp": ...}
 *   Signature: HMAC-SHA256(base64Url(header) + "." + base64Url(payload), secret)
 *
 * 最終 Token: base64(header).base64(payload).signature
 */
@Component
public class JwtTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final SecretKey secretKey;
    private final long expirationMs;
    private final String issuer;

    public JwtTokenProvider(
            @Value("${jwt.secret}") String secret,
            @Value("${jwt.expiration-ms}") long expirationMs,
            @Value("${jwt.issuer}") String issuer) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
        this.issuer = issuer;
    }

    /**
     * 產生 JWT Token
     *
     * 對應圖中 Step 3: Create & sign JWT
     *
     * Token 結構：
     * ┌──────────────────────────────────────────┐
     * │ Header (自動產生)                          │
     * │   alg: HS256                              │
     * │   typ: JWT                                │
     * ├──────────────────────────────────────────┤
     * │ Payload                                   │
     * │   sub: username                           │
     * │   role: USER/ADMIN                        │
     * │   iss: jwt-poc-app                        │
     * │   iat: (current timestamp)                │
     * │   exp: (current + expiration)             │
     * ├──────────────────────────────────────────┤
     * │ Signature                                 │
     * │   HMAC-SHA256(header + payload, secret)   │
     * └──────────────────────────────────────────┘
     */
    public String generateToken(String username, String role) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        String token = Jwts.builder()
                // Header: alg=HS256 (自動根據 SecretKey 類型設定)
                .subject(username)              // Payload: sub
                .claim("role", role)             // Payload: custom claim
                .issuer(issuer)                  // Payload: iss
                .issuedAt(now)                   // Payload: iat
                .expiration(expiry)              // Payload: exp
                .signWith(secretKey)             // Signature: 用 secret 簽名
                .compact();                      // 組合為 header.payload.signature

        log.debug("Generated JWT for user: {}, expires: {}", username, expiry);
        return token;
    }

    /**
     * 從 Token 中提取使用者名稱
     */
    public String getUsernameFromToken(String token) {
        return parseClaims(token).getSubject();
    }

    /**
     * 從 Token 中提取角色
     */
    public String getRoleFromToken(String token) {
        return parseClaims(token).get("role", String.class);
    }

    /**
     * 驗證 JWT Token
     *
     * 對應圖中 Step 7: Verify JWT
     *
     * 驗證項目：
     * 1. 簽章是否有效 (防篡改)
     * 2. Token 是否過期
     * 3. Token 格式是否正確
     */
    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (SecurityException e) {
            log.error("Invalid JWT signature: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.error("Malformed JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            log.error("Expired JWT token: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.error("Unsupported JWT token: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.error("JWT claims string is empty: {}", e.getMessage());
        }
        return false;
    }

    private Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
