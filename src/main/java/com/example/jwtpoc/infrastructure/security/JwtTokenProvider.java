package com.example.jwtpoc.infrastructure.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * JWT Token 提供者 — 支援 HS256 和 RS256 雙演算法
 *
 * HS256（對稱式）：
 *   簽名和驗證使用同一把 Secret Key
 *   適用：單一服務，簡單場景
 *   Header: {"alg": "HS256", "typ": "JWT"}
 *
 * RS256（非對稱式）：
 *   Private Key 簽名，Public Key 驗證
 *   適用：微服務架構，多服務只需 Public Key 即可驗證
 *   Header: {"alg": "RS256", "typ": "JWT"}
 *
 * 透過 jwt.algorithm 設定值切換，預設為 HS256（向下相容）
 */
@Component
public class JwtTokenProvider {

    private static final Logger log = LoggerFactory.getLogger(JwtTokenProvider.class);

    private final Key signingKey;
    private final JwtParser jwtParser;
    private final long expirationMs;
    private final String issuer;
    private final String algorithm;
    private final PublicKey publicKey;   // RS256 模式下的公鑰，HS256 為 null
    private final String keyId;          // JWKS 端點使用的 kid

    public JwtTokenProvider(
            @Value("${jwt.algorithm:HS256}") String algorithm,
            @Value("${jwt.secret:}") String secret,
            @Value("${jwt.rsa.public-key-location:}") String publicKeyLocation,
            @Value("${jwt.rsa.private-key-location:}") String privateKeyLocation,
            @Value("${jwt.expiration-ms}") long expirationMs,
            @Value("${jwt.issuer}") String issuer,
            @Value("${jwt.rsa.key-id:jwt-poc-key-1}") String keyId) {

        this.algorithm = algorithm.toUpperCase();
        this.expirationMs = expirationMs;
        this.issuer = issuer;
        this.keyId = keyId;

        if ("RS256".equals(this.algorithm)) {
            // RS256: 私鑰簽名，公鑰驗證
            PrivateKey privateKey = loadPrivateKey(privateKeyLocation);
            this.publicKey = loadPublicKey(publicKeyLocation);
            this.signingKey = privateKey;
            this.jwtParser = Jwts.parser().verifyWith(this.publicKey).build();
            log.info("JWT configured with RS256 (asymmetric: private key signs, public key verifies)");
        } else {
            // HS256: 同一把密鑰簽名和驗證
            SecretKey hmacKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
            this.signingKey = hmacKey;
            this.publicKey = null;
            this.jwtParser = Jwts.parser().verifyWith(hmacKey).build();
            log.info("JWT configured with HS256 (symmetric: same key signs and verifies)");
        }
    }

    /**
     * 產生 JWT Token
     *
     * .signWith(key) 會自動根據 Key 類型選擇演算法：
     *   SecretKey  → HS256
     *   PrivateKey → RS256
     */
    public String generateToken(String username, String role) {
        Date now = new Date();
        Date expiry = new Date(now.getTime() + expirationMs);

        String token = Jwts.builder()
                .id(UUID.randomUUID().toString())   // jti claim — 用於 Token 黑名單
                .subject(username)
                .claim("role", role)
                .issuer(issuer)
                .issuedAt(now)
                .expiration(expiry)
                .signWith(signingKey)
                .compact();

        log.debug("Generated JWT ({}) for user: {}, expires: {}", algorithm, username, expiry);
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

    /**
     * 從 Token 中提取 JWT ID (jti claim)
     */
    public String getJtiFromToken(String token) {
        return parseClaims(token).getId();
    }

    /**
     * 從 Token 中提取過期時間
     */
    public Date getExpirationFromToken(String token) {
        return parseClaims(token).getExpiration();
    }

    public long getExpirationMs() {
        return expirationMs;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * 取得 RSA 公鑰（RS256 模式），用於 JWKS 端點
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * 取得 Key ID，用於 JWKS 端點的 kid 欄位
     */
    public String getKeyId() {
        return keyId;
    }

    private Claims parseClaims(String token) {
        return jwtParser.parseSignedClaims(token).getPayload();
    }

    // === RSA Key Loading ===

    /**
     * 從 classpath 載入 RSA 私鑰 (PKCS#8 PEM 格式)
     *
     * PEM 格式範例：
     * -----BEGIN PRIVATE KEY-----
     * MIIEvQIBADANBgkqhki...
     * -----END PRIVATE KEY-----
     */
    private PrivateKey loadPrivateKey(String location) {
        try {
            String pem = readClasspathResource(location);
            String base64 = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(base64);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePrivate(spec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load RSA private key from: " + location, e);
        }
    }

    /**
     * 從 classpath 載入 RSA 公鑰 (X.509 PEM 格式)
     *
     * PEM 格式範例：
     * -----BEGIN PUBLIC KEY-----
     * MIIBIjANBgkqhki...
     * -----END PUBLIC KEY-----
     */
    private PublicKey loadPublicKey(String location) {
        try {
            String pem = readClasspathResource(location);
            String base64 = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(base64);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            return KeyFactory.getInstance("RSA").generatePublic(spec);
        } catch (Exception e) {
            throw new RuntimeException("Failed to load RSA public key from: " + location, e);
        }
    }

    private String readClasspathResource(String location) {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(location)) {
            if (is == null) {
                throw new RuntimeException("Classpath resource not found: " + location);
            }
            return new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))
                    .lines()
                    .collect(Collectors.joining("\n"));
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to read classpath resource: " + location, e);
        }
    }
}
