package com.example.jwtpoc.infrastructure.security;

import com.nimbusds.jose.Algorithm;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

import org.springframework.stereotype.Component;

import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;

/**
 * JWK (JSON Web Key) 提供者
 *
 * 將 RSA 公鑰轉換為 JWK Set JSON 格式，供 JWKS 端點使用。
 * JWKS (JSON Web Key Set) 是 OpenID Connect / OAuth 2.0 的標準協議，
 * 讓資源伺服器可以動態取得簽名公鑰，而不需要靜態配置。
 *
 * JWK Set 格式範例：
 * {
 *   "keys": [{
 *     "kty": "RSA",
 *     "use": "sig",
 *     "alg": "RS256",
 *     "kid": "jwt-poc-key-1",
 *     "n": "...",
 *     "e": "AQAB"
 *   }]
 * }
 */
@Component
public class JwkProvider {

    private final JwtTokenProvider jwtTokenProvider;

    public JwkProvider(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     * 產生 JWK Set JSON 字串
     *
     * @return JWK Set JSON，如果不是 RS256 模式則回傳 null
     */
    public String getJwkSetJson() {
        PublicKey publicKey = jwtTokenProvider.getPublicKey();
        if (publicKey == null) {
            return null; // HS256 模式沒有公鑰
        }

        RSAKey rsaKey = new RSAKey.Builder((RSAPublicKey) publicKey)
                .keyID(jwtTokenProvider.getKeyId())
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(new Algorithm(JWSAlgorithm.RS256.getName()))
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return jwkSet.toString();
    }
}
