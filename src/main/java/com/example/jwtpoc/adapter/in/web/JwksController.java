package com.example.jwtpoc.adapter.in.web;

import com.example.jwtpoc.infrastructure.security.JwkProvider;
import com.example.jwtpoc.infrastructure.security.JwtTokenProvider;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * JWKS (JSON Web Key Set) 端點
 *
 * 標準路徑: /.well-known/jwks.json
 *
 * 提供 RS256 公鑰供外部服務（如 OAuth 2.0 Resource Server）
 * 動態取得，實現零配置的 JWT 驗證。
 *
 * 這是 OpenID Connect Discovery 的一部分：
 * - Authorization Server 在此端點公開公鑰
 * - Resource Server 自動取得公鑰來驗證 JWT 簽名
 */
@RestController
public class JwksController {

    private final JwkProvider jwkProvider;
    private final JwtTokenProvider jwtTokenProvider;

    public JwksController(JwkProvider jwkProvider, JwtTokenProvider jwtTokenProvider) {
        this.jwkProvider = jwkProvider;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @GetMapping(value = "/.well-known/jwks.json", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> getJwks() {
        if (!"RS256".equals(jwtTokenProvider.getAlgorithm())) {
            return ResponseEntity.ok(Map.of(
                    "message", "JWKS endpoint requires RS256 algorithm. Current algorithm: "
                            + jwtTokenProvider.getAlgorithm(),
                    "hint", "Set jwt.algorithm=RS256 in application.properties to enable JWKS"
            ));
        }

        String jwkSetJson = jwkProvider.getJwkSetJson();
        return ResponseEntity.ok(jwkSetJson);
    }
}
