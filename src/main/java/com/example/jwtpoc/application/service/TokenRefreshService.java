package com.example.jwtpoc.application.service;

import com.example.jwtpoc.application.port.in.TokenRefreshUseCase;
import com.example.jwtpoc.application.port.out.RefreshTokenRepository;
import com.example.jwtpoc.application.port.out.UserRepository;
import com.example.jwtpoc.domain.model.RefreshToken;
import com.example.jwtpoc.domain.model.User;
import com.example.jwtpoc.infrastructure.security.JwtTokenProvider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * 應用服務 - 編排 Token 更新流程
 *
 * Token Rotation 流程：
 * 1. 驗證傳入的 Refresh Token 是否有效
 * 2. 撤銷舊的 Refresh Token
 * 3. 產生新的 Access Token (JWT) + 新的 Refresh Token (UUID)
 * 4. 儲存新的 Refresh Token 到資料庫
 * 5. 回傳新的 Token 對
 */
@Service
public class TokenRefreshService implements TokenRefreshUseCase {

    private static final Logger log = LoggerFactory.getLogger(TokenRefreshService.class);

    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final long refreshTokenExpirationMs;

    public TokenRefreshService(
            RefreshTokenRepository refreshTokenRepository,
            UserRepository userRepository,
            JwtTokenProvider jwtTokenProvider,
            @Value("${jwt.refresh-expiration-ms}") long refreshTokenExpirationMs) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.userRepository = userRepository;
        this.jwtTokenProvider = jwtTokenProvider;
        this.refreshTokenExpirationMs = refreshTokenExpirationMs;
    }

    @Override
    @Transactional
    public TokenPair refresh(String refreshTokenStr) {
        // 1. 查找 Refresh Token
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenStr)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        // 2. 驗證是否有效（未過期、未撤銷）
        if (!refreshToken.isValid()) {
            log.warn("Invalid refresh token used for user: {}", refreshToken.getUsername());
            throw new RuntimeException("Refresh token is expired or revoked");
        }

        // 3. Token Rotation: 撤銷舊 Token
        refreshToken.revoke();
        refreshTokenRepository.save(refreshToken);

        // 4. 查找使用者（取得 role 以產生新 JWT）
        String username = refreshToken.getUsername();
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));

        // 5. 產生新的 Token 對
        String newAccessToken = jwtTokenProvider.generateToken(user.getUsername(), user.getRole());
        RefreshToken newRefreshToken = createRefreshToken(username);

        log.debug("Token rotated for user: {}", username);
        return new TokenPair(newAccessToken, newRefreshToken.getToken(), jwtTokenProvider.getExpirationMs());
    }

    @Override
    public void logout(String refreshTokenStr) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenStr)
                .orElseThrow(() -> new RuntimeException("Refresh token not found"));

        refreshToken.revoke();
        refreshTokenRepository.save(refreshToken);
        log.debug("Refresh token revoked for user: {}", refreshToken.getUsername());
    }

    /** 建立並儲存新的 Refresh Token */
    public RefreshToken createRefreshToken(String username) {
        RefreshToken token = new RefreshToken(
                UUID.randomUUID().toString(),
                username,
                Instant.now().plusMillis(refreshTokenExpirationMs)
        );
        return refreshTokenRepository.save(token);
    }
}
