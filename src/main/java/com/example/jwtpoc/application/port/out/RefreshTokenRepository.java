package com.example.jwtpoc.application.port.out;

import com.example.jwtpoc.domain.model.RefreshToken;

import java.util.Optional;

/**
 * 出站埠 - Refresh Token 儲存庫
 * 領域層定義介面，基礎設施層實作
 */
public interface RefreshTokenRepository {

    Optional<RefreshToken> findByToken(String token);

    RefreshToken save(RefreshToken refreshToken);

    /** 撤銷某使用者的所有 Refresh Token（登出或安全事件時使用） */
    void revokeAllByUsername(String username);

    /** 刪除已過期的 Token（清理用） */
    void deleteExpiredTokens();
}
