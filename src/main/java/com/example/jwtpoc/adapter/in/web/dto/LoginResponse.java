package com.example.jwtpoc.adapter.in.web.dto;

/**
 * 登入回應 DTO
 * 包含 Access Token、Refresh Token 和相關資訊
 *
 * Access Token (JWT): 用於 API 認證，短效 (1 小時)
 * Refresh Token (UUID): 用於更新 Access Token，長效 (7 天)
 */
public record LoginResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        String username,
        long accessTokenExpiresInMs
) {
    public LoginResponse(String accessToken, String refreshToken, String username, long accessTokenExpiresInMs) {
        this(accessToken, refreshToken, "Bearer", username, accessTokenExpiresInMs);
    }
}
