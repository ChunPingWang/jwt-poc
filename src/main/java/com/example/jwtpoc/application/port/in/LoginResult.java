package com.example.jwtpoc.application.port.in;

/**
 * 登入結果 - 包含 Access Token 和 Refresh Token
 *
 * 為什麼要回傳兩個 Token？
 * ─────────────────────────────────────
 * Access Token (JWT): 短效（1 小時），用於 API 認證，stateless
 * Refresh Token (UUID): 長效（7 天），用於更新 Access Token，stateful
 *
 * 這種雙 Token 機制是業界標準做法（OAuth 2.0 也使用此模式）
 */
public record LoginResult(
        String accessToken,
        String refreshToken,
        String username,
        long accessTokenExpiresInMs
) {}
