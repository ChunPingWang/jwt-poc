package com.example.jwtpoc.adapter.in.web.dto;

/**
 * 登入回應 DTO
 * 包含 JWT Token 和相關資訊
 */
public record LoginResponse(
        String token,
        String tokenType,
        String username,
        long expiresInMs
) {
    public LoginResponse(String token, String username, long expiresInMs) {
        this(token, "Bearer", username, expiresInMs);
    }
}
