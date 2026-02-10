package com.example.jwtpoc.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Token 更新請求 DTO
 */
public record RefreshTokenRequest(
        @NotBlank(message = "Refresh token is required")
        String refreshToken
) {}
