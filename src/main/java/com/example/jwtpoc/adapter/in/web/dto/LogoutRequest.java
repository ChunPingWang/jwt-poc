package com.example.jwtpoc.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * 登出請求 DTO
 */
public record LogoutRequest(
        @NotBlank(message = "Refresh token is required")
        String refreshToken
) {}
