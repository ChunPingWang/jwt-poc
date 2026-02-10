package com.example.jwtpoc.adapter.in.web.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * 登入請求 DTO
 */
public record LoginRequest(
        @NotBlank(message = "Username is required")
        String username,

        @NotBlank(message = "Password is required")
        String password
) {}
