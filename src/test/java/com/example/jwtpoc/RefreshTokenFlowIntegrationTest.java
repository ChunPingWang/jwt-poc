package com.example.jwtpoc;

import com.example.jwtpoc.adapter.in.web.dto.LoginRequest;
import com.example.jwtpoc.adapter.in.web.dto.LogoutRequest;
import com.example.jwtpoc.adapter.in.web.dto.RefreshTokenRequest;
import com.example.jwtpoc.adapter.in.web.dto.UserRegistrationRequest;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Refresh Token 完整流程整合測試
 *
 * 測試 Token Rotation、登出、以及 Refresh Token 生命週期
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RefreshTokenFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static String accessToken;
    private static String refreshToken;

    @Test
    @Order(1)
    @DisplayName("註冊並登入，取得 Access Token 和 Refresh Token")
    void shouldRegisterAndLoginWithRefreshToken() throws Exception {
        // 註冊
        var registerReq = new UserRegistrationRequest("refreshuser", "password123", "USER");
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerReq)))
                .andExpect(status().isCreated());

        // 登入
        var loginReq = new LoginRequest("refreshuser", "password123");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        var response = objectMapper.readTree(result.getResponse().getContentAsString());
        accessToken = response.get("accessToken").asText();
        refreshToken = response.get("refreshToken").asText();
    }

    @Test
    @Order(2)
    @DisplayName("使用 Refresh Token 取得新的 Token 對 (Token Rotation)")
    void shouldRefreshTokenSuccessfully() throws Exception {
        var request = new RefreshTokenRequest(refreshToken);

        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").isNotEmpty())
                .andExpect(jsonPath("$.refreshToken").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andReturn();

        var response = objectMapper.readTree(result.getResponse().getContentAsString());
        String newAccessToken = response.get("accessToken").asText();
        String newRefreshToken = response.get("refreshToken").asText();

        // Token Rotation: 新的 Refresh Token 應與舊的不同
        Assertions.assertNotEquals(refreshToken, newRefreshToken,
                "Token rotation should issue a new refresh token");

        // 更新 token 供後續測試使用
        accessToken = newAccessToken;
        refreshToken = newRefreshToken;
    }

    @Test
    @Order(3)
    @DisplayName("新的 Access Token 可以存取受保護資源")
    void shouldAccessProtectedResourceWithRefreshedToken() throws Exception {
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("refreshuser"));
    }

    @Test
    @Order(4)
    @DisplayName("舊的 Refresh Token 在 Rotation 後應被拒絕")
    void shouldRejectOldRefreshTokenAfterRotation() throws Exception {
        // 使用 Order 1 的原始 refresh token（已在 Order 2 被撤銷）
        // 我們需要用當前 refresh token 先做一次 refresh，取得新的，然後用舊的測試
        String oldRefreshToken = refreshToken;

        // 先做一次 refresh 取得新的 token
        var refreshReq = new RefreshTokenRequest(refreshToken);
        MvcResult result = mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(refreshReq)))
                .andExpect(status().isOk())
                .andReturn();

        var response = objectMapper.readTree(result.getResponse().getContentAsString());
        accessToken = response.get("accessToken").asText();
        refreshToken = response.get("refreshToken").asText();

        // 用舊的 refresh token 應被拒絕
        var oldRequest = new RefreshTokenRequest(oldRefreshToken);
        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(oldRequest)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(5)
    @DisplayName("無效的 Refresh Token 應被拒絕")
    void shouldRejectInvalidRefreshToken() throws Exception {
        var request = new RefreshTokenRequest("invalid-random-uuid-token");

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(6)
    @DisplayName("登出成功 - 撤銷 Refresh Token")
    void shouldLogoutSuccessfully() throws Exception {
        var request = new LogoutRequest(refreshToken);

        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out successfully"));
    }

    @Test
    @Order(7)
    @DisplayName("登出後 Refresh Token 應被拒絕")
    void shouldRejectRefreshAfterLogout() throws Exception {
        var request = new RefreshTokenRequest(refreshToken);

        mockMvc.perform(post("/api/auth/refresh")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(8)
    @DisplayName("登出後 Access Token 仍然有效（JWT 是 stateless 的）")
    void shouldStillAccessWithAccessTokenAfterLogout() throws Exception {
        // 這是 JWT 的已知限制：登出只撤銷 Refresh Token，
        // 已發出的 Access Token 仍然有效直到過期
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk());
    }
}
