package com.example.jwtpoc;

import com.example.jwtpoc.adapter.in.web.dto.LoginRequest;
import com.example.jwtpoc.adapter.in.web.dto.LogoutRequest;
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
 * Token 黑名單整合測試
 *
 * 完整流程：註冊 → 登入 → 存取OK → 登出（黑名單）→ 存取被拒
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class TokenBlacklistIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static String accessToken;
    private static String refreshToken;

    @Test
    @Order(1)
    @DisplayName("註冊並登入取得 Token")
    void shouldRegisterAndLogin() throws Exception {
        var registerReq = new UserRegistrationRequest("blacklistuser", "password123", "USER");
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerReq)))
                .andExpect(status().isCreated());

        var loginReq = new LoginRequest("blacklistuser", "password123");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andReturn();

        var response = objectMapper.readTree(result.getResponse().getContentAsString());
        accessToken = response.get("accessToken").asText();
        refreshToken = response.get("refreshToken").asText();
    }

    @Test
    @Order(2)
    @DisplayName("登出前 Access Token 可以正常存取受保護資源")
    void shouldAccessProtectedResourceBeforeLogout() throws Exception {
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("blacklistuser"));
    }

    @Test
    @Order(3)
    @DisplayName("登出 - Access Token 加入黑名單")
    void shouldLogoutAndBlacklistAccessToken() throws Exception {
        var request = new LogoutRequest(refreshToken);

        mockMvc.perform(post("/api/auth/logout")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request))
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Logged out successfully"));
    }

    @Test
    @Order(4)
    @DisplayName("登出後 Access Token 應被拒絕（黑名單生效）")
    void shouldRejectAccessTokenAfterLogout() throws Exception {
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden());
    }
}
