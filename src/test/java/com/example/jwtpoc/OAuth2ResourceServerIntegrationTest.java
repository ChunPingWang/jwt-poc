package com.example.jwtpoc;

import com.example.jwtpoc.adapter.in.web.dto.LoginRequest;
import com.example.jwtpoc.adapter.in.web.dto.UserRegistrationRequest;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * OAuth 2.0 Resource Server 整合測試
 *
 * 使用 oauth2 Profile，驗證 Spring OAuth 2.0 Resource Server
 * 能透過 RSA 公鑰驗證 JWT（與 JWKS 端點使用相同的公鑰）。
 *
 * 注意：本 PoC 中 Authorization Server 和 Resource Server 在同一 JVM，
 * 因此使用本地公鑰配置 JwtDecoder。
 * 生產環境中 Resource Server 會透過 jwkSetUri 從 Authorization Server 取得公鑰。
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("oauth2")
@TestPropertySource(properties = {
        "jwt.algorithm=RS256"
})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class OAuth2ResourceServerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static String accessToken;

    @Test
    @Order(1)
    @DisplayName("註冊並登入取得 JWT（由本地 JwtTokenProvider 簽發）")
    void shouldRegisterAndLogin() throws Exception {
        var registerReq = new UserRegistrationRequest("oauth2user", "password123", "USER");
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerReq)))
                .andExpect(status().isCreated());

        var loginReq = new LoginRequest("oauth2user", "password123");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andReturn();

        var response = objectMapper.readTree(result.getResponse().getContentAsString());
        accessToken = response.get("accessToken").asText();
    }

    @Test
    @Order(2)
    @DisplayName("OAuth 2.0 Resource Server 應透過 RSA 公鑰驗證 JWT")
    void shouldValidateJwtViaOAuth2ResourceServer() throws Exception {
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("oauth2user"));
    }

    @Test
    @Order(3)
    @DisplayName("無效 JWT 應被拒絕")
    void shouldRejectInvalidJwt() throws Exception {
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer invalid.token.here"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @Order(4)
    @DisplayName("role claim 應正確映射為 Spring Security Authority")
    void shouldMapRoleClaimToAuthority() throws Exception {
        // USER 角色不能存取 ADMIN 端點
        mockMvc.perform(get("/api/protected/admin")
                        .header("Authorization", "Bearer " + accessToken))
                .andExpect(status().isForbidden());

        // 註冊 ADMIN 用戶
        var adminReq = new UserRegistrationRequest("oauth2admin", "password123", "ADMIN");
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(adminReq)))
                .andExpect(status().isCreated());

        var loginReq = new LoginRequest("oauth2admin", "password123");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andReturn();

        var response = objectMapper.readTree(result.getResponse().getContentAsString());
        String adminToken = response.get("accessToken").asText();

        // ADMIN 角色可以存取 ADMIN 端點
        mockMvc.perform(get("/api/protected/admin")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk());
    }
}
