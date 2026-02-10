package com.example.jwtpoc;

import com.example.jwtpoc.adapter.in.web.dto.LoginRequest;
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
 * JWT 完整流程整合測試
 *
 * 驗證圖中所有 Step 1-8 的流程
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class JwtFlowIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    private static String jwtToken;

    @Test
    @Order(1)
    @DisplayName("Step 1-2: 註冊新使用者")
    void shouldRegisterUser() throws Exception {
        var request = new UserRegistrationRequest("testuser", "password123", "USER");

        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.message").value("User registered successfully"));
    }

    @Test
    @Order(2)
    @DisplayName("Step 1-4: 登入取得 JWT Token")
    void shouldLoginAndGetJwt() throws Exception {
        var request = new LoginRequest("testuser", "password123");

        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.username").value("testuser"))
                .andReturn();

        // 儲存 Token 供後續測試使用
        var response = objectMapper.readTree(result.getResponse().getContentAsString());
        jwtToken = response.get("token").asText();

        // 驗證 JWT 結構: header.payload.signature
        String[] parts = jwtToken.split("\\.");
        Assertions.assertEquals(3, parts.length, "JWT should have 3 parts separated by dots");
    }

    @Test
    @Order(3)
    @DisplayName("Step 5-8: 使用 JWT 存取受保護資源")
    void shouldAccessProtectedResourceWithJwt() throws Exception {
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.username").value("testuser"))
                .andExpect(jsonPath("$.message").exists());
    }

    @Test
    @Order(4)
    @DisplayName("無 Token 存取受保護資源應回傳 401/403")
    void shouldRejectAccessWithoutJwt() throws Exception {
        mockMvc.perform(get("/api/protected/profile"))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(5)
    @DisplayName("無效 Token 應被拒絕")
    void shouldRejectInvalidJwt() throws Exception {
        mockMvc.perform(get("/api/protected/profile")
                        .header("Authorization", "Bearer invalid.token.here"))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(6)
    @DisplayName("非 ADMIN 角色不能存取管理端點")
    void shouldDenyNonAdminAccess() throws Exception {
        mockMvc.perform(get("/api/protected/admin")
                        .header("Authorization", "Bearer " + jwtToken))
                .andExpect(status().isForbidden());
    }

    @Test
    @Order(7)
    @DisplayName("ADMIN 角色可以存取管理端點")
    void shouldAllowAdminAccess() throws Exception {
        // 註冊 Admin
        var registerReq = new UserRegistrationRequest("admin", "admin123", "ADMIN");
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerReq)))
                .andExpect(status().isCreated());

        // Admin 登入
        var loginReq = new LoginRequest("admin", "admin123");
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginReq)))
                .andExpect(status().isOk())
                .andReturn();

        var response = objectMapper.readTree(result.getResponse().getContentAsString());
        String adminToken = response.get("token").asText();

        // 使用 Admin Token 存取
        mockMvc.perform(get("/api/protected/admin")
                        .header("Authorization", "Bearer " + adminToken))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Welcome Admin! This is an admin-only resource."));
    }
}
