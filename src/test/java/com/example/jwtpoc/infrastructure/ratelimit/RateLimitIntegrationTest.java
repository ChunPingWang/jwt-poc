package com.example.jwtpoc.infrastructure.ratelimit;

import com.example.jwtpoc.adapter.in.web.dto.LoginRequest;
import com.example.jwtpoc.adapter.in.web.dto.UserRegistrationRequest;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * 速率限制整合測試
 *
 * 使用較小的限制值（3 次 / 10 秒）以便測試
 */
@SpringBootTest
@AutoConfigureMockMvc
@TestPropertySource(properties = {
        "rate-limit.max-attempts=3",
        "rate-limit.window-ms=10000"
})
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class RateLimitIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @Order(1)
    @DisplayName("註冊測試用戶")
    void setup() throws Exception {
        var registerReq = new UserRegistrationRequest("ratelimituser", "password123", "USER");
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerReq)))
                .andExpect(status().isCreated());
    }

    @Test
    @Order(2)
    @DisplayName("超過登入嘗試次數後應回傳 429")
    void shouldReturn429AfterExceedingLoginAttempts() throws Exception {
        var loginReq = new LoginRequest("ratelimituser", "wrongpassword");
        String body = objectMapper.writeValueAsString(loginReq);

        // 前 3 次應被允許（即使密碼錯誤，速率限制器不檢查結果）
        for (int i = 0; i < 3; i++) {
            mockMvc.perform(post("/api/auth/login")
                            .contentType(MediaType.APPLICATION_JSON)
                            .content(body))
                    .andExpect(status().isUnauthorized());
        }

        // 第 4 次應被速率限制
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    @Order(3)
    @DisplayName("429 回應應包含 Retry-After header")
    void shouldIncludeRetryAfterHeader() throws Exception {
        var loginReq = new LoginRequest("ratelimituser", "wrongpassword");
        String body = objectMapper.writeValueAsString(loginReq);

        // 送出足夠多的請求觸發限制（可能已經有之前測試的記錄）
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/api/auth/login")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(body));
        }

        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.retryAfterSeconds").isNumber())
                .andExpect(jsonPath("$.message").isNotEmpty());
    }

    @Test
    @Order(4)
    @DisplayName("速率限制不應影響其他端點")
    void shouldNotRateLimitOtherEndpoints() throws Exception {
        // GET /api/protected/profile 不應被速率限制（會因無 token 回傳 403，但不是 429）
        for (int i = 0; i < 10; i++) {
            mockMvc.perform(get("/api/protected/profile"))
                    .andExpect(status().isForbidden());
        }
    }
}
