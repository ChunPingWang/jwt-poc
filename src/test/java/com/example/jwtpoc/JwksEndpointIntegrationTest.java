package com.example.jwtpoc;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * JWKS 端點整合測試
 */
class JwksEndpointIntegrationTest {

    @Nested
    @SpringBootTest
    @AutoConfigureMockMvc
    @TestPropertySource(properties = {"jwt.algorithm=RS256"})
    @DisplayName("RS256 模式")
    class Rs256Mode {

        @Autowired
        private MockMvc mockMvc;

        @Test
        @DisplayName("RS256 模式應回傳 JWKS JSON")
        void shouldReturnJwksJsonWhenRs256() throws Exception {
            mockMvc.perform(get("/.well-known/jwks.json"))
                    .andExpect(status().isOk())
                    .andExpect(content().contentTypeCompatibleWith("application/json"))
                    .andExpect(jsonPath("$.keys").isArray())
                    .andExpect(jsonPath("$.keys[0]").exists());
        }

        @Test
        @DisplayName("JWKS 應包含正確的 key 欄位")
        void shouldContainCorrectKeyFields() throws Exception {
            mockMvc.perform(get("/.well-known/jwks.json"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.keys[0].kid").value("jwt-poc-key-1"))
                    .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                    .andExpect(jsonPath("$.keys[0].use").value("sig"))
                    .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                    .andExpect(jsonPath("$.keys[0].n").isNotEmpty())
                    .andExpect(jsonPath("$.keys[0].e").isNotEmpty());
        }

        @Test
        @DisplayName("JWKS 端點不需要認證即可存取")
        void jwksEndpointShouldBePubliclyAccessible() throws Exception {
            // 不帶 Authorization header 也能存取
            mockMvc.perform(get("/.well-known/jwks.json"))
                    .andExpect(status().isOk());
        }
    }

    @Nested
    @SpringBootTest
    @AutoConfigureMockMvc
    @DisplayName("HS256 模式")
    class Hs256Mode {

        @Autowired
        private MockMvc mockMvc;

        @Test
        @DisplayName("HS256 模式應回傳說明訊息")
        void shouldReturnMessageWhenHs256() throws Exception {
            mockMvc.perform(get("/.well-known/jwks.json"))
                    .andExpect(status().isOk())
                    .andExpect(jsonPath("$.message").exists())
                    .andExpect(jsonPath("$.hint").exists());
        }
    }
}
