package com.example.jwtpoc.infrastructure.security;

import com.example.jwtpoc.infrastructure.ratelimit.RateLimitFilter;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.security.interfaces.RSAPublicKey;

/**
 * OAuth 2.0 Resource Server 配置
 *
 * 僅在 "oauth2" Profile 啟動時生效，展示標準 Spring Security OAuth 2.0
 * Resource Server 模式如何驗證 JWT。
 *
 * 對比自訂 JwtAuthenticationFilter 方式：
 *
 * ┌─────────────────────────────────────────────────────────────────┐
 * │ 自訂 Filter（預設模式）                                         │
 * │ - 手動提取 Authorization header                                 │
 * │ - 手動呼叫 JJWT 驗證簽章                                       │
 * │ - 手動從 claims 建立 Authentication                             │
 * │ - 適合學習 JWT 底層運作                                         │
 * ├─────────────────────────────────────────────────────────────────┤
 * │ OAuth 2.0 Resource Server（oauth2 模式）                        │
 * │ - Spring 自動處理 Token 提取和驗證                               │
 * │ - 使用 RSA 公鑰直接驗證（或透過 JWKS 端點動態取得）               │
 * │ - 只需自訂 claim → authority 映射                               │
 * │ - 適合生產環境、標準 OAuth 2.0 整合                              │
 * └─────────────────────────────────────────────────────────────────┘
 *
 * 本 PoC 使用本地 RSA 公鑰建立 JwtDecoder，因為 Authorization Server
 * 和 Resource Server 在同一 JVM 中。
 *
 * 生產環境中，Authorization Server 和 Resource Server 通常分開部署，
 * Resource Server 會透過 jwkSetUri 指向 Authorization Server 的 JWKS 端點：
 *   spring.security.oauth2.resourceserver.jwt.jwk-set-uri=https://auth-server/.well-known/jwks.json
 *
 * 啟動方式：
 *   mvn spring-boot:run -Dspring-boot.run.profiles=oauth2
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@Profile("oauth2")
public class OAuth2ResourceServerConfig {

    private final CustomJwtAuthenticationConverter jwtAuthenticationConverter;
    private final RateLimitFilter rateLimitFilter;
    private final JwtTokenProvider jwtTokenProvider;

    public OAuth2ResourceServerConfig(CustomJwtAuthenticationConverter jwtAuthenticationConverter,
                                       RateLimitFilter rateLimitFilter,
                                       JwtTokenProvider jwtTokenProvider) {
        this.jwtAuthenticationConverter = jwtAuthenticationConverter;
        this.rateLimitFilter = rateLimitFilter;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())

            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/.well-known/**").permitAll()
                .requestMatchers("/api/protected/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )

            .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))

            // 速率限制過濾器
            .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)

            // OAuth 2.0 Resource Server：使用 RSA 公鑰驗證 JWT
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt
                    .decoder(jwtDecoder())
                    .jwtAuthenticationConverter(jwtAuthenticationConverter)
                )
            );

        return http.build();
    }

    /**
     * JwtDecoder — 使用本地 RSA 公鑰驗證 JWT 簽名
     *
     * 生產環境替代方案：
     *   NimbusJwtDecoder.withJwkSetUri("https://auth-server/.well-known/jwks.json").build()
     */
    @Bean
    public JwtDecoder jwtDecoder() {
        RSAPublicKey publicKey = (RSAPublicKey) jwtTokenProvider.getPublicKey();
        return NimbusJwtDecoder.withPublicKey(publicKey).build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
