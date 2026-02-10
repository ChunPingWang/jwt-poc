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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security 配置
 *
 * 關鍵設計決策：
 * 1. STATELESS Session — JWT 本身攜帶狀態，不需要 Server-side Session
 * 2. 白名單 — /api/auth/** 不需要認證（登入/註冊）
 * 3. JWT Filter — 在 UsernamePasswordAuthenticationFilter 之前注入
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity  // 啟用 @PreAuthorize
@Profile("!oauth2")  // 預設模式；oauth2 Profile 使用 OAuth2ResourceServerConfig
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final RateLimitFilter rateLimitFilter;

    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                          RateLimitFilter rateLimitFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.rateLimitFilter = rateLimitFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // 1. 停用 CSRF（JWT 是 stateless，不需要 CSRF 保護）
            .csrf(csrf -> csrf.disable())

            // 2. Stateless Session（不建立 HttpSession）
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // 3. 路由權限設定
            .authorizeHttpRequests(auth -> auth
                // 公開端點 — 登入、註冊、H2 Console、JWKS
                .requestMatchers("/api/auth/**").permitAll()
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/.well-known/**").permitAll()
                // 管理員端點
                .requestMatchers("/api/protected/admin/**").hasRole("ADMIN")
                // 其餘都需要認證
                .anyRequest().authenticated()
            )

            // 4. H2 Console 需要 frameOptions 設定
            .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()))

            // 5. 注入速率限制過濾器（最先執行，在 JWT 過濾器之前）
            .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)

            // 6. 注入 JWT 過濾器（在速率限制之後、UsernamePasswordAuth 之前）
            .addFilterBefore(jwtAuthenticationFilter,
                    UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
