package com.example.jwtpoc.infrastructure.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.example.jwtpoc.application.port.out.TokenBlacklistRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * JWT 認證過濾器
 *
 * 對應圖中 Step 6 & 7:
 *   6. Request + Cookie (Bearer Token in Authorization Header)
 *   7. Verify JWT
 *
 * 每個 HTTP 請求都會經過此 Filter：
 *   1. 從 Header 提取 Token
 *   2. 驗證 Token 簽章 & 有效期
 *   3. 設定 Spring Security Context
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String BEARER_PREFIX = "Bearer ";

    private final JwtTokenProvider jwtTokenProvider;
    private final TokenBlacklistRepository tokenBlacklistRepository;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider,
                                   TokenBlacklistRepository tokenBlacklistRepository) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.tokenBlacklistRepository = tokenBlacklistRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // Step 6: 從 Request Header 提取 JWT
        String token = extractToken(request);

        if (token != null && jwtTokenProvider.validateToken(token)) {
            // 檢查 Token 是否已被列入黑名單（登出後撤銷）
            String jti = jwtTokenProvider.getJtiFromToken(token);
            if (jti != null && tokenBlacklistRepository.isBlacklisted(jti)) {
                log.debug("Token is blacklisted (jti={}), skipping authentication", jti);
            } else {
                // Step 7: 驗證 JWT 成功 → 設定 SecurityContext
                String username = jwtTokenProvider.getUsernameFromToken(token);
                String role = jwtTokenProvider.getRoleFromToken(token);

                var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));

                var authentication = new UsernamePasswordAuthenticationToken(
                        username, null, authorities);

                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("JWT authenticated user: {}, role: {}", username, role);
            }
        }

        // 繼續 Filter Chain
        filterChain.doFilter(request, response);
    }

    /**
     * 從 Authorization Header 提取 Bearer Token
     *
     * 格式: Authorization: Bearer eyJhbGciOiJIUzI1NiIs...
     */
    private String extractToken(HttpServletRequest request) {
        String bearerToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(BEARER_PREFIX)) {
            return bearerToken.substring(BEARER_PREFIX.length());
        }
        return null;
    }
}
