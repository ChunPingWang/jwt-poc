package com.example.jwtpoc.infrastructure.ratelimit;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * 速率限制過濾器 — 僅套用於 POST /api/auth/login
 *
 * 防止暴力破解登入攻擊：
 * - 按 IP 地址限制登入嘗試次數
 * - 超過限制回傳 HTTP 429 Too Many Requests
 * - 包含 Retry-After header 告知客戶端等待時間
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    private final RateLimiter rateLimiter;
    private final ObjectMapper objectMapper;

    public RateLimitFilter(RateLimiter rateLimiter, ObjectMapper objectMapper) {
        this.rateLimiter = rateLimiter;
        this.objectMapper = objectMapper;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // 僅對 POST /api/auth/login 套用速率限制
        return !("POST".equalsIgnoreCase(request.getMethod())
                && "/api/auth/login".equals(request.getRequestURI()));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String clientIp = extractClientIp(request);

        if (!rateLimiter.isAllowed(clientIp)) {
            long retryAfterMs = rateLimiter.getRetryAfterMs(clientIp);
            long retryAfterSeconds = (retryAfterMs + 999) / 1000; // 無條件進位到秒

            log.warn("Rate limit exceeded for IP: {}, retry after: {}s", clientIp, retryAfterSeconds);

            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));

            Map<String, Object> body = Map.of(
                    "error", "Too Many Requests",
                    "message", "Login attempts exceeded. Please try again later.",
                    "retryAfterSeconds", retryAfterSeconds
            );
            objectMapper.writeValue(response.getOutputStream(), body);
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * 提取客戶端 IP 地址
     *
     * 優先使用 X-Forwarded-For header（反向代理場景），
     * 否則使用 request.getRemoteAddr()
     */
    private String extractClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            // X-Forwarded-For 可能包含多個 IP，取第一個（原始客戶端）
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}
