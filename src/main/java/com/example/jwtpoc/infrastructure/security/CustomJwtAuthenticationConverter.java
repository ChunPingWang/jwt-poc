package com.example.jwtpoc.infrastructure.security;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * 自訂 JWT → Authentication 轉換器
 *
 * 標準 OAuth 2.0 Resource Server 預期 JWT 中使用 `scope` 或 `scp` claim，
 * 但本 PoC 的 Token 使用自訂的 `role` claim。
 *
 * 此轉換器將 `role` claim 映射為 Spring Security 的 ROLE_xxx GrantedAuthority，
 * 使 @PreAuthorize("hasRole('ADMIN')") 等授權註解能正常運作。
 *
 * 對比：
 * - 自訂 JwtAuthenticationFilter: 手動解析 Token、設定 SecurityContext
 * - OAuth2 Resource Server + 此 Converter: Spring 自動解析，只需自訂 claim 映射
 */
@Component
public class CustomJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        String role = jwt.getClaimAsString("role");
        List<SimpleGrantedAuthority> authorities = List.of(
                new SimpleGrantedAuthority("ROLE_" + role)
        );
        return new JwtAuthenticationToken(jwt, authorities, jwt.getSubject());
    }
}
