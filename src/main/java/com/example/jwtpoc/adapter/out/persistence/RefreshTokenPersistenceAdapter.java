package com.example.jwtpoc.adapter.out.persistence;

import com.example.jwtpoc.application.port.out.RefreshTokenRepository;
import com.example.jwtpoc.domain.model.RefreshToken;

import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.Optional;

/**
 * 持久化適配器 - 實作 Refresh Token 出站埠
 *
 * 負責 Domain Model ↔ JPA Entity 的轉換
 * 遵循 Dependency Inversion: Domain 定義介面，Adapter 實作
 */
@Component
public class RefreshTokenPersistenceAdapter implements RefreshTokenRepository {

    private final RefreshTokenJpaRepository jpaRepository;

    public RefreshTokenPersistenceAdapter(RefreshTokenJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public Optional<RefreshToken> findByToken(String token) {
        return jpaRepository.findByToken(token).map(this::toDomain);
    }

    @Override
    public RefreshToken save(RefreshToken refreshToken) {
        RefreshTokenEntity entity = toEntity(refreshToken);
        RefreshTokenEntity saved = jpaRepository.save(entity);
        return toDomain(saved);
    }

    @Override
    @Transactional
    public void revokeAllByUsername(String username) {
        jpaRepository.revokeAllByUsername(username);
    }

    @Override
    @Transactional
    public void deleteExpiredTokens() {
        jpaRepository.deleteByExpiryDateBefore(Instant.now());
    }

    // === Mapper Methods ===

    private RefreshToken toDomain(RefreshTokenEntity entity) {
        RefreshToken token = new RefreshToken(entity.getToken(), entity.getUsername(), entity.getExpiryDate());
        token.setId(entity.getId());
        token.setRevoked(entity.isRevoked());
        return token;
    }

    private RefreshTokenEntity toEntity(RefreshToken domain) {
        RefreshTokenEntity entity = new RefreshTokenEntity(domain.getToken(), domain.getUsername(), domain.getExpiryDate());
        entity.setId(domain.getId());
        entity.setRevoked(domain.isRevoked());
        return entity;
    }
}
