package com.example.jwtpoc.adapter.out.persistence;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;

import java.time.Instant;
import java.util.Optional;

/**
 * Spring Data JPA Repository - Refresh Token
 * 框架層實作，不直接暴露給 Domain
 */
public interface RefreshTokenJpaRepository extends JpaRepository<RefreshTokenEntity, Long> {

    Optional<RefreshTokenEntity> findByToken(String token);

    @Modifying
    @Query("UPDATE RefreshTokenEntity r SET r.revoked = true WHERE r.username = :username AND r.revoked = false")
    void revokeAllByUsername(String username);

    @Modifying
    @Query("DELETE FROM RefreshTokenEntity r WHERE r.expiryDate < :now")
    void deleteByExpiryDateBefore(Instant now);
}
