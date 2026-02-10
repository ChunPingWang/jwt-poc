package com.example.jwtpoc.adapter.out.persistence;

import jakarta.persistence.*;

import java.time.Instant;

/**
 * JPA Entity - Refresh Token 資料庫映射
 * 屬於 Adapter 層，不應洩漏到 Domain 層
 *
 * 資料庫結構：
 * ┌─────────────────────────────────────────┐
 * │ refresh_tokens                           │
 * ├─────────────────────────────────────────┤
 * │ id          BIGINT (PK, auto-increment) │
 * │ token       VARCHAR (unique, not null)   │
 * │ username    VARCHAR (not null)           │
 * │ expiry_date TIMESTAMP (not null)         │
 * │ revoked     BOOLEAN (default false)      │
 * └─────────────────────────────────────────┘
 */
@Entity
@Table(name = "refresh_tokens")
public class RefreshTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(unique = true, nullable = false)
    private String token;

    @Column(nullable = false)
    private String username;

    @Column(nullable = false)
    private Instant expiryDate;

    @Column(nullable = false)
    private boolean revoked = false;

    public RefreshTokenEntity() {}

    public RefreshTokenEntity(String token, String username, Instant expiryDate) {
        this.token = token;
        this.username = username;
        this.expiryDate = expiryDate;
        this.revoked = false;
    }

    // === Getters & Setters ===

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getToken() { return token; }
    public void setToken(String token) { this.token = token; }

    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }

    public Instant getExpiryDate() { return expiryDate; }
    public void setExpiryDate(Instant expiryDate) { this.expiryDate = expiryDate; }

    public boolean isRevoked() { return revoked; }
    public void setRevoked(boolean revoked) { this.revoked = revoked; }
}
