package com.example.jwtpoc.domain.model;

import java.time.Instant;

/**
 * 領域模型 - Refresh Token
 * 純 POJO，不依賴任何框架
 *
 * 為什麼需要 Refresh Token？
 * ─────────────────────────────────────────
 * Access Token (JWT) 是短效的（如 1 小時），過期後使用者需要重新認證。
 * Refresh Token 是長效的（如 7 天），用來「更新」Access Token，
 * 讓使用者不必反覆輸入帳密。
 *
 * 為什麼用 opaque UUID 而非 JWT？
 * ─────────────────────────────────────────
 * Refresh Token 存在資料庫中（stateful），伺服器可以隨時撤銷。
 * 這比 stateless JWT 更安全，因為被盜的 Refresh Token 可以被作廢。
 */
public class RefreshToken {

    private Long id;
    private String token;        // opaque UUID string
    private String username;     // 關聯的使用者
    private Instant expiryDate;  // 過期時間
    private boolean revoked;     // 是否已被撤銷

    public RefreshToken() {}

    public RefreshToken(String token, String username, Instant expiryDate) {
        this.token = token;
        this.username = username;
        this.expiryDate = expiryDate;
        this.revoked = false;
    }

    // === Domain Behavior ===

    /** 檢查 Token 是否已過期 */
    public boolean isExpired() {
        return Instant.now().isAfter(this.expiryDate);
    }

    /** 檢查 Token 是否仍然有效（未過期且未撤銷） */
    public boolean isValid() {
        return !isExpired() && !isRevoked();
    }

    /** 撤銷此 Token（登出時使用） */
    public void revoke() {
        this.revoked = true;
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
