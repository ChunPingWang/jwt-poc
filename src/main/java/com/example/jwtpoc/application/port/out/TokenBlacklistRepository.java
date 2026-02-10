package com.example.jwtpoc.application.port.out;

/**
 * 出站埠 - Token 黑名單儲存庫
 *
 * 用於在登出時撤銷 Access Token (JWT)。
 * 透過記錄 JWT 的 jti (JWT ID) claim 來標記已撤銷的 Token。
 *
 * PoC 使用 In-Memory 實現；生產環境建議使用 Redis 以支援分散式部署。
 */
public interface TokenBlacklistRepository {

    /**
     * 將 Token 加入黑名單
     *
     * @param jti  JWT ID (唯一識別碼)
     * @param ttlMs 存活時間（毫秒），對應 Token 的剩餘有效期
     */
    void blacklist(String jti, long ttlMs);

    /**
     * 檢查 Token 是否已被列入黑名單
     *
     * @param jti JWT ID
     * @return true 表示已被撤銷
     */
    boolean isBlacklisted(String jti);
}
