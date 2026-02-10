package com.example.jwtpoc.adapter.out.cache;

import com.example.jwtpoc.application.port.out.TokenBlacklistRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PreDestroy;

import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * In-Memory Token 黑名單適配器
 *
 * 使用 ConcurrentHashMap 儲存已撤銷的 JWT ID (jti) 及其過期時間戳。
 * ScheduledExecutorService 定期清理過期條目，防止記憶體洩漏。
 *
 * 生產環境建議替換為 Redis 實現：
 * - Redis SET with TTL 可自動過期
 * - 支援分散式部署（多實例共享黑名單）
 */
@Component
public class InMemoryTokenBlacklistAdapter implements TokenBlacklistRepository {

    private static final Logger log = LoggerFactory.getLogger(InMemoryTokenBlacklistAdapter.class);

    /** jti → 過期時間戳 (epoch millis) */
    private final ConcurrentHashMap<String, Long> blacklist = new ConcurrentHashMap<>();
    private final ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();

    public InMemoryTokenBlacklistAdapter(
            @Value("${jwt.blacklist.cleanup-interval-ms:60000}") long cleanupIntervalMs) {
        scheduler.scheduleAtFixedRate(this::cleanup, cleanupIntervalMs, cleanupIntervalMs, TimeUnit.MILLISECONDS);
        log.info("Token blacklist initialized (in-memory, cleanup interval: {}ms)", cleanupIntervalMs);
    }

    @Override
    public void blacklist(String jti, long ttlMs) {
        long expiryTimestamp = System.currentTimeMillis() + ttlMs;
        blacklist.put(jti, expiryTimestamp);
        log.debug("Token blacklisted: jti={}, ttl={}ms", jti, ttlMs);
    }

    @Override
    public boolean isBlacklisted(String jti) {
        Long expiry = blacklist.get(jti);
        if (expiry == null) {
            return false;
        }
        // 如果已過期，移除並回傳 false
        if (System.currentTimeMillis() > expiry) {
            blacklist.remove(jti);
            return false;
        }
        return true;
    }

    /** 清理過期的黑名單條目 */
    private void cleanup() {
        long now = System.currentTimeMillis();
        int before = blacklist.size();
        blacklist.entrySet().removeIf(entry -> now > entry.getValue());
        int removed = before - blacklist.size();
        if (removed > 0) {
            log.debug("Token blacklist cleanup: removed {} expired entries, {} remaining",
                    removed, blacklist.size());
        }
    }

    @PreDestroy
    public void shutdown() {
        scheduler.shutdown();
    }
}
