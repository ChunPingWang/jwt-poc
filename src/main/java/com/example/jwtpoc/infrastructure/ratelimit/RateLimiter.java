package com.example.jwtpoc.infrastructure.ratelimit;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.util.Deque;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * 滑動窗口速率限制器
 *
 * 使用 ConcurrentHashMap + Deque 實作 Sliding Window 演算法：
 * - 記錄每個 key（IP 地址）的請求時間戳
 * - 在時間窗口內超過最大次數則拒絕
 *
 * 生產環境建議使用 Redis + Lua Script 實現分散式速率限制
 */
@Component
public class RateLimiter {

    private final ConcurrentHashMap<String, Deque<Long>> requestLog = new ConcurrentHashMap<>();
    private final int maxAttempts;
    private final long windowMs;

    public RateLimiter(
            @Value("${rate-limit.max-attempts:5}") int maxAttempts,
            @Value("${rate-limit.window-ms:900000}") long windowMs) {
        this.maxAttempts = maxAttempts;
        this.windowMs = windowMs;
    }

    /**
     * 檢查請求是否被允許，並記錄時間戳
     *
     * @param key 識別 key（通常是 IP 地址）
     * @return true 表示允許，false 表示超過限制
     */
    public boolean isAllowed(String key) {
        long now = System.currentTimeMillis();
        Deque<Long> timestamps = requestLog.computeIfAbsent(key, k -> new ConcurrentLinkedDeque<>());

        // 清除過期的時間戳
        while (!timestamps.isEmpty() && now - timestamps.peekFirst() > windowMs) {
            timestamps.pollFirst();
        }

        if (timestamps.size() < maxAttempts) {
            timestamps.addLast(now);
            return true;
        }

        return false;
    }

    /**
     * 取得距離最早記錄過期的剩餘毫秒數
     *
     * @param key 識別 key
     * @return 需要等待的毫秒數，如果無記錄則回傳 0
     */
    public long getRetryAfterMs(String key) {
        Deque<Long> timestamps = requestLog.get(key);
        if (timestamps == null || timestamps.isEmpty()) {
            return 0;
        }
        long now = System.currentTimeMillis();
        long oldest = timestamps.peekFirst();
        long retryAfter = windowMs - (now - oldest);
        return Math.max(retryAfter, 0);
    }
}
