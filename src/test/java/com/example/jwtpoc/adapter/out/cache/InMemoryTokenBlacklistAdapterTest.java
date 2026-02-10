package com.example.jwtpoc.adapter.out.cache;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * In-Memory Token 黑名單單元測試
 */
class InMemoryTokenBlacklistAdapterTest {

    private final InMemoryTokenBlacklistAdapter adapter =
            new InMemoryTokenBlacklistAdapter(60000);

    @Test
    @DisplayName("加入黑名單後應回傳 true")
    void shouldBlacklistAndCheckToken() {
        adapter.blacklist("test-jti-1", 10000);
        assertTrue(adapter.isBlacklisted("test-jti-1"));
    }

    @Test
    @DisplayName("未加入黑名單的 jti 應回傳 false")
    void shouldReturnFalseForUnknown() {
        assertFalse(adapter.isBlacklisted("unknown-jti"));
    }

    @Test
    @DisplayName("TTL 過期後應回傳 false")
    void shouldExpireAfterTtl() throws InterruptedException {
        adapter.blacklist("expiring-jti", 100); // 100ms TTL
        assertTrue(adapter.isBlacklisted("expiring-jti"));

        Thread.sleep(150); // 等待過期
        assertFalse(adapter.isBlacklisted("expiring-jti"));
    }
}
