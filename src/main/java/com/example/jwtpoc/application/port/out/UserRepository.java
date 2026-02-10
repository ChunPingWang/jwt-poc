package com.example.jwtpoc.application.port.out;

import com.example.jwtpoc.domain.model.User;

import java.util.Optional;

/**
 * 出站埠 - 使用者儲存庫
 * 領域層定義介面，基礎設施層實作
 */
public interface UserRepository {

    Optional<User> findByUsername(String username);

    User save(User user);

    boolean existsByUsername(String username);
}
