package com.example.jwtpoc.application.port.in;

import com.example.jwtpoc.domain.model.User;

/**
 * 入站埠 - 認證用例
 * 定義應用程式對外提供的認證能力
 */
public interface AuthUseCase {

    /**
     * 使用者登入，回傳 JWT Token
     */
    String login(String username, String password);

    /**
     * 使用者註冊
     */
    User register(String username, String password, String role);
}
