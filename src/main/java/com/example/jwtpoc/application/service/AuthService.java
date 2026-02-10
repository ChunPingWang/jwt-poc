package com.example.jwtpoc.application.service;

import com.example.jwtpoc.application.port.in.AuthUseCase;
import com.example.jwtpoc.application.port.out.UserRepository;
import com.example.jwtpoc.domain.model.User;
import com.example.jwtpoc.infrastructure.security.JwtTokenProvider;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * 應用服務 - 編排認證流程
 *
 * 職責：
 * 1. 協調領域物件與基礎設施
 * 2. 不包含業務邏輯（業務邏輯在 Domain 層）
 * 3. 處理交易邊界
 */
@Service
public class AuthService implements AuthUseCase {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtTokenProvider jwtTokenProvider) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    /**
     * 登入流程：
     * 1. 查詢使用者
     * 2. 驗證密碼
     * 3. 產生 JWT Token
     */
    @Override
    public String login(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        // 產生 JWT — 對應圖中 Step 3: Create & sign JWT
        return jwtTokenProvider.generateToken(user.getUsername(), user.getRole());
    }

    /**
     * 註冊流程：
     * 1. 檢查使用者是否已存在
     * 2. 密碼加密
     * 3. 儲存使用者
     */
    @Override
    public User register(String username, String password, String role) {
        if (userRepository.existsByUsername(username)) {
            throw new RuntimeException("Username already exists: " + username);
        }

        User user = new User(username, passwordEncoder.encode(password), role);
        return userRepository.save(user);
    }
}
