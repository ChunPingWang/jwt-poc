package com.example.jwtpoc.application.service;

import com.example.jwtpoc.application.port.in.AuthUseCase;
import com.example.jwtpoc.application.port.in.LoginResult;
import com.example.jwtpoc.application.port.out.UserRepository;
import com.example.jwtpoc.domain.model.RefreshToken;
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
    private final TokenRefreshService tokenRefreshService;

    public AuthService(UserRepository userRepository,
                       PasswordEncoder passwordEncoder,
                       JwtTokenProvider jwtTokenProvider,
                       TokenRefreshService tokenRefreshService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtTokenProvider = jwtTokenProvider;
        this.tokenRefreshService = tokenRefreshService;
    }

    /**
     * 登入流程：
     * 1. 查詢使用者
     * 2. 驗證密碼
     * 3. 產生 Access Token (JWT) — stateless
     * 4. 產生 Refresh Token (UUID) — stateful, 儲存在資料庫
     */
    @Override
    public LoginResult login(String username, String password) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new RuntimeException("User not found: " + username));

        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new RuntimeException("Invalid password");
        }

        // 產生 JWT — 對應圖中 Step 3: Create & sign JWT
        String accessToken = jwtTokenProvider.generateToken(user.getUsername(), user.getRole());

        // 產生 Refresh Token — 儲存在資料庫，可撤銷
        RefreshToken refreshToken = tokenRefreshService.createRefreshToken(user.getUsername());

        return new LoginResult(
                accessToken,
                refreshToken.getToken(),
                user.getUsername(),
                jwtTokenProvider.getExpirationMs()
        );
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
