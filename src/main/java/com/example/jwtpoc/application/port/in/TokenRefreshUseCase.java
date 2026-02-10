package com.example.jwtpoc.application.port.in;

/**
 * 入站埠 - Token 更新用例
 *
 * 與 AuthUseCase 分離，遵循介面隔離原則 (ISP)：
 * - AuthUseCase: 登入、註冊（認證身份）
 * - TokenRefreshUseCase: Token 更新、登出（管理 Token 生命週期）
 */
public interface TokenRefreshUseCase {

    /**
     * 使用 Refresh Token 取得新的 Access Token + Refresh Token
     *
     * Token Rotation（輪替）策略：
     * 每次使用 Refresh Token 時，舊的會被撤銷，發出全新的一對 Token。
     * 這樣如果 Refresh Token 被盜，攻擊者和使用者會「競爭」使用，
     * 伺服器可以偵測到異常並撤銷所有 Token。
     */
    TokenPair refresh(String refreshToken);

    /**
     * 登出 - 撤銷 Refresh Token 並將 Access Token 加入黑名單
     *
     * @param refreshToken Refresh Token
     * @param accessToken  Access Token (JWT)，將被加入黑名單
     */
    void logout(String refreshToken, String accessToken);

    /**
     * 回傳值：一對新的 Token
     */
    record TokenPair(String accessToken, String refreshToken, long accessTokenExpiresInMs) {}
}
