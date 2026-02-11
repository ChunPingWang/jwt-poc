# JWT (JSON Web Token) 入門教學 — Spring Boot PoC

> 這是一份為初學者設計的 JWT 認證機制教學，搭配 Spring Boot 實作專案，讓你從零開始理解 JWT 的原理與應用。

---

## 目錄

1. [什麼是 JWT？](#什麼是-jwt)
2. [為什麼需要 JWT？](#為什麼需要-jwt)
3. [JWT 的結構](#jwt-的結構)
4. [HS256 vs RS256 簽章演算法](#hs256-vs-rs256-簽章演算法)
5. [認證流程圖解](#認證流程圖解)
6. [Refresh Token 機制](#refresh-token-機制)
7. [進階功能](#進階功能)
   - [Rate Limiting（速率限制）](#rate-limiting速率限制)
   - [Token Blacklist（黑名單）](#token-blacklist黑名單)
   - [JWKS 端點](#jwks-端點)
   - [OAuth 2.0 Resource Server](#oauth-20-resource-server)
8. [專案架構總覽](#專案架構總覽)
9. [核心程式碼逐行解說](#核心程式碼逐行解說)
10. [環境需求與啟動方式](#環境需求與啟動方式)
11. [API 測試教學（手把手）](#api-測試教學手把手)
12. [常見問題 FAQ](#常見問題-faq)
13. [延伸學習資源](#延伸學習資源)

---

## 什麼是 JWT？

**JWT（JSON Web Token）** 是一種開放標準（[RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)），用於在各方之間以 JSON 物件的形式，安全地傳遞資訊。

簡單來說：JWT 就像是一張「數位通行證」，伺服器發給你之後，你每次請求都帶著它，伺服器就知道你是誰。

### 生活比喻

想像你去遊樂園：
1. 你在入口處買票（**登入**）
2. 工作人員給你一個手環（**JWT Token**）
3. 之後你去任何設施，只要出示手環就可以玩（**帶著 Token 發送請求**）
4. 工作人員掃描手環確認有效（**伺服器驗證 Token**）
5. 手環到了晚上就失效（**Token 過期**）

---

## 為什麼需要 JWT？

### 傳統 Session vs JWT

```mermaid
graph TD
    subgraph "傳統 Session 方式"
        direction TB
        C1[Client] -->|"① 登入"| S1[Server]
        S1 -->|"② 建立 Session"| SS[(Session Store)]
        S1 -->|"③ 回傳 Session ID<br/>(Cookie)"| C1
        C1 -->|"④ 帶 Cookie 請求"| S1
        S1 -->|"⑤ 查詢 Session"| SS
    end
```

```mermaid
graph TD
    subgraph "JWT 方式"
        direction TB
        C2[Client] -->|"① 登入"| S2[Server]
        S2 -->|"② 產生 JWT + 簽名"| S2
        S2 -->|"③ 回傳 JWT Token"| C2
        C2 -->|"④ 帶 JWT 請求"| S2
        S2 -->|"⑤ 驗證簽章即可<br/>(不需查 DB)"| S2
    end
```

| 比較項目 | Session | JWT |
|---------|---------|-----|
| 狀態儲存 | 伺服器端（有狀態） | 客戶端（無狀態） |
| 擴展性 | 需要 Session 同步 | 天然支援分散式 |
| 跨域支援 | 依賴 Cookie，跨域困難 | 放在 Header，跨域容易 |
| 效能 | 每次需查詢 Session Store | 直接驗證簽章即可 |

---

## JWT 的結構

一個 JWT Token 由三個部分組成，用 `.` 分隔：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJyZXgiLCJyb2xlIjoiQURNSU4ifQ.xxxSignaturexxx
|_______________________________|  |__________________________________|  |_________________|
           Header                            Payload                        Signature
```

### 1. Header（標頭）

描述這個 Token 使用的演算法和類型。本專案支援兩種演算法：

```json
// HS256（對稱式）
{ "alg": "HS256", "typ": "JWT" }

// RS256（非對稱式）
{ "alg": "RS256", "typ": "JWT" }
```

經過 **Base64Url 編碼** 後變成：`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`

### 2. Payload（負載）

包含要傳遞的資料，稱為 **Claims（聲明）**。

```json
{
  "jti": "550e8400-...",   // JWT ID：唯一識別碼（Token 黑名單用）
  "sub": "rex",            // Subject：使用者名稱
  "role": "ADMIN",         // 自訂聲明：角色
  "iss": "jwt-poc-app",    // Issuer：簽發者
  "iat": 1700000000,       // Issued At：簽發時間
  "exp": 1700003600        // Expiration：過期時間
}
```

> **注意**：Payload 只是 Base64 編碼，**不是加密**！任何人都可以解碼看到內容。所以絕對不要在 Payload 中放密碼等敏感資訊。

### 3. Signature（簽名）

確保 Token 沒有被竄改的關鍵。

```
Signature = HMAC-SHA256(
  base64UrlEncode(Header) + "." + base64UrlEncode(Payload),
  secret密鑰
)
```

如果有人修改了 Header 或 Payload 的任何內容，重新計算出的簽名就不會與原本的匹配，伺服器就能偵測到 Token 被竄改了。

### 完整 Token 結構圖

```mermaid
block-beta
    columns 3
    block:header:1["Header"]
        h1["alg: HS256"]
        h2["typ: JWT"]
    end
    block:payload:1["Payload"]
        p1["sub: rex"]
        p2["role: ADMIN"]
        p3["exp: ..."]
    end
    block:signature:1["Signature"]
        s1["HMAC-SHA256("]
        s2["  header + payload,"]
        s3["  secret )"]
    end

    header --> payload --> signature

    style header fill:#fb923c,color:#fff
    style payload fill:#a78bfa,color:#fff
    style signature fill:#38bdf8,color:#fff
```

```
最終 Token = Base64(Header) + "." + Base64(Payload) + "." + Signature
```

---

## HS256 vs RS256 簽章演算法

本專案支援兩種 JWT 簽章演算法，透過 `jwt.algorithm` 設定值切換。

### 核心差異

```mermaid
graph LR
    subgraph HS256["HS256（對稱式）"]
        direction TB
        SECRET["🔑 同一把 Secret Key"]
        SECRET -->|簽名| SIGN_H["Server 產生 JWT"]
        SECRET -->|驗證| VERIFY_H["Server 驗證 JWT"]
    end

    subgraph RS256["RS256（非對稱式）"]
        direction TB
        PRIV["🔐 Private Key"]
        PUB["🔓 Public Key"]
        PRIV -->|簽名| SIGN_R["Server 產生 JWT"]
        PUB -->|驗證| VERIFY_R["任何服務驗證 JWT"]
    end

    style HS256 fill:#dbeafe,color:#000
    style RS256 fill:#dcfce7,color:#000
    style SECRET fill:#fbbf24,color:#000
    style PRIV fill:#f87171,color:#fff
    style PUB fill:#4ade80,color:#000
```

| 比較 | HS256（對稱式） | RS256（非對稱式） |
|------|---------------|-----------------|
| 密鑰 | 同一把 Secret Key | Private Key + Public Key |
| 簽名方 | 持有 Secret 的服務 | 持有 Private Key 的服務 |
| 驗證方 | 持有 Secret 的服務 | 任何持有 Public Key 的服務 |
| 安全性 | Secret 洩漏 = 可偽造 Token | Public Key 洩漏也無法偽造 |
| 適用場景 | 單一服務 | 微服務架構 |
| 效能 | 較快 | 較慢（RSA 運算） |

### RS256 在微服務中的優勢

```mermaid
graph TD
    subgraph "HS256 的困境"
        AUTH_H["認證服務<br/>🔑 Secret Key"] -->|"必須共享 Secret"| SVC1_H["服務 A<br/>🔑 Secret Key"]
        AUTH_H -->|"必須共享 Secret"| SVC2_H["服務 B<br/>🔑 Secret Key"]
        AUTH_H -->|"必須共享 Secret"| SVC3_H["服務 C<br/>🔑 Secret Key"]
    end

    subgraph "RS256 的解決方案"
        AUTH_R["認證服務<br/>🔐 Private Key"] -->|"只分發 Public Key"| SVC1_R["服務 A<br/>🔓 Public Key"]
        AUTH_R -->|"只分發 Public Key"| SVC2_R["服務 B<br/>🔓 Public Key"]
        AUTH_R -->|"只分發 Public Key"| SVC3_R["服務 C<br/>🔓 Public Key"]
    end

    style AUTH_H fill:#fbbf24,color:#000
    style AUTH_R fill:#4ade80,color:#000
```

> HS256 需要每個服務都持有 Secret Key（任何一個服務被入侵，攻擊者就能偽造 Token）。RS256 只需認證服務持有 Private Key，其他服務只需 Public Key（被入侵也無法偽造）。

### 如何切換演算法

在 `application.properties` 中修改：

```properties
# 切換為 RS256
jwt.algorithm=RS256

# RS256 需要的金鑰檔案（已內建於專案中）
jwt.rsa.private-key-location=keys/private.pem
jwt.rsa.public-key-location=keys/public.pem
```

```properties
# 切換回 HS256（預設）
jwt.algorithm=HS256

# HS256 需要的密鑰
jwt.secret=ThisIsAVeryLongSecretKeyForHS256AlgorithmAtLeast256BitsLong!!
```

> 切換演算法不需要修改任何程式碼 — 只需改設定檔。這是因為 `JwtTokenProvider` 在啟動時根據設定自動選擇對應的簽名/驗證策略。

### 金鑰管理

本專案在 `src/main/resources/keys/` 中附帶了一對 RSA 2048-bit PEM 金鑰供 PoC 使用。

> **重要**：正式環境中**絕對不要**將私鑰提交到版本控制。應使用環境變數、Vault 或 Key Management Service。

如需自行產生新的金鑰對：

```bash
# 產生 RSA 2048-bit 私鑰（PKCS#8 格式，Java 相容）
openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048

# 從私鑰導出公鑰
openssl rsa -in private.pem -pubout -out public.pem
```

---

## 認證流程圖解

### 登入與存取受保護資源

```mermaid
sequenceDiagram
    participant C as 🖥️ Client
    participant S as 🔐 Server
    participant DB as 🗄️ Database

    Note over C,DB: 登入流程 (Steps 1-4)

    C->>S: ① POST /api/auth/login<br/>{username, password}
    S->>DB: 查詢使用者
    DB-->>S: 使用者資料
    S->>S: ② 驗證密碼 (BCrypt)
    S->>S: ③ 產生 Access Token (JWT, 1hr)
    S->>DB: 建立 Refresh Token (UUID, 7d)
    S-->>C: ④ {accessToken, refreshToken}

    Note over C,DB: 存取受保護資源 (Steps 5-8)

    C->>S: ⑤ GET /api/protected/profile<br/>Authorization: Bearer <JWT>
    S->>S: ⑥ 從 Header 提取 JWT
    S->>S: ⑦ 驗證 JWT 簽章 & 有效期
    S-->>C: ⑧ 回傳受保護的資料
```

### 流程步驟說明

| 步驟 | 動作 | 對應程式碼 |
|------|------|----------|
| ① | 使用者發送帳號密碼 | `AuthController.login()` |
| ② | 伺服器驗證帳密 | `AuthService.login()` → `PasswordEncoder.matches()` |
| ③ | 產生 Access Token (JWT) | `JwtTokenProvider.generateToken()` |
| ④ | 回傳雙 Token 給 Client | `LoginResponse` 包含 accessToken + refreshToken |
| ⑤ | Client 帶 Token 請求 | HTTP Header: `Authorization: Bearer <token>` |
| ⑥ | 提取 Token | `JwtAuthenticationFilter.extractToken()` |
| ⑦ | 驗證 Token | `JwtTokenProvider.validateToken()` |
| ⑧ | 回傳資料 | `ProtectedController.getProfile()` |

---

## Refresh Token 機制

### 為什麼需要 Refresh Token？

Access Token (JWT) 的設計是「短效 + 無狀態」，但這帶來一個問題：Token 過期後使用者必須重新輸入帳密登入。

**Refresh Token** 解決了這個問題：

```mermaid
graph LR
    AT["Access Token (JWT)"] --- AT_DESC["短效 (1 小時)<br/>Stateless<br/>用於 API 認證"]
    RT["Refresh Token (UUID)"] --- RT_DESC["長效 (7 天)<br/>Stateful (存 DB)<br/>用於更新 Access Token"]

    style AT fill:#38bdf8,color:#fff
    style RT fill:#4ade80,color:#fff
    style AT_DESC fill:#f0f9ff,color:#1e3a5f
    style RT_DESC fill:#f0fdf4,color:#14532d
```

| 比較 | Access Token | Refresh Token |
|------|-------------|---------------|
| 格式 | JWT (自包含) | UUID (不透明) |
| 儲存 | Client 端 | Server 端 (DB) |
| 有效期 | 1 小時 | 7 天 |
| 用途 | API 認證 | 更新 Access Token |
| 可撤銷 | 不可（stateless） | 可以（stateful） |

### Token Rotation（輪替）流程

每次使用 Refresh Token 時，舊的會被撤銷，發出全新的一對 Token。這樣如果 Refresh Token 被盜，攻擊者和使用者會「競爭」使用，伺服器可以偵測到異常。

```mermaid
sequenceDiagram
    participant C as 🖥️ Client
    participant S as 🔐 Server
    participant DB as 🗄️ Database

    Note over C,DB: Access Token 過期後...

    C->>S: POST /api/auth/refresh<br/>{refreshToken: "uuid-old"}
    S->>DB: 查詢 Refresh Token
    DB-->>S: Token 資料
    S->>S: 驗證：未過期 & 未撤銷？

    alt Token 有效
        S->>DB: 撤銷舊 Refresh Token
        S->>S: 產生新 Access Token (JWT)
        S->>DB: 建立新 Refresh Token (UUID)
        S-->>C: ✅ {new accessToken, new refreshToken}
    else Token 無效（過期/已撤銷）
        S-->>C: ❌ 401 Unauthorized
        Note over C: 需要重新登入
    end
```

### Refresh Token 生命週期

```mermaid
stateDiagram-v2
    [*] --> Active : 登入 / Token Rotation
    Active --> Revoked : 登出 (logout)
    Active --> Revoked : Token Rotation (舊 Token)
    Active --> Expired : 超過 7 天
    Revoked --> [*]
    Expired --> [*]

    note right of Active : 可用於更新 Access Token
    note right of Revoked : 已被撤銷，無法使用
```

### 登出流程

```mermaid
graph TD
    LOGOUT["POST /api/auth/logout<br/>+ Authorization: Bearer JWT"] --> REVOKE["撤銷 Refresh Token ✅"]
    LOGOUT --> BLACKLIST["Access Token 加入黑名單 ✅"]

    BLACKLIST --> DETAIL["JwtAuthenticationFilter 檢查黑名單<br/>已撤銷的 Token 無法通過驗證"]
    BLACKLIST --> TTL["黑名單條目的 TTL = Token 剩餘有效期<br/>過期後自動清理，不佔用記憶體"]

    style REVOKE fill:#4ade80,color:#000
    style BLACKLIST fill:#4ade80,color:#000
    style DETAIL fill:#f0fdf4,color:#14532d
    style TTL fill:#f0fdf4,color:#14532d
```

> Token Blacklist 解決了 JWT stateless 的已知限制。詳見 [Token Blacklist（黑名單）](#token-blacklist黑名單) 章節。

---

## 進階功能

本專案實作了 4 項 JWT 安全進階功能，展示真實世界的 JWT 安全模式。

### Rate Limiting（速率限制）

防止暴力破解登入攻擊，按 IP 地址限制登入嘗試次數。

```mermaid
sequenceDiagram
    participant C as 🖥️ Client
    participant RL as 🚦 RateLimitFilter
    participant S as 🔐 Server

    C->>RL: POST /api/auth/login (第 1~5 次)
    RL->>S: 未超過限制，放行
    S-->>C: 200 OK / 401 Unauthorized

    C->>RL: POST /api/auth/login (第 6 次)
    RL-->>C: 429 Too Many Requests<br/>Retry-After: 900
```

**設計要點**：
- **滑動窗口演算法**：使用 `ConcurrentHashMap<IP, Deque<Timestamp>>` 記錄請求時間
- **僅套用於登入端點**：`shouldNotFilter()` 確保其他 API 不受影響
- **IP 提取**：優先使用 `X-Forwarded-For`（反向代理場景），否則用 `remoteAddr`
- **可配置**：透過 `rate-limit.max-attempts`（預設 5 次）和 `rate-limit.window-ms`（預設 15 分鐘）

```properties
# application.properties
rate-limit.max-attempts=5
rate-limit.window-ms=900000
```

> 生產環境建議使用 Redis + Lua Script 實現分散式速率限制。

---

### Token Blacklist（黑名單）

解決 JWT stateless 的已知限制：登出時將 Access Token 加入黑名單，使其立即失效。

```mermaid
sequenceDiagram
    participant C as 🖥️ Client
    participant F as 🔍 JwtAuthFilter
    participant BL as 🚫 Blacklist
    participant S as 🔐 Server

    Note over C,S: 登出流程
    C->>S: POST /api/auth/logout<br/>Authorization: Bearer JWT
    S->>S: 撤銷 Refresh Token
    S->>BL: 加入黑名單<br/>(jti, 剩餘TTL)
    S-->>C: 200 Logged out

    Note over C,S: 登出後存取
    C->>F: GET /api/protected/profile<br/>Authorization: Bearer JWT
    F->>BL: 檢查 jti 是否在黑名單？
    BL-->>F: 是 → 已撤銷
    F-->>C: 403 Forbidden
```

**設計要點**：
- **jti Claim**：每個 JWT 包含唯一的 `jti`（JWT ID，UUID），用於識別 Token
- **TTL 自動過期**：黑名單條目的存活時間 = Token 的剩餘有效期，過期後自動清理
- **In-Memory 儲存**：`ConcurrentHashMap<jti, expiryTimestamp>` + `ScheduledExecutorService` 定期清理
- **六角形架構**：`TokenBlacklistRepository`（出站埠）→ `InMemoryTokenBlacklistAdapter`（適配器）

```mermaid
graph LR
    JWT["JWT Token"] --> JTI["jti: uuid-abc-123"]
    JTI --> CHECK{"在黑名單中？"}
    CHECK -->|否| AUTH["設定 SecurityContext ✅"]
    CHECK -->|是| REJECT["跳過認證 ❌"]

    style JWT fill:#38bdf8,color:#fff
    style AUTH fill:#4ade80,color:#000
    style REJECT fill:#f87171,color:#fff
```

> 生產環境建議替換為 Redis 實現（`SET jti EX ttl`），支援分散式部署。

---

### JWKS 端點

**JWKS（JSON Web Key Set）** 是 OpenID Connect / OAuth 2.0 的標準協議，讓資源伺服器可以動態取得簽名公鑰。

```mermaid
sequenceDiagram
    participant RS as 🔐 Resource Server
    participant JWKS as 📋 JWKS Endpoint
    participant AS as 🏛️ Auth Server

    RS->>JWKS: GET /.well-known/jwks.json
    JWKS-->>RS: {"keys": [{"kty":"RSA", "kid":"jwt-poc-key-1", ...}]}
    RS->>RS: 使用公鑰驗證 JWT 簽名
```

**端點**：`GET /.well-known/jwks.json`

- **RS256 模式**：回傳 JWK Set JSON，包含 RSA 公鑰的 `kid`、`kty`、`use`、`alg`、`n`、`e` 欄位
- **HS256 模式**：回傳說明訊息（JWKS 需要非對稱金鑰）
- **公開存取**：不需要認證即可取得

回應範例（RS256 模式）：
```json
{
  "keys": [{
    "kty": "RSA",
    "use": "sig",
    "alg": "RS256",
    "kid": "jwt-poc-key-1",
    "n": "0vx7agoebGcQSuu...",
    "e": "AQAB"
  }]
}
```

> JWKS 使用 [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt) 函式庫將 `RSAPublicKey` 轉換為標準 JWK 格式。

---

### OAuth 2.0 Resource Server

展示標準 Spring Security OAuth 2.0 Resource Server 模式，透過 `@Profile("oauth2")` 啟用。

```mermaid
graph TB
    subgraph DEFAULT["預設模式（自訂 Filter）"]
        direction LR
        REQ1["Request"] --> RATE1["RateLimitFilter"]
        RATE1 --> JWT1["JwtAuthenticationFilter<br/>手動提取 & 驗證 JWT<br/>手動建立 Authentication"]
        JWT1 --> CTRL1["Controller"]
    end

    subgraph OAUTH2["OAuth2 模式（Spring 標準）"]
        direction LR
        REQ2["Request"] --> RATE2["RateLimitFilter"]
        RATE2 --> SPRING["Spring OAuth2<br/>BearerTokenAuthFilter<br/>自動提取 & 驗證 JWT"]
        SPRING --> CONV["CustomJwtAuthConverter<br/>role → ROLE_xxx"]
        CONV --> CTRL2["Controller"]
    end

    style DEFAULT fill:#dbeafe,color:#000
    style OAUTH2 fill:#dcfce7,color:#000
```

**啟動方式**：
```bash
mvn spring-boot:run -Dspring-boot.run.profiles=oauth2
```

**與預設模式的對比**：

| 比較 | 預設模式（自訂 Filter） | OAuth2 模式 |
|------|----------------------|-------------|
| JWT 提取 | 手動從 Header 取得 | Spring 自動處理 |
| JWT 驗證 | 手動呼叫 JJWT | Spring + Nimbus 自動處理 |
| Claim 映射 | 手動建立 Authentication | `CustomJwtAuthenticationConverter` |
| 演算法 | HS256 / RS256 | RS256（強制非對稱金鑰） |
| 適用場景 | 學習 JWT 底層運作 | 生產環境、標準 OAuth 2.0 整合 |

> OAuth2 模式使用本地 RSA 公鑰建立 `JwtDecoder`。生產環境中 Resource Server 會透過 `jwkSetUri` 從外部 Authorization Server 取得公鑰。

---

## 專案架構總覽

本專案採用 **六角形架構（Hexagonal Architecture）**，也稱為「Ports and Adapters」模式。

### 什麼是六角形架構？

核心想法：**業務邏輯（Domain）不應該依賴外部框架**，而是透過「介面（Port）」和「實作（Adapter）」來與外部世界溝通。

```mermaid
graph TB
    subgraph ADAPTER["🔌 Adapter 層（與外部世界溝通）"]
        direction LR
        subgraph IN_ADAPTER["入站適配器"]
            WEB["AuthController<br/>ProtectedController<br/>JwksController<br/>DTOs"]
        end
        subgraph OUT_ADAPTER["出站適配器"]
            PERSIST["UserPersistenceAdapter<br/>RefreshTokenPersistenceAdapter<br/>JPA Entities"]
            CACHE["InMemoryTokenBlacklistAdapter"]
        end
    end

    subgraph PORT["🔗 Port 層（介面定義）"]
        direction LR
        subgraph IN_PORT["入站埠"]
            AUTH_UC["AuthUseCase"]
            REFRESH_UC["TokenRefreshUseCase"]
        end
        subgraph OUT_PORT["出站埠"]
            USER_REPO["UserRepository"]
            TOKEN_REPO["RefreshTokenRepository"]
            BL_REPO["TokenBlacklistRepository"]
        end
    end

    subgraph APP["⚙️ Application 層（編排業務流程）"]
        AUTH_SVC["AuthService"]
        TOKEN_SVC["TokenRefreshService"]
    end

    subgraph DOMAIN["💎 Domain 層（純業務邏輯，無框架依賴）"]
        USER["User"]
        RTOKEN["RefreshToken"]
    end

    subgraph INFRA["🏗️ Infrastructure 層（技術實作）"]
        SEC["SecurityConfig<br/>OAuth2ResourceServerConfig"]
        JWT["JwtTokenProvider<br/>JwkProvider"]
        FILTER["JwtAuthenticationFilter"]
        RATE["RateLimitFilter<br/>RateLimiter"]
    end

    WEB --> AUTH_UC & REFRESH_UC
    AUTH_UC --> AUTH_SVC
    REFRESH_UC --> TOKEN_SVC
    AUTH_SVC --> USER_REPO & TOKEN_SVC
    AUTH_SVC --> JWT
    TOKEN_SVC --> TOKEN_REPO & USER_REPO & JWT & BL_REPO
    USER_REPO --> PERSIST
    TOKEN_REPO --> PERSIST
    BL_REPO --> CACHE
    AUTH_SVC -.-> USER & RTOKEN
    TOKEN_SVC -.-> USER & RTOKEN

    style DOMAIN fill:#fef3c7,color:#000
    style APP fill:#dbeafe,color:#000
    style ADAPTER fill:#f3e8ff,color:#000
    style INFRA fill:#dcfce7,color:#000
```

### 請求處理流程

```mermaid
graph LR
    REQ["HTTP Request"] --> RATE["RateLimitFilter<br/>(速率限制)"]
    RATE --> FILTER["JwtAuthenticationFilter<br/>(提取 & 驗證 JWT<br/>+ 檢查黑名單)"]
    FILTER --> SC["SecurityConfig<br/>(路由授權)"]
    SC --> CTRL["Controller<br/>(入站適配器)"]
    CTRL --> PORT["Use Case Port<br/>(入站埠)"]
    PORT --> SVC["Service<br/>(應用層)"]
    SVC --> REPO["Repository Port<br/>(出站埠)"]
    REPO --> ADAPTER["Persistence Adapter<br/>(出站適配器)"]
    ADAPTER --> DB["H2 Database"]

    style REQ fill:#64748b,color:#fff
    style RATE fill:#fef3c7,color:#000
    style FILTER fill:#dcfce7,color:#000
    style SC fill:#dcfce7,color:#000
    style CTRL fill:#f3e8ff,color:#000
    style PORT fill:#e0e7ff,color:#000
    style SVC fill:#dbeafe,color:#000
    style REPO fill:#e0e7ff,color:#000
    style ADAPTER fill:#f3e8ff,color:#000
    style DB fill:#fef3c7,color:#000
```

### 目錄結構

```
src/main/resources/
├── application.properties              # 設定檔（含 jwt.algorithm 切換）
├── application-oauth2.properties       # OAuth2 Profile 專用設定
└── keys/                               # RSA 金鑰對（PoC 用）
    ├── private.pem                     #   RSA 私鑰（PKCS#8 PEM）
    └── public.pem                      #   RSA 公鑰（X.509 PEM）

src/main/java/com/example/jwtpoc/
├── JwtPocApplication.java              # Spring Boot 啟動入口
│
├── domain/                             # 【領域層】純業務邏輯
│   └── model/
│       ├── User.java                   #   使用者領域模型
│       └── RefreshToken.java           #   Refresh Token 領域模型
│
├── application/                        # 【應用層】編排業務流程
│   ├── port/
│   │   ├── in/
│   │   │   ├── AuthUseCase.java        #   入站埠：登入 / 註冊
│   │   │   ├── TokenRefreshUseCase.java#   入站埠：Token 更新 / 登出
│   │   │   └── LoginResult.java        #   登入結果（含雙 Token）
│   │   └── out/
│   │       ├── UserRepository.java     #   出站埠：使用者資料存取
│   │       ├── RefreshTokenRepository.java # 出站埠：Refresh Token 存取
│   │       └── TokenBlacklistRepository.java # 出站埠：Token 黑名單
│   └── service/
│       ├── AuthService.java            #   認證服務：登入 / 註冊
│       └── TokenRefreshService.java    #   Token 服務：更新 / 登出 / 黑名單
│
├── adapter/                            # 【適配器層】與外部世界溝通
│   ├── in/web/                         #   入站適配器（HTTP 請求）
│   │   ├── AuthController.java         #     登入 / 註冊 / 更新 / 登出 API
│   │   ├── ProtectedController.java    #     受保護資源 API
│   │   ├── JwksController.java         #     JWKS 端點 (/.well-known/jwks.json)
│   │   ├── GlobalExceptionHandler.java #     全域例外處理
│   │   └── dto/                        #     資料傳輸物件
│   │       ├── LoginRequest.java       #       登入請求
│   │       ├── LoginResponse.java      #       登入回應（含雙 Token）
│   │       ├── RefreshTokenRequest.java#       Token 更新請求
│   │       ├── LogoutRequest.java      #       登出請求
│   │       └── UserRegistrationRequest.java  # 註冊請求
│   └── out/
│       ├── persistence/                #   出站適配器（資料庫）
│       │   ├── UserEntity.java         #     使用者 JPA Entity
│       │   ├── UserJpaRepository.java  #     使用者 Spring Data JPA
│       │   ├── UserPersistenceAdapter.java  # 使用者 Domain ↔ Entity 轉換
│       │   ├── RefreshTokenEntity.java      # Refresh Token JPA Entity
│       │   ├── RefreshTokenJpaRepository.java   # Refresh Token Spring Data JPA
│       │   └── RefreshTokenPersistenceAdapter.java  # Refresh Token Domain ↔ Entity
│       └── cache/                      #   出站適配器（快取）
│           └── InMemoryTokenBlacklistAdapter.java   # Token 黑名單 In-Memory 實現
│
└── infrastructure/                     # 【基礎設施層】技術實作
    ├── security/
    │   ├── SecurityConfig.java         #   Spring Security 配置（預設模式）
    │   ├── OAuth2ResourceServerConfig.java  # OAuth 2.0 RS 配置（oauth2 模式）
    │   ├── CustomJwtAuthenticationConverter.java  # OAuth2 role→authority 映射
    │   ├── JwtTokenProvider.java       #   JWT 產生 / 驗證 / 解析（HS256 + RS256）
    │   ├── JwtAuthenticationFilter.java#   JWT 請求過濾器（含黑名單檢查）
    │   └── JwkProvider.java            #   RSA 公鑰 → JWK Set 轉換
    └── ratelimit/
        ├── RateLimiter.java            #   滑動窗口速率限制演算法
        └── RateLimitFilter.java        #   登入端點速率限制過濾器
```

---

## 核心程式碼逐行解說

### 1. JWT Token 產生器 — `JwtTokenProvider.java`

這是整個 JWT 機制的核心，負責 Token 的產生、驗證與解析。支援 HS256 和 RS256 雙演算法。

```java
// 建構時根據 jwt.algorithm 設定自動選擇簽名策略
if ("RS256".equals(algorithm)) {
    // RS256: 私鑰簽名，公鑰驗證
    this.signingKey = loadPrivateKey(privateKeyLocation);
    this.jwtParser = Jwts.parser().verifyWith(loadPublicKey(publicKeyLocation)).build();
} else {
    // HS256: 同一把密鑰簽名和驗證
    SecretKey hmacKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    this.signingKey = hmacKey;
    this.jwtParser = Jwts.parser().verifyWith(hmacKey).build();
}
```

```java
// 產生 JWT Token — .signWith() 根據 Key 類型自動選擇演算法
public String generateToken(String username, String role) {
    return Jwts.builder()
            .id(UUID.randomUUID().toString()) // 設定 jti（Token 黑名單用）
            .subject(username)              // 設定 Payload 的 sub（主體）
            .claim("role", role)             // 設定自訂聲明：角色
            .issuer(issuer)                  // 設定 Payload 的 iss（簽發者）
            .issuedAt(now)                   // 設定 Payload 的 iat（簽發時間）
            .expiration(expiry)              // 設定 Payload 的 exp（過期時間）
            .signWith(signingKey)            // SecretKey → HS256, PrivateKey → RS256
            .compact();                      // 組合為 header.payload.signature
}
```

**初學者重點**：
- `Jwts.builder()` 是 JJWT 函式庫提供的建構器模式
- `.signWith(signingKey)` 會根據 Key 的類型自動選擇演算法（`SecretKey` → HS256, `PrivateKey` → RS256）
- 驗證時使用預先建構好的 `JwtParser`，無需在每次請求中判斷演算法

```java
// 驗證 JWT Token
public boolean validateToken(String token) {
    try {
        parseClaims(token);   // 嘗試解析，失敗就拋出例外
        return true;
    } catch (SecurityException e) {
        // 簽章無效 — 可能被竄改
    } catch (ExpiredJwtException e) {
        // Token 已過期
    } catch (MalformedJwtException e) {
        // Token 格式錯誤
    }
    return false;
}
```

### 2. JWT 過濾器 — `JwtAuthenticationFilter.java`

每一個 HTTP 請求都會經過此過濾器，檢查是否帶有有效的 JWT。

```java
@Override
protected void doFilterInternal(HttpServletRequest request,
                                HttpServletResponse response,
                                FilterChain filterChain) {

    // 第一步：從 Authorization Header 中提取 Token
    String token = extractToken(request);

    // 第二步：驗證 Token 是否有效
    if (token != null && jwtTokenProvider.validateToken(token)) {

        // 第三步：檢查 Token 是否已被列入黑名單（登出後撤銷）
        String jti = jwtTokenProvider.getJtiFromToken(token);
        if (jti != null && tokenBlacklistRepository.isBlacklisted(jti)) {
            // 已撤銷的 Token → 跳過認證
        } else {
            // 第四步：從 Token 中取出使用者資訊
            String username = jwtTokenProvider.getUsernameFromToken(token);
            String role = jwtTokenProvider.getRoleFromToken(token);

            // 第五步：建立 Spring Security 的認證物件
            var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));
            var authentication = new UsernamePasswordAuthenticationToken(
                    username, null, authorities);

            // 第六步：放入 SecurityContext
            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
    }

    filterChain.doFilter(request, response);
}
```

**初學者重點**：
- `OncePerRequestFilter` 確保每個請求只執行一次
- 提取 Token 時會去掉 `Bearer ` 前綴
- **黑名單檢查**：驗證簽章後還需檢查 `jti` 是否在黑名單中，解決登出後 Token 仍有效的問題
- 放入 `SecurityContext` 後，Controller 就能用 `Authentication auth` 參數取得使用者

### 3. Spring Security 配置 — `SecurityConfig.java`

```java
http
    // JWT 是 stateless，不需要 CSRF 保護
    .csrf(csrf -> csrf.disable())

    // 不建立 Server 端 Session（因為用 JWT 取代了 Session）
    .sessionManagement(session ->
        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

    // 設定哪些路徑需要認證
    .authorizeHttpRequests(auth -> auth
        .requestMatchers("/api/auth/**").permitAll()           // 登入、註冊：公開
        .requestMatchers("/.well-known/**").permitAll()        // JWKS 端點：公開
        .requestMatchers("/api/protected/admin/**").hasRole("ADMIN")  // 管理員限定
        .anyRequest().authenticated()                          // 其他：需認證
    )

    // 速率限制過濾器（防暴力破解登入）
    .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)

    // JWT 認證過濾器（含黑名單檢查）
    .addFilterBefore(jwtAuthenticationFilter,
            UsernamePasswordAuthenticationFilter.class);
```

### 4. 認證服務 — `AuthService.java`

```java
// 登入流程
public LoginResult login(String username, String password) {
    // 1. 從資料庫查詢使用者
    User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new RuntimeException("User not found"));

    // 2. 驗證密碼（BCrypt 加密比對）
    if (!passwordEncoder.matches(password, user.getPassword())) {
        throw new RuntimeException("Invalid password");
    }

    // 3. 密碼正確 → 產生 Access Token (JWT)
    String accessToken = jwtTokenProvider.generateToken(user.getUsername(), user.getRole());

    // 4. 產生 Refresh Token (UUID) 並儲存到資料庫
    RefreshToken refreshToken = tokenRefreshService.createRefreshToken(user.getUsername());

    return new LoginResult(accessToken, refreshToken.getToken(),
            user.getUsername(), jwtTokenProvider.getExpirationMs());
}
```

### 5. Token 更新服務 — `TokenRefreshService.java`

```java
// Token Rotation 流程
@Transactional
public TokenPair refresh(String refreshTokenStr) {
    // 1. 查找 Refresh Token
    RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenStr)
            .orElseThrow(() -> new RuntimeException("Refresh token not found"));

    // 2. 驗證是否有效（未過期、未撤銷）
    if (!refreshToken.isValid()) {
        throw new RuntimeException("Refresh token is expired or revoked");
    }

    // 3. Token Rotation: 撤銷舊 Token
    refreshToken.revoke();
    refreshTokenRepository.save(refreshToken);

    // 4. 查找使用者（取得 role 以產生新 JWT）
    User user = userRepository.findByUsername(refreshToken.getUsername())
            .orElseThrow(() -> new RuntimeException("User not found"));

    // 5. 產生新的 Token 對
    String newAccessToken = jwtTokenProvider.generateToken(user.getUsername(), user.getRole());
    RefreshToken newRefreshToken = createRefreshToken(user.getUsername());

    return new TokenPair(newAccessToken, newRefreshToken.getToken(),
            jwtTokenProvider.getExpirationMs());
}
```

### 6. 受保護的 Controller — `ProtectedController.java`

```java
// 任何已認證的使用者都能存取
@GetMapping("/profile")
public ResponseEntity<Map<String, Object>> getProfile(Authentication auth) {
    // auth.getName() → 從 JWT 的 sub 欄位取得的使用者名稱
    return ResponseEntity.ok(Map.of(
            "username", auth.getName(),
            "authorities", auth.getAuthorities().toString(),
            "message", "This is a protected resource. Your JWT is valid!"
    ));
}

// 只有 ADMIN 角色才能存取
@GetMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")   // Spring Security 會檢查角色
public ResponseEntity<Map<String, Object>> getAdminData(Authentication auth) {
    return ResponseEntity.ok(Map.of(
            "message", "Welcome Admin! This is an admin-only resource."
    ));
}
```

---

## 環境需求與啟動方式

### 環境需求

| 工具 | 版本 | 說明 |
|------|------|------|
| Java | 21+ | JDK 21 以上版本 |
| Maven | 3.9+ | 專案使用 Maven Wrapper，可不另裝 |

### 檢查 Java 版本

```bash
java -version
# 應顯示 java version "21.x.x" 或更高
```

### 啟動專案

```bash
# 進入專案目錄
cd jwt-poc

# 使用 Maven Wrapper 啟動（不需要額外安裝 Maven）
./mvnw spring-boot:run

# Windows 使用者
mvnw.cmd spring-boot:run
```

啟動後你會看到類似的訊息：
```
Started JwtPocApplication in 2.xxx seconds
```

伺服器預設在 `http://localhost:8080` 運行。

### 切換簽章演算法

專案預設使用 HS256。如需體驗 RS256，修改 `application.properties`：

```bash
# 使用 RS256 啟動
mvn spring-boot:run -Djwt.algorithm=RS256

# 或直接修改 application.properties 中的 jwt.algorithm=RS256
```

### 使用 OAuth 2.0 Resource Server 模式

```bash
# 啟用 oauth2 Profile（強制使用 RS256）
mvn spring-boot:run -Dspring-boot.run.profiles=oauth2
```

此模式下 Spring Security 自動處理 JWT 驗證，不使用自訂的 `JwtAuthenticationFilter`。詳見 [OAuth 2.0 Resource Server](#oauth-20-resource-server) 章節。

### 執行測試

```bash
./mvnw test
# 54 tests, 0 failures
```

---

## API 測試教學（手把手）

以下使用 `curl` 指令來測試所有 API。如果你更喜歡圖形介面，可以使用 [Postman](https://www.postman.com/) 或 [Insomnia](https://insomnia.rest/)。

### 完整測試流程總覽

```mermaid
graph TD
    A["步驟 1<br/>註冊使用者"] --> B["步驟 2<br/>登入取得雙 Token"]
    B --> C["步驟 3<br/>解碼 JWT"]
    B --> D["步驟 4<br/>存取受保護資源"]
    D --> E["步驟 5<br/>測試權限控制"]
    B --> F["步驟 6<br/>Token 更新"]
    F --> G["步驟 7<br/>登出 + 黑名單"]
    G --> H["步驟 8<br/>測試 JWKS 端點"]
    H --> I["步驟 9<br/>測試異常情境"]

    style A fill:#4ade80,color:#000
    style B fill:#38bdf8,color:#fff
    style F fill:#a78bfa,color:#fff
    style G fill:#fb923c,color:#fff
    style H fill:#a78bfa,color:#fff
```

### 步驟 1：註冊使用者

先建立一個普通使用者和一個管理員。

```bash
# 註冊普通使用者
curl -s -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123","role":"USER"}' | jq .
```

預期回應：
```json
{
  "message": "User registered successfully",
  "username": "alice",
  "role": "USER"
}
```

```bash
# 註冊管理員
curl -s -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"rex","password":"admin123","role":"ADMIN"}' | jq .
```

### 步驟 2：登入取得雙 Token

```bash
# 使用 alice 登入
curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq .
```

預期回應：
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIs...",
  "refreshToken": "550e8400-e29b-41d4-a716-446655440000",
  "tokenType": "Bearer",
  "username": "alice",
  "accessTokenExpiresInMs": 3600000
}
```

> **重要**：回應中包含兩個 Token — `accessToken` 用於 API 認證，`refreshToken` 用於更新 Token。

為了方便，把 Token 存到環境變數：

```bash
# 自動擷取雙 Token
RESPONSE=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}')

export TOKEN=$(echo $RESPONSE | jq -r '.accessToken')
export REFRESH_TOKEN=$(echo $RESPONSE | jq -r '.refreshToken')

echo "Access Token: $TOKEN"
echo "Refresh Token: $REFRESH_TOKEN"
```

### 步驟 3：解碼 JWT Token（看看裡面有什麼）

JWT 的 Header 和 Payload 是 Base64 編碼的，我們可以手動解碼查看內容：

```bash
# 解碼 Header（第一段）
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null && echo

# 解碼 Payload（第二段）
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null && echo
```

你會看到類似的輸出（演算法取決於 `jwt.algorithm` 設定）：
```json
{"alg":"HS256"}
{"jti":"550e8400-...","sub":"alice","role":"USER","iss":"jwt-poc-app","iat":1700000000,"exp":1700003600}
```

> 這證明了 Payload 並不是加密的！任何人拿到 Token 都可以看到內容。但因為沒有密鑰，無法偽造簽章。

### 步驟 4：使用 Token 存取受保護資源

```bash
# 存取個人資料（任何已認證使用者都可以）
curl -s http://localhost:8080/api/protected/profile \
  -H "Authorization: Bearer $TOKEN" | jq .
```

預期回應：
```json
{
  "username": "alice",
  "authorities": "[ROLE_USER]",
  "message": "This is a protected resource. Your JWT is valid!",
  "timestamp": "2026-02-10T..."
}
```

### 步驟 5：測試權限控制

```bash
# alice (USER) 嘗試存取管理員資源 → 被拒絕！
curl -s -o /dev/null -w "HTTP 狀態碼: %{http_code}\n" \
  http://localhost:8080/api/protected/admin \
  -H "Authorization: Bearer $TOKEN"
```

預期結果：`HTTP 狀態碼: 403`（Forbidden 禁止存取）

```bash
# 改用 ADMIN 帳號登入
ADMIN_RESPONSE=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"rex","password":"admin123"}')

export ADMIN_TOKEN=$(echo $ADMIN_RESPONSE | jq -r '.accessToken')

# 使用 ADMIN Token 存取管理員資源 → 成功！
curl -s http://localhost:8080/api/protected/admin \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq .
```

預期回應：
```json
{
  "username": "rex",
  "message": "Welcome Admin! This is an admin-only resource.",
  "secretData": "Sensitive admin information here...",
  "timestamp": "2026-02-10T..."
}
```

### 步驟 6：更新 Token（Refresh）

```bash
# 使用 Refresh Token 取得新的 Token 對
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}" | jq .
```

預期回應：
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...(新的 JWT)",
  "refreshToken": "a1b2c3d4-...(新的 UUID)",
  "tokenType": "Bearer",
  "accessTokenExpiresInMs": 3600000
}
```

> **注意**：舊的 Refresh Token 已被撤銷，必須使用新的 Refresh Token。這就是 Token Rotation。

```bash
# 更新環境變數
NEW_RESPONSE=$(curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}")

export TOKEN=$(echo $NEW_RESPONSE | jq -r '.accessToken')
export REFRESH_TOKEN=$(echo $NEW_RESPONSE | jq -r '.refreshToken')
```

### 步驟 7：登出

```bash
# 登出：撤銷 Refresh Token + 將 Access Token 加入黑名單
curl -s -X POST http://localhost:8080/api/auth/logout \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}" | jq .
```

預期回應：
```json
{
  "message": "Logged out successfully"
}
```

> 帶上 `Authorization` header 可讓伺服器將 Access Token 加入黑名單。不帶也能登出（僅撤銷 Refresh Token）。

```bash
# 驗證：登出後 Access Token 應被拒絕（黑名單生效）
curl -s -o /dev/null -w "登出後存取: HTTP %{http_code}\n" \
  http://localhost:8080/api/protected/profile \
  -H "Authorization: Bearer $TOKEN"
# 預期：HTTP 403
```

### 步驟 8：測試 JWKS 端點

```bash
# 取得 JWKS（HS256 模式會回傳說明訊息）
curl -s http://localhost:8080/.well-known/jwks.json | jq .

# 如果使用 RS256 模式，會回傳 JWK Set：
# {"keys":[{"kty":"RSA","use":"sig","alg":"RS256","kid":"jwt-poc-key-1","n":"...","e":"AQAB"}]}
```

### 步驟 9：測試異常情境

```bash
# 8a. 不帶 Token 直接存取 → 403
curl -s -o /dev/null -w "不帶 Token: HTTP %{http_code}\n" \
  http://localhost:8080/api/protected/profile

# 8b. 帶無效 Token → 403
curl -s -o /dev/null -w "無效 Token: HTTP %{http_code}\n" \
  http://localhost:8080/api/protected/profile \
  -H "Authorization: Bearer invalid.token.here"

# 8c. 錯誤密碼登入 → 401
curl -s http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"wrong"}' | jq .

# 8d. 登出後嘗試使用 Refresh Token → 401
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}" | jq .

# 8e. 無效的 Refresh Token → 401
curl -s -X POST http://localhost:8080/api/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"invalid-uuid"}' | jq .
```

---

## 常見問題 FAQ

### Q1: JWT Token 被偷了怎麼辦？

本專案提供了多層防護：
- **Token Blacklist**：登出時將 Access Token 加入黑名單，使其立即失效（本專案已實作）
- **Access Token 設定較短的過期時間**（1 小時）
- **搭配 Refresh Token 機制**（本專案已實作）
- **Refresh Token 可以被撤銷**（透過登出或 Token Rotation）
- **Rate Limiting**：防止暴力破解取得 Token（本專案已實作）
- **使用 HTTPS** 防止 Token 在傳輸中被截取

### Q2: 為什麼不能在 Payload 中放密碼？

因為 Payload 只是 Base64 編碼，不是加密。任何拿到 Token 的人都可以輕鬆解碼看到內容。Payload 適合放的資料：使用者 ID、角色、權限等。

### Q3: HS256 和 RS256 有什麼差別？

| 演算法 | 類型 | 密鑰 | 適用場景 |
|--------|------|------|---------|
| HS256 | 對稱式 | 同一把密鑰簽名和驗證 | 單一服務，簡單場景 |
| RS256 | 非對稱式 | 私鑰簽名，公鑰驗證 | 微服務架構，多服務驗證 |

本專案**兩種都支援**，透過 `jwt.algorithm` 設定值切換（預設 HS256）。詳見 [HS256 vs RS256 簽章演算法](#hs256-vs-rs256-簽章演算法) 章節。

### Q4: Token 過期了怎麼辦？

本專案已實作 Refresh Token 機制。當 Access Token 過期時，Client 可以使用 Refresh Token 呼叫 `POST /api/auth/refresh` 取得新的 Token 對，不需要重新輸入帳密。

### Q5: 為什麼 Refresh Token 用 UUID 而非 JWT？

| | JWT (Access Token) | UUID (Refresh Token) |
|---|---|---|
| 設計 | Stateless，伺服器不需儲存 | Stateful，儲存在資料庫 |
| 可撤銷 | 不可以 | 可以（從 DB 刪除或標記） |
| 包含資訊 | 自包含使用者資訊 | 只是一個隨機識別碼 |
| 適用 | 頻繁的 API 認證 | 偶爾的 Token 更新 |

Refresh Token 需要可撤銷（登出、安全事件），所以用 stateful 的 UUID 更安全。

### Q6: 什麼是 Token Rotation？

每次使用 Refresh Token 時，舊的會被撤銷並發出新的一對。如果攻擊者偷了 Refresh Token，當合法使用者或攻擊者先使用它時，另一方的 Token 就失效了。伺服器可以偵測到「同一個 Refresh Token 被使用兩次」的異常。

### Q7: 為什麼要關閉 CSRF？

CSRF（Cross-Site Request Forgery）保護是針對基於 Cookie 的認證設計的。JWT 使用 Authorization Header 傳遞，不受 CSRF 攻擊影響，所以可以安全地關閉。

### Q8: 為什麼用 H2 資料庫？

H2 是一個嵌入式的記憶體資料庫，專案啟動時自動建立，關閉時自動銷毀。非常適合 PoC 和開發測試使用。正式環境應替換為 PostgreSQL、MySQL 等。

---

## 延伸學習資源

### 相關規範
- [RFC 7519 - JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [JWT.io](https://jwt.io/) — 線上解碼與驗證 JWT 的工具

### 使用的技術
- [Spring Boot 3.3](https://spring.io/projects/spring-boot) — Java Web 框架
- [Spring Security](https://spring.io/projects/spring-security) — 安全框架
- [Spring OAuth2 Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/) — OAuth 2.0 資源伺服器
- [JJWT](https://github.com/jwtk/jjwt) — Java JWT 函式庫
- [Nimbus JOSE+JWT](https://connect2id.com/products/nimbus-jose-jwt) — JWKS / JWK 處理
- [H2 Database](https://www.h2database.com/) — 嵌入式記憶體資料庫
- [Lombok](https://projectlombok.org/) — Java 程式碼簡化工具

### 本專案已實作的進階主題
- **Rate Limiting**：滑動窗口演算法限制登入嘗試（詳見 [Rate Limiting](#rate-limiting速率限制)）
- **Token Blacklist**：In-Memory 實現 Access Token 撤銷（詳見 [Token Blacklist](#token-blacklist黑名單)）
- **JWKS 端點**：動態公鑰分發機制（詳見 [JWKS 端點](#jwks-端點)）
- **OAuth 2.0 Resource Server**：標準 Spring Security OAuth2 模式（詳見 [OAuth 2.0 RS](#oauth-20-resource-server)）

### 可進一步探索的主題
- **Redis Token Blacklist**：替換 In-Memory 為 Redis，支援分散式部署
- **OAuth 2.0 Authorization Server**：完整的 OAuth2 授權伺服器
- **OpenID Connect (OIDC)**：在 OAuth2 基礎上加入身份驗證
- **mTLS**：雙向 TLS 認證

---

> 本專案為教學用途的 PoC（Proof of Concept），不建議直接用於正式生產環境。生產環境應加強密鑰管理、錯誤處理、日誌記錄等安全措施。
