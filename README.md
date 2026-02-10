# JWT (JSON Web Token) 入門教學 — Spring Boot PoC

> 這是一份為初學者設計的 JWT 認證機制教學，搭配 Spring Boot 實作專案，讓你從零開始理解 JWT 的原理與應用。

---

## 目錄

1. [什麼是 JWT？](#什麼是-jwt)
2. [為什麼需要 JWT？](#為什麼需要-jwt)
3. [JWT 的結構](#jwt-的結構)
4. [認證流程圖解](#認證流程圖解)
5. [專案架構總覽](#專案架構總覽)
6. [核心程式碼逐行解說](#核心程式碼逐行解說)
7. [環境需求與啟動方式](#環境需求與啟動方式)
8. [API 測試教學（手把手）](#api-測試教學手把手)
9. [常見問題 FAQ](#常見問題-faq)
10. [延伸學習資源](#延伸學習資源)

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

### 傳統 Session 的問題

```
傳統方式：
Client → 登入 → Server 建立 Session → 把 Session ID 存在 Cookie
                  ↓
           Server 需要儲存每個使用者的 Session 資料
                  ↓
           多台 Server 時，Session 需要同步（很麻煩！）
```

### JWT 的優勢

```
JWT 方式：
Client → 登入 → Server 產生 JWT Token → 回傳給 Client
                  ↓
           Server 不需要儲存任何狀態（Stateless）
                  ↓
           Token 自身就包含了使用者資訊
                  ↓
           多台 Server 都能驗證（只要有相同的密鑰）
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

描述這個 Token 使用的演算法和類型。

```json
{
  "alg": "HS256",    // 簽名演算法：HMAC-SHA256
  "typ": "JWT"       // Token 類型：JWT
}
```

經過 **Base64Url 編碼** 後變成：`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`

### 2. Payload（負載）

包含要傳遞的資料，稱為 **Claims（聲明）**。

```json
{
  "sub": "rex",           // Subject：使用者名稱
  "role": "ADMIN",        // 自訂聲明：角色
  "iss": "jwt-poc-app",   // Issuer：簽發者
  "iat": 1700000000,      // Issued At：簽發時間
  "exp": 1700003600       // Expiration：過期時間
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

```
┌─────────────────────────────────────────────────────┐
│                    JWT Token                         │
├──────────────┬──────────────┬───────────────────────┤
│   Header     │   Payload    │     Signature          │
│              │              │                        │
│ {            │ {            │ HMAC-SHA256(           │
│  "alg":"HS256│  "sub":"rex" │   base64(header) +     │
│  "typ":"JWT" │  "role":"ADM"│   "." +                │
│ }            │  "iat":...   │   base64(payload),     │
│              │  "exp":...   │   secret               │
│              │ }            │ )                       │
├──────────────┼──────────────┼───────────────────────┤
│ Base64Url    │ Base64Url    │  自動計算產生            │
│ 編碼         │ 編碼          │                        │
└──────────────┴──────────────┴───────────────────────┘
         ↓              ↓               ↓
      xxxxx  +  "."  +  yyyyy  +  "."  + zzzzz
                       ↓
              最終 Token 字串
```

---

## 認證流程圖解

```
    使用者 (Client)                         伺服器 (Server)
         │                                       │
         │  ① POST /api/auth/login               │
         │  { username, password }                │
         │ ─────────────────────────────────────→ │
         │                                       │
         │                          ② 驗證帳號密碼   │
         │                          ③ 產生 & 簽署 JWT│
         │                                       │
         │  ④ 回傳 JWT Token                      │
         │ ←───────────────────────────────────── │
         │                                       │
         │  ⑤ 存取受保護資源                        │
         │  GET /api/protected/profile            │
         │  Header: Authorization: Bearer <JWT>   │
         │ ─────────────────────────────────────→ │
         │                                       │
         │                          ⑥ 從 Header 提取 JWT
         │                          ⑦ 驗證 JWT 簽章 & 有效期
         │                                       │
         │  ⑧ 回傳受保護的資料                      │
         │ ←───────────────────────────────────── │
         │                                       │
```

### 流程步驟說明

| 步驟 | 動作 | 對應程式碼 |
|------|------|----------|
| ① | 使用者發送帳號密碼 | `AuthController.login()` |
| ② | 伺服器驗證帳密 | `AuthService.login()` → `PasswordEncoder.matches()` |
| ③ | 產生 JWT Token | `JwtTokenProvider.generateToken()` |
| ④ | 回傳 Token 給 Client | `LoginResponse` 包含 token 字串 |
| ⑤ | Client 帶 Token 請求 | HTTP Header: `Authorization: Bearer <token>` |
| ⑥ | 提取 Token | `JwtAuthenticationFilter.extractToken()` |
| ⑦ | 驗證 Token | `JwtTokenProvider.validateToken()` |
| ⑧ | 回傳資料 | `ProtectedController.getProfile()` |

---

## 專案架構總覽

本專案採用 **六角形架構（Hexagonal Architecture）**，也稱為「Ports and Adapters」模式。

### 什麼是六角形架構？

核心想法：**業務邏輯（Domain）不應該依賴外部框架**，而是透過「介面（Port）」和「實作（Adapter）」來與外部世界溝通。

```
              ┌─────────────────────────────────────┐
              │         Adapter 層（外部）              │
              │  ┌───────────┐    ┌───────────────┐  │
              │  │ Web 控制器  │    │  JPA 持久化     │  │
              │  │ (入站適配器) │    │  (出站適配器)    │  │
              │  └─────┬─────┘    └──────┬────────┘  │
              │        │                 │           │
              │  ┌─────▼─────┐    ┌──────▼────────┐  │
              │  │ 入站 Port   │    │  出站 Port     │  │
              │  │ (AuthUseCase│    │ (UserRepository│  │
              │  └─────┬─────┘    └──────┬────────┘  │
              │        │                 │           │
              │  ┌─────▼─────────────────▼────────┐  │
              │  │        Application 層            │  │
              │  │        (AuthService)            │  │
              │  └────────────┬───────────────────┘  │
              │               │                      │
              │  ┌────────────▼───────────────────┐  │
              │  │         Domain 層               │  │
              │  │         (User Model)            │  │
              │  │         純業務邏輯，無框架依賴     │  │
              │  └────────────────────────────────┘  │
              │                                      │
              │  ┌────────────────────────────────┐  │
              │  │      Infrastructure 層          │  │
              │  │  SecurityConfig                 │  │
              │  │  JwtTokenProvider               │  │
              │  │  JwtAuthenticationFilter        │  │
              │  └────────────────────────────────┘  │
              └─────────────────────────────────────┘
```

### 目錄結構

```
src/main/java/com/example/jwtpoc/
├── JwtPocApplication.java              # Spring Boot 啟動入口
│
├── domain/                             # 【領域層】純業務邏輯
│   └── model/
│       └── User.java                   #   使用者領域模型
│
├── application/                        # 【應用層】編排業務流程
│   ├── port/
│   │   ├── in/
│   │   │   └── AuthUseCase.java        #   入站埠：定義認證能力
│   │   └── out/
│   │       └── UserRepository.java     #   出站埠：定義資料存取介面
│   └── service/
│       └── AuthService.java            #   應用服務：協調認證流程
│
├── adapter/                            # 【適配器層】與外部世界溝通
│   ├── in/web/                         #   入站適配器（HTTP 請求）
│   │   ├── AuthController.java         #     登入 / 註冊 API
│   │   ├── ProtectedController.java    #     受保護資源 API
│   │   ├── GlobalExceptionHandler.java #     全域例外處理
│   │   └── dto/                        #     資料傳輸物件
│   │       ├── LoginRequest.java       #       登入請求
│   │       ├── LoginResponse.java      #       登入回應（含 Token）
│   │       └── UserRegistrationRequest.java  # 註冊請求
│   └── out/persistence/                #   出站適配器（資料庫）
│       ├── UserEntity.java             #     JPA Entity
│       ├── UserJpaRepository.java      #     Spring Data JPA
│       └── UserPersistenceAdapter.java #     Domain ↔ Entity 轉換
│
└── infrastructure/                     # 【基礎設施層】技術實作
    └── security/
        ├── SecurityConfig.java         #   Spring Security 配置
        ├── JwtTokenProvider.java       #   JWT 產生 / 驗證 / 解析
        └── JwtAuthenticationFilter.java#   JWT 請求過濾器
```

---

## 核心程式碼逐行解說

### 1. JWT Token 產生器 — `JwtTokenProvider.java`

這是整個 JWT 機制的核心，負責 Token 的產生、驗證與解析。

```java
// 產生 JWT Token
public String generateToken(String username, String role) {
    Date now = new Date();
    Date expiry = new Date(now.getTime() + expirationMs);

    String token = Jwts.builder()
            .subject(username)              // 設定 Payload 的 sub（主體）
            .claim("role", role)             // 設定自訂聲明：角色
            .issuer(issuer)                  // 設定 Payload 的 iss（簽發者）
            .issuedAt(now)                   // 設定 Payload 的 iat（簽發時間）
            .expiration(expiry)              // 設定 Payload 的 exp（過期時間）
            .signWith(secretKey)             // 用密鑰簽名（自動選用 HS256）
            .compact();                      // 組合為 header.payload.signature

    return token;
}
```

**初學者重點**：
- `Jwts.builder()` 是 JJWT 函式庫提供的建構器模式
- `.signWith(secretKey)` 是安全的關鍵 — 沒有密鑰就無法偽造 Token
- `.compact()` 最終將三個部分用 `.` 串接成一個字串

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
    // 格式：Authorization: Bearer eyJhbGci...
    String token = extractToken(request);

    // 第二步：驗證 Token 是否有效
    if (token != null && jwtTokenProvider.validateToken(token)) {

        // 第三步：從 Token 中取出使用者資訊
        String username = jwtTokenProvider.getUsernameFromToken(token);
        String role = jwtTokenProvider.getRoleFromToken(token);

        // 第四步：建立 Spring Security 的認證物件
        var authorities = List.of(new SimpleGrantedAuthority("ROLE_" + role));
        var authentication = new UsernamePasswordAuthenticationToken(
                username, null, authorities);

        // 第五步：放入 SecurityContext，後續的 Controller 就能取得使用者資訊
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    // 繼續處理下一個 Filter
    filterChain.doFilter(request, response);
}
```

**初學者重點**：
- `OncePerRequestFilter` 確保每個請求只執行一次
- 提取 Token 時會去掉 `Bearer ` 前綴
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
        .requestMatchers("/api/protected/admin/**").hasRole("ADMIN")  // 管理員限定
        .anyRequest().authenticated()                          // 其他：需認證
    )

    // 在預設的帳密認證過濾器之前，插入我們的 JWT 過濾器
    .addFilterBefore(jwtAuthenticationFilter,
            UsernamePasswordAuthenticationFilter.class);
```

### 4. 認證服務 — `AuthService.java`

```java
// 登入流程
public String login(String username, String password) {
    // 1. 從資料庫查詢使用者
    User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new RuntimeException("User not found"));

    // 2. 驗證密碼（BCrypt 加密比對）
    if (!passwordEncoder.matches(password, user.getPassword())) {
        throw new RuntimeException("Invalid password");
    }

    // 3. 密碼正確 → 產生 JWT Token 回傳
    return jwtTokenProvider.generateToken(user.getUsername(), user.getRole());
}

// 註冊流程
public User register(String username, String password, String role) {
    // 1. 檢查使用者名稱是否已存在
    if (userRepository.existsByUsername(username)) {
        throw new RuntimeException("Username already exists");
    }

    // 2. 密碼加密後儲存（不會儲存明文密碼！）
    User user = new User(username, passwordEncoder.encode(password), role);
    return userRepository.save(user);
}
```

### 5. 受保護的 Controller — `ProtectedController.java`

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

### 執行測試

```bash
./mvnw test
```

---

## API 測試教學（手把手）

以下使用 `curl` 指令來測試所有 API。如果你更喜歡圖形介面，可以使用 [Postman](https://www.postman.com/) 或 [Insomnia](https://insomnia.rest/)。

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

### 步驟 2：登入取得 JWT Token

```bash
# 使用 alice 登入
curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq .
```

預期回應：
```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIs...",
  "tokenType": "Bearer",
  "username": "alice",
  "expiresInMs": 3600000
}
```

> **重要**：複製回應中的 `token` 值，後續步驟要用到！

為了方便，你可以把 Token 存到環境變數：

```bash
# 方法一：手動複製貼上
export TOKEN="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSIs..."

# 方法二：自動擷取（推薦）
export TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' | jq -r '.token')

echo "你的 JWT Token: $TOKEN"
```

### 步驟 3：解碼 JWT Token（看看裡面有什麼）

JWT 的 Header 和 Payload 是 Base64 編碼的，我們可以手動解碼查看內容：

```bash
# 解碼 Header（第一段）
echo $TOKEN | cut -d'.' -f1 | base64 -d 2>/dev/null && echo

# 解碼 Payload（第二段）
echo $TOKEN | cut -d'.' -f2 | base64 -d 2>/dev/null && echo
```

你會看到類似的輸出：
```json
{"alg":"HS256"}
{"sub":"alice","role":"USER","iss":"jwt-poc-app","iat":1700000000,"exp":1700003600}
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
export ADMIN_TOKEN=$(curl -s -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"rex","password":"admin123"}' | jq -r '.token')

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

### 步驟 6：測試異常情境

```bash
# 6a. 不帶 Token 直接存取 → 403
curl -s -o /dev/null -w "不帶 Token: HTTP %{http_code}\n" \
  http://localhost:8080/api/protected/profile

# 6b. 帶無效 Token → 403
curl -s -o /dev/null -w "無效 Token: HTTP %{http_code}\n" \
  http://localhost:8080/api/protected/profile \
  -H "Authorization: Bearer invalid.token.here"

# 6c. 錯誤密碼登入 → 401
curl -s http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"wrong"}' | jq .
```

---

## 常見問題 FAQ

### Q1: JWT Token 被偷了怎麼辦？

這確實是 JWT 的一個弱點。由於伺服器不儲存狀態，無法直接「撤銷」一個 Token。常見的解決方案：
- **設定較短的過期時間**（例如 15 分鐘）
- **搭配 Refresh Token 機制**
- **維護一個 Token 黑名單**（但這就有狀態了）
- **使用 HTTPS** 防止 Token 在傳輸中被截取

### Q2: 為什麼不能在 Payload 中放密碼？

因為 Payload 只是 Base64 編碼，不是加密。任何拿到 Token 的人都可以輕鬆解碼看到內容。Payload 適合放的資料：使用者 ID、角色、權限等。

### Q3: HS256 和 RS256 有什麼差別？

| 演算法 | 類型 | 密鑰 | 適用場景 |
|--------|------|------|---------|
| HS256 | 對稱式 | 同一把密鑰簽名和驗證 | 單一服務，簡單場景 |
| RS256 | 非對稱式 | 私鑰簽名，公鑰驗證 | 微服務架構，多服務驗證 |

本專案使用 HS256，因為是單一服務的 PoC。正式環境如果是微服務架構，建議考慮 RS256。

### Q4: Token 過期了怎麼辦？

用戶端收到 401 或發現 Token 過期後，需要重新登入取得新的 Token。進階做法是實作 Refresh Token 機制，讓用戶端可以「無感刷新」。

### Q5: 為什麼要關閉 CSRF？

CSRF（Cross-Site Request Forgery）保護是針對基於 Cookie 的認證設計的。JWT 使用 Authorization Header 傳遞，不受 CSRF 攻擊影響，所以可以安全地關閉。

### Q6: 為什麼用 H2 資料庫？

H2 是一個嵌入式的記憶體資料庫，專案啟動時自動建立，關閉時自動銷毀。非常適合 PoC 和開發測試使用。正式環境應替換為 PostgreSQL、MySQL 等。

---

## 延伸學習資源

### 相關規範
- [RFC 7519 - JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519)
- [JWT.io](https://jwt.io/) — 線上解碼與驗證 JWT 的工具

### 使用的技術
- [Spring Boot 3.3](https://spring.io/projects/spring-boot) — Java Web 框架
- [Spring Security](https://spring.io/projects/spring-security) — 安全框架
- [JJWT](https://github.com/jwtk/jjwt) — Java JWT 函式庫
- [H2 Database](https://www.h2database.com/) — 嵌入式記憶體資料庫
- [Lombok](https://projectlombok.org/) — Java 程式碼簡化工具

### 進階主題
- **Refresh Token**：實作無感刷新機制
- **RS256 非對稱加密**：適用於微服務架構
- **OAuth 2.0**：更完整的授權框架
- **Token 黑名單**：搭配 Redis 實作 Token 撤銷

---

> 本專案為教學用途的 PoC（Proof of Concept），不建議直接用於正式生產環境。生產環境應加強密鑰管理、錯誤處理、日誌記錄等安全措施。
