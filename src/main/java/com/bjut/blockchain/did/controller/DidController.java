package com.bjut.blockchain.did.controller;

import com.bjut.blockchain.did.model.Did; // Did模型
import com.bjut.blockchain.did.model.DidDocument; // DidDocument模型
import com.bjut.blockchain.did.service.DidAuthenticationService; // 认证服务
import com.bjut.blockchain.did.service.DidService; // DID管理服务
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest; // HTTP请求对象，用于session管理
import javax.servlet.http.HttpSession; // HTTP Session对象
import java.security.KeyPair; // 密钥对
import java.security.KeyPairGenerator; // 密钥对生成器
import java.security.NoSuchAlgorithmException; // 算法未找到异常
import java.security.Signature; // 签名对象
import java.nio.charset.StandardCharsets; // 标准字符集
import java.util.*; // 集合框架
import java.util.concurrent.ConcurrentHashMap; // 线程安全的HashMap，用于DEMO

@RestController
@RequestMapping("/api/did") // 所有此控制器的API都以 /api/did 开头
public class DidController {

    private final DidService didService;
    private final DidAuthenticationService didAuthenticationService;

    // --- 仅供演示：用于存储挑战和临时私钥的内存映射 ---
    // 警告：在实际生产应用中，挑战需要安全的、可能是分布式的存储机制，并设置有效时间（TTL）。
    // 私钥绝不应该像这样存储在服务器端。这完全是为了方便演示和测试签名验证流程。
    private final Map<String, String> activeChallenges = new ConcurrentHashMap<>(); // 存储结构: DID -> Challenge字符串
    private final Map<String, KeyPair> demoKeyPairs = new ConcurrentHashMap<>();   // 存储结构: DID -> KeyPair (仅用于演示服务器端签名)
    // --- 演示部分结束 ---

    @Autowired
    public DidController(DidService didService, DidAuthenticationService didAuthenticationService) {
        this.didService = didService;
        this.didAuthenticationService = didAuthenticationService;
    }

    // 用于挑战请求的 DTO (数据传输对象)
    static class ChallengeRequest {
        private String did; // 用户提供的DID
        public String getDid() { return did; }
        public void setDid(String did) { this.did = did; }
    }

    // 用于签名验证请求的 DTO
    static class VerificationRequest {
        public String did;             // 用户DID
        public String challenge;       // 用户声称已签名的挑战原文
        public String signatureBase64; // 对挑战的签名 (Base64编码)
        public String keyId;           // DID文档中用于签名的密钥ID (例如: did:example:123...#keys-1)

        // Getters 和 Setters
        public String getDid() { return did; }
        public void setDid(String did) { this.did = did; }
        public String getChallenge() { return challenge; }
        public void setChallenge(String challenge) { this.challenge = challenge; }
        public String getSignatureBase64() { return signatureBase64; }
        public void setSignatureBase64(String signatureBase64) { this.signatureBase64 = signatureBase64; }
        public String getKeyId() { return keyId; }
        public void setKeyId(String keyId) { this.keyId = keyId; }
    }


    /**
     * 认证流程阶段1：客户端为给定的DID请求一个挑战。
     * POST /api/did/auth/challenge
     * 请求体: {"did": "用户DID字符串"}
     * 成功响应: {"did": "用户DID", "challenge": "生成的挑战字符串", "keyIdHint": "建议使用的keyId"}
     */
    @PostMapping("/auth/challenge")
    public ResponseEntity<Map<String, String>> requestLoginChallenge(@RequestBody ChallengeRequest challengeRequest, HttpServletRequest httpRequest) {
        String did = challengeRequest.getDid();
        if (did == null || did.isEmpty()) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "必须提供DID。"));
        }

        // 检查DID是否存在或有效
        DidDocument doc = didService.getDidDocument(did);
        if (doc == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Collections.singletonMap("error", "找不到DID: " + did));
        }
        // 检查DID文档中是否有'authentication'密钥
        if (doc.getAuthentication() == null || doc.getAuthentication().isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error", "DID " + did + " 没有注册可用于认证的密钥。"));
        }

        // 生成一个唯一的挑战字符串
        String challenge = UUID.randomUUID().toString();

        // 在服务器端安全地存储这个挑战，并与DID关联。
        // 理想情况下，这个存储应有过期时间（TTL）。
        // 为了简单演示，我们使用内存中的 activeChallenges 映射。
        // 在生产环境中，可以考虑使用 HttpSession (如果会话已建立或即将建立) 或外部缓存 (如 Redis)。
        // httpRequest.getSession().setAttribute("challenge_for_" + did, challenge); // 示例：使用会话存储
        activeChallenges.put(did, challenge); // 仅供演示的存储方式

        Map<String, String> response = new HashMap<>();
        response.put("did", did);
        response.put("challenge", challenge);
        // 可选：如果DID文档的 'authentication' 部分有密钥，可以提示客户端使用哪个keyId
        if (!doc.getAuthentication().isEmpty()) {
            response.put("keyIdHint", doc.getAuthentication().get(0)); // 例如，提示使用第一个认证密钥
        }

        System.out.println("已为 DID '" + did + "' 生成挑战: '" + challenge + "'");
        return ResponseEntity.ok(response);
    }

    /**
     * 认证流程阶段2：客户端发送对挑战的签名以供验证。
     * POST /api/did/auth/verify
     * 请求体: {"did": "...", "challenge": "...", "signatureBase64": "...", "keyId": "..."}
     * 成功响应: {"success": true, "message": "登录成功！"}
     * 失败响应: {"success": false, "message": "错误信息"}
     */
    @PostMapping("/auth/verify")
    public ResponseEntity<Map<String, Object>> verifyLoginSignature(@RequestBody VerificationRequest verificationRequest, HttpServletRequest httpRequest) {
        Map<String, Object> response = new HashMap<>();
        String did = verificationRequest.getDid();
        String clientChallenge = verificationRequest.getChallenge(); // 客户端回传的挑战
        String signatureBase64 = verificationRequest.getSignatureBase64();
        String keyId = verificationRequest.getKeyId(); // 客户端指明用于签名的密钥ID

        // 基本输入校验
        if (did == null || clientChallenge == null || signatureBase64 == null || keyId == null || keyId.isEmpty()) {
            response.put("success", false);
            response.put("message", "请求中缺少 did, challenge, signatureBase64 或 keyId。");
            return ResponseEntity.badRequest().body(response);
        }

        // 从服务器端存储中检索之前为该DID生成的挑战
        // String serverChallenge = (String) httpRequest.getSession().getAttribute("challenge_for_" + did); // 示例：从会话中获取
        String serverChallenge = activeChallenges.get(did); // 仅供演示的获取方式

        if (serverChallenge == null) {
            response.put("success", false);
            response.put("message", "此DID没有活动的挑战或会话已过期。请重新请求挑战。");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        // 验证客户端回传的挑战是否与服务器生成的挑战一致
        if (!serverChallenge.equals(clientChallenge)) {
            response.put("success", false);
            response.put("message", "挑战不匹配。客户端提供的挑战与服务器生成的挑战不一致。");
            activeChallenges.remove(did); // 移除无效尝试的挑战
            // httpRequest.getSession().removeAttribute("challenge_for_" + did); // 从会话中移除
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        // 调用认证服务验证签名
        boolean isAuthenticated = didAuthenticationService.verifyDidControl(
                did,
                serverChallenge, // **重要**：始终使用服务器端信任的挑战原文进行验证
                signatureBase64,
                keyId
        );

        // 无论成功与否，都应消耗掉（移除）这个挑战，防止重放
        activeChallenges.remove(did);
        // httpRequest.getSession().removeAttribute("challenge_for_" + did);

        if (isAuthenticated) {
            // 认证成功，创建用户会话
            HttpSession session = httpRequest.getSession(true); // 如果不存在则创建新会话
            session.setAttribute("loggedInUserDid", did); // 在会话中标记用户已登录
            session.setMaxInactiveInterval(30 * 60); // 设置会话超时时间 (例如30分钟)

            response.put("success", true);
            response.put("message", "登录成功！");
            System.out.println("用户 " + did + " 登录成功。");
            return ResponseEntity.ok(response);
        } else {
            response.put("success", false);
            response.put("message", "登录失败：签名验证失败或提供的密钥无效。");
            System.out.println("用户 " + did + " 登录失败：签名验证失败。");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }
    }

    /**
     * 用户登出。
     * POST /api/did/logout
     */
    @PostMapping("/logout")
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            HttpSession session = request.getSession(false); // 获取现有会话，不要创建新的
            if (session != null) {
                String did = (String) session.getAttribute("loggedInUserDid");
                session.invalidate(); // 使会话无效
                if (did != null) {
                    activeChallenges.remove(did); // 清理演示用的挑战存储
                    System.out.println("用户 " + did + " 已登出。");
                } else {
                    System.out.println("一个匿名会话已登出/失效。");
                }
            }
            response.put("success", true);
            response.put("message", "成功登出！");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.err.println("登出时发生异常: " + e.getMessage());
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "登出过程中发生错误。");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * 创建一个新的 DID 及其关联的 DID 文档。
     * POST /api/did/create
     * 成功响应: {"didDocument": DidDocument对象, (DEMO ONLY): "demoPrivateKeyForClientTesting": "私钥Base64"}
     */
    @PostMapping("/create")
    public ResponseEntity<?> createDid() {
        try {
            // 为DID生成密钥对 (例如RSA, Ed25519等)
            // 此处使用RSA作为示例。确保DidAuthenticationService能够处理相应类型的密钥。
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048); // RSA密钥长度
            KeyPair didKeyPair = keyGen.generateKeyPair();

            // 将公钥转换为Base64字符串 (通常是公钥的SPKI ASN.1 DER编码的Base64)
            String publicKeyBase64 = Base64.getEncoder().encodeToString(didKeyPair.getPublic().getEncoded());

            // 调用DidService创建DID和DID文档，并关联公钥
            // DidService中的createDid方法现在会填充DidDocument的'authentication'字段
            Did newDid = didService.createDid(publicKeyBase64);

            if (newDid == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("创建 DID 对象失败。");
            }

            // --- 仅供演示：不安全地在服务器端存储密钥对，以便后续的 /auth/sign-challenge-for-demo 端点使用 ---
            // 警告：绝不能在生产环境中这样做！私钥必须由用户安全保管。
            demoKeyPairs.put(newDid.getDidString(), didKeyPair);
            System.out.println("DEMO模式：已为新DID " + newDid.getDidString() + " 在服务器端临时存储密钥对。");
            // --- 演示部分结束 ---

            DidDocument didDocument = didService.getDidDocument(newDid.getDidString());

            if (didDocument != null) {
                System.out.println("DID 创建成功: " + newDid.getDidString());
                Map<String, Object> responseMap = new HashMap<>();
                responseMap.put("didDocument", didDocument); // 返回整个DID文档

                // --- 仅供演示：可以将私钥（非常不安全地）返回给客户端，以便测试签名 ---
                // 在实际应用中，客户端自己生成并保管私钥。
                // responseMap.put("demoOnly_PrivateKeyBase64_DO_NOT_USE_IN_PRODUCTION", Base64.getEncoder().encodeToString(didKeyPair.getPrivate().getEncoded()));
                // --- 演示部分结束 ---

                return ResponseEntity.ok(responseMap);
            } else {
                System.err.println("DID 已创建 ("+ newDid.getDidString() +"), 但检索其文档失败。");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("创建后检索 DID 文档失败。");
            }

        } catch (NoSuchAlgorithmException e) {
            System.err.println("生成密钥对时出错 (不支持的算法): " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("生成密钥时出错。");
        } catch (Exception e) {
            System.err.println("创建 DID 时发生意外错误: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("DID 创建期间发生意外错误。");
        }
    }

    /**
     * 演示端点：使用服务器为演示目的存储的私钥对给定的挑战进行签名。
     * 警告：此端点极不安全，仅用于测试验证流程，模拟客户端签名行为。
     * 在真实系统中，签名操作必须在客户端由用户控制的私钥执行。
     * POST /api/did/auth/sign-challenge-for-demo
     * 请求体: {"did": "用户DID", "challenge": "待签名挑战"}
     * 成功响应: {"did": "...", "challenge": "...", "signatureBase64": "...", "keyId": "..."}
     */
    @PostMapping("/auth/sign-challenge-for-demo")
    public ResponseEntity<Map<String, String>> signChallengeForDemo(@RequestBody Map<String, String> payload) {
        String did = payload.get("did");
        String challenge = payload.get("challenge");

        if (did == null || challenge == null) {
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "请求中必须包含 did 和 challenge。"));
        }

        // 从演示存储中获取该DID的密钥对
        KeyPair didKeyPair = demoKeyPairs.get(did);
        if (didKeyPair == null) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Collections.singletonMap("error", "未找到此DID的演示密钥对。请先通过 /api/did/create 创建该DID。"));
        }

        try {
            // 根据密钥类型确定签名算法。此处假设创建时使用的是RSA。
            // 如果是其他类型（如EdDSA），算法名称会不同。
            String signatureAlgorithm = "SHA256withRSA"; // 与RSA密钥对应
            // if (didKeyPair.getPublic().getAlgorithm().equals("EdDSA")) {
            //     signatureAlgorithm = "EdDSA"; // 或 "NONEwithEdDSA" if data is pre-hashed
            // }

            Signature sig = Signature.getInstance(signatureAlgorithm);
            sig.initSign(didKeyPair.getPrivate()); // 使用私钥初始化签名
            sig.update(challenge.getBytes(StandardCharsets.UTF_8)); // 提供待签名的数据 (挑战)
            byte[] signatureBytes = sig.sign(); // 执行签名
            String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes); // 将签名转为Base64

            Map<String, String> response = new HashMap<>();
            response.put("did", did);
            response.put("challenge", challenge);
            response.put("signatureBase64", signatureBase64);

            // 同时提供用于验证此签名的 keyId (从DID文档的'authentication'部分获取)
            DidDocument doc = didService.getDidDocument(did);
            if (doc != null && doc.getAuthentication() != null && !doc.getAuthentication().isEmpty()) {
                response.put("keyId", doc.getAuthentication().get(0)); // 假设使用第一个认证密钥
            } else {
                response.put("keyId", did + "#keys-1"); // 作为备选的默认keyId格式
            }

            System.out.println("DEMO签名：已为 DID '" + did + "' 的挑战 '" + challenge + "' 生成签名: " + signatureBase64);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.err.println("DEMO签名过程中发生错误: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Collections.singletonMap("error", "对挑战进行签名时出错: " + e.getMessage()));
        }
    }

    /**
     * 解析 DID 字符串以获取其 DID 文档。
     * GET /api/did/resolve/{didString}
     */
    @GetMapping("/resolve/{didString:.+}") // PathVariable 中使用 正则表达式匹配包含 ":" 等特殊字符的DID
    public ResponseEntity<DidDocument> resolveDid(@PathVariable String didString) {
        // 简单的DID格式检查，实际中可能需要更复杂的解析和验证逻辑
        if (!didString.startsWith("did:")) {
            // 根据您的DID方法规范，可能返回400 Bad Request
            // return ResponseEntity.badRequest().body(null); // 或者一个错误对象
            System.out.println("请求解析的DID格式无效: " + didString);
            // 暂时允许通过，让DidService处理
        }
        DidDocument didDocument = didService.getDidDocument(didString);
        if (didDocument != null) {
            return ResponseEntity.ok(didDocument);
        } else {
            return ResponseEntity.notFound().build(); // 如果找不到DID文档，返回404
        }
    }

    /**
     * 获取所有（在内存中）已注册的 DID 列表。
     * GET /api/did/list
     */
    @GetMapping("/list")
    public ResponseEntity<Set<String>> listDids() {
        Set<String> dids = didService.getAllDids();
        // 如果dids为null（理论上不应发生，因为getAllDids返回不可修改视图或空集），则返回空集
        return ResponseEntity.ok(dids != null ? dids : Collections.emptySet());
    }
}