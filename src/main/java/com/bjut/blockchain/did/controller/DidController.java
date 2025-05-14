package com.bjut.blockchain.did.controller;

import com.bjut.blockchain.did.model.Did; // Did模型
import com.bjut.blockchain.did.model.DidDocument; // DidDocument模型
import com.bjut.blockchain.did.service.DidAuthenticationService; // 认证服务
import com.bjut.blockchain.did.service.DidService; // DID管理服务
import org.slf4j.Logger; // SLF4J 日志接口
import org.slf4j.LoggerFactory; // SLF4J 日志工厂
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest; // HTTP请求对象，用于session管理
import javax.servlet.http.HttpSession; // HTTP Session对象
// 移除了 KeyPair, KeyPairGenerator, Signature 的导入，因为服务器不再直接处理这些用于演示的私钥操作
import java.util.*; // 集合框架
// 移除了 ConcurrentHashMap 的导入，因为 demoKeyPairs 被移除了

@RestController
@RequestMapping("/api/did") // 所有此控制器的API都以 /api/did 开头
public class DidController {

    private static final Logger logger = LoggerFactory.getLogger(DidController.class);

    private final DidService didService;
    private final DidAuthenticationService didAuthenticationService;

    // demoKeyPairs Map 已被移除，服务器不再存储演示私钥

    @Autowired
    public DidController(DidService didService, DidAuthenticationService didAuthenticationService) {
        this.didService = didService;
        this.didAuthenticationService = didAuthenticationService;
    }

    // DTO 定义 (ChallengeRequest, VerificationRequest) 保持不变
    static class ChallengeRequest {
        private String did;
        public String getDid() { return did; }
        public void setDid(String did) { this.did = did; }
    }

    static class VerificationRequest {
        public String did;
        public String challenge;
        public String signatureBase64;
        public String keyId;

        public String getDid() { return did; }
        public void setDid(String did) { this.did = did; }
        public String getChallenge() { return challenge; }
        public void setChallenge(String challenge) { this.challenge = challenge; }
        public String getSignatureBase64() { return signatureBase64; }
        public void setSignatureBase64(String signatureBase64) { this.signatureBase64 = signatureBase64; }
        public String getKeyId() { return keyId; }
        public void setKeyId(String keyId) { this.keyId = keyId; }
    }

    // 新的 DTO 用于 /api/did/create 请求体
    static class CreateDidRequest {
        private String publicKeyBase64; // 客户端提供的公钥 (Base64编码)

        public String getPublicKeyBase64() { return publicKeyBase64; }
        public void setPublicKeyBase64(String publicKeyBase64) { this.publicKeyBase64 = publicKeyBase64; }
    }

    /**
     * 认证流程阶段1：客户端为给定的DID请求一个挑战。
     * POST /api/did/auth/challenge
     */
    @PostMapping("/auth/challenge")
    public ResponseEntity<Map<String, String>> requestLoginChallenge(@RequestBody ChallengeRequest challengeRequest, HttpServletRequest httpRequest) {
        String did = challengeRequest.getDid();
        if (did == null || did.isEmpty()) {
            logger.warn("请求挑战失败：DID为空。");
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "必须提供DID。"));
        }

        DidDocument doc = didService.getDidDocument(did);
        if (doc == null) {
            logger.warn("请求挑战失败：找不到DID '{}'。", did);
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Collections.singletonMap("error", "找不到DID: " + did));
        }
        if (doc.getAuthentication() == null || doc.getAuthentication().isEmpty()) {
            logger.warn("请求挑战失败：DID '{}' 没有注册可用于认证的密钥。", did);
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Collections.singletonMap("error", "DID " + did + " 没有注册可用于认证的密钥。"));
        }

        String challenge = UUID.randomUUID().toString();
        HttpSession session = httpRequest.getSession(true);

        session.setAttribute("login_challenge", challenge);
        session.setAttribute("login_challenge_did", did);

        Map<String, String> response = new HashMap<>();
        response.put("did", did);
        response.put("challenge", challenge);
        if (!doc.getAuthentication().isEmpty()) {
            response.put("keyIdHint", doc.getAuthentication().get(0));
        }

        logger.info("已为 DID '{}' 在会话 {} 中生成挑战: '{}'", did, session.getId(), challenge);
        return ResponseEntity.ok(response);
    }

    /**
     * 认证流程阶段2：客户端发送对挑战的签名以供验证。
     * POST /api/did/auth/verify
     */
    @PostMapping("/auth/verify")
    public ResponseEntity<Map<String, Object>> verifyLoginSignature(@RequestBody VerificationRequest verificationRequest, HttpServletRequest httpRequest) {
        Map<String, Object> response = new HashMap<>();
        String did = verificationRequest.getDid();
        String clientChallenge = verificationRequest.getChallenge();
        String signatureBase64 = verificationRequest.getSignatureBase64();
        String keyId = verificationRequest.getKeyId();

        if (did == null || clientChallenge == null || signatureBase64 == null || keyId == null || keyId.isEmpty()) {
            logger.warn("验证签名失败：请求参数不完整。DID: {}, Challenge: {}, Signature: {}, KeyID: {}", did, clientChallenge, signatureBase64 != null, keyId);
            response.put("success", false);
            response.put("message", "请求中缺少 did, challenge, signatureBase64 或 keyId。");
            return ResponseEntity.badRequest().body(response);
        }

        HttpSession session = httpRequest.getSession(false);
        if (session == null) {
            logger.warn("验证签名失败：会话不存在或已过期，无法找到DID '{}' 的挑战。", did);
            response.put("success", false);
            response.put("message", "会话不存在或已过期。请重新请求挑战。");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        String serverChallenge = (String) session.getAttribute("login_challenge");
        String challengeDid = (String) session.getAttribute("login_challenge_did");

        session.removeAttribute("login_challenge");
        session.removeAttribute("login_challenge_did");

        if (serverChallenge == null || challengeDid == null) {
            logger.warn("验证签名失败：在会话 {} 中未找到有效的服务器端挑战或关联的DID。", session.getId());
            response.put("success", false);
            response.put("message", "服务器端未找到有效挑战。请重新请求挑战。");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        if (!challengeDid.equals(did)) {
            logger.warn("验证签名失败：会话中的挑战是为DID '{}' 生成的，但当前验证请求针对DID '{}'。", challengeDid, did);
            response.put("success", false);
            response.put("message", "提供的DID与当前会话中挑战关联的DID不符。");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        if (!serverChallenge.equals(clientChallenge)) {
            logger.warn("验证签名失败：客户端挑战 '{}' 与服务器端挑战 '{}' (为DID '{}' 生成) 不匹配。", clientChallenge, serverChallenge, did);
            response.put("success", false);
            response.put("message", "挑战不匹配。客户端提供的挑战与服务器生成的挑战不一致。");
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        boolean isAuthenticated = didAuthenticationService.verifyDidControl(
                did,
                serverChallenge,
                signatureBase64,
                keyId
        );

        if (isAuthenticated) {
            HttpSession userSession = httpRequest.getSession(true);
            userSession.setAttribute("loggedInUserDid", did);
            userSession.setMaxInactiveInterval(30 * 60);

            response.put("success", true);
            response.put("message", "登录成功！");
            logger.info("用户 '{}' (会话ID: {}) 登录成功。", did, userSession.getId());
            return ResponseEntity.ok(response);
        } else {
            response.put("success", false);
            response.put("message", "登录失败：签名验证失败或提供的密钥无效。");
            logger.warn("用户 '{}' 登录失败：签名验证失败。", did);
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
            HttpSession session = request.getSession(false);
            if (session != null) {
                String did = (String) session.getAttribute("loggedInUserDid");
                session.removeAttribute("login_challenge");
                session.removeAttribute("login_challenge_did");
                session.invalidate();
                logger.info("用户 '{}' (原会话ID: {}) 已登出。", (did != null ? did : "[未知用户]"), session.getId());
            } else {
                logger.info("请求登出，但没有活动的会话。");
            }
            response.put("success", true);
            response.put("message", "成功登出！");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("登出时发生异常: {}", e.getMessage(), e);
            response.put("success", false);
            response.put("message", "登出过程中发生错误。");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * 创建一个新的 DID 及其关联的 DID 文档。
     * 客户端需要提供其公钥。服务器不再生成密钥对。
     * POST /api/did/create
     * 请求体: {"publicKeyBase64": "客户端生成的公钥Base64字符串"}
     * 成功响应: {"didDocument": DidDocument对象}
     */
    @PostMapping("/create")
    public ResponseEntity<?> createDid(@RequestBody CreateDidRequest createDidRequest) {
        String publicKeyBase64 = createDidRequest.getPublicKeyBase64();

        if (publicKeyBase64 == null || publicKeyBase64.isEmpty()) {
            logger.warn("创建DID失败：请求中未提供publicKeyBase64。");
            return ResponseEntity.badRequest().body(Collections.singletonMap("error", "必须在请求体中提供 publicKeyBase64。"));
        }

        try {
            // 服务器现在使用客户端提供的公钥来创建DID文档
            Did newDid = didService.createDid(publicKeyBase64);

            if (newDid == null) {
                logger.error("创建DID对象失败，didService.createDid返回null。");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("创建 DID 对象失败。");
            }

            // demoKeyPairs Map 和相关逻辑已被移除，服务器不再存储私钥。

            DidDocument didDocument = didService.getDidDocument(newDid.getDidString());

            if (didDocument != null) {
                logger.info("DID 创建成功: {}", newDid.getDidString());
                Map<String, Object> responseMap = new HashMap<>();
                responseMap.put("didDocument", didDocument); // 返回整个DID文档
                return ResponseEntity.ok(responseMap);
            } else {
                logger.error("DID '{}' 已创建, 但检索其文档失败。", newDid.getDidString());
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("创建后检索 DID 文档失败。");
            }
        } catch (Exception e) { // 更通用的异常捕获
            logger.error("创建 DID 时发生意外错误: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("DID 创建期间发生意外错误：" + e.getMessage());
        }
    }

    // DEMO 端点 /api/did/auth/sign-challenge-for-demo 已被移除。

    /**
     * 解析 DID 字符串以获取其 DID 文档。
     * GET /api/did/resolve/{didString}
     */
    @GetMapping("/resolve/{didString:.+}")
    public ResponseEntity<DidDocument> resolveDid(@PathVariable String didString) {
        if (!didString.startsWith("did:")) {
            logger.debug("请求解析的DID '{}' 格式可能无效。", didString);
        }
        DidDocument didDocument = didService.getDidDocument(didString);
        if (didDocument != null) {
            return ResponseEntity.ok(didDocument);
        } else {
            logger.info("未能解析DID '{}'，文档未找到。", didString);
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * 获取所有（在内存中）已注册的 DID 列表。
     * GET /api/did/list
     */
    @GetMapping("/list")
    public ResponseEntity<Set<String>> listDids() {
        Set<String> dids = didService.getAllDids();
        return ResponseEntity.ok(dids != null ? dids : Collections.emptySet());
    }
}