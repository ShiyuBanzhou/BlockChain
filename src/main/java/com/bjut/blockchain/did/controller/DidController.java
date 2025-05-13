package com.bjut.blockchain.did.controller;

import com.bjut.blockchain.did.dto.LoginRequest;
import com.bjut.blockchain.did.model.Did;
import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.did.service.DidAuthenticationService;
import com.bjut.blockchain.did.service.DidService;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.nio.charset.StandardCharsets;
import java.util.*;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

/**
 * 用于管理去中心化标识符 (DID) 的 REST 控制器。
 */
@RestController
@RequestMapping("/api/did") // <--- 修改: DID 操作的基础路径统一为 /api/did
public class DidController {

    private final DidService didService; // 声明为 final
    private final DidAuthenticationService didAuthenticationService; // 声明为 final

    // 推荐使用构造函数注入所有必要的依赖
    @Autowired
    public DidController(DidService didService, DidAuthenticationService didAuthenticationService) {
        this.didService = didService;
        this.didAuthenticationService = didAuthenticationService;
    }

    // 在此控制器实例中临时存储生成的密钥对 (仅用于演示目的)
    // 实际应用中，应使用安全存储或在外部管理密钥。
    private KeyPair lastGeneratedKeyPair;
    private String lastGeneratedDid; // 存储上一个生成的 DID，用于验证演示

    /**
     * 处理用户登录请求
     * @param loginRequest 包含DID和密码的登录请求体
     * @param request HttpServletRequest 用于获取HttpSession
     * @return ResponseEntity 包含登录结果
     */
    @PostMapping("/login") // 完整路径: /api/did/login
    public ResponseEntity<Map<String, Object>> login(@RequestBody LoginRequest loginRequest, HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            boolean isAuthenticated = didAuthenticationService.authenticate(loginRequest.getDid(), loginRequest.getPassword());

            if (isAuthenticated) {
                HttpSession session = request.getSession(true);
                session.setAttribute("loggedInUserDid", loginRequest.getDid());
                session.setMaxInactiveInterval(30 * 60);

                response.put("success", true);
                response.put("message", "登录成功！");
                return ResponseEntity.ok(response);
            } else {
                response.put("success", false);
                response.put("message", "认证失败：DID或密码错误。");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
            }
        } catch (Exception e) {
            System.err.println("登录异常: " + e.getMessage());
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "登录过程中发生错误，请稍后再试。");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * 处理用户登出请求
     * @param request HttpServletRequest 用于获取和使会话无效
     * @return ResponseEntity 包含登出结果
     */
    @PostMapping("/logout") // 完整路径: /api/did/logout
    public ResponseEntity<Map<String, Object>> logout(HttpServletRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            HttpSession session = request.getSession(false);
            if (session != null) {
                session.invalidate();
            }
            response.put("success", true);
            response.put("message", "成功登出！");
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            System.err.println("登出异常: " + e.getMessage());
            e.printStackTrace();
            response.put("success", false);
            response.put("message", "登出过程中发生错误。");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
    }

    /**
     * 创建一个新的 DID 及其关联的 DID 文档的端点。
     * @return 包含创建的 DidDocument 或错误消息的 ResponseEntity。
     */
    @PostMapping("/create") // 完整路径: /api/did/create
    public ResponseEntity<?> createDid() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair didKeyPair = keyGen.generateKeyPair();

            String publicKeyForDidDocument = Base64.getEncoder().encodeToString(didKeyPair.getPublic().getEncoded());
            // System.out.println("为DID文档生成的公钥 (Base64, X.509): " + publicKeyForDidDocument);

            Did newDid = didService.createDid(publicKeyForDidDocument);

            if (newDid == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("创建 DID 对象失败。");
            }
            // lastGeneratedDid = newDid.getDidString();
            // lastGeneratedKeyPair = didKeyPair; // 如果需要在其他地方使用这个刚生成的密钥对

            DidDocument didDocument = didService.getDidDocument(newDid.getDidString());

            if (didDocument != null) {
                // System.out.println("DID 创建成功: " + newDid.getDidString());
                return ResponseEntity.ok(didDocument);
            } else {
                // System.err.println("DID 已创建 ("+ newDid.getDidString() +"), 但检索其文档失败。");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("创建后检索 DID 文档失败。");
            }

        } catch (NoSuchAlgorithmException e) {
            // System.err.println("生成密钥对时出错: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("生成密钥出错。");
        } catch (Exception e) {
            // System.err.println("创建 DID 时出错: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("DID 创建期间发生意外错误。");
        }
    }

    /**
     * 将 DID 字符串解析为其 DID 文档的端点。
     * @param didString 要解析的 DID 字符串 (作为路径变量传递)。
     * @return 包含 DidDocument 或 404 Not Found 错误的 ResponseEntity。
     */
    @GetMapping("/resolve/{didString:.+}") // 完整路径: /api/did/resolve/{didString}
    public ResponseEntity<DidDocument> resolveDid(@PathVariable String didString) {
        if (!didString.startsWith("did:")) {
            return ResponseEntity.badRequest().build();
        }
        DidDocument didDocument = didService.getDidDocument(didString);
        if (didDocument != null) {
            return ResponseEntity.ok(didDocument);
        } else {
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * 获取所有已注册 DID 列表的端点。
     * @return 包含 DID 字符串集合的 ResponseEntity。
     */
    @GetMapping("/list") // 完整路径: /api/did/list
    public ResponseEntity<Set<String>> listDids() {
        Set<String> dids = didService.getAllDids();
        return ResponseEntity.ok(dids != null ? dids : Collections.emptySet());
    }

    /**
     * (演示端点) 检索上次生成的密钥对的公钥的端点。
     * @return 包含 Base64 编码公钥或错误消息的 ResponseEntity。
     */
    @GetMapping("/showPublicKey") // 完整路径: /api/did/showPublicKey
    public ResponseEntity<String> showLastPublicKey() {
        if (lastGeneratedKeyPair != null) {
            String publicKeyEncoded = Base64.getEncoder().encodeToString(lastGeneratedKeyPair.getPublic().getEncoded());
            return ResponseEntity.ok(publicKeyEncoded);
        } else {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("此会话中尚未通过 /did/create 生成密钥对。");
        }
    }

    static class VerificationRequest {
        public String did;
        public String challenge;
        public String signatureBase64;
        public String keyId;

        // Getters and Setters...
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
     * 使用挑战-响应签名验证 DID 控制权的端点。
     * @param request 包含 did、challenge、signatureBase64 和可选 keyId 的请求体。
     * @return 指示成功 (200 OK) 或失败 (401 Unauthorized) 的 ResponseEntity。
     */
    @PostMapping("/verifyControl") // 完整路径: /api/did/verifyControl
    public ResponseEntity<String> verifyControl(@RequestBody VerificationRequest request) {
        if (request == null || request.getDid() == null || request.getChallenge() == null || request.getSignatureBase64() == null) {
            return ResponseEntity.badRequest().body("请求体中缺少必填字段 (did, challenge, signatureBase64)");
        }
        boolean isValid = didAuthenticationService.verifyDidControl(
                request.getDid(),
                request.getChallenge(),
                request.getSignatureBase64(),
                request.getKeyId()
        );
        if (isValid) {
            return ResponseEntity.ok("DID 验证成功: " + request.getDid());
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("DID 验证失败: " + request.getDid());
        }
    }

    /**
     * (演示端点) 使用上次生成的私钥对默认挑战进行签名。
     * @return Base64 编码的签名或错误消息。
     */
    @GetMapping("/signChallenge") // 完整路径: /api/did/signChallenge
    public ResponseEntity<String> signDefaultChallenge() {
        if (lastGeneratedKeyPair == null || lastGeneratedDid == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("此会话中尚未通过 /did/create 生成密钥对或创建 DID。");
        }
        String challenge = "default-challenge-for-" + lastGeneratedDid;
        try {
            String algorithm = "SHA256withRSA";
            Signature sig = Signature.getInstance(algorithm);
            sig.initSign(lastGeneratedKeyPair.getPrivate());
            sig.update(challenge.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = sig.sign();
            String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);
            // System.out.println("已使用 " + algorithm + " 对挑战 '" + challenge + "' 进行签名");
            return ResponseEntity.ok(signatureBase64);
        } catch (Exception e) {
            // System.err.println("对挑战进行签名时出错: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("对挑战进行签名时出错: " + e.getMessage());
        }
    }
}
