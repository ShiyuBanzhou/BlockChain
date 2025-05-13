package com.bjut.blockchain.did.controller;

import com.bjut.blockchain.did.model.Did;
import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.did.service.DidAuthenticationService; // 引入认证服务
import com.bjut.blockchain.did.service.DidService;
// 引入密钥对和相关类
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature; // 引入签名类
import java.nio.charset.StandardCharsets; // 引入字符集
import java.util.Base64; // 用于编码公钥和签名
import java.util.Collections; // 用于空集合
import java.util.Set;
import java.util.Optional; // 引入 Optional

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * 用于管理去中心化标识符 (DID) 的 REST 控制器。
 */
@RestController
@RequestMapping("/did") // DID 操作的基础路径
public class DidController {

    @Autowired
    private DidService didService; // 注入 DID 服务

    @Autowired // 确保 DidAuthenticationService 已注入
    private DidAuthenticationService didAuthenticationService; // 注入 DID 认证服务

    // 在此控制器实例中临时存储生成的密钥对 (仅用于演示目的)
    // 实际应用中，应使用安全存储或在外部管理密钥。
    private KeyPair lastGeneratedKeyPair;
    private String lastGeneratedDid; // 存储上一个生成的 DID，用于验证演示

    /**
     * 创建一个新的 DID 及其关联的 DID 文档的端点。
     * 此示例生成一个密钥对并使用其公钥。
     * **临时使用 RSA 密钥以兼容旧版 Java。**
     *
     * @return 包含创建的 DidDocument 或错误消息的 ResponseEntity。
     */
    @PostMapping("/create")
    public ResponseEntity<?> createDid() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);
            KeyPair didKeyPair = keyGen.generateKeyPair(); // 这个密钥对用于DID的验证方法
            // lastGeneratedKeyPair = didKeyPair; // 你可以用它来演示签名，但它与证书密钥对的关系需要明确

            String publicKeyForDidDocument = Base64.getEncoder().encodeToString(didKeyPair.getPublic().getEncoded());
            System.out.println("为DID文档生成的公钥 (Base64, X.509): " + publicKeyForDidDocument);

            Did newDid = didService.createDid(publicKeyForDidDocument);

            if (newDid == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("创建 DID 对象失败。");
            }
            // lastGeneratedDid = newDid.getDidString(); // 你可能还想存储这个

            DidDocument didDocument = didService.getDidDocument(newDid.getDidString());

            if (didDocument != null) {
                System.out.println("DID 创建成功: " + newDid.getDidString());
                return ResponseEntity.ok(didDocument);
            } else {
                System.err.println("DID 已创建 ("+ newDid.getDidString() +"), 但检索其文档失败。");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("创建后检索 DID 文档失败。");
            }

        } catch (NoSuchAlgorithmException e) {
            System.err.println("生成密钥对时出错: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("生成密钥出错。");
        } catch (Exception e) {
            System.err.println("创建 DID 时出错: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("DID 创建期间发生意外错误。");
        }
    }

    /**
     * 将 DID 字符串解析为其 DID 文档的端点。
     *
     * @param didString 要解析的 DID 字符串 (作为路径变量传递)。
     * @return 包含 DidDocument 或 404 Not Found 错误的 ResponseEntity。
     */
    @GetMapping("/resolve/{didString:.+}") // 使用 .+ 捕获包含冒号的完整 DID 字符串
    public ResponseEntity<DidDocument> resolveDid(@PathVariable String didString) {
        // 基本验证，可以更健壮
        if (!didString.startsWith("did:")) {
            return ResponseEntity.badRequest().build(); // 如果格式不正确，返回 400
        }
        // 调用服务获取 DID 文档
        DidDocument didDocument = didService.getDidDocument(didString);
        if (didDocument != null) {
            // 如果找到，返回 200 OK 和文档
            return ResponseEntity.ok(didDocument);
        } else {
            // 如果未找到，返回 404 Not Found
            return ResponseEntity.notFound().build();
        }
    }

    /**
     * 获取所有已注册 DID 列表的端点。
     *
     * @return 包含 DID 字符串集合的 ResponseEntity。
     */
    @GetMapping("/list")
    public ResponseEntity<Set<String>> listDids() {
        // 调用服务获取所有 DID
        Set<String> dids = didService.getAllDids();
        if (dids != null) {
            // 返回 200 OK 和 DID 集合
            return ResponseEntity.ok(dids);
        } else {
            // 理论上不应发生，除非服务初始化注册表失败
            return ResponseEntity.ok(Collections.emptySet()); // 返回空集合
        }
    }

    /**
     * (演示端点) 检索上次生成的密钥对的公钥的端点。
     * **警告：** 这仅用于演示目的。
     *
     * @return 包含 Base64 编码公钥或错误消息的 ResponseEntity。
     */
    @GetMapping("/showPublicKey")
    public ResponseEntity<String> showLastPublicKey() {
        // 检查是否已通过 /did/create 在此会话中生成密钥对
        if (lastGeneratedKeyPair != null) {
            // 获取公钥并进行 Base64 编码
            String publicKeyEncoded = Base64.getEncoder().encodeToString(lastGeneratedKeyPair.getPublic().getEncoded());
            // 返回 200 OK 和公钥字符串
            return ResponseEntity.ok(publicKeyEncoded);
        } else {
            // 如果尚未生成密钥对，返回 404 Not Found
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("此会话中尚未通过 /did/create 生成密钥对。");
        }
    }

    // --- 用于验证请求的内部 DTO 类 ---
    static class VerificationRequest {
        public String did; // DID 字符串
        public String challenge; // 挑战字符串
        public String signatureBase64; // Base64 编码的签名
        public String keyId; // (可选) 用于签名的公钥 ID

        // Getters 和 Setters...
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
     *
     * @param request 包含 did、challenge、signatureBase64 和可选 keyId 的请求体。
     * @return 指示成功 (200 OK) 或失败 (401 Unauthorized) 的 ResponseEntity。
     */
    @PostMapping("/verifyControl")
    public ResponseEntity<String> verifyControl(@RequestBody VerificationRequest request) {
        // 基本的请求体验证
        if (request == null || request.getDid() == null || request.getChallenge() == null || request.getSignatureBase64() == null) {
            return ResponseEntity.badRequest().body("请求体中缺少必填字段 (did, challenge, signatureBase64)");
        }
        // 调用认证服务进行验证
        boolean isValid = didAuthenticationService.verifyDidControl(
                request.getDid(),
                request.getChallenge(),
                request.getSignatureBase64(),
                request.getKeyId() // keyId 可以为 null
        );
        if (isValid) {
            // 验证成功，返回 200 OK
            return ResponseEntity.ok("DID 验证成功: " + request.getDid());
        } else {
            // 验证失败，返回 401 Unauthorized
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("DID 验证失败: " + request.getDid());
        }
    }

    /**
     * (演示端点) 使用上次生成的私钥对默认挑战进行签名。
     * **警告：** 以这种方式暴露签名是不安全的。仅用于演示目的。
     * @return Base64 编码的签名或错误消息。
     */
    @GetMapping("/signChallenge")
    public ResponseEntity<String> signDefaultChallenge() {
        // 检查是否已生成密钥对和 DID
        if (lastGeneratedKeyPair == null || lastGeneratedDid == null) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("此会话中尚未通过 /did/create 生成密钥对或创建 DID。");
        }
        // 定义一个默认的挑战字符串
        String challenge = "default-challenge-for-" + lastGeneratedDid;
        try {
            // 根据密钥类型确定签名算法 (当前为 RSA)
            String algorithm = "SHA256withRSA"; // RSA 的标准签名算法
            // 如果切换回 EC, 使用 "SHA256withECDSA"
            // 如果使用 Ed25519 (配合 BouncyCastle), 使用 "EdDSA"

            // 创建签名对象
            Signature sig = Signature.getInstance(algorithm);
            // 使用私钥初始化签名
            sig.initSign(lastGeneratedKeyPair.getPrivate());
            // 更新要签名的数据 (挑战字符串的 UTF-8 字节)
            sig.update(challenge.getBytes(StandardCharsets.UTF_8));
            // 执行签名操作
            byte[] signatureBytes = sig.sign();
            // 将签名结果进行 Base64 编码
            String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);

            System.out.println("已使用 " + algorithm + " 对挑战 '" + challenge + "' 进行签名");
            // 返回 200 OK 和 Base64 编码的签名
            return ResponseEntity.ok(signatureBase64);

        } catch (Exception e) {
            // 捕获签名过程中可能出现的异常
            System.err.println("对挑战进行签名时出错: " + e.getMessage());
            e.printStackTrace();
            // 返回 500 Internal Server Error
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("对挑战进行签名时出错: " + e.getMessage());
        }
    }
}
