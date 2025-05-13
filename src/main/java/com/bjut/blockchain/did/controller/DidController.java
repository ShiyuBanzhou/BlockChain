package com.bjut.blockchain.did.controller;

import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.did.service.DidAuthenticationService;
import com.bjut.blockchain.did.service.DidService;
import com.bjut.blockchain.web.util.CommonUtil; // 假设您有这个工具类
import com.bjut.blockchain.web.util.CryptoUtil; // 引入CryptoUtil

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.security.KeyPair; // 修复：添加了导入
import java.security.PrivateKey; // 修复：添加了导入
import java.util.Base64;
import java.util.HashMap; // 修复：用于替代 Map.of() 以兼容旧版Java
import java.util.Map;
import java.util.Optional;


@RestController
@RequestMapping("/did") // API路径前缀
public class DidController {
    private static final Logger logger = LoggerFactory.getLogger(DidController.class);

    @Autowired
    private DidService didService; // 注入DidService

    @Autowired
    private DidAuthenticationService didAuthenticationService; // 注入DidAuthenticationService

    /**
     * 创建一个新的DID。
     * @return 创建的DID文档或错误信息。
     */
    @PostMapping("/create")
    // 修复：移除了 keyType 参数，假设从 DidService 使用默认类型
    public ResponseEntity<?> createDid() {
        try {
            DidDocument didDocument = didService.createAndRegisterDid();
            return ResponseEntity.ok(didDocument);
        } catch (Exception e) {
            logger.error("创建DID时出错: ", e);
            // 修复：适配 CommonUtil.getResponse(int code, String msg, Object data)
            return CommonUtil.getResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), "创建DID失败: " + e.getMessage(), null);
        }
    }

    /**
     * 解析一个DID以获取其DID文档。
     * @param didMethod DID方法名 (例如 "example")
     * @param specificId DID的特定标识符
     * @return DID文档或错误信息。
     */
    @GetMapping("/resolve/{didMethod}/{specificId}")
    public ResponseEntity<?> resolveDid(@PathVariable String didMethod, @PathVariable String specificId) {
        String fullDid = "did:" + didMethod + ":" + specificId; // 拼接完整的DID
        Optional<DidDocument> didDocument = didService.resolveDid(fullDid);
        if (didDocument.isPresent()) { // 修复：从 isEmpty() 改为 isPresent()
            return ResponseEntity.ok(didDocument.get());
        } else {
            // 修复：适配 CommonUtil.getResponse(int code, String msg, Object data)
            return CommonUtil.getResponse(HttpStatus.NOT_FOUND.value(), "DID 未找到: " + fullDid, null);
        }
    }

    /**
     * 列出所有已注册的DID。
     * @return 包含所有DID文档的Map。
     */
    @GetMapping("/list")
    public ResponseEntity<Map<String, DidDocument>> listAllDids() {
        return ResponseEntity.ok(didService.getAllDids());
    }

    /**
     * (仅用于测试和演示) 为给定的DID和挑战生成签名。
     * @param didString 要为其生成签名的DID。
     * @return 包含挑战和签名的响应，或错误信息。
     */
    @PostMapping("/generate-challenge-signature")
    public ResponseEntity<?> generateChallengeSignature(@RequestParam String didString) {
        Optional<KeyPair> keyPairOpt = didService.getKeyPairForDid(didString); // 仅用于演示，获取存储的密钥对
        if (!keyPairOpt.isPresent()) { // 修复：从 isEmpty() 改为 isPresent()
            return CommonUtil.getResponse(HttpStatus.NOT_FOUND.value(), "未找到与DID关联的密钥对 (仅演示): " + didString, null);
        }
        PrivateKey privateKey = keyPairOpt.get().getPrivate(); // 获取私钥
        String challenge = "这是一个随机挑战字符串-" + System.currentTimeMillis(); // 生成一个简单的挑战字符串
        try {
            // 重要提示：您的 CryptoUtil.sign 方法签名是 sign(byte[] data, byte[] privateKey)
            // 此处代码期望的是 sign(byte[] data, PrivateKey privateKey)
            // 您需要：
            // 1. 修改您的 CryptoUtil.sign 以接受 PrivateKey 对象。
            // 2. 或者，在此处更改调用为 privateKey.getEncoded()。
            // 目前，此代码调用方式假定 CryptoUtil 匹配首选签名。
            // byte[] signatureBytes = CryptoUtil.sign(challenge.getBytes(), privateKey);

            // 修复：适配用户的 CryptoUtil.sign(byte[] data, byte[] privateKey)
            byte[] signatureBytes = CryptoUtil.sign(challenge.getBytes(), privateKey.getEncoded());


            String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes); // 将签名编码为Base64

            // 修复：使用 HashMap 替代 Map.of() 以兼容旧版Java
            Map<String, String> response = new HashMap<>();
            response.put("did", didString);
            response.put("challenge", challenge);
            response.put("signatureBase64", signatureBase64);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            logger.error("生成签名时出错: ", e);
            return CommonUtil.getResponse(HttpStatus.INTERNAL_SERVER_ERROR.value(), "生成签名失败: " + e.getMessage(), null);
        }
    }

    /**
     * 验证DID的控制权。
     * @param didString 要验证的DID。
     * @param challenge 用于验证的挑战字符串。
     * @param signatureBase64 对挑战的签名 (Base64编码)。
     * @param publicKeyId (可选) DID文档中用于签名的公钥ID。
     * @return 验证结果。
     */
    @PostMapping("/verify-did")
    public ResponseEntity<?> verifyDid(
            @RequestParam String didString,
            @RequestParam String challenge,
            @RequestParam String signatureBase64,
            @RequestParam(required = false) String publicKeyId) {

        boolean isValid = didAuthenticationService.verifyDidControl(didString, challenge, signatureBase64, publicKeyId);
        if (isValid) {
            return CommonUtil.getResponse(HttpStatus.OK.value(), "DID 验证成功: " + didString, null);
        } else {
            return CommonUtil.getResponse(HttpStatus.UNAUTHORIZED.value(), "DID 验证失败: " + didString, null);
        }
    }
}