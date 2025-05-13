package com.bjut.blockchain.did.service;

import com.bjut.blockchain.did.model.Did;
import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.web.util.CryptoUtil; // 假设您有此工具类，或使用类似功能
// import com.bjut.blockchain.web.util.PublicKeyUtil; // 如果有公钥转换等帮助方法

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class DidService {
    private static final Logger logger = LoggerFactory.getLogger(DidService.class);

    // 内存中的DID注册表 (DID -> DIDDocument)
    // 注意：这只是一个模拟，实际应用中DID文档会存储在区块链或其他分布式账本上
    private final Map<String, DidDocument> didRegistry = new ConcurrentHashMap<>();
    // 内存中的私钥存储 (DID -> PrivateKey) - 极度不安全，仅用于演示目的！
    // 真实场景中，私钥由用户/实体自己安全保管。
    private final Map<String, KeyPair> privateKeyStore = new ConcurrentHashMap<>();


    /**
     * 创建一个新的DID和关联的DID文档。
     * 注意: keyType 参数已移除，假设 CryptoUtil.generateKeyPair() 生成默认类型密钥。
     * @return 生成的DID文档。
     * @throws Exception 如果密钥生成失败。
     */
    public DidDocument createAndRegisterDid() throws Exception { // 修复：移除了 keyType 参数
        // 1. 生成密钥对
        // 修复：根据用户的 CryptoUtil 调用 generateKeyPair() (无参数)
        // 重要提示：您的 CryptoUtil.generateKeyPair() 需要能正常工作。
        KeyPair keyPair = CryptoUtil.generateKeyPair();
        if (keyPair == null) {
            throw new RuntimeException("CryptoUtil.generateKeyPair() 返回为 null");
        }
        PublicKey publicKey = keyPair.getPublic();

        // 2. 生成唯一的特定标识符
        String specificIdentifier = UUID.randomUUID().toString().replace("-", "");
        Did did = new Did(specificIdentifier);
        String fullDid = did.getFullDid(); // 修复：修正了方法名使用

        // 3. 创建验证方法
        String publicKeyEncodedString = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String keyId = fullDid + "#keys-1"; // 验证方法的ID

        // 根据公钥算法确定验证方法类型
        // 这是一个简化的假设。真实的DID方法有更复杂的规则。
        String verificationMethodType;
        switch (publicKey.getAlgorithm()) {
            case "EC":
            case "ECDSA": // BouncyCastle 或 SunEC 的 EC 密钥常用此算法名
                verificationMethodType = "EcdsaSecp256k1VerificationKey2019"; // 假设 EC 密钥使用 secp256k1 曲线
                break;
            case "RSA":
                verificationMethodType = "RsaVerificationKey2018";
                break;
            default:
                logger.warn("未知的公钥算法 '{}', 使用通用的验证方法类型。", publicKey.getAlgorithm());
                verificationMethodType = "VerificationKey2020"; // 通用备用类型
                break;
        }


        DidDocument.VerificationMethod verificationMethod = new DidDocument.VerificationMethod(
                keyId,
                verificationMethodType,
                fullDid, // controller 是 DID 本身
                publicKeyEncodedString // 使用Base64编码的公钥字符串
        );

        // 4. 创建DID文档
        DidDocument didDocument = new DidDocument(fullDid, Collections.singletonList(verificationMethod));

        // 5. (模拟) 注册DID文档到内存注册表
        didRegistry.put(fullDid, didDocument);
        // (极不安全，仅演示用) 存储私钥以便后续演示签名操作
        privateKeyStore.put(fullDid, keyPair);

        logger.info("创建并注册了新的DID: {}, 文档: {}", fullDid, didDocument);
        return didDocument;
    }

    // getKeyTypeForDidDocument 方法已移除，因为 keyType 不再是此处的直接输入。
    // 类型现在从生成的公钥算法中推断。

    /**
     * 解析DID，从内存注册表中获取其DID文档。
     * @param didString 完整的DID字符串 (例如 "did:example:123...")
     * @return Optional包含DID文档，如果未找到则为空。
     */
    public Optional<DidDocument> resolveDid(String didString) {
        DidDocument doc = didRegistry.get(didString);
        if (doc == null) {
            logger.warn("无法解析DID: {} - 未在注册表中找到。", didString);
        }
        return Optional.ofNullable(doc);
    }

    /**
     * (仅用于演示) 获取与DID关联的密钥对。
     * 警告：在实际应用中，服务不应该能访问用户的私钥。
     */
    public Optional<KeyPair> getKeyPairForDid(String didString) { // 修复：添加了 KeyPair 的导入
        return Optional.ofNullable(privateKeyStore.get(didString));
    }

    /**
     * 获取所有已注册的DID及其文档。
     * @return 包含所有DID文档的Map。
     */
    public Map<String, DidDocument> getAllDids() {
        return Collections.unmodifiableMap(didRegistry);
    }
}