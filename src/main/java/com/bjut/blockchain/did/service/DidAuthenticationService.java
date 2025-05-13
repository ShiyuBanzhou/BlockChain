package com.bjut.blockchain.did.service;

import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.web.util.CryptoUtil; // 您的加密工具类
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.PublicKey; // 修复：添加了导入
import java.security.KeyPair;   // 修复：添加了导入
import java.security.KeyFactory; // 用于重构 PublicKey
import java.security.spec.X509EncodedKeySpec; // 用于重构 PublicKey
import java.util.Base64;
import java.util.Optional;

@Service
public class DidAuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(DidAuthenticationService.class);

    @Autowired
    private DidService didService; // 注入DidService

    /**
     * 验证一个实体是否拥有给定DID的控制权。
     * 这通常通过要求实体使用其与DID关联的私钥签署一个挑战（challenge）来实现。
     *
     * @param didString 要验证的DID
     * @param challenge 一个随机生成的字符串或数据，由调用方提供
     * @param signatureBase64 由实体使用其私钥对挑战进行的签名的Base64编码
     * @param publicKeyIdInDocument (可选) DID文档中用于签名的公钥的ID (例如 "did:example:123#keys-1")
     * 如果为null，则尝试使用DID文档中的第一个合适的公钥。
     * @return 如果签名有效且与DID关联，则为true。
     */
    public boolean verifyDidControl(String didString, String challenge, String signatureBase64, String publicKeyIdInDocument) {
        Optional<DidDocument> didDocumentOpt = didService.resolveDid(didString);
        if (!didDocumentOpt.isPresent()) { // 修复：从 isEmpty() 改为 !isPresent() 以兼容旧版Java
            logger.warn("DID认证失败：无法解析DID {}", didString);
            return false;
        }

        DidDocument didDocument = didDocumentOpt.get();
        if (didDocument.getVerificationMethod() == null || didDocument.getVerificationMethod().isEmpty()) {
            logger.warn("DID认证失败：DID文档 {} 中没有验证方法。", didString);
            return false;
        }

        // 查找用于验证的公钥
        Optional<DidDocument.VerificationMethod> verificationMethodOpt = findVerificationMethod(didDocument, publicKeyIdInDocument);

        if (!verificationMethodOpt.isPresent()) { // 修复：从 isEmpty() 改为 !isPresent()
            logger.warn("DID认证失败：在DID文档 {} 中未找到合适的公钥 (ID: {}).", didString, publicKeyIdInDocument);
            return false;
        }

        DidDocument.VerificationMethod vm = verificationMethodOpt.get();
        try {
            // 从DID文档中获取公钥 (假设是Base64编码的)
            byte[] publicKeyEncodedBytes = Base64.getDecoder().decode(vm.getPublicKeyEncoded());

            // 从编码字节重构 PublicKey 对象
            // 从验证方法类型推断算法 (简化版)
            String keyAlgorithm;
            if (vm.getType().contains("Rsa")) {
                keyAlgorithm = "RSA";
            } else if (vm.getType().contains("Ecdsa") || vm.getType().contains("EC")) { // EC密钥常用
                keyAlgorithm = "EC"; // 或 "ECDSA"，取决于提供者
            } else {
                logger.error("无法从验证方法类型 {} 推断公钥算法。", vm.getType());
                // 尝试使用存储的密钥对中的算法进行演示，
                // 这在生产环境中不应该这样做。
                // 在生产环境中，DID文档的VM类型必须足够明确。
                Optional<KeyPair> tempKeyPair = didService.getKeyPairForDid(didString);
                if (tempKeyPair.isPresent()) {
                    keyAlgorithm = tempKeyPair.get().getPublic().getAlgorithm();
                    logger.warn("回退：使用存储的密钥对中的算法：{}", keyAlgorithm);
                } else {
                    logger.error("无法确定公钥算法，也无法从存储的密钥对中回退。");
                    return false;
                }
            }

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyEncodedBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(keyAlgorithm);
            PublicKey publicKey = keyFactory.generatePublic(keySpec); // 修复：正确地重构 PublicKey

            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

            // 重要提示：您的 CryptoUtil.verify 方法签名是 verify(byte[] data, byte[] publicKey, byte[] sign)
            // 此处代码期望的是 verify(byte[] data, byte[] signature, PublicKey publicKey)
            // 您需要：
            // 1. 修改您的 CryptoUtil.verify 以接受 PublicKey 对象并匹配参数顺序。
            // 2. 或者，在此处更改调用为 publicKey.getEncoded() 并调整参数顺序，
            //    但通常首选使用 PublicKey 对象。
            // 目前，此代码调用方式假定 CryptoUtil 匹配首选签名。
            // boolean isValid = CryptoUtil.verify(challenge.getBytes(), signatureBytes, publicKey);

            // 修复：适配用户的 CryptoUtil.verify(byte[] data, byte[] publicKey, byte[] sign)
            // 这意味着我们将公钥作为字节传递，并交换签名和公钥的顺序。
            boolean isValid = CryptoUtil.verify(challenge.getBytes(), publicKey.getEncoded(), signatureBytes);
            logger.debug("验证调用：数据长度={}, 公钥字节长度={}, 签名字节长度={}",
                    challenge.getBytes().length, publicKey.getEncoded().length, signatureBytes.length);


            if (isValid) {
                logger.info("DID {} 控制验证成功。", didString);
                return true;
            } else {
                logger.warn("DID {} 控制验证失败：签名无效。", didString);
                return false;
            }
        } catch (Exception e) {
            logger.error("DID认证期间发生错误 for DID {}: {}", didString, e.getMessage(), e);
            return false;
        }
    }

    /**
     * 在DID文档中查找指定的验证方法。
     * @param doc DID文档
     * @param keyId 要查找的验证方法ID (例如 "did:example:123#keys-1")。如果为null，则返回第一个。
     * @return 包含验证方法的Optional，如果未找到则为空。
     */
    private Optional<DidDocument.VerificationMethod> findVerificationMethod(DidDocument doc, String keyId) {
        if (doc.getVerificationMethod() == null) {
            return Optional.empty();
        }
        if (keyId != null) { // 如果指定了keyId
            return doc.getVerificationMethod().stream()
                    .filter(vm -> keyId.equals(vm.getId()))
                    .findFirst();
        } else { // 如果未指定keyId，返回第一个（这是一个简化策略）
            return doc.getVerificationMethod().stream().findFirst();
        }
    }
}