package com.bjut.blockchain.did.service;

import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.web.util.CryptoUtil; // 您的加密工具类

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.PublicKey; // 公钥接口
import java.security.KeyFactory; // 密钥工厂，用于从规范生成密钥对象
import java.security.spec.X509EncodedKeySpec; // X.509编码的密钥规范
import java.util.Base64; // Base64编解码
import java.util.Optional; // Optional类，用于处理可能为空的值
import java.nio.charset.StandardCharsets; // 字符集定义

// 如果您还需要证书验证相关功能（例如 verifyDidControlWithCertificate），请取消注释相关导入
// import com.bjut.blockchain.web.service.CAImpl;
// import com.bjut.blockchain.web.util.CertificateValidator;
// import java.security.cert.X509Certificate;

@Service
public class DidAuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(DidAuthenticationService.class);

    @Autowired
    private DidService didService; // 注入DidService以获取DID文档

    /**
     * 通过检查对质询（challenge）的签名来验证对 DID 的控制权。
     *
     * @param didString             DID字符串。
     * @param challenge             被签名的质询字符串。
     * @param signatureBase64       Base64编码的签名。
     * @param publicKeyIdInDocument DID文档中用于签名的验证方法（公钥）的ID (例如, "did:example:123#keys-1")。
     * 如果为null或空，则会尝试使用'authentication'关系中指定的第一个密钥。
     * @return 如果签名有效则返回true，否则返回false。
     */
    public boolean verifyDidControl(String didString, String challenge, String signatureBase64, String publicKeyIdInDocument) {
        // 1. 获取 DID 文档
        DidDocument didDocument = didService.getDidDocument(didString);
        if (didDocument == null) {
            logger.warn("DID 控制权验证失败：找不到 DID {} 的 DID 文档。", didString);
            return false;
        }

        // 2. 检查 DID 文档中是否有验证方法
        if (didDocument.getVerificationMethod() == null || didDocument.getVerificationMethod().isEmpty()) {
            logger.warn("DID 控制权验证失败：DID 文档 {} 中没有找到验证方法。", didString);
            return false;
        }

        // 3. 根据 publicKeyIdInDocument（如果提供）或 DID 文档中 'authentication' 部分指定的密钥ID，查找对应的验证方法
        Optional<DidDocument.VerificationMethod> vmOpt = findVerificationMethod(didDocument, publicKeyIdInDocument);

        if (!vmOpt.isPresent()) { // 检查 Optional 是否包含值
            logger.warn("DID 控制权验证失败：在 DID 文档 {} 中未找到合适的验证方法 (请求的密钥 ID: {}).", didString, publicKeyIdInDocument);
            return false;
        }

        DidDocument.VerificationMethod vm = vmOpt.get(); // 获取验证方法
        logger.debug("找到用于验证的验证方法: {}", vm.getId());

        // 4. 从验证方法中获取 Base64 编码的公钥字符串
        String encodedPublicKey = vm.getPublicKeyBase64();
        if (encodedPublicKey == null || encodedPublicKey.isEmpty()) {
            logger.warn("DID 控制权验证失败：验证方法 {} 中的公钥字符串 (Base64) 缺失或为空。", vm.getId());
            return false;
        }

        try {
            // 5. 从编码的公钥字符串和类型重构 PublicKey 对象
            PublicKey publicKey = reconstructPublicKey(encodedPublicKey, vm.getType());
            if (publicKey == null) {
                logger.error("DID 控制权验证失败：无法从验证方法 {} (DID: {}) 重构公钥。", vm.getId(), didString);
                return false;
            }
            logger.debug("成功为DID {} 重构公钥: 算法={}, 格式={}", didString, publicKey.getAlgorithm(), publicKey.getFormat());

            // 6. 解码 Base64 格式的签名
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
            // 将质询字符串转换为字节数组 (使用UTF-8编码)
            byte[] challengeBytes = challenge.getBytes(StandardCharsets.UTF_8);

            // 7. 使用公钥验证签名
            // 确保您的 CryptoUtil.verify 方法签名是: verify(byte[] data, byte[] publicKeyBytes, byte[] signatureBytes)
            boolean isValid = CryptoUtil.verify(challengeBytes, publicKey.getEncoded(), signatureBytes);

            if (isValid) {
                logger.info("DID {} 的控制权验证成功。", didString);
                return true;
            } else {
                logger.warn("DID {} 的控制权验证失败：签名无效。", didString);
                return false;
            }
        } catch (IllegalArgumentException e) {
            // Base64 解码失败
            logger.error("DID {} 控制权验证失败: 无效的 Base64 编码 (签名)。错误: {}", didString, e.getMessage());
            return false;
        } catch (Exception e) {
            // 其他异常，例如 KeyFactory 错误, Signature 错误等
            logger.error("DID {} 控制权验证失败: 验证过程中发生错误。错误: {}", didString, e.getMessage(), e);
            return false;
        }
    }

    /**
     * 在 DID 文档中查找指定的验证方法。
     *
     * @param doc   DID 文档。
     * @param keyId 要查找的验证方法 ID (例如 "did:example:123#keys-1")。
     * 如果为 null 或空字符串，则优先查找 'authentication' 部分引用的第一个有效密钥。
     * @return 包含验证方法的 Optional，如果未找到则为空。
     */
    private Optional<DidDocument.VerificationMethod> findVerificationMethod(DidDocument doc, String keyId) {
        // 确保验证方法列表存在且不为空
        if (doc.getVerificationMethod() == null || doc.getVerificationMethod().isEmpty()) {
            logger.warn("在 DID 文档 {} 中没有验证方法列表。", doc.getId());
            return Optional.empty();
        }

        // 1. 如果指定了 keyId，进行精确查找
        if (keyId != null && !keyId.isEmpty()) {
            logger.debug("尝试根据指定的 keyId '{}' 查找验证方法。", keyId);
            return doc.getVerificationMethod().stream()
                    .filter(vm -> vm != null && keyId.equals(vm.getId())) // 过滤出 ID 匹配的项
                    .findFirst(); // 返回第一个匹配项
        }

        // 2. 如果未指定 keyId，则查找 'authentication' 部分引用的第一个密钥
        // 'authentication' 列表包含了可用于认证此DID的验证方法的ID
        logger.debug("未指定 keyId，尝试从 'authentication' 关系中查找验证方法。");
        if (doc.getAuthentication() != null && !doc.getAuthentication().isEmpty()) {
            for (String authKeyId : doc.getAuthentication()) { // 遍历所有声明用于认证的密钥ID
                if (authKeyId == null || authKeyId.isEmpty()) continue; // 跳过空的ID

                Optional<DidDocument.VerificationMethod> authVm = doc.getVerificationMethod().stream()
                        .filter(vm -> vm != null && authKeyId.equals(vm.getId())) // 查找对应的验证方法
                        .findFirst();
                if (authVm.isPresent()) { // 检查是否找到 (Java 8 兼容)
                    logger.debug("找到 'authentication' 中引用的验证方法: {}", authKeyId);
                    return authVm; // 返回第一个在 'authentication' 中找到并实际存在的验证方法
                } else {
                    logger.warn("'authentication' 中引用的密钥 ID '{}' 在验证方法列表中未找到。", authKeyId);
                }
            }
            // 如果 'authentication' 列表中的所有keyId都无效或未在verificationMethod中找到
            logger.warn("DID {} 的 'authentication' 列表中没有有效的、可用的验证方法。", doc.getId());
        } else {
            logger.warn("DID {} 的 'authentication' 列表为空或未定义。", doc.getId());
        }

        // 3. 如果以上都未找到（没有指定keyId，且'authentication'中没有合适的或为空）
        // 根据策略，可以选择不返回任何密钥，或者（不推荐地）返回列表中的第一个密钥。
        // 为了安全和明确性，如果认证意图不明确，最好是不返回。
        logger.warn("无法为 DID {} 确定用于认证的验证方法。", doc.getId());
        return Optional.empty();
    }


    /**
     * 从其编码的字符串表示和类型重构 PublicKey 对象。
     *
     * @param encodedKey 编码的公钥字符串（例如 Base58、Base64）。
     * @param keyType    密钥类型（例如 "RsaVerificationKey2018", "Ed25519VerificationKey2018"）。
     * @return PublicKey 对象，如果重构失败则返回 null。
     */
    private PublicKey reconstructPublicKey(String encodedKey, String keyType) {
        logger.debug("尝试重构公钥。类型: {}, 编码密钥 (前10字符): {}", keyType, encodedKey.substring(0, Math.min(10, encodedKey.length())));
        String algorithm; // 用于 KeyFactory 的算法名称
        byte[] keyBytes;  // 解码后的密钥字节

        try {
            // 假设密钥是 Base64 编码的 (X.509 SPKI格式的公钥通常用Base64)
            keyBytes = Base64.getDecoder().decode(encodedKey);
            logger.debug("成功将公钥从 Base64 解码，字节长度: {}", keyBytes.length);
        } catch (IllegalArgumentException e) {
            logger.error("无法将公钥从 Base64 解码: {}", e.getMessage());
            // 在这里可以添加对其他编码（如 Base58）的尝试（如果需要）
            return null; // 如果不支持或解码失败，返回 null
        }

        // 根据 keyType 推断 KeyFactory 所需的算法名称
        if (keyType == null) {
            logger.error("无法确定密钥算法：keyType 为 null。");
            return null;
        }

        // 尝试更精确地匹配或推断算法
        // W3C DID Pkcs RsaVerificationKey2018 (https://w3c-ccg.github.io/lds-rsa2018/)
        // W3C DID Pkcs Ed25519VerificationKey2018 (https://w3c-ccg.github.io/lds-ed25519-2018/)
        // W3C DID Pkcs EcdsaSecp256k1VerificationKey2019 (https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/)
        switch (keyType) {
            case "RsaVerificationKey2018":
                algorithm = "RSA";
                break;
            case "Ed25519VerificationKey2018":
                algorithm = "EdDSA"; // Java 15+ 标准支持 "EdDSA", "Ed25519". BouncyCastle 也支持.
                break;
            case "EcdsaSecp256k1VerificationKey2019": // NIST P-256 (secp256r1) vs secp256k1
                algorithm = "EC"; // secp256k1 曲线的EC密钥
                break;
            case "JsonWebKey2020": // JWK 可能包含多种算法，需要进一步解析JWK本身来确定
                logger.warn("JsonWebKey2020 类型需要进一步解析JWK以确定具体算法，此处暂不支持直接重构。");
                return null; // 或者尝试从 keyBytes 中提取更多信息
            default:
                // 尝试基于包含的字符串进行通用推断
                if (keyType.toUpperCase().contains("RSA")) {
                    algorithm = "RSA";
                } else if (keyType.toUpperCase().contains("EC") || keyType.toUpperCase().contains("SECP256R1") || keyType.toUpperCase().contains("P-256")) {
                    algorithm = "EC"; // 通常指 secp256r1 (NIST P-256)
                } else if (keyType.toUpperCase().contains("ED25519") || keyType.toUpperCase().contains("EDDSA")) {
                    algorithm = "EdDSA";
                } else {
                    logger.error("不支持或无法识别的密钥类型，无法确定算法: {}", keyType);
                    return null;
                }
        }
        logger.debug("推断出的密钥算法: {}", algorithm);

        try {
            // 对于 RSA, EC, EdDSA 密钥，通常使用 X.509 编码规范 (SubjectPublicKeyInfo - SPKI)
            if ("RSA".equals(algorithm) || "EC".equals(algorithm) || "EdDSA".equals(algorithm)) {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                return keyFactory.generatePublic(keySpec); // 生成 PublicKey 对象
            } else {
                // 理论上不应到达这里，因为前面已经检查过算法
                logger.error("算法 {} 在此实现中不被支持进行密钥重构。", algorithm);
                return null;
            }
        } catch (Exception e) {
            // 捕获 KeyFactory.getInstance 或 generatePublic 可能抛出的异常
            logger.error("重构 PublicKey (算法: {}) 失败: {}", algorithm, e.getMessage(), e);
            return null; // 重构失败返回 null
        }
    }
}