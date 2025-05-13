package com.bjut.blockchain.did.service;

import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.web.service.CAImpl;
import com.bjut.blockchain.web.util.CertificateValidator;
import com.bjut.blockchain.web.util.CryptoUtil; // 引入你的加密工具类

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.KeyPair; // 保持导入以备将来使用或参考
import java.security.KeyFactory; // 用于重构 PublicKey
import java.security.cert.X509Certificate;
import java.security.spec.X509EncodedKeySpec; // 用于重构 PublicKey
import java.util.Base64;
import java.util.Optional;

/**
 * 处理基于 DID 的认证和验证的服务类。
 */
@Service
public class DidAuthenticationService {
    private static final Logger logger = LoggerFactory.getLogger(DidAuthenticationService.class);

    @Autowired
    private DidService didService; // 注入 DidService

    /**
     * 验证一个实体是否拥有给定 DID 的控制权。
     * 通过验证使用与 DID 关联的私钥对挑战（challenge）进行的签名来实现。
     *
     * @param didString             要验证的 DID。
     * @param challenge             一个随机生成的字符串或数据，由调用方提供。
     * @param signatureBase64       由实体使用其私钥对挑战进行的签名的 Base64 编码。
     * @param publicKeyIdInDocument (可选) DID 文档中用于签名的公钥的 ID (例如 "did:example:123#keys-1")。
     * 如果为 null，则尝试使用 DID 文档中的第一个合适的公钥。
     * @return 如果签名有效且与 DID 关联，则为 true。
     */
    public boolean verifyDidControl(String didString, String challenge, String signatureBase64, String publicKeyIdInDocument) {
        // 1. 获取 DID 文档
        DidDocument didDocument = didService.getDidDocument(didString);
        if (didDocument == null) {
            logger.warn("DID 控制权验证失败：无法解析 DID 文档 {}", didString);
            return false;
        }

        // 2. 检查是否存在验证方法
        if (didDocument.getVerificationMethod() == null || didDocument.getVerificationMethod().isEmpty()) {
            logger.warn("DID 控制权验证失败：DID 文档 {} 中没有验证方法。", didString);
            return false;
        }

        // 3. 查找用于验证的公钥对应的验证方法
        Optional<DidDocument.VerificationMethod> verificationMethodOpt = findVerificationMethod(didDocument, publicKeyIdInDocument);

        // 检查 Optional 是否包含值 (兼容 Java 8)
        if (!verificationMethodOpt.isPresent()) {
            logger.warn("DID 控制权验证失败：在 DID 文档 {} 中未找到合适的验证方法 (请求的密钥 ID: {}).", didString, publicKeyIdInDocument);
            return false;
        }

        DidDocument.VerificationMethod vm = verificationMethodOpt.get();
        logger.debug("找到验证方法: {}", vm.getId());

        // 4. 从验证方法中获取编码后的公钥字符串
        // **修正：使用 getPublicKeyBase64() 获取密钥**
        String encodedPublicKey = vm.getPublicKeyBase64();
        if (encodedPublicKey == null || encodedPublicKey.isEmpty()) {
            // 如果 Base64 字段为空，可以尝试其他字段或报错
            logger.warn("DID 控制权验证失败：验证方法 {} 中的公钥字符串 (Base64) 缺失或为空。", vm.getId());
            return false;
        }

        try {
            // 5. 从编码字符串重构 PublicKey 对象
            // 使用辅助方法 reconstructPublicKey
            PublicKey publicKey = reconstructPublicKey(encodedPublicKey, vm.getType());
            if (publicKey == null) {
                logger.error("DID 控制权验证失败：无法从验证方法 {} (DID: {}) 重构公钥。", vm.getId(), didString);
                return false;
            }
            logger.debug("成功重构公钥: 算法={}, 格式={}", publicKey.getAlgorithm(), publicKey.getFormat());

            // 6. 解码签名
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

            // 7. 验证签名
            // **适配你的 CryptoUtil.verify(byte[] data, byte[] publicKey, byte[] sign) 签名**
            // 将 PublicKey 对象编码为字节数组，并调整参数顺序。
            byte[] publicKeyBytes = publicKey.getEncoded();
            boolean isValid = CryptoUtil.verify(challenge.getBytes(), publicKeyBytes, signatureBytes);

            logger.debug("正在验证签名: 数据字节数={}, 公钥字节数={}, 签名字节数={}",
                    challenge.getBytes().length, publicKeyBytes.length, signatureBytes.length);

            if (isValid) {
                logger.info("DID {} 控制权验证成功。", didString);
                return true;
            } else {
                logger.warn("DID {} 控制权验证失败：签名无效。", didString);
                return false;
            }
        } catch (IllegalArgumentException e) {
            // Base64 解码失败
            logger.error("DID 控制权验证失败 (DID: {}): 无效的 Base64 编码 (签名或公钥)。{}", didString, e.getMessage());
            return false;
        } catch (Exception e) {
            // 其他异常，例如 KeyFactory 错误, Signature 错误等
            logger.error("DID 控制权验证失败 (DID: {}): 验证过程中发生错误。{}", didString, e.getMessage(), e);
            return false;
        }
    }

    /**
     * 在 DID 文档中查找指定的验证方法。
     *
     * @param doc   DID 文档。
     * @param keyId 要查找的验证方法 ID (例如 "did:example:123#keys-1")。如果为 null，则返回第一个关联 'authentication' 的方法，或第一个方法作为回退。
     * @return 包含验证方法的 Optional，如果未找到则为空。
     */
    private Optional<DidDocument.VerificationMethod> findVerificationMethod(DidDocument doc, String keyId) {
        // 检查验证方法列表是否有效
        if (doc.getVerificationMethod() == null || doc.getVerificationMethod().isEmpty()) {
            return Optional.empty();
        }

        // 1. 如果指定了 keyId，进行精确查找
        if (keyId != null) {
            return doc.getVerificationMethod().stream()
                    .filter(vm -> vm != null && keyId.equals(vm.getId())) // 过滤出 ID 匹配的项
                    .findFirst(); // 返回第一个匹配项
        }

        // 2. 如果未指定 keyId，优先查找 'authentication' 部分引用的第一个密钥
        if (doc.getAuthentication() != null && !doc.getAuthentication().isEmpty()) {
            String firstAuthKeyId = doc.getAuthentication().get(0); // 获取第一个认证密钥 ID
            Optional<DidDocument.VerificationMethod> authVm = doc.getVerificationMethod().stream()
                    .filter(vm -> vm != null && firstAuthKeyId.equals(vm.getId())) // 查找对应的验证方法
                    .findFirst();
            if (authVm.isPresent()) { // 检查是否找到 (Java 8 兼容)
                logger.debug("未指定 keyId，使用第一个认证密钥: {}", firstAuthKeyId);
                return authVm; // 返回找到的认证密钥
            } else {
                // 如果认证密钥 ID 在验证方法列表中找不到，记录警告
                logger.warn("第一个认证密钥 ID '{}' 在验证方法列表中未找到。", firstAuthKeyId);
            }
        }

        // 3. 如果 'authentication' 找不到或为空，或者引用的密钥无效，则回退到列表中的第一个验证方法
        logger.debug("未指定 keyId 且未找到合适的认证密钥，回退到第一个验证方法。");
        return doc.getVerificationMethod().stream().findFirst(); // 返回列表中的第一个验证方法
    }


    /**
     * 从其编码的字符串表示和类型重构 PublicKey 对象。
     * **注意：** 这是一个占位符实现，需要根据实际使用的密钥类型和编码进行具体实现。
     * 对于 Ed25519、Base58 等，标准 Java 库支持有限，可能需要外部库（如 BouncyCastle）。
     *
     * @param encodedKey 编码的公钥字符串（例如 Base58、Base64）。
     * @param keyType    密钥类型（例如 "RsaVerificationKey2018", "Ed25519VerificationKey2018"）。
     * @return PublicKey 对象，如果重构失败则返回 null。
     */
    private PublicKey reconstructPublicKey(String encodedKey, String keyType) {
        // 记录尝试重构的日志
        logger.debug("尝试重构公钥。类型: {}, 编码密钥 (前10字符): {}", keyType, encodedKey.substring(0, Math.min(10, encodedKey.length())));
        String algorithm = null; // 用于 KeyFactory 的算法名称
        byte[] keyBytes = null; // 解码后的密钥字节

        try {
            // 假设 RSA/EC 密钥使用 Base64 编码
            keyBytes = Base64.getDecoder().decode(encodedKey);
            logger.debug("成功解码 Base64 密钥，长度: {}", keyBytes.length);
        } catch (IllegalArgumentException e) {
            // 如果 Base64 解码失败，记录错误
            logger.error("无法将公钥解码为 Base64: {}", e.getMessage());
            // 在这里可以添加对 Base58 或其他编码的尝试（如果需要）
            // 例如: 使用 BouncyCastle 或其他库进行 Base58 解码
            return null; // 如果不支持或解码失败，返回 null
        }

        // 根据 keyType 推断 KeyFactory 所需的算法名称
        if (keyType == null) {
            logger.error("无法确定密钥算法：keyType 为 null。");
            return null;
            // **修正：确保类型检查与 DidService 中设置的类型 ("RsaVerificationKey2018") 匹配**
        } else if ("RsaVerificationKey2018".equals(keyType) || keyType.contains("Rsa")) { // 优先检查特定类型
            algorithm = "RSA";
        } else if (keyType.contains("Ecdsa") || keyType.contains("EC") || keyType.contains("P256") || keyType.contains("K256")) { // 常见的 ECDSA 指示符
            algorithm = "EC";
        } else if (keyType.contains("Ed25519")) {
            algorithm = "EdDSA"; // EdDSA 密钥在标准 Java 中的算法名称 (可能需要 BouncyCastle 或 JDK 15+)
            logger.warn("EdDSA 密钥重构可能需要 BouncyCastle 提供者或 JDK 15+。");
        } else {
            // 如果类型无法识别
            logger.error("不支持或无法识别的密钥类型，无法确定算法: {}", keyType);
            return null;
        }
        logger.debug("推断出的密钥算法: {}", algorithm);

        try {
            // 对于 RSA 和 EC 密钥，使用 X.509 规范
            if ("RSA".equals(algorithm) || "EC".equals(algorithm)) {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                return keyFactory.generatePublic(keySpec); // 生成 PublicKey 对象
            } else if ("EdDSA".equals(algorithm)) {
                // EdDSA 重构可能需要特定处理或提供者
                // 尝试使用标准名称 (可能需要 BouncyCastle 提供者)
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("EdDSA"); // 或在某些环境中是 "Ed25519"
                return keyFactory.generatePublic(keySpec);
                // 如果使用 BouncyCastle:
                // KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", "BC"); // 指定 BouncyCastle 提供者
                // return keyFactory.generatePublic(keySpec);
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

    // --- 用于演示 Optional 用法的示例方法 (保留供参考) ---
    /**
     * 演示将可能为 null 的 KeyPair 包装在 Optional 中的示例方法。
     *
     * @param didString DID 字符串。
     * @return Optional<KeyPair>
     */
    public Optional<KeyPair> getKeyPairOptional(String didString) {
        // 假设 getKeyPairForDid 可能返回 null
        KeyPair kp = didService.getKeyPairForDid(didString); // 此方法返回 KeyPair 或 null
        // 使用 Optional.ofNullable 包装结果
        return Optional.ofNullable(kp);
    }

    /**
     * 验证一个实体是否拥有给定 DID 的控制权，并验证其提供的证书。
     *
     * @param didString             要验证的 DID。
     * @param challenge             一个随机生成的字符串或数据。
     * @param signatureBase64       签名的 Base64 编码。
     * @param presentedCertificateBase64 实体出示的X.509证书的Base64编码。
     * @param publicKeyIdInDocument (可选) DID 文档中用于签名的公钥的 ID。
     * @return 如果签名和证书都有效且与 DID 关联，则为 true。
     */
    public boolean verifyDidControlWithCertificate(String didString, String challenge, String signatureBase64,
                                                   String presentedCertificateBase64, String publicKeyIdInDocument) {
        // 1. 获取 DID 文档
        DidDocument didDocument = didService.getDidDocument(didString);
        if (didDocument == null) {
            logger.warn("DID 控制权验证失败：无法解析 DID 文档 {}", didString);
            return false;
        }

        // 2. 查找用于验证的公钥对应的验证方法
        Optional<DidDocument.VerificationMethod> verificationMethodOpt = findVerificationMethod(didDocument, publicKeyIdInDocument);
        if (!verificationMethodOpt.isPresent()) {
            logger.warn("DID 控制权验证失败：在 DID 文档 {} 中未找到合适的验证方法 (请求的密钥 ID: {}).", didString, publicKeyIdInDocument);
            return false;
        }
        DidDocument.VerificationMethod vm = verificationMethodOpt.get();
        logger.debug("找到验证方法: {}", vm.getId());

        // 3. 验证出示的证书
        if (presentedCertificateBase64 == null || presentedCertificateBase64.isEmpty()) {
            logger.warn("DID 控制权验证失败：未提供证书。");
            return false;
        }
        try {
            X509Certificate presentedCertificate = CertificateValidator.stringToCertificate(presentedCertificateBase64);

            // 3a. 验证证书本身是否有效 (信任链, 有效期等)
            // 你需要传入根CA证书来进行完整的链验证
            String rootCaCertStr = CAImpl.getRootCertificateStr(); // 获取根CA证书字符串
            if (!CertificateValidator.validateCertificate(presentedCertificate, CertificateValidator.stringToCertificate(rootCaCertStr))) {
                logger.warn("DID 控制权验证失败：出示的证书无效或不受信任。 DID: {}", didString);
                return false;
            }
            logger.debug("出示的证书 {} 本身有效。", presentedCertificate.getSubjectX500Principal().getName());

            // 3b. 验证证书与DID文档中声明的证书指纹是否匹配
            String expectedFingerprint = vm.getX509CertificateFingerprint();
            if (expectedFingerprint == null || expectedFingerprint.isEmpty()) {
                logger.warn("DID 控制权验证失败：DID文档的验证方法 {} 未声明证书指纹。", vm.getId());
                return false; // 或者根据策略，如果允许无指纹，则跳过此检查
            }
            MessageDigest messageDigestPresented = MessageDigest.getInstance("SHA-256");
            byte[] presentedFingerprintBytes = messageDigestPresented.digest(presentedCertificate.getEncoded());
            String presentedFingerprint = CryptoUtil.byte2Hex(presentedFingerprintBytes);

            if (!expectedFingerprint.equals(presentedFingerprint)) {
                logger.warn("DID 控制权验证失败：证书指纹不匹配。预期: {}, 实际: {}. DID: {}",
                        expectedFingerprint, presentedFingerprint, didString);
                return false;
            }
            logger.debug("证书指纹匹配成功。");

            // 3c. (重要) 验证证书中的公钥是否与VerificationMethod中的公钥匹配
            String vmPublicKeyBase64 = vm.getPublicKeyBase64();
            String certPublicKeyBase64 = Base64.getEncoder().encodeToString(presentedCertificate.getPublicKey().getEncoded());
            if (!vmPublicKeyBase64.equals(certPublicKeyBase64)) {
                logger.warn("DID 控制权验证失败：VerificationMethod 公钥与证书公钥不匹配. DID: {}", didString);
                return false;
            }
            logger.debug("VerificationMethod 公钥与证书公钥匹配成功。");

        } catch (Exception e) {
            logger.error("DID 控制权验证失败：处理或验证证书时出错。 DID: {}, Error: {}", didString, e.getMessage(), e);
            return false;
        }

        // 4. 如果上述所有检查都通过，则继续验证签名 (使用证书中的公钥或VM中的公钥，它们此时应已验证为匹配)
        // （这里的 verifyDidControl 方法需要调用，或者将其逻辑合并到这里）
        return verifyDidControl(didString, challenge, signatureBase64, publicKeyIdInDocument); // 调用原有的签名验证逻辑
        // 它会从VM中获取公钥
    }
}
