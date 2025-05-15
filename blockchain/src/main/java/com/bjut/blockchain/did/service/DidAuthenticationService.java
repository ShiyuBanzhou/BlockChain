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
     * 验证使用临时（匿名）公钥对挑战进行的签名。
     * Verifies a signature against a challenge using a provided temporary (anonymous) public key.
     *
     * @param challenge                 服务器下发的挑战字符串。The challenge string issued by the server.
     * @param temporaryPublicKeyBase64  客户端生成的临时公钥 (Base64编码, 期望是SPKI格式)。The client-generated temporary public key (Base64 encoded, expected to be in SPKI format).
     * @param signatureBase64           客户端对挑战的签名 (Base64编码)。The client's signature of the challenge (Base64 encoded).
     * @return 如果签名有效则返回 true，否则返回 false。True if the signature is valid, false otherwise.
     */
    public boolean verifyAnonymousSignature(String challenge, String temporaryPublicKeyBase64, String signatureBase64) {
        if (challenge == null || temporaryPublicKeyBase64 == null || signatureBase64 == null ||
                challenge.isEmpty() || temporaryPublicKeyBase64.isEmpty() || signatureBase64.isEmpty()) {
            logger.warn("匿名签名验证失败：缺少必要的参数 (challenge, temporaryPublicKeyBase64, or signatureBase64)。");
            return false;
        }

        try {
            // 假设客户端为临时密钥生成的是RSA密钥对，并且公钥是X.509 SPKI格式然后Base64编码。
            // 因此，在调用 reconstructPublicKey 时，我们可以传递一个能映射到 "RSA" 的类型，
            // 或者如果 reconstructPublicKey 足够智能，可以直接传递 "RSA"。
            // 鉴于 CryptoUtil.verify 硬编码了 "RSA"，这里我们显式地按RSA处理。
            PublicKey tempPublicKey = reconstructPublicKey(temporaryPublicKeyBase64, "RSA"); // 使用 "RSA" 作为类型提示
            if (tempPublicKey == null) {
                logger.error("为匿名验证重建临时公钥失败。提供的公钥 (前缀): {}", temporaryPublicKeyBase64.substring(0, Math.min(30, temporaryPublicKeyBase64.length())));
                return false;
            }
            logger.debug("成功为匿名认证重建临时公钥: 算法={}, 格式={}", tempPublicKey.getAlgorithm(), tempPublicKey.getFormat());


            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);
            byte[] challengeBytes = challenge.getBytes(StandardCharsets.UTF_8);

            // 调用 CryptoUtil.verify。它内部使用 "SHA256withRSA"。
            boolean isValid = CryptoUtil.verify(challengeBytes, tempPublicKey.getEncoded(), signatureBytes);

            if (isValid) {
                logger.info("使用临时密钥进行的匿名签名验证成功。");
                return true;
            } else {
                logger.warn("使用临时密钥进行的匿名签名验证失败：签名无效。");
                return false;
            }
        } catch (IllegalArgumentException e) {
            // Base64 解码失败
            logger.error("匿名签名验证失败：无效的 Base64 编码。错误: {}", e.getMessage());
            return false;
        } catch (Exception e) {
            // 其他异常，例如 KeyFactory 错误, Signature 错误等
            logger.error("匿名签名验证失败：验证过程中发生错误。错误: {}", e.getMessage(), e);
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
        logger.debug("未指定 keyId，尝试从 'authentication' 关系中查找验证方法。");
        if (doc.getAuthentication() != null && !doc.getAuthentication().isEmpty()) {
            for (String authKeyId : doc.getAuthentication()) {
                if (authKeyId == null || authKeyId.isEmpty()) continue;

                Optional<DidDocument.VerificationMethod> authVm = doc.getVerificationMethod().stream()
                        .filter(vm -> vm != null && authKeyId.equals(vm.getId()))
                        .findFirst();
                if (authVm.isPresent()) {
                    logger.debug("找到 'authentication' 中引用的验证方法: {}", authKeyId);
                    return authVm;
                } else {
                    logger.warn("'authentication' 中引用的密钥 ID '{}' 在验证方法列表中未找到。", authKeyId);
                }
            }
            logger.warn("DID {} 的 'authentication' 列表中没有有效的、可用的验证方法。", doc.getId());
        } else {
            logger.warn("DID {} 的 'authentication' 列表为空或未定义。", doc.getId());
        }
        logger.warn("无法为 DID {} 确定用于认证的验证方法。", doc.getId());
        return Optional.empty();
    }


    /**
     * 从其编码的字符串表示和类型重构 PublicKey 对象。
     *
     * @param encodedKey 编码的公钥字符串（例如 Base58、Base64）。
     * @param keyType    密钥类型（例如 "RsaVerificationKey2018", "Ed25519VerificationKey2018", 或直接是算法名如 "RSA"）。
     * @return PublicKey 对象，如果重构失败则返回 null。
     */
    private PublicKey reconstructPublicKey(String encodedKey, String keyType) {
        logger.debug("尝试重构公钥。类型提示: {}, 编码密钥 (前10字符): {}", keyType, encodedKey.substring(0, Math.min(10, encodedKey.length())));
        String algorithm;
        byte[] keyBytes;

        try {
            keyBytes = Base64.getDecoder().decode(encodedKey);
            logger.debug("成功将公钥从 Base64 解码，字节长度: {}", keyBytes.length);
        } catch (IllegalArgumentException e) {
            logger.error("无法将公钥从 Base64 解码: {}", e.getMessage());
            return null;
        }

        if (keyType == null) {
            logger.error("无法确定密钥算法：keyType 为 null。");
            return null;
        }

        // 根据 keyType 推断 KeyFactory 所需的算法名称
        // 为了兼容 verifyAnonymousSignature 直接传入 "RSA" 的情况
        if ("RSA".equalsIgnoreCase(keyType) || "RsaVerificationKey2018".equals(keyType)) {
            algorithm = "RSA";
        } else if ("EdDSA".equalsIgnoreCase(keyType) || "Ed25519VerificationKey2018".equals(keyType)) {
            algorithm = "EdDSA";
        } else if ("EC".equalsIgnoreCase(keyType) || "EcdsaSecp256k1VerificationKey2019".equals(keyType)) {
            algorithm = "EC";
        } else if ("JsonWebKey2020".equals(keyType)) {
            logger.warn("JsonWebKey2020 类型需要进一步解析JWK以确定具体算法，此处暂不支持直接重构。");
            return null;
        } else {
            // 尝试基于包含的字符串进行通用推断 (作为后备)
            if (keyType.toUpperCase().contains("RSA")) {
                algorithm = "RSA";
            } else if (keyType.toUpperCase().contains("EC") || keyType.toUpperCase().contains("SECP256R1") || keyType.toUpperCase().contains("P-256")) {
                algorithm = "EC";
            } else if (keyType.toUpperCase().contains("ED25519") || keyType.toUpperCase().contains("EDDSA")) {
                algorithm = "EdDSA";
            } else {
                logger.error("不支持或无法识别的密钥类型，无法确定算法: {}", keyType);
                return null;
            }
        }
        logger.debug("推断出的密钥算法: {}", algorithm);

        try {
            if ("RSA".equals(algorithm) || "EC".equals(algorithm) || "EdDSA".equals(algorithm)) {
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
                return keyFactory.generatePublic(keySpec);
            } else {
                logger.error("算法 {} 在此实现中不被支持进行密钥重构。", algorithm);
                return null;
            }
        } catch (Exception e) {
            logger.error("重构 PublicKey (算法: {}) 失败: {}", algorithm, e.getMessage(), e);
            return null;
        }
    }
}
