package com.bjut.blockchain.did.service;

import com.bjut.blockchain.web.service.CAImpl; // 用于获取证书
import com.bjut.blockchain.web.util.CryptoUtil; // 用于哈希和字节转换
import com.bjut.blockchain.did.model.Did;
import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.web.service.BlockService; // 假设引入 BlockService
import com.bjut.blockchain.web.model.Transaction; // 假设引入 Transaction
import com.bjut.blockchain.web.util.CommonUtil; // 引入 CommonUtil 计算哈希和JSON转换
import com.fasterxml.jackson.core.JsonProcessingException; // JSON处理异常
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.MessageDigest; // 用于计算指纹
import java.security.cert.X509Certificate; // 证书类型
import java.util.Base64; // Base64编码
import java.util.HashMap; // Map实现
import java.util.Map; // Map接口
import java.util.UUID; // 生成唯一ID
import java.util.Set; // Set接口
import java.util.Collections; // Collections工具类
import java.security.KeyPair; // 密钥对，当前服务不直接管理其存储
import java.util.Arrays; // 用于创建列表
import java.util.List; // 列表接口

/**
 * 服务类，用于管理和操作 DID (去中心化标识符)。
 * 提供创建、解析 DID 以及管理 DID 文档的功能。
 */
@Service
public class DidService {

    // 使用 Map 模拟 DID 注册表或存储 (DID 字符串 -> DidDocument)
    // 注意：这是一个内存存储，应用重启后数据会丢失。生产环境需要持久化存储。
    private static final Map<String, DidDocument> didRegistry = new HashMap<>();


    // 注入 BlockService 用于将 DID 相关信息上链
    @Autowired(required = false) // required = false 避免强制依赖，方便测试
    private BlockService blockService;

    /**
     * 使用提供的公钥创建一个新的 DID 和关联的 DID 文档。
     * 将 DID 文档注册到内存注册表，并尝试将其锚定到区块链。
     *
     * @param publicKeyBase64 Base64 编码的公钥字符串 (通常是 X.509 格式的公钥字节)。
     * @return 新创建的 Did 对象。
     */
    public Did createDid(String publicKeyBase64) {
        // 生成 DID 的方法特定标识符
        String methodSpecificId = UUID.randomUUID().toString();
        // 构造 DID 字符串 (示例格式，您可以替换为您的 DID 方法)
        String didString = "did:example:" + methodSpecificId;
        Did did = new Did(didString);

        // 创建 DID 文档对象
        DidDocument doc = new DidDocument();
        doc.setId(didString); // 设置 DID 文档的 ID 为 DID 字符串

        // 创建验证方法对象并填充信息
        DidDocument.VerificationMethod verificationMethod = new DidDocument.VerificationMethod();
        String keyId = didString + "#keys-1"; // DID文档中密钥的唯一标识符
        verificationMethod.setId(keyId);
        verificationMethod.setType("RsaVerificationKey2018"); // 假设使用RSA密钥，并遵循W3C标准命名 (或根据实际密钥类型如 Ed25519VerificationKey2018)
        verificationMethod.setController(didString); // 控制者是 DID 本身
        verificationMethod.setPublicKeyBase64(publicKeyBase64); // 设置公钥

        // ---- 集成证书管理 (可选，如果您的用例需要) ----
        try {
            X509Certificate nodeCertificate = CAImpl.getCertificate(); // 获取节点自身的证书 (如果适用)
            if (nodeCertificate != null) {
                // 计算证书指纹 (SHA-256)
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                byte[] fingerprintBytes = messageDigest.digest(nodeCertificate.getEncoded());
                String fingerprint = CryptoUtil.byte2Hex(fingerprintBytes); // 转换为十六进制字符串
                verificationMethod.setX509CertificateFingerprint(fingerprint); // 在验证方法中设置证书指纹
                System.out.println("证书指纹 " + fingerprint + " 已关联到密钥 " + keyId);
            } else {
                System.err.println("未能获取证书用于DID: " + didString);
            }
        } catch (Exception e) {
            System.err.println("在DID创建过程中处理证书时出错: " + e.getMessage());
            // 根据错误处理策略决定是否继续
        }
        // ---- 证书管理结束 ----

        // 将验证方法添加到 DID 文档的 verificationMethod 列表中
        doc.setVerificationMethod(Arrays.asList(verificationMethod));

        // **重要**: 将此密钥的 ID 添加到 'authentication' 验证关系中
        // 这表明该密钥可用于对 DID 主体进行身份验证。
        doc.setAuthentication(Arrays.asList(keyId));

        // 在内存中注册 DID 文档
        registerDidDocument(did, doc);

        // (可选) 将 DID 信息锚定到区块链
        anchorDidToBlockchain(doc);

        return did; // 返回创建的 DID 对象
    }

    /**
     * 根据 DID 字符串解析并获取 Did 对象。
     * @param didString DID 字符串。
     * @return 解析后的 Did 对象，如果格式无效则返回 null。
     */
    public Did resolveDid(String didString) {
        if (isValidDid(didString)) {
            return new Did(didString);
        }
        return null;
    }

    /**
     * 验证 DID 字符串格式是否有效。
     * @param didString 要验证的 DID 字符串。
     * @return 如果有效则返回 true，否则返回 false。
     */
    private boolean isValidDid(String didString) {
        // 简单的格式校验，生产环境中应根据具体的 DID 方法规范进行更严格的校验
        return didString != null && didString.startsWith("did:");
    }

    /**
     * "注册" 或存储 DID 文档。
     * 当前实现使用简单的内存 Map 模拟。在生产环境中，这可能涉及数据库、
     * 分布式文件系统（如 IPFS）或直接在区块链上存储/锚定。
     * @param did 与文档关联的 DID。
     * @param doc 要注册的 DID 文档。
     */
    public void registerDidDocument(Did did, DidDocument doc) {
        if (did != null && doc != null && did.getDidString().equals(doc.getId())) {
            didRegistry.put(did.getDidString(), doc);
            System.out.println("DID 文档已在内存中注册: " + did.getDidString());
        } else {
            System.err.println("注册 DID 文档失败: 无效的输入参数。");
        }
    }

    /**
     * 根据给定的 DID 字符串检索关联的 DID 文档。
     * @param didString DID 字符串。
     * @return 关联的 DidDocument，如果未找到则返回 null。
     */
    public DidDocument getDidDocument(String didString) {
        return didRegistry.get(didString);
    }

    /**
     * 获取所有已注册的 DID 字符串。
     * @return 包含所有 DID 字符串的 Set 集合 (不可修改的视图)。
     */
    public Set<String> getAllDids() {
        return Collections.unmodifiableSet(didRegistry.keySet());
    }

    /**
     * (占位符/待移除或修改) 获取与 DID 关联的密钥对。
     * **注意：** 此服务当前配置不直接管理私钥。私钥应由用户/客户端安全管理。
     * 此方法主要用于演示或特定内部测试场景。
     * @param didString DID 字符串。
     * @return KeyPair 对象，如果服务不管理密钥或未找到，则返回 null。
     */
    public KeyPair getKeyPairForDid(String didString) {
        // 实际应用中，此服务不应该能访问私钥。
        System.out.println("警告: 调用了 getKeyPairForDid。在理想的DID系统中，服务端不应存储或直接访问用户私钥。");
        // 如果您为DEMO在服务器端存储了密钥对 (例如在DidController中)，这里可以考虑如何访问，
        // 但这违背了DID的核心原则。通常此方法在服务端是无意义的。
        return null;
    }


    /**
     * 将 DID 文档的关键信息（例如其哈希）锚定到区块链上。
     * 这通常通过创建一个包含 DID 文档哈希（或整个文档，取决于链的容量和成本）的特殊交易来实现。
     * @param doc 要锚定的 DID 文档。
     */
    private void anchorDidToBlockchain(DidDocument doc) {
        // 检查 BlockService 是否可用
        if (blockService == null) {
            System.out.println("BlockService 不可用。跳过 DID 的区块链锚定: " + (doc != null ? doc.getId() : "[文档为空]"));
            return;
        }
        // 检查文档是否有效
        if (doc == null || doc.getId() == null) {
            System.err.println("无法将空的或无ID的 DID 文档锚定到区块链。");
            return;
        }

        try {
            // 计算文档哈希
            String docHash = doc.calculateDocumentHash();
            if (docHash == null) {
                System.err.println("计算 DID 文档哈希失败: " + doc.getId());
                return;
            }

            // 创建锚定交易
            Transaction didAnchorTx = new Transaction();
            didAnchorTx.setId(UUID.randomUUID().toString()); // 交易的唯一ID
            didAnchorTx.setTimestamp(System.currentTimeMillis()); // 交易时间戳

            // 交易的 publicKey 和 sign 应由对区块链有写入权限的实体（例如，DID的控制者或服务节点）设置
            // didAnchorTx.setPublicKey("..."); // 发起此锚定交易的实体的公钥
            // didAnchorTx.setSign("...");    // 对此交易的签名

            // 准备交易数据 (通常是JSON格式)
            Map<String, String> dataMap = new HashMap<>();
            dataMap.put("type", "DID_ANCHOR"); // 交易类型，便于链上识别
            dataMap.put("did", doc.getId());   // 被锚定的DID
            dataMap.put("documentHash", docHash); // DID文档的哈希

            // 使用 CommonUtil 将 Map 转换为 JSON 字符串并存储在交易的 data 字段中
            try {
                didAnchorTx.setData(CommonUtil.getJson(dataMap));
            } catch (JsonProcessingException e) {
                System.err.println("将DID锚定交易数据转换为JSON时出错 for DID " + doc.getId() + ": " + e.getMessage());
                return; // 无法创建交易数据
            }


            // 将交易添加到交易池，等待被矿工打包
            boolean added = blockService.addTransaction(didAnchorTx);
            if (added) {
                System.out.println("DID " + doc.getId() + " (哈希: " + docHash + ") 的锚定交易 " + didAnchorTx.getId() + " 已成功添加到交易池。");
            } else {
                System.err.println("添加 DID " + doc.getId() + " 的锚定交易 " + didAnchorTx.getId() + " 到交易池失败。");
            }

        } catch (Exception e) {
            // 捕获所有其他潜在异常
            System.err.println("将 DID 文档 " + doc.getId() + " 锚定到区块链时发生意外错误: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * (示例方法) 从区块链验证 DID 文档的哈希。
     * 这需要 `BlockService` 中有方法能根据 DID 查询到其最新的锚定哈希。
     * @param doc 要验证的 DID 文档。
     * @return 如果验证成功（当前文档哈希与链上锚定哈希匹配）则返回 true，否则返回 false。
     */
    public boolean verifyDidDocumentFromBlockchain(DidDocument doc) {
        if (blockService == null) {
            System.out.println("BlockService 不可用。跳过 DID 的区块链验证: " + (doc != null ? doc.getId() : "[文档为空]"));
            return false; // 或者根据策略返回 true/抛出异常
        }
        if (doc == null || doc.getId() == null) {
            System.err.println("无法从区块链验证空的或无ID的 DID 文档。");
            return false;
        }

        try {
            // 计算当前内存中/提供的 DID 文档的哈希
            String currentDocHash = doc.calculateDocumentHash();
            if (currentDocHash == null) {
                System.err.println("计算当前 DID 文档哈希失败: " + doc.getId());
                return false;
            }

            // 从区块链查询此 DID 关联的最新锚定哈希
            // 这需要 BlockService 中有类似 findDidAnchorHash(String did) 的方法
            String anchoredHash = blockService.findDidAnchorHash(doc.getId());

            // 比较哈希值
            if (anchoredHash != null && anchoredHash.equals(currentDocHash)) {
                System.out.println("DID 文档 " + doc.getId() + " 的区块链哈希验证成功。");
                return true;
            } else {
                System.err.println("DID 文档 " + doc.getId() + " 的区块链哈希验证失败。当前哈希: " + currentDocHash + ", 链上锚定哈希: " + anchoredHash);
                return false;
            }
        } catch (Exception e) {
            System.err.println("从区块链验证 DID 文档 " + doc.getId() + " 时发生错误: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
}