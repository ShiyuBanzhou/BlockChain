package com.bjut.blockchain.did.service;

import com.bjut.blockchain.did.entity.DidDocumentEntity; // 引入JPA实体
import com.bjut.blockchain.did.model.Did;
import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.did.repository.DidDocumentRepository; // 引入JPA仓库
import com.bjut.blockchain.web.model.Transaction;
import com.bjut.blockchain.web.service.BlockService;
import com.bjut.blockchain.web.service.CAImpl;
import com.bjut.blockchain.web.util.CommonUtil;
import com.bjut.blockchain.web.util.CryptoUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional; // 用于JPA的事务管理

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;
import java.security.KeyPair; // 仅用于 getKeyPairForDid 的声明，实际不应由此服务管理


@Service
public class DidService {

    private static final Logger logger = LoggerFactory.getLogger(DidService.class);

    private final DidDocumentRepository didDocumentRepository; // 注入JPA仓库

    @Autowired(required = false)
    private BlockService blockService;

    @Autowired
    public DidService(DidDocumentRepository didDocumentRepository) {
        this.didDocumentRepository = didDocumentRepository;
    }

    // 内存注册表 didRegistry 和文件持久化相关逻辑已移除

    @Transactional // 对数据库的写操作，建议使用事务
    public Did createDid(String publicKeyBase64) {
        String methodSpecificId = UUID.randomUUID().toString();
        String didString = "did:example:" + methodSpecificId; // 您可以根据需要调整DID方法名称
        Did did = new Did(didString);
        DidDocument docModel = new DidDocument(); // 这是我们的业务模型对象
        docModel.setId(didString);

        DidDocument.VerificationMethod verificationMethod = new DidDocument.VerificationMethod();
        String keyId = didString + "#keys-1"; // 构造密钥ID
        verificationMethod.setId(keyId);
        // 假设客户端提供的是RSA公钥，并用于RSASSA-PKCS1-v1_5签名
        // 如果您使用其他密钥类型（如ECDSA），请相应调整此类型字符串
        verificationMethod.setType("RsaVerificationKey2018");
        verificationMethod.setController(didString);
        verificationMethod.setPublicKeyBase64(publicKeyBase64);

        // 关联证书指纹 (如果需要)
        try {
            X509Certificate nodeCertificate = CAImpl.getCertificate();
            if (nodeCertificate != null) {
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                byte[] fingerprintBytes = messageDigest.digest(nodeCertificate.getEncoded());
                String fingerprint = CryptoUtil.byte2Hex(fingerprintBytes);
                verificationMethod.setX509CertificateFingerprint(fingerprint);
                logger.debug("证书指纹 {} 已关联到密钥ID {}", fingerprint, keyId);
            } else {
                logger.warn("为DID '{}' 创建时未能获取节点证书。", didString);
            }
        } catch (Exception e) {
            logger.error("为DID '{}' 处理证书时出错: {}", didString, e.getMessage(), e);
        }

        docModel.setVerificationMethod(Arrays.asList(verificationMethod));
        docModel.setAuthentication(Arrays.asList(keyId)); // 将此密钥ID用于认证
        docModel.setService(new ArrayList<>()); // 初始化空的service列表，或根据需要填充

        // 将业务模型对象 (DidDocument) 注册 (即保存到数据库)
        registerDidDocument(did, docModel);

        // 区块链锚定逻辑 (保持不变，假设它与DID文档的存储方式无关)
        anchorDidToBlockchain(docModel);

        logger.info("成功创建并注册了新的DID到数据库: {}", didString);
        return did;
    }

    public Did resolveDid(String didString) {
        if (isValidDid(didString)) {
            return new Did(didString);
        }
        logger.warn("尝试解析无效的DID格式: {}", didString);
        return null;
    }

    private boolean isValidDid(String didString) {
        // 简单的DID格式校验
        return didString != null && didString.startsWith("did:");
    }

    /**
     * 将DidDocument模型对象保存到数据库。
     * @param did DID对象
     * @param docModel 要保存的DidDocument模型对象
     */
    @Transactional // 数据库写操作，使用事务
    public void registerDidDocument(Did did, DidDocument docModel) {
        if (did == null || docModel == null || !did.getDidString().equals(docModel.getId())) {
            String errorMsg = String.format("注册DID文档失败: 无效的输入参数。DID: %s, Document ID: %s",
                    (did != null ? did.getDidString() : "null"),
                    (docModel != null ? docModel.getId() : "null"));
            logger.error(errorMsg);
            throw new IllegalArgumentException(errorMsg); // 抛出异常，事务会回滚
        }

        // 将 DidDocument (模型) 转换为 DidDocumentEntity (JPA实体)
        DidDocumentEntity entity = new DidDocumentEntity(
                docModel.getId(),
                docModel.getVerificationMethod(),
                docModel.getAuthentication(),
                docModel.getService()
        );
        // 如果有时间戳字段，在这里设置 entity.setCreatedAt(Instant.now()); 等

        try {
            didDocumentRepository.save(entity); // 保存到数据库，save方法同时处理新建和更新
            logger.info("DID文档 '{}' 已成功保存/更新到数据库。", docModel.getId());
        } catch (Exception e) {
            logger.error("保存DID文档 '{}' 到数据库时发生错误: {}", docModel.getId(), e.getMessage(), e);
            // 根据需要，可以抛出自定义的运行时异常，以便事务回滚
            throw new RuntimeException("保存DID文档到数据库失败", e);
        }
    }

    /**
     * 从数据库根据DID字符串检索DidDocument模型对象。
     * @param didString DID字符串
     * @return DidDocument模型对象，如果未找到则返回null。
     */
    @Transactional(readOnly = true) // 数据库读操作，标记为只读事务以优化
    public DidDocument getDidDocument(String didString) {
        if (didString == null || didString.isEmpty()) {
            logger.debug("尝试获取DID文档，但提供的didString为空。");
            return null;
        }
        Optional<DidDocumentEntity> entityOptional = didDocumentRepository.findById(didString);

        if (entityOptional.isPresent()) {
            DidDocumentEntity entity = entityOptional.get();
            // 将 DidDocumentEntity (JPA实体) 转换为 DidDocument (模型)
            DidDocument docModel = new DidDocument();
            docModel.setId(entity.getId());
            // 注意：转换器已经处理了列表的JSON转换，所以可以直接获取列表对象
            docModel.setVerificationMethod(entity.getVerificationMethod() != null ? new ArrayList<>(entity.getVerificationMethod()) : new ArrayList<>());
            docModel.setAuthentication(entity.getAuthentication() != null ? new ArrayList<>(entity.getAuthentication()) : new ArrayList<>());
            docModel.setService(entity.getService() != null ? new ArrayList<>(entity.getService()) : new ArrayList<>());
            // 如果有时间戳等其他字段，也需要从entity转换到docModel

            logger.debug("从数据库成功检索到DID文档: {}", didString);
            return docModel;
        } else {
            logger.debug("在数据库中未找到DID: {}", didString);
            return null;
        }
    }

    /**
     * 从数据库获取所有已注册的DID字符串。
     * @return 包含所有DID字符串的Set集合。
     */
    @Transactional(readOnly = true)
    public Set<String> getAllDids() {
        List<DidDocumentEntity> allEntities = didDocumentRepository.findAll();
        if (allEntities.isEmpty()) {
            logger.debug("当前数据库中没有DID文档。");
            return Collections.emptySet();
        }
        return allEntities.stream()
                .map(DidDocumentEntity::getId) // 等同于 entity -> entity.getId()
                .collect(Collectors.toSet());
    }

    // getKeyPairForDid 方法保持不变 (它本身不应该被服务端频繁使用或依赖)
    public KeyPair getKeyPairForDid(String didString) {
        logger.warn("调用了 getKeyPairForDid。在理想的DID系统中，服务端不应存储或直接访问用户私钥。DID: {}", didString);
        return null;
    }

    // anchorDidToBlockchain 方法保持不变
    private void anchorDidToBlockchain(DidDocument doc) {
        if (blockService == null) {
            logger.info("BlockService 不可用。跳过 DID '{}' 的区块链锚定。", (doc != null ? doc.getId() : "[文档为空]"));
            return;
        }
        if (doc == null || doc.getId() == null) {
            logger.error("无法将空的或无ID的 DID 文档锚定到区块链。");
            return;
        }
        try {
            String docHash = doc.calculateDocumentHash();
            if (docHash == null) {
                logger.error("计算 DID 文档 '{}' 的哈希失败，无法锚定。", doc.getId());
                return;
            }
            Transaction didAnchorTx = new Transaction();
            didAnchorTx.setId(UUID.randomUUID().toString());
            didAnchorTx.setTimestamp(System.currentTimeMillis());
            Map<String, String> dataMap = new HashMap<>();
            dataMap.put("type", "DID_ANCHOR");
            dataMap.put("did", doc.getId());
            dataMap.put("documentHash", docHash);
            try {
                didAnchorTx.setData(CommonUtil.getJson(dataMap));
            } catch (JsonProcessingException e) {
                logger.error("将DID锚定交易数据转换为JSON时出错 for DID '{}': {}", doc.getId(), e.getMessage(), e);
                return;
            }
            boolean added = blockService.addTransaction(didAnchorTx);
            if (added) {
                logger.info("DID '{}' (哈希: {}) 的锚定交易 '{}' 已成功添加到交易池。", doc.getId(), docHash, didAnchorTx.getId());
            } else {
                logger.warn("添加 DID '{}' 的锚定交易 '{}' 到交易池失败。", doc.getId(), didAnchorTx.getId());
            }
        } catch (Exception e) {
            logger.error("将 DID 文档 '{}' 锚定到区块链时发生意外错误: {}", doc.getId(), e.getMessage(), e);
        }
    }

    // verifyDidDocumentFromBlockchain 方法保持不变
    public boolean verifyDidDocumentFromBlockchain(DidDocument doc) {
        if (blockService == null) { /* ... */ return false; }
        if (doc == null || doc.getId() == null) { /* ... */ return false; }
        try {
            String currentDocHash = doc.calculateDocumentHash();
            if (currentDocHash == null) { /* ... */ return false; }
            String anchoredHash = blockService.findDidAnchorHash(doc.getId());
            if (anchoredHash != null && anchoredHash.equals(currentDocHash)) {
                logger.info("DID 文档 '{}' 的区块链哈希验证成功。", doc.getId());
                return true;
            } else {
                logger.warn("DID 文档 '{}' 的区块链哈希验证失败。当前哈希: {}, 链上锚定哈希: {}", doc.getId(), currentDocHash, anchoredHash);
                return false;
            }
        } catch (Exception e) {
            logger.error("从区块链验证 DID 文档 '{}' 时发生错误: {}", doc.getId(), e.getMessage(), e);
            return false;
        }
    }
}