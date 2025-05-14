package com.bjut.blockchain.did.service;

import com.bjut.blockchain.did.entity.DidDocumentEntity;
import com.bjut.blockchain.did.model.Did;
import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.did.model.DidDocument.VerificationMethod;
import com.bjut.blockchain.did.repository.DidDocumentRepository;
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
import org.springframework.transaction.annotation.Transactional;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.stream.Collectors;
import java.security.KeyPair;

/**
 * 服务类，用于管理和操作 DID (去中心化标识符)。
 * 提供创建、解析 DID，管理 DID 文档（包括添加和移除验证方法），
 * 以及将DID信息锚定到区块链的功能。
 * DID文档持久化到MySQL数据库。
 */
@Service
public class DidService {

    private static final Logger logger = LoggerFactory.getLogger(DidService.class);

    private final DidDocumentRepository didDocumentRepository;
    private final BlockService blockService; // 可选注入，用于区块链锚定

    @Autowired
    public DidService(DidDocumentRepository didDocumentRepository,
                      @Autowired(required = false) BlockService blockService) {
        this.didDocumentRepository = didDocumentRepository;
        this.blockService = blockService;
    }

    /**
     * 创建一个新的DID及其关联的DID文档，并将其保存到数据库。
     * @param publicKeyBase64 客户端提供的公钥 (Base64编码)。
     * @return 创建的Did对象。
     */
    @Transactional
    public Did createDid(String publicKeyBase64) {
        String methodSpecificId = UUID.randomUUID().toString();
        String didString = "did:example:" + methodSpecificId; // 您可以根据需要调整DID方法名称
        Did did = new Did(didString);
        DidDocument docModel = new DidDocument(); // 这是我们的业务模型对象
        docModel.setId(didString);

        VerificationMethod verificationMethod = new VerificationMethod();
        String keyId = didString + "#keys-1"; // 默认的第一个密钥ID
        verificationMethod.setId(keyId);
        // 假设客户端提供的是RSA公钥，并用于RSASSA-PKCS1-v1_5签名
        // 如果您使用其他密钥类型（如ECDSA），请相应调整此类型字符串
        verificationMethod.setType("RsaVerificationKey2018");
        verificationMethod.setController(didString);
        verificationMethod.setPublicKeyBase64(publicKeyBase64);

        // 尝试关联证书指纹 (如果CA服务可用)
        try {
            X509Certificate nodeCertificate = CAImpl.getCertificate();
            if (nodeCertificate != null) {
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                byte[] fingerprintBytes = messageDigest.digest(nodeCertificate.getEncoded());
                String fingerprint = CryptoUtil.byte2Hex(fingerprintBytes);
                verificationMethod.setX509CertificateFingerprint(fingerprint);
                logger.debug("证书指纹 {} 已关联到密钥ID {}", fingerprint, keyId);
            } else {
                logger.warn("为DID '{}' 创建时未能从CA服务获取到节点证书，证书指纹将不会设置。", didString);
            }
        } catch (Exception e) {
            // 不中断DID创建流程，仅记录警告
            logger.warn("为DID '{}' 处理或从CA服务获取证书时出错 (CA服务可能未运行在 http://localhost:9065): {}。证书指纹将不会设置。", didString, e.getMessage());
        }

        docModel.setVerificationMethod(new ArrayList<>(Arrays.asList(verificationMethod))); // 确保是可修改列表
        docModel.setAuthentication(new ArrayList<>(Arrays.asList(keyId))); // 将此密钥ID用于认证，确保是可修改列表
        docModel.setService(new ArrayList<>()); // 初始化空的service列表

        registerDidDocument(did, docModel); // 保存到数据库

        // 尝试锚定到区块链 (如果BlockService可用)
        if (this.blockService != null) {
            anchorDidToBlockchain(docModel);
        } else {
            logger.warn("BlockService未注入，跳过为DID '{}' 创建时的区块链锚定。", didString);
        }

        logger.info("成功创建并注册了新的DID到数据库: {}", didString);
        return did;
    }

    /**
     * 将DidDocument模型对象保存或更新到数据库。
     * 此方法由 createDid 和更新方法内部调用。
     * @param did DID对象。
     * @param docModel 要保存/更新的DidDocument模型对象。
     */
    @Transactional
    public void registerDidDocument(Did did, DidDocument docModel) {
        if (did == null || docModel == null || !did.getDidString().equals(docModel.getId())) {
            String errorMsg = String.format("注册DID文档失败: 无效的输入参数。DID: %s, Document ID: %s",
                    (did != null ? did.getDidString() : "null"),
                    (docModel != null ? docModel.getId() : "null"));
            logger.error(errorMsg);
            throw new IllegalArgumentException(errorMsg); // 抛出异常，以便事务回滚
        }

        // 将 DidDocument (模型) 转换为 DidDocumentEntity (JPA实体)
        DidDocumentEntity entity = new DidDocumentEntity(
                docModel.getId(),
                // 确保列表是新的ArrayList实例，以防原始列表是不可修改的（例如Arrays.asList的结果）
                docModel.getVerificationMethod() != null ? new ArrayList<>(docModel.getVerificationMethod()) : new ArrayList<>(),
                docModel.getAuthentication() != null ? new ArrayList<>(docModel.getAuthentication()) : new ArrayList<>(),
                docModel.getService() != null ? new ArrayList<>(docModel.getService()) : new ArrayList<>()
        );
        // 如果有 created_at, updated_at 字段，JPA的 @PrePersist, @PreUpdate 会处理

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
     * @param didString DID字符串。
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
            // 确保从实体转换回模型时，列表是可修改的ArrayList
            docModel.setVerificationMethod(entity.getVerificationMethod() != null ? new ArrayList<>(entity.getVerificationMethod()) : new ArrayList<>());
            docModel.setAuthentication(entity.getAuthentication() != null ? new ArrayList<>(entity.getAuthentication()) : new ArrayList<>());
            docModel.setService(entity.getService() != null ? new ArrayList<>(entity.getService()) : new ArrayList<>());

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


    /**
     * 向指定的DID文档中添加一个新的验证方法。
     * 此方法假定授权已在Controller层完成。
     * @param didString 要更新的DID。
     * @param newVmModel 要添加的新验证方法模型。
     * @return 更新后的DidDocument模型，如果DID不存在或更新失败则返回null。
     */
    @Transactional
    public DidDocument addVerificationMethodToDocument(String didString, VerificationMethod newVmModel) {
        if (didString == null || didString.isEmpty() || newVmModel == null ||
                newVmModel.getId() == null || newVmModel.getId().isEmpty()) {
            logger.error("添加验证方法失败：无效的参数。DID: {}, NewVM ID: {}", didString, (newVmModel != null ? newVmModel.getId() : "null"));
            return null; // 或者抛出IllegalArgumentException
        }
        // 校验新的KeyID是否以其所属的DID开头，并包含 '#'
        if (!newVmModel.getId().startsWith(didString + "#")) {
            logger.error("添加验证方法失败：新的密钥ID '{}' 格式无效，它必须以 '{}#' 开头。", newVmModel.getId(), didString);
            return null; // 或者抛出IllegalArgumentException
        }

        Optional<DidDocumentEntity> entityOptional = didDocumentRepository.findById(didString);
        if (!entityOptional.isPresent()) {
            logger.warn("尝试更新DID文档 '{}' 失败：该DID在数据库中不存在。", didString);
            return null;
        }

        DidDocumentEntity entity = entityOptional.get();
        // 从数据库实体获取的列表可能是不可修改的代理，或者由转换器返回的是不可修改的Collections.emptyList()
        // 因此，总是创建一个新的可修改列表副本进行操作
        List<VerificationMethod> verificationMethods = entity.getVerificationMethod() != null ? new ArrayList<>(entity.getVerificationMethod()) : new ArrayList<>();

        final String newKeyId = newVmModel.getId();
        boolean keyIdExists = verificationMethods.stream().anyMatch(vm -> newKeyId.equals(vm.getId()));
        if (keyIdExists) {
            logger.warn("添加验证方法到DID '{}' 失败：密钥ID '{}' 已存在。", didString, newKeyId);
            // 根据策略，可以选择更新现有同名keyId的VM，或直接失败。此处选择失败。
            return null;
        }

        verificationMethods.add(newVmModel);
        entity.setVerificationMethod(verificationMethods); // 设置更新后的列表回实体
        // 如果有 updated_at 字段，在这里更新: entity.setUpdatedAt(Instant.now());

        try {
            DidDocumentEntity updatedEntity = didDocumentRepository.save(entity); // 保存更新后的实体
            logger.info("成功为DID '{}' 添加了新的验证方法 '{}'。", didString, newVmModel.getId());

            // 将更新后的实体转换回模型对象返回
            DidDocument updatedDocModel = getDidDocument(updatedEntity.getId()); // 复用getDidDocument进行转换

            // (可选) 将DID文档的更新（例如新哈希）锚定到区块链
            if (updatedDocModel != null && this.blockService != null) {
                anchorDidToBlockchain(updatedDocModel);
            } else if (this.blockService == null) {
                logger.warn("BlockService未注入，跳过为更新后的DID '{}' 进行区块链锚定。", didString);
            }
            return updatedDocModel;
        } catch (Exception e) {
            logger.error("保存更新（添加密钥）后的DID文档 '{}' 到数据库时出错: {}", didString, e.getMessage(), e);
            // 抛出运行时异常以触发事务回滚
            throw new RuntimeException("更新（添加密钥）DID文档时数据库操作失败", e);
        }
    }

    /**
     * 从指定的DID文档中移除一个验证方法。
     * 此方法假定授权已在Controller层完成。
     * @param didString 要更新的DID。
     * @param keyIdToRemove 要移除的验证方法的完整ID。
     * @return 更新后的DidDocument模型，如果DID不存在、密钥ID未找到或更新失败则返回null。
     */
    @Transactional
    public DidDocument removeVerificationMethodFromDocument(String didString, String keyIdToRemove) {
        if (didString == null || didString.isEmpty() || keyIdToRemove == null || keyIdToRemove.isEmpty()) {
            logger.error("移除验证方法失败：无效的参数。DID: {}, KeyIDToRemove: {}", didString, keyIdToRemove);
            return null; // 或者抛出IllegalArgumentException
        }

        Optional<DidDocumentEntity> entityOptional = didDocumentRepository.findById(didString);
        if (!entityOptional.isPresent()) {
            logger.warn("尝试移除密钥从DID '{}' 失败：该DID在数据库中不存在。", didString);
            return null;
        }

        DidDocumentEntity entity = entityOptional.get();
        List<VerificationMethod> verificationMethods = entity.getVerificationMethod() != null ? new ArrayList<>(entity.getVerificationMethod()) : new ArrayList<>();
        List<String> authenticationIds = entity.getAuthentication() != null ? new ArrayList<>(entity.getAuthentication()) : new ArrayList<>();

        // 查找并移除验证方法
        boolean vmRemoved = verificationMethods.removeIf(vm -> keyIdToRemove.equals(vm.getId()));

        if (!vmRemoved) {
            logger.warn("尝试从DID '{}' 移除密钥ID '{}' 失败：该密钥ID在验证方法列表中未找到。", didString, keyIdToRemove);
            // 由于没有更改，直接返回当前文档模型
            return getDidDocument(didString);
        }

        // 如果被移除的密钥ID也存在于 authentication 列表中，也将其移除
        boolean authIdRemoved = authenticationIds.removeIf(authId -> keyIdToRemove.equals(authId));
        if (authIdRemoved) {
            logger.info("密钥ID '{}' 也已从DID '{}' 的 authentication 列表中移除。", keyIdToRemove, didString);
        }

        // 检查在移除后是否还存在至少一个 authentication method，如果 authentication 列表变空，可能需要警告或特殊处理
        if (authenticationIds.isEmpty() && !verificationMethods.isEmpty()) {
            logger.warn("警告：移除密钥ID '{}' 后，DID '{}' 的 authentication 列表为空，但仍有其他验证方法。该DID可能无法再用于认证，除非添加新的authentication引用。", keyIdToRemove, didString);
        } else if (verificationMethods.isEmpty() && authenticationIds.isEmpty()){
            logger.warn("警告：移除密钥ID '{}' 后，DID '{}' 不再有任何验证方法或认证引用。该DID可能已失控。", keyIdToRemove, didString);
        }


        entity.setVerificationMethod(verificationMethods);
        entity.setAuthentication(authenticationIds);
        // entity.setUpdatedAt(Instant.now()); // 如果有更新时间戳字段

        try {
            DidDocumentEntity updatedEntity = didDocumentRepository.save(entity);
            logger.info("成功从DID '{}' 移除了验证方法 '{}'。", didString, keyIdToRemove);

            DidDocument updatedDocModel = getDidDocument(updatedEntity.getId());
            if (updatedDocModel != null && this.blockService != null) {
                anchorDidToBlockchain(updatedDocModel); // 锚定更新后的文档
            } else if (this.blockService == null) {
                logger.warn("BlockService未注入，跳过为更新（移除密钥）后的DID '{}' 进行区块链锚定。", didString);
            }
            return updatedDocModel;
        } catch (Exception e) {
            logger.error("保存更新（移除密钥）后的DID文档 '{}' 到数据库时出错: {}", didString, e.getMessage(), e);
            throw new RuntimeException("更新（移除密钥）DID文档时数据库操作失败", e);
        }
    }

    // --- 其他辅助方法 ---
    public Did resolveDid(String didString) {
        if (isValidDid(didString)) {
            return new Did(didString);
        }
        logger.warn("尝试解析无效的DID格式: {}", didString);
        return null;
    }

    private boolean isValidDid(String didString) {
        return didString != null && didString.startsWith("did:");
    }

    public KeyPair getKeyPairForDid(String didString) {
        logger.warn("调用了 getKeyPairForDid。在理想的DID系统中，服务端不应存储或直接访问用户私钥。DID: {}", didString);
        return null; // 服务端不管理私钥
    }

    private void anchorDidToBlockchain(DidDocument docModel) {
        if (blockService == null) {
            logger.info("BlockService 不可用。跳过 DID '{}' 的区块链锚定。", (docModel != null ? docModel.getId() : "[文档为空]"));
            return;
        }
        if (docModel == null || docModel.getId() == null) {
            logger.error("无法将空的或无ID的 DID 文档锚定到区块链。");
            return;
        }
        try {
            String docHash = docModel.calculateDocumentHash(); // DidDocument模型应有此方法
            if (docHash == null) {
                logger.error("计算 DID 文档 '{}' 的哈希失败，无法锚定。", docModel.getId());
                return;
            }
            Transaction didAnchorTx = new Transaction();
            didAnchorTx.setId(UUID.randomUUID().toString());
            didAnchorTx.setTimestamp(System.currentTimeMillis());
            Map<String, String> dataMap = new HashMap<>();
            dataMap.put("type", "DID_ANCHOR");
            dataMap.put("did", docModel.getId());
            dataMap.put("documentHash", docHash);
            try {
                // CommonUtil.getJson 应使用注入的或静态的ObjectMapper
                didAnchorTx.setData(CommonUtil.getJson(dataMap));
            } catch (JsonProcessingException e) {
                logger.error("将DID锚定交易数据转换为JSON时出错 for DID '{}': {}", docModel.getId(), e.getMessage(), e);
                return;
            }
            // BlockService.addTransaction 现在将交易保存到数据库的待处理池
            boolean added = blockService.addTransaction(didAnchorTx);
            if (added) {
                logger.info("DID '{}' (哈希: {}) 的锚定交易 '{}' 已成功添加到待处理交易池。", docModel.getId(), docHash, didAnchorTx.getId());
            } else {
                logger.warn("添加 DID '{}' 的锚定交易 '{}' 到待处理交易池失败。", docModel.getId(), didAnchorTx.getId());
            }
        } catch (Exception e) {
            logger.error("将 DID 文档 '{}' 锚定到区块链时发生意外错误: {}", docModel.getId(), e.getMessage(), e);
        }
    }

    public boolean verifyDidDocumentFromBlockchain(DidDocument docModel) {
        if (blockService == null) {
            logger.info("BlockService不可用，跳过DID '{}'的区块链验证。", (docModel != null ? docModel.getId() : "[文档为空]"));
            return false;
        }
        if (docModel == null || docModel.getId() == null) {
            logger.error("无法从区块链验证空或无ID的DID文档。");
            return false;
        }
        try {
            String currentDocHash = docModel.calculateDocumentHash();
            if (currentDocHash == null) {
                logger.error("计算当前DID文档 '{}' 哈希失败，无法从区块链验证。", docModel.getId());
                return false;
            }
            // BlockService.findDidAnchorHash 应查询已打包到区块中的交易
            String anchoredHash = blockService.findDidAnchorHash(docModel.getId());
            if (anchoredHash != null && anchoredHash.equals(currentDocHash)) {
                logger.info("DID 文档 '{}' 的区块链哈希验证成功。", docModel.getId());
                return true;
            } else {
                logger.warn("DID 文档 '{}' 的区块链哈希验证失败。当前哈希: {}, 链上锚定哈希: {}", docModel.getId(), currentDocHash, anchoredHash);
                return false;
            }
        } catch (Exception e) {
            logger.error("从区块链验证 DID 文档 '{}' 时发生错误: {}", docModel.getId(), e.getMessage(), e);
            return false;
        }
    }
}
