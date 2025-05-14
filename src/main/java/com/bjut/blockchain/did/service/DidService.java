package com.bjut.blockchain.did.service;

import com.bjut.blockchain.web.service.CAImpl;
import com.bjut.blockchain.web.util.CryptoUtil;
import com.bjut.blockchain.did.model.Did;
import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.web.service.BlockService;
import com.bjut.blockchain.web.model.Transaction;
import com.bjut.blockchain.web.util.CommonUtil;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference; // 用于反序列化泛型Map
import com.fasterxml.jackson.databind.ObjectMapper; // Jackson ObjectMapper
import org.slf4j.Logger; // SLF4J 日志接口
import org.slf4j.LoggerFactory; // SLF4J 日志工厂
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct; // 用于初始化加载
import java.io.File; // 文件操作
import java.io.IOException; // IO异常
import java.nio.file.Files; // 新的NIO文件操作
import java.nio.file.Paths; // 路径操作
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
// import java.util.Base64; // Base64在CommonUtil或CryptoUtil中处理
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.Set;
import java.util.Collections;
import java.security.KeyPair; // 仅用于getKeyPairForDid的声明，实际不应由此服务管理
import java.util.Arrays;
// import java.util.List; // 已在Arrays中使用

/**
 * 服务类，用于管理和操作 DID (去中心化标识符)。
 * 提供创建、解析 DID 以及管理 DID 文档的功能。
 * 新增了将DID注册表持久化到文件的功能。
 */
@Service
public class DidService {

    private static final Logger logger = LoggerFactory.getLogger(DidService.class); // 添加日志记录器

    // DID 注册表，现在会从文件加载和保存到文件
    private static Map<String, DidDocument> didRegistry = new HashMap<>(); // 改为非final，以便从文件加载时重新赋值

    // Jackson ObjectMapper 用于JSON序列化和反序列化
    private final ObjectMapper objectMapper;

    // DID注册表持久化文件的路径
    // 您可以将其配置在 application.yml 中，然后使用 @Value 注入
    private static final String DID_REGISTRY_FILE_PATH = "did_registry.json"; // 文件名

    @Autowired(required = false)
    private BlockService blockService;

    // 构造函数注入 ObjectMapper
    @Autowired
    public DidService(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    /**
     * 服务初始化时，从文件加载DID注册表。
     */
    @PostConstruct
    private void initializeDidRegistry() {
        loadDidRegistryFromFile();
    }

    /**
     * 从JSON文件加载DID注册表到内存。
     */
    private synchronized void loadDidRegistryFromFile() { // 添加 synchronized 保证线程安全的文件访问
        File registryFile = new File(DID_REGISTRY_FILE_PATH);
        if (registryFile.exists() && registryFile.length() > 0) { // 检查文件是否存在且不为空
            try {
                String jsonContent = new String(Files.readAllBytes(Paths.get(DID_REGISTRY_FILE_PATH)));
                // 反序列化为 Map<String, DidDocument>
                TypeReference<HashMap<String, DidDocument>> typeRef = new TypeReference<HashMap<String, DidDocument>>() {};
                didRegistry = objectMapper.readValue(jsonContent, typeRef);
                logger.info("成功从 '{}' 加载 {} 个DID文档到注册表。", DID_REGISTRY_FILE_PATH, didRegistry.size());
            } catch (IOException e) {
                logger.error("从文件 '{}' 加载DID注册表失败: {}", DID_REGISTRY_FILE_PATH, e.getMessage(), e);
                // 如果加载失败，保持一个空的注册表或采取其他错误处理措施
                didRegistry = new HashMap<>();
            }
        } else {
            logger.info("DID注册表文件 '{}' 不存在或为空，将使用空的注册表启动。", DID_REGISTRY_FILE_PATH);
            didRegistry = new HashMap<>(); //确保如果文件不存在，注册表也被初始化为空map
        }
    }

    /**
     * 将内存中的DID注册表保存到JSON文件。
     */
    private synchronized void saveDidRegistryToFile() { // 添加 synchronized 保证线程安全的文件访问
        try {
            // 使用objectMapper将Map序列化为格式化的JSON字符串
            String jsonContent = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsString(didRegistry);
            Files.write(Paths.get(DID_REGISTRY_FILE_PATH), jsonContent.getBytes());
            logger.debug("成功将 {} 个DID文档保存到注册表文件 '{}'。", didRegistry.size(), DID_REGISTRY_FILE_PATH);
        } catch (IOException e) {
            logger.error("保存DID注册表到文件 '{}' 失败: {}", DID_REGISTRY_FILE_PATH, e.getMessage(), e);
        }
    }


    public Did createDid(String publicKeyBase64) {
        String methodSpecificId = UUID.randomUUID().toString();
        String didString = "did:example:" + methodSpecificId;
        Did did = new Did(didString);
        DidDocument doc = new DidDocument();
        doc.setId(didString);

        DidDocument.VerificationMethod verificationMethod = new DidDocument.VerificationMethod();
        String keyId = didString + "#keys-1";
        verificationMethod.setId(keyId);
        verificationMethod.setType("RsaVerificationKey2018");
        verificationMethod.setController(didString);
        verificationMethod.setPublicKeyBase64(publicKeyBase64);

        try {
            X509Certificate nodeCertificate = CAImpl.getCertificate();
            if (nodeCertificate != null) {
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                byte[] fingerprintBytes = messageDigest.digest(nodeCertificate.getEncoded());
                String fingerprint = CryptoUtil.byte2Hex(fingerprintBytes);
                verificationMethod.setX509CertificateFingerprint(fingerprint);
                logger.debug("证书指纹 {} 已关联到密钥 {}", fingerprint, keyId);
            } else {
                logger.warn("为DID '{}' 创建时未能获取节点证书。", didString);
            }
        } catch (Exception e) {
            logger.error("为DID '{}' 处理证书时出错: {}", didString, e.getMessage(), e);
        }

        doc.setVerificationMethod(Arrays.asList(verificationMethod));
        doc.setAuthentication(Arrays.asList(keyId));

        registerDidDocument(did, doc); // 内部会调用 saveDidRegistryToFile()
        anchorDidToBlockchain(doc);

        logger.info("成功创建并注册了新的DID: {}", didString);
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
        return didString != null && didString.startsWith("did:");
    }

    public void registerDidDocument(Did did, DidDocument doc) {
        if (did != null && doc != null && did.getDidString().equals(doc.getId())) {
            didRegistry.put(did.getDidString(), doc);
            logger.info("DID文档 '{}' 已在内存中注册/更新。", did.getDidString());
            saveDidRegistryToFile(); // 每次注册/更新后保存到文件
        } else {
            logger.error("注册DID文档失败: 无效的输入参数。DID: {}, Document ID: {}",
                    (did != null ? did.getDidString() : "null"),
                    (doc != null ? doc.getId() : "null"));
        }
    }

    public DidDocument getDidDocument(String didString) {
        DidDocument doc = didRegistry.get(didString);
        if (doc == null) {
            logger.debug("在注册表中未找到DID: {}", didString);
        }
        return doc;
    }

    public Set<String> getAllDids() {
        if (didRegistry.isEmpty()) {
            logger.debug("当前DID注册表为空。");
        }
        return Collections.unmodifiableSet(didRegistry.keySet());
    }

    public KeyPair getKeyPairForDid(String didString) {
        logger.warn("调用了 getKeyPairForDid，但此服务不管理私钥。DID: {}", didString);
        return null;
    }

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
                didAnchorTx.setData(CommonUtil.getJson(dataMap)); // CommonUtil内部应使用注入的或静态的ObjectMapper
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

    public boolean verifyDidDocumentFromBlockchain(DidDocument doc) {
        if (blockService == null) {
            logger.info("BlockService 不可用。跳过 DID '{}' 的区块链验证。", (doc != null ? doc.getId() : "[文档为空]"));
            return false;
        }
        if (doc == null || doc.getId() == null) {
            logger.error("无法从区块链验证空的或无ID的 DID 文档。");
            return false;
        }

        try {
            String currentDocHash = doc.calculateDocumentHash();
            if (currentDocHash == null) {
                logger.error("计算当前 DID 文档 '{}' 哈希失败，无法从区块链验证。", doc.getId());
                return false;
            }

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