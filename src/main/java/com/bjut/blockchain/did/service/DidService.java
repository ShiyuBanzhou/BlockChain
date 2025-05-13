package com.bjut.blockchain.did.service;

import com.bjut.blockchain.web.service.CAImpl;
import com.bjut.blockchain.web.util.CryptoUtil;
import com.bjut.blockchain.did.model.Did;
import com.bjut.blockchain.did.model.DidDocument;
import com.bjut.blockchain.web.service.BlockService; // 假设引入 BlockService
import com.bjut.blockchain.web.model.Transaction; // 假设引入 Transaction
import com.bjut.blockchain.web.util.CommonUtil; // 引入 CommonUtil 计算哈希
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.Set; // 引入 Set
import java.util.Collections; // 引入 Collections
import java.security.KeyPair; // 引入 KeyPair 以备将来使用或参考

/**
 * 服务类，用于管理和操作 DID (去中心化标识符)。
 * 提供创建、解析 DID 以及管理 DID 文档的功能。
 */
@Service
public class DidService {

    // 使用 Map 模拟 DID 注册表或存储 (DID 字符串 -> DidDocument)
    private static final Map<String, DidDocument> didRegistry = new HashMap<>();
    // (可选) 如果 DidService 需要管理密钥对，可以添加一个 Map
    // private static final Map<String, KeyPair> keyStorage = new HashMap<>();

    // 注入 BlockService 用于将 DID 相关信息上链 (需要自行实现)
    @Autowired(required = false) // required = false 避免强制依赖，方便测试
    private BlockService blockService;

    /**
     * 使用提供的公钥创建一个新的 DID 和关联的 DID 文档。
     * 将 DID 文档注册到内存注册表，并尝试将其锚定到区块链。
     * 假设提供的公钥是 Base64 编码的 X.509 格式 (适用于 RSA/EC)。
     *
     * @param publicKeyBase64 Base64 编码的公钥字符串。
     * @return 新创建的 Did 对象。
     */
    public Did createDid(String publicKeyBase64) {
        // 生成 DID 的方法特定标识符
        String methodSpecificId = UUID.randomUUID().toString();
        // 构造 DID 字符串 (示例格式)
        String didString = "did:example:" + methodSpecificId;
        Did did = new Did(didString);

        // 创建 DID 文档对象
        DidDocument doc = new DidDocument();
        doc.setId(didString); // 设置 DID 文档的 ID 为 DID 字符串

        // 创建验证方法对象并填充信息
        DidDocument.VerificationMethod verificationMethod = new DidDocument.VerificationMethod();
        verificationMethod.setId(didString + "#keys-1"); // 设置验证方法 ID
        verificationMethod.setType("RsaVerificationKey2018"); // RSA 密钥的标准类型
        verificationMethod.setController(didString); // 控制者是 DID 本身
        verificationMethod.setPublicKeyBase64(publicKeyBase64);
        // verificationMethod.setPublicKeyBase58(null); // Base58 字段可以设为 null 或不使用

        // ---- 集成证书管理 ----
        try {
            X509Certificate nodeCertificate = CAImpl.getCertificate(); // 获取节点自己的证书
            if (nodeCertificate != null) {
                // 计算证书指纹
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                byte[] fingerprintBytes = messageDigest.digest(nodeCertificate.getEncoded());
                String fingerprint = CryptoUtil.byte2Hex(fingerprintBytes);
                verificationMethod.setX509CertificateFingerprint(fingerprint);


                System.out.println("证书已关联到DID: " + didString + "，指纹: " + fingerprint);
            } else {
                System.err.println("未能获取证书用于DID: " + didString);
            }

        } catch (Exception e) {
            System.err.println("在DID创建过程中处理证书时出错: " + e.getMessage());
            // 根据错误处理策略决定是否继续
        }

        // 将验证方法添加到 DID 文档
        doc.getVerificationMethod().add(verificationMethod);
        // 假设此密钥也用于认证，将其 ID 添加到认证列表中
        doc.getAuthentication().add(verificationMethod.getId());

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
        // 简单的格式校验，生产环境中应更严格
        return didString != null && didString.startsWith("did:");
    }

    /**
     * "注册" 或存储 DID 文档。
     * 实际应用中可能涉及将文档存储在分布式文件系统（如 IPFS）或区块链上。
     * 这里使用简单的内存 Map 模拟。
     * @param did 与文档关联的 DID。
     * @param doc 要注册的 DID 文档。
     */
    public void registerDidDocument(Did did, DidDocument doc) {
        if (did != null && doc != null && did.getDidString().equals(doc.getId())) {
            didRegistry.put(did.getDidString(), doc);
            System.out.println("DID 文档已注册: " + did.getDidString());
        } else {
            System.err.println("注册 DID 文档失败: 无效输入。");
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
     * @return 包含所有 DID 字符串的 Set 集合。
     */
    public Set<String> getAllDids() {
        // 返回注册表键集的一个不可修改的视图，防止外部修改
        return Collections.unmodifiableSet(didRegistry.keySet());
    }

    /**
     * (占位符/待移除) 获取与 DID 关联的密钥对。
     * **注意：** 当前实现假设密钥管理在服务外部进行。
     * @param didString DID 字符串。
     * @return KeyPair 对象，如果服务不管理密钥或未找到，则返回 null。
     */
    public KeyPair getKeyPairForDid(String didString) {
        System.out.println("警告: 调用了 getKeyPairForDid, 但此配置下 DidService 不管理私钥。");
        // return keyStorage.get(didString); // 如果实现了 keyStorage
        return null; // 当前配置下返回 null
    }


    /**
     * 将 DID 文档的关键信息（例如哈希）锚定到区块链上。
     * 通常通过创建一个包含 DID 文档哈希的特殊交易来实现。
     * @param doc 要锚定的 DID 文档。
     */
    private void anchorDidToBlockchain(DidDocument doc) {
        // 检查 BlockService 是否可用
        if (blockService == null) {
            System.out.println("BlockService 不可用。跳过 DID 的区块链锚定: " + doc.getId());
            return;
        }
        // 检查文档是否有效
        if (doc == null || doc.getId() == null) {
            System.err.println("无法将空的 DID 文档锚定到区块链。");
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
            didAnchorTx.setId(UUID.randomUUID().toString()); // 交易 ID
            didAnchorTx.setTimestamp(System.currentTimeMillis()); // 时间戳
            // 交易的 publicKey 和 sign 应由调用者（控制密钥的一方）设置
            // didAnchorTx.setPublicKey("...");
            // didAnchorTx.setSign("...");

            // 准备交易数据
            Map<String, String> data = new HashMap<>();
            data.put("type", "DID_ANCHOR"); // 添加类型字段，便于查询
            data.put("did", doc.getId());
            data.put("documentHash", docHash);
            // 使用 CommonUtil 将 Map 转换为 JSON 字符串存储在 data 字段
            didAnchorTx.setData(CommonUtil.getJson(data));

            // 将交易添加到交易池
            boolean added = blockService.addTransaction(didAnchorTx);
            if (added) {
                System.out.println("将 DID " + doc.getId() + " (哈希: " + docHash + ") 通过交易 " + didAnchorTx.getId() + " 锚定到区块链。");
            } else {
                System.err.println("添加 DID 锚定交易 " + didAnchorTx.getId() + " 到交易池失败。");
            }

        } catch (Exception e) {
            System.err.println("将 DID 文档 " + doc.getId() + " 锚定到区块链时出错: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * (示例) 从区块链验证 DID 文档的哈希。
     * @param doc 要验证的 DID 文档。
     * @return 如果验证成功（哈希匹配）则返回 true，否则返回 false。
     */
    public boolean verifyDidDocumentFromBlockchain(DidDocument doc) {
        if (blockService == null) {
            System.out.println("BlockService 不可用。跳过 DID 的区块链验证: " + doc.getId());
            return false; // 或根据策略返回 true/抛出异常
        }
        if (doc == null || doc.getId() == null) {
            System.err.println("无法从区块链验证空的 DID 文档。");
            return false;
        }

        try {
            // 计算当前文档的哈希
            String currentDocHash = doc.calculateDocumentHash();
            if (currentDocHash == null) {
                System.err.println("计算当前 DID 文档哈希失败: " + doc.getId());
                return false;
            }

            // 从区块链查询此 DID 关联的锚定哈希
            String anchoredHash = blockService.findDidAnchorHash(doc.getId()); // 使用 BlockService 的方法

            // 比较哈希值
            if (anchoredHash != null && anchoredHash.equals(currentDocHash)) {
                System.out.println("DID 区块链验证成功: " + doc.getId());
                return true;
            } else {
                System.err.println("DID 区块链验证失败: " + doc.getId() + ". 当前哈希: " + currentDocHash + ", 锚定哈希: " + anchoredHash);
                return false;
            }
        } catch (Exception e) {
            System.err.println("从区块链验证 DID 文档 " + doc.getId() + " 时出错: " + e.getMessage());
            e.printStackTrace();
            return false;
        }
    }
}
