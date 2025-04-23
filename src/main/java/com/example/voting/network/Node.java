package com.example.voting.network;

import com.example.voting.blockchain.*;
import com.example.voting.crypto.CryptoUtil;
import com.example.voting.crypto.DigitalCertificate;
import com.example.voting.crypto.KeyUtil;
import com.example.voting.trust.TrustManager;
import com.example.voting.SystemLogger;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set; // Import Set

/**
 * Represents a node in the simulated blockchain network.
 * Includes node discovery logic.
 * 模拟区块链网络中的节点。
 * 包括节点发现逻辑。
 */
public class Node {
    private String nodeId;
    private IdentityBlockchain identityChain;
    private VotingBlockchain votingChain;
    private KeyPair rsaKeyPair;
    private SecretKey groupKey;
    private TrustManager trustManager;
    private PublicKey caPublicKey;
    private X509CRL currentCRL;
    private NetworkManager networkManager;
    private boolean joinedNetwork = false; // Flag to indicate if node has joined 标记节点是否已加入

    /**
     * Constructor for Node. Node is not registered with NetworkManager here.
     * 节点的构造函数。节点此时尚未在 NetworkManager 中注册。
     * @param nodeId        Unique identifier for the node. 节点的唯一标识符。
     * @param idChain       Reference to the identity blockchain. 对身份区块链的引用。
     * @param voteChain     Reference to the voting blockchain. 对投票区块链的引用。
     * @param caPublicKey   The public key of the trusted CA. 受信任 CA 的公钥。
     * @param networkManager Reference to the network manager. 对网络管理器的引用。
     */
    public Node(String nodeId, IdentityBlockchain idChain, VotingBlockchain voteChain,
                PublicKey caPublicKey, NetworkManager networkManager) {
        this.nodeId = nodeId;
        this.identityChain = idChain;
        this.votingChain = voteChain;
        this.caPublicKey = caPublicKey;
        this.networkManager = networkManager; // Store reference 存储引用
        this.rsaKeyPair = KeyUtil.generateRSAKeyPair();
        this.trustManager = new TrustManager(nodeId);
        if (this.rsaKeyPair == null) {
            throw new RuntimeException("Failed to generate RSA key pair for node " + nodeId);
        }
        // DO NOT register here anymore - registration happens in joinNetwork
        // 不再在此处注册 - 注册发生在 joinNetwork 中
        SystemLogger.log("节点 " + nodeId + " 已创建 (尚未加入网络)。");
    }

    /**
     * Simulates the process of joining the network.
     * Registers with the NetworkManager and discovers initial peers.
     * 模拟加入网络的过程。
     * 向 NetworkManager 注册并发现初始对等节点。
     * @param seedNodeIds A set of known seed node IDs (can be empty if this IS a seed node). 已知种子节点 ID 的集合（如果这是种子节点，则可以为空）。
     */
    public void joinNetwork(Set<String> seedNodeIds) {
        if (joinedNetwork) {
            SystemLogger.log("节点 " + nodeId + " 已加入网络。");
            return;
        }
        if (networkManager == null) {
            SystemLogger.error("节点 " + nodeId + " 无法加入网络：NetworkManager 未设置。");
            return;
        }

        SystemLogger.log("节点 " + nodeId + " 正在尝试加入网络...");

        // 1. Register self with the NetworkManager
        // 1. 向 NetworkManager 注册自己
        networkManager.registerNode(this);

        // 2. Discover peers (unless this is the only node or a seed node starting first)
        // 2. 发现对等节点（除非这是唯一的节点或第一个启动的种子节点）
        // In a real P2P system, would contact seeds. Here, we query the manager.
        // 在真实的 P2P 系统中，会联系种子节点。这里我们查询管理器。
        if (!seedNodeIds.contains(this.nodeId) || networkManager.getAllNodeIds().size() > 1) {
            int maxPeersToDiscover = 5; // Example limit 示例限制
            List<String> discoveredPeerIds = networkManager.getRandomPeerIds(this.nodeId, maxPeersToDiscover);
            if (!discoveredPeerIds.isEmpty()) {
                SystemLogger.log("节点 " + nodeId + " 发现了 " + discoveredPeerIds.size() + " 个对等节点: " + discoveredPeerIds);
                // Optional: Store discovered peers locally or use them for direct communication later
                // 可选：在本地存储发现的对等节点或稍后用于直接通信
            } else {
                SystemLogger.log("节点 " + nodeId + " 未发现其他对等节点（可能是第一个节点）。");
            }
        } else {
            SystemLogger.log("节点 " + nodeId + " 是种子节点或第一个节点，跳过对等节点发现。");
        }

        // 3. Mark as joined and potentially announce presence
        // 3. 标记为已加入并可能宣告存在
        this.joinedNetwork = true;
        SystemLogger.log("节点 " + nodeId + " 已成功加入网络。");

        // Optional: Broadcast a "hello" or "join" message
        // 可选：广播 "hello" 或 "join" 消息
        // broadcast("JOIN: Node " + nodeId + " is online.");
    }

    // --- Getters and Key Management (unchanged) ---
    public String getId() { return nodeId; }
    public PublicKey getPublicKey() { return rsaKeyPair.getPublic(); }
    private PrivateKey getPrivateKey() { return rsaKeyPair.getPrivate(); }
    public PublicKey getCaPublicKey() { return caPublicKey; }
    public TrustManager getTrustManager() { return trustManager; } // Added getter 添加了 getter
    public void updateCRL(X509CRL newCRL) { /* ... unchanged ... */
        if (newCRL != null) { try { newCRL.verify(this.caPublicKey); this.currentCRL = newCRL; } catch (Exception e) { SystemLogger.error("Node " + nodeId + ": Received invalid CRL. Ignoring."); e.printStackTrace(); } } else { SystemLogger.error("Node " + nodeId + ": Received null CRL."); } }
    public void receiveGroupKey(String encKey) { /* ... unchanged ... */
        try { this.groupKey = GroupCommUtil.decryptGroupKey(encKey, getPrivateKey()); if (this.groupKey == null) { SystemLogger.error("Node " + nodeId + " failed to decrypt group key."); } } catch (Exception e) { SystemLogger.error("Error receiving group key for node " + nodeId + ": " + e.getMessage()); e.printStackTrace(); } }

    // --- Communication Methods ---
    public void broadcast(String msg) {
        if (!joinedNetwork) { SystemLogger.error("节点 " + nodeId + " 无法广播：尚未加入网络。"); return; }
        if (networkManager == null || groupKey == null || msg == null) { SystemLogger.error("Node " + nodeId + " broadcast prerequisites not met."); return; }
        try {
            String signature = CryptoUtil.signSHA256withRSA(msg, getPrivateKey()); if (signature == null) { SystemLogger.error("Node " + nodeId + " failed signing for broadcast."); return; }
            String cipher = CryptoUtil.encryptAES(msg, groupKey); if (cipher == null) { SystemLogger.error("Node " + nodeId + " failed encrypting for broadcast."); return; }
            networkManager.routeBroadcast(this.nodeId, signature, cipher);
        } catch (Exception e) { SystemLogger.error("Node " + nodeId + " error during broadcast prep: " + e.getMessage()); e.printStackTrace(); }
    }

    public void receiveMessage(String senderId, String signature, String cipher) {
        // 1. Basic checks & Trust Check
        if (senderId == null || signature == null || cipher == null) { SystemLogger.error(nodeId + ": Received invalid message components (sender=" + senderId + ")"); return; }
        if (!trustManager.isTrusted(senderId)) { SystemLogger.log(nodeId + ": Ignored message from untrusted node " + senderId + " (Score: " + String.format("%.1f", trustManager.getTrustScore(senderId)) + ")"); return; }
        if (groupKey == null || identityChain == null || caPublicKey == null) { SystemLogger.error(nodeId + ": Cannot process message from " + senderId + ": Missing prerequisites."); return; }
        SystemLogger.log(nodeId + ": Received message from trusted sender " + senderId + ". Verifying...");

        // 2. Get Sender Certificate
        DigitalCertificate senderCertWrapper = identityChain.getCertificateForNode(senderId);
        if (senderCertWrapper == null || senderCertWrapper.getX509Certificate() == null) { SystemLogger.error(nodeId + ": Could not find certificate for sender " + senderId + ". Ignoring."); return; }
        X509Certificate senderCert = senderCertWrapper.getX509Certificate();

        // 3. Verify Sender Certificate
        try { senderCert.verify(caPublicKey); senderCert.checkValidity(); }
        catch (Exception e) { SystemLogger.error(nodeId + ": Sender certificate verification failed for " + senderId + ". Reason: " + e.getMessage() + ". Ignoring."); trustManager.recordInvalidCertificate(senderId); return; }

        // 4. Check CRL
        if (currentCRL != null) {
            if (currentCRL.isRevoked(senderCert)) {
                X509CRLEntry revokedEntry = currentCRL.getRevokedCertificate(senderCert); String revocationDateStr = (revokedEntry != null) ? revokedEntry.getRevocationDate().toString() : "N/A";
                SystemLogger.error(nodeId + ": !!! CERTIFICATE REVOKED for sender " + senderId + " (Serial: " + senderCert.getSerialNumber().toString(16) + ", Revoked on: " + revocationDateStr + "). Ignoring. !!!");
                trustManager.recordRevokedCertificate(senderId); return;
            }
        } else { SystemLogger.error(nodeId + ": Warning - No CRL available for sender " + senderId); }

        // 5. Decrypt Message
        String plain = CryptoUtil.decryptAES(cipher, groupKey);
        if (plain == null) { SystemLogger.error(nodeId + ": Failed to decrypt message from " + senderId + ". Ignoring."); trustManager.recordDecryptionFailure(senderId); return; }

        // 6. Verify Signature
        PublicKey senderPubKey = senderCert.getPublicKey();
        if (!CryptoUtil.verifySHA256withRSA(plain, signature, senderPubKey)) { SystemLogger.error(nodeId + ": !!! INVALID SIGNATURE on message from " + senderId + ". Ignoring. !!!"); trustManager.recordInvalidSignature(senderId); return; }

        // 7. Process Valid Message & Increase Trust
        SystemLogger.log(nodeId + ": Received VALID message from " + senderId + ": " + plain);
        trustManager.recordValidMessage(senderId);
        // Add message handling logic here
        // 在此处添加消息处理逻辑
    }
}