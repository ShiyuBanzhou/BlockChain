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
 * Includes enhanced node discovery logic distinguishing seed nodes.
 * 模拟区块链网络中的节点。
 * 包括区分种子节点的增强节点发现逻辑。
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
    private NetworkService networkService;
    private boolean joinedNetwork = false;

    /**
     * Constructor for Node. Node is not registered with NetworkManager here.
     * 节点的构造函数。节点此时尚未在 NetworkManager 中注册。
     * @param nodeId        Unique identifier for the node. 节点的唯一标识符。
     * @param idChain       Reference to the identity blockchain. 对身份区块链的引用。
     * @param voteChain     Reference to the voting blockchain. 对投票区块链的引用。
     * @param caPublicKey   The public key of the trusted CA. 受信任 CA 的公钥。
     * @param networkService Reference to the network service implementation. 对网络服务实现的引用。
     */
    public Node(String nodeId, IdentityBlockchain idChain, VotingBlockchain voteChain,
                PublicKey caPublicKey, NetworkService networkService) {
        this.nodeId = nodeId;
        this.identityChain = idChain;
        this.votingChain = voteChain;
        this.caPublicKey = caPublicKey;
        this.networkService = networkService;
        this.rsaKeyPair = KeyUtil.generateRSAKeyPair();
        this.trustManager = new TrustManager(nodeId);
        if (this.rsaKeyPair == null) {
            throw new RuntimeException("Failed to generate RSA key pair for node " + nodeId);
        }
        if (this.networkService != null) {
            this.networkService.setMessageReceiver(this);
        }
        SystemLogger.log("节点 " + nodeId + " 已创建 (尚未加入网络)。");
    }

    /**
     * Simulates the process of joining the network.
     * Registers with the NetworkService and discovers initial peers based on seed node status.
     * 模拟加入网络的过程。
     * 向 NetworkService 注册并根据种子节点状态发现初始对等节点。
     * @param seedNodeIds A set of known seed node IDs. Should contain this node's ID if it's a seed.
     * 一个已知种子节点 ID 的集合。如果此节点是种子节点，则应包含其 ID。
     */
    public void joinNetwork(Set<String> seedNodeIds) {
        if (joinedNetwork) {
            SystemLogger.log("节点 " + nodeId + " 已加入网络。");
            return;
        }
        if (networkService == null) {
            SystemLogger.error("节点 " + nodeId + " 无法加入网络：NetworkService 未设置。");
            return;
        }

        boolean isSeed = seedNodeIds != null && seedNodeIds.contains(this.nodeId);
        SystemLogger.log("节点 " + nodeId + " 正在尝试加入网络... (是否种子节点: " + isSeed + ")");

        // 1. Register self with the NetworkService
        // 1. 向 NetworkService 注册自己
        // Registration should happen regardless of seed status
        // 无论种子状态如何都应进行注册
        networkService.registerNode(this);

        // 2. Discover peers
        // 2. 发现对等节点
        // In a real P2P system:
        // - If seed: Might wait for connections or actively ping known peers.
        // - If not seed: Would contact seeds from the seedNodeIds list.
        // In our simulation:
        // - We query the NetworkService, which has global knowledge.
        // - We log the *intent* based on seed status.
        // 在真实的 P2P 系统中：
        // - 如果是种子节点：可能会等待连接或主动 ping 已知对等节点。
        // - 如果不是种子节点：将联系 seedNodeIds 列表中的种子节点。
        // 在我们的模拟中：
        // - 我们查询具有全局知识的 NetworkService。
        // - 我们根据种子状态记录 *意图*。

        int maxPeersToDiscover = 5; // How many peers to request 期望请求多少对等节点
        List<String> discoveredPeerIds = null;

        if (isSeed) {
            // Seed node logic: Discover only if others might exist
            // 种子节点逻辑：仅当可能存在其他节点时才发现
            // We check if *any* other nodes are registered *before* us joining,
            // but since registration happens just before this check, we check total size > 1.
            // 我们检查在我们加入*之前*是否有*任何*其他节点已注册，
            // 但由于注册发生在此检查之前，我们检查总大小是否 > 1。
            if (networkService.getAllNodeIds().size() > 1) {
                SystemLogger.log("节点 " + nodeId + " (种子节点) 正在发现现有对等节点...");
                discoveredPeerIds = networkService.discoverPeers(this.nodeId, maxPeersToDiscover);
            } else {
                SystemLogger.log("节点 " + nodeId + " (种子节点) 是网络中的第一个节点，跳过发现。");
            }
        } else {
            // Non-seed node logic: Always try to discover from the network (simulating contacting seeds)
            // 非种子节点逻辑：始终尝试从网络发现（模拟联系种子节点）
            SystemLogger.log("节点 " + nodeId + " (非种子节点) 正在通过 NetworkService 发现对等节点 (模拟联系种子)...");
            discoveredPeerIds = networkService.discoverPeers(this.nodeId, maxPeersToDiscover);
        }

        // Log discovered peers if any
        // 如果有，记录发现的对等节点
        if (discoveredPeerIds != null && !discoveredPeerIds.isEmpty()) {
            SystemLogger.log("节点 " + nodeId + " 发现了 " + discoveredPeerIds.size() + " 个对等节点: " + discoveredPeerIds);
            // TODO: Future enhancement - Store and use this peer list
            // TODO: 未来增强 - 存储并使用此对等节点列表
        } else if (!isSeed || networkService.getAllNodeIds().size() > 1) {
            // Log if non-seed or seed (but not first) found no peers
            // 如果非种子节点或种子节点（但不是第一个）未找到对等节点，则记录日志
            SystemLogger.log("节点 " + nodeId + " 未发现其他对等节点。");
        }

        // 3. Mark as joined and potentially announce presence
        // 3. 标记为已加入并可能宣告存在
        this.joinedNetwork = true;
        SystemLogger.log("节点 " + nodeId + " 已成功加入网络。");

        // Optional: Broadcast a "hello" or "join" message
        // 可选：广播 "hello" 或 "join" 消息
        // Only broadcast join if not the very first node
        // 仅当不是第一个节点时才广播加入消息
        if (networkService.getAllNodeIds().size() > 1) {
            broadcast("JOIN: Node " + nodeId + " is online.");
        }
    }

    // --- Getters and Key Management ---
    public String getId() { return nodeId; }
    public PublicKey getPublicKey() { return rsaKeyPair.getPublic(); }
    private PrivateKey getPrivateKey() { return rsaKeyPair.getPrivate(); }
    public PublicKey getCaPublicKey() { return caPublicKey; }
    public TrustManager getTrustManager() { return trustManager; }
    public void updateCRL(X509CRL newCRL) { /* ... unchanged ... */
        if (newCRL != null) { try { newCRL.verify(this.caPublicKey); this.currentCRL = newCRL; } catch (Exception e) { SystemLogger.error("Node " + nodeId + ": Received invalid CRL. Ignoring."); e.printStackTrace(); } } else { SystemLogger.error("Node " + nodeId + ": Received null CRL."); } }
    public void receiveGroupKey(String encKey) { /* ... unchanged ... */
        try { this.groupKey = GroupCommUtil.decryptGroupKey(encKey, getPrivateKey()); if (this.groupKey == null) { SystemLogger.error("Node " + nodeId + " failed to decrypt group key."); } } catch (Exception e) { SystemLogger.error("Error receiving group key for node " + nodeId + ": " + e.getMessage()); e.printStackTrace(); } }

    // --- Communication Methods ---
    public void broadcast(String msg) {
        if (!joinedNetwork) { SystemLogger.error("节点 " + nodeId + " 无法广播：尚未加入网络。"); return; }
        if (networkService == null || groupKey == null || msg == null) { SystemLogger.error("Node " + nodeId + " broadcast prerequisites not met."); return; }
        try {
            String signature = CryptoUtil.signSHA256withRSA(msg, getPrivateKey()); if (signature == null) { SystemLogger.error("Node " + nodeId + " failed signing for broadcast."); return; }
            String cipher = CryptoUtil.encryptAES(msg, groupKey); if (cipher == null) { SystemLogger.error("Node " + nodeId + " failed encrypting for broadcast."); return; }
            NetworkMessage netMsg = new BasicNetworkMessage(this.nodeId, signature, cipher, "GROUP_MSG");
            // SystemLogger.log("节点 " + nodeId + ": 准备广播消息: " + netMsg.getMessageType()); // Reduce noise 减少噪音
            networkService.broadcast(netMsg);
        } catch (Exception e) { SystemLogger.error("Node " + nodeId + " error during broadcast prep: " + e.getMessage()); e.printStackTrace(); }
    }

    public void receiveMessage(String senderId, String signature, String cipher) {
        // --- Logic remains the same ---
        // --- 逻辑保持不变 ---
        if (senderId == null || signature == null || cipher == null) { SystemLogger.error(nodeId + ": Received invalid message components (sender=" + senderId + ")"); return; }
        if (!trustManager.isTrusted(senderId)) { SystemLogger.log(nodeId + ": Ignored message from untrusted node " + senderId + " (Score: " + String.format("%.1f", trustManager.getTrustScore(senderId)) + ")"); return; }
        if (groupKey == null || identityChain == null || caPublicKey == null) { SystemLogger.error(nodeId + ": Cannot process message from " + senderId + ": Missing prerequisites."); return; }
        // SystemLogger.log(nodeId + ": Received message from trusted sender " + senderId + ". Verifying..."); // Reduce noise 减少噪音

        DigitalCertificate senderCertWrapper = identityChain.getCertificateForNode(senderId);
        if (senderCertWrapper == null || senderCertWrapper.getX509Certificate() == null) { SystemLogger.error(nodeId + ": Could not find certificate for sender " + senderId + ". Ignoring."); return; }
        X509Certificate senderCert = senderCertWrapper.getX509Certificate();

        try { senderCert.verify(caPublicKey); senderCert.checkValidity(); }
        catch (Exception e) { SystemLogger.error(nodeId + ": Sender certificate verification failed for " + senderId + ". Reason: " + e.getMessage() + ". Ignoring."); trustManager.recordInvalidCertificate(senderId); return; }

        if (currentCRL != null) {
            if (currentCRL.isRevoked(senderCert)) {
                X509CRLEntry revokedEntry = currentCRL.getRevokedCertificate(senderCert); String revocationDateStr = (revokedEntry != null) ? revokedEntry.getRevocationDate().toString() : "N/A";
                SystemLogger.error(nodeId + ": !!! CERTIFICATE REVOKED for sender " + senderId + " (Serial: " + senderCert.getSerialNumber().toString(16) + ", Revoked on: " + revocationDateStr + "). Ignoring. !!!");
                trustManager.recordRevokedCertificate(senderId); return;
            }
        } else { SystemLogger.error(nodeId + ": Warning - No CRL available for sender " + senderId); }

        String plain = CryptoUtil.decryptAES(cipher, groupKey);
        if (plain == null) { SystemLogger.error(nodeId + ": Failed to decrypt message from " + senderId + ". Ignoring."); trustManager.recordDecryptionFailure(senderId); return; }

        PublicKey senderPubKey = senderCert.getPublicKey();
        if (!CryptoUtil.verifySHA256withRSA(plain, signature, senderPubKey)) { SystemLogger.error(nodeId + ": !!! INVALID SIGNATURE on message from " + senderId + ". Ignoring. !!!"); trustManager.recordInvalidSignature(senderId); return; }

        SystemLogger.log(nodeId + ": Received VALID message from " + senderId + ": " + plain);
        trustManager.recordValidMessage(senderId);
        // Add message handling logic here
        // 在此处添加消息处理逻辑
    }
}