package com.example.voting.network;

import com.example.voting.blockchain.*;
import com.example.voting.crypto.CryptoUtil;
import com.example.voting.crypto.DigitalCertificate;
import com.example.voting.crypto.KeyUtil;
import com.example.voting.trust.TrustManager;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.security.cert.X509Certificate;
import java.util.List; // Keep for potential future use 保留以备将来使用

/**
 * Represents a node in the simulated blockchain network.
 * Interacts with the NetworkManager for communication.
 * 模拟区块链网络中的节点。
 * 通过 NetworkManager 进行通信交互。
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
    private NetworkManager networkManager; // Reference to the network manager 对网络管理器的引用

    /**
     * Constructor for Node.
     * 节点的构造函数。
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
        this.networkManager = networkManager; // Store network manager reference 存储网络管理器引用
        this.rsaKeyPair = KeyUtil.generateRSAKeyPair();
        this.trustManager = new TrustManager(nodeId);
        if (this.rsaKeyPair == null) {
            throw new RuntimeException("Failed to generate RSA key pair for node " + nodeId);
        }
        // Register with the network manager after initialization
        // 初始化后向网络管理器注册
        if (this.networkManager != null) {
            this.networkManager.registerNode(this);
        } else {
            System.err.println("Warning: Node " + nodeId + " initialized without a NetworkManager!");
        }
        // System.out.println("Node " + nodeId + " initialized and registered with NetworkManager."); // Moved registration log to NetworkManager 移动注册日志到 NetworkManager
    }

    // --- Getters and Key Management ---
    // --- Getter 和密钥管理 ---
    public String getId() { return nodeId; }
    public PublicKey getPublicKey() { return rsaKeyPair.getPublic(); }
    private PrivateKey getPrivateKey() { return rsaKeyPair.getPrivate(); }
    public PublicKey getCaPublicKey() { return caPublicKey; }

    public void updateCRL(X509CRL newCRL) {
        if (newCRL != null) {
            try {
                newCRL.verify(this.caPublicKey);
                this.currentCRL = newCRL;
                // System.out.println("Node " + nodeId + ": Updated CRL. Issuer: [" + newCRL.getIssuerX500Principal() + "], Next update: " + newCRL.getNextUpdate()); // Reduce verbosity 减少冗余输出
            } catch (Exception e) {
                System.err.println("Node " + nodeId + ": Received invalid CRL - signature verification failed. Ignoring CRL.");
                e.printStackTrace();
            }
        } else {
            System.err.println("Node " + nodeId + ": Received null CRL during update attempt.");
        }
    }

    public void receiveGroupKey(String encKey) {
        try {
            this.groupKey = GroupCommUtil.decryptGroupKey(encKey, getPrivateKey());
            if (this.groupKey == null) {
                System.err.println("Node " + nodeId + " failed to decrypt group key.");
            }
        } catch (Exception e) {
            System.err.println("Error receiving group key for node " + nodeId + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    // --- Communication Methods ---
    // --- 通信方法 ---

    /**
     * Sends a message for broadcast via the NetworkManager.
     * 通过 NetworkManager 发送广播消息。
     * Signs and encrypts the message before sending.
     * 发送前对消息进行签名和加密。
     * @param msg The plaintext message to broadcast. 要广播的明文消息。
     */
    public void broadcast(String msg) {
        if (networkManager == null) {
            System.err.println("Node " + nodeId + " cannot broadcast: NetworkManager not set.");
            return;
        }
        if (groupKey == null) {
            System.err.println("Node " + nodeId + " cannot broadcast: Group key not set.");
            return;
        }
        if (msg == null) {
            System.err.println("Node " + nodeId + " cannot broadcast: Message is null.");
            return;
        }

        try {
            // 1. Sign the original plaintext message
            // 1. 对原始明文消息进行签名
            String signature = CryptoUtil.signSHA256withRSA(msg, getPrivateKey());
            if (signature == null) {
                System.err.println("Node " + nodeId + " failed to sign the message for broadcast.");
                return;
            }

            // 2. Encrypt the original plaintext message
            // 2. 加密原始明文消息
            String cipher = CryptoUtil.encryptAES(msg, groupKey);
            if (cipher == null) {
                System.err.println("Node " + nodeId + " failed to encrypt the message for broadcast.");
                return;
            }

            // 3. Send to NetworkManager for routing
            // 3. 发送给 NetworkManager 进行路由
            // System.out.println("Node " + nodeId + ": Sending broadcast request to NetworkManager."); // Reduce verbosity 减少冗余输出
            networkManager.routeBroadcast(this.nodeId, signature, cipher);

        } catch (Exception e) {
            System.err.println("Node " + nodeId + " encountered an error preparing broadcast: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Receives a message delivered by the NetworkManager.
     * 接收由 NetworkManager 传递的消息。
     * Verifies sender's certificate (including CRL check), decrypts, and verifies signature.
     * 验证发送方的证书（包括 CRL 检查）、解密并验证签名。
     * @param senderId The ID (CN) of the sending node. 发送方节点的 ID (CN)。
     * @param signature The signature of the original plaintext message (Base64 encoded). 原始明文消息的签名（Base64 编码）。
     * @param cipher The encrypted message (Base64 encoded). 加密消息（Base64 编码）。
     */
    public void receiveMessage(String senderId, String signature, String cipher) {
        // 1. Basic checks & Trust
        // 1. 基本检查和信任
        if (senderId == null || signature == null || cipher == null) {
            System.err.println(nodeId + ": Received invalid message components from NetworkManager (sender=" + senderId + ")");
            return;
        }
        if (trustManager.isBlacklisted(senderId)) {
            return; // Silently ignore blacklisted nodes 静默忽略黑名单节点
        }
        if (groupKey == null || identityChain == null || caPublicKey == null) {
            System.err.println(nodeId + ": Cannot process message from " + senderId + ": Missing prerequisites (groupKey/idChain/caKey).");
            return;
        }

        // 2. Get Sender Certificate
        // 2. 获取发送者证书
        DigitalCertificate senderCertWrapper = identityChain.getCertificateForNode(senderId);
        if (senderCertWrapper == null || senderCertWrapper.getX509Certificate() == null) {
            System.err.println(nodeId + ": Could not find certificate for sender " + senderId + ". Ignoring message.");
            return;
        }
        X509Certificate senderCert = senderCertWrapper.getX509Certificate();

        // 3. Verify Sender Certificate (Signature & Validity)
        // 3. 验证发送者证书（签名和有效期）
        try {
            senderCert.verify(caPublicKey);
            senderCert.checkValidity();
        } catch (Exception e) {
            System.err.println(nodeId + ": Sender certificate verification failed for " + senderId + ". Reason: " + e.getMessage() + ". Ignoring message.");
            return;
        }

        // 4. Check Certificate against CRL
        // 4. 对照 CRL 检查证书
        if (currentCRL != null) {
            if (currentCRL.isRevoked(senderCert)) {
                X509CRLEntry revokedEntry = currentCRL.getRevokedCertificate(senderCert);
                String revocationDateStr = (revokedEntry != null) ? revokedEntry.getRevocationDate().toString() : "N/A";
                System.err.println(nodeId + ": !!! CERTIFICATE REVOKED for sender " + senderId +
                        " (Serial: " + senderCert.getSerialNumber().toString(16) +
                        ", Revoked on: " + revocationDateStr +
                        "). Ignoring message. !!!");
                return;
            }
        } else {
            System.err.println(nodeId + ": Warning - No CRL available to check revocation status for sender " + senderId);
        }

        // 5. Decrypt Message
        // 5. 解密消息
        String plain = CryptoUtil.decryptAES(cipher, groupKey);
        if (plain == null) {
            System.err.println(nodeId + ": Failed to decrypt message from " + senderId + ". Ignoring.");
            return;
        }

        // 6. Verify Signature
        // 6. 验证签名
        PublicKey senderPubKey = senderCert.getPublicKey();
        if (!CryptoUtil.verifySHA256withRSA(plain, signature, senderPubKey)) {
            System.err.println(nodeId + ": !!! INVALID SIGNATURE on message from " + senderId + ". Ignoring message. !!!");
            return;
        }

        // 7. Process Valid Message
        // 7. 处理有效消息
        System.out.println(nodeId + ": Received VALID message from " + senderId + ": " + plain);
        // Add message handling logic here
        // 在此处添加消息处理逻辑
    }
}