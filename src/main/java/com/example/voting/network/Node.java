package com.example.voting.network;

import com.example.voting.blockchain.*;
import com.example.voting.crypto.CryptoUtil;
import com.example.voting.trust.TrustManager;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.util.List;

/**
 * 模拟区块链网络节点
 */
public class Node {
    private String nodeId;
    private IdentityBlockchain identityChain;
    private VotingBlockchain votingChain;
    private KeyPair rsaKeyPair;      // 接收群组密钥用的 RSA 密钥对
    private SecretKey groupKey;      // 群组 AES 密钥
    private TrustManager trustManager;

    public Node(String nodeId, IdentityBlockchain idChain, VotingBlockchain voteChain) {
        this.nodeId = nodeId;
        this.identityChain = idChain;
        this.votingChain = voteChain;
        this.rsaKeyPair = GroupCommUtil.generateNodeKeyPair();
        this.trustManager = new TrustManager(nodeId);
    }

    public String getId() { return nodeId; }
    public java.security.PublicKey getPublicKey() { return rsaKeyPair.getPublic(); }

    /** 接收并解密群组密钥 */
    public void receiveGroupKey(String encKey) {
        this.groupKey = GroupCommUtil.decryptGroupKey(encKey, rsaKeyPair.getPrivate());
    }

    /** 加密广播消息给其他节点 */
    public void broadcast(String msg, List<Node> peers) {
        if (groupKey == null) return;
        String cipher = CryptoUtil.encryptAES(msg, groupKey);
        for (Node peer : peers) {
            if (!peer.getId().equals(this.nodeId)) {
                peer.receiveMessage(cipher, this);
            }
        }
    }

    /** 接收并解密消息 */
    public void receiveMessage(String cipher, Node sender) {
        if (trustManager.isBlacklisted(sender.getId())) return; // 跳过黑名单节点
        String plain = CryptoUtil.decryptAES(cipher, groupKey);
        System.out.println(nodeId + " 收到来自 " + sender.getId() + " 的消息: " + plain);
        // 可进一步解析区块或交易
    }
}
