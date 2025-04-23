package com.example.voting.trust;

import com.example.voting.SystemLogger; // Import SystemLogger
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Manages dynamic trust scores for network nodes.
 * Scores are adjusted based on observed behavior.
 * 管理网络节点的动态信任分数。
 * 分数根据观察到的行为进行调整。
 */
public class TrustManager {

    // --- Constants for Trust Score Management ---
    // --- 信任分数管理常量 ---
    private static final double INITIAL_TRUST_SCORE = 50.0; // Starting score for unknown nodes 未知节点的起始分数
    private static final double MAX_TRUST_SCORE = 100.0; // Maximum possible score 最高可能分数
    private static final double MIN_TRUST_SCORE = 0.0;   // Minimum possible score 最低可能分数
    private static final double TRUST_THRESHOLD_ACCEPT = 30.0; // Minimum score to accept messages 接受消息的最低分数
    private static final double TRUST_THRESHOLD_WARN = 15.0; // Score below which warnings are severe 低于此分数则警告严重

    // Score adjustments for specific events 特定事件的分数调整
    private static final double SCORE_INCREMENT_VALID_MSG = 1.0;   // Successful message verification 成功消息验证
    private static final double SCORE_DECREMENT_INVALID_SIG = -15.0; // Invalid signature 无效签名
    private static final double SCORE_DECREMENT_REVOKED_CERT = -25.0; // Using revoked certificate 使用已吊销证书
    private static final double SCORE_DECREMENT_INVALID_CERT = -10.0; // Invalid certificate (expired, bad signature) 无效证书（过期、签名错误）
    private static final double SCORE_DECREMENT_DECRYPT_FAIL = -5.0;  // Decryption failure (might indicate key issue) 解密失败（可能表示密钥问题）

    // Map storing trust scores for known node IDs
    // 存储已知节点 ID 信任分数的 Map
    private final Map<String, Double> trustScores = new ConcurrentHashMap<>();
    private final String ownerNodeId; // ID of the node owning this manager 拥有此管理器的节点的 ID

    /**
     * Constructor for TrustManager.
     * TrustManager 的构造函数。
     * @param ownerNodeId The ID of the node this manager belongs to. 此管理器所属节点的 ID。
     */
    public TrustManager(String ownerNodeId) {
        this.ownerNodeId = ownerNodeId;
        SystemLogger.log("TrustManager initialized for node " + ownerNodeId);
    }

    /**
     * Gets the current trust score for a given node.
     * Returns the initial score if the node is unknown.
     * 获取给定节点的当前信任分数。
     * 如果节点未知，则返回初始分数。
     * @param nodeId The ID of the node to query. 要查询的节点的 ID。
     * @return The trust score (between MIN and MAX). 信任分数（介于 MIN 和 MAX 之间）。
     */
    public double getTrustScore(String nodeId) {
        // Return initial score for nodes not yet encountered
        // 对于尚未遇到的节点返回初始分数
        return trustScores.getOrDefault(nodeId, INITIAL_TRUST_SCORE);
    }

    /**
     * Increases the trust score for a node, capped at MAX_TRUST_SCORE.
     * 增加节点的信任分数，上限为 MAX_TRUST_SCORE。
     * @param nodeId The ID of the node. 节点的 ID。
     * @param amount The positive amount to increase the score by. 分数增加的正数数量。
     */
    public void increaseTrust(String nodeId, double amount) {
        if (amount <= 0) return; // Only positive increases 只允许正数增加
        double currentScore = getTrustScore(nodeId);
        double newScore = Math.min(currentScore + amount, MAX_TRUST_SCORE); // Apply ceiling 应用上限
        trustScores.put(nodeId, newScore);
        SystemLogger.log("TrustManager (" + ownerNodeId + "): Increased trust for " + nodeId + " by " + String.format("%.1f", amount) + ". New score: " + String.format("%.1f", newScore));
    }

    /**
     * Decreases the trust score for a node, floored at MIN_TRUST_SCORE.
     * 降低节点的信任分数，下限为 MIN_TRUST_SCORE。
     * @param nodeId The ID of the node. 节点的 ID。
     * @param amount The positive amount to decrease the score by (will be made negative). 分数减少的正数数量（将变为负数）。
     */
    public void decreaseTrust(String nodeId, double amount) {
        if (amount >= 0) return; // Ensure amount is negative for decrease 确保减少量为负数
        double currentScore = getTrustScore(nodeId);
        double newScore = Math.max(currentScore + amount, MIN_TRUST_SCORE); // Apply floor 应用下限
        trustScores.put(nodeId, newScore);
        SystemLogger.log("TrustManager (" + ownerNodeId + "): Decreased trust for " + nodeId + " by " + String.format("%.1f", amount) + ". New score: " + String.format("%.1f", newScore));

        // Log severe warnings if score drops very low
        // 如果分数降得非常低，则记录严重警告
        if (newScore < TRUST_THRESHOLD_WARN) {
            SystemLogger.error("TrustManager (" + ownerNodeId + "): SEVERE WARNING - Trust score for " + nodeId + " is critically low (" + String.format("%.1f", newScore) + ")!");
        }
    }

    /**
     * Checks if a node's trust score meets a minimum threshold.
     * 检查节点的信任分数是否达到最低阈值。
     * @param nodeId The ID of the node to check. 要检查的节点的 ID。
     * @param threshold The minimum score required. 所需的最低分数。
     * @return true if the node's score is >= threshold, false otherwise. 如果节点的分数 >= 阈值，则返回 true，否则返回 false。
     */
    public boolean isTrusted(String nodeId, double threshold) {
        return getTrustScore(nodeId) >= threshold;
    }

    /**
     * Checks if a node is considered generally trustworthy for interaction.
     * Uses the default TRUST_THRESHOLD_ACCEPT.
     * 检查节点是否被认为通常值得信赖以进行交互。
     * 使用默认的 TRUST_THRESHOLD_ACCEPT。
     * @param nodeId The ID of the node to check. 要检查的节点的 ID。
     * @return true if the node is trusted, false otherwise. 如果节点受信任则返回 true，否则返回 false。
     */
    public boolean isTrusted(String nodeId) {
        return isTrusted(nodeId, TRUST_THRESHOLD_ACCEPT);
    }

    // --- Convenience methods for specific events ---
    // --- 特定事件的便捷方法 ---

    public void recordValidMessage(String nodeId) {
        increaseTrust(nodeId, SCORE_INCREMENT_VALID_MSG);
    }

    public void recordInvalidSignature(String nodeId) {
        decreaseTrust(nodeId, SCORE_DECREMENT_INVALID_SIG);
    }

    public void recordRevokedCertificate(String nodeId) {
        decreaseTrust(nodeId, SCORE_DECREMENT_REVOKED_CERT);
    }

    public void recordInvalidCertificate(String nodeId) {
        decreaseTrust(nodeId, SCORE_DECREMENT_INVALID_CERT);
    }

    public void recordDecryptionFailure(String nodeId) {
        decreaseTrust(nodeId, SCORE_DECREMENT_DECRYPT_FAIL);
    }

}