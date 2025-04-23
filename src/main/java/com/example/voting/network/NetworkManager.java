package com.example.voting.network;

import com.example.voting.SystemLogger; // Import SystemLogger
import java.util.ArrayList;
import java.util.Collections; // Import Collections
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Manages the simulated network environment.
 * Handles node registration, message routing, and peer discovery.
 * 管理模拟的网络环境。
 * 处理节点注册、消息路由和对等节点发现。
 */
public class NetworkManager {

    private final Map<String, Node> registeredNodes = new ConcurrentHashMap<>();

    /**
     * Registers a node with the network manager.
     * 向网络管理器注册一个节点。
     * @param node The node to register. 要注册的节点。
     */
    public void registerNode(Node node) {
        if (node != null && node.getId() != null) {
            if (registeredNodes.putIfAbsent(node.getId(), node) == null) {
                SystemLogger.log("NetworkManager: 节点已注册 - " + node.getId());
            } else {
                // Node already registered, log as info
                // 节点已注册，记录为信息
                // SystemLogger.log("NetworkManager: Node " + node.getId() + " already registered.");
            }
        } else {
            SystemLogger.error("NetworkManager: 尝试注册无效节点。");
        }
    }

    /**
     * Unregisters a node from the network manager.
     * 从网络管理器注销一个节点。
     * @param nodeId The ID of the node to unregister. 要注销的节点的 ID。
     */
    public void unregisterNode(String nodeId) {
        if (nodeId != null) {
            Node removedNode = registeredNodes.remove(nodeId);
            if (removedNode != null) {
                SystemLogger.log("NetworkManager: 节点已注销 - " + nodeId);
            }
        }
    }

    /**
     * Gets a list of all currently registered node IDs.
     * 获取当前所有已注册节点的 ID 列表。
     * @return A list of node IDs. 节点 ID 列表。
     */
    public List<String> getAllNodeIds() {
        return new ArrayList<>(registeredNodes.keySet());
    }

    /**
     * Gets a list of all currently registered Node objects (excluding the requester).
     * 获取当前所有已注册 Node 对象的列表（不包括请求者）。
     * @param requesterId The ID of the node requesting the list, to exclude itself. 请求列表的节点的 ID，用于排除自身。
     * @return A list of other Node objects. 其他 Node 对象的列表。
     */
    public List<Node> getPeers(String requesterId) {
        return registeredNodes.values().stream()
                .filter(node -> !node.getId().equals(requesterId))
                .collect(Collectors.toList());
    }

    /**
     * Retrieves a specific node by its ID.
     * 根据 ID 检索特定节点。
     * @param nodeId The ID of the node to retrieve. 要检索的节点的 ID。
     * @return The Node object if found, otherwise null. 如果找到则返回 Node 对象，否则返回 null。
     */
    public Node getNodeById(String nodeId) {
        return registeredNodes.get(nodeId);
    }

    /**
     * Returns a list of random peer IDs, excluding the requester.
     * 返回随机对等节点 ID 的列表，不包括请求者。
     * @param requesterId The ID of the node requesting peers. 请求对等节点的节点的 ID。
     * @param count The maximum number of peer IDs to return. 要返回的最大对等节点 ID 数。
     * @return A list of random peer node IDs. 随机对等节点 ID 的列表。
     */
    public List<String> getRandomPeerIds(String requesterId, int count) {
        // Get all node IDs except the requester
        // 获取除请求者之外的所有节点 ID
        List<String> potentialPeers = registeredNodes.keySet().stream()
                .filter(id -> !id.equals(requesterId))
                .collect(Collectors.toList());

        // Shuffle the list
        // 打乱列表顺序
        Collections.shuffle(potentialPeers);

        // Return the requested number of peers (or fewer if not enough exist)
        // 返回请求数量的对等节点（如果数量不足则返回更少）
        return potentialPeers.stream()
                .limit(count)
                .collect(Collectors.toList());
    }


    /**
     * Routes a broadcast message from a sender to all other registered nodes.
     * 将来自发送者的广播消息路由到所有其他已注册节点。
     * @param senderId The ID of the sending node. 发送方节点的 ID。
     * @param signature The signature of the original message. 原始消息的签名。
     * @param cipher The encrypted message content. 加密的消息内容。
     */
    public void routeBroadcast(String senderId, String signature, String cipher) {
        Node sender = registeredNodes.get(senderId);
        if (sender == null) {
            SystemLogger.error("NetworkManager: 无法路由来自未知发送者的广播: " + senderId);
            return;
        }

        int deliveryCount = 0;
        for (Node recipient : registeredNodes.values()) {
            if (!recipient.getId().equals(senderId)) {
                try {
                    // Simulate delivery
                    // 模拟传递
                    recipient.receiveMessage(senderId, signature, cipher);
                    deliveryCount++;
                } catch (Exception e) {
                    SystemLogger.error("NetworkManager: 传递消息从 " + senderId + " 到 " + recipient.getId() + " 时出错: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
        // SystemLogger.log("NetworkManager: Broadcast from " + senderId + " delivered to " + deliveryCount + " peers."); // Reduce noise 减少噪音
    }
}