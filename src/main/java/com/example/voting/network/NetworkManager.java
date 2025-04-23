package com.example.voting.network;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Manages the simulated network environment.
 * Handles node registration and message routing.
 * 管理模拟的网络环境。
 * 处理节点注册和消息路由。
 */
public class NetworkManager {

    // A map to store registered nodes, keyed by their nodeId
    // 用于存储已注册节点的 Map，以 nodeId 作为键
    private final Map<String, Node> registeredNodes = new ConcurrentHashMap<>();

    /**
     * Registers a node with the network manager.
     * 向网络管理器注册一个节点。
     * @param node The node to register. 要注册的节点。
     */
    public void registerNode(Node node) {
        if (node != null && node.getId() != null) {
            // Check if node already registered to avoid duplicate messages
            // 检查节点是否已注册以避免重复消息
            if (registeredNodes.putIfAbsent(node.getId(), node) == null) {
                System.out.println("NetworkManager: Node registered - " + node.getId());
            } else {
                System.out.println("NetworkManager: Node " + node.getId() + " already registered.");
            }
        } else {
            System.err.println("NetworkManager: Attempted to register an invalid node.");
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
                System.out.println("NetworkManager: Node unregistered - " + nodeId);
            }
        }
    }

    /**
     * Gets a list of all currently registered node IDs.
     * 获取当前所有已注册节点的 ID 列表。
     * @return A list of node IDs. 节点 ID 列表。
     */
    public List<String> getAllNodeIds() {
        // Return a new list to prevent modification of the internal keyset view
        // 返回一个新列表以防止修改内部键集视图
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
                .collect(Collectors.toList()); // Collect into a new list 收集到一个新列表中
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
     * Routes a broadcast message from a sender to all other registered nodes.
     * 将来自发送者的广播消息路由到所有其他已注册节点。
     * Simulates network delivery.
     * 模拟网络传递。
     * @param senderId The ID of the sending node. 发送方节点的 ID。
     * @param signature The signature of the original message. 原始消息的签名。
     * @param cipher The encrypted message content. 加密的消息内容。
     */
    public void routeBroadcast(String senderId, String signature, String cipher) {
        Node sender = registeredNodes.get(senderId);
        if (sender == null) {
            System.err.println("NetworkManager: Cannot route broadcast from unknown sender: " + senderId);
            return;
        }

        // System.out.println("NetworkManager: Routing broadcast from " + senderId + "..."); // Reduce verbosity 减少冗余输出
        int deliveryCount = 0;
        for (Node recipient : registeredNodes.values()) {
            // Don't send back to the original sender
            // 不要发送回原始发送者
            if (!recipient.getId().equals(senderId)) {
                // Simulate delivery by calling the recipient's receive method
                // 通过调用接收者的接收方法来模拟传递
                // System.out.println("NetworkManager: Delivering message from " + senderId + " to " + recipient.getId()); // Reduce verbosity 减少冗余输出
                // Introduce potential delay or message loss simulation here later
                // 稍后在此处引入潜在的延迟或消息丢失模拟
                try {
                    recipient.receiveMessage(senderId, signature, cipher);
                    deliveryCount++;
                } catch (Exception e) {
                    // Catch potential errors during message processing at the recipient
                    // 捕获接收方消息处理期间的潜在错误
                    System.err.println("NetworkManager: Error delivering message from " + senderId + " to " + recipient.getId() + ": " + e.getMessage());
                    e.printStackTrace(); // Log stack trace for debugging 记录堆栈跟踪以进行调试
                }
            }
        }
        // System.out.println("NetworkManager: Broadcast from " + senderId + " delivered to " + deliveryCount + " peers."); // Reduce verbosity 减少冗余输出
    }

    // TODO: Add methods for unicast (point-to-point) message routing if needed
    // TODO: 如果需要，添加用于单播（点对点）消息路由的方法
}