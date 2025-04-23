package com.example.voting.network;

import com.example.voting.SystemLogger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Implements NetworkService for local, in-memory simulation.
 * Routes messages by directly calling methods on registered Node objects.
 * 为本地内存模拟实现 NetworkService。
 * 通过直接调用已注册 Node 对象上的方法来路由消息。
 */
public class LocalSimulationNetworkService implements NetworkService {

    private final Map<String, Node> registeredNodes = new ConcurrentHashMap<>();
    private Node messageReceiver = null; // Should only be one receiver (the node using this service) 应该只有一个接收者（使用此服务的节点）

    @Override
    public void start() {
        SystemLogger.log("LocalSimulationNetworkService: Started (no network setup needed).");
    }

    @Override
    public void stop() {
        SystemLogger.log("LocalSimulationNetworkService: Stopped.");
        registeredNodes.clear(); // Clear nodes on stop 在停止时清除节点
    }

    @Override
    public void registerNode(Node node) {
        if (node != null && node.getId() != null) {
            if (registeredNodes.putIfAbsent(node.getId(), node) == null) {
                SystemLogger.log("LocalSimNetwork: 节点已注册 - " + node.getId());
            }
        } else {
            SystemLogger.error("LocalSimNetwork: 尝试注册无效节点。");
        }
    }

    @Override
    public void unregisterNode(String nodeId) {
        if (nodeId != null) {
            if (registeredNodes.remove(nodeId) != null) {
                SystemLogger.log("LocalSimNetwork: 节点已注销 - " + nodeId);
            }
        }
    }

    @Override
    public Node getNodeById(String nodeId) {
        return registeredNodes.get(nodeId);
    }

    @Override
    public List<String> discoverPeers(String requesterId, int count) { // Renamed method 重命名方法
        // SystemLogger.log("LocalSimNetwork: Node " + requesterId + " discovering peers (max " + count + ")"); // Reduce noise 减少噪音
        List<String> potentialPeers = registeredNodes.keySet().stream()
                .filter(id -> !id.equals(requesterId))
                .collect(Collectors.toList());
        Collections.shuffle(potentialPeers);
        List<String> discovered = potentialPeers.stream().limit(count).collect(Collectors.toList());
        // SystemLogger.log("LocalSimNetwork: Peers discovered for " + requesterId + ": " + discovered); // Reduce noise 减少噪音
        return discovered;
    }

    @Override
    public void broadcast(NetworkMessage message) {
        String senderId = message.getSenderId();
        SystemLogger.log("LocalSimNetwork: 正在路由来自 " + senderId + " 的广播消息: " + message.getMessageType());
        int deliveryCount = 0;
        for (Node recipient : registeredNodes.values()) {
            if (!recipient.getId().equals(senderId)) {
                try {
                    // Simulate delivery by calling receive method directly
                    // 通过直接调用接收方法来模拟传递
                    SystemLogger.log("LocalSimNetwork: 正在将消息从 " + senderId + " 传递给 " + recipient.getId());
                    // Extract payload and signature for the Node's receiveMessage method signature
                    // 为 Node 的 receiveMessage 方法签名提取负载和签名
                    // This assumes the payload is the encrypted cipher and signature is separate
                    // 这假设负载是加密的密文，签名是分开的
                    // *** Adapt this if Node.receiveMessage signature changes ***
                    // *** 如果 Node.receiveMessage 签名更改，请调整此项 ***
                    if (message.getPayload() instanceof String && "GROUP_MSG".equals(message.getMessageType())) {
                        recipient.receiveMessage(senderId, message.getSignature(), (String)message.getPayload());
                        deliveryCount++;
                    } else {
                        SystemLogger.error("LocalSimNetwork: 无法传递非 GROUP_MSG 类型的广播或负载类型错误。");
                    }

                } catch (Exception e) {
                    SystemLogger.error("LocalSimNetwork: 传递消息从 " + senderId + " 到 " + recipient.getId() + " 时出错: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        }
        SystemLogger.log("LocalSimNetwork: 来自 " + senderId + " 的广播已传递给 " + deliveryCount + " 个对等节点。");
    }

    @Override
    public boolean sendMessage(String recipientId, NetworkMessage message) {
        SystemLogger.log("LocalSimNetwork: 正在尝试将单播消息从 " + message.getSenderId() + " 发送给 " + recipientId);
        Node recipient = registeredNodes.get(recipientId);
        if (recipient != null) {
            try {
                // Simulate direct delivery
                // 模拟直接传递
                if (message.getPayload() instanceof String && "GROUP_MSG".equals(message.getMessageType())) { // Assuming same format 假设格式相同
                    recipient.receiveMessage(message.getSenderId(), message.getSignature(), (String)message.getPayload());
                    SystemLogger.log("LocalSimNetwork: 单播消息已成功传递给 " + recipientId);
                    return true;
                } else {
                    SystemLogger.error("LocalSimNetwork: 无法传递非 GROUP_MSG 类型的单播或负载类型错误。");
                    return false;
                }
            } catch (Exception e) {
                SystemLogger.error("LocalSimNetwork: 传递单播消息给 " + recipientId + " 时出错: " + e.getMessage());
                e.printStackTrace();
                return false;
            }
        } else {
            SystemLogger.error("LocalSimNetwork: 找不到单播消息的接收者: " + recipientId);
            return false;
        }
    }

    @Override
    public void setMessageReceiver(Node handler) {
        // In local simulation, the 'handler' is typically the node itself,
        // and messages are delivered directly via receiveMessage.
        // This method might be more relevant for real network implementations
        // where a central listener thread needs to dispatch messages.
        // 在本地模拟中，“处理程序”通常是节点本身，
        // 消息通过 receiveMessage 直接传递。
        // 此方法可能与需要中央侦听器线程分派消息的真实网络实现更相关。
        SystemLogger.log("LocalSimNetwork: Message receiver set (not actively used in this implementation).");
        this.messageReceiver = handler;
    }
    @Override
    public List<String> getAllNodeIds() {
        // Return a new list to prevent modification of the internal keyset view
        // 返回一个新列表以防止修改内部键集视图
        return new ArrayList<>(registeredNodes.keySet());
    }


}