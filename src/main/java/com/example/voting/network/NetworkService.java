package com.example.voting.network;

import java.util.List;
import java.util.Set;

/**
 * Interface defining the network communication capabilities required by nodes.
 * Allows swapping between local simulation and real network implementations.
 * 定义节点所需的网络通信功能的接口。
 * 允许在本地模拟和真实网络实现之间切换。
 */
public interface NetworkService {

    /**
     * Starts the network service (e.g., listening for connections).
     * 启动网络服务（例如，侦听连接）。
     */
    void start();

    /**
     * Stops the network service (e.g., closing connections).
     * 停止网络服务（例如，关闭连接）。
     */
    void stop();

    /**
     * Registers a node with the network service.
     *向网络服务注册节点。
     * @param node The node instance to register. 要注册的节点实例。
     */
    void registerNode(Node node);

    /**
     * Unregisters a node from the network service.
     * 从网络服务注销节点。
     * @param nodeId The ID of the node to unregister. 要注销的节点的 ID。
     */
    void unregisterNode(String nodeId);

    /**
     * Retrieves a specific node instance by its ID.
     * Needed for local simulation or direct access. May return null in real network.
     * 根据 ID 检索特定节点实例。
     * 本地模拟或直接访问需要。在真实网络中可能返回 null。
     * @param nodeId The ID of the node. 节点的 ID。
     * @return The Node object, or null if not found or not applicable. Node 对象，如果找不到或不适用则返回 null。
     */
    Node getNodeById(String nodeId); // Keep for now 保留以备后用

    /**
     * Gets a list of known peer node IDs (excluding the requester).
     * 获取已知对等节点 ID 的列表（不包括请求者）。
     * @param requesterId The ID of the node requesting the list. 请求列表的节点的 ID。
     * @param count Max number of peers to return. 要返回的最大对等节点数。
     * @return A list of peer node IDs. 对等节点 ID 的列表。
     */
    List<String> discoverPeers(String requesterId, int count);

    /**
     * Sends a message for broadcast to all other connected/known nodes.
     * 发送广播消息给所有其他连接/已知的节点。
     * @param message The message to broadcast. 要广播的消息。
     */
    void broadcast(NetworkMessage message);

    /**
     * Sends a message directly to a specific recipient node.
     * 直接向特定接收者节点发送消息。
     * @param recipientId The ID of the target node. 目标节点的 ID。
     * @param message The message to send. 要发送的消息。
     * @return true if sending was initiated successfully, false otherwise (e.g., recipient unknown). 如果发送成功启动则返回 true，否则返回 false（例如，接收者未知）。
     */
    boolean sendMessage(String recipientId, NetworkMessage message);

    /**
     * Sets the handler for incoming messages. The Node will typically pass itself.
     * 设置传入消息的处理程序。Node 通常会传递自身。
     * @param handler The object responsible for processing received messages. 负责处理接收到的消息的对象。
     */
    void setMessageReceiver(Node handler); // Node implements message handling Node
    /**
     * Gets a list of all currently registered node IDs.
     * 获取当前所有已注册节点的 ID 列表。
     * @return A list of node IDs. 节点 ID 列表。
     */
    List<String> getAllNodeIds();// 实现消息处理
}