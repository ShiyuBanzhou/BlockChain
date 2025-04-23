package com.example.voting.network;

import java.io.Serializable; // Import Serializable

/**
 * Interface representing a message sent over the network.
 * Must be Serializable to be sent over real networks.
 * 代表通过网络发送的消息的接口。
 * 必须是 Serializable 才能通过真实网络发送。
 */
public interface NetworkMessage extends Serializable { // Make it Serializable 使其可序列化

    /**
     * Gets the ID of the node that originally sent the message.
     * 获取最初发送消息的节点的 ID。
     * @return Sender's node ID. 发送者的节点 ID。
     */
    String getSenderId();

    /**
     * Gets the digital signature of the message payload, created by the sender.
     * 获取由发送者创建的消息负载的数字签名。
     * @return Base64 encoded signature string. Base64 编码的签名字符串。
     */
    String getSignature();

    /**
     * Gets the main content/payload of the message.
     * This might be encrypted data, a block, a transaction, etc.
     * 获取消息的主要内容/负载。
     * 这可能是加密数据、区块、交易等。
     * @return The message payload (often as a String or byte array). 消息负载（通常为字符串或字节数组）。
     */
    Object getPayload(); // Use Object for flexibility 使用 Object 以获得灵活性

    /**
     * Gets the type of the message (e.g., BROADCAST, UNICAST, BLOCK, TX).
     * 获取消息的类型（例如，BROADCAST、UNICAST、BLOCK、TX）。
     * @return A string representing the message type. 代表消息类型的字符串。
     */
    String getMessageType(); // Added for routing/handling 添加用于路由/处理
}