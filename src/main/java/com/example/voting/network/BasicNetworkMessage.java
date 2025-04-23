package com.example.voting.network;

/**
 * A basic implementation of the NetworkMessage interface.
 * NetworkMessage 接口的基本实现。
 */
public class BasicNetworkMessage implements NetworkMessage {

    // Use serialVersionUID for Serializable classes
    // 为 Serializable 类使用 serialVersionUID
    private static final long serialVersionUID = 1L;

    private final String senderId;
    private final String signature;
    private final Object payload; // Can hold String, byte[], etc. 可以容纳 String、byte[] 等。
    private final String messageType;

    /**
     * Constructor for BasicNetworkMessage.
     * BasicNetworkMessage 的构造函数。
     * @param senderId    The ID of the sender node. 发送方节点的 ID。
     * @param signature   The signature of the payload. 负载的签名。
     * @param payload     The message content. 消息内容。
     * @param messageType A string indicating the type of message. 指示消息类型的字符串。
     */
    public BasicNetworkMessage(String senderId, String signature, Object payload, String messageType) {
        // Add check to ensure payload is Serializable if possible, or handle specific types
        // 添加检查以确保负载是 Serializable（如果可能），或处理特定类型
        // For now, we assume payload will be String or byte[] which are Serializable
        // 现在，我们假设负载将是 String 或 byte[]，它们是 Serializable 的
        this.senderId = senderId;
        this.signature = signature;
        this.payload = payload;
        this.messageType = messageType;
    }

    @Override
    public String getSenderId() { return senderId; }
    @Override
    public String getSignature() { return signature; }
    @Override
    public Object getPayload() { return payload; }
    @Override
    public String getMessageType() { return messageType; }

    @Override
    public String toString() {
        String payloadStr = (payload instanceof String) ? "\"" + payload + "\"" : (payload != null ? payload.getClass().getSimpleName() : "null");
        if (payload instanceof byte[]) { payloadStr = "byte[" + ((byte[]) payload).length + "]"; }
        return "BasicNetworkMessage{" + "type='" + messageType + '\'' + ", from='" + senderId + '\'' + ", payload=" + payloadStr + ", sig='" + (signature != null ? signature.substring(0, Math.min(signature.length(), 10)) + "..." : "null") + '\'' + '}';
    }
}