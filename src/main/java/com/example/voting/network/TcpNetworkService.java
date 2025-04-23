package com.example.voting.network;

import com.example.voting.SystemLogger;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.Collectors;

/**
 * Implements NetworkService using TCP sockets for real network communication.
 * 使用 TCP 套接字实现 NetworkService 以进行真实网络通信。
 */
public class TcpNetworkService implements NetworkService {

    private final int listeningPort;
    private ServerSocket serverSocket;
    private volatile boolean running = false; // Use volatile for thread visibility 使用 volatile 保证线程可见性
    private Node messageReceiver; // The local node that handles received messages 处理接收消息的本地节点
    private final ExecutorService clientHandlerExecutor = Executors.newCachedThreadPool(); // Thread pool for incoming connections 用于入站连接的线程池
    private final Map<String, Node> registeredNodes = new ConcurrentHashMap<>(); // Local map used by this service 此服务使用的本地映射
    private final Map<String, PeerAddress> knownPeers = new ConcurrentHashMap<>(); // Map nodeId to PeerAddress 将 nodeId 映射到 PeerAddress
    private final Map<String, ObjectOutputStream> outputStreams = new ConcurrentHashMap<>(); // Cache outgoing streams 缓存出站流

    /**
     * Constructor for TcpNetworkService.
     * TcpNetworkService 的构造函数。
     * @param listeningPort The port this service will listen on for incoming connections. 此服务将侦听传入连接的端口。
     * @param initialPeers A map of initial known peer node IDs to their addresses. 初始已知对等节点 ID 到其地址的映射。
     */
    public TcpNetworkService(int listeningPort, Map<String, PeerAddress> initialPeers) {
        this.listeningPort = listeningPort;
        if (initialPeers != null) {
            this.knownPeers.putAll(initialPeers);
        }
    }

    @Override
    public void start() {
        if (running) {
            SystemLogger.log("TcpNetworkService is already running.");
            return;
        }
        running = true;
        try {
            serverSocket = new ServerSocket(listeningPort);
            SystemLogger.log("TcpNetworkService: Listening for connections on port " + listeningPort);

            // Start acceptor thread
            // 启动接收者线程
            new Thread(this::acceptConnections, "TCP-Acceptor").start();

        } catch (IOException e) {
            running = false;
            SystemLogger.error("TcpNetworkService: Could not start listening on port " + listeningPort + ": " + e.getMessage());
            // Rethrow or handle appropriately
            // 重新抛出或适当处理
            throw new RuntimeException("Failed to start network service", e);
        }
    }

    private void acceptConnections() {
        while (running && serverSocket != null && !serverSocket.isClosed()) {
            try {
                Socket clientSocket = serverSocket.accept(); // Blocks until a connection is made 阻塞直到建立连接
                SystemLogger.log("TcpNetworkService: Accepted connection from " + clientSocket.getRemoteSocketAddress());
                // Handle each client connection in a new thread
                // 在新线程中处理每个客户端连接
                clientHandlerExecutor.submit(new ClientHandler(clientSocket));
            } catch (IOException e) {
                if (running) { // Only log error if service is supposed to be running 仅当服务应运行时才记录错误
                    SystemLogger.error("TcpNetworkService: Error accepting connection: " + e.getMessage());
                }
                // If serverSocket is closed, the loop will terminate
                // 如果 serverSocket 关闭，循环将终止
            }
        }
        SystemLogger.log("TcpNetworkService: Acceptor thread stopped.");
    }

    @Override
    public void stop() {
        SystemLogger.log("TcpNetworkService: Stopping...");
        running = false;
        try {
            if (serverSocket != null && !serverSocket.isClosed()) {
                serverSocket.close();
            }
        } catch (IOException e) {
            SystemLogger.error("TcpNetworkService: Error closing server socket: " + e.getMessage());
        }
        // Close all outgoing connections
        // 关闭所有出站连接
        outputStreams.forEach((peerId, oos) -> {
            try {
                oos.close(); // This will also close the underlying socket 这也将关闭底层套接字
            } catch (IOException e) { /* ignore */ }
        });
        outputStreams.clear();
        // Shutdown executor service
        // 关闭执行器服务
        clientHandlerExecutor.shutdown();
        try {
            if (!clientHandlerExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                clientHandlerExecutor.shutdownNow();
            }
        } catch (InterruptedException e) {
            clientHandlerExecutor.shutdownNow();
            Thread.currentThread().interrupt();
        }
        registeredNodes.clear(); // Clear local node map 清除本地节点映射
        SystemLogger.log("TcpNetworkService: Stopped.");
    }

    @Override
    public void registerNode(Node node) {
        // In TCP mode, registration mainly means storing the local node handler
        // 在 TCP 模式下，注册主要意味着存储本地节点处理程序
        if (node != null) {
            registeredNodes.put(node.getId(), node); // Keep track locally 本地跟踪
            setMessageReceiver(node); // Set the receiver 设置接收者
            SystemLogger.log("TcpNetworkService: Local node handler registered: " + node.getId());
        }
    }

    @Override
    public void unregisterNode(String nodeId) {
        // Primarily for local simulation, less relevant here unless tracking local node state
        // 主要用于本地模拟，除非跟踪本地节点状态，否则在此处不太相关
        registeredNodes.remove(nodeId);
        if (messageReceiver != null && messageReceiver.getId().equals(nodeId)) {
            messageReceiver = null;
        }
        // Also close any connection associated with this node ID?
        // 也要关闭与此节点 ID 关联的任何连接？
        closeConnection(nodeId);
        SystemLogger.log("TcpNetworkService: Local node handler unregistered: " + nodeId);
    }

    @Override
    public Node getNodeById(String nodeId) {
        // This might only return the local node in TCP mode
        // 在 TCP 模式下，这可能只返回本地节点
        return registeredNodes.get(nodeId);
    }

    @Override
    public List<String> discoverPeers(String requesterId, int count) {
        // Simple strategy: return known peers from configuration/cache
        // 简单策略：从配置/缓存返回已知对等节点
        SystemLogger.log("TcpNetworkService: Node " + requesterId + " discovering peers (returning known peers).");
        List<String> peerIds = new ArrayList<>(knownPeers.keySet());
        peerIds.remove(requesterId); // Don't return self 不要返回自己
        Collections.shuffle(peerIds);
        return peerIds.stream().limit(count).collect(Collectors.toList());
        // TODO: Implement more advanced discovery (e.g., contacting seeds)
        // TODO: 实现更高级的发现（例如，联系种子节点）
    }

    @Override
    public List<String> getAllNodeIds() {
        // In TCP mode, this might just return the local node ID + known peers
        // 在 TCP 模式下，这可能只返回本地节点 ID + 已知对等节点
        List<String> ids = new ArrayList<>(knownPeers.keySet());
        // Add local node ID if registered
        // 如果已注册，则添加本地节点 ID
        if (messageReceiver != null && !ids.contains(messageReceiver.getId())) {
            ids.add(messageReceiver.getId());
        }
        return ids;
    }


    @Override
    public void broadcast(NetworkMessage message) {
        String senderId = message.getSenderId();
        SystemLogger.log("TcpNetworkService: Initiating broadcast from " + senderId + " for message type " + message.getMessageType());
        // Send to all known peers except self
        // 发送给除自己之外的所有已知对等节点
        int count = 0;
        for (String peerId : knownPeers.keySet()) {
            if (!peerId.equals(senderId)) {
                if (sendMessage(peerId, message)) {
                    count++;
                }
            }
        }
        SystemLogger.log("TcpNetworkService: Broadcast from " + senderId + " sent to " + count + " known peers.");
    }

    @Override
    public boolean sendMessage(String recipientId, NetworkMessage message) {
        PeerAddress address = knownPeers.get(recipientId);
        if (address == null) {
            SystemLogger.error("TcpNetworkService: Cannot send message to unknown peer: " + recipientId);
            return false;
        }

        ObjectOutputStream oos = outputStreams.get(recipientId);
        try {
            if (oos == null) {
                // Establish connection if not already connected
                // 如果尚未连接，则建立连接
                SystemLogger.log("TcpNetworkService: Establishing connection to " + recipientId + " at " + address);
                Socket socket = new Socket(address.getHost(), address.getPort());
                oos = new ObjectOutputStream(socket.getOutputStream());
                // Send local node ID first for identification? Optional.
                // 首先发送本地节点 ID 以进行识别？可选。
                outputStreams.put(recipientId, oos); // Cache the stream 缓存流
                SystemLogger.log("TcpNetworkService: Connection established to " + recipientId);
            }

            // Send the message object
            // 发送消息对象
            SystemLogger.log("TcpNetworkService: Sending " + message.getMessageType() + " message from " + message.getSenderId() + " to " + recipientId);
            oos.writeObject(message);
            oos.flush(); // Ensure data is sent 确保数据已发送
            return true;
        } catch (IOException e) {
            SystemLogger.error("TcpNetworkService: Error sending message to " + recipientId + " at " + address + ": " + e.getMessage());
            // Connection likely broken, remove stream and close socket
            // 连接可能已断开，删除流并关闭套接字
            closeConnection(recipientId);
            return false;
        }
    }

    private void closeConnection(String peerId) {
        ObjectOutputStream oos = outputStreams.remove(peerId);
        if (oos != null) {
            try {
                oos.close(); // Closes underlying socket 关闭底层套接字
                SystemLogger.log("TcpNetworkService: Closed connection to " + peerId);
            } catch (IOException e) {
                SystemLogger.error("TcpNetworkService: Error closing connection to " + peerId + ": " + e.getMessage());
            }
        }
    }


    @Override
    public void setMessageReceiver(Node handler) {
        this.messageReceiver = handler;
        SystemLogger.log("TcpNetworkService: Message receiver set to Node " + (handler != null ? handler.getId() : "null"));
    }

    /**
     * Handles communication with a single connected client.
     * 处理与单个连接客户端的通信。
     */
    private class ClientHandler implements Runnable {
        private final Socket clientSocket;
        private ObjectInputStream ois;
        // Track the ID of the node connected through this socket
        // 跟踪通过此套接字连接的节点的 ID
        private String connectedNodeId = null;

        public ClientHandler(Socket socket) {
            this.clientSocket = socket;
        }

        @Override
        public void run() {
            try {
                ois = new ObjectInputStream(clientSocket.getInputStream());
                // Optional: Initial handshake to identify the connecting node
                // 可选：初始握手以识别连接节点
                // NetworkMessage initialMsg = (NetworkMessage) ois.readObject();
                // connectedNodeId = initialMsg.getSenderId();
                // SystemLogger.log("TcpNetworkService: Identified incoming connection as " + connectedNodeId);

                while (running && !clientSocket.isClosed()) {
                    Object receivedObject = ois.readObject(); // Blocks until an object is received 阻塞直到接收到对象
                    if (receivedObject instanceof NetworkMessage) {
                        NetworkMessage message = (NetworkMessage) receivedObject;
                        SystemLogger.log("TcpNetworkService: Received message from " + message.getSenderId() + " via " + clientSocket.getRemoteSocketAddress() + ": " + message.getMessageType());

                        // Update known peers if sender is new? (Simple approach)
                        // 如果发送者是新的，则更新已知对等节点？（简单方法）
                        if (!knownPeers.containsKey(message.getSenderId())) {
                            // Assuming the message contains enough info or we trust the sender ID
                            // 假设消息包含足够的信息，或者我们信任发送者 ID
                            // We might need a proper handshake to get the peer's listening address
                            // 我们可能需要一个正确的握手来获取对等节点的侦听地址
                            SystemLogger.log("TcpNetworkService: Discovered new peer " + message.getSenderId() + " via incoming message (address unknown).");
                            // knownPeers.put(message.getSenderId(), new PeerAddress(clientSocket.getInetAddress().getHostAddress(), ???)); // Need port! 需要端口！
                        }


                        if (messageReceiver != null) {
                            // Pass necessary info to the node's handler method
                            // 将必要信息传递给节点的处理程序方法
                            if (message.getPayload() instanceof String && "GROUP_MSG".equals(message.getMessageType())) {
                                messageReceiver.receiveMessage(message.getSenderId(), message.getSignature(), (String)message.getPayload());
                            } else {
                                SystemLogger.error("TcpNetworkService: Received unhandled message type or payload from " + message.getSenderId() + ": " + message.getMessageType());
                            }
                        } else {
                            SystemLogger.error("TcpNetworkService: No message receiver set to handle message from " + message.getSenderId());
                        }
                    } else {
                        SystemLogger.error("TcpNetworkService: Received unexpected object type from " + clientSocket.getRemoteSocketAddress());
                    }
                }
            } catch (EOFException e) {
                // Connection closed normally by the client
                // 客户端正常关闭连接
                SystemLogger.log("TcpNetworkService: Connection closed by peer " + clientSocket.getRemoteSocketAddress());
            } catch (IOException | ClassNotFoundException e) {
                if (running) {
                    SystemLogger.error("TcpNetworkService: Error handling client " + clientSocket.getRemoteSocketAddress() + ": " + e.getMessage());
                    // e.printStackTrace(); // More detail for debugging 更多调试细节
                }
            } finally {
                try {
                    if (ois != null) ois.close();
                    if (clientSocket != null && !clientSocket.isClosed()) clientSocket.close();
                } catch (IOException e) { /* ignore closing errors */ }
                SystemLogger.log("TcpNetworkService: Client handler finished for " + clientSocket.getRemoteSocketAddress());
                // Remove from known peers or output streams if applicable?
                // 如果适用，从已知对等节点或输出流中删除？
                // Requires mapping socket back to nodeId 需要将套接字映射回 nodeId
            }
        }
    }
}