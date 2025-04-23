package com.example.voting;

import com.example.voting.blockchain.*;
import com.example.voting.crypto.*;
import com.example.voting.network.GroupCommUtil;
import com.example.voting.network.LocalSimulationNetworkService; // Import LocalSimulationNetworkService
import com.example.voting.network.NetworkManager; // Keep for potential future use (or remove if fully replaced)
import com.example.voting.network.NetworkService; // Import NetworkService
import com.example.voting.network.Node;
import com.example.voting.network.PeerAddress; // Import PeerAddress
import com.example.voting.network.TcpNetworkService; // Import TcpNetworkService
import com.example.voting.trust.TrustManager;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.net.InetAddress; // Import InetAddress
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509CRL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class MainApp extends Application {

    static {
        // Ensure BC provider is added only once
        // 确保 BC 提供者只添加一次
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private CertificateAuthority rootCA;
    private IdentityBlockchain identityChain;
    private VotingBlockchain votingChain;
    private NetworkService networkService; // Use NetworkService interface 类型是接口
    private ThresholdScheme.Share[] keyShares;
    private SecretKey electionKey;
    private int voteCount = 0;
    private Label resultLabel;
    private TextArea logArea;
    private Map<String, UserCredentials> users = new HashMap<>();

    // Configuration Defaults (can be overridden by args/config file)
    // 配置默认值（可由参数/配置文件覆盖）
    private static int BASE_PORT = 8000; // Starting port for nodes 节点的起始端口
    private static String NETWORK_MODE = "LOCAL"; // "LOCAL" or "TCP"
    private static Map<String, PeerAddress> initialKnownPeers = new HashMap<>();
    private static String localNodeIdOverride = null; // Allow overriding node ID 允许覆盖节点 ID

    private static final List<String> CANDIDATES = List.of("候选人1", "候选人2", "候选人3");
    // Define seed nodes (used by nodes when joining)
    // 定义种子节点（节点加入时使用）
    private static final Set<String> SEED_NODES = Set.of("Node1");


    private static class UserCredentials {
        final KeyPair keyPair;
        final DigitalCertificate certificate;
        UserCredentials(KeyPair kp, DigitalCertificate cert) { this.keyPair = kp; this.certificate = cert; }
    }

    @Override
    public void start(Stage stage) {
        processAppParameters(); // Process params first 首先处理参数
        try {
            initSystem();
            setupUI(stage);
            // Run CRL test only in LOCAL mode where Node1 is guaranteed to exist
            // 仅在保证 Node1 存在的 LOCAL 模式下运行 CRL 测试
            if ("LOCAL".equalsIgnoreCase(NETWORK_MODE)) {
                Platform.runLater(this::runCRLTestScenario);
            }
        } catch (Exception e) {
            handleInitializationError(e);
            return;
        }
    }

    /** Process application parameters from System Properties. */
    /** 从系统属性处理应用程序参数。 */
    private void processAppParameters() {
        // Read from System Properties, providing defaults
        // 从系统属性读取，提供默认值
        NETWORK_MODE = System.getProperty("app.mode", "LOCAL").toUpperCase(); // Default to LOCAL 默认使用 LOCAL
        try {
            BASE_PORT = Integer.parseInt(System.getProperty("app.port", "8000")); // Default port 8000 默认端口 8000
        } catch (NumberFormatException e) {
            System.err.println("Invalid app.port system property. Using default 8000.");
            BASE_PORT = 8000;
        }
        localNodeIdOverride = System.getProperty("app.nodeId"); // Optional override 可选覆盖

        // Parse peers from a comma-separated string: "Node1=host:port,Node2=host:port"
        // 从逗号分隔的字符串解析对等节点："Node1=host:port,Node2=host:port"
        initialKnownPeers.clear(); // Clear previous peers 清除先前的对等节点
        String peersProperty = System.getProperty("app.peers"); // e.g., "Node2=IP_B:8001,Node3=IP_C:8002"
        if (peersProperty != null && !peersProperty.trim().isEmpty()) {
            String[] peerEntries = peersProperty.split(",");
            for (String entry : peerEntries) {
                String[] parts = entry.trim().split("=", 2);
                if (parts.length == 2) {
                    String peerId = parts[0].trim();
                    String[] addrParts = parts[1].trim().split(":", 2);
                    if (addrParts.length == 2) {
                        try {
                            initialKnownPeers.put(peerId, new PeerAddress(addrParts[0].trim(), Integer.parseInt(addrParts[1].trim())));
                        } catch (NumberFormatException e) {
                            System.err.println("Invalid peer address format in app.peers: " + entry);
                        }
                    } else { System.err.println("Invalid peer address format in app.peers: " + entry); }
                } else { System.err.println("Invalid peer format in app.peers: " + entry); }
            }
        }


        // Log the final configuration being used
        // 记录最终使用的配置
        System.out.println("--- Application Configuration ---");
        System.out.println("Network Mode: " + NETWORK_MODE);
        System.out.println("Listening Port: " + BASE_PORT);
        if (localNodeIdOverride != null) System.out.println("Local Node ID Override: " + localNodeIdOverride);
        System.out.println("Initial Known Peers: " + initialKnownPeers);
        System.out.println("-------------------------------");
    }


    /** Handles critical initialization errors. */
    /** 处理关键初始化错误。 */
    private void handleInitializationError(Exception e) {
        SystemLogger.error("FATAL: System initialization failed!");
        e.printStackTrace();
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.ERROR); alert.setTitle("Initialization Error");
            alert.setHeaderText("Failed to initialize the voting system.");
            alert.setContentText("Application cannot start. Please check the logs.\nError: " + e.getMessage());
            alert.showAndWait(); Platform.exit();
        });
    }

    /** Sets up the JavaFX user interface. */
    /** 设置 JavaFX 用户界面。 */
    private void setupUI(Stage stage) {
        stage.setTitle("区块链安全机制演示 (网络抽象)");

        logArea = new TextArea(); logArea.setEditable(false); logArea.setWrapText(true); logArea.setPrefHeight(350);
        SystemLogger.setLogTextArea(logArea); SystemLogger.setConsoleOutputEnabled(false);
        SystemLogger.log("系统界面初始化...");

        Label voterLabel = new Label("模拟投票者:");
        ChoiceBox<String> voterSelectBox = new ChoiceBox<>(); voterSelectBox.getItems().addAll(users.keySet());
        if (!users.isEmpty()) voterSelectBox.setValue(users.keySet().iterator().next());

        Label candidateLabel = new Label("选择候选人:");
        ListView<String> candidateList = new ListView<>(); candidateList.getItems().addAll(CANDIDATES); candidateList.setPrefHeight(100);

        Button voteBtn = new Button("模拟投票"); resultLabel = new Label("投票结果将在此显示");

        Button crlTestBtn = new Button("运行 CRL 测试"); crlTestBtn.setOnAction(e -> new Thread(this::runCRLTestScenario).start());
        Button trustScoresBtn = new Button("显示信任分数"); trustScoresBtn.setOnAction(e -> showTrustScores());
        HBox actionButtons = new HBox(10, crlTestBtn, trustScoresBtn); actionButtons.setPadding(new Insets(10, 0, 0, 0));

        VBox topControls = new VBox(10, voterLabel, voterSelectBox, candidateLabel, candidateList, voteBtn, resultLabel, new Separator(), actionButtons);
        topControls.setPadding(new Insets(10));

        BorderPane rootLayout = new BorderPane(); rootLayout.setTop(topControls); rootLayout.setCenter(logArea);
        Scene scene = new Scene(rootLayout, 650, 600); stage.setScene(scene); stage.show();
        SystemLogger.log("系统界面已就绪。");

        voteBtn.setOnAction(e -> {
            String selectedVoterId = voterSelectBox.getValue(); String selectedCandidate = candidateList.getSelectionModel().getSelectedItem();
            if (selectedVoterId == null || selectedCandidate == null) { showAlert(Alert.AlertType.WARNING, "输入错误", "请选择投票者和候选人。"); return; }
            UserCredentials voterCreds = users.get(selectedVoterId); if (voterCreds == null) { showAlert(Alert.AlertType.ERROR, "内部错误", "找不到选定的投票者凭据。"); return; }
            SystemLogger.log("开始为 " + selectedVoterId + " 模拟投票给 " + selectedCandidate);
            new Thread(() -> castVote(selectedCandidate, voterCreds)).start();
        });
    }

    /** Displays the trust scores in the log area and optionally an alert. */
    /** 在日志区域和可选的警报框中显示信任分数。 */
    private void showTrustScores() {
        SystemLogger.log("\n--- 当前节点信任分数 ---");
        if (networkService == null) { SystemLogger.error("无法显示信任分数：NetworkService 未初始化。"); return; }
        List<String> allIds = networkService.getAllNodeIds();
        if (allIds.isEmpty()) { SystemLogger.log("网络中没有节点。"); showAlert(Alert.AlertType.INFORMATION, "信任分数", "网络中没有节点可显示信任分数。"); return; }

        StringBuilder scoresLog = new StringBuilder(); StringBuilder scoresAlert = new StringBuilder();
        for (String viewerId : allIds) {
            Node viewerNode = networkService.getNodeById(viewerId);
            if (viewerNode == null || viewerNode.getTrustManager() == null) continue;
            scoresLog.append("节点 ").append(viewerId).append(" 的视角:\n"); scoresAlert.append("节点 ").append(viewerId).append(" 的视角:\n");
            TrustManager tm = viewerNode.getTrustManager(); boolean otherNodesExist = false;
            for (String targetId : allIds) {
                if (!targetId.equals(viewerId)) {
                    otherNodesExist = true; double score = tm.getTrustScore(targetId); String formattedScore = String.format("%.1f", score);
                    scoresLog.append("  - 对节点 ").append(targetId).append(" 的信任分数: ").append(formattedScore).append("\n");
                    scoresAlert.append("  - ").append(targetId).append(": ").append(formattedScore).append("\n");
                }
            }
            if (!otherNodesExist) { scoresLog.append("  (无其他节点)\n"); scoresAlert.append("  (无其他节点)\n"); }
            scoresLog.append("\n"); scoresAlert.append("\n");
        }
        SystemLogger.log(scoresLog.toString().trim());
        showAlert(Alert.AlertType.INFORMATION, "节点信任分数", scoresAlert.toString().trim());
    }

    /** Helper to show alerts */
    /** 显示警报的辅助方法 */
    private void showAlert(Alert.AlertType type, String title, String message) {
        if (Platform.isFxApplicationThread()) { Alert alert = new Alert(type); alert.setTitle(title); alert.setHeaderText(null); alert.setContentText(message); alert.showAndWait(); }
        else { Platform.runLater(() -> { Alert alert = new Alert(type); alert.setTitle(title); alert.setHeaderText(null); alert.setContentText(message); alert.showAndWait(); }); }
    }

    /** System initialization */
    /** 系统初始化 */
    private void initSystem() throws Exception {
        SystemLogger.log("开始系统初始化 (模式: " + NETWORK_MODE + ")...");

        // 0. Initialize Network Service based on mode
        // 0. 根据模式初始化网络服务
        if ("TCP".equalsIgnoreCase(NETWORK_MODE)) {
            networkService = new TcpNetworkService(BASE_PORT, initialKnownPeers);
        } else { // Default to LOCAL 默认使用 LOCAL
            networkService = new LocalSimulationNetworkService();
        }
        networkService.start();
        SystemLogger.log("NetworkService (" + networkService.getClass().getSimpleName() + ") 已初始化并启动。");

        // 1. CA
        // 1. CA
        rootCA = new CertificateAuthority("VotingRootCA"); SystemLogger.log("根 CA (VotingRootCA) 已初始化。");
        // 2. Blockchains
        // 2. 区块链
        identityChain = new IdentityBlockchain(1, null); votingChain = new VotingBlockchain(2); SystemLogger.log("身份链和投票链已初始化。");

        // 3. Create Nodes & Issue Certificates
        // 3. 创建节点并颁发证书
        Map<String, Node> tempNodeMap = new HashMap<>(); // Use temporary map 使用临时 Map
        Map<String, DigitalCertificate> nodeCertMap = new HashMap<>();
        SystemLogger.log("开始创建网络节点对象...");

        // *** Conditional Node Creation based on Mode ***
        // *** 根据模式有条件地创建节点 ***
        if ("LOCAL".equalsIgnoreCase(NETWORK_MODE)) {
            // In LOCAL mode, create all predefined nodes
            // 在 LOCAL 模式下，创建所有预定义的节点
            List<String> nodeIds = Arrays.asList("Node1", "Node2", "Node3");
            for (String nodeId : nodeIds) {
                Node node = new Node(nodeId, identityChain, votingChain, rootCA.getPublicKey(), networkService);
                tempNodeMap.put(nodeId, node);
                DigitalCertificate nodeCert = rootCA.issueCertificate(nodeId, node.getPublicKey(), 730);
                if (nodeCert != null && rootCA.verifyCertificate(nodeCert)) {
                    identityChain.registerNodeCertificate(nodeCert); nodeCertMap.put(nodeId, nodeCert);
                    SystemLogger.log("节点 " + nodeId + " 对象已创建并获得证书。");
                } else { throw new RuntimeException("无法为节点颁发或验证证书: " + nodeId); }
            }
        } else { // TCP Mode (or other future modes) TCP 模式（或其他未来模式）
            // In TCP mode, create only the local node
            // 在 TCP 模式下，仅创建本地节点
            String localNodeId = determineLocalNodeId(); // Get local ID 获取本地 ID
            Node localNode = new Node(localNodeId, identityChain, votingChain, rootCA.getPublicKey(), networkService);
            tempNodeMap.put(localNodeId, localNode); // Store the single local node 存储单个本地节点
            DigitalCertificate localCert = rootCA.issueCertificate(localNodeId, localNode.getPublicKey(), 730);
            if (localCert != null && rootCA.verifyCertificate(localCert)) {
                identityChain.registerNodeCertificate(localCert); nodeCertMap.put(localNodeId, localCert);
                SystemLogger.log("本地节点 " + localNodeId + " 对象已创建并获得证书。");
            } else { throw new RuntimeException("无法为本地节点颁发或验证证书: " + localNodeId); }
        }
        SystemLogger.log(tempNodeMap.size() + " 个节点对象已创建。");

        // 4. Nodes Join the Network
        // 4. 节点加入网络
        SystemLogger.log("开始让已创建的节点加入网络...");
        // Let nodes join one by one (or concurrently if desired)
        // 让节点逐个加入（如果需要可以并发）
        for (Node node : tempNodeMap.values()) {
            node.joinNetwork(SEED_NODES); // All created nodes attempt to join 所有创建的节点尝试加入
        }
        // Verify registration matches created nodes
        // 验证注册是否与创建的节点匹配
        if (networkService.getAllNodeIds().size() != tempNodeMap.size()) {
            SystemLogger.error("注册的节点数 (" + networkService.getAllNodeIds().size() + ") 与创建的节点数 (" + tempNodeMap.size() + ") 不匹配！");
            // Consider throwing an exception if critical
            // 如果关键则考虑抛出异常
            // throw new RuntimeException("节点注册数量不匹配！");
        }
        SystemLogger.log(networkService.getAllNodeIds().size() + " 个节点已加入网络并注册。");


        // 5. Voter Users & Certificates
        // 5. 选民用户和证书
        SystemLogger.log("开始创建选民用户...");
        createAndRegisterUser("VoterAlice"); createAndRegisterUser("VoterBob");
        for (UserCredentials user : users.values()) {
            Block idBlock = createIdentityBlock(user.certificate);
            if (!identityChain.addBlock(idBlock)) { SystemLogger.error("无法为选民添加身份区块: " + user.certificate.getSubject()); }
        }
        SystemLogger.log(users.size() + " 个选民用户已创建并注册到身份链。");
        SystemLogger.log("身份链当前状态:\n" + identityChain);

        // 6. Group Key Distribution (Only in LOCAL mode)
        // 6. 群组密钥分发（仅在 LOCAL 模式下）
        if ("LOCAL".equalsIgnoreCase(NETWORK_MODE)) {
            var groupAESKey = GroupCommUtil.generateGroupKey(); if (groupAESKey == null) throw new RuntimeException("无法生成群组密钥。");
            SystemLogger.log("开始分发群组密钥 (仅本地模式)...");
            for (String nodeId : networkService.getAllNodeIds()) {
                Node node = networkService.getNodeById(nodeId); if (node != null) {
                    String encryptedGroupKey = GroupCommUtil.encryptGroupKeyForNode(groupAESKey, node.getPublicKey());
                    if (encryptedGroupKey != null) node.receiveGroupKey(encryptedGroupKey); else SystemLogger.error("无法为节点 " + node.getId() + " 加密群组密钥。");
                }
            } SystemLogger.log("群组密钥分发完成。");
        } else { SystemLogger.log("跳过群组密钥分发 (TCP 模式)。"); }

        // 7. Threshold Key Setup
        // 7. 门限密钥设置
        electionKey = CryptoUtil.generateAESKey(128); if (electionKey == null) throw new RuntimeException("无法生成选举密钥。");
        BigInteger secret = new BigInteger(1, electionKey.getEncoded());
        keyShares = ThresholdScheme.generateSharesFromSecret(secret, 3, 2); if (keyShares == null || keyShares.length != 3) throw new RuntimeException("无法生成门限密钥分片。");
        SystemLogger.log("门限密钥分片已生成。");

        // 8. Generate and Distribute Initial CRL
        // 8. 生成并分发初始 CRL
        SystemLogger.log("开始生成初始 CRL...");
        X509CRL initialCRL = rootCA.generateCRL(7);
        if (initialCRL != null) {
            SystemLogger.log("开始向所有已注册节点分发初始 CRL...");
            int crlDistributedCount = 0;
            // Distribute to all nodes known by the service (local or potentially remote in TCP)
            // 分发给服务已知的所有节点（本地或 TCP 中的潜在远程节点）
            for (String nodeId : networkService.getAllNodeIds()) {
                Node node = networkService.getNodeById(nodeId);
                if (node != null) { // Only distribute if we have the local Node object 仅当我们有本地 Node 对象时才分发
                    node.updateCRL(initialCRL);
                    crlDistributedCount++;
                } else if ("TCP".equalsIgnoreCase(NETWORK_MODE)) {
                    // In TCP mode, we can't directly call updateCRL on remote nodes.
                    // They would need to fetch it or receive it via broadcast.
                    // 在 TCP 模式下，我们无法直接在远程节点上调用 updateCRL。
                    // 它们需要获取它或通过广播接收它。
                    SystemLogger.log("TCP 模式：无法直接向远程节点 " + nodeId + " 分发 CRL。");
                }
            }
            SystemLogger.log("初始 CRL 已分发给 " + crlDistributedCount + " 个本地已知节点。");
        } else { SystemLogger.error("严重警告：无法生成初始 CRL。吊销检查将无法工作。"); }
        SystemLogger.log("系统初始化完成。");
    }

    /** Determines the local node ID based on configuration or defaults. */
    /** 根据配置或默认值确定本地节点 ID。 */
    private String determineLocalNodeId() {
        if (localNodeIdOverride != null && !localNodeIdOverride.trim().isEmpty()) {
            return localNodeIdOverride.trim();
        }
        return "Node" + BASE_PORT;
    }

    /** Runs a simple test scenario for CRL functionality. */
    /** 运行 CRL 功能的简单测试场景。 */
    private void runCRLTestScenario() {
        // Only run in LOCAL mode where Node1 is expected
        // 仅在预期 Node1 存在的 LOCAL 模式下运行
        if (!"LOCAL".equalsIgnoreCase(NETWORK_MODE)) {
            SystemLogger.log("跳过 CRL 测试场景 (非本地模式)。");
            return;
        }
        new Thread(() -> {
            SystemLogger.log("\n--- 开始运行 CRL 测试场景 (本地模式) ---");
            Node senderNode = networkService.getNodeById("Node1");
            if (senderNode == null) { SystemLogger.error("CRL 测试错误：无法获取发送节点 (Node1)。"); return; }

            String testMessage = "CRLTest: 来自 " + senderNode.getId() + " 的消息 (吊销前)";
            SystemLogger.log("\n步骤 1: " + senderNode.getId() + " 广播消息 (吊销前)..."); senderNode.broadcast(testMessage);
            try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

            SystemLogger.log("\n步骤 2: 吊销节点 " + senderNode.getId() + " 的证书..."); DigitalCertificate senderCert = identityChain.getCertificateForNode(senderNode.getId());
            if (senderCert != null) { rootCA.revokeCertificate(senderCert); } else { SystemLogger.error("CRL 测试错误：找不到节点 " + senderNode.getId() + " 的证书进行吊销。"); return; }
            try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

            SystemLogger.log("\n步骤 3: 生成并分发更新后的 CRL..."); X509CRL updatedCRL = rootCA.generateCRL(7);
            if (updatedCRL != null) { for (String nodeId : networkService.getAllNodeIds()) { Node node = networkService.getNodeById(nodeId); if (node != null) { node.updateCRL(updatedCRL); } } }
            else { SystemLogger.error("CRL 测试错误：无法生成更新后的 CRL。"); return; }
            try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

            SystemLogger.log("\n步骤 4: " + senderNode.getId() + " 广播消息 (吊销后)..."); String testMessageAfter = "CRLTest: 来自 " + senderNode.getId() + " 的消息 (吊销后)"; senderNode.broadcast(testMessageAfter);
            SystemLogger.log("\n--- CRL 测试场景完成 ---");
        }).start();
    }


    // --- Methods that were previously commented out are now restored ---
    // --- 之前被注释掉的方法现在已恢复 ---

    /** Creates a voter user, generates keys, issues a certificate, and stores credentials. */
    /** 创建选民用户、生成密钥、颁发证书并存储凭据。 */
    private void createAndRegisterUser(String username) {
        KeyPair userKP = KeyUtil.generateRSAKeyPair();
        if (userKP == null) {
            SystemLogger.error("无法为用户生成密钥对: " + username);
            return;
        }
        DigitalCertificate userCert = rootCA.issueCertificate(username, userKP.getPublic(), 365); // 1 year validity 1 年有效期
        if (userCert != null && rootCA.verifyCertificate(userCert)) {
            users.put(username, new UserCredentials(userKP, userCert));
            SystemLogger.log("成功创建并认证用户: " + username);
        } else {
            SystemLogger.error("无法创建或验证用户证书: " + username);
        }
    }

    /** Creates a block for the identity chain containing certificate info. */
    /** 为包含证书信息的身份链创建区块。 */
    private Block createIdentityBlock(DigitalCertificate cert) {
        Block last = identityChain.getLastBlock();
        Block b = new Block(last.getIndex() + 1, last.getHash());
        String payload = "ADD_VOTER:Subject=" + cert.getSubject() + ",SN=" + cert.getSerialNumber();
        Transaction tx = new Transaction(Transaction.Type.IDENTITY, payload);
        b.addTransaction(tx);
        b.finalizeBlock(); // Calculate hash 计算哈希
        return b;
    }

    /** Authenticates a user (simple lookup and cert check for demo). */
    /** 验证用户（用于演示的简单查找和证书检查）。 */
    private boolean authenticate(String username) {
        UserCredentials creds = users.get(username);
        if (creds != null) {
            // Check certificate validity using the CA
            // 使用 CA 检查证书有效性
            if (rootCA.verifyCertificate(creds.certificate) && creds.certificate.isValid()) {
                SystemLogger.log("用户认证成功 (用于UI目的): " + username);
                return true;
            } else {
                SystemLogger.error("认证失败：证书无效或无法验证 " + username);
                return false;
            }
        }
        SystemLogger.error("认证失败：找不到用户 " + username);
        return false;
    }

    /** Casts a vote for the selected candidate by the specified voter. */
    /** 由指定的投票者为所选候选人投票。 */
    private void castVote(String candidate, UserCredentials voter) {
        if (voter == null || voter.certificate == null) {
            SystemLogger.error("无法投票，投票者凭据无效。");
            showAlert(Alert.AlertType.ERROR, "投票错误", "投票者凭据无效。");
            return;
        }
        String voterId = extractCN(voter.certificate.getSubject()); // Get voter CN 获取选民 CN
        SystemLogger.log("用户 " + voterId + " 正在为 " + candidate + " 投票...");

        // 1. Encrypt vote
        String encryptedVote = CryptoUtil.encryptAES(candidate, electionKey);
        if (encryptedVote == null) {
            SystemLogger.error("投票加密失败，用户: " + voterId);
            showAlert(Alert.AlertType.ERROR, "投票错误", "加密投票失败。");
            return;
        }
        SystemLogger.log("投票已加密，用户: " + voterId);

        // 2. Blind Signature
        SystemLogger.log("开始为投票令牌获取盲签名，用户: " + voterId);
        BigInteger token = BigInteger.valueOf(System.currentTimeMillis()).add(BigInteger.valueOf(new SecureRandom().nextInt()));
        BigInteger rsaN = BlindSignatureUtil.getN(); BigInteger rsaE = BlindSignatureUtil.getE();
        BigInteger blindingFactor = BlindSignatureUtil.generateBlindingFactor(rsaN);
        BigInteger blindedMessage = BlindSignatureUtil.blindMessage(token, blindingFactor, rsaE, rsaN);
        BigInteger signedBlindedMessage = BlindSignatureUtil.blindSign(blindedMessage);
        BigInteger finalSignature = BlindSignatureUtil.unblindSignature(signedBlindedMessage, blindingFactor, rsaN);
        if (!BlindSignatureUtil.verifySignature(token, finalSignature)) {
            SystemLogger.error("盲签名验证失败！用户: " + voterId);
        } else {
            SystemLogger.log("盲签名成功获取并验证，用户: " + voterId);
        }

        // 3. Create Transaction
        String payload = encryptedVote + "|" + finalSignature.toString(16);
        Transaction voteTx = new Transaction(Transaction.Type.VOTE, payload);
        SystemLogger.log("投票交易已创建，用户: " + voterId);

        // 4. Mine Block (PoW)
        Block lastBlock = votingChain.getLastBlock();
        Block newBlock = new Block(lastBlock.getIndex() + 1, lastBlock.getHash());
        newBlock.addTransaction(voteTx);
        int nonce = 0; String prefix = "0".repeat(votingChain.difficulty); String blockHash;
        long startTime = System.currentTimeMillis();
        SystemLogger.log("开始为区块 " + newBlock.getIndex() + " 挖掘 (难度: " + votingChain.difficulty + ")...");
        do {
            String dataToHash = newBlock.getIndex() + newBlock.getPrevHash() + newBlock.getTimestamp() + newBlock.getTransactions().toString() + nonce;
            blockHash = CryptoUtil.sha256(dataToHash);
            nonce++;
            if (System.currentTimeMillis() - startTime > 60000) { // 60 second timeout 60 秒超时
                SystemLogger.error("挖矿超时！区块 " + newBlock.getIndex());
                showAlert(Alert.AlertType.ERROR, "挖矿错误", "挖矿超时，无法添加区块。");
                return;
            }
        } while (!blockHash.startsWith(prefix));
        long endTime = System.currentTimeMillis();
        SystemLogger.log("区块 " + newBlock.getIndex() + " 已挖掘! Nonce = " + (nonce - 1) + ", Hash = " + blockHash.substring(0,12) + "..., 耗时 = " + (endTime-startTime) + "ms");
        newBlock.setHash(blockHash);

        // 5. Add Block to Voting Chain
        if (votingChain.addBlock(newBlock)) {
            voteCount++;
            SystemLogger.log("投票交易已添加到投票链的区块 #" + newBlock.getIndex());
            updateResults(); // Update UI results 更新 UI 结果
        } else {
            SystemLogger.error("无法将已挖掘的区块 #" + newBlock.getIndex() + " 添加到投票链！");
            showAlert(Alert.AlertType.ERROR, "链错误", "无法将区块添加到投票链。");
        }
    }

    /** Updates the results displayed in the UI based on the voting chain cache. */
    /** 根据投票链缓存更新 UI 中显示的结果。 */
    private void updateResults() {
        if (keyShares == null || keyShares.length < 2) {
            SystemLogger.error("无法更新结果：门限分片不足。");
            Platform.runLater(() -> resultLabel.setText("错误：门限密钥分片不足。"));
            return;
        }
        SystemLogger.log("请求更新投票结果...");
        try {
            // 1. Recover Tally Key
            SystemLogger.log("正在恢复计票密钥...");
            ThresholdScheme.Share s1 = keyShares[0]; ThresholdScheme.Share s2 = keyShares[1];
            BigInteger recoveredSecretBI = ThresholdScheme.recoverSecret(s1, s2);
            int keyLengthBytes = electionKey.getEncoded().length;
            SecretKey tallyKey = CryptoUtil.secretKeyFromBigInteger(recoveredSecretBI, keyLengthBytes);
            if (tallyKey == null) {
                SystemLogger.error("无法从恢复的秘密重构计票密钥。");
                Platform.runLater(() -> resultLabel.setText("错误：无法恢复计票密钥。"));
                return;
            }
            SystemLogger.log("计票密钥已成功恢复。");

            // 2. Get vote counts using the cache-aware method
            Map<String, Integer> voteCounts = votingChain.getLatestVoteCounts(tallyKey);
            if (voteCounts.isEmpty() && !votingChain.isCacheValid()) {
                SystemLogger.error("计票失败，无法显示结果。");
                Platform.runLater(() -> resultLabel.setText("错误：计票失败。"));
                return;
            }

            // 3. Update UI
            int totalDecryptedVotes = voteCounts.values().stream().mapToInt(Integer::intValue).sum();
            final String resultText = buildResultString(voteCounts, totalDecryptedVotes, voteCount);
            Platform.runLater(() -> resultLabel.setText(resultText));
            SystemLogger.log("投票结果 UI 已更新。");

        } catch (Exception e) {
            final String errorMsg = "错误：计票时发生异常。\n" + e.getMessage();
            Platform.runLater(() -> resultLabel.setText(errorMsg));
            SystemLogger.error("计票时出错:");
            e.printStackTrace();
        }
    }

    /** Builds the result string ensuring consistent candidate order. */
    /** 构建结果字符串，确保候选人顺序一致。 */
    private String buildResultString(Map<String, Integer> counts, int decryptedTotal, int txTotal) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("总有效投票数: %d (来自 %d 笔投票交易)\n", decryptedTotal, txTotal));
        // Iterate through the predefined CANDIDATES list for consistent order
        // 遍历预定义的 CANDIDATES 列表以确保顺序一致
        for (String candidate : CANDIDATES) {
            sb.append(String.format("%s: %d\n", candidate, counts.getOrDefault(candidate, 0)));
        }
        return sb.toString();
    }

    /** Extracts the Common Name (CN) from a Distinguished Name string. */
    /** 从可分辨名称字符串中提取通用名称 (CN)。 */
    private String extractCN(String dn) {
        if (dn == null) return "Unknown";
        String[] parts = dn.split(",");
        for (String part : parts) {
            String trimmedPart = part.trim();
            if (trimmedPart.toUpperCase().startsWith("CN=")) {
                return trimmedPart.substring(3);
            }
        }
        // Fallback to full DN if CN not found
        // 如果找不到 CN 则回退到完整 DN
        return dn;
    }

    public static void main(String[] args) {
        launch(args);
    }
}