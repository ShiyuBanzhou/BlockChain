package com.example.voting;

import com.example.voting.blockchain.*;
import com.example.voting.crypto.*;
import com.example.voting.network.GroupCommUtil;
import com.example.voting.network.NetworkManager;
import com.example.voting.network.Node;
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
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509CRL;
import java.util.ArrayList; // Import ArrayList
import java.util.Arrays;
import java.util.Collections; // Import Collections
import java.util.HashMap;
import java.util.HashSet; // Import HashSet
import java.util.List;
import java.util.Map;
import java.util.Set; // Import Set
import java.util.stream.Collectors;

public class MainApp extends Application {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private CertificateAuthority rootCA;
    private IdentityBlockchain identityChain;
    private VotingBlockchain votingChain;
    private NetworkManager networkManager;
    private ThresholdScheme.Share[] keyShares;
    private SecretKey electionKey;
    private int voteCount = 0;
    private Label resultLabel;
    private TextArea logArea;
    private Map<String, UserCredentials> users = new HashMap<>();

    // Define candidate list centrally
    // 集中定义候选人列表
    private static final List<String> CANDIDATES = List.of("候选人1", "候选人2", "候选人3");
    // Define seed nodes
    // 定义种子节点
    private static final Set<String> SEED_NODES = Set.of("Node1");


    private static class UserCredentials {
        final KeyPair keyPair;
        final DigitalCertificate certificate;
        UserCredentials(KeyPair kp, DigitalCertificate cert) { this.keyPair = kp; this.certificate = cert; }
    }

    @Override
    public void start(Stage stage) {
        try {
            initSystem();
            setupUI(stage);
            // Run CRL test automatically after UI is ready
            // 在 UI 就绪后自动运行 CRL 测试
            Platform.runLater(this::runCRLTestScenario);
        } catch (Exception e) {
            handleInitializationError(e);
            return;
        }
    }

    /** Handles critical initialization errors. */
    /** 处理关键初始化错误。 */
    private void handleInitializationError(Exception e) {
        SystemLogger.error("FATAL: System initialization failed!");
        e.printStackTrace();
        Platform.runLater(() -> {
            Alert alert = new Alert(Alert.AlertType.ERROR);
            alert.setTitle("Initialization Error");
            alert.setHeaderText("Failed to initialize the voting system.");
            alert.setContentText("Application cannot start. Please check the logs.\nError: " + e.getMessage());
            alert.showAndWait();
            Platform.exit();
        });
    }

    /** Sets up the JavaFX user interface. */
    /** 设置 JavaFX 用户界面。 */
    private void setupUI(Stage stage) {
        stage.setTitle("区块链安全机制演示 (节点发现)"); // Update title 更新标题

        // --- Log Area ---
        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setWrapText(true);
        logArea.setPrefHeight(350);
        SystemLogger.setLogTextArea(logArea);
        SystemLogger.setConsoleOutputEnabled(false);
        SystemLogger.log("系统界面初始化...");

        // --- Voting Control Panel ---
        Label voterLabel = new Label("模拟投票者:");
        ChoiceBox<String> voterSelectBox = new ChoiceBox<>();
        voterSelectBox.getItems().addAll(users.keySet());
        if (!users.isEmpty()) voterSelectBox.setValue(users.keySet().iterator().next());

        Label candidateLabel = new Label("选择候选人:");
        ListView<String> candidateList = new ListView<>();
        candidateList.getItems().addAll(CANDIDATES);
        candidateList.setPrefHeight(100);

        Button voteBtn = new Button("模拟投票");
        resultLabel = new Label("投票结果将在此显示");

        // --- Action Buttons Panel ---
        Button crlTestBtn = new Button("运行 CRL 测试");
        crlTestBtn.setOnAction(e -> new Thread(this::runCRLTestScenario).start());

        Button trustScoresBtn = new Button("显示信任分数");
        trustScoresBtn.setOnAction(e -> showTrustScores());

        HBox actionButtons = new HBox(10, crlTestBtn, trustScoresBtn);
        actionButtons.setPadding(new Insets(10, 0, 0, 0));

        // --- Combine Voting Controls and Action Buttons ---
        VBox topControls = new VBox(10,
                voterLabel, voterSelectBox,
                candidateLabel, candidateList,
                voteBtn, resultLabel,
                new Separator(),
                actionButtons
        );
        topControls.setPadding(new Insets(10));

        // --- Main Layout (BorderPane) ---
        BorderPane rootLayout = new BorderPane();
        rootLayout.setTop(topControls);
        rootLayout.setCenter(logArea);

        // --- Scene and Stage ---
        Scene scene = new Scene(rootLayout, 650, 600);
        stage.setScene(scene);
        stage.show();
        SystemLogger.log("系统界面已就绪。");

        // --- Vote Button Action ---
        voteBtn.setOnAction(e -> {
            String selectedVoterId = voterSelectBox.getValue();
            String selectedCandidate = candidateList.getSelectionModel().getSelectedItem();
            if (selectedVoterId == null || selectedCandidate == null) {
                showAlert(Alert.AlertType.WARNING, "输入错误", "请选择投票者和候选人。");
                return;
            }
            UserCredentials voterCreds = users.get(selectedVoterId);
            if (voterCreds == null) {
                showAlert(Alert.AlertType.ERROR, "内部错误", "找不到选定的投票者凭据。");
                return;
            }
            SystemLogger.log("开始为 " + selectedVoterId + " 模拟投票给 " + selectedCandidate);
            new Thread(() -> castVote(selectedCandidate, voterCreds)).start();
        });
    }

    /** Displays the trust scores in the log area and optionally an alert. */
    /** 在日志区域和可选的警报框中显示信任分数。 */
    private void showTrustScores() {
        SystemLogger.log("\n--- 当前节点信任分数 ---");
        if (networkManager == null || networkManager.getAllNodeIds().isEmpty()) {
            SystemLogger.log("网络中没有节点。");
            showAlert(Alert.AlertType.INFORMATION, "信任分数", "网络中没有节点可显示信任分数。");
            return;
        }

        StringBuilder scoresLog = new StringBuilder();
        StringBuilder scoresAlert = new StringBuilder();
        List<String> allIds = networkManager.getAllNodeIds();

        for (String viewerId : allIds) {
            Node viewerNode = networkManager.getNodeById(viewerId);
            if (viewerNode == null || viewerNode.getTrustManager() == null) continue;

            scoresLog.append("节点 ").append(viewerId).append(" 的视角:\n");
            scoresAlert.append("节点 ").append(viewerId).append(" 的视角:\n");

            TrustManager tm = viewerNode.getTrustManager();
            boolean otherNodesExist = false;
            for (String targetId : allIds) {
                if (!targetId.equals(viewerId)) {
                    otherNodesExist = true;
                    double score = tm.getTrustScore(targetId);
                    String formattedScore = String.format("%.1f", score);
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
        if (Platform.isFxApplicationThread()) {
            Alert alert = new Alert(type); alert.setTitle(title); alert.setHeaderText(null); alert.setContentText(message); alert.showAndWait();
        } else {
            Platform.runLater(() -> { Alert alert = new Alert(type); alert.setTitle(title); alert.setHeaderText(null); alert.setContentText(message); alert.showAndWait(); });
        }
    }


    /** System initialization */
    /** 系统初始化 */
    private void initSystem() throws Exception {
        SystemLogger.log("开始系统初始化...");
        // 0. Network Manager
        networkManager = new NetworkManager(); SystemLogger.log("NetworkManager 已初始化。");
        // 1. CA
        rootCA = new CertificateAuthority("VotingRootCA"); SystemLogger.log("根 CA (VotingRootCA) 已初始化。");
        // 2. Blockchains
        identityChain = new IdentityBlockchain(1, null); votingChain = new VotingBlockchain(2); SystemLogger.log("身份链和投票链已初始化。");

        // 3. Create Nodes & Issue Certificates (Nodes do NOT register yet)
        // 3. 创建节点并颁发证书（节点尚未注册）
        List<String> nodeIds = Arrays.asList("Node1", "Node2", "Node3");
        Map<String, Node> tempNodeMap = new HashMap<>(); // Temporary map to hold nodes 临时 Map 保存节点
        Map<String, DigitalCertificate> nodeCertMap = new HashMap<>();
        SystemLogger.log("开始创建网络节点对象...");
        for (String nodeId : nodeIds) {
            // Create node instance, pass NetworkManager reference
            // 创建节点实例，传递 NetworkManager 引用
            Node node = new Node(nodeId, identityChain, votingChain, rootCA.getPublicKey(), networkManager);
            tempNodeMap.put(nodeId, node); // Store node temporarily 临时存储节点

            // Issue and verify certificate
            // 颁发并验证证书
            DigitalCertificate nodeCert = rootCA.issueCertificate(nodeId, node.getPublicKey(), 730);
            if (nodeCert != null && rootCA.verifyCertificate(nodeCert)) {
                identityChain.registerNodeCertificate(nodeCert); nodeCertMap.put(nodeId, nodeCert);
                SystemLogger.log("节点 " + nodeId + " 对象已创建并获得证书。");
            } else { throw new RuntimeException("无法为节点颁发或验证证书: " + nodeId); }
        }
        SystemLogger.log(tempNodeMap.size() + " 个节点对象已创建。");

        // 4. *** Nodes Join the Network (Registration & Discovery) ***
        // 4. *** 节点加入网络（注册与发现）***
        SystemLogger.log("开始让节点加入网络...");
        for (Node node : tempNodeMap.values()) {
            node.joinNetwork(SEED_NODES); // Call join method 调用 join 方法
        }
        // Verify registration in NetworkManager
        // 验证 NetworkManager 中的注册
        if (networkManager.getAllNodeIds().size() != nodeIds.size()) { throw new RuntimeException("并非所有节点都已成功注册到 NetworkManager。"); }
        SystemLogger.log(networkManager.getAllNodeIds().size() + " 个节点已加入网络并注册。");


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

        // 6. Group Key Distribution (AFTER nodes joined)
        // 6. 群组密钥分发（节点加入后）
        var groupAESKey = GroupCommUtil.generateGroupKey(); if (groupAESKey == null) throw new RuntimeException("无法生成群组密钥。");
        SystemLogger.log("开始分发群组密钥...");
        for (String nodeId : networkManager.getAllNodeIds()) {
            Node node = networkManager.getNodeById(nodeId); if (node != null) {
                String encryptedGroupKey = GroupCommUtil.encryptGroupKeyForNode(groupAESKey, node.getPublicKey());
                if (encryptedGroupKey != null) node.receiveGroupKey(encryptedGroupKey); else SystemLogger.error("无法为节点 " + node.getId() + " 加密群组密钥。");
            } else { SystemLogger.error("警告：在群组密钥分发期间找不到节点 " + nodeId); }
        } SystemLogger.log("群组密钥分发完成。");

        // 7. Threshold Key Setup
        // 7. 门限密钥设置
        electionKey = CryptoUtil.generateAESKey(128); if (electionKey == null) throw new RuntimeException("无法生成选举密钥。");
        BigInteger secret = new BigInteger(1, electionKey.getEncoded());
        keyShares = ThresholdScheme.generateSharesFromSecret(secret, 3, 2); if (keyShares == null || keyShares.length != 3) throw new RuntimeException("无法生成门限密钥分片。");
        SystemLogger.log("门限密钥分片已生成。");

        // 8. Generate and Distribute Initial CRL (AFTER nodes joined)
        // 8. 生成并分发初始 CRL（节点加入后）
        SystemLogger.log("开始生成初始 CRL...");
        X509CRL initialCRL = rootCA.generateCRL(7); if (initialCRL != null) {
            SystemLogger.log("开始向所有节点分发初始 CRL...");
            for (String nodeId : networkManager.getAllNodeIds()) { Node node = networkManager.getNodeById(nodeId); if (node != null) { node.updateCRL(initialCRL); }
            else { SystemLogger.error("警告：在 CRL 分发期间找不到节点 " + nodeId); } }
            SystemLogger.log("初始 CRL 分发完成。");
        } else { SystemLogger.error("严重警告：无法生成初始 CRL。吊销检查将无法工作。"); }
        SystemLogger.log("系统初始化完成。");
    }

    /** Runs a simple test scenario for CRL functionality using NetworkManager. */
    /** 使用 NetworkManager 运行 CRL 功能的简单测试场景。 */
    private void runCRLTestScenario() {
        new Thread(() -> {
            SystemLogger.log("\n--- 开始运行 CRL 测试场景 ---");
            Node senderNode = networkManager.getNodeById("Node1"); // Use specific ID 使用特定 ID
            if (senderNode == null) { SystemLogger.error("CRL 测试错误：无法从 NetworkManager 获取发送节点 (Node1)。"); return; }

            String testMessage = "CRLTest: 来自 " + senderNode.getId() + " 的消息 (吊销前)";
            SystemLogger.log("\n步骤 1: " + senderNode.getId() + " 广播消息 (吊销前)..."); senderNode.broadcast(testMessage);
            try { Thread.sleep(500); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

            SystemLogger.log("\n步骤 2: 吊销节点 " + senderNode.getId() + " 的证书..."); DigitalCertificate senderCert = identityChain.getCertificateForNode(senderNode.getId());
            if (senderCert != null) { rootCA.revokeCertificate(senderCert); } else { SystemLogger.error("CRL 测试错误：找不到节点 " + senderNode.getId() + " 的证书进行吊销。"); return; }
            try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

            SystemLogger.log("\n步骤 3: 生成并分发更新后的 CRL..."); X509CRL updatedCRL = rootCA.generateCRL(7);
            if (updatedCRL != null) { for (String nodeId : networkManager.getAllNodeIds()) { Node node = networkManager.getNodeById(nodeId); if (node != null) { node.updateCRL(updatedCRL); } } }
            else { SystemLogger.error("CRL 测试错误：无法生成更新后的 CRL。"); return; }
            try { Thread.sleep(100); } catch (InterruptedException e) { Thread.currentThread().interrupt(); }

            SystemLogger.log("\n步骤 4: " + senderNode.getId() + " 广播消息 (吊销后)..."); String testMessageAfter = "CRLTest: 来自 " + senderNode.getId() + " 的消息 (吊销后)"; senderNode.broadcast(testMessageAfter);
            SystemLogger.log("\n--- CRL 测试场景完成 ---");
        }).start();
    }


    // --- Other methods (createAndRegisterUser, createIdentityBlock, authenticate, castVote, updateResults, buildResultString, main, extractCN) ---
    // --- 其他方法 (createAndRegisterUser, createIdentityBlock, authenticate, castVote, updateResults, buildResultString, main, extractCN) ---
    private void createAndRegisterUser(String username) {
        KeyPair userKP = KeyUtil.generateRSAKeyPair(); if (userKP == null) { SystemLogger.error("无法为用户生成密钥对: " + username); return; }
        DigitalCertificate userCert = rootCA.issueCertificate(username, userKP.getPublic(), 365);
        if (userCert != null && rootCA.verifyCertificate(userCert)) { users.put(username, new UserCredentials(userKP, userCert)); SystemLogger.log("成功创建并认证用户: " + username); }
        else { SystemLogger.error("无法创建或验证用户证书: " + username); }
    }
    private Block createIdentityBlock(DigitalCertificate cert) {
        Block last = identityChain.getLastBlock(); Block b = new Block(last.getIndex() + 1, last.getHash());
        String payload = "ADD_VOTER:Subject=" + cert.getSubject() + ",SN=" + cert.getSerialNumber(); Transaction tx = new Transaction(Transaction.Type.IDENTITY, payload);
        b.addTransaction(tx); b.finalizeBlock(); return b;
    }
    private boolean authenticate(String username) {
        UserCredentials creds = users.get(username); if (creds != null) {
            if (rootCA.verifyCertificate(creds.certificate) && creds.certificate.isValid()) { SystemLogger.log("用户认证成功 (用于UI目的): " + username); return true; }
            else { SystemLogger.error("认证失败：证书无效或无法验证 " + username); return false; }
        } SystemLogger.error("认证失败：找不到用户 " + username); return false;
    }
    private void castVote(String candidate, UserCredentials voter) {
        if (voter == null || voter.certificate == null) { SystemLogger.error("无法投票，投票者凭据无效。"); showAlert(Alert.AlertType.ERROR, "投票错误", "投票者凭据无效。"); return; }
        String voterId = extractCN(voter.certificate.getSubject()); SystemLogger.log("用户 " + voterId + " 正在为 " + candidate + " 投票...");
        String encryptedVote = CryptoUtil.encryptAES(candidate, electionKey); if (encryptedVote == null) { SystemLogger.error("投票加密失败，用户: " + voterId); showAlert(Alert.AlertType.ERROR, "投票错误", "加密投票失败。"); return; }
        SystemLogger.log("投票已加密，用户: " + voterId); SystemLogger.log("开始为投票令牌获取盲签名，用户: " + voterId);
        BigInteger token = BigInteger.valueOf(System.currentTimeMillis()).add(BigInteger.valueOf(new SecureRandom().nextInt())); BigInteger rsaN = BlindSignatureUtil.getN(); BigInteger rsaE = BlindSignatureUtil.getE();
        BigInteger blindingFactor = BlindSignatureUtil.generateBlindingFactor(rsaN); BigInteger blindedMessage = BlindSignatureUtil.blindMessage(token, blindingFactor, rsaE, rsaN);
        BigInteger signedBlindedMessage = BlindSignatureUtil.blindSign(blindedMessage); BigInteger finalSignature = BlindSignatureUtil.unblindSignature(signedBlindedMessage, blindingFactor, rsaN);
        if (!BlindSignatureUtil.verifySignature(token, finalSignature)) { SystemLogger.error("盲签名验证失败！用户: " + voterId); } else { SystemLogger.log("盲签名成功获取并验证，用户: " + voterId); }
        String payload = encryptedVote + "|" + finalSignature.toString(16); Transaction voteTx = new Transaction(Transaction.Type.VOTE, payload); SystemLogger.log("投票交易已创建，用户: " + voterId);
        Block lastBlock = votingChain.getLastBlock(); Block newBlock = new Block(lastBlock.getIndex() + 1, lastBlock.getHash()); newBlock.addTransaction(voteTx);
        int nonce = 0; String prefix = "0".repeat(votingChain.difficulty); String blockHash; long startTime = System.currentTimeMillis(); SystemLogger.log("开始为区块 " + newBlock.getIndex() + " 挖掘 (难度: " + votingChain.difficulty + ")...");
        do { String dataToHash = newBlock.getIndex() + newBlock.getPrevHash() + newBlock.getTimestamp() + newBlock.getTransactions().toString() + nonce; blockHash = CryptoUtil.sha256(dataToHash); nonce++;
            if (System.currentTimeMillis() - startTime > 60000) { SystemLogger.error("挖矿超时！区块 " + newBlock.getIndex()); showAlert(Alert.AlertType.ERROR, "挖矿错误", "挖矿超时，无法添加区块。"); return; }
        } while (!blockHash.startsWith(prefix));
        long endTime = System.currentTimeMillis(); SystemLogger.log("区块 " + newBlock.getIndex() + " 已挖掘! Nonce = " + (nonce - 1) + ", Hash = " + blockHash.substring(0,12) + "..., 耗时 = " + (endTime-startTime) + "ms"); newBlock.setHash(blockHash);
        if (votingChain.addBlock(newBlock)) { voteCount++; SystemLogger.log("投票交易已添加到投票链的区块 #" + newBlock.getIndex()); updateResults(); }
        else { SystemLogger.error("无法将已挖掘的区块 #" + newBlock.getIndex() + " 添加到投票链！"); showAlert(Alert.AlertType.ERROR, "链错误", "无法将区块添加到投票链。"); }
    }
    private void updateResults() {
        if (keyShares == null || keyShares.length < 2) { SystemLogger.error("无法更新结果：门限分片不足。"); Platform.runLater(() -> resultLabel.setText("错误：门限密钥分片不足。")); return; }
        SystemLogger.log("请求更新投票结果..."); try {
            SystemLogger.log("正在恢复计票密钥..."); ThresholdScheme.Share s1 = keyShares[0]; ThresholdScheme.Share s2 = keyShares[1]; BigInteger recoveredSecretBI = ThresholdScheme.recoverSecret(s1, s2);
            int keyLengthBytes = electionKey.getEncoded().length; SecretKey tallyKey = CryptoUtil.secretKeyFromBigInteger(recoveredSecretBI, keyLengthBytes);
            if (tallyKey == null) { SystemLogger.error("无法从恢复的秘密重构计票密钥。"); Platform.runLater(() -> resultLabel.setText("错误：无法恢复计票密钥。")); return; } SystemLogger.log("计票密钥已成功恢复。");
            Map<String, Integer> voteCounts = votingChain.getLatestVoteCounts(tallyKey);
            if (voteCounts.isEmpty() && !votingChain.isCacheValid()) { SystemLogger.error("计票失败，无法显示结果。"); Platform.runLater(() -> resultLabel.setText("错误：计票失败。")); return; }
            int totalDecryptedVotes = voteCounts.values().stream().mapToInt(Integer::intValue).sum();
            final String resultText = buildResultString(voteCounts, totalDecryptedVotes, voteCount);
            Platform.runLater(() -> resultLabel.setText(resultText)); SystemLogger.log("投票结果 UI 已更新。");
        } catch (Exception e) { final String errorMsg = "错误：计票时发生异常。\n" + e.getMessage(); Platform.runLater(() -> resultLabel.setText(errorMsg)); SystemLogger.error("计票时出错:"); e.printStackTrace(); }
    }
    private String buildResultString(Map<String, Integer> counts, int decryptedTotal, int txTotal) {
        StringBuilder sb = new StringBuilder(); sb.append(String.format("总有效投票数: %d (来自 %d 笔投票交易)\n", decryptedTotal, txTotal));
        for (String candidate : CANDIDATES) { // Use predefined order 使用预定义顺序
            sb.append(String.format("%s: %d\n", candidate, counts.getOrDefault(candidate, 0)));
        }
        return sb.toString();
    }
    private String extractCN(String dn) {
        if (dn == null) return "Unknown"; String[] parts = dn.split(",");
        for (String part : parts) { String trimmedPart = part.trim(); if (trimmedPart.toUpperCase().startsWith("CN=")) { return trimmedPart.substring(3); } }
        return dn;
    }
    public static void main(String[] args) { launch(args); }
}