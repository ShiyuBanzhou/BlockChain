package com.example.voting;

import com.example.voting.blockchain.*;
import com.example.voting.crypto.*;
import com.example.voting.network.GroupCommUtil;
import com.example.voting.network.NetworkManager;
import com.example.voting.network.Node;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.geometry.Insets; // Import Insets
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.BorderPane; // Use BorderPane for layout 使用 BorderPane 进行布局
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
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MainApp extends Application {

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            // System.out.println("Registering Bouncy Castle security provider..."); // Less noise 减少噪音
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
    private Label resultLabel; // Voting result display 投票结果显示
    private TextArea logArea; // Area for displaying logs 用于显示日志的区域
    private Map<String, UserCredentials> users = new HashMap<>(); // Voter credentials 选民凭据
    // loggedInUser might not be strictly needed anymore if we simulate all votes
    // 如果我们模拟所有投票，loggedInUser 可能不再严格需要
    // private UserCredentials loggedInUser = null;

    private static class UserCredentials {
        final KeyPair keyPair;
        final DigitalCertificate certificate;
        UserCredentials(KeyPair kp, DigitalCertificate cert) { this.keyPair = kp; this.certificate = cert; }
    }

    @Override
    public void start(Stage stage) {
        try {
            initSystem(); // Initialize backend components 初始化后端组件
            setupUI(stage); // Setup the user interface 设置用户界面
            // runCRLTestScenario(); // Run test scenario after UI is shown? Or triggered by button? 在 UI 显示后运行测试场景？还是由按钮触发？
        } catch (Exception e) {
            handleInitializationError(e);
            return;
        }
    }

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
        stage.setTitle("区块链安全机制演示"); // Update title 更新标题

        // --- Log Area ---
        logArea = new TextArea();
        logArea.setEditable(false);
        logArea.setWrapText(true);
        logArea.setPrefHeight(300); // Set preferred height 设置首选高度
        SystemLogger.setLogTextArea(logArea); // Configure logger 配置记录器
        SystemLogger.setConsoleOutputEnabled(false); // Disable duplicate console logs 禁用重复的控制台日志
        SystemLogger.log("系统界面初始化...");

        // --- Voting Control Panel ---
        Label voterLabel = new Label("选择模拟投票者:");
        ChoiceBox<String> voterSelectBox = new ChoiceBox<>();
        voterSelectBox.getItems().addAll(users.keySet()); // Populate with voter names 从选民名称填充
        if (!users.isEmpty()) {
            voterSelectBox.setValue(users.keySet().iterator().next()); // Default to first voter 默认为第一个选民
        }

        Label candidateLabel = new Label("选择候选人:");
        ListView<String> candidateList = new ListView<>();
        candidateList.getItems().addAll("候选人1", "候选人2", "候选人3");
        candidateList.setPrefHeight(100); // Limit height 限制高度

        Button voteBtn = new Button("模拟投票");
        resultLabel = new Label("投票结果将在此显示"); // Initial text 初始文本

        // Add CRL Test Button
        Button crlTestBtn = new Button("运行 CRL 测试");
        crlTestBtn.setOnAction(e -> runCRLTestScenario()); // Trigger test scenario 触发测试场景

        VBox voteControls = new VBox(10,
                voterLabel, voterSelectBox,
                candidateLabel, candidateList,
                voteBtn, resultLabel,
                new Separator(), // Add a separator 添加分隔符
                crlTestBtn
        );
        voteControls.setPadding(new Insets(10));

        // --- Main Layout (BorderPane) ---
        BorderPane rootLayout = new BorderPane();
        rootLayout.setTop(voteControls); // Voting controls at the top 顶部投票控件
        rootLayout.setCenter(logArea); // Log area in the center 中央日志区域

        // --- Scene and Stage ---
        Scene scene = new Scene(rootLayout, 600, 550); // Adjust size 调整大小
        stage.setScene(scene);
        stage.show();
        SystemLogger.log("系统界面已就绪。");

        // --- Button Action ---
        voteBtn.setOnAction(e -> {
            String selectedVoterId = voterSelectBox.getValue();
            String selectedCandidate = candidateList.getSelectionModel().getSelectedItem();

            if (selectedVoterId == null) {
                SystemLogger.error("请先选择一个投票者！");
                showAlert(Alert.AlertType.WARNING, "输入错误", "请选择一个投票者。");
                return;
            }
            if (selectedCandidate == null) {
                SystemLogger.error("请先选择一个候选人！");
                showAlert(Alert.AlertType.WARNING, "输入错误", "请选择一个候选人。");
                return;
            }

            UserCredentials voterCreds = users.get(selectedVoterId);
            if (voterCreds == null) {
                SystemLogger.error("内部错误：找不到投票者 '" + selectedVoterId + "' 的凭据！");
                showAlert(Alert.AlertType.ERROR, "内部错误", "找不到选定的投票者凭据。");
                return;
            }

            // Run voting in a background thread to avoid blocking UI during mining
            // 在后台线程中运行投票以避免在挖掘期间阻塞 UI
            SystemLogger.log("开始为 " + selectedVoterId + " 模拟投票给 " + selectedCandidate);
            new Thread(() -> castVote(selectedCandidate, voterCreds)).start(); // Pass credentials 传递凭据

        });
    }

    /** Helper to show alerts */
    /** 显示警报的辅助方法 */
    private void showAlert(Alert.AlertType type, String title, String message) {
        Platform.runLater(() -> {
            Alert alert = new Alert(type);
            alert.setTitle(title);
            alert.setHeaderText(null);
            alert.setContentText(message);
            alert.showAndWait();
        });
    }


    /** System initialization */
    /** 系统初始化 */
    private void initSystem() throws Exception {
        SystemLogger.log("开始系统初始化...");

        // 0. Network Manager
        // 0. 网络管理器
        networkManager = new NetworkManager();
        SystemLogger.log("NetworkManager 已初始化。");

        // 1. CA
        // 1. CA
        rootCA = new CertificateAuthority("VotingRootCA");
        SystemLogger.log("根 CA (VotingRootCA) 已初始化。");

        // 2. Blockchains
        // 2. 区块链
        identityChain = new IdentityBlockchain(1, null);
        votingChain = new VotingBlockchain(2);
        SystemLogger.log("身份链和投票链已初始化。");

        // 3. Nodes & Node Certificates
        // 3. 节点和节点证书
        List<String> nodeIds = Arrays.asList("Node1", "Node2", "Node3");
        Map<String, DigitalCertificate> nodeCertMap = new HashMap<>();
        SystemLogger.log("开始初始化网络节点...");
        for (String nodeId : nodeIds) {
            Node node = new Node(nodeId, identityChain, votingChain, rootCA.getPublicKey(), networkManager);
            // Node registers itself with NetworkManager in constructor
            // 节点在其构造函数中向 NetworkManager 注册自己
            DigitalCertificate nodeCert = rootCA.issueCertificate(nodeId, node.getPublicKey(), 730);
            if (nodeCert != null && rootCA.verifyCertificate(nodeCert)) {
                identityChain.registerNodeCertificate(nodeCert);
                nodeCertMap.put(nodeId, nodeCert);
                SystemLogger.log("节点 " + nodeId + " 已初始化并获得证书 (SN: ..." + nodeCert.getSerialNumber().substring(nodeCert.getSerialNumber().length()-6) + ")");
            } else {
                throw new RuntimeException("无法为节点颁发或验证证书: " + nodeId);
            }
        }
        if (networkManager.getAllNodeIds().size() != nodeIds.size()) {
            throw new RuntimeException("并非所有节点都已成功注册到 NetworkManager。");
        }
        SystemLogger.log(networkManager.getAllNodeIds().size() + " 个节点已初始化并注册。");

        // 4. Voter Users & Certificates
        // 4. 选民用户和证书
        SystemLogger.log("开始创建选民用户...");
        createAndRegisterUser("VoterAlice");
        createAndRegisterUser("VoterBob");
        for (UserCredentials user : users.values()) {
            Block idBlock = createIdentityBlock(user.certificate);
            if (!identityChain.addBlock(idBlock)) {
                SystemLogger.error("无法为选民添加身份区块: " + user.certificate.getSubject());
            }
        }
        SystemLogger.log(users.size() + " 个选民用户已创建并注册到身份链。");
        SystemLogger.log("身份链当前状态:\n" + identityChain);

        // 5. Group Key Distribution
        // 5. 群组密钥分发
        var groupAESKey = GroupCommUtil.generateGroupKey();
        if (groupAESKey == null) throw new RuntimeException("无法生成群组密钥。");
        SystemLogger.log("开始分发群组密钥...");
        for (String nodeId : networkManager.getAllNodeIds()) {
            Node node = networkManager.getNodeById(nodeId);
            if (node != null) {
                String encryptedGroupKey = GroupCommUtil.encryptGroupKeyForNode(groupAESKey, node.getPublicKey());
                if (encryptedGroupKey != null) node.receiveGroupKey(encryptedGroupKey);
                else SystemLogger.error("无法为节点 " + node.getId() + " 加密群组密钥。");
            }
        }
        SystemLogger.log("群组密钥分发完成。");

        // 6. Threshold Key Setup
        // 6. 门限密钥设置
        electionKey = CryptoUtil.generateAESKey(128);
        if (electionKey == null) throw new RuntimeException("无法生成选举密钥。");
        BigInteger secret = new BigInteger(1, electionKey.getEncoded());
        keyShares = ThresholdScheme.generateSharesFromSecret(secret, 3, 2); // n=3, t=2
        if (keyShares == null || keyShares.length != 3) throw new RuntimeException("无法生成门限密钥分片。");
        SystemLogger.log("门限密钥分片已生成。");

        // 7. Generate and Distribute Initial CRL
        // 7. 生成并分发初始 CRL
        SystemLogger.log("开始生成初始 CRL...");
        X509CRL initialCRL = rootCA.generateCRL(7);
        if (initialCRL != null) {
            SystemLogger.log("开始向所有节点分发初始 CRL...");
            for (String nodeId : networkManager.getAllNodeIds()) {
                Node node = networkManager.getNodeById(nodeId);
                if (node != null) {
                    node.updateCRL(initialCRL);
                }
            }
            SystemLogger.log("初始 CRL 分发完成。");
        } else {
            SystemLogger.error("严重警告：无法生成初始 CRL。吊销检查将无法工作。");
        }
        SystemLogger.log("系统初始化完成。");
    }

    /** Runs a simple test scenario for CRL functionality. */
    /** 运行 CRL 功能的简单测试场景。 */
    private void runCRLTestScenario() {
        List<String> nodeIds = networkManager.getAllNodeIds();
        if (nodeIds.size() < 2) {
            SystemLogger.log("CRL 测试场景：节点不足，无法运行测试。");
            return;
        }
        SystemLogger.log("\n--- 开始运行 CRL 测试场景 ---");

        Node senderNode = networkManager.getNodeById(nodeIds.get(0)); // Node1
        if (senderNode == null) { SystemLogger.error("CRL 测试错误：无法从 NetworkManager 获取发送节点。"); return; }

        String testMessage = "CRLTest: 来自 Node1 的消息 (吊销前)";

        // 1. Test communication BEFORE revocation
        // 1. 测试吊销前的通信
        SystemLogger.log("\n步骤 1: " + senderNode.getId() + " 广播消息 (吊销前)...");
        senderNode.broadcast(testMessage);

        // 2. Revoke Sender's Certificate
        // 2. 吊销发送者的证书
        SystemLogger.log("\n步骤 2: 吊销节点 " + senderNode.getId() + " 的证书...");
        DigitalCertificate senderCert = identityChain.getCertificateForNode(senderNode.getId());
        if (senderCert != null) {
            rootCA.revokeCertificate(senderCert);
        } else {
            SystemLogger.error("CRL 测试错误：找不到节点 " + senderNode.getId() + " 的证书进行吊销。");
            return;
        }

        // 3. Generate and Distribute NEW CRL
        // 3. 生成并分发新的 CRL
        SystemLogger.log("\n步骤 3: 生成并分发更新后的 CRL...");
        X509CRL updatedCRL = rootCA.generateCRL(7);
        if (updatedCRL != null) {
            for (String nodeId : networkManager.getAllNodeIds()) {
                Node node = networkManager.getNodeById(nodeId);
                if (node != null) {
                    node.updateCRL(updatedCRL);
                }
            }
        } else {
            SystemLogger.error("CRL 测试错误：无法生成更新后的 CRL。");
            return;
        }

        // 4. Test communication AFTER revocation
        // 4. 测试吊销后的通信
        SystemLogger.log("\n步骤 4: " + senderNode.getId() + " 广播消息 (吊销后)...");
        String testMessageAfter = "CRLTest: 来自 Node1 的消息 (吊销后)";
        senderNode.broadcast(testMessageAfter);

        SystemLogger.log("\n--- CRL 测试场景完成 ---");
    }


    // --- Other methods ---
    // --- 其他方法 ---
    private void createAndRegisterUser(String username) {
        KeyPair userKP = KeyUtil.generateRSAKeyPair();
        if (userKP == null) { SystemLogger.error("无法为用户生成密钥对: " + username); return; }
        DigitalCertificate userCert = rootCA.issueCertificate(username, userKP.getPublic(), 365);
        if (userCert != null && rootCA.verifyCertificate(userCert)) {
            users.put(username, new UserCredentials(userKP, userCert));
            SystemLogger.log("成功创建并认证用户: " + username);
        } else {
            SystemLogger.error("无法创建或验证用户证书: " + username);
        }
    }
    private Block createIdentityBlock(DigitalCertificate cert) {
        Block last = identityChain.getLastBlock();
        Block b = new Block(last.getIndex() + 1, last.getHash());
        String payload = "ADD_VOTER:Subject=" + cert.getSubject() + ",SN=" + cert.getSerialNumber();
        Transaction tx = new Transaction(Transaction.Type.IDENTITY, payload);
        b.addTransaction(tx);
        b.finalizeBlock();
        return b;
    }
    private boolean authenticate(String username) {
        // Authentication might not be needed if we simulate votes directly
        // 如果我们直接模拟投票，则可能不需要身份验证
        UserCredentials creds = users.get(username);
        if (creds != null) {
            if (rootCA.verifyCertificate(creds.certificate) && creds.certificate.isValid()) {
                // loggedInUser = creds; // We don't necessarily need to track loggedInUser now 我们现在不一定需要跟踪 loggedInUser
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
    private void castVote(String candidate, UserCredentials voter) { // Now takes UserCredentials 现在接受 UserCredentials
        if (voter == null || voter.certificate == null) {
            SystemLogger.error("无法投票，投票者凭据无效。");
            showAlert(Alert.AlertType.ERROR, "投票错误", "投票者凭据无效。");
            return;
        }
        String voterId = extractCN(voter.certificate.getSubject()); // Get voter CN 获取选民 CN
        SystemLogger.log("用户 " + voterId + " 正在为 " + candidate + " 投票...");

        // 1. Encrypt vote
        // 1. 加密投票
        String encryptedVote = CryptoUtil.encryptAES(candidate, electionKey);
        if (encryptedVote == null) {
            SystemLogger.error("投票加密失败，用户: " + voterId);
            showAlert(Alert.AlertType.ERROR, "投票错误", "加密投票失败。");
            return;
        }
        SystemLogger.log("投票已加密，用户: " + voterId);

        // 2. Blind Signature (using insecure demo util)
        // 2. 盲签名（使用不安全的演示工具）
        SystemLogger.log("开始为投票令牌获取盲签名，用户: " + voterId);
        BigInteger token = BigInteger.valueOf(System.currentTimeMillis()).add(BigInteger.valueOf(new SecureRandom().nextInt()));
        BigInteger rsaN = BlindSignatureUtil.getN(); BigInteger rsaE = BlindSignatureUtil.getE();
        BigInteger blindingFactor = BlindSignatureUtil.generateBlindingFactor(rsaN);
        BigInteger blindedMessage = BlindSignatureUtil.blindMessage(token, blindingFactor, rsaE, rsaN);
        BigInteger signedBlindedMessage = BlindSignatureUtil.blindSign(blindedMessage); // Simulate authority 模拟权威机构
        BigInteger finalSignature = BlindSignatureUtil.unblindSignature(signedBlindedMessage, blindingFactor, rsaN);
        if (!BlindSignatureUtil.verifySignature(token, finalSignature)) {
            SystemLogger.error("盲签名验证失败！用户: " + voterId);
            // showAlert(Alert.AlertType.WARNING, "签名警告", "盲签名验证失败。"); // Might continue anyway 可能无论如何都继续
        } else {
            SystemLogger.log("盲签名成功获取并验证，用户: " + voterId);
        }

        // 3. Create Transaction
        // 3. 创建交易
        String payload = encryptedVote + "|" + finalSignature.toString(16);
        Transaction voteTx = new Transaction(Transaction.Type.VOTE, payload);
        SystemLogger.log("投票交易已创建，用户: " + voterId);

        // 4. Mine Block (PoW)
        // 4. 挖掘区块 (PoW)
        Block lastBlock = votingChain.getLastBlock();
        Block newBlock = new Block(lastBlock.getIndex() + 1, lastBlock.getHash());
        newBlock.addTransaction(voteTx);
        int nonce = 0;
        String prefix = "0".repeat(votingChain.difficulty);
        String blockHash;
        long startTime = System.currentTimeMillis();
        SystemLogger.log("开始为区块 " + newBlock.getIndex() + " 挖掘 (难度: " + votingChain.difficulty + ")...");
        do {
            String dataToHash = newBlock.getIndex() + newBlock.getPrevHash() + newBlock.getTimestamp() + newBlock.getTransactions().toString() + nonce;
            blockHash = CryptoUtil.sha256(dataToHash);
            nonce++;
            // Add a timeout check to prevent infinite loops
            // 添加超时检查以防止无限循环
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
        // 5. 将区块添加到投票链
        if (votingChain.addBlock(newBlock)) {
            voteCount++;
            SystemLogger.log("投票交易已添加到投票链的区块 #" + newBlock.getIndex());
            updateResults(); // Update UI results 更新 UI 结果
        } else {
            SystemLogger.error("无法将已挖掘的区块 #" + newBlock.getIndex() + " 添加到投票链！");
            showAlert(Alert.AlertType.ERROR, "链错误", "无法将区块添加到投票链。");
        }
    }

    private void updateResults() {
        if (keyShares == null || keyShares.length < 2) {
            SystemLogger.error("无法更新结果：门限分片不足。");
            Platform.runLater(() -> resultLabel.setText("错误：门限密钥分片不足。"));
            return;
        }
        SystemLogger.log("开始更新投票结果...");
        try {
            // 1. Recover Key
            // 1. 恢复密钥
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

            // 2. Tally Votes
            // 2. 统计投票
            Map<String, Integer> voteCounts = new HashMap<>();
            voteCounts.put("候选人1", 0); voteCounts.put("候选人2", 0); voteCounts.put("候选人3", 0);
            int totalDecryptedVotes = 0; int transactionCount = 0;
            List<Block> currentVoteChain = votingChain.getChain(); // Get chain copy 获取链副本
            SystemLogger.log("正在从 " + currentVoteChain.size() + " 个投票区块中计票...");

            for (Block block : currentVoteChain) {
                for (Transaction tx : block.getTransactions()) {
                    transactionCount++;
                    if (tx.getType() == Transaction.Type.VOTE) {
                        String[] parts = tx.getPayload().split("\\|");
                        if (parts.length >= 1) {
                            String cipherTextBase64 = parts[0];
                            String decryptedVote = CryptoUtil.decryptAES(cipherTextBase64, tallyKey);
                            if (decryptedVote != null) {
                                totalDecryptedVotes++;
                                voteCounts.put(decryptedVote, voteCounts.getOrDefault(decryptedVote, 0) + 1);
                            } else { SystemLogger.error("无法解密区块 " + block.getIndex() + " 中的投票, Tx: " + tx); }
                        } else { SystemLogger.error("区块 " + block.getIndex() + " 中无效的投票负载格式, Tx: " + tx); }
                    }
                }
            }
            SystemLogger.log("计票完成。处理的总交易数: " + transactionCount);

            // 3. Update UI
            // 3. 更新 UI
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
    private String buildResultString(Map<String, Integer> counts, int decryptedTotal, int txTotal) {
        StringBuilder sb = new StringBuilder();
        sb.append(String.format("总有效投票数: %d (来自 %d 笔投票交易)\n", decryptedTotal, txTotal));
        counts.forEach((candidate, count) -> sb.append(String.format("%s: %d\n", candidate, count)) );
        return sb.toString();
    }
    private String extractCN(String dn) {
        if (dn == null) return "Unknown";
        String[] parts = dn.split(",");
        for (String part : parts) { String trimmedPart = part.trim(); if (trimmedPart.toUpperCase().startsWith("CN=")) { return trimmedPart.substring(3); } }
        // SystemLogger.error("警告：无法从 DN 中提取 CN: " + dn); // Less noise 减少噪音
        return dn; // Fallback to full DN 回退到完整 DN
    }
    public static void main(String[] args) { launch(args); }
}