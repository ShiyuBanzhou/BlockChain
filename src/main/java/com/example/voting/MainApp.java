package com.example.voting;

import com.example.voting.blockchain.*;
import com.example.voting.crypto.*;
import com.example.voting.network.GroupCommUtil;
import com.example.voting.network.Node;
import javafx.application.Application;
import javafx.scene.Scene;
import javafx.scene.control.*;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;
import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.KeyPair;
import java.util.Arrays;
import java.util.List;
import java.util.Set;

public class MainApp extends Application {
    private CertificateAuthority rootCA;
    private IdentityBlockchain identityChain;
    private VotingBlockchain votingChain;
    private List<Node> nodes;
    private ThresholdScheme.Share[] keyShares;
    private SecretKey electionKey;
    private int voteCount = 0;
    private Label resultLabel;

    @Override
    public void start(Stage stage) {
        initSystem();

        stage.setTitle("区块链匿名投票系统");
        ChoiceBox<String> userBox = new ChoiceBox<>();
        userBox.getItems().addAll("VoterAlice", "VoterBob");
        userBox.setValue("VoterAlice");
        Button loginBtn = new Button("登录");
        Label status = new Label("请选择身份并登录");
        VBox loginPane = new VBox(10, userBox, loginBtn, status);
        Scene loginScene = new Scene(loginPane, 300, 150);

        Label welcome = new Label();
        ListView<String> list = new ListView<>();
        list.getItems().addAll("候选人1", "候选人2", "候选人3");
        Button voteBtn = new Button("投票");
        resultLabel = new Label("尚未投票");
        VBox votePane = new VBox(10, welcome, list, voteBtn, resultLabel);
        Scene voteScene = new Scene(votePane, 400, 300);

        loginBtn.setOnAction(e -> {
            String user = userBox.getValue();
            if (authenticate(user)) {
                welcome.setText("欢迎，" + user + "，请选择候选人。");
                stage.setScene(voteScene);
            } else {
                status.setText("身份验证失败");
            }
        });

        voteBtn.setOnAction(e -> {
            String choice = list.getSelectionModel().getSelectedItem();
            castVote(choice);
        });

        stage.setScene(loginScene);
        stage.show();
    }

    /** 系统初始化：CA、区块链、节点、群组密钥、门限分片 */
    private void initSystem() {
        rootCA = new CertificateAuthority("RootCA");
        KeyPair aliceKP = GroupCommUtil.generateNodeKeyPair();
        KeyPair bobKP   = GroupCommUtil.generateNodeKeyPair();
        DigitalCertificate ca = rootCA.issueCertificate("VoterAlice", aliceKP, 365);
        DigitalCertificate cb = rootCA.issueCertificate("VoterBob", bobKP, 365);

        identityChain = new IdentityBlockchain(1, Set.of());
        votingChain  = new VotingBlockchain(2);
        identityChain.addBlock(createIdentityBlock(ca));
        identityChain.addBlock(createIdentityBlock(cb));

        Node n1 = new Node("Node1", identityChain, votingChain);
        Node n2 = new Node("Node2", identityChain, votingChain);
        Node n3 = new Node("Node3", identityChain, votingChain);
        nodes = Arrays.asList(n1,n2,n3);
        var gk = GroupCommUtil.generateGroupKey();
        for (Node n : nodes) {
            String ek = GroupCommUtil.encryptGroupKeyForNode(gk, n.getPublicKey());
            n.receiveGroupKey(ek);
        }
        // 1) 先生成一个 128bit 的 AES key 作为“投票加密密钥”
        electionKey = CryptoUtil.generateAESKey();

        // 2) 把这个 key 转成大整数，然后做门限分片
        BigInteger secret = new BigInteger(1, electionKey.getEncoded());
        keyShares = ThresholdScheme.generateSharesFromSecret(secret);
    }

    private Block createIdentityBlock(DigitalCertificate cert) {
        Block last = identityChain.getLastBlock();
        Block b = new Block(last.getIndex()+1, last.getHash());
        String p = "ADD_VOTER:" + cert.getSubject() + ",SN=" + cert.getSerialNumber();
        b.addTransaction(new Transaction(Transaction.Type.IDENTITY, p));
        b.finalizeBlock();
        return b;
    }

    private boolean authenticate(String user) {
        return "VoterAlice".equals(user) || "VoterBob".equals(user);
    }

    private void castVote(String candidate) {
        voteCount++;
        String enc = CryptoUtil.encryptAES(candidate, electionKey);
        BigInteger token = BigInteger.valueOf(System.currentTimeMillis());
        BigInteger blind = BlindSignatureUtil.blindMessage(token, new BigInteger("17"));
        BigInteger sb = BlindSignatureUtil.blindSign(blind);
        BigInteger sig = BlindSignatureUtil.unblindSignature(sb);
        String payload = enc + "|credSig=" + sig.toString(16);
        Transaction tx = new Transaction(Transaction.Type.VOTE, payload);

        // PoW 挖矿并加块
        Block last = votingChain.getLastBlock();
        Block nb = new Block(last.getIndex()+1, last.getHash());
        nb.addTransaction(tx);
        int nonce = 0;
        String prefix = "0".repeat(votingChain.difficulty);
        String h;
        do {
            String data = nb.getIndex()+nb.getPrevHash()+nb.getTimestamp()+nb.getTransactions().toString()+nonce;
            h = CryptoUtil.sha256(data);
            nonce++;
        } while (!h.startsWith(prefix));
        nb.addTransaction(new Transaction(Transaction.Type.OTHER, "Nonce=" + (nonce-1)));
        nb.finalizeBlock();
        votingChain.addBlock(nb);

        updateResults();
    }

    /**
     * 从投票链上读取所有投票，门限恢复出 AES 密钥后解密并统计
     */
    private void updateResults() {
        // 1) 用任意两份分片恢复出原始的“秘密”大整数
        ThresholdScheme.Share s1 = keyShares[0];
        ThresholdScheme.Share s2 = keyShares[1];
        BigInteger recoveredSecret = ThresholdScheme.recoverSecret(s1, s2);

        // 2) 按照 electionKey 原始字节长度重构出同样长度的 AES SecretKey
        int keyLen = electionKey.getEncoded().length;  // e.g. 16 字节
        SecretKey tallyKey = CryptoUtil.secretKeyFromBigInteger(recoveredSecret, keyLen);

        // 3) 遍历投票链，解密每笔投票并计数
        int c1 = 0, c2 = 0, c3 = 0;
        for (Block block : votingChain.getChain()) {
            for (Transaction tx : block.getTransactions()) {
                if (tx.getType() == Transaction.Type.VOTE) {
                    // tx.payload 格式：<Base64_AES密文>|credSig=...
                    String cipherText = tx.getPayload().split("\\|")[0];
                    String vote = CryptoUtil.decryptAES(cipherText, tallyKey);
                    switch (vote) {
                        case "候选人1": c1++; break;
                        case "候选人2": c2++; break;
                        case "候选人3": c3++; break;
                    }
                }
            }
        }

        // 4) 更新界面显示
        resultLabel.setText(String.format(
                "总投票数：%d\n候选人1：%d\n候选人2：%d\n候选人3：%d",
                voteCount, c1, c2, c3
        ));
    }

    public static void main(String[] args) {
        launch(args);
    }
}
