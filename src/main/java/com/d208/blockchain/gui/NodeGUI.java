package com.d208.blockchain.gui;

import com.d208.blockchain.model.*;
import com.d208.blockchain.network.Node;
// 工具类和证书类需要引入
import com.d208.blockchain.utils.CertificateManager;
import com.d208.blockchain.utils.ECDSAUtils; // 尽管部分调用被替换，但签名逻辑可能仍间接使用

import javax.swing.*;
import java.awt.*;
import java.math.BigDecimal;
import java.security.cert.X509Certificate; // 引入 X509Certificate
import java.text.SimpleDateFormat; // 用于格式化日期
import java.util.HashMap;
import java.util.Objects;

public class NodeGUI extends JFrame {
    Node node;

    Container container;
    JPanel mainPanel;

    JPanel showNodePanel;
    JPanel showBlockPanel;
    JPanel showTxPanel;
    JPanel showUTXOPanel;
    JPanel makeTxPanel;
    String utxoStr;
    JTextArea UTXOInfoTA;
    JScrollPane UTXOInfoJSP;

    Block targetBlock;

    // 定义日期格式化器
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss Z");


    // 中文字符串常量
    private static final String TITLE_PREFIX = "节点端口: ";
    private static final String NODE_INFO_BTN = "节点信息";
    private static final String FIND_BLOCK_BTN = "查询区块";
    private static final String FIND_TX_BTN = "查询交易";
    private static final String UTXO_BTN = "UTXO 查看";
    private static final String MAKE_TX_BTN = "发起交易";
    private static final String NODE_INDEX_LABEL = "节点编号";
    private static final String NODE_PORT_LABEL = "监听端口";
    // --- 修改节点信息标签 ---
    private static final String NODE_CERT_SUBJECT_LABEL = "证书主体 (Subject DN)"; // 替换原地址标签
    private static final String NODE_CERT_ISSUER_LABEL = "证书颁发者 (Issuer DN)"; // 新增
    private static final String NODE_CERT_VALID_FROM_LABEL = "证书有效期自"; // 新增
    private static final String NODE_CERT_VALID_TO_LABEL = "证书有效期至"; // 新增
    private static final String NODE_PUBLIC_KEY_LABEL = "节点公钥 (Base64)"; // 新增，用于显示公钥
    // --- 修改结束 ---
    private static final String MINER_LABEL = "是否为矿工";
    private static final String BLOCK_IDX_LABEL = "区块索引 (高度)";
    private static final String INPUT_PLACEHOLDER = "请在此输入...";
    private static final String TIMESTAMP_LABEL = "时间戳";
    private static final String HASH_LABEL = "区块哈希";
    private static final String PREV_HASH_LABEL = "上一区块哈希";
    private static final String ROOT_HASH_LABEL = "默克尔根哈希";
    private static final String DIFFICULTY_LABEL = "难度";
    private static final String NONCE_LABEL = "随机数 (Nonce)";
    private static final String FIND_BTN = "查询";
    private static final String TX_IN_BLOCK_IDX_LABEL = "所属区块索引:";
    private static final String TX_IDX_IN_BLOCK_LABEL = "区块内交易索引:";
    private static final String TX_ID_LABEL = "交易ID (TxId)";
    private static final String TX_INPUT_LABEL = "交易输入 (TxIn)";
    private static final String TX_OUTPUT_LABEL = "交易输出 (TxOut)";
    private static final String INPUT_TXOUT_ID_LABEL = "引用的交易输出ID:";
    private static final String INPUT_TXOUT_IDX_LABEL = "引用的交易输出索引:";
    private static final String INPUT_SIGNATURE_LABEL = "签名:";
    private static final String OUTPUT_ADDRESS_LABEL = "接收地址 (公钥 Base64):"; // 明确地址是公钥
    private static final String OUTPUT_AMOUNT_LABEL = "金额:";
    private static final String UTXO_INFO_TITLE = "未花费交易输出 (UTXO) 列表";
    private static final String MAKE_TX_INPUT_ID_LABEL = "使用的UTXO交易ID";
    private static final String MAKE_TX_INPUT_IDX_LABEL = "使用的UTXO索引";
    private static final String MAKE_TX_ADDRESS_LABEL = "接收方地址 (公钥 Base64)"; // 明确需要输入公钥
    private static final String MAKE_TX_AMOUNT_LABEL = "转账金额";
    private static final String SEND_BTN = "发送";
    private static final String UTXO_FORMAT = "交易ID: %s\n输出索引: %s\n金额: %s\n地址(公钥): %s\n\n"; // UTXO显示地址


    public NodeGUI(Node node){
        this.node = node;

        this.showNodePanel = new JPanel();
        this.showBlockPanel = new JPanel();
        this.showTxPanel = new JPanel();
        this.showUTXOPanel = new JPanel();
        this.makeTxPanel = new JPanel();

        this.setTitle(TITLE_PREFIX + node.getPort());
        this.setLocation(500, 500); // Consider dynamic positioning if multiple GUIs are launched
        this.setSize(new Dimension(650, 700)); // Increased size for more info
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.container = this.getContentPane();
        container.setLayout(new BorderLayout());

        JPanel northPanel = new JPanel();
        northPanel.setLayout(new FlowLayout());
        container.add(northPanel, BorderLayout.NORTH);
        addButtons(northPanel);

        mainPanel = new JPanel();
        mainPanel.setLayout(new CardLayout());
        container.add(mainPanel, BorderLayout.CENTER);

        // Initialize panels - call methods that set up components
        setShowNodePanel();
        setShowBlockPanel();
        setShowTxPanel();
        setShowUTXOPanel();
        setMkTxPanel();

        // Add panels to CardLayout
        mainPanel.add(showNodePanel, NODE_INFO_BTN);
        mainPanel.add(showBlockPanel, FIND_BLOCK_BTN);
        mainPanel.add(showTxPanel, FIND_TX_BTN);
        mainPanel.add(showUTXOPanel, UTXO_BTN);
        mainPanel.add(makeTxPanel, MAKE_TX_BTN);

        // Show default panel
        showPanel(NODE_INFO_BTN);

        this.setVisible(true);
    }

    private void showPanel(String panelName) {
        CardLayout cl = (CardLayout)(mainPanel.getLayout());
        cl.show(mainPanel, panelName);
        if (Objects.equals(panelName, UTXO_BTN)) {
            updateUTXO();
        }
    }

    // ========================================================================
    // Step 4: 更新节点信息面板以显示证书信息
    // ========================================================================
    public void setShowNodePanel() {
        showNodePanel.setLayout(null); // Using absolute layout
        showNodePanel.setPreferredSize(new Dimension(600, 650)); // Adjusted size

        int currentY = 30; // Starting Y position
        int labelWidth = 180;
        int fieldWidth = 400;
        int fieldX = 200;
        int spacing = 40; // Spacing between rows

        // Node Index
        JLabel nodeIndexLabel = new JLabel(NODE_INDEX_LABEL);
        nodeIndexLabel.setBounds(30, currentY, labelWidth, 20);
        showNodePanel.add(nodeIndexLabel);
        JTextField nodeIndexTF = new JTextField(String.valueOf(node.getIndex()));
        nodeIndexTF.setBounds(fieldX, currentY, fieldWidth, 20);
        nodeIndexTF.setEditable(false);
        showNodePanel.add(nodeIndexTF);
        currentY += spacing;

        // Node Port
        JLabel nodePortLabel = new JLabel(NODE_PORT_LABEL);
        nodePortLabel.setBounds(30, currentY, labelWidth, 20);
        showNodePanel.add(nodePortLabel);
        JTextField nodePortTF = new JTextField(String.valueOf(node.getPort()));
        nodePortTF.setBounds(fieldX, currentY, fieldWidth, 20);
        nodePortTF.setEditable(false);
        showNodePanel.add(nodePortTF);
        currentY += spacing;

        // Certificate Subject DN
        JLabel certSubjectLabel = new JLabel(NODE_CERT_SUBJECT_LABEL);
        certSubjectLabel.setBounds(30, currentY, labelWidth, 20);
        showNodePanel.add(certSubjectLabel);
        JTextArea certSubjectTA = new JTextArea();
        certSubjectTA.setLineWrap(true);
        certSubjectTA.setWrapStyleWord(true);
        certSubjectTA.setEditable(false);
        // Extract Subject DN from certificate
        if (node.getCertificate() instanceof X509Certificate) {
            certSubjectTA.setText(((X509Certificate) node.getCertificate()).getSubjectX500Principal().getName());
        } else {
            certSubjectTA.setText("N/A");
        }
        JScrollPane subjectScrollPane = new JScrollPane(certSubjectTA);
        subjectScrollPane.setBounds(fieldX, currentY, fieldWidth, 60); // Increased height for DN
        showNodePanel.add(subjectScrollPane);
        currentY += 60 + spacing/2; // Adjust spacing after multi-line field

        // Certificate Issuer DN
        JLabel certIssuerLabel = new JLabel(NODE_CERT_ISSUER_LABEL);
        certIssuerLabel.setBounds(30, currentY, labelWidth, 20);
        showNodePanel.add(certIssuerLabel);
        JTextArea certIssuerTA = new JTextArea();
        certIssuerTA.setLineWrap(true);
        certIssuerTA.setWrapStyleWord(true);
        certIssuerTA.setEditable(false);
        // Extract Issuer DN from certificate
        if (node.getCertificate() instanceof X509Certificate) {
            certIssuerTA.setText(((X509Certificate) node.getCertificate()).getIssuerX500Principal().getName());
        } else {
            certIssuerTA.setText("N/A");
        }
        JScrollPane issuerScrollPane = new JScrollPane(certIssuerTA);
        issuerScrollPane.setBounds(fieldX, currentY, fieldWidth, 60); // Increased height for DN
        showNodePanel.add(issuerScrollPane);
        currentY += 60 + spacing/2; // Adjust spacing

        // Certificate Valid From
        JLabel validFromLabel = new JLabel(NODE_CERT_VALID_FROM_LABEL);
        validFromLabel.setBounds(30, currentY, labelWidth, 20);
        showNodePanel.add(validFromLabel);
        JTextField validFromTF = new JTextField();
        validFromTF.setEditable(false);
        if (node.getCertificate() instanceof X509Certificate) {
            validFromTF.setText(DATE_FORMAT.format(((X509Certificate) node.getCertificate()).getNotBefore()));
        } else {
            validFromTF.setText("N/A");
        }
        validFromTF.setBounds(fieldX, currentY, fieldWidth, 20);
        showNodePanel.add(validFromTF);
        currentY += spacing;

        // Certificate Valid To
        JLabel validToLabel = new JLabel(NODE_CERT_VALID_TO_LABEL);
        validToLabel.setBounds(30, currentY, labelWidth, 20);
        showNodePanel.add(validToLabel);
        JTextField validToTF = new JTextField();
        validToTF.setEditable(false);
        if (node.getCertificate() instanceof X509Certificate) {
            validToTF.setText(DATE_FORMAT.format(((X509Certificate) node.getCertificate()).getNotAfter()));
        } else {
            validToTF.setText("N/A");
        }
        validToTF.setBounds(fieldX, currentY, fieldWidth, 20);
        showNodePanel.add(validToTF);
        currentY += spacing;

        // Public Key Display (Base64)
        JLabel pubKeyLabel = new JLabel(NODE_PUBLIC_KEY_LABEL);
        pubKeyLabel.setBounds(30, currentY, labelWidth, 20);
        showNodePanel.add(pubKeyLabel);
        JTextArea pubKeyTA = new JTextArea(CertificateManager.getPubKeyStr(node.getCertificate()));
        pubKeyTA.setLineWrap(true);
        pubKeyTA.setWrapStyleWord(true);
        pubKeyTA.setEditable(false);
        JScrollPane pubKeyScrollPane = new JScrollPane(pubKeyTA);
        pubKeyScrollPane.setBounds(fieldX, currentY, fieldWidth, 80); // Height for key
        showNodePanel.add(pubKeyScrollPane);
        currentY += 80 + spacing/2;

        // Miner Status
        JLabel minerLabel = new JLabel(MINER_LABEL);
        minerLabel.setBounds(30, currentY, labelWidth, 20);
        showNodePanel.add(minerLabel);
        JTextField minerTF = new JTextField(String.valueOf(node.getMine()));
        minerTF.setBounds(fieldX, currentY, fieldWidth, 20);
        minerTF.setEditable(false);
        showNodePanel.add(minerTF);
        // currentY += spacing; // No need to increment Y if it's the last element
    }
    // ========================================================================
    // 节点信息面板更新结束
    // ========================================================================


    public void setShowBlockPanel() {
        showBlockPanel.setPreferredSize(new Dimension(500, 500));
        showBlockPanel.setLayout(null);

        JLabel BlockIDX = new JLabel(BLOCK_IDX_LABEL);
        BlockIDX.setBounds(30, 30, 150, 20);
        showBlockPanel.add(BlockIDX);
        JTextField blockIDXTF = new JTextField();
        blockIDXTF.setText(INPUT_PLACEHOLDER);
        blockIDXTF.setForeground(Color.GRAY);
        blockIDXTF.setBounds(200, 30, 300, 20);
        blockIDXTF.addFocusListener(new java.awt.event.FocusAdapter() {
            public void focusGained(java.awt.event.FocusEvent evt) {
                if (blockIDXTF.getText().equals(INPUT_PLACEHOLDER)) {
                    blockIDXTF.setText("");
                    blockIDXTF.setForeground(Color.BLACK);
                }
            }
            public void focusLost(java.awt.event.FocusEvent evt) {
                if (blockIDXTF.getText().isEmpty()) {
                    blockIDXTF.setForeground(Color.GRAY);
                    blockIDXTF.setText(INPUT_PLACEHOLDER);
                }
            }
        });
        showBlockPanel.add(blockIDXTF);


        JLabel Timestamp = new JLabel(TIMESTAMP_LABEL);
        Timestamp.setBounds(30, 80, 150, 20);
        showBlockPanel.add(Timestamp);
        JTextField timestampTF = new JTextField();
        timestampTF.setBounds(200, 80, 300, 20);
        timestampTF.setEditable(false);
        showBlockPanel.add(timestampTF);

        JLabel Hash = new JLabel(HASH_LABEL);
        Hash.setBounds(30, 130, 150, 20);
        showBlockPanel.add(Hash);
        JTextField hashTF = new JTextField();
        hashTF.setBounds(200, 130, 300, 20);
        hashTF.setEditable(false);
        showBlockPanel.add(hashTF);

        JLabel PreviousHash = new JLabel(PREV_HASH_LABEL);
        PreviousHash.setBounds(30, 180, 150, 20);
        showBlockPanel.add(PreviousHash);
        JTextField previousHashTF = new JTextField();
        previousHashTF.setBounds(200, 180, 300, 20);
        previousHashTF.setEditable(false);
        showBlockPanel.add(previousHashTF);

        JLabel rootHash = new JLabel(ROOT_HASH_LABEL);
        rootHash.setBounds(30, 230, 150, 20);
        showBlockPanel.add(rootHash);
        JTextField rootHashTF = new JTextField();
        rootHashTF.setBounds(200, 230, 300, 20);
        rootHashTF.setEditable(false);
        showBlockPanel.add(rootHashTF);

        JLabel Difficulty = new JLabel(DIFFICULTY_LABEL);
        Difficulty.setBounds(30, 280, 150, 20);
        showBlockPanel.add(Difficulty);
        JTextField difficultyTF = new JTextField();
        difficultyTF.setBounds(200, 280, 300, 20);
        difficultyTF.setEditable(false);
        showBlockPanel.add(difficultyTF);

        JLabel nonce = new JLabel(NONCE_LABEL);
        nonce.setBounds(30, 330, 150, 20);
        showBlockPanel.add(nonce);
        JTextField nonceTF = new JTextField();
        nonceTF.setBounds(200, 330, 300, 20);
        nonceTF.setEditable(false);
        showBlockPanel.add(nonceTF);

        JButton findNode = new JButton(FIND_BTN);
        findNode.setBounds(210, 380, 80, 30);
        showBlockPanel.add(findNode);

        findNode.addActionListener(e -> {
            String idxStr = blockIDXTF.getText();
            if (idxStr.equals(INPUT_PLACEHOLDER) || idxStr.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请输入有效的区块索引！", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            try {
                int idx = Integer.parseInt(idxStr);
                // Access local chain safely
                java.util.List<Block> localChain = node.getLocalChain(); // Get a safe copy
                if (idx < 0 || idx >= localChain.size()) {
                    JOptionPane.showMessageDialog(this, "区块索引超出范围！(链高: " + localChain.size() + ")", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                targetBlock = localChain.get(idx); // Use the copy
                timestampTF.setText(String.valueOf(targetBlock.getTimestamp()));
                hashTF.setText(targetBlock.getHash());
                previousHashTF.setText(targetBlock.getPreviousHash());
                rootHashTF.setText(targetBlock.getRootHash());
                difficultyTF.setText(String.valueOf(targetBlock.getDifficulty()));
                nonceTF.setText(String.valueOf(targetBlock.getNonce()));
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, "区块索引必须是数字！", "错误", JOptionPane.ERROR_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "查询区块时发生错误: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                ex.printStackTrace();
            }
        });
    }

    public void setShowTxPanel() {
        showTxPanel.setPreferredSize(new Dimension(500, 500));
        showTxPanel.setLayout(null);

        JLabel blockIdxLabel = new JLabel(TX_IN_BLOCK_IDX_LABEL);
        blockIdxLabel.setBounds(30, 10, 150, 20);
        showTxPanel.add(blockIdxLabel);
        JTextField blockIdxTF = new JTextField();
        blockIdxTF.setBounds(200, 10, 300, 20);
        showTxPanel.add(blockIdxTF);

        JLabel txIdxLabel = new JLabel(TX_IDX_IN_BLOCK_LABEL);
        txIdxLabel.setBounds(30, 35, 150, 20);
        showTxPanel.add(txIdxLabel);
        JTextField txIdxTF = new JTextField();
        txIdxTF.setBounds(200, 35, 300, 20);
        showTxPanel.add(txIdxTF);

        JButton findBtn = new JButton(FIND_BTN);
        findBtn.setBounds(200, 65, 100, 25);
        showTxPanel.add(findBtn);

        JLabel txIdLabel = new JLabel(TX_ID_LABEL);
        txIdLabel.setBounds(30, 100, 150, 20);
        showTxPanel.add(txIdLabel);
        JTextField txIdTF = new JTextField("",20);
        txIdTF.setEditable(false);
        txIdTF.setBounds(200, 100, 300, 20);
        showTxPanel.add(txIdTF);

        JLabel txInputTitle = new JLabel(TX_INPUT_LABEL);
        txInputTitle.setBounds(30, 130, 100, 20);
        showTxPanel.add(txInputTitle);

        JLabel txOutputTitle = new JLabel(TX_OUTPUT_LABEL);
        txOutputTitle.setBounds(270, 130, 100, 20);
        showTxPanel.add(txOutputTitle);

        // --- Input Info ---
        JLabel InputIDLabel = new JLabel(INPUT_TXOUT_ID_LABEL);
        InputIDLabel.setBounds(30, 160, 150, 20);
        showTxPanel.add(InputIDLabel);
        JTextField InputIDTF = new JTextField("",20);
        InputIDTF.setEditable(false);
        InputIDTF.setBounds(30, 185, 200, 20);
        showTxPanel.add(InputIDTF);

        JLabel InputIndexLabel = new JLabel(INPUT_TXOUT_IDX_LABEL);
        InputIndexLabel.setBounds(30, 215, 150, 20);
        showTxPanel.add(InputIndexLabel);
        JTextField InputIndexTF = new JTextField();
        InputIndexTF.setEditable(false);
        InputIndexTF.setBounds(30, 240, 200, 20);
        showTxPanel.add(InputIndexTF);

        JLabel InputSignatureLabel = new JLabel(INPUT_SIGNATURE_LABEL);
        InputSignatureLabel.setBounds(30, 270, 150, 20);
        showTxPanel.add(InputSignatureLabel);
        JTextArea InputSignatureTA = new JTextArea();
        InputSignatureTA.setEditable(false);
        InputSignatureTA.setLineWrap(true);
        InputSignatureTA.setWrapStyleWord(true);
        JScrollPane signatureScrollPane = new JScrollPane(InputSignatureTA);
        signatureScrollPane.setBounds(30, 295, 200, 60);
        showTxPanel.add(signatureScrollPane);

        // --- Output Info ---
        JLabel OutputAddressLabel = new JLabel(OUTPUT_ADDRESS_LABEL);
        OutputAddressLabel.setBounds(270, 160, 180, 20); // Increased width for label
        showTxPanel.add(OutputAddressLabel);
        JTextArea OutputAddressTA = new JTextArea();
        OutputAddressTA.setEditable(false);
        OutputAddressTA.setLineWrap(true);
        OutputAddressTA.setWrapStyleWord(true);
        JScrollPane outAddrScrollPane = new JScrollPane(OutputAddressTA);
        outAddrScrollPane.setBounds(270, 185, 200, 50);
        showTxPanel.add(outAddrScrollPane);

        JLabel OutputAmountLabel = new JLabel(OUTPUT_AMOUNT_LABEL);
        OutputAmountLabel.setBounds(270, 245, 150, 20);
        showTxPanel.add(OutputAmountLabel);
        JTextField OutputAmountTF = new JTextField();
        OutputAmountTF.setBounds(270, 270, 200, 20);
        OutputAmountTF.setEditable(false);
        showTxPanel.add(OutputAmountTF);

        findBtn.addActionListener(e -> {
            try {
                int blockIdx = Integer.parseInt(blockIdxTF.getText());
                int txIdx = Integer.parseInt(txIdxTF.getText());

                // Access local chain safely
                java.util.List<Block> localChain = node.getLocalChain(); // Get a safe copy
                if (blockIdx < 0 || blockIdx >= localChain.size()) {
                    JOptionPane.showMessageDialog(this, "区块索引超出范围！(链高: " + localChain.size() + ")", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                Block block = localChain.get(blockIdx); // Use the copy

                if (txIdx < 0 || block.getTransactionList() == null || txIdx >= block.getTransactionList().size()) {
                    String txListSize = (block.getTransactionList() == null) ? "null" : String.valueOf(block.getTransactionList().size());
                    JOptionPane.showMessageDialog(this, "区块内交易索引超出范围！(交易数: " + txListSize + ")", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                Transaction transaction = block.getTransactionList().get(txIdx);

                txIdTF.setText(transaction.getId());

                // Clear old data
                InputIDTF.setText("");
                InputIndexTF.setText("");
                InputSignatureTA.setText("");
                OutputAddressTA.setText("");
                OutputAmountTF.setText("");

                // Display first input (if exists)
                if (transaction.getTxIns() != null && transaction.getTxIns().length > 0) {
                    TxIn firstIn = transaction.getTxIns()[0];
                    if ("coinbase".equals(firstIn.signature)) {
                        InputIDTF.setText("N/A (Coinbase)");
                        InputIndexTF.setText(String.valueOf(firstIn.txOutIndex)); // Show block height
                        InputSignatureTA.setText("Coinbase");
                    } else {
                        InputIDTF.setText(firstIn.txOutId);
                        InputIndexTF.setText(String.valueOf(firstIn.txOutIndex));
                        InputSignatureTA.setText(firstIn.signature);
                    }
                } else {
                    InputIDTF.setText("No Inputs");
                }

                // Display first output (if exists)
                if (transaction.getTxOuts() != null && transaction.getTxOuts().length > 0) {
                    TxOut firstOut = transaction.getTxOuts()[0];
                    OutputAddressTA.setText(firstOut.address);
                    OutputAmountTF.setText(String.valueOf(firstOut.amount));
                }
                // If more inputs/outputs need display, a JTable or similar is required

            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, "索引必须是数字！", "错误", JOptionPane.ERROR_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "查询交易时发生错误: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                ex.printStackTrace();
            }
        });
    }

    public void setShowUTXOPanel() {
        showUTXOPanel.setLayout(new BorderLayout());
        showUTXOPanel.setBorder(BorderFactory.createTitledBorder(UTXO_INFO_TITLE));

        UTXOInfoTA = new JTextArea();
        UTXOInfoTA.setEditable(false);
        UTXOInfoTA.setLineWrap(true);
        UTXOInfoTA.setWrapStyleWord(true);

        UTXOInfoJSP = new JScrollPane(UTXOInfoTA);
        UTXOInfoJSP.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        showUTXOPanel.add(UTXOInfoJSP, BorderLayout.CENTER);
    }

    public void updateUTXO(){
        utxoStr = formatUTXO();
        UTXOInfoTA.setText(utxoStr);
        UTXOInfoTA.setCaretPosition(0);
    }

    // Format UTXO for display, including address
    public String formatUTXO(){
        HashMap<String, TxOut> map = node.getUtxo(); // Gets a safe copy
        StringBuilder utxoBuilder = new StringBuilder();
        if (map.isEmpty()) {
            return "当前节点没有可用的 UTXO";
        }
        String myAddress = CertificateManager.getPubKeyStr(node.getCertificate());
        for (String key : map.keySet()) {
            String[] parts = key.split("\\s+");
            if (parts.length == 2) {
                String id = parts[0];
                String idx = parts[1];
                TxOut txOut = map.get(key);
                // Check if the UTXO address belongs to the current node
                boolean isMine = txOut.address.equals(myAddress);
                if (isMine) {
                    utxoBuilder.append("** 我的 UTXO **\n"); // Highlight owned UTXOs
                }
                // Include address in the output format string
                utxoBuilder.append(String.format(UTXO_FORMAT, id, idx, txOut.amount, txOut.address));
            }
        }
        return utxoBuilder.toString();
    }


    public void setMkTxPanel() {
        makeTxPanel.setPreferredSize(new Dimension(500, 500));
        makeTxPanel.setLayout(null);

        JLabel TxInoutIdLabel = new JLabel(MAKE_TX_INPUT_ID_LABEL);
        TxInoutIdLabel.setBounds(30, 30, 150, 20);
        makeTxPanel.add(TxInoutIdLabel);
        JTextArea TxInoutIdTA = new JTextArea();
        TxInoutIdTA.setLineWrap(true);
        TxInoutIdTA.setWrapStyleWord(true);
        JScrollPane txInIdScrollPane = new JScrollPane(TxInoutIdTA);
        txInIdScrollPane.setBounds(200, 30, 300, 60);
        makeTxPanel.add(txInIdScrollPane);

        JLabel TxInoutIdxLabel = new JLabel(MAKE_TX_INPUT_IDX_LABEL);
        TxInoutIdxLabel.setBounds(30, 100, 150, 20);
        makeTxPanel.add(TxInoutIdxLabel);
        JTextField TxInoutIdxTF = new JTextField();
        TxInoutIdxTF.setBounds(200, 100, 300, 20);
        makeTxPanel.add(TxInoutIdxTF);


        JLabel TxAddressLabel = new JLabel(MAKE_TX_ADDRESS_LABEL);
        TxAddressLabel.setBounds(30, 130, 180, 20); // Increased width for label
        makeTxPanel.add(TxAddressLabel);
        JTextArea TxAddressTA = new JTextArea();
        TxAddressTA.setLineWrap(true);
        TxAddressTA.setWrapStyleWord(true);
        JScrollPane txAddrScrollPane = new JScrollPane(TxAddressTA);
        txAddrScrollPane.setBounds(200, 130, 300, 80);
        makeTxPanel.add(txAddrScrollPane);

        JLabel MakeTxAmountLabel = new JLabel(MAKE_TX_AMOUNT_LABEL);
        MakeTxAmountLabel.setBounds(30, 220, 150, 20);
        makeTxPanel.add(MakeTxAmountLabel);
        JTextField MakeTxAmountTF = new JTextField();
        MakeTxAmountTF.setBounds(200, 220, 300, 20);
        makeTxPanel.add(MakeTxAmountTF);

        JButton sendBtn = new JButton(SEND_BTN);
        sendBtn.setBounds(240, 270, 100, 30);
        makeTxPanel.add(sendBtn);

        sendBtn.addActionListener(e -> {
            String inputTxOutId = TxInoutIdTA.getText().trim();
            String inputTxOutIndexStr = TxInoutIdxTF.getText().trim();
            String targetAddress = TxAddressTA.getText().trim(); // Expecting Base64 public key string
            String amountStr = MakeTxAmountTF.getText().trim();

            if (inputTxOutId.isEmpty() || inputTxOutIndexStr.isEmpty() || targetAddress.isEmpty() || amountStr.isEmpty()) {
                JOptionPane.showMessageDialog(this, "所有字段均为必填项！", "输入错误", JOptionPane.WARNING_MESSAGE);
                return;
            }

            try {
                int inputTxOutIndex = Integer.parseInt(inputTxOutIndexStr);
                double amount = Double.parseDouble(amountStr);

                if (amount <= 0) {
                    JOptionPane.showMessageDialog(this, "转账金额必须大于 0！", "输入错误", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                // --- UTXO and Ownership Validation (crucial) ---
                String utxoKey = inputTxOutId + " " + inputTxOutIndex;
                HashMap<String, TxOut> currentUtxo = node.getUtxo(); // Get a safe copy
                if (!currentUtxo.containsKey(utxoKey)) {
                    JOptionPane.showMessageDialog(this, "提供的 UTXO ID 或索引无效或已被花费！", "错误", JOptionPane.ERROR_MESSAGE);
                    updateUTXO(); // Refresh display in case it was spent recently
                    return;
                }
                TxOut utxoToSpend = currentUtxo.get(utxoKey);

                // Validate ownership: Check if the address in the UTXO matches this node's public key
                String myAddress = CertificateManager.getPubKeyStr(node.getCertificate());
                if (!utxoToSpend.address.equals(myAddress)) {
                    JOptionPane.showMessageDialog(this, "您不拥有要花费的 UTXO！", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                // --- Validation End ---

                // Validate amount
                if (utxoToSpend.amount < amount) {
                    JOptionPane.showMessageDialog(this, "UTXO 金额 (" + utxoToSpend.amount + ") 不足以支付转账金额 (" + amount + ")！", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                // Generate signature using node's internal method
                // The message signed is the ID of the transaction output being spent
                String signature = node.signMessage(inputTxOutId);
                if (signature == null) {
                    JOptionPane.showMessageDialog(this, "无法生成交易签名！", "签名错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                TxIn in = new TxIn(inputTxOutId, inputTxOutIndex, signature);
                TxOut out = new TxOut(targetAddress, amount); // Target output

                // Handle change
                TxOut changeOutput = null;
                // Use BigDecimal for precise calculation of change
                BigDecimal change = BigDecimal.valueOf(utxoToSpend.amount).subtract(BigDecimal.valueOf(amount));
                // If change is greater than zero (using compareTo)
                if (change.compareTo(BigDecimal.ZERO) > 0) {
                    // Send change back to self
                    changeOutput = new TxOut(myAddress, change.doubleValue()); // Convert back to double for TxOut
                }

                // Prepare transaction inputs and outputs
                TxIn[] ins = {in};
                TxOut[] outs;
                if (changeOutput != null) {
                    outs = new TxOut[]{out, changeOutput}; // Transfer + Change
                } else {
                    outs = new TxOut[]{out}; // Only transfer (exact amount or no change needed)
                }

                // --- Initiate Transaction via Node ---
                // The node's initTx method now performs the validation internally
                node.initTx(ins, outs);
                // Success/failure messages are handled by initTx/validation logic,
                // or you can add more specific GUI feedback if needed.

                // Clear fields only if initTx was successful (maybe initTx should return a boolean?)
                // For now, clear regardless, assuming success message is sufficient.
                TxInoutIdTA.setText("");
                TxInoutIdxTF.setText("");
                TxAddressTA.setText("");
                MakeTxAmountTF.setText("");
                // Update UTXO display after attempting transaction
                updateUTXO();


            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, "索引和金额必须是有效的数字！", "输入错误", JOptionPane.WARNING_MESSAGE);
            } catch (Exception ex) { // Catch potential errors from initTx or other issues
                JOptionPane.showMessageDialog(this, "创建或发送交易时发生错误: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                ex.printStackTrace();
            }
        });
    }

    public void addButtons(JPanel panel) {
        JButton showNodeBtn = new JButton(NODE_INFO_BTN);
        JButton showBlockBtn = new JButton(FIND_BLOCK_BTN);
        JButton showTxBtn = new JButton(FIND_TX_BTN);
        JButton showUTXOBtn = new JButton(UTXO_BTN);
        JButton mkTxBtn = new JButton(MAKE_TX_BTN);

        showNodeBtn.addActionListener(e -> showPanel(NODE_INFO_BTN));
        showBlockBtn.addActionListener(e -> showPanel(FIND_BLOCK_BTN));
        showTxBtn.addActionListener(e -> showPanel(FIND_TX_BTN));
        showUTXOBtn.addActionListener(e -> showPanel(UTXO_BTN));
        mkTxBtn.addActionListener(e -> showPanel(MAKE_TX_BTN));

        panel.add(showNodeBtn);
        panel.add(showBlockBtn);
        panel.add(showTxBtn);
        panel.add(showUTXOBtn);
        panel.add(mkTxBtn);
    }
}