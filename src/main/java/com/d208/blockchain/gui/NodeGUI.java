package com.d208.blockchain.gui;

import com.d208.blockchain.model.*;
import com.d208.blockchain.network.Node;
import com.d208.blockchain.utils.ECDSAUtils;

import javax.swing.*;
import java.awt.*;
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

    // 中文字符串常量
    private static final String TITLE_PREFIX = "节点端口: ";
    private static final String NODE_INFO_BTN = "节点信息";
    private static final String FIND_BLOCK_BTN = "查询区块";
    private static final String FIND_TX_BTN = "查询交易";
    private static final String UTXO_BTN = "UTXO 查看";
    private static final String MAKE_TX_BTN = "发起交易";
    private static final String NODE_INDEX_LABEL = "节点编号";
    private static final String NODE_PORT_LABEL = "监听端口";
    private static final String NODE_ADDRESS_LABEL = "节点地址 (公钥)";
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
    private static final String OUTPUT_ADDRESS_LABEL = "接收地址:";
    private static final String OUTPUT_AMOUNT_LABEL = "金额:";
    private static final String UTXO_INFO_TITLE = "未花费交易输出 (UTXO) 列表";
    private static final String MAKE_TX_INPUT_ID_LABEL = "使用的UTXO交易ID";
    private static final String MAKE_TX_INPUT_IDX_LABEL = "使用的UTXO索引";
    private static final String MAKE_TX_ADDRESS_LABEL = "接收方地址";
    private static final String MAKE_TX_AMOUNT_LABEL = "转账金额";
    private static final String SEND_BTN = "发送";
    private static final String UTXO_FORMAT = "交易ID: %s\n输出索引: %s\n金额: %s\n\n";


    public NodeGUI(Node node){
        this.node = node;

        this.showNodePanel = new JPanel();
        this.showBlockPanel = new JPanel();
        this.showTxPanel = new JPanel();
        this.showUTXOPanel = new JPanel();
        this.makeTxPanel = new JPanel();


        this.setTitle(TITLE_PREFIX + node.getPort()); // 设置窗口标题
        this.setLocation(500, 500);
        this.setSize(new Dimension(600, 600));
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.container = this.getContentPane();
        container.setLayout(new BorderLayout());

        JPanel northPanel = new JPanel();
        northPanel.setLayout(new FlowLayout());
        container.add(northPanel, BorderLayout.NORTH);
        addButtons(northPanel); // 添加顶部按钮

        mainPanel = new JPanel();
        mainPanel.setLayout(new CardLayout()); // 使用CardLayout方便切换面板
        container.add(mainPanel, BorderLayout.CENTER);

        // 初始化各个面板
        setShowNodePanel();
        setShowBlockPanel();
        setShowTxPanel();
        setShowUTXOPanel();
        setMkTxPanel();

        // 将面板添加到 CardLayout
        mainPanel.add(showNodePanel, NODE_INFO_BTN);
        mainPanel.add(showBlockPanel, FIND_BLOCK_BTN);
        mainPanel.add(showTxPanel, FIND_TX_BTN);
        mainPanel.add(showUTXOPanel, UTXO_BTN);
        mainPanel.add(makeTxPanel, MAKE_TX_BTN);

        // 默认显示节点信息面板
        showPanel(NODE_INFO_BTN);

        this.setVisible(true);
    }

    // 切换主面板显示的内容
    private void showPanel(String panelName) {
        CardLayout cl = (CardLayout)(mainPanel.getLayout());
        cl.show(mainPanel, panelName);
        // 特殊处理：每次显示 UTXO 面板时都更新内容
        if (Objects.equals(panelName, UTXO_BTN)) {
            updateUTXO();
        }
    }

    // 设置节点信息面板
    public void setShowNodePanel() {
        showNodePanel.setPreferredSize(new Dimension(500, 500));
        showNodePanel.setLayout(null); // 保持 null 布局以匹配原代码，但建议使用布局管理器

        JLabel NodeIndex = new JLabel(NODE_INDEX_LABEL);
        NodeIndex.setBounds(30, 30, 150, 20); // 调整标签宽度
        showNodePanel.add(NodeIndex);
        JTextField NodeIndexTF = new JTextField(String.valueOf(node.getIndex()));
        NodeIndexTF.setBounds(200, 30, 300, 20);
        NodeIndexTF.setEditable(false);
        showNodePanel.add(NodeIndexTF);

        JLabel NodePort = new JLabel(NODE_PORT_LABEL);
        NodePort.setBounds(30, 80, 150, 20);
        showNodePanel.add(NodePort);
        JTextField NodePortTF = new JTextField(String.valueOf(node.getPort()));
        NodePortTF.setBounds(200, 80, 300, 20);
        NodePortTF.setEditable(false);
        showNodePanel.add(NodePortTF);

        JLabel NodeAddress = new JLabel(NODE_ADDRESS_LABEL);
        NodeAddress.setBounds(30, 130, 150, 20);
        showNodePanel.add(NodeAddress);
        JTextArea NodeAddressTA = new JTextArea(ECDSAUtils.getPubKeyStr(node.getPubKey()));
        NodeAddressTA.setBounds(200, 130, 300, 80);
        NodeAddressTA.setLineWrap(true); // 自动换行
        NodeAddressTA.setWrapStyleWord(true); // 按单词换行
        NodeAddressTA.setEditable(false);
        JScrollPane addressScrollPane = new JScrollPane(NodeAddressTA); // 添加滚动条
        addressScrollPane.setBounds(200, 130, 300, 80);
        showNodePanel.add(addressScrollPane);

        JLabel Miner = new JLabel(MINER_LABEL);
        Miner.setBounds(30, 240, 150, 20);
        showNodePanel.add(Miner);
        JTextField MinerTF = new JTextField(String.valueOf(node.getMine()));
        MinerTF.setBounds(200, 240, 300, 20);
        MinerTF.setEditable(false);
        showNodePanel.add(MinerTF);
    }

    // 设置查询区块面板
    public void setShowBlockPanel() {
        showBlockPanel.setPreferredSize(new Dimension(500, 500));
        showBlockPanel.setLayout(null);

        JLabel BlockIDX = new JLabel(BLOCK_IDX_LABEL);
        BlockIDX.setBounds(30, 30, 150, 20);
        showBlockPanel.add(BlockIDX);
        JTextField blockIDXTF = new JTextField();
        blockIDXTF.setText(INPUT_PLACEHOLDER); // 设置提示文本
        blockIDXTF.setForeground(Color.GRAY);
        blockIDXTF.setBounds(200, 30, 300, 20);
        // 添加焦点监听器以清除/恢复提示文本 (可选)
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

        JButton findNode = new JButton(FIND_BTN); // 使用中文按钮文本
        findNode.setBounds(210, 380, 80, 30);
        showBlockPanel.add(findNode);

        findNode.addActionListener(e -> { // 使用 Lambda 表达式简化
            String idxStr = blockIDXTF.getText();
            if (idxStr.equals(INPUT_PLACEHOLDER) || idxStr.isEmpty()) {
                JOptionPane.showMessageDialog(this, "请输入有效的区块索引！", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            try {
                int idx = Integer.parseInt(idxStr);
                if (idx < 0 || idx >= node.getLocalChain().size()) {
                    JOptionPane.showMessageDialog(this, "区块索引超出范围！", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                targetBlock = node.getLocalChain().get(idx);
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
                ex.printStackTrace(); // 打印详细错误到控制台
            }
        });
    }

    // 设置查询交易面板
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

        JButton findBtn = new JButton(FIND_BTN); // 中文按钮
        findBtn.setBounds(200, 65, 100, 25); // 调整位置和大小
        showTxPanel.add(findBtn);

        JLabel txIdLabel = new JLabel(TX_ID_LABEL);
        txIdLabel.setBounds(30, 100, 150, 20); // 调整 Y 坐标
        showTxPanel.add(txIdLabel);
        JTextField txIdTF = new JTextField("",20);
        txIdTF.setEditable(false);
        txIdTF.setBounds(200, 100, 300, 20); // 调整 Y 坐标
        showTxPanel.add(txIdTF);

        JLabel txInputTitle = new JLabel(TX_INPUT_LABEL);
        txInputTitle.setBounds(30, 130, 100, 20); // 调整 Y 坐标
        showTxPanel.add(txInputTitle);

        JLabel txOutputTitle = new JLabel(TX_OUTPUT_LABEL);
        txOutputTitle.setBounds(270, 130, 100, 20); // 调整 Y 坐标
        showTxPanel.add(txOutputTitle);

        // --- 输入信息 ---
        JLabel InputIDLabel = new JLabel(INPUT_TXOUT_ID_LABEL);
        InputIDLabel.setBounds(30, 160, 150, 20); // 调整 Y 坐标和宽度
        showTxPanel.add(InputIDLabel);
        JTextField InputIDTF = new JTextField("",20);
        InputIDTF.setEditable(false);
        InputIDTF.setBounds(30, 185, 200, 20); // 调整 Y 坐标
        showTxPanel.add(InputIDTF);

        JLabel InputIndexLabel = new JLabel(INPUT_TXOUT_IDX_LABEL);
        InputIndexLabel.setBounds(30, 215, 150, 20); // 调整 Y 坐标
        showTxPanel.add(InputIndexLabel);
        JTextField InputIndexTF = new JTextField();
        InputIndexTF.setEditable(false);
        InputIndexTF.setBounds(30, 240, 200, 20); // 调整 Y 坐标
        showTxPanel.add(InputIndexTF);

        JLabel InputSignatureLabel = new JLabel(INPUT_SIGNATURE_LABEL);
        InputSignatureLabel.setBounds(30, 270, 150, 20); // 调整 Y 坐标
        showTxPanel.add(InputSignatureLabel);
        JTextArea InputSignatureTA = new JTextArea(); // 使用 JTextArea 显示可能较长的签名
        InputSignatureTA.setEditable(false);
        InputSignatureTA.setLineWrap(true);
        InputSignatureTA.setWrapStyleWord(true);
        JScrollPane signatureScrollPane = new JScrollPane(InputSignatureTA);
        signatureScrollPane.setBounds(30, 295, 200, 60); // 调整 Y 坐标和高度
        showTxPanel.add(signatureScrollPane);

        // --- 输出信息 ---
        JLabel OutputAddressLabel = new JLabel(OUTPUT_ADDRESS_LABEL);
        OutputAddressLabel.setBounds(270, 160, 150, 20); // 调整 Y 坐标
        showTxPanel.add(OutputAddressLabel);
        JTextArea OutputAddressTA = new JTextArea(); // 使用 JTextArea 显示地址
        OutputAddressTA.setEditable(false);
        OutputAddressTA.setLineWrap(true);
        OutputAddressTA.setWrapStyleWord(true);
        JScrollPane outAddrScrollPane = new JScrollPane(OutputAddressTA);
        outAddrScrollPane.setBounds(270, 185, 200, 50); // 调整 Y 坐标和高度
        showTxPanel.add(outAddrScrollPane);


        JLabel OutputAmountLabel = new JLabel(OUTPUT_AMOUNT_LABEL);
        OutputAmountLabel.setBounds(270, 245, 150, 20); // 调整 Y 坐标
        showTxPanel.add(OutputAmountLabel);
        JTextField OutputAmountTF = new JTextField();
        OutputAmountTF.setBounds(270, 270, 200, 20); // 调整 Y 坐标
        OutputAmountTF.setEditable(false);
        showTxPanel.add(OutputAmountTF);

        findBtn.addActionListener(e -> { // Lambda 表达式
            try {
                int blockIdx = Integer.parseInt(blockIdxTF.getText());
                int txIdx = Integer.parseInt(txIdxTF.getText());

                if (blockIdx < 0 || blockIdx >= node.getLocalChain().size()) {
                    JOptionPane.showMessageDialog(this, "区块索引超出范围！", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                Block block = node.getLocalChain().get(blockIdx);

                if (txIdx < 0 || txIdx >= block.getTransactionList().size()) {
                    JOptionPane.showMessageDialog(this, "区块内交易索引超出范围！", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                Transaction transaction = block.getTransactionList().get(txIdx);

                txIdTF.setText(transaction.getId());

                // 清空旧数据
                InputIDTF.setText("");
                InputIndexTF.setText("");
                InputSignatureTA.setText("");
                OutputAddressTA.setText("");
                OutputAmountTF.setText("");

                // 显示第一个输入和输出（假设至少有一个）
                if (transaction.getTxIns() != null && transaction.getTxIns().length > 0) {
                    TxIn firstIn = transaction.getTxIns()[0];
                    InputIDTF.setText(firstIn.txOutId);
                    InputIndexTF.setText(String.valueOf(firstIn.txOutIndex));
                    InputSignatureTA.setText(firstIn.signature); // 填充 JTextArea
                } else {
                    InputIDTF.setText("N/A (例如 Coinbase)");
                }

                if (transaction.getTxOuts() != null && transaction.getTxOuts().length > 0) {
                    TxOut firstOut = transaction.getTxOuts()[0];
                    OutputAddressTA.setText(firstOut.address); // 填充 JTextArea
                    OutputAmountTF.setText(String.valueOf(firstOut.amount));
                }
                // 如果需要显示所有输入输出，需要更复杂的界面布局，例如 JTable

            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, "索引必须是数字！", "错误", JOptionPane.ERROR_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "查询交易时发生错误: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                ex.printStackTrace();
            }
        });
    }

    // 设置 UTXO 查看面板
    public void setShowUTXOPanel() {
        showUTXOPanel.setLayout(new BorderLayout()); // 使用 BorderLayout
        showUTXOPanel.setBorder(BorderFactory.createTitledBorder(UTXO_INFO_TITLE)); // 添加标题边框

        UTXOInfoTA = new JTextArea();
        UTXOInfoTA.setEditable(false); // 不可编辑
        UTXOInfoTA.setLineWrap(true);
        UTXOInfoTA.setWrapStyleWord(true);

        UTXOInfoJSP = new JScrollPane(UTXOInfoTA);
        UTXOInfoJSP.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);

        showUTXOPanel.add(UTXOInfoJSP, BorderLayout.CENTER); // 添加到中心区域
    }

    // 更新 UTXO 显示区域
    public void updateUTXO(){
        utxoStr = formatUTXO(); // 使用格式化方法
        UTXOInfoTA.setText(utxoStr);
        UTXOInfoTA.setCaretPosition(0); // 滚动到顶部
        // UTXOInfoTA.paintImmediately(UTXOInfoTA.getBounds()); // 通常不需要手动调用 paintImmediately
    }

    // 格式化 UTXO 信息用于显示
    public String formatUTXO(){
        HashMap<String, TxOut> map = node.getUtxo();
        StringBuilder utxoBuilder = new StringBuilder();
        if (map.isEmpty()) {
            return "当前节点没有可用的 UTXO";
        }
        for (String key : map.keySet()) {
            String[] parts = key.split("\\s+"); // Key 格式是 "txId index"
            if (parts.length == 2) {
                String id = parts[0];
                String idx = parts[1];
                TxOut txOut = map.get(key);
                // 检查地址是否属于当前节点，并高亮显示 (可选增强)
                // boolean isMine = txOut.address.equals(ECDSAUtils.getPubKeyStr(node.getPubKey()));
                // utxoBuilder.append(isMine ? "** 我的 UTXO **\n" : "");
                utxoBuilder.append(String.format(UTXO_FORMAT, id, idx, txOut.amount));
            }
        }
        return utxoBuilder.toString();
    }


    // 设置发起交易面板
    public void setMkTxPanel() {
        makeTxPanel.setPreferredSize(new Dimension(500, 500));
        makeTxPanel.setLayout(null);

        JLabel TxInoutIdLabel = new JLabel(MAKE_TX_INPUT_ID_LABEL);
        TxInoutIdLabel.setBounds(30, 30, 150, 20);
        makeTxPanel.add(TxInoutIdLabel);
        JTextArea TxInoutIdTA = new JTextArea(); // 使用 JTextArea
        TxInoutIdTA.setLineWrap(true);
        TxInoutIdTA.setWrapStyleWord(true);
        JScrollPane txInIdScrollPane = new JScrollPane(TxInoutIdTA);
        txInIdScrollPane.setBounds(200, 30, 300, 60);
        makeTxPanel.add(txInIdScrollPane);

        JLabel TxInoutIdxLabel = new JLabel(MAKE_TX_INPUT_IDX_LABEL);
        TxInoutIdxLabel.setBounds(30, 100, 150, 20); // 调整 Y 坐标
        makeTxPanel.add(TxInoutIdxLabel);
        JTextField TxInoutIdxTF = new JTextField();
        TxInoutIdxTF.setBounds(200, 100, 300, 20); // 调整 Y 坐标
        makeTxPanel.add(TxInoutIdxTF);


        JLabel TxAddressLabel = new JLabel(MAKE_TX_ADDRESS_LABEL);
        TxAddressLabel.setBounds(30, 130, 150, 20); // 调整 Y 坐标
        makeTxPanel.add(TxAddressLabel);
        JTextArea TxAddressTA = new JTextArea(); // 使用 JTextArea
        TxAddressTA.setLineWrap(true);
        TxAddressTA.setWrapStyleWord(true);
        JScrollPane txAddrScrollPane = new JScrollPane(TxAddressTA);
        txAddrScrollPane.setBounds(200, 130, 300, 80); // 调整 Y 坐标
        makeTxPanel.add(txAddrScrollPane);

        JLabel MakeTxAmountLabel = new JLabel(MAKE_TX_AMOUNT_LABEL);
        MakeTxAmountLabel.setBounds(30, 220, 150, 20); // 调整 Y 坐标
        makeTxPanel.add(MakeTxAmountLabel);
        JTextField MakeTxAmountTF = new JTextField();
        MakeTxAmountTF.setBounds(200, 220, 300, 20); // 调整 Y 坐标
        makeTxPanel.add(MakeTxAmountTF);

        JButton sendBtn = new JButton(SEND_BTN); // 中文按钮
        sendBtn.setBounds(240, 270, 100, 30); // 调整 Y 坐标
        makeTxPanel.add(sendBtn);


        sendBtn.addActionListener(e -> { // Lambda 表达式
            String inputTxOutId = TxInoutIdTA.getText().trim(); // 去除首尾空格
            String inputTxOutIndexStr = TxInoutIdxTF.getText().trim();
            String targetAddress = TxAddressTA.getText().trim();
            String amountStr = MakeTxAmountTF.getText().trim();

            // 基本输入验证
            if (inputTxOutId.isEmpty() || inputTxOutIndexStr.isEmpty() || targetAddress.isEmpty() || amountStr.isEmpty()) {
                JOptionPane.showMessageDialog(this, "所有字段均为必填项！", "输入错误", JOptionPane.WARNING_MESSAGE);
                return;
            }

            try {
                int inputTxOutIndex = Integer.parseInt(inputTxOutIndexStr);
                double amount = Double.parseDouble(amountStr); // 使用 double 处理金额

                if (amount <= 0) {
                    JOptionPane.showMessageDialog(this, "转账金额必须大于 0！", "输入错误", JOptionPane.WARNING_MESSAGE);
                    return;
                }

                // 从 UTXO 验证输入是否有效且属于自己 (重要补充逻辑)
                String utxoKey = inputTxOutId + " " + inputTxOutIndex;
                if (!node.getUtxo().containsKey(utxoKey)) {
                    JOptionPane.showMessageDialog(this, "提供的 UTXO ID 或索引无效！", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                TxOut utxoToSpend = node.getUtxo().get(utxoKey);

                // 验证地址所有权 (重要补充逻辑)
                // 这里的验证逻辑比较复杂，因为原始TxOut没有直接存储所有者的公钥字符串
                // 简单假设：如果能在本地UTXO找到，就认为是自己的（这不安全，需要改进）
                // 更好的方法是在 Node 类中验证


                if (utxoToSpend.amount < amount) {
                    JOptionPane.showMessageDialog(this, "UTXO 金额不足以支付转账金额！", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }


                // 生成签名
                String signature = ECDSAUtils.signECDSA(node.getPriKey(), inputTxOutId); // 签名内容应该是 inputTxOutId

                TxIn in = new TxIn(inputTxOutId, inputTxOutIndex, signature);
                TxOut out = new TxOut(targetAddress, amount);

                // 处理找零 (重要补充逻辑)
                TxOut changeOutput = null;
                double change = utxoToSpend.amount - amount;
                if (change > 0) { // 如果有找零
                    // 找零地址通常是发送者自己的地址
                    changeOutput = new TxOut(ECDSAUtils.getPubKeyStr(node.getPubKey()), change);
                }


                TxIn[] ins = {in};
                TxOut[] outs;
                if (changeOutput != null) {
                    outs = new TxOut[]{out, changeOutput}; // 包含转账输出和找零输出
                } else {
                    outs = new TxOut[]{out}; // 只有转账输出
                }


                Transaction transaction = new Transaction(ins, outs);

                // 验证并发送交易
                if (node.isValidTx(transaction)) { // 调用节点的验证逻辑
                    Message msg = new Message(transaction, 2);
                    node.getMsgChannel().sendMsg(msg);
                    JOptionPane.showMessageDialog(this, "交易已发送！", "成功", JOptionPane.INFORMATION_MESSAGE);
                    // 清空输入框
                    TxInoutIdTA.setText("");
                    TxInoutIdxTF.setText("");
                    TxAddressTA.setText("");
                    MakeTxAmountTF.setText("");
                } else {
                    // isValidTx 内部应该能提示具体错误，这里给个通用提示
                    JOptionPane.showMessageDialog(this, "交易无效，未能发送！", "错误", JOptionPane.ERROR_MESSAGE);
                }

            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(this, "索引和金额必须是有效的数字！", "输入错误", JOptionPane.WARNING_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(this, "创建或发送交易时发生错误: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                ex.printStackTrace();
            }
        });
    }

    // 添加顶部导航按钮
    public void addButtons(JPanel panel) {
        JButton showNodeBtn = new JButton(NODE_INFO_BTN);
        JButton showBlockBtn = new JButton(FIND_BLOCK_BTN);
        JButton showTxBtn = new JButton(FIND_TX_BTN);
        JButton showUTXOBtn = new JButton(UTXO_BTN);
        JButton mkTxBtn = new JButton(MAKE_TX_BTN);

        // 为每个按钮添加事件监听器，用于切换 mainPanel 中的卡片
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