package com.d208.blockchain.network;

import com.d208.blockchain.model.*;
import com.d208.blockchain.utils.CertificateManager;
import com.d208.blockchain.utils.ECDSAUtils;
import com.d208.blockchain.utils.HashUtil;
import lombok.Data;
import lombok.SneakyThrows;

import java.io.IOException; // 明确导入
import java.math.BigDecimal; // 明确导入 BigDecimal
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map; // 明确导入 Map
import java.util.Objects;

@Data
public class Node {
    int index;
    int port;
    Boolean mine;
    int[] portList;

    // --- 身份字段 ---
    private PrivateKey privateKey;
    private Certificate certificate;
    // --- 身份字段结束 ---

    // 共享状态需要线程安全访问
    final ArrayList<Transaction> txPool = new ArrayList<Transaction>();
    final ArrayList<Block> localChain = new ArrayList<Block>();
    final HashMap<String, TxOut> utxo = new HashMap<>();

    MsgChannel msgChannel;
    public static final int DIFF_ADJ_INTERVAL = 2;
    public static final int BLOCK_GEN_INTERVAL = 2500;
    public static final int COINBASE_REWARD = 50;

    // --- 构造函数 ---
    public Node(int index, int port, Boolean mine, int[] portList, PrivateKey privateKey, Certificate certificate) throws Exception {
        this.index = index;
        this.port = port;
        this.mine = mine;
        this.portList = portList;
        this.privateKey = Objects.requireNonNull(privateKey, "Private key cannot be null");
        this.certificate = Objects.requireNonNull(certificate, "Certificate cannot be null");
        msgChannel = new MsgChannel(port, portList);
    }
    // --- 构造函数结束 ---

    @SneakyThrows
    public void initNode() {
        System.out.println("Initializing Node " + index + " on port " + port);
        if (this.certificate instanceof X509Certificate) {
            System.out.println("  Certificate Subject: " + ((X509Certificate)this.certificate).getSubjectX500Principal());
            System.out.println("  Certificate Issuer: " + ((X509Certificate)this.certificate).getIssuerX500Principal());
            System.out.println("  Certificate Valid From: " + ((X509Certificate)this.certificate).getNotBefore());
            System.out.println("  Certificate Valid Until: " + ((X509Certificate)this.certificate).getNotAfter());
        }
        System.out.println("  Public Key (from cert): " + CertificateManager.getPubKeyStr(this.certificate));
        System.out.println("Requesting Blocks from neighbor nodes...");
        sendBlockReq();
        System.out.println("Starting Receiver Thread...");
        receiveMsg();
        if(mine) {
            System.out.println("Starting Mining Thread...");
            mining();
        } else {
            System.out.println("Node is not configured as a miner.");
        }
    }

    @SneakyThrows
    public void sendBlockReq(){
        int idx;
        synchronized (localChain) {
            idx = localChain.size();
        }
        Message message = new Message("" + idx, 1);
        msgChannel.sendMsg(message);
        System.out.println("Node["+index+"] sent block request starting from index: " + idx);
    }

    public void receiveMsg() {
        Thread receiverThread = new Thread(new Runnable() {
            @SneakyThrows
            @Override
            public void run() {
                Message msg = null;
                while (true) {
                    try {
                        msg = msgChannel.receiveMsg();
                        processMsg(msg);
                    } catch (IOException | ClassNotFoundException e) {
                        System.err.println("Node[" + index + "] Error receiving or processing message: " + e.getMessage());
                        Thread.sleep(100);
                    } catch (Exception e) {
                        System.err.println("Node[" + index + "] Error processing received message: " + e.getMessage());
                        e.printStackTrace();
                    }
                }
            }
        });
        receiverThread.setDaemon(true);
        receiverThread.setName("Node-" + index + "-Receiver");
        receiverThread.start();
    }

    public void processMsg(Message msg) throws Exception {
        if (msg == null) {
            System.err.println("Node[" + index + "] received a null message.");
            return;
        }
        int type = msg.getType();
        switch (type) {
            case 1: processNewReq(msg.getReq()); break;
            case 2: processNewTx(msg.getTx()); break;
            case 3: processNewBlock(msg.getBlock()); break;
            default: System.err.println("Node[" + index + "] received message with unknown type: " + type); break;
        }
    }

    @SneakyThrows
    public void processNewReq(String req){
        try {
            int requestedIdx = Integer.parseInt(req.trim());
            System.out.println("Node["+index +"]: Received block request starting from index ["+requestedIdx+"]");
            synchronized(localChain) {
                if (requestedIdx < 0) {
                    System.err.println("Node[" + index + "]: Received invalid block request index: " + requestedIdx);
                    return;
                }
                int currentChainSize = localChain.size();
                for (int idxToSend = requestedIdx; idxToSend < currentChainSize; idxToSend++) {
                    Block reqBlock = localChain.get(idxToSend);
                    Message blockMsg = new Message(reqBlock, 3);
                    msgChannel.sendMsg(blockMsg);
                    System.out.println("Node["+index +"]: Sent block ["+ idxToSend+"] in response to request.");
                    Thread.sleep(50);
                }
            }
        } catch (NumberFormatException e) {
            System.err.println("Node[" + index + "]: Received invalid block request format: " + req);
        } catch (InterruptedException e) {
            System.err.println("Node[" + index + "]: Sending blocks interrupted.");
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            System.err.println("Node[" + index + "]: Error sending block: " + e.getMessage());
            e.printStackTrace();
        }
    }

    @SneakyThrows
    public void initTx(TxIn[] txIns, TxOut[] txOuts){
        Transaction transaction = new Transaction(txIns, txOuts);
        System.out.println("Node[" + index + "] attempting to initiate transaction: " + transaction.getId());
        // 调用更新后的验证逻辑，传入当前节点的全局 UTXO
        if(isValidTx(transaction, this.utxo)){ // Pass the global UTXO map
            System.out.println("Node[" + index + "] initiated transaction is valid. Broadcasting...");
            Message msg = new Message(transaction, 2);
            msgChannel.sendMsg(msg);
            synchronized (txPool) {
                txPool.add(transaction);
            }
        } else {
            System.err.println("Node[" + index + "] initiated transaction validation failed. Cannot send: " + transaction.getId());
        }
    }

    public Transaction Test(String id){
        String inputTxOutId = id;
        String signature = signMessage(inputTxOutId); // Use internal sign method
        if (signature == null) { System.err.println("Failed to sign test transaction"); return null; }
        TxIn in = new TxIn(inputTxOutId, 0, signature);
        String myAddress = CertificateManager.getPubKeyStr(this.certificate);
        TxOut out = new TxOut("TestAddr1_" + myAddress, 40);
        TxOut out1 = new TxOut("TestAddr2_" + myAddress, 60);
        TxIn[] ins = {in};
        TxOut[] outs = {out, out1};
        Transaction transaction = new Transaction(ins, outs);
        System.out.println("Node[" + index + "] created test transaction: " + transaction.getId());
        return transaction;
    }

    public Transaction coinbaseTx(){
        int currentChainHeight;
        synchronized (localChain) {
            currentChainHeight = localChain.size();
        }
        TxIn in = new TxIn("0", currentChainHeight, "coinbase");
        String myAddress = CertificateManager.getPubKeyStr(this.certificate);
        TxOut out = new TxOut(myAddress, COINBASE_REWARD);
        TxIn[] ins = {in};
        TxOut[] outs = {out};
        Transaction transaction = new Transaction(ins, outs);
        return transaction;
    }

    public Transaction testCoinbase(int i){
        // 1. Create Coinbase
        TxIn coinbaseIn = new TxIn("0", i, "coinbase");
        String myAddress = CertificateManager.getPubKeyStr(this.certificate);
        TxOut coinbaseOut = new TxOut(myAddress, COINBASE_REWARD);
        Transaction coinbase = new Transaction(new TxIn[]{coinbaseIn}, new TxOut[]{coinbaseOut});
        String coinbaseTxId = coinbase.getId();
        System.out.println("Node[" + index + "] created test coinbase tx: " + coinbaseTxId);
        // 2. Create Spending Tx
        String signature = signMessage(coinbaseTxId); // Sign the ID of the tx being spent
        if (signature == null) { System.err.println("Failed to sign test coinbase spending transaction"); return null; }
        TxIn spendingIn = new TxIn(coinbaseTxId, 0, signature);
        TxOut spendingOut1 = new TxOut("SpendAddr1_" + myAddress, 20);
        TxOut spendingOut2 = new TxOut("SpendAddr2_" + myAddress, 30);
        Transaction spendingTx = new Transaction(new TxIn[]{spendingIn}, new TxOut[]{spendingOut1, spendingOut2});
        System.out.println("Node[" + index + "] created test spending tx: " + spendingTx.getId());
        return spendingTx;
    }

    // --- 新增的签名方法 ---
    public String signMessage(String message) {
        if (this.privateKey == null) {
            System.err.println("Node[" + index + "] cannot sign message: Private key is not loaded.");
            return null;
        }
        try {
            return ECDSAUtils.signECDSA(this.privateKey, message);
        } catch (Exception e) {
            System.err.println("Node[" + index + "] failed to sign message: " + message);
            e.printStackTrace();
            return null;
        }
    }
    // --- 签名方法结束 ---

    public void processNewTx(Transaction tx) throws Exception {
        System.out.println("Node[" + index + "] received transaction: " + tx.getId());
        // 使用更新后的验证逻辑，传入当前节点的全局 UTXO
        if (isValidTx(tx, this.utxo)) { // Pass the global UTXO map
            System.out.println("Node[" + index + "] received transaction is valid. Adding to pool.");
            synchronized(txPool) {
                boolean alreadyExists = txPool.stream().anyMatch(existingTx -> existingTx.getId().equals(tx.getId()));
                if (!alreadyExists) {
                    txPool.add(tx);
                    System.out.println("Node[" + index + "] Added tx " + tx.getId() + " to pool. Pool size: " + txPool.size());
                } else {
                    System.out.println("Node[" + index + "] Transaction " + tx.getId() + " already in pool.");
                }
            }
        } else {
            // isValidTx 内部应打印失败原因
            System.err.println("Node[" + index + "] received invalid transaction: " + tx.getId() + ". Discarding.");
        }
    }

    // ========================================================================
    // Step 3: 更新交易验证逻辑
    // ========================================================================

    /**
     * 验证交易是否有效（针对给定的 UTXO 集合）。
     * 此方法现在是交易验证的核心。
     * @param tx 要验证的交易。
     * @param referenceUtxo 用于查找输入的 UTXO 集合（可能是全局 UTXO 或模拟 UTXO）。
     * @return 如果交易有效则返回 true，否则 false。
     * @throws Exception 如果签名验证等操作失败。
     */
    public boolean isValidTx(Transaction tx, Map<String, TxOut> referenceUtxo) throws Exception {
        if (tx == null || tx.getId() == null) {
            System.err.println("Validation Error (isValidTx): Transaction or Transaction ID is null.");
            return false;
        }
        // System.out.println("DEBUG: Validating transaction " + tx.getId());

        // 1. 检查是否为 Coinbase 交易
        if (tx.getTxIns() != null && tx.getTxIns().length == 1 && "coinbase".equals(tx.getTxIns()[0].signature)) {
            return isValidCoinbaseTx(tx); // 使用单独的方法验证 Coinbase
        }

        // --- 普通交易验证 ---
        if (tx.getTxIns() == null || tx.getTxIns().length == 0) {
            System.err.println("Validation Error (isValidTx): Transaction " + tx.getId() + " has no inputs.");
            return false;
        }
        if (tx.getTxOuts() == null || tx.getTxOuts().length == 0) {
            System.err.println("Validation Error (isValidTx): Transaction " + tx.getId() + " has no outputs.");
            return false;
        }

        // 2. 验证交易结构和基本规则
        //  a) 检查重复的 TxIn (引用同一个 UTXO)
        List<String> consumedUtxoKeys = new ArrayList<>();
        for (TxIn txIn : tx.getTxIns()) {
            if (txIn == null || txIn.txOutId == null || txIn.signature == null) {
                System.err.println("Validation Error (isValidTx): Transaction " + tx.getId() + " contains invalid TxIn fields.");
                return false;
            }
            String utxoKey = txIn.txOutId + " " + txIn.txOutIndex;
            if (consumedUtxoKeys.contains(utxoKey)) {
                System.err.println("Validation Error (isValidTx): Transaction " + tx.getId() + " attempts to spend the same UTXO twice: " + utxoKey);
                return false;
            }
            consumedUtxoKeys.add(utxoKey);
        }
        // b) 检查 TxOut 金额是否为正
        for (TxOut txOut : tx.getTxOuts()) {
            if (txOut == null || txOut.address == null || txOut.amount <= 0) {
                System.err.println("Validation Error (isValidTx): Transaction " + tx.getId() + " contains invalid TxOut (address null, or amount non-positive: " + (txOut != null ? txOut.amount : "null") + ").");
                return false;
            }
        }

        // 3. 验证输入来源 (UTXO 存在性) 和计算总输入金额
        BigDecimal totalInputAmount = BigDecimal.ZERO;
        // 存储引用的 UTXO 以便后续签名验证
        Map<TxIn, TxOut> referencedUtxos = new HashMap<>();

        // 创建 referenceUtxo 的副本进行操作，如果它是全局 UTXO 则需要同步
        Map<String, TxOut> utxoView;
        if (referenceUtxo == this.utxo) { // 判断是否是全局 UTXO
            synchronized (this.utxo) {
                utxoView = new HashMap<>(referenceUtxo); // 操作副本
            }
        } else {
            utxoView = referenceUtxo; // 已经是副本或模拟器
        }

        for (TxIn txIn : tx.getTxIns()) {
            String utxoKey = txIn.txOutId + " " + txIn.txOutIndex;
            TxOut referencedTxOut = utxoView.get(utxoKey);

            if (referencedTxOut == null) {
                System.err.println("Validation Error (isValidTx): Transaction " + tx.getId() + " references non-existent or spent UTXO: " + utxoKey);
                return false;
            }
            // 累加输入金额
            totalInputAmount = totalInputAmount.add(BigDecimal.valueOf(referencedTxOut.amount));
            // 存储引用关系
            referencedUtxos.put(txIn, referencedTxOut);
        }

        // 4. 计算总输出金额
        BigDecimal totalOutputAmount = BigDecimal.ZERO;
        for (TxOut txOut : tx.getTxOuts()) {
            totalOutputAmount = totalOutputAmount.add(BigDecimal.valueOf(txOut.amount));
        }

        // 5. 验证金额：总输入 >= 总输出
        if (totalInputAmount.compareTo(totalOutputAmount) < 0) {
            System.err.println("Validation Error (isValidTx): Transaction " + tx.getId() + " has insufficient input funds. Input: " + totalInputAmount + ", Output: " + totalOutputAmount);
            return false;
        }

        // 6. 验证每个输入的签名
        for (TxIn txIn : tx.getTxIns()) {
            TxOut referencedTxOut = referencedUtxos.get(txIn); // 获取对应的 UTXO
            if (referencedTxOut == null) {
                // 理论上不会发生，因为前面已经检查过
                System.err.println("Internal Error (isValidTx): Referenced UTXO missing during signature check for " + tx.getId());
                return false;
            }
            String ownerPublicKeyBase64 = referencedTxOut.address; // 从 UTXO 获取所有者的公钥地址
            // 验证签名：签名(signature), 公钥(ownerPublicKeyBase64), 被签名的内容(txIn.txOutId)
            if (!isValidSignature(txIn.signature, ownerPublicKeyBase64, txIn.txOutId)) {
                // isValidSignature 内部会打印详细错误
                System.err.println("Validation Error (isValidTx): Signature verification failed for input referencing " + txIn.txOutId + ":" + txIn.txOutIndex + " in transaction " + tx.getId());
                return false;
            }
        }

        // System.out.println("DEBUG: Transaction " + tx.getId() + " passed all validations.");
        return true; // 所有检查通过
    }

    /**
     * 验证 Coinbase 交易的基本规则。
     * @param tx Coinbase 交易。
     * @return 如果有效则返回 true。
     */
    private boolean isValidCoinbaseTx(Transaction tx) {
        if (tx.getTxIns() == null || tx.getTxIns().length != 1 || !"coinbase".equals(tx.getTxIns()[0].signature)) {
            // 不应该在这里被调用，但做个检查
            return false;
        }
        if (tx.getTxOuts() == null || tx.getTxOuts().length != 1) {
            System.err.println("Validation Error (isValidCoinbaseTx): Coinbase tx " + tx.getId() + " should have exactly one output.");
            return false;
        }
        TxOut output = tx.getTxOuts()[0];
        if (output.amount != COINBASE_REWARD) {
            System.err.println("Validation Error (isValidCoinbaseTx): Coinbase tx " + tx.getId() + " has incorrect reward amount. Expected: " + COINBASE_REWARD + ", Got: " + output.amount);
            return false;
        }
        // 可以添加对输出地址的检查（如果需要）
        // System.out.println("DEBUG: Coinbase transaction " + tx.getId() + " is valid.");
        return true;
    }

    /**
     * 验证 ECDSA 签名。
     * 此方法现在主要负责调用底层的验证库。
     * @param signature 签名 (十六进制字符串)。
     * @param publicKeyBase64 用于验证的公钥 (Base64 编码字符串)。
     * @param message 被签名的原始消息 (这里假设是引用的 txOutId)。
     * @return 如果签名有效则返回 true。
     */
    public Boolean isValidSignature(String signature, String publicKeyBase64, String message) {
        // System.out.println("DEBUG: Verifying signature: pubKey=" + publicKeyBase64.substring(0, 10) + "..., msg=" + message);
        if (signature == null || publicKeyBase64 == null || message == null) {
            System.err.println("Signature validation Error: Null parameter provided.");
            return false;
        }
        try {
            PublicKey publicKey = ECDSAUtils.getPublicKey(publicKeyBase64);
            boolean isValid = ECDSAUtils.verifyECDSA(publicKey, signature, message);
            // if (!isValid) {
            //     System.err.println("Signature verification failed for pubKey: " + publicKeyBase64 + ", message: " + message);
            // }
            return isValid;
        } catch (Exception e) {
            System.err.println("Signature verification Error: Exception during verification for pubKey: " + publicKeyBase64 + ", message: " + message + " - " + e.getMessage());
            // e.printStackTrace(); // 调试时可以打开
            return false;
        }
    }

    /**
     * 验证一个区块内的所有交易是否都有效（相对于当前 UTXO 状态和彼此之间）。
     * 使用传入的完整交易列表。
     * @param transactionList 区块中的交易列表。
     * @return 如果所有交易都有效则返回 true。
     */
    public Boolean allTxInBlockIsValid(List<Transaction> transactionList){
        if (transactionList == null) {
            System.err.println("Validation Error (allTxInBlockIsValid): Transaction list is null.");
            return false; // 或者返回 true 如果允许空块？根据业务规则决定
        }
        if (transactionList.isEmpty()) {
            // System.out.println("DEBUG: Block contains no transactions (considered valid).");
            return true; // 空交易列表通常是有效的
        }
        // System.out.println("DEBUG: Validating " + transactionList.size() + " transactions in block.");

        // 创建 UTXO 集合的模拟副本，用于在此区块内进行验证
        HashMap<String, TxOut> utxoEmulator;
        synchronized (this.utxo) {
            utxoEmulator = new HashMap<>(this.utxo);
        }
        // 存储区块内新产生的 UTXO key，防止块内双花
        List<String> blockGeneratedUtxoKeys = new ArrayList<>();

        for(int txIndex = 0; txIndex < transactionList.size(); txIndex++) {
            Transaction tx = transactionList.get(txIndex);

            // 特殊处理 Coinbase 交易 (必须是第一个，且只能有一个)
            boolean isCoinbase = (tx.getTxIns() != null && tx.getTxIns().length == 1 && "coinbase".equals(tx.getTxIns()[0].signature));
            if (isCoinbase) {
                if (txIndex != 0) {
                    System.err.println("Validation Error (allTxInBlockIsValid): Coinbase transaction is not the first transaction in the block.");
                    return false;
                }
                if (!isValidCoinbaseTx(tx)) { // 再次验证 Coinbase 规则
                    System.err.println("Validation Error (allTxInBlockIsValid): Invalid Coinbase transaction found.");
                    return false; // isValidCoinbaseTx 会打印具体原因
                }
            } else {
                // 非 Coinbase 交易，使用 isValidTx 进行验证 (传入模拟器)
                try {
                    if (!isValidTx(tx, utxoEmulator)) {
                        System.err.println("Validation Error (allTxInBlockIsValid): Transaction " + tx.getId() + " failed validation within the block context.");
                        return false; // isValidTx 会打印具体原因
                    }
                } catch (Exception e) {
                    System.err.println("Validation Error (allTxInBlockIsValid): Exception during validation of tx " + tx.getId() + " in block: " + e.getMessage());
                    e.printStackTrace();
                    return false;
                }
            }

            // 更新模拟器：移除花费的 UTXO，添加新的 UTXO
            // 处理输入 (移除) - 仅对非 Coinbase 交易
            if (!isCoinbase && tx.getTxIns() != null) {
                for(TxIn txIn : tx.getTxIns()){
                    String utxoKey = txIn.txOutId + " " + txIn.txOutIndex;
                    // 从模拟器中移除，如果移除失败说明验证逻辑有误或状态不一致
                    if (utxoEmulator.remove(utxoKey) == null) {
                        System.err.println("Internal Error (allTxInBlockIsValid): UTXO " + utxoKey + " not found in emulator during update for tx " + tx.getId());
                        return false; // 验证应该已经捕获了这一点
                    }
                }
            }
            // 处理输出 (添加)
            if (tx.getTxOuts() != null) {
                for(int i = 0; i < tx.getTxOuts().length; i++){
                    String newUtxoKey = tx.getId() + " " + i;
                    // 检查是否在当前块内重复生成了 UTXO key
                    if (blockGeneratedUtxoKeys.contains(newUtxoKey)) {
                        System.err.println("Validation Error (allTxInBlockIsValid): Block attempts to generate duplicate UTXO key: " + newUtxoKey + " from tx " + tx.getId());
                        return false;
                    }
                    // 检查是否与模拟器中已存在的 key 冲突 (理论上不应发生，因为 txid 不同)
                    if (utxoEmulator.containsKey(newUtxoKey)) {
                        System.err.println("Internal Error (allTxInBlockIsValid): Duplicate UTXO key detected in emulator when adding output: " + newUtxoKey);
                        return false;
                    }
                    utxoEmulator.put(newUtxoKey, tx.getTxOuts()[i]);
                    blockGeneratedUtxoKeys.add(newUtxoKey); // 记录本区块内生成的 key
                }
            }
        }
        // System.out.println("DEBUG: All transactions in the block passed validation.");
        return true; // 所有交易都通过了验证
    }

    // ========================================================================
    // 验证逻辑更新结束
    // ========================================================================


    public void processNewBlock(Block block){
        if (block == null) {
            System.err.println("Node[" + index + "] received a null block.");
            return;
        }
        System.out.println("Node[" + index + "] received block: " + block.getIndex());

        synchronized (localChain) { // Ensure atomic check and update of the chain
            int currentHeight = localChain.size();
            Block previousBlock = (currentHeight > 0) ? localChain.get(currentHeight - 1) : null;

            // 1. Check if the block extends the current chain
            if (currentHeight == block.getIndex()) {
                boolean isValid;
                if (block.getIndex() == 0) {
                    isValid = isValidGenesisBlock(block);
                    if (isValid) System.out.println("Node[" + index + "] Genesis block is valid.");
                    else System.err.println("Node[" + index + "] Received invalid Genesis block.");
                } else {
                    isValid = isValidNewBlock(block, previousBlock);
                    if (isValid) System.out.println("Node[" + index + "] New block " + block.getIndex() + " is valid and extends the chain.");
                    // Error message is printed inside isValidNewBlock
                }

                if (isValid) {
                    localChain.add(block);
                    System.out.println("Node[" + index + "] Added Block [" + block.getIndex() + "] to local chain. Chain height: " + localChain.size());
                    // Update UTXO and TxPool only AFTER successful addition
                    updateUTXO(block);
                    updateTxPool(block);
                }
            }
            // 2. Received block is older than current chain height
            else if (block.getIndex() < currentHeight) {
                System.out.println("Node[" + index + "] Received block " + block.getIndex() + " which is older than current height " + currentHeight + ". Ignoring.");
            }
            // 3. Received block is further ahead (indicates a gap)
            else {
                System.out.println("Node[" + index + "] Received block " + block.getIndex() + " which is ahead of current height " + currentHeight + ". Gap detected, requesting missing blocks...");
                sendBlockReq(); // Request blocks starting from current height
            }
        }
    }

    public void updateTxPool(Block block){
        if (block == null || block.getTransactionList() == null) return;
        List<Transaction> confirmedTxs = block.getTransactionList();
        if (confirmedTxs.isEmpty()) return;

        synchronized (txPool) {
            List<Transaction> txsToRemove = new ArrayList<>();
            Map<String, Transaction> poolTxMap = new HashMap<>(); // Faster lookup
            for (Transaction poolTx : txPool) {
                poolTxMap.put(poolTx.getId(), poolTx);
            }

            for (Transaction confirmedTx : confirmedTxs) {
                if (poolTxMap.containsKey(confirmedTx.getId())) {
                    txsToRemove.add(poolTxMap.get(confirmedTx.getId()));
                }
            }

            if (!txsToRemove.isEmpty()) {
                txPool.removeAll(txsToRemove);
                System.out.println("Node[" + index + "] Removed " + txsToRemove.size() + " confirmed transactions from pool. Pool size: " + txPool.size());
            }
        }
    }

    public void updateUTXO(Block block){
        if (block == null || block.getTransactionList() == null) return;
        List<Transaction> transactionList = block.getTransactionList();
        int inputsRemoved = 0;
        int outputsAdded = 0;

        synchronized (utxo) {
            for(Transaction tx : transactionList){
                // Remove spent UTXOs (inputs) - skip for coinbase
                boolean isCoinbase = (tx.getTxIns() != null && tx.getTxIns().length == 1 && "coinbase".equals(tx.getTxIns()[0].signature));
                if (!isCoinbase && tx.getTxIns() != null) {
                    for(TxIn txIn : tx.getTxIns()){
                        String utxoKeyToRemove = txIn.txOutId + " " + txIn.txOutIndex;
                        if (utxo.remove(utxoKeyToRemove) != null) {
                            inputsRemoved++;
                        } else {
                            System.err.println("Warning: UTXO key " + utxoKeyToRemove + " not found while updating UTXO for confirmed tx " + tx.getId());
                        }
                    }
                }
                // Add new UTXOs (outputs)
                if (tx.getTxOuts() != null) {
                    for(int i = 0; i < tx.getTxOuts().length; i++){
                        String newUtxoKey = tx.getId() + " " + i;
                        if (!utxo.containsKey(newUtxoKey)) {
                            utxo.put(newUtxoKey, tx.getTxOuts()[i]);
                            outputsAdded++;
                        } else {
                            System.err.println("Warning: UTXO key " + newUtxoKey + " already exists while updating UTXO for confirmed tx " + tx.getId());
                        }
                    }
                }
            }
        }
        System.out.println("Node[" + index + "] Updated UTXO based on block " + block.getIndex() + ". Removed " + inputsRemoved + " inputs, added " + outputsAdded + " outputs. UTXO size: " + utxo.size());
    }

    public boolean isValidNewBlock(Block newBlock, Block prevBlock){
        if (newBlock == null || prevBlock == null) {
            System.err.println("Block validation failed: Null block provided.");
            return false;
        }
        if(prevBlock.getIndex() + 1 != newBlock.getIndex()) {
            System.err.println("Block validation failed: Index mismatch. Prev=" + prevBlock.getIndex() + ", New=" + newBlock.getIndex());
            return false;
        }
        if(!Objects.equals(prevBlock.getHash(), newBlock.getPreviousHash())) {
            System.err.println("Block validation failed: PreviousHash mismatch for block " + newBlock.getIndex());
            System.err.println("  Expected (Prev Block Hash): " + prevBlock.getHash());
            System.err.println("  Received (New Block PrevHash): " + newBlock.getPreviousHash());
            return false;
        }
        String calculatedHash = calculateHash(newBlock);
        if(!Objects.equals(calculatedHash, newBlock.getHash())) {
            System.err.println("Block validation failed: Hash calculation mismatch for block " + newBlock.getIndex());
            System.err.println("  Calculated: " + calculatedHash);
            System.err.println("  Received: " + newBlock.getHash());
            return false;
        }
        if (!hashMatchesDifficulty(newBlock.getHash(), newBlock.getDifficulty())) {
            System.err.println("Block validation failed: Hash " + newBlock.getHash() + " does not meet difficulty " + newBlock.getDifficulty() + " for block " + newBlock.getIndex());
            return false;
        }
        // Use the updated allTxInBlockIsValid for internal transaction validation
        if(!allTxInBlockIsValid(newBlock.getTransactionList())) {
            // allTxInBlockIsValid should print the specific reason
            System.err.println("Block validation failed: Invalid transactions within block " + newBlock.getIndex() + ".");
            return false;
        }
        return true;
    }

    public boolean isValidGenesisBlock(Block block){
        if (block == null) return false;
        if(block.getIndex() != 0) {
            System.err.println("Genesis block validation failed: Index is not 0.");
            return false;
        }
        if (!"0".equals(block.getPreviousHash()) && block.getPreviousHash() != null) {
            System.err.println("Genesis block validation warning: PreviousHash is not '0' or null (value: " + block.getPreviousHash() + "). Accepting based on definition.");
            // Decide if this should be a strict failure based on your chain rules
        }
        String calculatedHash = calculateHash(block);
        if(!Objects.equals(calculatedHash, block.getHash())) {
            System.err.println("Genesis block validation failed: Hash calculation mismatch.");
            return false;
        }
        if (!hashMatchesDifficulty(block.getHash(), block.getDifficulty())) {
            System.err.println("Genesis block validation failed: Hash does not meet difficulty " + block.getDifficulty());
            return false;
        }
        if(!allTxInBlockIsValid(block.getTransactionList())) {
            System.err.println("Genesis block validation failed: Invalid transactions within block.");
            return false;
        }
        return true;
    }

    private boolean hashMatchesDifficulty(String hash, int difficulty) {
        if (hash == null || difficulty < 0) return false;
        String requiredPrefix = HashUtil.getPrefix0(difficulty);
        if (requiredPrefix == null && difficulty > 0) return false; // Error getting prefix
        if (difficulty == 0) return true; // Difficulty 0 requires no prefix
        return hash.startsWith(requiredPrefix);
    }

    public void mining() {
        if (!this.mine) {
            System.out.println("Node[" + index + "] is not a miner, skipping mining thread start.");
            return;
        }
        Thread miningThread = new Thread(new Runnable() {
            @SneakyThrows
            @Override
            public void run() {
                System.out.println("Node[" + Node.this.index + "] Mining thread started.");
                while (true) {
                    int currentChainHeight;
                    Block latestBlock = null;
                    synchronized (localChain) {
                        currentChainHeight = localChain.size();
                        if (currentChainHeight > 0) {
                            latestBlock = localChain.get(currentChainHeight - 1);
                        }
                    }

                    int nextIndex = currentChainHeight;
                    String previousHash = (latestBlock != null) ? latestBlock.getHash() : "0";
                    int difficulty;
                    // Get difficulty based on a safe copy of the chain
                    synchronized(localChain) {
                        difficulty = getDifficulty(localChain);
                    }

                    Transaction coinbaseTx = coinbaseTx();
                    List<Transaction> currentTxPoolCopy;
                    synchronized (txPool) {
                        currentTxPoolCopy = new ArrayList<>(txPool);
                    }
                    List<Transaction> txsForBlock = new ArrayList<>();
                    txsForBlock.add(coinbaseTx);
                    txsForBlock.addAll(currentTxPoolCopy); // Consider filtering/prioritizing txs here

                    String rootHash = "";
                    if (!txsForBlock.isEmpty()) {
                        rootHash = new MerkleTree(txsForBlock).getRoot();
                    } else {
                        rootHash = HashUtil.getHashForStr("");
                    }

                    // 在 mining 方法的 while 循环内
                    // -- 修改日志打印，安全处理 previousHash --
                    String prevHashDisplay = (previousHash.length() >= 8) ? previousHash.substring(0, 8) : previousHash;
                    System.out.println("Node["+Node.this.index+"] starting PoW for block " + nextIndex + " (Diff: " + difficulty + ", Txs: " + txsForBlock.size() + ", PrevHash: " + prevHashDisplay + "...)");
                    // -- 修改结束 --
                    Block newBlock = findBlock(nextIndex, System.currentTimeMillis(), previousHash, rootHash, difficulty);

                    if (newBlock != null) {
                        newBlock.setTransactionList(txsForBlock);
                        Block finalLatestBlock;
                        synchronized(localChain){
                            finalLatestBlock = (localChain.isEmpty()) ? null : localChain.get(localChain.size()-1);
                        }
                        boolean finalValidation = (newBlock.getIndex() == 0) ? isValidGenesisBlock(newBlock) : isValidNewBlock(newBlock, finalLatestBlock);

                        if (finalValidation) {
                            synchronized (localChain) {
                                if (localChain.size() == newBlock.getIndex()) {
                                    localChain.add(newBlock);
                                    System.out.println("Node["+Node.this.index+"] Added mined block ["+newBlock.index+"] to local chain. Chain height: " + localChain.size() + ", Hash: " + newBlock.getHash().substring(0, 8) + "...");
                                } else {
                                    System.out.println("Node["+Node.this.index+"] Mined block ["+newBlock.index+"] is stale (chain height changed during validation). Discarding.");
                                    newBlock = null;
                                }
                            }
                            if (newBlock != null) {
                                updateUTXO(newBlock);
                                synchronized (txPool) {
                                    txPool.removeAll(currentTxPoolCopy);
                                    System.out.println("Node[" + index + "] Removed packaged Txs from pool after mining block " + newBlock.getIndex() + ". Pool size: " + txPool.size());
                                }
                                Message message = new Message(newBlock, 3);
                                msgChannel.sendMsg(message);
                                System.out.println("Node["+Node.this.index+"] Broadcasted mined block ["+newBlock.index+"].");
                            }
                        } else {
                            System.err.println("Node["+Node.this.index+"] Mined block ["+newBlock.getIndex()+"] failed final validation! Discarding.");
                        }
                    }
                    Thread.sleep(100);
                }
            }
        });
        miningThread.setDaemon(true);
        miningThread.setName("Node-" + index + "-Miner");
        miningThread.start();
    }

    public Block getLatestBlock(){
        synchronized (localChain) {
            if (localChain.isEmpty()) return null;
            return localChain.get(localChain.size() - 1);
        }
    }

    // Pass a copy of the chain to avoid holding lock for long
    public int getDifficulty(ArrayList<Block> currentLocalChainCopy){
        if (currentLocalChainCopy.isEmpty()) return 1;
        Block latestBlock = currentLocalChainCopy.get(currentLocalChainCopy.size() - 1);
        if (latestBlock.getIndex() > 0 && latestBlock.getIndex() % DIFF_ADJ_INTERVAL == 0) {
            return getAdjustedDifficulty(latestBlock, currentLocalChainCopy);
        } else {
            return latestBlock.getDifficulty();
        }
    }

    public int getAdjustedDifficulty(Block latestBlock, ArrayList<Block> currentLocalChainCopy){
        int prevAdjustmentBlockIndex = Math.max(0, currentLocalChainCopy.size() - DIFF_ADJ_INTERVAL);
        Block prevAdjustmentBlock = currentLocalChainCopy.get(prevAdjustmentBlockIndex);
        long timeExpected = (long)BLOCK_GEN_INTERVAL * DIFF_ADJ_INTERVAL;
        long timeTaken = latestBlock.getTimestamp() - prevAdjustmentBlock.getTimestamp();

        System.out.println("Difficulty Adjustment Check:");
        System.out.println("  Blocks: " + prevAdjustmentBlockIndex + " to " + latestBlock.getIndex());
        System.out.println("  Time Expected: " + timeExpected + " ms");
        System.out.println("  Time Taken: " + timeTaken + " ms");
        System.out.println("  Previous Difficulty: " + prevAdjustmentBlock.getDifficulty());

        int currentDifficulty = prevAdjustmentBlock.getDifficulty();
        if (timeTaken < timeExpected / 2) {
            int newDifficulty = currentDifficulty + 1;
            System.out.println("  Increasing difficulty to " + newDifficulty);
            return newDifficulty;
        } else if (timeTaken > timeExpected * 2 && currentDifficulty > 0) { // Prevent difficulty going below 0
            int newDifficulty = currentDifficulty - 1;
            System.out.println("  Decreasing difficulty to " + newDifficulty);
            return newDifficulty;
        } else {
            System.out.println("  Keeping difficulty at " + currentDifficulty);
            return currentDifficulty;
        }
    }

    public Block findBlock(int index, long timestamp, String previousHash, String rootHash, int difficulty){
        String requiredPrefix = HashUtil.getPrefix0(difficulty);
        if (requiredPrefix == null && difficulty > 0) {
            System.err.println("Error getting required prefix for difficulty " + difficulty);
            return null;
        }
        long nonce = 0;
        String inputForHashing = index + "" + timestamp + previousHash + rootHash + difficulty;
        while(true){
            int currentChainHeight;
            synchronized (localChain) { currentChainHeight = localChain.size(); }
            if(index != currentChainHeight) { return null; } // Chain height changed, abort

            String hash = HashUtil.getHashForStr(inputForHashing + nonce);
            if(hash != null && (difficulty == 0 || (requiredPrefix != null && hash.startsWith(requiredPrefix)))){
                return new Block(index, timestamp, hash, previousHash, rootHash, difficulty, nonce);
            }
            nonce++;
            if (nonce % 2000000 == 0) { // Progress update less frequently
                System.out.println("Node["+this.index+"] PoW progress for block " + index + ": Nonce reached " + nonce + "...");
            }
        }
    }

    public String calculateHash(Block block){
        if (block == null) return null;
        String str = block.getIndex() + "" + block.getTimestamp() + block.getPreviousHash() + block.getRootHash() + block.getDifficulty() + block.getNonce();
        return HashUtil.getHashForStr(str);
    }

    // --- Getters ---
    public Certificate getCertificate() { return certificate; }
    public PublicKey getPublicKey() { return (certificate != null) ? certificate.getPublicKey() : null; }
    public int getIndex() { return index; }
    public int getPort() { return port; }
    public Boolean getMine() { return mine; }
    public List<Block> getLocalChain() { synchronized (localChain) { return new ArrayList<>(localChain); } }
    public HashMap<String, TxOut> getUtxo() { synchronized (utxo) { return new HashMap<>(utxo); } }
    public List<Transaction> getTxPool() { synchronized(txPool) { return new ArrayList<>(txPool); } }
}