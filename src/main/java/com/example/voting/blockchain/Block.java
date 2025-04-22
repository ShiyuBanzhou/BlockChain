package com.example.voting.blockchain;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import com.example.voting.crypto.CryptoUtil;

/**
 * 区块数据结构
 */
public class Block {
    private int index;                   // 区块高度
    private long timestamp;             // 时间戳
    private List<Transaction> transactions = new ArrayList<>(); // 交易列表
    private String prevHash;            // 前一个区块哈希
    private String hash;                // 本区块哈希
    private List<String> signatures = new ArrayList<>();  // PoA 多重签名列表

    public Block(int index, String prevHash) {
        this.index = index;
        this.prevHash = prevHash;
        this.timestamp = Instant.now().toEpochMilli();
    }

    public void addTransaction(Transaction tx) {
        transactions.add(tx);
    }

    /** 计算区块哈希：SHA-256(index + prevHash + timestamp + transactions + signatures) */
    public String computeHash() {
        String data = index + prevHash + timestamp + transactions.toString() + signatures.toString();
        return CryptoUtil.sha256(data);
    }

    /** 生成并设置本区块哈希 */
    public void finalizeBlock() {
        this.hash = computeHash();
    }

    // Getters
    public int getIndex() { return index; }
    public String getHash() { return hash; }
    public String getPrevHash() { return prevHash; }
    public List<Transaction> getTransactions() { return transactions; }
    public List<String> getSignatures() { return signatures; }

    public long getTimestamp() {return timestamp; }
}
