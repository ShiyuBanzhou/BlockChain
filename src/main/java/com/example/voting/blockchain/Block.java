package com.example.voting.blockchain;

import com.example.voting.crypto.CryptoUtil;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects; // Import Objects for hashCode/equals

/**
 * Represents a block in the blockchain.
 * 区块链中的区块。
 */
public class Block {
    private int index;                   // Block height 区块高度
    private long timestamp;             // Timestamp 时间戳
    private List<Transaction> transactions = new ArrayList<>(); // List of transactions 交易列表
    private String prevHash;            // Hash of the previous block 前一个区块哈希
    private String hash;                // Hash of this block (calculated) 本区块哈希（计算得出）
    private List<String> signatures = new ArrayList<>();  // List of signatures for PoA PoA 的签名列表

    /**
     * Constructor for a new block. Hash is initially null.
     * 新区块的构造函数。哈希初始为 null。
     * @param index Index of the block. 区块索引。
     * @param prevHash Hash of the previous block. 前一个区块的哈希。
     */
    public Block(int index, String prevHash) {
        this.index = index;
        this.prevHash = prevHash;
        this.timestamp = Instant.now().toEpochMilli();
        this.hash = null; // Hash is calculated later 哈希稍后计算
    }

    /**
     * Adds a transaction to the block.
     *向区块添加交易。
     * Should ideally be done before finalizing/calculating hash.
     * 理想情况下应在最终确定/计算哈希之前完成。
     * @param tx The transaction to add. 要添加的交易。
     */
    public void addTransaction(Transaction tx) {
        if (this.hash != null) {
            System.err.println("Warning: Adding transaction to an already finalized block (hash calculated).");
            // Consider throwing an exception or preventing addition
            // 考虑抛出异常或阻止添加
        }
        transactions.add(tx);
    }

    /**
     * Calculates the hash of the block based on its content.
     * 根据区块内容计算区块哈希。
     * Used for PoA or if hash needs recalculation.
     * 用于 PoA 或需要重新计算哈希时。
     * Hash = SHA-256(index + prevHash + timestamp + transactions.toString() + signatures.toString())
     * 哈希 = SHA-256(索引 + 前哈希 + 时间戳 + 交易.toString() + 签名.toString())
     * @return The calculated SHA-256 hash. 计算出的 SHA-256 哈希。
     */
    public String computeHash() {
        // Ensure transactions have a stable string representation
        // 确保交易具有稳定的字符串表示形式
        String txData = transactions.toString();
        // Ensure signatures have a stable string representation
        // 确保签名具有稳定的字符串表示形式
        String sigData = signatures.toString();
        String data = index + prevHash + timestamp + txData + sigData;
        return CryptoUtil.sha256(data);
    }

    /**
     * Finalizes the block by calculating and setting its hash.
     * 通过计算并设置其哈希来最终确定区块。
     * Typically used for genesis block or PoA blocks.
     * 通常用于创世区块或 PoA 区块。
     */
    public void finalizeBlock() {
        this.hash = computeHash();
    }

    // --- Getters ---

    public int getIndex() { return index; }
    public String getHash() { return hash; } // Can be null if not finalized/mined 可以为 null 如果未最终确定/挖掘
    public String getPrevHash() { return prevHash; }
    public List<Transaction> getTransactions() { return transactions; }
    public List<String> getSignatures() { return signatures; }
    public long getTimestamp() { return timestamp; }

    // --- Setter ---

    /**
     * Sets the hash for this block.
     * 设置此区块的哈希。
     * Primarily used after PoW mining where the hash is found externally.
     * 主要在 PoW 挖掘之后使用，此时哈希是在外部找到的。
     * @param hash The calculated hash of the block. 区块的计算哈希。
     */
    public void setHash(String hash) {
        this.hash = hash;
    }

    // --- Overrides for potential use in Sets/Maps ---
    // --- 用于 Set/Map 中潜在用途的覆盖 ---

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Block block = (Block) o;
        // Two blocks are equal if their calculated hash is the same (or both null and contents match)
        // 如果两个区块的计算哈希相同（或者都为 null 且内容匹配），则它们相等
        if (hash != null && block.hash != null) {
            return hash.equals(block.hash);
        }
        // Fallback to content comparison if hashes are not set
        // 如果未设置哈希，则回退到内容比较
        return index == block.index &&
                timestamp == block.timestamp &&
                Objects.equals(prevHash, block.prevHash) &&
                Objects.equals(transactions, block.transactions) &&
                Objects.equals(signatures, block.signatures);
    }

    @Override
    public int hashCode() {
        // Use hash if available, otherwise compute hash based on content
        // 如果哈希可用则使用哈希，否则根据内容计算哈希
        if (hash != null) {
            return hash.hashCode();
        }
        return Objects.hash(index, timestamp, transactions, prevHash, signatures);
    }

    @Override
    public String toString() {
        return "Block{" +
                "index=" + index +
                ", timestamp=" + timestamp +
                ", prevHash='" + (prevHash != null ? prevHash.substring(0, Math.min(8, prevHash.length())) + "..." : "null") + '\'' +
                ", hash='" + (hash != null ? hash.substring(0, Math.min(8, hash.length())) + "..." : "null") + '\'' +
                ", transactions=" + transactions.size() +
                ", signatures=" + signatures.size() +
                '}';
    }
}
