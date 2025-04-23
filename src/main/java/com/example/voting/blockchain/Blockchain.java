package com.example.voting.blockchain;

import java.util.ArrayList;
import java.util.List;

/**
 * Base class for blockchain framework.
 * Provides chain maintenance and basic validation.
 * 区块链框架基类。
 * 提供链维护和基本验证。
 */
public class Blockchain {
    protected List<Block> chain = new ArrayList<>();
    public int difficulty = 0;           // PoW difficulty PoW 难度
    protected int requiredSignatures = 1;   // PoA required signatures PoA 所需签名

    public Blockchain() {
        // Create Genesis Block
        // 创建创世区块
        Block genesis = new Block(0, "0");
        genesis.addTransaction(new Transaction(Transaction.Type.OTHER, "Genesis Block"));
        genesis.finalizeBlock(); // Calculate hash for genesis 计算创世区块哈希
        chain.add(genesis);
        System.out.println("Genesis block created and added.");
    }

    /** Gets the latest block */
    /** 获取最新区块 */
    public Block getLastBlock() {
        if (chain.isEmpty()) {
            // This should not happen if genesis block is always created
            // 如果总是创建创世区块，则不应发生这种情况
            throw new IllegalStateException("Blockchain is empty, cannot get last block.");
        }
        return chain.get(chain.size() - 1);
    }

    /**
     * Adds a new block after basic validation (previous hash).
     * 在基本验证（前一个哈希）后添加新区块。
     * Subclasses should override for specific consensus checks.
     * 子类应覆盖以进行特定的共识检查。
     * @param newBlock The block to add. 要添加的区块。
     * @return true if the block passes basic checks and is added, false otherwise. 如果区块通过基本检查并已添加，则返回 true，否则返回 false。
     */
    public boolean addBlock(Block newBlock) {
        if (newBlock == null) {
            System.err.println("Blockchain.addBlock: Attempted to add a null block.");
            return false;
        }
        Block prev = getLastBlock();

        // *** Add Logging for prevHash check ***
        // *** 添加 prevHash 检查的日志记录 ***
        String expectedPrevHash = prev.getHash();
        String actualPrevHash = newBlock.getPrevHash();
        System.out.println("Blockchain.addBlock: Checking Block " + newBlock.getIndex() +
                ". PrevHash expected: " + (expectedPrevHash != null ? expectedPrevHash.substring(0, 8) : "null") + "..." +
                ", Block has prevHash: " + (actualPrevHash != null ? actualPrevHash.substring(0, 8) : "null") + "...");

        if (actualPrevHash == null || !actualPrevHash.equals(expectedPrevHash)) {
            // *** Add Logging for failure ***
            // *** 添加失败的日志记录 ***
            System.err.println("Blockchain.addBlock: Block " + newBlock.getIndex() + " REJECTED due to prevHash mismatch.");
            return false; // Fails basic prevHash check 失败基本 prevHash 检查
        }

        // PoW check (only if instance of VotingBlockchain) - moved this logic entirely to VotingBlockchain override
        // PoW 检查（仅当是 VotingBlockchain 实例时）- 此逻辑已完全移至 VotingBlockchain 覆盖
        // if (this instanceof VotingBlockchain) { ... }

        // Block passes basic checks, add it
        // 区块通过基本检查，添加它
        chain.add(newBlock);
        // *** Add Logging for success ***
        // *** 添加成功的日志记录 ***
        System.out.println("Blockchain.addBlock: Block " + newBlock.getIndex() + " passed basic checks and added to chain (size now " + chain.size() + "). Returning true.");
        return true;
    }

    /** Gets the full chain */
    /** 获取完整链 */
    public List<Block> getChain() {
        return new ArrayList<>(chain); // Return a copy to prevent external modification 返回副本以防止外部修改
    }

    @Override
    public String toString() {
        return "Blockchain{chainSize=" + chain.size() + "}";
    }
}
