package com.example.voting.blockchain;

import java.util.ArrayList;
import java.util.List;

/**
 * 区块链框架基类，提供链维护与共识接口
 */
public class Blockchain {
    protected List<Block> chain = new ArrayList<>();
    public int difficulty = 0;           // PoW 难度
    protected int requiredSignatures = 1;   // PoA 需要的签名数量

    public Blockchain() {
        // 创建创世区块
        Block genesis = new Block(0, "0");
        genesis.addTransaction(new Transaction(Transaction.Type.OTHER, "Genesis Block"));
        genesis.finalizeBlock();
        chain.add(genesis);
    }

    /** 获取最新区块 */
    public Block getLastBlock() {
        return chain.get(chain.size() - 1);
    }

    /**
     * 添加新区块：先校验前哈希，再根据子类决定 PoW 或 PoA 规则
     */
    public boolean addBlock(Block newBlock) {
        Block prev = getLastBlock();
        if (!newBlock.getPrevHash().equals(prev.getHash())) {
            return false;
        }
        // PoW 共识检查
        if (this instanceof VotingBlockchain) {
            String prefix = "0".repeat(difficulty);
            if (!newBlock.getHash().startsWith(prefix)) {
                return false;
            }
        }
        // PoA 共识检查
        if (this instanceof IdentityBlockchain) {
            if (((IdentityBlockchain)this).countValidSignatures(newBlock) < requiredSignatures) {
                return false;
            }
        }
        chain.add(newBlock);
        return true;
    }

    /** 获取完整链 */
    public List<Block> getChain() {
        return chain;
    }
}
