package com.example.voting.blockchain;

import com.example.voting.crypto.CryptoUtil;
import com.example.voting.SystemLogger; // Import SystemLogger
import javax.crypto.SecretKey; // Import SecretKey
import java.util.HashMap; // Import HashMap
import java.util.List; // Import List
import java.util.Map; // Import Map
import java.util.Collections; // Import Collections

/**
 * Voting chain using Proof-of-Work (PoW).
 * Includes optimized state management for vote counts.
 * 使用工作量证明 (PoW) 的投票链。
 * 包含投票计数的优化状态管理。
 */
public class VotingBlockchain extends Blockchain {

    // Cache for vote counts, mapping candidate name to count
    // 投票计数缓存，将候选人名称映射到计数
    private Map<String, Integer> voteCountsCache = new HashMap<>();
    private boolean cacheValid = false; // Flag to indicate if cache needs rebuilding 标记缓存是否需要重建

    public VotingBlockchain(int difficulty) {
        super();
        this.difficulty = difficulty;
        // Initialize cache for known candidates
        // 为已知候选人初始化缓存
        voteCountsCache.put("候选人1", 0);
        voteCountsCache.put("候选人2", 0);
        voteCountsCache.put("候选人3", 0);
        // Cache is initially invalid until first tally
        // 缓存在首次计票前初始无效
        SystemLogger.log("Voting Blockchain initialized. Difficulty: " + difficulty);
    }

    /**
     * Overrides addBlock to perform PoW check AFTER basic validation.
     * Informs that the cache is now invalid.
     * 覆盖 addBlock 以在基本验证后执行 PoW 检查。
     * 通知缓存现在无效。
     * @param newBlock The block to add. 要添加的区块。
     * @return true if the block passes checks and is added, false otherwise. 如果区块通过检查并已添加，则返回 true，否则返回 false。
     */
    @Override
    public boolean addBlock(Block newBlock) {
        // 1. Perform basic checks (prevHash) from parent.
        //    If checks fail, return false. Parent does NOT add the block yet.
        // 1. 执行父类的基本检查 (prevHash)。
        //    如果检查失败，返回 false。父类尚未添加区块。
        //    We need to re-check prevHash here because super.addBlock was removed from IdentityBlockchain override.
        //    我们需要在此处重新检查 prevHash，因为 super.addBlock 已从 IdentityBlockchain 覆盖中删除。
        if (newBlock == null) {
            SystemLogger.error("VotingBlockchain.addBlock: Attempted to add a null block.");
            return false;
        }
        Block prev = getLastBlock();
        if (newBlock.getPrevHash() == null || !newBlock.getPrevHash().equals(prev.getHash())) {
            SystemLogger.error("VotingBlockchain.addBlock: Block " + newBlock.getIndex() + " REJECTED due to prevHash mismatch.");
            return false;
        }
        SystemLogger.log("VotingBlockchain.addBlock: Block " + newBlock.getIndex() + " passed prevHash check.");

        // 2. Perform PoW check
        // 2. 执行 PoW 检查
        String prefix = "0".repeat(difficulty);
        // We need the block's hash. It should be set by the miner before calling addBlock.
        // 我们需要区块的哈希。矿工应在调用 addBlock 之前设置它。
        if (newBlock.getHash() == null || !newBlock.getHash().startsWith(prefix)) {
            SystemLogger.error("VotingBlockchain.addBlock: Block " + newBlock.getIndex() + " REJECTED due to invalid PoW hash (Hash: " + newBlock.getHash() + ", Prefix: " + prefix + ")");
            return false; // PoW check failed PoW 检查失败
        }
        SystemLogger.log("VotingBlockchain.addBlock: Block " + newBlock.getIndex() + " passed PoW check.");

        // 3. If all checks pass, add the block to the chain
        // 3. 如果所有检查都通过，则将区块添加到链中
        chain.add(newBlock);
        cacheValid = false; // Invalidate cache whenever a new block is added 每当添加新区块时使缓存无效
        SystemLogger.log("VotingBlockchain.addBlock: Block " + newBlock.getIndex() + " successfully added (Cache invalidated). Chain size: " + chain.size());
        return true;
    }

    /**
     * Recalculates the vote counts by iterating through the entire chain
     * and updates the cache. This should be called when results are needed
     * and the cache is invalid.
     * 通过遍历整个链重新计算投票计数并更新缓存。
     * 当需要结果且缓存无效时应调用此方法。
     * @param tallyKey The AES key required to decrypt votes. 解密投票所需的 AES 密钥。
     * @return true if tallying was successful, false otherwise. 如果计票成功则返回 true，否则返回 false。
     */
    public boolean tallyVotesFromChain(SecretKey tallyKey) {
        SystemLogger.log("VotingBlockchain: Starting full vote tally from chain...");
        if (tallyKey == null) {
            SystemLogger.error("VotingBlockchain: Cannot tally votes, tally key is null.");
            return false;
        }

        // Reset cache
        // 重置缓存
        Map<String, Integer> tempCounts = new HashMap<>();
        tempCounts.put("候选人1", 0);
        tempCounts.put("候选人2", 0);
        tempCounts.put("候选人3", 0);
        int processedVotes = 0;

        // Iterate through the chain (skip genesis block)
        // 遍历链（跳过创世区块）
        for (int i = 1; i < chain.size(); i++) { // Start from index 1 从索引 1 开始
            Block block = chain.get(i);
            for (Transaction tx : block.getTransactions()) {
                if (tx.getType() == Transaction.Type.VOTE) {
                    String[] parts = tx.getPayload().split("\\|");
                    if (parts.length >= 1) {
                        String cipherTextBase64 = parts[0];
                        String decryptedVote = CryptoUtil.decryptAES(cipherTextBase64, tallyKey);
                        if (decryptedVote != null) {
                            tempCounts.put(decryptedVote, tempCounts.getOrDefault(decryptedVote, 0) + 1);
                            processedVotes++;
                        } else {
                            SystemLogger.error("VotingBlockchain: Failed to decrypt vote in block " + block.getIndex());
                        }
                    } else {
                        SystemLogger.error("VotingBlockchain: Invalid vote payload format in block " + block.getIndex());
                    }
                }
            }
        }

        // Update the cache and mark as valid
        // 更新缓存并标记为有效
        this.voteCountsCache = tempCounts;
        this.cacheValid = true;
        SystemLogger.log("VotingBlockchain: Vote tally complete. Processed " + processedVotes + " votes. Cache updated.");
        return true;
    }

    /**
     * Returns the latest vote counts. If the cache is invalid,
     * it triggers a recalculation using the provided tally key.
     * 返回最新的投票计数。如果缓存无效，
     * 它会使用提供的计票密钥触发重新计算。
     * @param tallyKey The AES key needed for recalculation if cache is invalid. 如果缓存无效，重新计算所需的 AES 密钥。
     * @return A map of candidate names to vote counts, or an empty map if tallying fails. 候选人名称到投票计数的 Map，如果计票失败则返回空 Map。
     */
    public Map<String, Integer> getLatestVoteCounts(SecretKey tallyKey) {
        if (!cacheValid) {
            SystemLogger.log("VotingBlockchain: Cache is invalid, triggering recalculation...");
            if (!tallyVotesFromChain(tallyKey)) {
                // Tallying failed, return empty map or handle error appropriately
                // 计票失败，返回空 Map 或适当处理错误
                return Collections.emptyMap();
            }
        } else {
            SystemLogger.log("VotingBlockchain: Returning vote counts from valid cache.");
        }
        // Return a copy to prevent external modification
        // 返回副本以防止外部修改
        return new HashMap<>(voteCountsCache);
    }

    /**
     * Checks if the vote cache is currently valid.
     * 检查投票缓存当前是否有效。
     * @return true if the cache is valid, false otherwise. 如果缓存有效则返回 true，否则返回 false。
     */
    public boolean isCacheValid() {
        return cacheValid;
    }

    // mineBlock method might be removed if mining logic is fully in MainApp
    // 如果挖掘逻辑完全在 MainApp 中，则可以删除 mineBlock 方法
    /*
    public Block mineBlock(Transaction tx) {
        // ... (Mining logic - This should probably live in the entity performing the mining)
        // ... （挖掘逻辑 - 这可能应该存在于执行挖掘的实体中）
    }
    */
    @Override
    public String toString() {
        return "VotingBlockchain{chainSize=" + chain.size() + ", difficulty=" + difficulty + ", cacheValid=" + cacheValid + "}";
    }
}