package com.example.voting.blockchain;

import com.example.voting.crypto.CryptoUtil;

/**
 * 投票链：使用 PoW 挖矿
 */
public class VotingBlockchain extends Blockchain {
    public VotingBlockchain(int difficulty) {
        super();
        this.difficulty = difficulty;
    }

    /** 挖矿：寻找满足 difficulty 前导零的哈希 */
    public Block mineBlock(Transaction tx) {
        Block last = getLastBlock();
        Block newBlock = new Block(last.getIndex() + 1, last.getHash());
        newBlock.addTransaction(tx);
        int nonce = 0;
        String prefix = "0".repeat(difficulty);
        while (true) {
            String data = newBlock.getIndex() + newBlock.getPrevHash()
                    + newBlock.getTimestamp() + newBlock.getTransactions().toString()
                    + nonce;
            String hash = CryptoUtil.sha256(data);
            if (hash.startsWith(prefix)) {
                newBlock.addTransaction(new Transaction(Transaction.Type.OTHER, "Nonce=" + nonce));
                newBlock.finalizeBlock();
                break;
            }
            nonce++;
        }
        return newBlock;
    }
}
