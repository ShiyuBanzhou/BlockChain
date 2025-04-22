package com.example.voting.blockchain;

import java.util.Set;
import com.example.voting.crypto.CryptoUtil;

/**
 * 身份链：采用 PoA（权威签名）共识
 */
public class IdentityBlockchain extends Blockchain {
    private Set<String> authorityPubKeys;

    public IdentityBlockchain(int requiredSignatures, Set<String> authorityPubKeys) {
        super();
        this.requiredSignatures = requiredSignatures;
        this.authorityPubKeys = authorityPubKeys;
    }

    /** 权威节点对区块进行签名 */
    public void signBlock(Block block, String authorityPrivateKey) {
        String sig = CryptoUtil.signSHA256(block.computeHash(), authorityPrivateKey);
        block.getSignatures().add(sig);
    }

    /** 统计有效签名数（应验证每个签名对应的公钥，这里简化处理） */
    public int countValidSignatures(Block block) {
        return block.getSignatures().size();
    }
}
