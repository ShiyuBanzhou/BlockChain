package com.example.voting.blockchain;

import com.example.voting.crypto.CryptoUtil;
import com.example.voting.crypto.DigitalCertificate;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

/**
 * Identity chain using Proof-of-Authority (PoA) consensus.
 * Includes storage for node certificates and skips PoA check for voter registration blocks.
 * 使用权威证明 (PoA) 共识的身份链。
 * 现在包含节点证书的存储，并跳过选民注册区块的 PoA 检查。
 */
public class IdentityBlockchain extends Blockchain {
    private Set<PublicKey> authorityPubKeys;
    private Map<String, DigitalCertificate> nodeCertificates = new HashMap<>();

    public IdentityBlockchain(int requiredSignatures, Set<PublicKey> authorityPubKeys) {
        super();
        this.requiredSignatures = requiredSignatures;
        this.authorityPubKeys = authorityPubKeys;
        System.out.println("Identity Blockchain initialized. Required Signatures: " + requiredSignatures);
    }

    public void registerNodeCertificate(DigitalCertificate cert) {
        if (cert != null && cert.getX509Certificate() != null) {
            String subjectDN = cert.getSubject();
            String nodeId = extractCN(subjectDN);
            if (nodeId != null) {
                nodeCertificates.put(nodeId, cert);
                // System.out.println("IdentityBlockchain: Registered certificate for node '" + nodeId + "'");
            } else {
                System.err.println("IdentityBlockchain: Could not extract CN from certificate subject: " + subjectDN);
            }
        } else {
            System.err.println("IdentityBlockchain: Attempted to register a null or invalid certificate.");
        }
    }

    public DigitalCertificate getCertificateForNode(String nodeId) {
        return nodeCertificates.get(nodeId);
    }

    private String extractCN(String dn) {
        if (dn == null) return null;
        String[] parts = dn.split(",");
        for (String part : parts) {
            String trimmedPart = part.trim();
            if (trimmedPart.toUpperCase().startsWith("CN=")) {
                return trimmedPart.substring(3);
            }
        }
        return null;
    }

    public void signBlock(Block block, PrivateKey authorityPrivateKey) {
        if (block == null || authorityPrivateKey == null) {
            System.err.println("Error signing block: Block or private key is null.");
            return;
        }
        try {
            String blockHash = block.computeHash();
            String sig = CryptoUtil.signSHA256withRSA(blockHash, authorityPrivateKey);
            if (sig != null) {
                block.getSignatures().add(sig);
            } else {
                System.err.println("Failed to generate signature for block " + block.getIndex());
            }
        } catch (Exception e) {
            System.err.println("Error during block signing for block " + block.getIndex() + ": " + e.getMessage());
            e.printStackTrace();
        }
    }

    public int countValidSignatures(Block block) {
        if (block == null) return 0;
        return block.getSignatures().size();
    }

    /**
     * Overrides addBlock to include PoA check, skipping it for voter identity blocks.
     * 覆盖 addBlock 以包含 PoA 检查，但跳过选民身份区块的检查。
     * Explicitly manages return value.
     * 显式管理返回值。
     */
    @Override
    public boolean addBlock(Block newBlock) {
        System.out.println("IdentityBlockchain.addBlock: Attempting to add Block " + newBlock.getIndex());

        // 1. Perform basic prevHash check directly here
        // 1. 直接在此处执行基本的 prevHash 检查
        if (newBlock == null) {
            System.err.println("IdentityBlockchain.addBlock: Attempted to add a null block.");
            return false;
        }
        Block prev = getLastBlock();
        String expectedPrevHash = prev.getHash();
        String actualPrevHash = newBlock.getPrevHash();

        System.out.println("IdentityBlockchain.addBlock: Checking Block " + newBlock.getIndex() +
                ". PrevHash expected: " + (expectedPrevHash != null ? expectedPrevHash.substring(0, 8) : "null") + "..." +
                ", Block has prevHash: " + (actualPrevHash != null ? actualPrevHash.substring(0, 8) : "null") + "...");

        if (actualPrevHash == null || !actualPrevHash.equals(expectedPrevHash)) {
            System.err.println("IdentityBlockchain.addBlock: Block " + newBlock.getIndex() + " REJECTED due to prevHash mismatch.");
            return false; // Fails basic prevHash check
        }
        System.out.println("IdentityBlockchain.addBlock: Block " + newBlock.getIndex() + " passed prevHash check.");


        // 2. Check if this block is primarily for voter registration
        // 2. 检查此区块是否主要用于选民注册
        boolean isVoterRegistrationBlock = false;
        if (!newBlock.getTransactions().isEmpty()) {
            Transaction firstTx = newBlock.getTransactions().get(0);
            if (firstTx.getType() == Transaction.Type.IDENTITY &&
                    firstTx.getPayload() != null &&
                    firstTx.getPayload().startsWith("ADD_VOTER:")) {
                isVoterRegistrationBlock = true;
            }
        }
        System.out.println("IdentityBlockchain.addBlock: Block " + newBlock.getIndex() + " - isVoterRegistrationBlock = " + isVoterRegistrationBlock);


        // 3. Apply PoA Consensus Check ONLY if it's NOT a voter registration block
        // 3. 仅当它不是选民注册区块时才应用 PoA 共识检查
        if (!isVoterRegistrationBlock) {
            int sigCount = countValidSignatures(newBlock);
            System.out.println("IdentityBlockchain.addBlock: Block " + newBlock.getIndex() + " is NOT voter registration. Checking PoA signatures ("+ sigCount + "/" + this.requiredSignatures +").");
            if (sigCount < this.requiredSignatures) {
                // PoA check failed for a non-voter block.
                System.err.println("IdentityBlockchain.addBlock: Block " + newBlock.getIndex() + " REJECTED: Insufficient PoA signatures.");
                // Do NOT add the block
                // 不要添加区块
                return false; // Indicate failure
            } else {
                System.out.println("IdentityBlockchain.addBlock: Block " + newBlock.getIndex() + " passed PoA check.");
                // PoA passed, proceed to add block
                // PoA 通过，继续添加区块
            }
        } else {
            // Voter registration block, PoA check skipped. Proceed to add block.
            // 选民注册区块，跳过 PoA 检查。继续添加区块。
            System.out.println("IdentityBlockchain.addBlock: Block " + newBlock.getIndex() + " (Voter Registration) PoA check skipped.");
        }

        // 4. If all checks passed or were skipped, add the block to the chain
        // 4. 如果所有检查都通过或被跳过，则将区块添加到链中
        chain.add(newBlock);
        System.out.println("IdentityBlockchain.addBlock: Block " + newBlock.getIndex() + " successfully added to chain (size now " + chain.size() + "). Returning true.");
        return true; // Explicitly return true after successful addition
    }

    @Override
    public String toString() {
        return "IdentityBlockchain{" +
                "chainSize=" + chain.size() +
                ", requiredSignatures=" + requiredSignatures +
                ", knownNodeCerts=" + nodeCertificates.size() +
                '}';
    }
}