package com.simulation.blockchain.basic;

import com.simulation.blockchain.security.SecurityUtils;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Block implements java.io.Serializable {
    public String hash;
    public String previousHash;
    public String data;
    public long timeStamp;
    public String signature;
    public String certificate;

    public Block(
            String data, String previousHash,
            PrivateKey privKey, X509Certificate cert
    ) throws Exception {
        this.data = data;
        this.previousHash = previousHash;
        this.timeStamp = System.currentTimeMillis();
        this.hash = calculateHash();
        byte[] sigBytes = SecurityUtils.signData(this.hash, privKey);
        this.signature = Base64.getEncoder().encodeToString(sigBytes);
        this.certificate = SecurityUtils.certToBase64(cert);
    }

    public String calculateHash() {
        return StringUtil.applySha256(previousHash + timeStamp + data);
    }

    public boolean isValid() throws Exception {
        if (!hash.equals(calculateHash())) return false;
        X509Certificate cert = SecurityUtils.loadCertificate(certificate);
        PublicKey pubKey = cert.getPublicKey();
        byte[] sigBytes = Base64.getDecoder().decode(signature);
        return SecurityUtils.verifyData(hash, sigBytes, pubKey);
    }
}
