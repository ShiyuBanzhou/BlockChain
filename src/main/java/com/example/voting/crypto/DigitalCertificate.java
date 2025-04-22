package com.example.voting.crypto;

import java.security.PublicKey;
import java.time.Instant;
import java.util.UUID;

/**
 * 模拟 X.509 证书结构
 */
public class DigitalCertificate {
    private String serialNumber;    // 序列号
    private String subject;         // 持有者标识（选民ID 或节点ID）
    private PublicKey publicKey;    // 公钥
    private long validFrom, validTo;// 有效期
    private String issuer;          // 颁发者名称
    private byte[] signature;       // CA 签名

    public DigitalCertificate(String subject, PublicKey pubKey, String issuer, long validDays) {
        this.serialNumber = UUID.randomUUID().toString();
        this.subject = subject;
        this.publicKey = pubKey;
        this.issuer = issuer;
        this.validFrom = Instant.now().toEpochMilli();
        this.validTo = Instant.now().plusMillis(validDays*86400_000L).toEpochMilli();
    }
    // Getters & setter for signature...
    public String getSerialNumber() { return serialNumber; }
    public String getSubject() { return subject; }
    public PublicKey getPublicKey() { return publicKey; }
    public long getValidTo() { return validTo; }
    public String getIssuer() { return issuer; }
    public byte[] getSignature() { return signature; }
    public void setSignature(byte[] sig) { this.signature = sig; }
}
