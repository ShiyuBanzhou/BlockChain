package com.example.voting.crypto;

import java.security.*;
import java.security.cert.CertificateException;
import java.time.Instant;

/**
 * 模拟证书颁发机构（CA）
 */
public class CertificateAuthority {
    private String name;
    private KeyPair keyPair;  // CA 自身密钥对

    public CertificateAuthority(String name) {
        this.name = name;
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            this.keyPair = gen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("CA 密钥生成失败", e);
        }
    }

    /** 颁发证书：签名证书内容 */
    public DigitalCertificate issueCertificate(String subject, KeyPair subjectKey, long validDays) {
        DigitalCertificate cert = new DigitalCertificate(subject, subjectKey.getPublic(), name, validDays);
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(keyPair.getPrivate());
            String data = cert.getSerialNumber() + cert.getSubject() + cert.getIssuer()
                    + cert.getValidTo() + cert.getPublicKey().toString();
            sig.update(data.getBytes());
            cert.setSignature(sig.sign());
        } catch (Exception e) {
            throw new RuntimeException("签发证书失败", e);
        }
        return cert;
    }

    /** 验证证书有效性和签名 */
    public boolean verifyCertificate(DigitalCertificate cert) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(keyPair.getPublic());
            String data = cert.getSerialNumber() + cert.getSubject() + cert.getIssuer()
                    + cert.getValidTo() + cert.getPublicKey().toString();
            sig.update(data.getBytes());
            return sig.verify(cert.getSignature()) && Instant.now().toEpochMilli() < cert.getValidTo();
        } catch (Exception e) {
            return false;
        }
    }
}
