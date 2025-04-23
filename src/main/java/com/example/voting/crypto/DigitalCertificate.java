package com.example.voting.crypto;

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * Digital Certificate wrapper using standard X.509 certificate.
 * 使用标准 X.509 证书的数字证书包装器。
 */
public class DigitalCertificate {

    private final X509Certificate certificate; // The actual X.509 certificate object 实际的 X.509 证书对象

    /**
     * Constructor to wrap an existing X509Certificate.
     * 包装现有 X509Certificate 的构造函数。
     * @param certificate The X.509 certificate to wrap. 要包装的 X.509 证书。
     */
    public DigitalCertificate(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null.");
        }
        this.certificate = certificate;
    }

    /**
     * Gets the underlying X.509 certificate.
     * 获取底层的 X.509 证书。
     * @return The X509Certificate object. X509Certificate 对象。
     */
    public X509Certificate getX509Certificate() {
        return certificate;
    }

    // --- Convenience methods to access common certificate fields ---
    // --- 访问常用证书字段的便捷方法 ---

    /**
     * Gets the subject distinguished name (DN).
     * 获取使用者可分辨名称 (DN)。
     * Example: "CN=VoterAlice, OU=VotingGroup, O=MyOrg, C=US"
     * @return Subject DN string. 使用者 DN 字符串。
     */
    public String getSubject() {
        // Note: getSubjectX500Principal().getName() returns the full DN string
        // 注意：getSubjectX500Principal().getName() 返回完整的 DN 字符串
        return certificate.getSubjectX500Principal().getName();
    }

    /**
     * Gets the issuer distinguished name (DN).
     * 获取颁发者可分辨名称 (DN)。
     * @return Issuer DN string. 颁发者 DN 字符串。
     */
    public String getIssuer() {
        return certificate.getIssuerX500Principal().getName();
    }

    /**
     * Gets the certificate serial number.
     * 获取证书序列号。
     * @return Serial number as a String. 序列号字符串。
     */
    public String getSerialNumber() {
        return certificate.getSerialNumber().toString(16); // Usually displayed in hex 通常以十六进制显示
    }

    /**
     * Gets the public key from the certificate.
     * 从证书获取公钥。
     * @return The PublicKey object. PublicKey 对象。
     */
    public PublicKey getPublicKey() {
        return certificate.getPublicKey();
    }

    /**
     * Gets the start date of the certificate validity period.
     * 获取证书有效期的开始日期。
     * @return The start date. 开始日期。
     */
    public Date getValidFrom() {
        return certificate.getNotBefore();
    }

    /**
     * Gets the end date of the certificate validity period.
     * 获取证书有效期的结束日期。
     * @return The end date. 结束日期。
     */
    public Date getValidTo() {
        return certificate.getNotAfter();
    }

    /**
     * Gets the signature algorithm name.
     * 获取签名算法名称。
     * Example: "SHA256withRSA"
     * @return Signature algorithm name. 签名算法名称。
     */
    public String getSignatureAlgorithm() {
        return certificate.getSigAlgName();
    }

    /**
     * Verifies the certificate's signature using the issuer's public key.
     * 使用颁发者的公钥验证证书签名。
     * Note: This only checks the signature, not the validity period or revocation status.
     * 注意：这仅检查签名，不检查有效期或吊销状态。
     * @param issuerPublicKey The public key of the certificate issuer (CA). 证书颁发者 (CA) 的公钥。
     * @return true if the signature is valid, false otherwise. 如果签名有效则返回 true，否则返回 false。
     */
    public boolean verifySignature(PublicKey issuerPublicKey) {
        try {
            // Use Bouncy Castle provider explicitly for verification
            // 显式使用 Bouncy Castle 提供者进行验证
            certificate.verify(issuerPublicKey, "BC");
            return true;
        } catch (Exception e) {
            System.err.println("Certificate signature verification failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Checks if the certificate is currently valid (within its validity period).
     * 检查证书当前是否有效（在有效期内）。
     * @return true if the certificate is valid today, false otherwise. 如果证书当前有效则返回 true，否则返回 false。
     */
    public boolean isValid() {
        try {
            certificate.checkValidity(); // Checks NotBefore and NotAfter dates 检查 NotBefore 和 NotAfter 日期
            return true;
        } catch (Exception e) {
            // CertificateExpiredException or CertificateNotYetValidException
            // 证书过期异常或证书尚未生效异常
            System.err.println("Certificate validity check failed: " + e.getMessage());
            return false;
        }
    }

    @Override
    public String toString() {
        return "DigitalCertificate{" +
                "subject='" + getSubject() + '\'' +
                ", issuer='" + getIssuer() + '\'' +
                ", serialNumber='" + getSerialNumber() + '\'' +
                ", validTo=" + getValidTo() +
                '}';
    }
}
