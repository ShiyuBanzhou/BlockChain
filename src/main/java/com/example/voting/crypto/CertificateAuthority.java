package com.example.voting.crypto;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLReason; // Import CRLReason
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder; // Import X509CRLHolder
import org.bouncycastle.cert.X509v2CRLBuilder; // Import X509v2CRLBuilder
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter; // Import JcaX509CRLConverter
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL; // Import X509CRL
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map; // Import Map
import java.util.Set; // Import Set
import java.util.concurrent.ConcurrentHashMap; // Use ConcurrentHashMap for thread safety 使用 ConcurrentHashMap 保证线程安全
import javax.security.auth.x500.X500Principal;

/**
 * Certificate Authority (CA) using Bouncy Castle.
 * Includes support for Certificate Revocation Lists (CRL).
 * 使用 Bouncy Castle 的证书颁发机构 (CA)。
 * 包含对证书吊销列表 (CRL) 的支持。
 */
public class CertificateAuthority {

    private final String commonName;
    private final KeyPair keyPair;
    private final X509Certificate caCertificate;
    private final X500Principal caPrincipal;

    // Store revoked certificate serial numbers and their revocation date
    // 存储被吊销证书的序列号及其吊销日期
    private final Map<BigInteger, Date> revokedCertificates = new ConcurrentHashMap<>();

    public CertificateAuthority(String commonName) {
        this.commonName = commonName;
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA", "BC");
            gen.initialize(2048, new SecureRandom());
            this.keyPair = gen.generateKeyPair();
            // Create self-signed cert *before* assigning caPrincipal
            // 在分配 caPrincipal *之前* 创建自签名证书
            X509Certificate tempCert = createSelfSignedCertificateInternal();
            this.caCertificate = tempCert;
            // Assign caPrincipal *after* cert creation
            // 在证书创建 *之后* 分配 caPrincipal
            this.caPrincipal = this.caCertificate.getSubjectX500Principal();
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize Certificate Authority", e);
        }
    }

    /** Internal helper to create self-signed cert */
    /** 创建自签名证书的内部辅助方法 */
    private X509Certificate createSelfSignedCertificateInternal() throws Exception {
        Instant now = Instant.now();
        Date validFrom = Date.from(now);
        Date validTo = Date.from(now.plus(365 * 10, ChronoUnit.DAYS));
        // Create X500Name for the CA
        // 为 CA 创建 X500Name
        X500Name caX500Name = new X500Name("CN=" + this.commonName + ", O=Voting Authority, C=XX");
        PublicKey caPublicKey = keyPair.getPublic();
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                caX500Name, serialNumber, validFrom, validTo, caX500Name, caPublicKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        // Ensure cRLSign usage is present for CA cert
        // 确保 CA 证书中存在 cRLSign 用法
        certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(caPublicKey));
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caPublicKey));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
    }

    public DigitalCertificate issueCertificate(String subjectCommonName, PublicKey subjectPublicKey, long validDays) {
        try {
            Instant now = Instant.now();
            Date validFrom = Date.from(now);
            Date validTo = Date.from(now.plus(validDays, ChronoUnit.DAYS));
            // Convert CA principal to BC X500Name for issuer
            // 将 CA principal 转换为 BC X500Name 作为颁发者
            X500Name issuerName = X500Name.getInstance(this.caPrincipal.getEncoded());
            X500Name subjectName = new X500Name("CN=" + subjectCommonName + ", OU=NodesOrVoters, O=Voting Authority, C=XX");
            // Ensure unique serial numbers, 128 bits should be sufficient
            // 确保序列号唯一，128 位应该足够
            BigInteger serialNumber = new BigInteger(128, new SecureRandom());

            X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                    issuerName, serialNumber, validFrom, validTo, subjectName, subjectPublicKey);

            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            certBuilder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
            certBuilder.addExtension(Extension.subjectKeyIdentifier, false, extUtils.createSubjectKeyIdentifier(subjectPublicKey));
            certBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCertificate.getPublicKey()));
            // Optionally add CRL Distribution Point extension here
            // 可选地在此处添加 CRL 分发点扩展

            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
            X509CertificateHolder certHolder = certBuilder.build(signer);
            X509Certificate issuedCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
            return new DigitalCertificate(issuedCert);
        } catch (Exception e) {
            System.err.println("Failed to issue certificate for " + subjectCommonName);
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Revokes a certificate by adding its serial number to the revocation list.
     * 通过将其序列号添加到吊销列表来吊销证书。
     * @param serialNumber The serial number of the certificate to revoke. 要吊销的证书的序列号。
     */
    public void revokeCertificate(BigInteger serialNumber) {
        if (serialNumber != null) {
            // Store current time as revocation date
            // 将当前时间存储为吊销日期
            revokedCertificates.putIfAbsent(serialNumber, new Date()); // Use putIfAbsent to avoid overwriting date 使用 putIfAbsent 避免覆盖日期
            System.out.println("CA: Revoked certificate with serial number: " + serialNumber.toString(16));
        }
    }

    /**
     * Revokes a certificate using the DigitalCertificate object.
     * 使用 DigitalCertificate 对象吊销证书。
     * @param cert The certificate to revoke. 要吊销的证书。
     */
    public void revokeCertificate(DigitalCertificate cert) {
        if (cert != null && cert.getX509Certificate() != null) {
            revokeCertificate(cert.getX509Certificate().getSerialNumber());
        }
    }

    /**
     * Generates the Certificate Revocation List (CRL) signed by the CA.
     * 生成由 CA 签名的证书吊销列表 (CRL)。
     * @param daysUntilNextUpdate Number of days until the next CRL update is expected. 距离下次 CRL 更新预期的天数。
     * @return The signed X509CRL object. 签名的 X509CRL 对象。
     */
    public X509CRL generateCRL(long daysUntilNextUpdate) {
        try {
            Instant now = Instant.now();
            Date thisUpdate = Date.from(now);
            Date nextUpdate = Date.from(now.plus(daysUntilNextUpdate, ChronoUnit.DAYS));

            // Use CA's name as the CRL issuer
            // 使用 CA 的名称作为 CRL 颁发者
            X500Name issuerName = X500Name.getInstance(this.caPrincipal.getEncoded());
            X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerName, thisUpdate);
            crlBuilder.setNextUpdate(nextUpdate);

            // Add revoked certificates to the CRL
            // 将被吊销的证书添加到 CRL
            System.out.println("CA: Generating CRL with " + revokedCertificates.size() + " revoked entries.");
            for (Map.Entry<BigInteger, Date> entry : revokedCertificates.entrySet()) {
                BigInteger serial = entry.getKey();
                Date revocationDate = entry.getValue();
                // Add revoked certificate entry with reason code (e.g., keyCompromise)
                // 添加带有原因代码（例如，keyCompromise）的已吊销证书条目
                crlBuilder.addCRLEntry(serial, revocationDate, CRLReason.keyCompromise);
                System.out.println("  - Added revoked serial: " + serial.toString(16));
            }

            // Add Authority Key Identifier extension to CRL (helps link CRL to CA cert)
            // 向 CRL 添加颁发机构密钥标识符扩展（有助于将 CRL 链接到 CA 证书）
            JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
            crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, extUtils.createAuthorityKeyIdentifier(caCertificate.getPublicKey()));

            // TODO: Add CRL Number extension (incrementing sequence number) for better CRL management
            // TODO: 添加 CRL 编号扩展（递增序列号）以实现更好的 CRL 管理

            // Sign the CRL using the CA's private key
            // 使用 CA 的私钥签署 CRL
            ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(keyPair.getPrivate());
            X509CRLHolder crlHolder = crlBuilder.build(signer);

            // Convert to standard Java X509CRL
            // 转换为标准 Java X509CRL
            System.out.println("CA: CRL generated successfully.");
            return new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);

        } catch (Exception e) {
            System.err.println("Failed to generate CRL");
            e.printStackTrace();
            return null;
        }
    }


    public boolean verifyCertificate(DigitalCertificate certWrapper) {
        // Verification logic remains the same as previous version
        // 验证逻辑与先前版本相同
        if (certWrapper == null || certWrapper.getX509Certificate() == null) {
            System.err.println("Verification failed: Certificate wrapper or X509Certificate is null.");
            return false;
        }
        X509Certificate cert = certWrapper.getX509Certificate();
        try {
            // Compare issuer principal object directly
            // 直接比较颁发者 principal 对象
            if (!cert.getIssuerX500Principal().equals(this.caPrincipal)) {
                System.err.println("Verification failed: Issuer DN [" + cert.getIssuerX500Principal() + "] does not match CA Subject DN [" + this.caPrincipal + "].");
                return false;
            }
            cert.verify(this.keyPair.getPublic());
            cert.checkValidity();
            return true;
        } catch (CertificateException e) {
            // More specific logging for validity issues
            // 更具体的有效期问题日志记录
            System.err.println("Certificate verification failed (Validity/Encoding) for ["+ cert.getSubjectX500Principal() +"]: " + e.getMessage());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException | NoSuchProviderException e) {
            // More specific logging for signature issues
            // 更具体的签名问题日志记录
            System.err.println("Certificate verification failed (Signature) for ["+ cert.getSubjectX500Principal() +"]: " + e.getMessage());
        } catch (Exception e) {
            // Catch-all for unexpected errors
            // 捕获所有意外错误
            System.err.println("Unexpected error during certificate verification for ["+ cert.getSubjectX500Principal() +"]: " + e.getMessage());
            e.printStackTrace();
        }
        return false; // Return false if any verification step failed 如果任何验证步骤失败则返回 false
    }

    public PublicKey getPublicKey() { return keyPair.getPublic(); }
    public X509Certificate getCaCertificate() { return caCertificate; }
}
