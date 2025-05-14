package com.bjut.ca.server.impl;

import com.bjut.ca.Util.CertificateValidator;
import com.bjut.ca.Util.PublicKeyUtil;
import com.bjut.ca.Util.X509CertificateUtil; // 确保导入
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class CAimpl {

    public static final Logger logger = LoggerFactory.getLogger(CAimpl.class);

    private KeyPair caKeyPair;
    private X509Certificate caCertificate;

    // KeyStore 配置
    private static final String KEYSTORE_FILE_PATH = "ca_keystore.p12";
    private static final String KEYSTORE_PASSWORD = "changeit"; // 生产环境中应使用更安全的管理方式
    private static final String CA_ALIAS = "cakey";

    // CRL 相关配置
    private static final String CRL_DIST_POINT_URI = "http://localhost:9065/ca/crl"; // CRL分发点URL，端口和路径应与实际部署匹配
    private final List<RevokedCertificateEntry> revokedCertificates = new CopyOnWriteArrayList<>(); // 存储已吊销证书信息 (线程安全)
    public BigInteger crlNumber = BigInteger.ONE; // CRL编号，每次生成新的CRL时递增

    // 内部类用于存储吊销信息
    private static class RevokedCertificateEntry {
        final BigInteger serialNumber;
        final Date revocationDate;
        final CRLReason reason; // org.bouncycastle.asn1.x509.CRLReason

        RevokedCertificateEntry(BigInteger serialNumber, Date revocationDate, CRLReason reason) {
            this.serialNumber = serialNumber;
            this.revocationDate = revocationDate;
            this.reason = reason;
        }
    }

    public CAimpl() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        loadOrGenerateCA();
        // TODO: 在实际应用中，吊销列表也应该持久化和加载
        // loadRevokedCertificates();
    }

    private void loadOrGenerateCA() throws Exception {
        File keystoreFile = new File(KEYSTORE_FILE_PATH);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        if (keystoreFile.exists()) {
            logger.info("正在从 {} 加载已存在的CA密钥库...", KEYSTORE_FILE_PATH);
            try (FileInputStream fis = new FileInputStream(keystoreFile)) {
                keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
                if (keyStore.containsAlias(CA_ALIAS)) {
                    PrivateKey privateKey = (PrivateKey) keyStore.getKey(CA_ALIAS, KEYSTORE_PASSWORD.toCharArray());
                    java.security.cert.Certificate certificate = keyStore.getCertificate(CA_ALIAS);
                    if (privateKey == null || !(certificate instanceof X509Certificate)) {
                        logger.error("密钥库 {} 中的别名 {} 存在，但未能正确加载密钥或证书。", KEYSTORE_FILE_PATH, CA_ALIAS);
                        throw new KeyStoreException("无法从密钥库加载有效的CA密钥或证书。");
                    }
                    PublicKey publicKey = certificate.getPublicKey();
                    this.caKeyPair = new KeyPair(publicKey, privateKey);
                    this.caCertificate = (X509Certificate) certificate;
                    logger.info("CA密钥对和根证书已成功从密钥库 {} 加载。", KEYSTORE_FILE_PATH);
                    try {
                        this.caCertificate.checkValidity();
                        logger.info("加载的CA根证书当前有效。有效期至: {}", this.caCertificate.getNotAfter());
                    } catch (CertificateExpiredException e) {
                        logger.warn("警告：从密钥库加载的CA根证书已过期！日期: {}", this.caCertificate.getNotAfter());
                    } catch (CertificateNotYetValidException e) {
                        logger.warn("警告：从密钥库加载的CA根证书尚未生效！日期: {}", this.caCertificate.getNotBefore());
                    }
                    return;
                } else {
                    logger.warn("密钥库 {} 存在但未找到别名 {}。将尝试生成新的CA。", KEYSTORE_FILE_PATH, CA_ALIAS);
                }
            } catch (Exception e) {
                logger.error("从密钥库 {} 加载CA密钥对和证书失败。将尝试生成新的CA。错误: {}", KEYSTORE_FILE_PATH, e.getMessage(), e);
            }
        }

        logger.info("未找到或无法加载现有的CA密钥库。正在生成新的CA密钥对和根证书...");
        this.caKeyPair = generateKeyPair();
        this.caCertificate = generateCACertificate(this.caKeyPair);
        logger.info("新的CA密钥对和根证书已生成。");

        keyStore.load(null, null);
        keyStore.setKeyEntry(CA_ALIAS, this.caKeyPair.getPrivate(), KEYSTORE_PASSWORD.toCharArray(), new java.security.cert.Certificate[]{this.caCertificate});
        try (FileOutputStream fos = new FileOutputStream(keystoreFile)) {
            keyStore.store(fos, KEYSTORE_PASSWORD.toCharArray());
            logger.info("新的CA密钥对和根证书已保存到密钥库: {}", KEYSTORE_FILE_PATH);
        } catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
            logger.error("保存新的CA密钥对和根证书到密钥库 {} 失败: {}", KEYSTORE_FILE_PATH, e.getMessage(), e);
            throw new RuntimeException("无法保存CA密钥库。", e);
        }
    }

    public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        logger.debug("生成新的RSA密钥对。");
        return keyPairGenerator.generateKeyPair();
    }

    private X509Certificate generateCACertificate(KeyPair keyPair) throws OperatorCreationException, CertificateException, CertIOException, NoSuchAlgorithmException {
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        X500Name issuerAndSubject = new X500Name("CN=MyBlockchainRootCA, OU=BlockchainDept, O=MyOrg, L=Beijing, ST=Beijing, C=CN");
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Calendar calendar = Calendar.getInstance();
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 10);
        Date endDate = calendar.getTime();

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerAndSubject, serialNumber, startDate, endDate, issuerAndSubject, publicKey);

        BasicConstraints basicConstraints = new BasicConstraints(true);
        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(publicKey);
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(privateKey);
        logger.debug("正在生成自签名CA根证书，序列号: {}, 有效期: {} - {}", serialNumber, startDate, endDate);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
    }

    public X509Certificate issueCertificate(PublicKey subjectPublicKey, String subjectDN) throws OperatorCreationException, CertificateException, CertIOException, NoSuchAlgorithmException {
        PrivateKey caPrivateKey = this.caKeyPair.getPrivate();
        X500Name issuer = new X500Name(this.caCertificate.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(subjectDN);
        BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());
        Calendar calendar = Calendar.getInstance();
        Date startDate = calendar.getTime();
        calendar.add(Calendar.YEAR, 1);
        Date endDate = calendar.getTime();

        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer, serialNumber, startDate, endDate, subject, subjectPublicKey);

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        BasicConstraints basicConstraints = new BasicConstraints(false);
        certBuilder.addExtension(Extension.basicConstraints, true, basicConstraints);
        KeyUsage keyUsage = new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment | KeyUsage.dataEncipherment);
        certBuilder.addExtension(Extension.keyUsage, true, keyUsage);
        KeyPurposeId[] ekUsages = new KeyPurposeId[]{
                KeyPurposeId.id_kp_clientAuth, KeyPurposeId.id_kp_serverAuth};
        ExtendedKeyUsage extendedKeyUsage = new ExtendedKeyUsage(ekUsages);
        certBuilder.addExtension(Extension.extendedKeyUsage, false, extendedKeyUsage);
        SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(subjectPublicKey);
        certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);
        AuthorityKeyIdentifier aki = extUtils.createAuthorityKeyIdentifier(this.caCertificate.getPublicKey());
        certBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);

        GeneralName crlDistributionPointName = new GeneralName(GeneralName.uniformResourceIdentifier, CRL_DIST_POINT_URI);
        GeneralNames crlDistributionPointNames = new GeneralNames(crlDistributionPointName);
        DistributionPointName dpn = new DistributionPointName(DistributionPointName.FULL_NAME, crlDistributionPointNames);
        DistributionPoint crlDistributionPoint = new DistributionPoint(dpn, null, null);
        certBuilder.addExtension(Extension.cRLDistributionPoints, false, new DERSequence(crlDistributionPoint));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(caPrivateKey);
        logger.info("正在为主题 '{}' 颁发证书，序列号: {}, 由 '{}' 签名。", subjectDN, serialNumber, issuer.toString());
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(certBuilder.build(signer));
    }

    public boolean revokeCertificate(BigInteger serialNumber, int reasonCode) {
        if (serialNumber == null) {
            logger.warn("尝试吊销证书失败：序列号为null。");
            return false;
        }
        if (revokedCertificates.stream().anyMatch(entry -> entry.serialNumber.equals(serialNumber))) {
            logger.info("证书 (序列号: {}) 之前已被吊销。", serialNumber);
            return false;
        }

        CRLReason reason = CRLReason.lookup(reasonCode);
        if (reason == null) { // lookup returns null if code is invalid
            logger.warn("无效的吊销原因代码: {}。将使用默认原因 unspecified。", reasonCode);
            // Ensure we use the integer code for unspecified if lookup failed for the original code
            reason = CRLReason.lookup(CRLReason.unspecified);
        }
        // If reason is still null (e.g. unspecified itself is somehow invalid in the lookup table, though unlikely),
        // we must provide a valid integer code to addCRLEntry.
        int finalReasonCode = (reason != null) ? reason.getValue().intValue() : CRLReason.unspecified;


        Date revocationDate = new Date();
        // Store the original CRLReason object if needed for other purposes, but use its int value for addCRLEntry
        RevokedCertificateEntry entry = new RevokedCertificateEntry(serialNumber, revocationDate, CRLReason.lookup(finalReasonCode));
        revokedCertificates.add(entry);
        logger.info("证书 (序列号: {}) 已被吊销。原因代码: {}, 日期: {}", serialNumber, finalReasonCode, revocationDate);
        this.crlNumber = this.crlNumber.add(BigInteger.ONE);
        return true;
    }

    public X509CRL generateCRL() throws CRLException, OperatorCreationException, CertIOException, NoSuchAlgorithmException {
        X500Name issuerName = X500Name.getInstance(this.caCertificate.getSubjectX500Principal().getEncoded());
        Date now = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(now);
        calendar.add(Calendar.DAY_OF_YEAR, 7);
        Date nextUpdate = calendar.getTime();

        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(issuerName, now);
        crlBuilder.setNextUpdate(nextUpdate);

        for (RevokedCertificateEntry entry : revokedCertificates) {
            // *** FIX: Pass the integer value of the reason ***
            crlBuilder.addCRLEntry(entry.serialNumber, entry.revocationDate, entry.reason.getValue().intValue());
        }

        JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
        AuthorityKeyIdentifier aki = extUtils.createAuthorityKeyIdentifier(this.caCertificate.getPublicKey());
        crlBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);
        crlBuilder.addExtension(Extension.cRLNumber, false, new CRLNumber(this.crlNumber));

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build(this.caKeyPair.getPrivate());
        X509CRLHolder crlHolder = crlBuilder.build(signer);

        logger.info("已生成CRL，CRL内部编号: {}, 包含 {} 个已吊销条目。", this.crlNumber, revokedCertificates.size());
        return new JcaX509CRLConverter().setProvider("BC").getCRL(crlHolder);
    }

    public X509Certificate getCA(String userPublicKeyString, String userDN) throws Exception {
        PublicKey parsedPublicKey = PublicKeyUtil.stringToPublicKey(userPublicKeyString, "RSA");
        if (parsedPublicKey == null) {
            logger.error("无法从字符串解析用户公钥: {}", userPublicKeyString);
            throw new IllegalArgumentException("无效的用户公钥字符串。");
        }
        return issueCertificate(parsedPublicKey, userDN);
    }

    public X509Certificate getCACertificate() {
        return this.caCertificate;
    }

    private static String keyUsageToString(boolean[] keyUsage) {
        if (keyUsage == null) return "N/A";
        StringBuilder sb = new StringBuilder();
        String[] names = {"digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"};
        for (int i = 0; i < keyUsage.length; i++) {
            if (keyUsage[i]) {
                if (sb.length() > 0) sb.append(", ");
                if (i < names.length) sb.append(names[i]); else sb.append("bit").append(i);
            }
        }
        return sb.length() > 0 ? sb.toString() : "No specific usage defined";
    }

    private static String extendedKeyUsageToString(List<String> ekuList) {
        if (ekuList == null || ekuList.isEmpty()) return "N/A";
        StringBuilder sb = new StringBuilder();
        for (String oid : ekuList) {
            if (sb.length() > 0) sb.append(", ");
            if (KeyPurposeId.id_kp_serverAuth.getId().equals(oid)) sb.append("serverAuth");
            else if (KeyPurposeId.id_kp_clientAuth.getId().equals(oid)) sb.append("clientAuth");
            else if (KeyPurposeId.id_kp_codeSigning.getId().equals(oid)) sb.append("codeSigning");
            else if (KeyPurposeId.id_kp_emailProtection.getId().equals(oid)) sb.append("emailProtection");
            else if (KeyPurposeId.id_kp_timeStamping.getId().equals(oid)) sb.append("timeStamping");
            else if (KeyPurposeId.id_kp_OCSPSigning.getId().equals(oid)) sb.append("OCSPSigning");
            else sb.append(oid);
        }
        return sb.toString();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {
        CAimpl ca = null;
        try {
            ca = new CAimpl();

            X509Certificate rootCertificate = ca.getCACertificate();
            System.out.println("根证书信息:");
            System.out.println("  主题: " + rootCertificate.getSubjectX500Principal().getName());
            System.out.println("  颁发者: " + rootCertificate.getIssuerX500Principal().getName());
            System.out.println("  序列号: " + rootCertificate.getSerialNumber());
            System.out.println("  有效期: " + rootCertificate.getNotBefore() + " 至 " + rootCertificate.getNotAfter());
            int basicConstraints = rootCertificate.getBasicConstraints();
            System.out.println("  是CA: " + (basicConstraints >= 0));
            if (basicConstraints > 0) System.out.println("  路径长度约束: " + basicConstraints);
            if (rootCertificate.getKeyUsage() != null)
                System.out.println("  密钥用途: " + keyUsageToString(rootCertificate.getKeyUsage()));
            if (rootCertificate.getExtendedKeyUsage() != null)
                System.out.println("  扩展密钥用途: " + extendedKeyUsageToString(rootCertificate.getExtendedKeyUsage()));

            KeyPair userKeyPair1 = ca.generateKeyPair();
            X509Certificate userCert1 = ca.issueCertificate(userKeyPair1.getPublic(), "CN=User1,O=MyOrg,C=CN");
            System.out.println("\n已为 User1 颁发证书，序列号: " + userCert1.getSerialNumber());
            byte[] cdpBytes1 = userCert1.getExtensionValue(Extension.cRLDistributionPoints.getId());
            if (cdpBytes1 != null) System.out.println("  User1 证书包含CRL分发点扩展。");
            else System.out.println("  User1 证书不包含CRL分发点扩展。");

            // 生成一个用于测试的公钥字符串
            KeyPair generatedUserKeyPair = ca.generateKeyPair();
            PublicKey generatedUserPublicKey = generatedUserKeyPair.getPublic();
            String generatedUserPublicKeyBase64 = com.bjut.ca.Util.PublicKeyUtil.publicKeyToString(generatedUserPublicKey);
            System.out.println("\nGenerated User Public Key (Base64 for testing): " + generatedUserPublicKeyBase64);


            KeyPair userKeyPair2 = ca.generateKeyPair();
            X509Certificate userCert2 = ca.issueCertificate(userKeyPair2.getPublic(), "CN=User2,O=MyOrg,C=CN");
            System.out.println("已为 User2 颁发证书，序列号: " + userCert2.getSerialNumber());

            System.out.println("\n正在吊销 User1 的证书 (序列号: " + userCert1.getSerialNumber() + ")");
            ca.revokeCertificate(userCert1.getSerialNumber(), CRLReason.privilegeWithdrawn); // 使用 Bouncy Castle 的常量

            X509CRL crl = ca.generateCRL();
            System.out.println("\n已生成CRL:");
            System.out.println("  颁发者: " + crl.getIssuerX500Principal().getName());
            System.out.println("  本次更新时间: " + crl.getThisUpdate());
            System.out.println("  下次更新时间: " + crl.getNextUpdate());

            // 解析并打印 CRL Number 扩展
            byte[] crlNumExtBytes = crl.getExtensionValue(Extension.cRLNumber.getId());
            if (crlNumExtBytes != null) {
                try (ASN1InputStream ais = new ASN1InputStream(crlNumExtBytes)) {
                    DEROctetString octetString = (DEROctetString) ais.readObject();
                    if (octetString != null) {
                        try (ASN1InputStream ois = new ASN1InputStream(octetString.getOctets())) {
                            CRLNumber crlNum = CRLNumber.getInstance(ois.readObject());
                            System.out.println("  CRL Number (parsed): " + crlNum.getCRLNumber());
                        }
                    }
                } catch (IOException e) {
                    System.out.println("  无法解析CRL Number扩展: " + e.getMessage());
                }
            } else {
                System.out.println("  CRL Number扩展未找到。");
            }

            if (crl.getRevokedCertificate(userCert1.getSerialNumber()) != null) {
                System.out.println("  User1的证书 (序列号: " + userCert1.getSerialNumber() + ") 在CRL中。");
            }
            if (crl.getRevokedCertificate(userCert2.getSerialNumber()) == null) {
                System.out.println("  User2的证书 (序列号: " + userCert2.getSerialNumber() + ") 不在CRL中。");
            }

            boolean isValidUser1 = CertificateValidator.validateCertificate(userCert1, rootCertificate);
            System.out.println("\nUser1 证书基础验证 (未检查CRL): " + isValidUser1);
            boolean isValidUser2 = CertificateValidator.validateCertificate(userCert2, rootCertificate);
            System.out.println("User2 证书基础验证 (未检查CRL): " + isValidUser2);

        } catch (Exception e) {
            logger.error("CAimpl 主方法测试时发生错误: ", e);
            e.printStackTrace(); // 打印完整的堆栈跟踪
        }


        KeyPair userKeyPair = ca.generateKeyPair();
        PublicKey userPublicKey = userKeyPair.getPublic();
        String userPublicKeyBase64 = com.bjut.ca.Util.PublicKeyUtil.publicKeyToString(userPublicKey);
        System.out.println("\nGenerated User Public Key (Base64 for testing): " + userPublicKeyBase64);
    }
}
