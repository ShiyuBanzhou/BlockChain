package com.bjut.ca.Util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.util.Base64;
import java.util.Date;

public class CertificateValidator {

    private static final Logger logger = LoggerFactory.getLogger(CertificateValidator.class);

    /**
     * 验证给定证书是否由指定的根证书颁发、当前有效，并且未在提供的CRL中被吊销。
     *
     * @param certificate 待验证的X509证书对象
     * @param rootCertificate 根X509证书对象，用于验证给定证书的签名
     * @param crl 证书吊销列表，如果为null，则不执行CRL检查
     * @return 如果证书有效、签名验证成功且未被吊销（或未提供CRL），则返回true；否则返回false
     */
    public static boolean validateCertificate(X509Certificate certificate, X509Certificate rootCertificate, X509CRL crl) {
        if (certificate == null || rootCertificate == null) {
            logger.error("验证证书失败：输入证书或根证书为null。");
            return false;
        }
        try {
            // 1. 验证证书的有效期
            Date now = new Date();
            certificate.checkValidity(now);
            logger.debug("证书 {} 在有效期内。", certificate.getSerialNumber());

            // 2. 验证证书的签名是否由根证书的公钥签发
            PublicKey issuerPublicKey = rootCertificate.getPublicKey();
            certificate.verify(issuerPublicKey);
            logger.debug("证书 {} 的签名验证成功 (由根证书 {} 签发)。", certificate.getSerialNumber(), rootCertificate.getSubjectX500Principal());

            // 3. 检查证书是否在CRL中被吊销 (如果提供了CRL)
            if (crl != null) {
                if (crl.isRevoked(certificate)) {
                    logger.warn("证书 {} (序列号: {}) 已被吊销，根据提供的CRL。", certificate.getSubjectX500Principal(), certificate.getSerialNumber());
                    X509CRLEntry entry = crl.getRevokedCertificate(certificate.getSerialNumber());
                    if (entry != null) {
                        logger.warn("吊销日期: {}, 吊销原因: {}", entry.getRevocationDate(), entry.getRevocationReason());
                    }
                    return false;
                }
                logger.debug("证书 {} 未在提供的CRL中找到吊销记录。", certificate.getSerialNumber());
            } else {
                logger.debug("未提供CRL，跳过吊销检查。");
            }

            return true;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            logger.warn("证书 {} 不在有效期内: {}", certificate.getSerialNumber(), e.getMessage());
            return false;
        } catch (SignatureException | NoSuchAlgorithmException | InvalidKeyException | CertificateException |
                 NoSuchProviderException e) {
            logger.error("证书 {} 签名验证失败或发生其他证书错误: {}", certificate.getSerialNumber(), e.getMessage(), e);
            return false;
        }
    }

    /**
     * 验证给定证书是否由指定的根证书颁发且当前有效 (不执行CRL检查)。
     *
     * @param certificate 待验证的X509证书对象
     * @param rootCertificate 根X509证书对象，用于验证给定证书的签名
     * @return 如果证书有效且签名验证成功，则返回true；否则返回false
     */
    public static boolean validateCertificate(X509Certificate certificate, X509Certificate rootCertificate) {
        // 调用新的方法，传入null作为CRL，表示不进行CRL检查
        return validateCertificate(certificate, rootCertificate, null);
    }


    /**
     * 通过字符串形式的证书内容验证证书的有效性 (不执行CRL检查)。
     *
     * @param certificateBase64 以字符串形式表示的待验证证书内容
     * @param rootCertificateBase64 以字符串形式表示的根证书内容，用于验证给定证书的签名
     * @return 如果证书有效且签名验证成功，则返回true；否则返回false
     */
    public static boolean validateCertificateByString(String certificateBase64, String rootCertificateBase64) {
        try {
            X509Certificate cert = stringToCertificate(certificateBase64);
            X509Certificate rootCert = stringToCertificate(rootCertificateBase64);
            return validateCertificate(cert, rootCert, null); // 不进行CRL检查
        } catch (CertificateException e) {
            logger.error("将字符串转换为证书时出错: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 将 Base64 编码的字符串转换为 X509Certificate 对象
     *
     * @param certificateBase64 Base64 编码的证书字符串
     * @return X509Certificate 对象
     * @throws CertificateException 如果证书加载失败
     */
    public static X509Certificate stringToCertificate(String certificateBase64) throws CertificateException {
        if (certificateBase64 == null || certificateBase64.trim().isEmpty()) {
            throw new CertificateException("输入的证书Base64字符串为null或空。");
        }
        try {
            String processedCertificateBase64 = certificateBase64.replace(" ", "+");
            byte[] certificateBytes = Base64.getDecoder().decode(processedCertificateBase64);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
        } catch (IllegalArgumentException e) {
            throw new CertificateException("无法解码Base64证书字符串: " + e.getMessage(), e);
        }
    }

    /**
     * 将 Base64 编码的字符串转换为 X509CRL 对象
     *
     * @param crlBase64 Base64 编码的CRL字符串
     * @return X509CRL 对象
     * @throws CRLException 如果CRL加载失败
     * @throws CertificateException 如果 CertificateFactory 实例获取失败 (不太可能)
     */
    public static X509CRL stringToCRL(String crlBase64) throws CRLException, CertificateException {
        if (crlBase64 == null || crlBase64.trim().isEmpty()) {
            throw new CRLException("输入的CRL Base64字符串为null或空。");
        }
        try {
            String processedCrlBase64 = crlBase64.replace(" ", "+");
            byte[] crlBytes = Base64.getDecoder().decode(processedCrlBase64);
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            return (X509CRL) certificateFactory.generateCRL(new ByteArrayInputStream(crlBytes));
        } catch (IllegalArgumentException e) {
            throw new CRLException("无法解码Base64 CRL字符串: " + e.getMessage(), e);
        }
    }
}
