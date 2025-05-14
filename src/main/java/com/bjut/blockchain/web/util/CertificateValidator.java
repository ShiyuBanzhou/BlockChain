package com.bjut.blockchain.web.util;

import com.bjut.blockchain.web.service.CAImpl; // 主应用的CA客户端
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.util.Base64;
import java.util.Date;

public class CertificateValidator {
    private static final Logger logger = LoggerFactory.getLogger(CertificateValidator.class);
    private static final String CA_CRL_URL = "http://localhost:9065/ca/crl"; // CA的CRL分发点URL

    // 用于缓存CRL及其获取时间，避免频繁请求
    private static X509CRL cachedCRL = null;
    private static long lastCRLFetchTime = 0;
    private static final long CRL_CACHE_DURATION = 10 * 60 * 1000; // CRL缓存10分钟 (毫秒)

    /**
     * 从CA服务器获取最新的CRL。包含简单的缓存机制。
     * @return X509CRL 对象，如果获取失败则返回null。
     */
    private static X509CRL fetchCRL() {
        long now = System.currentTimeMillis();
        if (cachedCRL != null && (now - lastCRLFetchTime < CRL_CACHE_DURATION)) {
            logger.debug("使用缓存的CRL。");
            return cachedCRL;
        }

        logger.info("正在从 {} 获取最新的CRL...", CA_CRL_URL);
        HttpURLConnection connection = null;
        try {
            URL url = new URL(CA_CRL_URL);
            connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(5000); // 5秒连接超时
            connection.setReadTimeout(10000);  // 10秒读取超时

            int responseCode = connection.getResponseCode();
            if (responseCode == HttpURLConnection.HTTP_OK) {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                try (InputStream crlStream = connection.getInputStream()) {
                    cachedCRL = (X509CRL) cf.generateCRL(crlStream);
                    lastCRLFetchTime = System.currentTimeMillis();
                    logger.info("成功获取并解析了CRL，版本号: {}, 下次更新: {}", cachedCRL.getVersion(), cachedCRL.getNextUpdate());
                    return cachedCRL;
                }
            } else {
                logger.error("从CA获取CRL失败，HTTP响应码: {}", responseCode);
                return cachedCRL; // 返回旧的缓存（如果有）或null
            }
        } catch (MalformedURLException e) {
            logger.error("CRL URL格式错误: {}", CA_CRL_URL, e);
        } catch (IOException e) {
            logger.error("连接到CRL分发点 {} 时发生IO错误: {}", CA_CRL_URL, e.getMessage());
        } catch (CertificateException | CRLException e) {
            logger.error("解析获取到的CRL时出错: {}", e.getMessage(), e);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
        logger.warn("获取CRL失败，将返回当前缓存的CRL（如果存在）或null。");
        return cachedCRL; // 获取失败时返回当前缓存的CRL或null
    }


    /**
     * 验证给定证书是否由指定的根证书颁发、当前有效，并且未在获取的CRL中被吊销。
     *
     * @param certificate 待验证的X509证书对象
     * @param rootCertificate 根X509证书对象，用于验证给定证书的签名
     * @param crl 要使用的CRL，如果为null，则会尝试从CA获取最新的CRL
     * @return 如果证书有效、签名验证成功且未被吊销，则返回true；否则返回false
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

            // 3. 检查证书是否在CRL中被吊销
            X509CRL effectiveCRL = (crl != null) ? crl : fetchCRL(); // 如果未提供CRL，则获取最新的

            if (effectiveCRL != null) {
                if (effectiveCRL.isRevoked(certificate)) {
                    logger.warn("证书 {} (序列号: {}) 已被吊销，根据CRL (版本: {}, 下次更新: {})。",
                            certificate.getSubjectX500Principal(), certificate.getSerialNumber(),
                            effectiveCRL.getVersion(), effectiveCRL.getNextUpdate());
                    X509CRLEntry entry = effectiveCRL.getRevokedCertificate(certificate.getSerialNumber());
                    if (entry != null) {
                        logger.warn("吊销日期: {}, 吊销原因: {}", entry.getRevocationDate(), entry.getRevocationReason());
                    }
                    return false;
                }
                logger.debug("证书 {} 未在CRL中找到吊销记录。", certificate.getSerialNumber());
            } else {
                logger.warn("无法获取CRL，跳过吊销检查。这可能存在安全风险！");
                // 根据策略，如果无法获取CRL，可能应该验证失败
                // return false;
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
     * 这是为了兼容旧代码调用而添加的重载方法。
     *
     * @param certificate 待验证的X509证书对象
     * @param rootCertificate 根X509证书对象，用于验证给定证书的签名
     * @return 如果证书有效且签名验证成功，则返回true；否则返回false
     */
    public static boolean validateCertificate(X509Certificate certificate, X509Certificate rootCertificate) {
        // 调用新的方法，传入null作为CRL，表示不进行CRL检查 (或让其内部尝试获取)
        // 为了与 @Deprecated 方法的行为一致（即不检查CRL），这里明确传入null
        return validateCertificate(certificate, rootCertificate, null);
    }


    /**
     * 通过Base64 编码字符串形式的证书内容验证证书的有效性。
     * 此方法会尝试获取根证书和最新的CRL进行验证。
     *
     * @param certificateBase64 以字符串形式表示的待验证证书内容
     * @return 如果证书有效且签名验证成功且未被吊销，则返回true；否则返回false
     */
    public static boolean validateCertificateByString(String certificateBase64) {
        try {
            X509Certificate cert = stringToCertificate(certificateBase64);
            // 从主应用的CA客户端获取根证书
            X509Certificate rootCert = CAImpl.getRootCertificate(); // 假设 CAImpl.getRootCertificate() 能正确获取
            if (rootCert == null) {
                logger.error("无法获取根证书，验证失败。");
                return false;
            }
            // 调用新的方法，让它自己去获取CRL
            return validateCertificate(cert, rootCert, null);
        } catch (CertificateException e) {
            logger.error("将字符串转换为证书时出错: {}", e.getMessage(), e);
            return false;
        } catch (Exception e) { // 捕获 CAImpl.getRootCertificate() 可能抛出的其他异常
            logger.error("获取根证书时出错: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * 通过Base64 编码字符串形式的证书内容验证证书的有效性 (使用提供的根证书字符串，不执行CRL检查)。
     *
     * @param certificateBase64 以字符串形式表示的待验证证书内容
     * @param rootCertificateBase64 以字符串形式表示的根证书内容，用于验证给定证书的签名
     * @return 如果证书有效且签名验证成功，则返回true；否则返回false
     * @deprecated 推荐使用 validateCertificateByString(String certificateBase64) 进行更完整的验证，或 validateCertificate(X509Certificate, X509Certificate, X509CRL) 进行精确控制。
     */
    @Deprecated
    public static boolean validateCertificateByString(String certificateBase64, String rootCertificateBase64) {
        logger.warn("正在使用已弃用的 validateCertificateByString(String, String) 方法，此方法不执行CRL检查。");
        try {
            X509Certificate cert = stringToCertificate(certificateBase64);
            X509Certificate rootCert = stringToCertificate(rootCertificateBase64);
            // ** FIX: Call the overloaded method that takes two X509Certificate arguments **
            return validateCertificate(cert, rootCert);
        } catch (CertificateException e) {
            logger.error("将字符串转换为证书时出错: {}", e.getMessage(), e);
            return false;
        }
    }


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
}
