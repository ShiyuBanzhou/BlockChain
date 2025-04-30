package com.bjut.blockchain.web.util;

import java.io.ByteArrayInputStream;
import java.security.*;
import java.security.cert.*;
import java.util.Base64;
import java.util.Date;

public class CertificateValidator {

    /**
     * 验证给定证书是否由指定的根证书颁发且当前有效
     *
     * @param certificate 待验证的X509证书对象
     * @param rootCertificate 根X509证书对象，用于验证给定证书的签名
     * @return 如果证书有效且签名验证成功，则返回true；否则返回false
     */
    public static boolean validateCertificate(X509Certificate certificate, X509Certificate rootCertificate) {
        try {
            // 验证证书的有效期
            Date now = new Date();
            certificate.checkValidity(now);

            // 验证证书的签名
            PublicKey issuerPublicKey = rootCertificate.getPublicKey();
            certificate.verify(issuerPublicKey);

            return true;
        } catch (CertificateExpiredException | CertificateNotYetValidException e) {
            System.err.println("证书不在有效期内: " + e.getMessage());
            return false;
        } catch (SignatureException | NoSuchAlgorithmException | InvalidKeyException | CertificateException |
                 NoSuchProviderException e) {
            System.err.println("证书签名验证失败: " + e.getMessage());
            return false;
        }
    }

    /**
     * 通过Base64 编码字符串形式的证书内容验证证书的有效性
     *
     * @param certificate 以字符串形式表示的待验证证书内容
     * @param rootCertificate 以字符串形式表示的根证书内容，用于验证给定证书的签名
     * @return 如果证书有效且签名验证成功，则返回true；否则返回false
     * @throws RuntimeException 如果证书解析失败，则抛出运行时异常
     */
    public static boolean validateCertificateByString(String certificate, String rootCertificate) {
        try {
            return validateCertificate(stringToCertificate(certificate), stringToCertificate(rootCertificate));
        } catch (CertificateException e) {
            throw new RuntimeException(e);
        }
    }
    
    public static boolean validateCertificateByString(String certificate) {
        try {
            return validateCertificateByString(certificate, CAImpl.getRootCertificateStr());
        } catch (Exception e) {
            throw new RuntimeException(e);
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
        byte[] certificateBytes = Base64.getDecoder().decode(certificateBase64);
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        return (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(certificateBytes));
    }
}    
