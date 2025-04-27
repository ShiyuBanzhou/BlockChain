package com.bjut.ca.Util;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class X509CertificateUtil {


    /**
     * 将 X509Certificate 转换为 Base64 编码的字符串
     *
     * @param certificate X509Certificate 对象
     * @return Base64 编码的字符串
     * @throws CertificateEncodingException 如果证书编码失败
     */
    public static String certificateToString(X509Certificate certificate) throws CertificateEncodingException {
        byte[] certificateBytes = certificate.getEncoded();
        return Base64.getEncoder().encodeToString(certificateBytes);
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
