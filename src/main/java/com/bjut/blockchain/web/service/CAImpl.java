package com.bjut.blockchain.web.service;

import com.alibaba.fastjson.JSONObject;
import com.bjut.blockchain.web.util.CertificateValidator;
import com.bjut.blockchain.web.util.HttpRequestUtil;
import com.bjut.blockchain.web.util.PublicKeyUtil;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

@Service
public class CAImpl {

    /**
     * CA服务器的URL地址
      */
    private static final String CA_URL ="http://127.0.0.1:9065";

    /**
     * 用户的可分辨名称(Distinguished Name)，用于在证书签名请求(CSR)中标识用户信息
     */
    private static final String USER_DN ="CN=User, OU=User, O=00r, L=User, ST=User, C=User";


    // 存储证书对象
    public static X509Certificate certificate=null;
    // 存储证书字符串
    public static String certificateStr=null;

    // 存储根证书对象
    public static X509Certificate rootCertificate = null;
    // 存储根证书字符串
    public static String rootCertificateStr = null;

    // 存储密钥对（公钥和私钥）
    public static KeyPair keyPair=null;

    /**
     * 获取根证书
     * 如果根证书为空，则通过HTTP GET请求从CA服务器获取，并将其解析为证书对象
     * @return X509Certificate 根证书对象
     * @throws Exception 如果获取或解析证书时发生错误
     */
    public static X509Certificate getRootCertificate() throws Exception {
        if (rootCertificate == null) {
            String meaaage = HttpRequestUtil.httpGet(CA_URL + "/root-ca");
            rootCertificate = CertificateValidator.stringToCertificate(meaaage);
            rootCertificateStr = meaaage;
        }
        return rootCertificate;
    }

    /**
     * 获取根证书Base64编码字符串
     * 如果根证书字符串为空，则通过HTTP GET请求从CA服务器获取，并将其解析为证书对象和字符串
     * @return String 根证书字符串
     * @throws Exception 如果获取或解析证书时发生错误
     */
    public static String getRootCertificateStr() throws Exception {
        if (rootCertificateStr == null) {
            String meaaage = HttpRequestUtil.httpGet(CA_URL + "/root-ca");
            rootCertificate = CertificateValidator.stringToCertificate(meaaage);
            rootCertificateStr = meaaage;
        }
        return rootCertificateStr;
    }

    /**
     * 获取证书Base64编码字符串
     * 如果证书字符串为空，则调用创建证书的方法
     * @return String 证书字符串
     * @throws Exception 如果创建证书时发生错误
     */
    public static String getCertificateStr() throws Exception {
        if (certificateStr == null) {
            createCertificate();
        }
        return certificateStr;
    }

    /**
     * 获取证书对象
     * 如果证书对象为空，则调用创建证书的方法
     * @return X509Certificate 证书对象
     * @throws Exception 如果创建证书时发生错误
     */
    public static X509Certificate getCertificate() throws Exception {
        if (certificate == null) {
            createCertificate();
        }
        return certificate;
    }

    /**
     * 创建证书
     * 生成用户公钥，将其与用户DN一起发送到CA服务器，获取证书字符串并解析为证书对象
     * @throws Exception 如果生成公钥或获取证书时发生错误
     */
    public static void createCertificate() throws Exception {
        PublicKey userPublicKey = getKeyPair().getPublic();
        String userPublicKeyStr = PublicKeyUtil.publicKeyToString(userPublicKey);
        String url = "userPublicKey=" + userPublicKeyStr + "&userDN=" + USER_DN;
        String message = HttpRequestUtil.httpPostForm(url, CA_URL + "/ca");
        certificateStr = message;
        certificate = CertificateValidator.stringToCertificate(message);
    }

    /**
     * 获取密钥对
     * 如果密钥对为空，则生成一个新的RSA密钥对
     * @return KeyPair 密钥对对象
     * @throws Exception 如果生成密钥对时发生错误
     */
    public static KeyPair getKeyPair() throws Exception {
        if (keyPair == null) {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
            System.out.println("keyPair:"+keyPair);
        }
        return keyPair;
    }


    /**
     * 获取证书的Map表示
     * 如果证书对象为空，则调用创建证书的方法，然后将证书的各个字段放入Map中，并返回其JSON字符串表示
     * @return String 证书的JSON字符串表示
     * @throws Exception 如果创建证书时发生错误
     */
    public static String getCertificateMap() throws Exception {
        if (certificate == null) {
            createCertificate();
        }
        // 将 certificate 转成 map 格式
        Map<String, Object> certificateMap = new HashMap<>();
        certificateMap.put("subjectDN", certificate.getSubjectDN().getName());
        certificateMap.put("issuerDN", certificate.getIssuerDN().getName());
        certificateMap.put("serialNumber", certificate.getSerialNumber().toString());
        certificateMap.put("notBefore", certificate.getNotBefore().toString());
        certificateMap.put("notAfter", certificate.getNotAfter().toString());
        //certificateMap.put("publicKeyFormat", certificate.getPublicKey().getFormat());
        // 返回 map 的 json 格式，用 fastjson
        return JSONObject.toJSONString(certificateMap);
    }
}
