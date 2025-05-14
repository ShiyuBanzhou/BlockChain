package com.bjut.blockchain.web.service;

import com.alibaba.fastjson.JSONObject;
import com.bjut.blockchain.web.util.CertificateValidator;
import com.bjut.blockchain.web.util.CryptoUtil;
import com.bjut.blockchain.web.util.HttpRequestUtil;
import com.bjut.blockchain.web.util.PublicKeyUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value; // For potential future configuration
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.net.URLEncoder; // For URL encoding parameters
import java.nio.charset.StandardCharsets; // For specifying charset in URL encoding

@Service
public class CAImpl {

    private static final Logger logger = LoggerFactory.getLogger(CAImpl.class);

    /**
     * CA服务器的基础URL地址
     * TODO: 考虑从 application.yml 配置注入
     */
    // @Value("${ca.server.url:http://localhost:9065}") // Example for future config
    private static final String CA_SERVER_BASE_URL = "http://localhost:9065"; // Ensure this is correct

    private static final String ROOT_CERT_ENDPOINT = "/ca/root-certificate";
    private static final String ISSUE_CERT_ENDPOINT = "/ca/certificate";


    /**
     * 用户的可分辨名称(Distinguished Name)，用于在证书签名请求(CSR)中标识用户信息
     * TODO: 考虑从 application.yml 配置注入，或根据节点动态生成
     */
    // @Value("${node.dn:CN=Node,OU=BlockchainNodes,O=MyOrg,C=CN}") // Example for future config
    private static final String NODE_DISTINGUISHED_NAME = "CN=ThisNode,OU=Nodes,O=MyBlockchainApp,C=CN";


    // 存储证书对象
    public static X509Certificate nodeCertificate = null;
    // 存储证书字符串
    public static String nodeCertificateStr = null;

    // 存储根证书对象
    public static X509Certificate rootCACertificate = null;
    // 存储根证书字符串
    public static String rootCACertificateStr = null;

    // 存储密钥对（公钥和私钥）
    public static KeyPair nodeKeyPair = null;

    /**
     * 获取根CA证书对象。
     * 如果根证书为空，则通过HTTP GET请求从CA服务器获取，并将其解析为证书对象。
     * @return X509Certificate 根证书对象
     * @throws Exception 如果获取或解析证书时发生错误
     */
    public static X509Certificate getRootCertificate() throws Exception {
        if (rootCACertificate == null) {
            logger.info("本地缓存的根CA证书为空，正在从CA服务器 {} 获取...", CA_SERVER_BASE_URL + ROOT_CERT_ENDPOINT);
            String message = HttpRequestUtil.httpGet(CA_SERVER_BASE_URL + ROOT_CERT_ENDPOINT);
            if (message == null || message.trim().isEmpty()) {
                logger.error("从CA服务器获取根证书失败，返回为空。");
                throw new Exception("无法从CA服务器获取根证书。");
            }
            rootCACertificate = CertificateValidator.stringToCertificate(message);
            rootCACertificateStr = message;
            logger.info("根CA证书获取成功并已缓存。主题: {}", rootCACertificate.getSubjectX500Principal());
        }
        return rootCACertificate;
    }

    /**
     * 获取根CA证书的Base64编码字符串。
     * @return String 根证书字符串
     * @throws Exception 如果获取或解析证书时发生错误
     */
    public static String getRootCertificateStr() throws Exception {
        if (rootCACertificateStr == null) {
            getRootCertificate(); // This will populate both rootCACertificate and rootCACertificateStr
        }
        return rootCACertificateStr;
    }

    /**
     * 获取本节点的证书Base64编码字符串。
     * 如果证书字符串为空，则调用创建证书的方法。
     * @return String 证书字符串
     * @throws Exception 如果创建证书时发生错误
     */
    public static String getCertificateStr() throws Exception {
        if (nodeCertificateStr == null) {
            createNodeCertificate();
        }
        return nodeCertificateStr;
    }

    /**
     * 获取本节点的证书对象。
     * 如果证书对象为空，则调用创建证书的方法。
     * @return X509Certificate 证书对象
     * @throws Exception 如果创建证书时发生错误
     */
    public static X509Certificate getCertificate() throws Exception {
        if (nodeCertificate == null) {
            createNodeCertificate();
        }
        return nodeCertificate;
    }

    /**
     * 为本节点创建证书。
     * 生成节点公钥，将其与节点DN一起发送到CA服务器，获取证书字符串并解析为证书对象。
     * @throws Exception 如果生成公钥或获取证书时发生错误
     */
    public static void createNodeCertificate() throws Exception {
        logger.info("本地缓存的节点证书为空，正在为节点 {} 从CA服务器 {} 请求新证书...", NODE_DISTINGUISHED_NAME, CA_SERVER_BASE_URL + ISSUE_CERT_ENDPOINT);
        PublicKey userPublicKey = getNodeKeyPair().getPublic();
        String userPublicKeyStr = PublicKeyUtil.publicKeyToString(userPublicKey);

        if (userPublicKeyStr == null) {
            logger.error("未能将节点公钥转换为字符串。");
            throw new Exception("无法将节点公钥转换为字符串表示。");
        }

        // 构建POST请求的表单参数，确保进行URL编码
        String encodedUserPublicKey = URLEncoder.encode(userPublicKeyStr, StandardCharsets.UTF_8.name());
        String encodedUserDN = URLEncoder.encode(NODE_DISTINGUISHED_NAME, StandardCharsets.UTF_8.name());
        String formParams = "userPublicKey=" + encodedUserPublicKey + "&userDN=" + encodedUserDN;

        logger.debug("向CA发送的证书请求参数: {}", formParams);

        String message = HttpRequestUtil.httpPostForm(formParams, CA_SERVER_BASE_URL + ISSUE_CERT_ENDPOINT);

        if (message == null || message.trim().isEmpty()) {
            logger.error("从CA服务器获取节点证书失败，返回为空。");
            throw new Exception("无法从CA服务器获取节点证书。");
        }
        nodeCertificateStr = message;
        nodeCertificate = CertificateValidator.stringToCertificate(message);
        logger.info("节点证书获取成功并已缓存。主题: {}", nodeCertificate.getSubjectX500Principal());
    }

    /**
     * 获取本节点的密钥对。
     * 如果密钥对为空，则生成一个新的RSA密钥对。
     * @return KeyPair 密钥对对象
     */
    public static KeyPair getNodeKeyPair() { // Removed throws Exception as createNodeKeyPair handles it internally
        if (nodeKeyPair == null) {
            createNodeKeyPair();
        }
        return nodeKeyPair;
    }

    /**
     * 为本节点创建新的密钥对。
     */
    public static void createNodeKeyPair() {
        try {
            logger.debug("正在为节点生成新的RSA密钥对...");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048); // 使用2048位密钥
            nodeKeyPair = keyPairGenerator.generateKeyPair();
            logger.info("节点密钥对已生成。公钥 (Hex): {}", CryptoUtil.byte2Hex(nodeKeyPair.getPublic().getEncoded()).substring(0,30)+"...");
        } catch (Exception e) {
            logger.error("创建节点密钥对时发生错误: {}", e.getMessage(), e);
            // Consider re-throwing as a runtime exception if this is critical for startup
            throw new RuntimeException("无法创建节点密钥对", e);
        }
    }


    /**
     * 获取本节点证书的Map表示。
     * 如果证书对象为空，则调用创建证书的方法，然后将证书的各个字段放入Map中，并返回其JSON字符串表示。
     * @return String 证书的JSON字符串表示
     * @throws Exception 如果创建证书时发生错误
     */
    public static String getCertificateMap() throws Exception {
        if (nodeCertificate == null) {
            createNodeCertificate();
        }
        // 将 certificate 转成 map 格式
        Map<String, Object> certificateMap = new HashMap<>();
        certificateMap.put("subjectDN", nodeCertificate.getSubjectDN().getName());
        certificateMap.put("issuerDN", nodeCertificate.getIssuerDN().getName());
        certificateMap.put("serialNumber", nodeCertificate.getSerialNumber().toString());
        certificateMap.put("notBefore", nodeCertificate.getNotBefore().toString());
        certificateMap.put("notAfter", nodeCertificate.getNotAfter().toString());
        // certificateMap.put("publicKeyFormat", nodeCertificate.getPublicKey().getFormat()); // 通常不需要
        // 返回 map 的 json 格式，用 fastjson
        return JSONObject.toJSONString(certificateMap);
    }
}
