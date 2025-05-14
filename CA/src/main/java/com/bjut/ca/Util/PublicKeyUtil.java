package com.bjut.ca.Util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PublicKeyUtil {

    private static final Logger logger = LoggerFactory.getLogger(PublicKeyUtil.class);

    /**
     * 将 PublicKey 对象转换为 Base64 编码的字符串
     * @param publicKey 要转换的 PublicKey 对象
     * @return 转换后的 Base64 编码字符串，如果转换失败则返回 null
     */
    public static String publicKeyToString(PublicKey publicKey) {
        if (publicKey == null) {
            logger.warn("Input PublicKey object is null.");
            return null;
        }
        try {
            byte[] publicKeyBytes = publicKey.getEncoded();
            return Base64.getEncoder().encodeToString(publicKeyBytes);
        } catch (Exception e) {
            logger.error("Error encoding PublicKey to string: {}", e.getMessage(), e);
            return null;
        }
    }
    /**
     * 将 Base64 编码的字符串转换为 PublicKey 对象
     * @param publicKeyStr Base64 编码的公钥字符串
     * @param algorithm 公钥使用的算法，例如 "RSA"
     * @return 转换后的 PublicKey 对象，如果转换失败则返回 null
     */
    public static PublicKey stringToPublicKey(String publicKeyStr, String algorithm) {
        if (publicKeyStr == null || publicKeyStr.trim().isEmpty()) {
            logger.warn("Input publicKeyStr is null or empty.");
            return null;
        }
        if (algorithm == null || algorithm.trim().isEmpty()) {
            logger.warn("Input algorithm is null or empty.");
            return null;
        }
        try {
            // **关键修复：替换公钥字符串中的空格为'+'，以处理URL传输中可能发生的转换**
            // Base64编码的'+'在URL中可能会被视为空格，这里将其还原。
            String processedPublicKeyStr = publicKeyStr.replace(" ", "+");

            byte[] publicKeyBytes = Base64.getDecoder().decode(processedPublicKeyStr);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            return keyFactory.generatePublic(keySpec);
        } catch (IllegalArgumentException e) {
            // Base64.getDecoder().decode() 会在输入不是有效Base64时抛出此异常
            logger.error("Failed to decode Base64 public key string: {}. Input (processed, first 30 chars): '{}...'", e.getMessage(), publicKeyStr.replace(" ", "+").substring(0, Math.min(publicKeyStr.length(), 30)));
            return null;
        } catch (NoSuchAlgorithmException e) {
            logger.error("Error converting string to PublicKey: Algorithm {} not found. {}", algorithm, e.getMessage(), e);
            return null;
        } catch (InvalidKeySpecException e) {
            logger.error("Error converting string to PublicKey: Invalid key specification for algorithm {}. This often means the decoded Base64 string is not a valid key format. {}", algorithm, e.getMessage(), e);
            return null;
        } catch (Exception e) { // 捕获其他意外异常
            logger.error("An unexpected error occurred while converting string to PublicKey: {}", e.getMessage(), e);
            return null;
        }
    }
}
