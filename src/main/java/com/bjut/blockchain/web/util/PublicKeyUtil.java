package com.bjut.blockchain.web.util;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class PublicKeyUtil {

    /**
     * 将 PublicKey 对象转换为 Base64 编码的字符串
     * @param publicKey 要转换的 PublicKey 对象
     * @return 转换后的 Base64 编码字符串，如果转换失败则返回 null
     */
    public static String publicKeyToString(PublicKey publicKey) {
        if (publicKey == null) {
            return null;
        }
        try {
            byte[] publicKeyBytes = publicKey.getEncoded();
            return Base64.getEncoder().encodeToString(publicKeyBytes);
        } catch (Exception e) {
            e.printStackTrace();
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
        if (publicKeyStr == null || algorithm == null) {
            return null;
        }
        try {
            byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyStr);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance(algorithm);
            return keyFactory.generatePublic(keySpec);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }
}