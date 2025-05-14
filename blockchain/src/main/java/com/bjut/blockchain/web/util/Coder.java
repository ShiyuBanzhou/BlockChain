package com.bjut.blockchain.web.util;

import java.security.MessageDigest;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * 基础加密组件
 *
 * @author Jared Jia
 * 
 */
public abstract class Coder {
    public static final String KEY_SHA = "SHA";
    public static final String KEY_MD5 = "MD5";

    /**
     * MAC算法可选以下多种算法
     *
     * <pre>
     * HmacMD5
     * HmacSHA256
     * </pre>
     */
    public static final String KEY_MAC = "HmacMD5";

    /**
     * BASE64解码
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptBASE64(String key) throws Exception {
    	Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(key);
    }

    /**
     * BASE64编码
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptBASE64(byte[] key) throws Exception {
    	Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(key);
    }

    /**
     * MD5加密
     *
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] encryptMD5(byte[] data) throws Exception {

        MessageDigest md5 = MessageDigest.getInstance(KEY_MD5);
        md5.update(data);

        return md5.digest();

    }

    /**
     * SHA加密
     *
     * @param data
     * @return
     * @throws Exception
     */
    public static byte[] encryptSHA(byte[] data) throws Exception {

        MessageDigest sha = MessageDigest.getInstance(KEY_SHA);
        sha.update(data);

        return sha.digest();

    }

    /**
     * 初始化HMAC密钥
     *
     * @return
     * @throws Exception
     */
    public static String initMacKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_MAC);

        SecretKey secretKey = keyGenerator.generateKey();
        return encryptBASE64(secretKey.getEncoded());
    }

    /**
     * HMAC加密
     *
     * @param data
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] encryptHMAC(byte[] data, String key) throws Exception {

        SecretKey secretKey = new SecretKeySpec(decryptBASE64(key), KEY_MAC);
        Mac mac = Mac.getInstance(secretKey.getAlgorithm());
        mac.init(secretKey);

        return mac.doFinal(data);

    }


      /**
     * 使用AES算法加密明文
     *
     * @param plainText 明文字符串
     * @param secretKeyStr 十六进制编码的密钥字符串
     * @return 加密后的密文字符串，经过Base64编码
     * @throws Exception 如果加密过程中发生错误
     */
    public static String encryptAES(String plainText, String secretKeyStr) throws Exception {
        // 将十六进制编码的密钥字符串转换为字节数组
        byte[] secretKeyBytes = hexStringToByteArray(secretKeyStr);
        // 使用字节数组创建一个AES密钥
        SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");
        // 获取AES Cipher实例
        Cipher cipher = Cipher.getInstance("AES");
        // 初始化Cipher为加密模式
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // 使用Cipher加密明文并返回Base64编码的密文字符串
        byte[] encryptedBytes = cipher.doFinal(plainText.getBytes("UTF-8"));
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    /**
     * 使用AES算法解密密文
     *
     * @param encryptedText Base64编码的密文字符串
     * @param secretKeyStr 十六进制编码的密钥字符串
     * @return 解密后的明文字符串
     * @throws Exception 如果解密过程中发生错误
     */
    public static String decryptAES(String encryptedText, String secretKeyStr) throws Exception {
        // 将十六进制编码的密钥字符串转换为字节数组
        byte[] secretKeyBytes = hexStringToByteArray(secretKeyStr);
        // 使用字节数组创建一个AES密钥
        SecretKey secretKey = new SecretKeySpec(secretKeyBytes, "AES");
        // 获取AES Cipher实例
        Cipher cipher = Cipher.getInstance("AES");
        // 初始化Cipher为解密模式
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        // 使用Cipher解密密文并返回明文字符串
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes, "UTF-8");
    }

    /**
     * 将十六进制字符串转换为字节数组
     *
     * @param hexString 十六进制字符串
     * @return 字节数组
     */
    private static byte[] hexStringToByteArray(String hexString) {
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                    + Character.digit(hexString.charAt(i + 1), 16));
        }
        return data;
    }
}
