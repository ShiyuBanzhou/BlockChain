package com.example.voting.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

/**
 * 通用加密/签名/哈希工具
 */
public class CryptoUtil {
    /** 计算 SHA-256 摘要并转 hex */
    public static String sha256(String data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(data.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /** AES 对称加密 */
    public static String encryptAES(String plain, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] ct = cipher.doFinal(plain.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(ct);
        } catch (Exception e) {
            throw new RuntimeException("AES 加密失败", e);
        }
    }

    /** AES 对称解密 */
    public static String decryptAES(String cipherText, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] ct = Base64.getDecoder().decode(cipherText);
            byte[] pt = cipher.doFinal(ct);
            return new String(pt, "UTF-8");
        } catch (Exception e) {
            throw new RuntimeException("AES 解密失败", e);
        }
    }

    /** 从字节恢复 SecretKey */
    public static SecretKey secretKeyFromBytes(byte[] bytes) {
        return new SecretKeySpec(bytes, "AES");
    }

    /** RSA 签名（私钥 Base64 字符串） */
    public static String signSHA256(String data, String base64PrivKey) {
        try {
            byte[] pkBytes = Base64.getDecoder().decode(base64PrivKey);
            PrivateKey priv = KeyUtil.privateKeyFromBytes(pkBytes); // 需实现
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(priv);
            sig.update(data.getBytes("UTF-8"));
            return Base64.getEncoder().encodeToString(sig.sign());
        } catch (Exception e) {
            throw new RuntimeException("签名失败", e);
        }
    }

    /** RSA 签名验证 */
    public static boolean verifySignature(String data, String base64Sig, PublicKey pubKey) {
        try {
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(pubKey);
            sig.update(data.getBytes("UTF-8"));
            byte[] sigBytes = Base64.getDecoder().decode(base64Sig);
            return sig.verify(sigBytes);
        } catch (Exception e) {
            return false;
        }
    }

    // 生成真正的 128bit AES 密钥
    public static SecretKey generateAESKey() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("AES 密钥生成失败", e);
        }
    }

    // 从任意长度的 BigInteger 恢复为恰好 keyLength 字节的 AES key
    public static SecretKey secretKeyFromBigInteger(BigInteger secret, int keyLength) {
        byte[] full = new byte[keyLength];
        byte[] bytes = secret.toByteArray();
        // 取最低 keyLength 字节（忽略多余高位，或左侧补 0）
        int copyLen = Math.min(bytes.length, keyLength);
        System.arraycopy(bytes, bytes.length - copyLen, full, keyLength - copyLen, copyLen);
        return new SecretKeySpec(full, "AES");
    }
}
