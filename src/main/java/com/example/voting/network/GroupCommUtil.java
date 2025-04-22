package com.example.voting.network;

import com.example.voting.crypto.CryptoUtil;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import javax.crypto.Cipher;
import java.util.Base64;

/**
 * 群组密钥分发：RSA + AES
 */
public class GroupCommUtil {
    /** 为节点生成 RSA 密钥对 */
    public static KeyPair generateNodeKeyPair() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            return gen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("生成节点RSA密钥对失败", e);
        }
    }

    /** 生成 AES 群组密钥 */
    public static SecretKey generateGroupKey() {
        try {
            KeyGenerator gen = KeyGenerator.getInstance("AES");
            gen.init(128);
            return gen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("生成群组AES密钥失败", e);
        }
    }

    /** 将 AES 密钥用节点公钥加密后 Base64 编码 */
    public static String encryptGroupKeyForNode(SecretKey groupKey, java.security.PublicKey nodePubKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, nodePubKey);
            byte[] enc = cipher.doFinal(groupKey.getEncoded());
            return Base64.getEncoder().encodeToString(enc);
        } catch (Exception e) {
            throw new RuntimeException("群组密钥加密失败", e);
        }
    }

    /** 节点用私钥解密收到的群组密钥 */
    public static SecretKey decryptGroupKey(String encKeyBase64, java.security.PrivateKey nodePrivKey) {
        try {
            byte[] enc = Base64.getDecoder().decode(encKeyBase64);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, nodePrivKey);
            byte[] keyBytes = cipher.doFinal(enc);
            return CryptoUtil.secretKeyFromBytes(keyBytes);
        } catch (Exception e) {
            throw new RuntimeException("群组密钥解密失败", e);
        }
    }
}
