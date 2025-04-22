package com.example.voting.crypto;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyUtil：从字节数组恢复 RSA 私钥和公钥
 */
public class KeyUtil {

    /**
     * 将 PKCS#8 格式的私钥字节数组转换为 PrivateKey 对象
     * @param keyBytes 私钥的 DER 编码字节（PKCS#8）
     * @return PrivateKey 对象
     * @throws Exception 如果解析或生成失败
     */
    public static PrivateKey privateKeyFromBytes(byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePrivate(spec);
    }

    /**
     * 将 X.509 格式的公钥字节数组转换为 PublicKey 对象
     * @param keyBytes 公钥的 DER 编码字节（X.509）
     * @return PublicKey 对象
     * @throws Exception 如果解析或生成失败
     */
    public static PublicKey publicKeyFromBytes(byte[] keyBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        return kf.generatePublic(spec);
    }
}
