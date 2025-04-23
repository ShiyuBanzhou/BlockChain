package com.example.voting.crypto;

import java.security.*; // Import necessary classes 导入必要的类
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * KeyUtil: Utility for handling RSA keys.
 * KeyUtil：处理 RSA 密钥的实用工具。
 */
public class KeyUtil {

    private static final int RSA_KEY_SIZE = 2048; // Standard RSA key size 标准 RSA 密钥大小
    private static final String ALGORITHM = "RSA"; // Algorithm name 算法名称
    private static final String BC_PROVIDER = "BC"; // Bouncy Castle provider Bouncy Castle 提供者

    /**
     * Generates a new RSA KeyPair.
     * 生成新的 RSA 密钥对。
     * @return A new KeyPair object. 新的 KeyPair 对象。
     * @throws RuntimeException if key generation fails. 如果密钥生成失败。
     */
    public static KeyPair generateRSAKeyPair() {
        try {
            // Get KeyPairGenerator instance, explicitly using Bouncy Castle
            // 获取 KeyPairGenerator 实例，显式使用 Bouncy Castle
            KeyPairGenerator gen = KeyPairGenerator.getInstance(ALGORITHM, BC_PROVIDER);
            // Initialize with key size and a secure random source
            // 使用密钥大小和安全随机源进行初始化
            gen.initialize(RSA_KEY_SIZE, new SecureRandom());
            System.out.println("Generating RSA Key Pair (" + RSA_KEY_SIZE + " bits)...");
            KeyPair keyPair = gen.generateKeyPair();
            System.out.println("RSA Key Pair generated successfully.");
            return keyPair;
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            // These errors usually indicate a setup problem (BC provider not registered?)
            // 这些错误通常表示设置问题（BC 提供者未注册？）
            System.err.println("FATAL: Failed to get KeyPairGenerator instance for RSA with BC provider.");
            e.printStackTrace();
            throw new RuntimeException("Key generation setup failed (BC provider missing or algorithm invalid?)", e);
        } catch (Exception e) {
            // Catch other potential exceptions during initialization or generation
            // 捕获初始化或生成过程中的其他潜在异常
            System.err.println("ERROR: Failed to generate RSA key pair.");
            e.printStackTrace();
            throw new RuntimeException("RSA key pair generation failed", e);
        }
    }


    /**
     * Converts PKCS#8 encoded private key bytes to a PrivateKey object.
     * 将 PKCS#8 编码的私钥字节转换为 PrivateKey 对象。
     * @param keyBytes DER encoded private key bytes (PKCS#8). DER 编码的私钥字节 (PKCS#8)。
     * @return PrivateKey object. PrivateKey 对象。
     * @throws Exception If parsing or generation fails. 如果解析或生成失败。
     */
    public static PrivateKey privateKeyFromBytes(byte[] keyBytes) throws Exception {
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        // Specify BC provider for consistency
        // 指定 BC 提供者以保持一致性
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM, BC_PROVIDER);
        return kf.generatePrivate(spec);
    }

    /**
     * Converts X.509 encoded public key bytes to a PublicKey object.
     * 将 X.509 编码的公钥字节转换为 PublicKey 对象。
     * @param keyBytes DER encoded public key bytes (X.509). DER 编码的公钥字节 (X.509)。
     * @return PublicKey object. PublicKey 对象。
     * @throws Exception If parsing or generation fails. 如果解析或生成失败。
     */
    public static PublicKey publicKeyFromBytes(byte[] keyBytes) throws Exception {
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        // Specify BC provider for consistency
        // 指定 BC 提供者以保持一致性
        KeyFactory kf = KeyFactory.getInstance(ALGORITHM, BC_PROVIDER);
        return kf.generatePublic(spec);
    }
}
