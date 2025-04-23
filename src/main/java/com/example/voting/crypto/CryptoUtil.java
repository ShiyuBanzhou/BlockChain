package com.example.voting.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

/**
 * General encryption/signing/hashing utility.
 * 通用加密/签名/哈希工具。
 * Optionally specifies Bouncy Castle ("BC") provider for consistency.
 * 可选地指定 Bouncy Castle ("BC") 提供者以保持一致性。
 */
public class CryptoUtil {

    private static final String BC_PROVIDER = "BC"; // Bouncy Castle provider name Bouncy Castle 提供者名称

    /**
     * Calculates SHA-256 digest and returns hex string.
     * 计算 SHA-256 摘要并返回十六进制字符串。
     * @param data Input string. 输入字符串。
     * @return SHA-256 hash as hex string. SHA-256 哈希的十六进制字符串。
     */
    public static String sha256(String data) {
        try {
            // SHA-256 is standard, provider specification usually not needed here
            // SHA-256 是标准的，这里通常不需要指定提供者
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] d = md.digest(data.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : d) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 hashing failed", e);
        }
    }

    /**
     * Encrypts using AES.
     * 使用 AES 加密。
     * @param plain Plain text. 明文。
     * @param key Secret AES key. 秘密 AES 密钥。
     * @return Base64 encoded ciphertext. Base64 编码的密文。
     */
    public static String encryptAES(String plain, SecretKey key) {
        try {
            // AES is standard, provider specification usually not needed here
            // AES 是标准的，这里通常不需要指定提供者
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Specify mode and padding 指定模式和填充
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] ct = cipher.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(ct);
        } catch (Exception e) {
            throw new RuntimeException("AES encryption failed", e);
        }
    }

    /**
     * Decrypts using AES.
     * 使用 AES 解密。
     * @param cipherText Base64 encoded ciphertext. Base64 编码的密文。
     * @param key Secret AES key. 秘密 AES 密钥。
     * @return Plain text. 明文。
     */
    public static String decryptAES(String cipherText, SecretKey key) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // Use the same mode and padding 使用相同的模式和填充
            cipher.init(Cipher.DECRYPT_MODE, key);
            byte[] ct = Base64.getDecoder().decode(cipherText);
            byte[] pt = cipher.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // Decryption failures are common (wrong key, corrupted data), handle more gracefully in production
            // 解密失败很常见（密钥错误、数据损坏），在生产环境中应更优雅地处理
            System.err.println("AES decryption failed: " + e.getMessage());
            // Depending on context, might return null, throw specific exception, etc.
            // 根据上下文，可能返回 null、抛出特定异常等。
            return null; // Or rethrow as a custom exception 或者重新抛出为自定义异常
            // throw new RuntimeException("AES decryption failed", e);
        }
    }

    /**
     * Reconstructs SecretKey from bytes.
     * 从字节恢复 SecretKey。
     * @param bytes Key bytes. 密钥字节。
     * @return SecretKey object. SecretKey 对象。
     */
    public static SecretKey secretKeyFromBytes(byte[] bytes) {
        if (bytes == null) return null;
        // Ensure key length is valid for AES (16, 24, or 32 bytes)
        // 确保密钥长度对 AES 有效（16、24 或 32 字节）
        if (bytes.length != 16 && bytes.length != 24 && bytes.length != 32) {
            // Handle error: Log, throw exception, etc.
            // 处理错误：记录日志、抛出异常等。
            System.err.println("Invalid AES key length: " + bytes.length);
            // Pad or truncate if necessary and policy allows, but usually indicates an error
            // 如果策略允许，根据需要填充或截断，但这通常表示错误
            // For now, return null or throw
            // 暂时返回 null 或抛出异常
            return null;
        }
        return new SecretKeySpec(bytes, "AES");
    }

    /**
     * Signs data using SHA256withRSA and the private key.
     * 使用 SHA256withRSA 和私钥对数据进行签名。
     * @param data The data to sign. 要签名的数据。
     * @param privKey The private key. 私钥。
     * @return Base64 encoded signature. Base64 编码的签名。
     */
    public static String signSHA256withRSA(String data, PrivateKey privKey) {
        try {
            // Explicitly use Bouncy Castle provider
            // 显式使用 Bouncy Castle 提供者
            Signature sig = Signature.getInstance("SHA256withRSA", BC_PROVIDER);
            sig.initSign(privKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            byte[] signatureBytes = sig.sign();
            return Base64.getEncoder().encodeToString(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException("SHA256withRSA signing failed", e);
        }
    }

    /**
     * Verifies a SHA256withRSA signature.
     * 验证 SHA256withRSA 签名。
     * @param data The original data. 原始数据。
     * @param base64Sig Base64 encoded signature. Base64 编码的签名。
     * @param pubKey The public key corresponding to the private key used for signing.
     * 与用于签名的私钥对应的公钥。
     * @return true if the signature is valid, false otherwise. 如果签名有效则返回 true，否则返回 false。
     */
    public static boolean verifySHA256withRSA(String data, String base64Sig, PublicKey pubKey) {
        try {
            byte[] sigBytes = Base64.getDecoder().decode(base64Sig);
            // Explicitly use Bouncy Castle provider
            // 显式使用 Bouncy Castle 提供者
            Signature sig = Signature.getInstance("SHA256withRSA", BC_PROVIDER);
            sig.initVerify(pubKey);
            sig.update(data.getBytes(StandardCharsets.UTF_8));
            return sig.verify(sigBytes);
        } catch (Exception e) {
            // Signature verification failure is expected in many cases (tampered data, wrong key)
            // 在许多情况下（数据被篡改、密钥错误），签名验证失败是预期的
            System.err.println("Signature verification failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * Generates a new AES key (default 128 bits).
     * 生成新的 AES 密钥（默认为 128 位）。
     * @return A new SecretKey. 新的 SecretKey。
     */
    public static SecretKey generateAESKey() {
        return generateAESKey(128); // Default to 128 bits 默认为 128 位
    }

    /**
     * Generates a new AES key with specified size.
     * 生成具有指定大小的新 AES 密钥。
     * @param keySize Key size in bits (must be 128, 192, or 256). 密钥大小（位）（必须是 128、192 或 256）。
     * @return A new SecretKey. 新的 SecretKey。
     */
    public static SecretKey generateAESKey(int keySize) {
        if (keySize != 128 && keySize != 192 && keySize != 256) {
            throw new IllegalArgumentException("Invalid AES key size: " + keySize + ". Must be 128, 192, or 256.");
        }
        try {
            // Explicitly use Bouncy Castle provider
            // 显式使用 Bouncy Castle 提供者
            KeyGenerator keyGen = KeyGenerator.getInstance("AES", BC_PROVIDER);
            keyGen.init(keySize, new SecureRandom()); // Use SecureRandom 使用 SecureRandom
            return keyGen.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("AES key generation failed", e);
        }
    }

    /**
     * Reconstructs an AES SecretKey from a BigInteger, ensuring correct length.
     * 从 BigInteger 重构 AES SecretKey，确保长度正确。
     * @param secret The secret BigInteger. 秘密 BigInteger。
     * @param keyLengthBytes The desired key length in bytes (16, 24, or 32). 所需的密钥长度（字节）（16、24 或 32）。
     * @return The reconstructed SecretKey. 重构的 SecretKey。
     */
    public static SecretKey secretKeyFromBigInteger(BigInteger secret, int keyLengthBytes) {
        if (keyLengthBytes != 16 && keyLengthBytes != 24 && keyLengthBytes != 32) {
            throw new IllegalArgumentException("Invalid AES key length in bytes: " + keyLengthBytes);
        }
        byte[] fullKeyBytes = new byte[keyLengthBytes];
        byte[] secretBytes = secret.toByteArray();

        // Copy the least significant bytes from secretBytes into fullKeyBytes
        // 将 secretBytes 中最低有效字节复制到 fullKeyBytes 中
        int startInSecret = Math.max(0, secretBytes.length - keyLengthBytes); // Start index in secretBytes
        int startInFull = Math.max(0, keyLengthBytes - secretBytes.length);   // Start index in fullKeyBytes
        int lengthToCopy = Math.min(keyLengthBytes, secretBytes.length);      // Number of bytes to copy

        System.arraycopy(secretBytes, startInSecret, fullKeyBytes, startInFull, lengthToCopy);

        return new SecretKeySpec(fullKeyBytes, "AES");
    }
}
