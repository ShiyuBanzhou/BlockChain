package com.example.voting.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Simple RSA Blind Signature Example - INSECURE, FOR DEMONSTRATION ONLY.
 * 简单 RSA 盲签名示例 - 不安全，仅供演示。
 * Uses small, hardcoded keys. DO NOT USE IN PRODUCTION.
 * 使用小的硬编码密钥。请勿在生产环境中使用。
 */
public class BlindSignatureUtil {
    // --- Insecure hardcoded RSA parameters ---
    // --- 不安全的硬编码 RSA 参数 ---
    private static final BigInteger n; // Modulus 模数
    private static final BigInteger e; // Public exponent 公钥指数
    private static final BigInteger d; // Private exponent 私钥指数 (Should be kept secret by authority) （应由权威机构保密）

    // Static initializer to set up the insecure keys
    // 静态初始化块，用于设置不安全的密钥
    static {
        // Example using small primes (61, 53) - Replace with secure generation in real use
        // 使用小素数 (61, 53) 的示例 - 在实际使用中替换为安全生成
        BigInteger p = BigInteger.valueOf(61);
        BigInteger q = BigInteger.valueOf(53);
        n = p.multiply(q); // n = 3233
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); // phi = 60 * 52 = 3120
        e = BigInteger.valueOf(17); // Common public exponent 常用的公钥指数
        // Calculate private exponent d such that e*d = 1 (mod phi)
        // 计算私钥指数 d，使得 e*d = 1 (mod phi)
        d = e.modInverse(phi); // d = 17^-1 mod 3120 = 2753
        System.out.println("--- BlindSignatureUtil initialized (INSECURE DEMO) ---");
        System.out.println("n (Modulus): " + n);
        System.out.println("e (Public Exp): " + e);
        System.out.println("d (Private Exp): " + d);
        System.out.println("----------------------------------------------------");
    }

    // --- Getters for RSA parameters (needed by MainApp) ---
    // --- RSA 参数的 Getter（MainApp 需要） ---

    /**
     * Gets the RSA modulus (n).
     * 获取 RSA 模数 (n)。
     * @return The modulus. 模数。
     */
    public static BigInteger getN() {
        return n;
    }

    /**
     * Gets the RSA public exponent (e).
     * 获取 RSA 公钥指数 (e)。
     * @return The public exponent. 公钥指数。
     */
    public static BigInteger getE() {
        return e;
    }

    // Note: getD() is usually not exposed as 'd' is the private key.
    // 注意：通常不公开 getD()，因为 'd' 是私钥。
    // The blindSign method uses 'd' internally.
    // blindSign 方法在内部使用 'd'。


    /**
     * Generates a random blinding factor 'r' such that gcd(r, n) = 1.
     * 生成一个随机盲化因子 'r'，使得 gcd(r, n) = 1。
     * @param modulus The RSA modulus (n). RSA 模数 (n)。
     * @return A suitable blinding factor. 合适的盲化因子。
     */
    public static BigInteger generateBlindingFactor(BigInteger modulus) {
        SecureRandom rnd = new SecureRandom();
        BigInteger r;
        do {
            // Generate a random number less than n
            // 生成小于 n 的随机数
            r = new BigInteger(modulus.bitLength(), rnd);
        } while (r.compareTo(BigInteger.ONE) <= 0 || r.compareTo(modulus) >= 0 || !r.gcd(modulus).equals(BigInteger.ONE));
        // Ensure r > 1, r < n, and r is coprime to n
        // 确保 r > 1, r < n, 且 r 与 n 互质
        return r;
    }

    /**
     * Client: Blinds the message m using blinding factor r.
     * 客户端：使用盲化因子 r 盲化消息 m。
     * Calculates m' = m * (r^e) mod n.
     * 计算 m' = m * (r^e) mod n。
     * @param message The original message (e.g., a token). 原始消息（例如，令牌）。
     * @param blindingFactor The random blinding factor 'r'. 随机盲化因子 'r'。
     * @param publicExponent The RSA public exponent 'e'. RSA 公钥指数 'e'。
     * @param modulus The RSA modulus 'n'. RSA 模数 'n'。
     * @return The blinded message m'. 盲化后的消息 m'。
     */
    public static BigInteger blindMessage(BigInteger message, BigInteger blindingFactor, BigInteger publicExponent, BigInteger modulus) {
        // Calculate r^e mod n
        // 计算 r^e mod n
        BigInteger rPowE = blindingFactor.modPow(publicExponent, modulus);
        // Calculate m' = m * (r^e) mod n
        // 计算 m' = m * (r^e) mod n
        return message.multiply(rPowE).mod(modulus);
    }

    /**
     * Authority: Signs the blinded message m' using the private key d.
     * 权威机构：使用私钥 d 对盲化消息 m' 进行签名。
     * Calculates s' = (m')^d mod n.
     * 计算 s' = (m')^d mod n。
     * @param blindedMsg The blinded message m'. 盲化后的消息 m'。
     * @return The signature s' on the blinded message. 对盲化消息的签名 s'。
     */
    public static BigInteger blindSign(BigInteger blindedMsg) {
        // Sign using the authority's private exponent 'd' and modulus 'n'
        // 使用权威机构的私钥指数 'd' 和模数 'n' 进行签名
        return blindedMsg.modPow(d, n);
    }

    /**
     * Client: Unblinds the signature s' using the original blinding factor r.
     * 客户端：使用原始盲化因子 r 对签名 s' 进行去盲。
     * Calculates s = s' * (r^-1) mod n.
     * 计算 s = s' * (r^-1) mod n。
     * @param signedBlindedMsg The signature s' received from the authority. 从权威机构收到的签名 s'。
     * @param blindingFactor The original blinding factor 'r' used. 使用的原始盲化因子 'r'。
     * @param modulus The RSA modulus 'n'. RSA 模数 'n'。
     * @return The unblinded signature s on the original message m. 对原始消息 m 的去盲签名 s。
     */
    public static BigInteger unblindSignature(BigInteger signedBlindedMsg, BigInteger blindingFactor, BigInteger modulus) {
        // Calculate the modular inverse of r: r^-1 mod n
        // 计算 r 的模逆：r^-1 mod n
        BigInteger rInv = blindingFactor.modInverse(modulus);
        // Calculate s = s' * (r^-1) mod n
        // 计算 s = s' * (r^-1) mod n
        return signedBlindedMsg.multiply(rInv).mod(modulus);
    }

    /**
     * Verifies the unblinded signature s against the original message m.
     * 对照原始消息 m 验证去盲后的签名 s。
     * Checks if s^e mod n == m mod n.
     * 检查是否 s^e mod n == m mod n。
     * @param originalMessage The original message m. 原始消息 m。
     * @param signature The unblinded signature s. 去盲后的签名 s。
     * @return true if the signature is valid, false otherwise. 如果签名有效则返回 true，否则返回 false。
     */
    public static boolean verifySignature(BigInteger originalMessage, BigInteger signature) {
        // Verify using the public exponent 'e' and modulus 'n'
        // 使用公钥指数 'e' 和模数 'n' 进行验证
        BigInteger verification = signature.modPow(e, n);
        // Compare with the original message (mod n)
        // 与原始消息比较 (mod n)
        return verification.equals(originalMessage.mod(n));
    }
}
