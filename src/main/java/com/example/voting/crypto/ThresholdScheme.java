package com.example.voting.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Simple Shamir's Secret Sharing Scheme (t=2, n).
 * 简单的 Shamir 秘密共享方案 (t=2, n)。
 * Uses a linear polynomial f(x) = secret + a*x mod p.
 * 使用线性多项式 f(x) = secret + a*x mod p。
 * Requires 2 shares to reconstruct the secret.
 * 需要 2 个分片来重构秘密。
 */
public class ThresholdScheme {

    // Use a larger prime modulus (e.g., 256-bit) to comfortably accommodate 128-bit secrets.
    // 使用更大的素数模数（例如 256 位）以轻松容纳 128 位秘密。
    // This is the prime used in secp256k1 curve: 2^256 - 2^32 - 977
    // 这是 secp256k1 曲线中使用的素数：2^256 - 2^32 - 977
    private static final BigInteger PRIME_MODULUS = new BigInteger(
            "115792089237316195423570985008687907853269984665640564039457584007908834671663");

    /**
     * Represents a share of the secret.
     * 表示秘密的一个分片。
     */
    public static class Share {
        public final int id;            // Share identifier (x-coordinate, 1 to n) 分片标识符（x 坐标，1 到 n）
        public final BigInteger value;  // Share value (y-coordinate, f(id)) 分片值（y 坐标，f(id)）

        public Share(int id, BigInteger value) {
            this.id = id;
            this.value = value;
        }

        @Override
        public String toString() {
            return "Share{" + "id=" + id + ", value=" + value + '}';
        }
    }

    /**
     * Generates 'n' shares from a secret BigInteger using a linear polynomial (t=2).
     * 使用线性多项式 (t=2) 从秘密 BigInteger 生成 'n' 个分片。
     * Polynomial: f(x) = secret + a*x mod p, where p is a large prime.
     * 多项式：f(x) = secret + a*x mod p，其中 p 是一个大素数。
     * @param secret The secret BigInteger to share. Must be less than PRIME_MODULUS. 要共享的秘密 BigInteger。必须小于 PRIME_MODULUS。
     * @param n The total number of shares to generate. 要生成的总分片数。
     * @param t The threshold number of shares required to recover (currently fixed at 2). 恢复所需的阈值分片数（当前固定为 2）。
     * @return An array of 'n' Share objects. 'n' 个 Share 对象的数组。
     * @throws IllegalArgumentException if secret >= PRIME_MODULUS or n < t or t != 2. 如果 secret >= PRIME_MODULUS 或 n < t 或 t != 2。
     */
    public static Share[] generateSharesFromSecret(BigInteger secret, int n, int t) {
        // --- Input Validation ---
        // --- 输入验证 ---
        if (t != 2) {
            throw new IllegalArgumentException("This implementation currently only supports threshold t=2.");
        }
        if (n < t) {
            throw new IllegalArgumentException("Number of shares (n) must be at least the threshold (t).");
        }
        // This check should now always pass for 128-bit secrets with the larger prime
        // 对于较大的素数，此检查现在应始终通过 128 位秘密
        if (secret.compareTo(PRIME_MODULUS) >= 0) {
            System.err.println("Secret Value: " + secret);
            System.err.println("Prime Modulus: " + PRIME_MODULUS);
            throw new IllegalArgumentException("Secret is too large for the chosen prime modulus.");
        }
        if (secret.signum() < 0) {
            throw new IllegalArgumentException("Secret must be non-negative.");
        }

        SecureRandom rnd = new SecureRandom();

        // Generate a random coefficient 'a' for the linear polynomial f(x) = secret + a*x
        // 为线性多项式 f(x) = secret + a*x 生成随机系数 'a'
        // 'a' should also be less than the prime modulus, and non-zero
        // 'a' 也应小于素数模数，且非零
        BigInteger a;
        do {
            // Generate random BigInteger up to the bit length of the modulus, then take mod p
            // 生成最大为模数位长的随机 BigInteger，然后取模 p
            a = new BigInteger(PRIME_MODULUS.bitLength(), rnd).mod(PRIME_MODULUS);
        } while (a.signum() == 0); // Ensure a is not zero 确保 a 不为零


        System.out.println("Generating " + n + " shares (t=2) for secret..."); // Removed secret logging 删除了秘密日志记录
        System.out.println("Using prime modulus (first 10 digits): " + PRIME_MODULUS.toString().substring(0, 10) + "...");
        // System.out.println("Random coefficient 'a': " + a); // Can be verbose 可以是冗余输出


        Share[] shares = new Share[n];
        for (int i = 0; i < n; i++) {
            int x = i + 1; // Share IDs are 1, 2, ..., n 分片 ID 为 1, 2, ..., n
            BigInteger bigX = BigInteger.valueOf(x);

            // Calculate f(x) = (secret + a*x) mod p
            // 计算 f(x) = (secret + a*x) mod p
            BigInteger termAX = a.multiply(bigX).mod(PRIME_MODULUS); // Calculate a*x mod p 计算 a*x mod p
            BigInteger fx = secret.add(termAX).mod(PRIME_MODULUS); // Calculate secret + (a*x mod p) mod p 计算 secret + (a*x mod p) mod p

            shares[i] = new Share(x, fx);
            // System.out.println("Generated Share: " + shares[i]); // Can be verbose 可以是冗余输出
        }
        return shares;
    }

    /**
     * Recovers the secret using exactly two shares (Lagrange interpolation for t=2).
     * 使用恰好两个分片恢复秘密（针对 t=2 的拉格朗日插值）。
     * Assumes f(x) = secret + a*x mod p. The secret is f(0).
     * 假设 f(x) = secret + a*x mod p。秘密是 f(0)。
     * Calculates secret = (y1*x2 - y2*x1) * (x2 - x1)^-1 mod p
     * 计算 secret = (y1*x2 - y2*x1) * (x2 - x1)^-1 mod p
     * @param s1 The first share. 第一个分片。
     * @param s2 The second share. 第二个分片。
     * @return The recovered secret BigInteger. 恢复的秘密 BigInteger。
     * @throws IllegalArgumentException if shares have the same id. 如果分片具有相同的 id。
     */
    public static BigInteger recoverSecret(Share s1, Share s2) {
        // System.out.println("Recovering secret using shares: " + s1 + " and " + s2); // Reduce verbosity 减少冗余输出
        // System.out.println("Using prime modulus (first 10 digits): " + PRIME_MODULUS.toString().substring(0, 10) + "..."); // Reduce verbosity 减少冗余输出

        BigInteger x1 = BigInteger.valueOf(s1.id);
        BigInteger y1 = s1.value;
        BigInteger x2 = BigInteger.valueOf(s2.id);
        BigInteger y2 = s2.value;

        if (x1.equals(x2)) {
            throw new IllegalArgumentException("Shares must have distinct IDs for recovery.");
        }

        // Calculate using Lagrange polynomial L(0) for f(x) = a*x + secret
        // L(0) = y1 * l1(0) + y2 * l2(0)
        // l1(0) = x2 * (x2 - x1)^-1 mod p
        // l2(0) = x1 * (x1 - x2)^-1 mod p = -x1 * (x2 - x1)^-1 mod p

        // Calculate denominator (x2 - x1) mod p
        // 计算分母 (x2 - x1) mod p
        BigInteger denom = x2.subtract(x1).mod(PRIME_MODULUS);
        // Calculate modular inverse of denominator: (x2 - x1)^-1 mod p
        // 计算分母的模逆：(x2 - x1)^-1 mod p
        BigInteger denomInv = denom.modInverse(PRIME_MODULUS);

        // Calculate numerator term 1: y1 * x2 mod p
        // 计算分子项 1：y1 * x2 mod p
        BigInteger term1 = y1.multiply(x2).mod(PRIME_MODULUS);

        // Calculate numerator term 2: y2 * x1 mod p
        // 计算分子项 2：y2 * x1 mod p
        BigInteger term2 = y2.multiply(x1).mod(PRIME_MODULUS);

        // Calculate numerator: (y1*x2 - y2*x1) mod p
        // 计算分子：(y1*x2 - y2*x1) mod p
        BigInteger numerator = term1.subtract(term2).mod(PRIME_MODULUS);

        // Calculate secret = numerator * denomInv mod p
        // 计算 secret = numerator * denomInv mod p
        BigInteger recoveredSecret = numerator.multiply(denomInv).mod(PRIME_MODULUS);

        // System.out.println("Recovered secret (first 10 digits): " + recoveredSecret.toString().substring(0, Math.min(10, recoveredSecret.toString().length()))); // Reduce verbosity 减少冗余输出
        return recoveredSecret;
    }

    /**
     * Gets the prime modulus used by the scheme.
     * 获取方案使用的素数模数。
     * @return The prime modulus as a BigInteger. 作为 BigInteger 的素数模数。
     */
    public static BigInteger getPrimeModulus() {
        return PRIME_MODULUS;
    }
}
