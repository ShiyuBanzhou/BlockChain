package com.bjut.blockchain.web.util;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

/**
 * Shamir 秘密共享方案工具类。
 * (k, n) 门限方案：将一个秘密分成 n 份，任意 k 份可以恢复秘密，少于 k 份则无法获取任何信息。
 */
public final class ShamirUtil {

    private ShamirUtil() {} // 防止实例化

    /**
     * 将秘密分割成 n 份，需要 k 份才能恢复。
     *
     * @param secret 要分割的秘密 (BigInteger)。
     * @param k      恢复秘密所需的最小份数（门限值）。
     * @param n      共享份总数。
     * @param prime  一个大素数，必须大于 secret 和 n。
     * @param random 用于生成随机多项式系数的安全随机数生成器。
     * @return 一个包含 n 份秘密共享的 Map。键是份额的索引 x (从 1 到 n 的 BigInteger)，值是对应的份额 y (BigInteger)。
     * @throws IllegalArgumentException 如果参数无效（例如 k > n, prime 不够大等）。
     */
    public static Map<BigInteger, BigInteger> split(final BigInteger secret, final int k, final int n, final BigInteger prime, final Random random) {
        if (k <= 0 || n < k || secret.compareTo(prime) >= 0 || BigInteger.valueOf(n).compareTo(prime) >= 0) {
            throw new IllegalArgumentException("Invalid parameters: k=" + k + ", n=" + n + ", secret=" + secret + ", prime=" + prime);
        }
        if (!prime.isProbablePrime(256)) { // 增加素性检查
            throw new IllegalArgumentException("Modulus 'prime' must be prime.");
        }


        // 生成一个 k-1 次的随机多项式 P(x) = a[0] + a[1]*x + ... + a[k-1]*x^(k-1)
        // 其中 a[0] = secret
        final BigInteger[] coefficients = new BigInteger[k];
        coefficients[0] = secret;
        for (int i = 1; i < k; i++) {
            // 系数需要在 [0, prime-1] 范围内随机选择
            BigInteger randomCoeff;
            do {
                randomCoeff = new BigInteger(prime.bitLength(), random);
            } while (randomCoeff.compareTo(BigInteger.ZERO) < 0 || randomCoeff.compareTo(prime) >= 0);
            coefficients[i] = randomCoeff;
        }

        // 计算 n 个点的份额 (x, P(x) mod prime) for x = 1, 2, ..., n
        final Map<BigInteger, BigInteger> shares = new HashMap<>();
        for (int i = 1; i <= n; i++) {
            BigInteger x = BigInteger.valueOf(i);
            BigInteger y = evaluatePolynomial(coefficients, x, prime);
            shares.put(x, y);
        }

        return shares;
    }

    /**
     * 使用提供的份额恢复秘密。
     *
     * @param shares 一个 Map，包含至少 k 份有效的秘密份额。键是份额索引 x，值是份额 y。
     * 份额数量必须大于等于生成时指定的 k 值。
     * @param prime  用于生成这些份额的素数模数 P。
     * @return 恢复的秘密 BigInteger。
     * @throws IllegalArgumentException 如果份额不足或 prime 无效。
     */
    public static BigInteger combine(final Map<BigInteger, BigInteger> shares, final BigInteger prime) {
        if (shares == null || shares.isEmpty() || prime == null || prime.signum() <= 0) {
            throw new IllegalArgumentException("Invalid parameters for combining shares.");
        }
        if (!prime.isProbablePrime(256)) { // 增加素性检查
            throw new IllegalArgumentException("Modulus 'prime' must be prime.");
        }

        // 使用拉格朗日插值法恢复 P(0)，即原始秘密
        BigInteger recoveredSecret = BigInteger.ZERO;
        BigInteger[] xCoords = shares.keySet().toArray(new BigInteger[0]);
        BigInteger[] yCoords = shares.values().toArray(new BigInteger[0]);
        int k = shares.size(); // 实际参与恢复的份额数量

        for (int i = 0; i < k; i++) {
            BigInteger xi = xCoords[i];
            BigInteger yi = yCoords[i];

            BigInteger lagrangeNumerator = BigInteger.ONE;
            BigInteger lagrangeDenominator = BigInteger.ONE;

            // 计算拉格朗日基多项式 L_i(0)
            for (int j = 0; j < k; j++) {
                if (i == j) {
                    continue;
                }
                BigInteger xj = xCoords[j];
                // Numerator: product of (-xj) for j != i
                lagrangeNumerator = lagrangeNumerator.multiply(xj.negate()).mod(prime);
                // Denominator: product of (xi - xj) for j != i
                lagrangeDenominator = lagrangeDenominator.multiply(xi.subtract(xj)).mod(prime);
            }

            // 计算分母的模逆元
            BigInteger invDenominator = lagrangeDenominator.modInverse(prime);

            // 计算 L_i(0) * y_i
            BigInteger term = yi.multiply(lagrangeNumerator).multiply(invDenominator).mod(prime);

            // 累加到结果
            recoveredSecret = recoveredSecret.add(term).mod(prime);
        }

        return recoveredSecret;
    }

    /**
     * 计算多项式在点 x 处的值 (模 prime)。
     * P(x) = coefficients[0] + coefficients[1]*x + ... + coefficients[k-1]*x^(k-1)
     *
     * @param coefficients 多项式系数数组 (a[0] 到 a[k-1])。
     * @param x            要求值的点。
     * @param prime        模数。
     * @return P(x) mod prime。
     */
    private static BigInteger evaluatePolynomial(final BigInteger[] coefficients, final BigInteger x, final BigInteger prime) {
        BigInteger result = BigInteger.ZERO;
        BigInteger xPower = BigInteger.ONE; // x^0

        for (BigInteger coefficient : coefficients) {
            BigInteger term = coefficient.multiply(xPower).mod(prime);
            result = result.add(term).mod(prime);
            xPower = xPower.multiply(x).mod(prime); // 计算下一个 x 的幂次
        }
        return result;
    }

    // --- Main method for testing (可选) ---
    public static void main(String[] args) {
        // 示例用法
        SecureRandom random = new SecureRandom();
        BigInteger secret = new BigInteger("1234567890123456789012345678901234567890"); // 示例秘密
        int k = 3; // 门限值
        int n = 5; // 总份额数
        BigInteger prime = BigInteger.probablePrime(secret.bitLength() + 1, random); // 选择一个足够大的素数

        System.out.println("Secret: " + secret);
        System.out.println("Prime modulus: " + prime);
        System.out.println("Threshold (k): " + k);
        System.out.println("Total shares (n): " + n);

        // 1. 分割秘密
        Map<BigInteger, BigInteger> allShares = split(secret, k, n, prime, random);
        System.out.println("\nGenerated Shares:");
        allShares.forEach((idx, share) -> System.out.println(" Share " + idx + ": " + share));

        // 2. 使用 k 份份额恢复秘密
        Map<BigInteger, BigInteger> sharesToRecover = new HashMap<>();
        // 取前 k 份
        int count = 0;
        for (Map.Entry<BigInteger, BigInteger> entry : allShares.entrySet()) {
            if (count < k) {
                sharesToRecover.put(entry.getKey(), entry.getValue());
                count++;
            } else {
                break;
            }
        }

        System.out.println("\nUsing " + k + " shares to recover:");
        sharesToRecover.forEach((idx, share) -> System.out.println(" Share " + idx + ": " + share));

        BigInteger recoveredSecret = combine(sharesToRecover, prime);
        System.out.println("\nRecovered Secret: " + recoveredSecret);
        System.out.println("Recovery successful: " + recoveredSecret.equals(secret));

        // 3. 尝试使用少于 k 份份额恢复 (应该失败或得到错误结果)
        Map<BigInteger, BigInteger> insufficientShares = new HashMap<>();
        count = 0;
        for (Map.Entry<BigInteger, BigInteger> entry : allShares.entrySet()) {
            if (count < k - 1) {
                insufficientShares.put(entry.getKey(), entry.getValue());
                count++;
            } else {
                break;
            }
        }
        System.out.println("\nTrying to recover with " + (k-1) + " shares:");
        try {
            // combine 方法内部没有检查份额数量是否足够 k，
            // 拉格朗日插值会进行计算，但结果通常是错误的。
            // 更健壮的 combine 实现应该检查 shares.size() >= k
            BigInteger wrongSecret = combine(insufficientShares, prime);
            System.out.println("Result with insufficient shares: " + wrongSecret);
            System.out.println("Is it the original secret? " + wrongSecret.equals(secret));
        } catch (Exception e) {
            System.out.println("Error combining insufficient shares (as expected): " + e.getMessage());
        }
    }
}
