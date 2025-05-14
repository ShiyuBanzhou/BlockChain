package com.bjut.blockchain.web.service;

import com.bjut.blockchain.web.util.ShamirUtil; // 引入 Shamir 工具类
import org.springframework.stereotype.Service;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

/**
 * 服务类，提供基于 Shamir 秘密共享的门限认证功能。
 */
@Service
public class ThresholdAuthService {

    private static final SecureRandom random = new SecureRandom();
    private static final int CERTAINTY = 256; // Miller-Rabin 素性测试的确定性参数

    /**
     * 生成一个用于门限方案的秘密，并将其分割成 n 份，需要 k 份才能恢复。
     *
     * @param n 共享份总数。
     * @param k 恢复秘密所需的最小份数（门限值）。
     * @param secretBitLength 秘密的比特长度（例如 256 位）。
     * @return 一个包含 n 份秘密共享的 Map，键是份额索引 (1 到 n)，值是份额本身。
     * 返回的 Map 中还包含一个特殊键 "prime"，其值为使用的素数模数。
     * 如果参数无效，则返回 null。
     */
    public Map<BigInteger, BigInteger> splitSecret(int n, int k, int secretBitLength) {
        if (k <= 0 || n < k || secretBitLength <= 0) {
            System.err.println("Invalid parameters for secret splitting: n=" + n + ", k=" + k + ", bits=" + secretBitLength);
            return null;
        }

        // 1. 生成一个足够大的秘密
        BigInteger secret = new BigInteger(secretBitLength, random);

        // 2. 选择一个足够大的素数 P，P > secret 且 P > n
        // 素数的选择对于安全性至关重要，需要比 secret 和 n 都大
        // 这里选择一个比 secret 大一点的素数
        BigInteger prime = BigInteger.probablePrime(secretBitLength + 1, random);
        // 确保 prime > n (通常 secretBitLength 足够大时会自动满足)
        while (prime.compareTo(BigInteger.valueOf(n)) <= 0 || prime.compareTo(secret) <= 0) {
            prime = BigInteger.probablePrime(prime.bitLength() + 1, random);
        }


        System.out.println("Splitting secret (bit length " + secretBitLength + ") into " + n + " shares with threshold " + k + " using prime " + prime);
        // System.out.println("Secret: " + secret); // 注意：实际应用中不应打印秘密

        // 3. 使用 ShamirUtil 进行分割
        try {
            Map<BigInteger, BigInteger> shares = ShamirUtil.split(secret, k, n, prime, random);
            shares.put(BigInteger.valueOf(0), prime); // 使用索引 0 存储素数 P (或者使用其他非份额索引的键)
            // 或者创建一个专门的返回对象包含 shares 和 prime
            System.out.println("Secret split successfully.");
            return shares;
        } catch (Exception e) {
            System.err.println("Error splitting secret: " + e.getMessage());
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 使用提供的份额恢复秘密。
     *
     * @param shares 一个 Map，包含至少 k 份有效的秘密份额。键是份额索引，值是份额。
     * @param prime  用于生成这些份额的素数模数 P。
     * @param k      恢复秘密所需的最小份数（门限值）。
     * @return 恢复的秘密 BigInteger。如果份额不足或无效，则返回 null。
     */
    public BigInteger recoverSecret(Map<BigInteger, BigInteger> shares, BigInteger prime, int k) {
        if (shares == null || shares.size() < k || prime == null || prime.signum() <= 0 || k <= 0) {
            System.err.println("Invalid parameters for secret recovery: shares size=" + (shares == null ? "null" : shares.size()) + ", k=" + k + ", prime=" + prime);
            return null;
        }

        System.out.println("Attempting to recover secret with " + shares.size() + " shares (threshold " + k + ") using prime " + prime);

        try {
            BigInteger recoveredSecret = ShamirUtil.combine(shares, prime);
            System.out.println("Secret recovered successfully.");
            // System.out.println("Recovered Secret: " + recoveredSecret); // 注意：实际应用中不应打印秘密
            return recoveredSecret;
        } catch (Exception e) {
            System.err.println("Error recovering secret: " + e.getMessage());
            // 可能是因为份额不足或被篡改
            e.printStackTrace();
            return null;
        }
    }

    /**
     * 验证一组份额是否满足门限要求，并能成功恢复出某个（未知的）秘密。
     * 这可以用于验证是否有足够多的参与者同意了某个操作。
     *
     * @param shares 收到的份额 Map。
     * @param prime  使用的素数模数 P。
     * @param k      门限值。
     * @return 如果份额数量达到 k 且可以成功组合（意味着它们来自同一个原始秘密），则返回 true，否则返回 false。
     */
    public boolean verifyThreshold(Map<BigInteger, BigInteger> shares, BigInteger prime, int k) {
        if (shares == null || prime == null || k <= 0) {
            return false;
        }
        if (shares.size() < k) {
            System.out.println("Verification failed: Not enough shares provided (" + shares.size() + "/" + k + ")");
            return false;
        }
        // 尝试恢复秘密，如果成功则说明满足门限且份额有效
        BigInteger recovered = recoverSecret(shares, prime, k);
        boolean success = recovered != null;
        if (success) {
            System.out.println("Threshold verification successful: " + shares.size() + " shares provided, threshold " + k + " met.");
        } else {
            System.out.println("Threshold verification failed: Could not recover secret with provided shares.");
        }
        return success;
    }

}
