package com.example.voting.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * 简单 Shamir 门限方案：2-of-3
 */
public class ThresholdScheme {
    public static class Share {
        public int id;            // 分享编号 1~3
        public BigInteger value;  // 分片值 f(id)
        public Share(int id, BigInteger value) { this.id = id; this.value = value; }
    }

    /** 生成 3 个分片，秘密位于常数项 */
    public static Share[] generateShares() {
        SecureRandom rnd = new SecureRandom();
        BigInteger prime = BigInteger.valueOf(104729);      // 质数模数
        BigInteger secret = new BigInteger(64, rnd);         // 64 位秘密
        BigInteger a = new BigInteger(64, rnd);              // 一次多项式系数
        Share[] shares = new Share[3];
        for (int x = 1; x <= 3; x++) {
            BigInteger fx = secret.add(a.multiply(BigInteger.valueOf(x))).mod(prime);
            shares[x-1] = new Share(x, fx);
        }
        System.out.println("调试：秘密 = " + secret);
        return shares;
    }

    /** 从任意两个分片插值恢复秘密 */
    public static BigInteger recoverSecret(Share s1, Share s2) {
        BigInteger x1 = BigInteger.valueOf(s1.id), x2 = BigInteger.valueOf(s2.id);
        BigInteger y1 = s1.value, y2 = s2.value;
        BigInteger a = (y2.subtract(y1)).divide(x2.subtract(x1));
        return y1.subtract(a.multiply(x1));
    }

    /**
     * 将一个大整数 secret（比如 16 byte 的 AES key）拆成 3 片，
     * 任意两片可恢复原 secret（线性多项式 f(x)=secret + a*x）
     */
    public static Share[] generateSharesFromSecret(BigInteger secret) {
        SecureRandom rnd = new SecureRandom();
        // 随机系数 a
        BigInteger a = new BigInteger(secret.bitLength(), rnd);
        Share[] shares = new Share[3];
        for (int x = 1; x <= 3; x++) {
            // f(x) = secret + a*x
            BigInteger fx = secret.add(a.multiply(BigInteger.valueOf(x)));
            shares[x - 1] = new Share(x, fx);
        }
        return shares;
    }
}
