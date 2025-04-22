package com.example.voting.crypto;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * 简单 RSA 盲签名示例
 */
public class BlindSignatureUtil {
    private static BigInteger n, e, d;
    private static BigInteger blindFactor; // 保存盲因子

    static {
        // 示例用小质数生成 RSA 密钥，实际应使用 2048+ 位
        BigInteger p = BigInteger.valueOf(61), q = BigInteger.valueOf(53);
        n = p.multiply(q);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.valueOf(17);
        d = e.modInverse(phi);
    }

    /** 客户端：盲化消息 m -> m' = m * r^e mod n */
    public static BigInteger blindMessage(BigInteger message, BigInteger pubExp) {
        SecureRandom rnd = new SecureRandom();
        BigInteger r;
        do {
            r = new BigInteger(n.bitLength()-1, rnd);
        } while (!r.gcd(n).equals(BigInteger.ONE));
        blindFactor = r;
        return message.multiply(r.modPow(pubExp, n)).mod(n);
    }

    /** 权威用私钥对盲化消息签名 s' = (m')^d mod n */
    public static BigInteger blindSign(BigInteger blindedMsg) {
        return blindedMsg.modPow(d, n);
    }

    /** 客户端：去盲 s = s' * r^{-1} mod n */
    public static BigInteger unblindSignature(BigInteger signedBlindedMsg) {
        BigInteger rInv = blindFactor.modInverse(n);
        return signedBlindedMsg.multiply(rInv).mod(n);
    }

    /** 验证签名：检查 s^e mod n == message */
    public static boolean verifySignature(BigInteger msg, BigInteger sig) {
        return sig.modPow(e, n).equals(msg.mod(n));
    }
}
