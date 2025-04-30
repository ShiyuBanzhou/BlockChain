package com.bjut.blockchain.web.util;

import lombok.Getter;

import java.security.MessageDigest;
import java.util.Arrays;

public class KeyAgreementUtil {
   
    @Getter
    public static String keyAgreementValue="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /**
     * 执行密钥协议算法
     * 该方法接收一个字符串数组，按照特定的规则生成一个用于密钥协议的字符串，然后计算该字符串的SHA-256哈希值
     *
     * @param strings 字符串数组，包含需要进行密钥协议的字符串
     */
    public static void keyAgreement(String[] strings) {
        try {
            // 按字典序排序
            Arrays.sort(strings);
            // 拼接成一个字符串
            StringBuilder sb = new StringBuilder();
            for (String str : strings) {
                sb.append(str);
            }
            String concatenatedString = sb.toString();
            // 计算SHA-256哈希值
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(concatenatedString.getBytes());
            // 将字节数组转换为十六进制字符串
            StringBuilder hexString = new StringBuilder();
            for (byte b : hashBytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            keyAgreementValue = hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 algorithm not found", e);
        }
    }

}
