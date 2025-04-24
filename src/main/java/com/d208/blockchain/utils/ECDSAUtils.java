package com.d208.blockchain.utils;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64; // 替换导入

public class ECDSAUtils {

    private static final String ALGORITHM = "EC";
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray(); // 用于十六进制转换

    // generate KeyPair
    public static KeyPair getKeyPair() throws NoSuchAlgorithmException, NoSuchProviderException {
        //Creating KeyPair generator object
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance(ALGORITHM);

        //Initializing the KeyPairGenerator
        // 使用默认的 SecureRandom 即可，通常不需要指定 "SHA1PRNG"
        // SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        keyPairGen.initialize(256); // SecureRandom 会自动提供

        return keyPairGen.generateKeyPair();
    }


    // generate signature
    public static String signECDSA(PrivateKey privateKey, String message) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(privateKey);
            signature.update(message.getBytes()); // 最好指定字符集, e.g., message.getBytes(StandardCharsets.UTF_8)

            byte[] sign = signature.sign();

            // 使用自定义方法将 byte[] 转换为十六进制字符串
            return bytesToHex(sign);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            // 更具体的异常处理
            e.printStackTrace(); // 或者抛出自定义异常
        }
        return null; // 或者抛出异常表明失败
    }

    // verify signature
    public static boolean verifyECDSA(PublicKey publicKey, String signedHex, String message) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initVerify(publicKey);
            signature.update(message.getBytes()); // 最好指定字符集

            // 使用自定义方法将十六进制字符串转换为 byte[]
            byte[] signedBytes = hexToBytes(signedHex);
            if (signedBytes == null) {
                System.err.println("Invalid hex signature format");
                return false;
            }
            boolean bool = signature.verify(signedBytes);

            System.out.println("verify：" + bool); // 日志建议使用日志框架
            return bool;
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            // 更具体的异常处理
            e.printStackTrace(); // 或者返回 false，或者抛出异常
        }
        return false;
    }

    /**
     * 将 公钥/私钥 编码后以 Base64 的格式保存到指定文件
     */
    public static void saveKeyForEncodedBase64(Key key, File keyFile) throws IOException {
        // 获取密钥编码后的格式
        byte[] encBytes = key.getEncoded();

        // 转换为 Base64 文本 (使用 java.util.Base64)
        String encBase64 = Base64.getEncoder().encodeToString(encBytes);

        // 保存到文件 (确保 IOUtils 是可用的)
        IOUtils.writeFile(encBase64, keyFile);
    }

    public static String getPubKeyStr(PublicKey key){
        byte[] bytes = key.getEncoded();
        // 使用 java.util.Base64
        String pubKeyStr = Base64.getEncoder().encodeToString(bytes);
        return pubKeyStr;
    }

    /**
     * 根据公钥的 Base64 文本创建公钥对象
     */
    public static PublicKey getPublicKey(String pubKeyBase64) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 把 公钥的Base64文本 转换为已编码的 公钥bytes (使用 java.util.Base64)
        byte[] encPubKey = Base64.getDecoder().decode(pubKeyBase64);

        // 创建 已编码的公钥规格
        X509EncodedKeySpec encPubKeySpec = new X509EncodedKeySpec(encPubKey);

        // 获取指定算法的密钥工厂, 根据 已编码的公钥规格, 生成公钥对象
        return KeyFactory.getInstance(ALGORITHM).generatePublic(encPubKeySpec);
    }

    /**
     * 根据私钥的 Base64 文本创建私钥对象
     */
    public static PrivateKey getPrivateKey(String priKeyBase64) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // 把 私钥的Base64文本 转换为已编码的 私钥bytes (使用 java.util.Base64)
        byte[] encPriKey = Base64.getDecoder().decode(priKeyBase64);

        // 创建 已编码的私钥规格
        PKCS8EncodedKeySpec encPriKeySpec = new PKCS8EncodedKeySpec(encPriKey);

        // 获取指定算法的密钥工厂, 根据 已编码的私钥规格, 生成私钥对象
        return KeyFactory.getInstance(ALGORITHM).generatePrivate(encPriKeySpec);
    }

    // --- Helper methods for Hex Conversion ---

    /**
     * Converts a byte array to a hexadecimal string.
     *
     * @param bytes the byte array to convert
     * @return the hexadecimal string representation
     */
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * @param hexString the hexadecimal string to convert
     * @return the byte array, or null if the hex string is invalid
     */
    public static byte[] hexToBytes(String hexString) {
        if (hexString == null || hexString.length() % 2 != 0) {
            return null; // Invalid hex string length
        }
        int len = hexString.length();
        byte[] data = new byte[len / 2];
        try {
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(hexString.charAt(i), 16) << 4)
                        + Character.digit(hexString.charAt(i + 1), 16));
            }
        } catch (NumberFormatException e) {
            // Handle cases where characters are not valid hex digits
            System.err.println("Error parsing hex string: " + e.getMessage());
            return null;
        }
        return data;
    }
}