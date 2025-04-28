package com.bjut.blockchain.web.util;

import java.io.*;
import java.security.MessageDigest;


public class IntegrityChecker {
    
    private static final String CHECKSUM_FILE = "calculate.sha256";

    /**
     * 验证 JAR 文件的完整性
     * 通过比较存储的哈希值和当前 JAR 文件计算出的哈希值来验证文件是否被篡改
     *
     * @return 如果存储的哈希值和计算出的哈希值匹配，则返回 true，表示文件未被篡改；否则返回 false
     */
    public static boolean verifyIntegrity() {
        try {
            // 获取当前 JAR 文件的路径
            // 读取 calculate.sha256 文件中的哈希值
            String storedHash = readStoredHash();
            if (storedHash == null) {
                System.err.println("Failed to read stored hash.");
                return false;
            }
            System.out.println("Stored SHA-256 hash: " + storedHash);

            // 计算当前 JAR 文件的 SHA-256 哈希值
            String calculatedHash = calculateJarSHA256("blockchain-node2.jar");
            System.out.println("Calculated SHA-256 hash: " + calculatedHash);

            // 比较存储的哈希值和计算出的哈希值是否一致
            return calculatedHash.equals(storedHash);
        } catch (Exception e) {
            System.err.println("Error verifying integrity: " + e.getMessage());
            e.printStackTrace(); // 打印详细的堆栈信息
            return false;
        }
    }

    /**
     * 读取存储的哈希值
     * 从与 JAR 包同级的 CHECKSUM_FILE 文件中读取存储的哈希值
     *
     * @return 存储的哈希值字符串，如果读取失败则返回 null
     */
    private static String readStoredHash() {
        StringBuilder content = new StringBuilder();
        // 获取与JAR包同级的CHECKSUM_FILE路径
        String filePath = System.getProperty("user.dir") + File.separator + CHECKSUM_FILE;

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
            }
            String[] parts = content.toString().split("  ");
            if (parts.length > 0) {
                return parts[0].trim();
            }
        } catch (FileNotFoundException e) {
            System.err.println("Checksum file not found: " + filePath);
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Error reading checksum file: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 计算指定 JAR 文件的 SHA-256 哈希值
     *
     * @param jarPath JAR 文件的路径
     * @return 计算出的 SHA-256 哈希值字符串，如果计算过程中发生错误则返回 null
     */
    public static String calculateJarSHA256(String jarPath) {
        try (InputStream fis = new FileInputStream(jarPath)) {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] byteArray = new byte[4096];
            int bytesCount;

            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }

            // Convert the byte array to a hex string
            StringBuilder hexString = new StringBuilder();
            for (byte b : digest.digest()) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }

            return hexString.toString();
        } catch (Exception e) {
            System.out.println("Error reading JAR file " + jarPath + ": " + e.getMessage());
            return null;
        }
    }
}