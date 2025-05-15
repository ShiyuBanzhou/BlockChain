import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
// import java.security.Security; // 通常不需要为 RSA 注册额外 Provider
import java.util.Base64; // 用于 Base64 编码
// import javax.xml.bind.DatatypeConverter; // 用于十六进制编码，如果也需要的话

public class KeyPair {

    /**
     * 生成 RSA 密钥对。
     *
     * @param keySize 密钥长度，例如 2048 位
     * @return KeyPair 对象，包含公钥和私钥
     * @throws Exception 如果密钥生成失败
     */
    public static java.security.KeyPair generateRSAKeyPair(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * 将字节数组转换为 Base64 编码的字符串。
     * 这是 login.html 中公钥输入框期望的格式。
     *
     * @param bytes 字节数组
     * @return Base64 编码的字符串
     */
    public static String bytesToBase64(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        return Base64.getEncoder().encodeToString(bytes);
    }

    /**
     * 将字节数组转换为十六进制字符串 (可选输出格式)。
     * @param bytes 字节数组
     * @return 十六进制字符串
     */
    public static String bytesToHex(byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        try {
            return javax.xml.bind.DatatypeConverter.printHexBinary(bytes).toLowerCase();
        } catch (NoClassDefFoundError e) {
            StringBuilder hexString = new StringBuilder(2 * bytes.length);
            for (byte b : bytes) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString().toLowerCase();
        }
    }


    public static void main(String[] args) {
        try {
            int rsaKeySize = 2048; // RSA 密钥长度，2048 位是常见的安全长度
            System.out.println("正在生成 RSA " + rsaKeySize + "-bit 密钥对...");
            java.security.KeyPair keyPair = generateRSAKeyPair(rsaKeySize);

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            // 获取密钥的原始字节 (通常是 ASN.1 DER 编码的 X.509 SubjectPublicKeyInfo 格式)
            byte[] publicKeyBytes = publicKey.getEncoded();
            byte[] privateKeyBytes = privateKey.getEncoded();

            // 将公钥转换为 Base64 字符串 (这是 login.html 中注册新DID时需要的格式)
            String publicKeyBase64 = bytesToBase64(publicKeyBytes);

            // 将公钥转换为十六进制字符串 (可选)
            String publicKeyHex = bytesToHex(publicKeyBytes);

            // 私钥也同样可以转换
            String privateKeyBase64 = bytesToBase64(privateKeyBytes); // 仅为演示
            String privateKeyHex = bytesToHex(privateKeyBytes);       // 仅为演示

            System.out.println("\n====================================================================");
            System.out.println("                 RSA 密钥对生成结果 (长度: " + rsaKeySize + " 位)");
            System.out.println("====================================================================");
            System.out.println("公钥信息:");
            System.out.println("  -> 算法: " + publicKey.getAlgorithm()); // 应为 "RSA"
            System.out.println("  -> 格式 (编码前): " + publicKey.getFormat()); // 通常是 "X.509"
            System.out.println("  -> 原始字节长度: " + publicKeyBytes.length);
            System.out.println("--------------------------------------------------------------------");
            System.out.println("  >>> 公钥 (Base64) <<<  (用于 login.html 注册):");
            System.out.println("      " + publicKeyBase64);
            System.out.println("--------------------------------------------------------------------");
            System.out.println("  公钥 (Hex):");
            System.out.println("      " + publicKeyHex);
            System.out.println("====================================================================");
            System.out.println("私钥信息 (警告：请妥善保管您的私钥，绝不要泄露!):");
            System.out.println("  -> 算法: " + privateKey.getAlgorithm()); // 应为 "RSA"
            System.out.println("  -> 格式 (编码前): " + privateKey.getFormat()); // 通常是 "PKCS#8"
            System.out.println("  -> 原始字节长度: " + privateKeyBytes.length);
            System.out.println("--------------------------------------------------------------------");
            System.out.println("  私钥 (Base64) - [仅为演示，请勿在生产中如此显示或存储]:");
            System.out.println("      " + privateKeyBase64);
            System.out.println("--------------------------------------------------------------------");
            System.out.println("  私钥 (Hex) - [仅为演示，请勿在生产中如此显示或存储]:");
            System.out.println("      " + privateKeyHex);
            System.out.println("====================================================================");
            System.out.println("\n操作指引:");
            System.out.println("1. 复制上面输出的 \"公钥 (Base64)\" 字符串。");
            System.out.println("2. 将其粘贴到 login.html 页面的“公钥 (Base64格式, 注册时需要)”输入框中。");
            System.out.println("3. 【重要】修改您的 DidService.java 中的 createDid 方法，为 VerificationMethod 设置类型，例如：");
            System.out.println("   vm.setType(\"RsaVerificationKey2018\");");
            System.out.println("4. 安全地保存上面输出的私钥信息。您将需要此私钥来对登录挑战进行签名。");
            System.out.println("====================================================================");

        } catch (Exception e) {
            System.err.println("\n密钥对生成或转换失败：");
            e.printStackTrace();
        }
    }
}
