package com.bjut.blockchain.web.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.UUID;
import org.springframework.util.DigestUtils;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidAlgorithmParameterException;

/**
 * 密码学工具类
 * 
 * @author Jared Jia
 *
 */
public class CryptoUtil {

	/**
	 * SHA256散列函数
	 * @param str
	 * @return
	 */
	public static String SHA256(String str) {
		MessageDigest messageDigest;
		String encodeStr = "";
		try {
			messageDigest = MessageDigest.getInstance("SHA-256");
			messageDigest.update(str.getBytes("UTF-8"));
			encodeStr = byte2Hex(messageDigest.digest());
		} catch (Exception e) {
			System.out.println("getSHA256 is error" + e.getMessage());
		}
		return encodeStr;
	}
	
	public static String byte2Hex(byte[] bytes) {
		StringBuilder builder = new StringBuilder();
		String temp;
		for (int i = 0; i < bytes.length; i++) {
			temp = Integer.toHexString(bytes[i] & 0xFF);
			if (temp.length() == 1) {
				builder.append("0");
			}
			builder.append(temp);
		}
		return builder.toString();
	}

	public static String MD5(String str) {
		String resultStr = DigestUtils.md5DigestAsHex(str.getBytes());
		return resultStr.substring(4, resultStr.length());
	}

	public static String UUID() {
		return UUID.randomUUID().toString().replaceAll("\\-", "");
	}

	/**
	 * 生成密钥对 (例如 EC secp256r1)。
	 * @return 生成的密钥对。
	 * @throws NoSuchAlgorithmException 如果算法不可用。
	 * @throws InvalidAlgorithmParameterException 如果算法参数无效。
	 */
	public static KeyPair generateKeyPair() throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
		// 常用的椭圆曲线 secp256r1 (NIST P-256)
		ECGenParameterSpec ecSpec = new ECGenParameterSpec("secp256r1");
		keyPairGenerator.initialize(ecSpec, new SecureRandom());
		return keyPairGenerator.generateKeyPair();
	}

	/**
	 * 使用私钥对数据进行签名。
	 * @param data 要签名的数据。
	 * @param privateKeyBytes PKCS#8 编码的私钥字节。
	 * @return 签名后的字节数组。
	 * @throws Exception 如果签名过程中发生错误。
	 */
	public static byte[] sign(byte[] data, byte[] privateKeyBytes) throws Exception {
		PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		// 假设密钥是EC类型的，与generateKeyPair对应
		KeyFactory keyFactory = KeyFactory.getInstance("EC");
		PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);

		// 常用的签名算法 SHA256withECDSA
		Signature signature = Signature.getInstance("SHA256withECDSA");
		signature.initSign(privateKey);
		signature.update(data);
		return signature.sign();
	}

	/**
	 * 使用公钥验证签名。
	 * @param data 原始数据。
	 * @param publicKeyBytes X.509 编码的公钥字节。
	 * @param signatureBytes 要验证的签名字节。
	 * @return 如果签名有效则返回 true，否则返回 false。
	 * @throws Exception 如果验证过程中发生错误。
	 */
	public static boolean verify(byte[] data, byte[] publicKeyBytes, byte[] signatureBytes) throws Exception {
		X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);

		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initVerify(publicKey);
		signature.update(data);
		return signature.verify(signatureBytes);
	}

	/**
	 * 对输入字符串应用 SHA-256 哈希算法。
	 *
	 * @param input 要进行哈希处理的字符串。
	 * @return 输入字符串的 SHA-256 哈希值（以十六进制字符串形式表示）。
	 * 如果发生异常则返回 null。
	 */
	public static String applySha256(String input) {
		try {
			// 获取 SHA-256 MessageDigest 实例
			MessageDigest digest = MessageDigest.getInstance("SHA-256");

			// 对输入字符串进行哈希计算 (使用 UTF-8 编码)
			byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

			// 将 byte 数组转换为十六进制字符串
			StringBuilder hexString = new StringBuilder();
			for (byte b : hash) {
				// byte 转 int，然后转十六进制，& 0xff 处理负数情况
				String hex = Integer.toHexString(0xff & b);
				// 保证每个字节都表示为两位十六进制数
				if (hex.length() == 1) {
					hexString.append('0');
				}
				hexString.append(hex);
			}
			return hexString.toString();
		} catch (NoSuchAlgorithmException e) {
			// 通常不应该发生，因为 SHA-256 是标准算法
			System.err.println("Error applying SHA-256: Algorithm not found. " + e.getMessage());
			// 抛出运行时异常，因为这是环境问题
			throw new RuntimeException("SHA-256 algorithm not found", e);
		} catch (Exception e) {
			// 捕获其他可能的异常
			System.err.println("Error applying SHA-256: " + e.getMessage());
			e.printStackTrace();
			return null; // 或者根据错误处理策略返回特定值
		}
	}

}
