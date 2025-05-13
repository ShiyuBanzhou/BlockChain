package com.bjut.blockchain.web.model;

import java.io.Serializable; // 建议实现 Serializable 接口

/**
 * 交易数据结构
 */
public class Transaction implements Serializable { // 实现 Serializable

	private static final long serialVersionUID = 1L; // Serializable UID

	/**
	 * 交易ID
	 */
	private String id;

	/**
	 * 交易发起方公钥（或地址）
	 */
	private String publicKey;

	/**
	 * 交易签名
	 */
	private String sign;

	/**
	 * 交易时间戳
	 */
	private long timestamp;

	/**
	 * 交易内容/数据 (例如转账信息、DID 锚定信息等)
	 * 使用 String 类型存储 JSON 或其他格式的数据。
	 */
	private String data;

	// --- Getters and Setters ---

	public String getId() {
		return id;
	}

	public void setId(String id) {
		this.id = id;
	}

	public String getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}

	public String getSign() {
		return sign;
	}

	public void setSign(String sign) {
		this.sign = sign;
	}

	public long getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(long timestamp) {
		this.timestamp = timestamp;
	}

	public String getData() {
		return data;
	}

	public void setData(String data) {
		this.data = data;
	}

	// --- equals, hashCode, toString (可选但推荐) ---

	@Override
	public String toString() {
		return "Transaction{" +
				"id='" + id + '\'' +
				", publicKey='" + publicKey + '\'' +
				", sign='" + sign + '\'' +
				", timestamp=" + timestamp +
				", data='" + data + '\'' +
				'}';
	}

	// 注意：equals 和 hashCode 应基于交易的唯一标识（通常是 id）
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Transaction that = (Transaction) o;
		return java.util.Objects.equals(id, that.id); // 基于 ID 判断相等
	}

	@Override
	public int hashCode() {
		return java.util.Objects.hash(id); // 基于 ID 计算哈希码
	}
}
