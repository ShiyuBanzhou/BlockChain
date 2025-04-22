package com.example.voting.blockchain;

/**
 * 通用交易结构：可表示身份注册、投票或信任更新
 */
public class Transaction {
    public enum Type { IDENTITY, VOTE, TRUST, OTHER }
    private Type type;        // 交易类型
    private String payload;   // 交易载荷（JSON 或自定义格式）
    private String signature; // 交易签名

    public Transaction(Type type, String payload) {
        this.type = type;
        this.payload = payload;
    }

    public Type getType() { return type; }
    public String getPayload() { return payload; }
    public String getSignature() { return signature; }

    public void signTransaction(String sig) {
        this.signature = sig;
    }

    @Override
    public String toString() {
        return "Transaction{" + type + ":" + payload + "}";
    }
}
